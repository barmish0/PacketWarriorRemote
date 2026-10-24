import time
import threading
from collections import deque
from scapy.all import conf, sendp
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from Server.core.network_info import get_my_ip, get_my_mac, get_default_gateway
from Server.core.firewall import block_ip
from Server.core.logger import log_security_event
from Server.core.remote_output import remote_print

# Attack tracking parameters
RATE_LIMIT_WINDOW = 3.0     # Lookback period in seconds
MAX_REQUESTS_IN_WINDOW = 5  # Alert threshold for rapid DHCP requests
COOLDOWN_PERIOD = 2.0       # Minimum seconds between repeated alert banners
POST_ATTACK_HOLD = 10.0     # Seconds to keep sweeping & releasing after attacker stops

request_history = deque()
recent_Cache = deque(maxlen=300)  # Stores recent (ip, mac) pairs even before threshold trips
compromised_leases = {}           # Persistent ledger of stolen leases: {"IP": "MAC"}

last_alert_time = 0.0
last_attack_time = 0.0
attack_active = False
is_guard_running = False
target_server_ip = "192.168.1.1"
lease_lock = threading.Lock()


def get_active_iface():
    """Returns the exact network interface used for outbound traffic."""
    try:
        return conf.route.route("8.8.8.8")[0]
    except Exception:
        return conf.iface


def extract_client_mac(packet) -> str:
    """
    Extracts the client MAC address from the BOOTP chaddr field first
    (since starvation tools randomize BOOTP chaddr), falling back to Ether.src.
    """
    try:
        if packet.haslayer(BOOTP):
            raw_chaddr = bytes(packet[BOOTP].chaddr)[:6]
            if raw_chaddr and raw_chaddr != b"\x00" * 6:
                return ":".join(f"{b:02x}" for b in raw_chaddr)
    except Exception:
        pass

    if packet.haslayer(Ether):
        return packet[Ether].src.lower()
    return "00:00:00:00:00:00"


def build_release_packets(claimed_ip: str, client_mac: str, server_ip: str) -> list:
    """
    Builds a DHCPRELEASE packet to free committed leases (ACKs).
    """
    clean_mac = client_mac.replace(":", "").replace("-", "")
    raw_mac = bytes.fromhex(clean_mac).ljust(16, b"\x00")

    # Standard DHCPRELEASE (frees committed ACK leases)
    rel = (
        Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff")
        / IP(src=claimed_ip, dst=server_ip)
        / UDP(sport=68, dport=67)
        / BOOTP(chaddr=raw_mac, ciaddr=claimed_ip)
        / DHCP(options=[
            ("message-type", "release"),
            ("server_id", server_ip),
            ("end")
        ])
    )
    return [rel]


def start_dhcp_reaper(server_ip: str = None):
    """
    Starts a high-speed background thread using a persistent L2 socket.
    Continuously releases all compromised leases during the attack AND
    performs multi-pass cleanup sweeps after the attacker stops.
    """
    global is_guard_running, target_server_ip
    is_guard_running = True
    target_server_ip = server_ip or get_default_gateway()
    iface = get_active_iface()

    def _reaper_loop():
        global attack_active
        # Open a persistent Layer 2 socket so sending takes less than 1ms instead of 80ms
        l2_sock = None
        try:
            l2_sock = conf.L2socket(iface=iface)
        except Exception:
            l2_sock = None

        while is_guard_running:
            now = time.time()

            # Keep cleaning up for POST_ATTACK_HOLD seconds after the last attack packet
            if attack_active and (now - last_attack_time > POST_ATTACK_HOLD) and not compromised_leases:
                attack_active = False
                print("[+] DHCP pool recovery complete. Standing by for new attacks...")

            if compromised_leases:
                with lease_lock:
                    # Take a snapshot of all stolen IPs to release in this batch
                    current_batch = dict(compromised_leases)
                    # If the attacker has stopped sending packets for 3+ seconds,
                    # we do a final multi-pass flush and then clear the ledger
                    attacker_stopped = (now - last_attack_time) > 3.0
                    if attacker_stopped:
                        compromised_leases.clear()

                released_count = 0
                for ip_addr, mac_addr in current_batch.items():
                    try:
                        pkts = build_release_packets(ip_addr, mac_addr, target_server_ip)
                        for p in pkts:
                            if l2_sock:
                                l2_sock.send(p)
                            else:
                                sendp(p, iface=iface, verbose=False)
                        released_count += 1
                    except Exception:
                        pass

                if released_count > 0:
                    status = "POST-ATTACK SWEEP" if (now - last_attack_time) > 1.5 else "ACTIVE DEFENSE"
                    remote_print(f"[RECOVER - {status}] Purged {released_count} starved IP lease(s) back to {target_server_ip}.")

                # If the attacker stopped, send one extra confirmation pass 0.5s later
                # to make sure the router processed every release
                if attacker_stopped and current_batch:
                    time.sleep(0.5)
                    for ip_addr, mac_addr in current_batch.items():
                        try:
                            for p in build_release_packets(ip_addr, mac_addr, target_server_ip):
                                if l2_sock:
                                    l2_sock.send(p)
                                else:
                                    sendp(p, iface=iface, verbose=False)
                        except Exception:
                            pass
                    remote_print(f"[+] Final cleanup sweep finished: All {len(current_batch)} IP(s) unlocked.")

            time.sleep(0.25)

        if l2_sock:
            try:
                l2_sock.close()
            except Exception:
                pass

    t = threading.Thread(target=_reaper_loop, daemon=True)
    t.start()


def stop_dhcp_reaper():
    """Stops the background lease recovery thread."""
    global is_guard_running
    is_guard_running = False


def check_dhcp_packet(packet, server_ip="192.168.1.1"):
    """
    Non-blocking packet analyzer: Detects DHCP starvation floods and queues
    all compromised (IP, MAC) leases for the high-speed background reaper.
    """
    global last_alert_time, last_attack_time, attack_active, target_server_ip
    target_server_ip = server_ip

    if not packet.haslayer(DHCP) or not packet.haslayer(BOOTP):
        return

    # Never release our own legitimate host IP/MAC!
    my_ip = get_my_ip()
    my_mac = get_my_mac().lower()

    options = {opt[0]: opt[1] for opt in packet[DHCP].options if isinstance(opt, tuple)}
    msg_type = options.get("message-type")

    current_time = time.time()
    client_mac = extract_client_mac(packet)

    if client_mac == my_mac:
        return

    # 1 = Discover, 3 = Request (Client-to-Server packets)
    if msg_type in (1, 3, "discover", "request"):
        request_history.append((current_time, client_mac))
        while request_history and request_history[0][0] < current_time - RATE_LIMIT_WINDOW:
            request_history.popleft()

        requested_ip = options.get("requested_addr") or packet[BOOTP].ciaddr
        if isinstance(requested_ip, bytes):
            requested_ip = ".".join(str(b) for b in requested_ip)

        if requested_ip and requested_ip not in ("0.0.0.0", my_ip):
            recent_Cache.append((current_time, requested_ip, client_mac))

        # Check for threshold breach
        if len(request_history) >= MAX_REQUESTS_IN_WINDOW:
            attack_active = True
            last_attack_time = current_time
            unique_macs = {mac for _, mac in request_history}

            if current_time - last_alert_time > COOLDOWN_PERIOD:
                remote_print("\n" + "!" * 65)
                remote_print(f"[BLUE ALERT] DHCP Starvation detected! {len(request_history)} requests in {RATE_LIMIT_WINDOW}s")
                remote_print(f"[!] Involved MAC patterns: {len(unique_macs)} unique addresses")
                remote_print("!" * 65)
                last_alert_time = current_time

                # Log the security event to logs/security_alerts.log and logs/events.jsonl
                log_security_event(
                    module="DHCP Guard",
                    event_type="DHCP Starvation Flood",
                    source=f"{len(unique_macs)} Spoofed MACs (latest: {client_mac})",
                    target=server_ip,
                    action_taken="L2 Lease Reaper + Firewall Block",
                    details=f"{len(request_history)} requests in {RATE_LIMIT_WINDOW}s"
                )

            # Sweep all recently seen leases (including the first 1-4 packets before the threshold tripped!)
            with lease_lock:
                for ts, r_ip, r_mac in list(recent_Cache):
                    if current_time - ts <= RATE_LIMIT_WINDOW * 2:
                        compromised_leases[r_ip] = r_mac
                if requested_ip and requested_ip not in ("0.0.0.0", my_ip):
                    compromised_leases[requested_ip] = client_mac

            # Host firewall mitigation via centralized core/firewall.py
            if packet.haslayer(IP) and packet[IP].src not in ("0.0.0.0", "255.255.255.255", server_ip, my_ip):
                block_ip(packet[IP].src, reason="DHCP Starvation Flood")

    # 2 = Offer, 5 = ACK (Server-to-Client replies)
    # Catch every IP the router offers or assigns during or right after the flood!
    elif msg_type in (2, 5, "offer", "ack"):
        assigned_ip = packet[BOOTP].yiaddr
        if assigned_ip and assigned_ip not in ("0.0.0.0", my_ip):
            # Always cache recent router assignments in case the flood just started
            recent_Cache.append((current_time, assigned_ip, client_mac))

            # If an attack is active (or was active within the last 10 seconds),
            # immediately queue this IP for release so even delayed router replies get freed!
            if attack_active or (current_time - last_attack_time <= POST_ATTACK_HOLD):
                with lease_lock:
                    compromised_leases[assigned_ip] = client_mac