import re
import time
import platform
import subprocess
import threading
from scapy.all import sendp, srp1, conf
from scapy.layers.l2 import Ether, ARP
from Server.core.network_info import get_my_ip, get_my_mac, get_default_gateway
from Server.core.logger import log_security_event
from Server.core.remote_output import remote_print

# Local baseline dictionary to track trusted IP-to-MAC associations: {"IP": "MAC"}
known_devices = {}
is_monitoring = False


def normalize_mac(mac_str: str) -> str:
    """
    Converts macOS shorthand MACs (e.g. 'd4:92:5e:e9:17:4')
    into standard 2-digit zero-padded lowercase format ('d4:92:5e:e9:17:04').
    """
    parts = mac_str.replace("-", ":").lower().split(":")
    if len(parts) == 6:
        return ":".join(p.zfill(2) for p in parts)
    return mac_str.lower()


def get_active_iface():
    """Returns the exact network interface used for outbound traffic."""
    try:
        return conf.route.route("8.8.8.8")[0]
    except Exception:
        return conf.iface


def seed_baseline():
    """
    Actively resolves and locks the true gateway and local host MACs
    BEFORE starting the sniffer, so fake attack packets cannot poison the baseline.
    """
    my_ip = get_my_ip()
    my_mac = normalize_mac(get_my_mac())
    gateway_ip = get_default_gateway()
    iface = get_active_iface()

    # Save our own interface
    known_devices[my_ip] = my_mac

    # Resolve legitimate router MAC directly
    remote_print(f"[*] Resolving authentic gateway MAC for {gateway_ip}...")
    query = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=gateway_ip)
    ans = srp1(query, timeout=2, iface=iface, verbose=False)

    if ans and ans.haslayer(ARP):
        real_gw_mac = normalize_mac(ans[ARP].hwsrc)
        known_devices[gateway_ip] = real_gw_mac
        remote_print(f"[+] Trusted Gateway Baseline: {gateway_ip} -> {real_gw_mac}")
    else:
        remote_print("[!] Warning: Could not resolve gateway MAC via packet probe.")


def heal_network(ip_address: str, real_mac: str, iface=None):
    """
    Locks the authentic MAC in the local OS table so spoofed packets are ignored,
    and sends corrective ARP replies to the router so return traffic reaches us.
    """
    remote_print(f"[FIX] Locking real mapping & healing router: {ip_address} -> {real_mac}")

    target_iface = iface or get_active_iface()
    my_ip = get_my_ip()
    my_mac = normalize_mac(get_my_mac())
    os_name = platform.system()

    # 1. Lock the real MAC statically in our local OS ARP table
    # Static entries cannot be overwritten by the attacker's ARP packets
    try:
        if os_name == "Darwin":  # macOS
            subprocess.run(f"arp -d {ip_address}", shell=True, capture_output=True)
            subprocess.run(f"arp -s {ip_address} {real_mac}", shell=True, capture_output=True)
        elif os_name == "Windows":
            win_mac = real_mac.replace(":", "-")
            subprocess.run(f"arp -d {ip_address}", shell=True, capture_output=True)
            subprocess.run(f"arp -s {ip_address} {win_mac}", shell=True, capture_output=True)
        else:  # Linux
            subprocess.run(
                f"ip neigh replace {ip_address} lladdr {real_mac} nud permanent dev {target_iface}",
                shell=True,
                capture_output=True
            )
    except Exception:
        pass

    # 2. Heal the Router (Gateway) so it sends internet replies back to OUR real MAC
    # Tells the router (ip_address / real_mac) that our IP (my_ip) is at our real MAC (my_mac)
    fix_for_router = Ether(dst=real_mac, src=my_mac) / ARP(
        op=2,
        hwsrc=my_mac,
        psrc=my_ip,
        hwdst=real_mac,
        pdst=ip_address
    )

    # 3. Build Layer 2 Gratuitous ARP packet to force victims back to the authentic MAC
    fix_broadcast = Ether(dst="ff:ff:ff:ff:ff:ff", src=real_mac) / ARP(
        op=2,  # Operation 2 = ARP Reply / Gratuitous ARP
        hwsrc=real_mac,
        psrc=ip_address,
        hwdst="ff:ff:ff:ff:ff:ff",
        pdst=ip_address
    )

    # Send 5 rapid packets to overpower the attacker's 2-second interval
    sendp([fix_for_router, fix_broadcast], count=5, inter=0.1, iface=target_iface, verbose=False)


def trigger_alert(target_ip: str, real_mac: str, attacker_mac: str):
    """Prints the alert banner, logs the event, and automatically broadcasts correction."""
    remote_print("\n" + "=" * 55)
    remote_print("[BLUE ALERT] ARP SPOOFING / POISONING DETECTED!")
    remote_print(f"Target IP:     {target_ip}")
    remote_print(f"Authentic MAC: {real_mac}")
    remote_print(f"Attacker MAC:  {attacker_mac}")
    remote_print("=" * 55)

    # Log the alert to logs/security_alerts.log and logs/events.jsonl
    log_security_event(
        module="ARP Guard",
        event_type="ARP Cache Poisoning",
        source=attacker_mac,
        target=target_ip,
        action_taken="Static ARP Lock + Router Heal",
        details=f"Authentic MAC: {real_mac}"
    )

    # Automatically broadcast correction to neutralize the attack
    heal_network(target_ip, real_mac)


def check_packet(packet):
    """Inspects ARP traffic for conflicting MAC mappings."""
    if not packet.haslayer(ARP):
        return

    sender_ip = packet[ARP].psrc
    sender_mac = normalize_mac(packet[ARP].hwsrc)

    # Ignore irrelevant, loopback, or broadcast packets
    if sender_ip in ("0.0.0.0", "255.255.255.255") or sender_mac == "ff:ff:ff:ff:ff:ff":
        return

    # First time seeing this IP: establish trusted baseline mapping
    if sender_ip not in known_devices:
        known_devices[sender_ip] = sender_mac
        print(f"[+] Saved baseline: {sender_ip} -> {sender_mac}")
        return

    # Check for unauthorized MAC modification (Spoofing indicator)
    real_mac = known_devices[sender_ip]
    if real_mac != sender_mac:
        trigger_alert(sender_ip, real_mac, sender_mac)


def poll_os_arp_table():
    """
    Backup monitor: Directly inspects the OS ARP cache ('arp -a') every second.
    Guarantees detection on Windows and macOS even if Npcap/BPF misses frames.
    """
    global is_monitoring
    is_monitoring = True

    # Matches both standard 2-digit and macOS 1-digit hex bytes
    arp_regex = re.compile(
        r"\(?(\d+\.\d+\.\d+\.\d+)\)?\s+(?:at\s+)?([0-9a-fA-F]{1,2}(?:[:\-][0-9a-fA-F]{1,2}){5})"
    )

    def _poll():
        while is_monitoring:
            try:
                output = subprocess.check_output("arp -a", shell=True, text=True)
                for line in output.splitlines():
                    match = arp_regex.search(line)
                    if match:
                        ip = match.group(1)
                        mac = normalize_mac(match.group(2))

                        # Skip broadcast and multicast addresses
                        if ip in ("255.255.255.255", "224.0.0.22") or mac == "ff:ff:ff:ff:ff:ff":
                            continue

                        # Check if the OS ARP table entry changed from our trusted baseline
                        if ip in known_devices and known_devices[ip] != mac:
                            trigger_alert(ip, known_devices[ip], mac)
            except Exception:
                pass
            time.sleep(1.0)

    t = threading.Thread(target=_poll, daemon=True)
    t.start()


def stop_os_arp_polling():
    """Stops the background OS ARP table polling thread."""
    global is_monitoring
    is_monitoring = False


def cleanup_static_routes(gateway_ip: str = None):
    """Reverts static ARP table locks on exit so the laptop roams freely on other networks."""
    target_gw = gateway_ip or get_default_gateway()
    os_name = platform.system()
    try:
        if os_name in ("Windows", "Darwin"):
            subprocess.run(f"arp -d {target_gw}", shell=True, capture_output=True)
        else:
            subprocess.run(f"ip neigh del {target_gw} dev {get_active_iface()}", shell=True, capture_output=True)
        remote_print(f"[*] Restored dynamic ARP routing for {target_gw}.")
    except Exception:
        pass