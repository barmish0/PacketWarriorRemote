import socket
from scapy.all import srp, sr1, conf
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, UDP

def get_vendor(mac: str) -> str:
    """Extracts hardware manufacturer from MAC address OUI database."""
    try:
        # Query Scapy's built-in MAC vendor database (OUI prefix lookup)
        vendor = conf.manufdb._resolve_MAC(mac)
        return vendor if vendor != mac else "Unknown Vendor"
    except Exception:
        return "Unknown Vendor"

def query_netbios_name(ip: str) -> str:
    """Attempts to query NetBIOS name on UDP port 137 for Windows/SMB devices."""
    try:
        # Standard NetBIOS Name Query packet payload structure
        nb_query = (
            b"\x82\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            b"\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41"
            b"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
            b"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01"
        )
        pkt = IP(dst=ip) / UDP(sport=137, dport=137) / nb_query
        reply = sr1(pkt, timeout=0.5, verbose=False)
        if reply and reply.haslayer(UDP):
            raw_data = bytes(reply[UDP].payload)
            # Parse NetBIOS hostname bytes from the response buffer
            if len(raw_data) >= 72:
                name = raw_data[57:72].decode("utf-8", errors="ignore").strip()
                if name:
                    return name
    except Exception:
        pass
    return "Unknown"

def resolve_hostname(ip: str) -> str:
    """Attempts standard reverse DNS first, falls back to NetBIOS."""
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except (socket.herror, socket.gaierror, socket.timeout):
        # Fallback to NetBIOS query if standard reverse DNS fails
        return query_netbios_name(ip)

def scan_network(subnet: str = "192.168.1.0/24", timeout: int = 4, retry: int = 1):
    """Sends ARP requests with retries and inspects MAC OUI + hostnames."""
    print(f"[*] Scanning subnet: {subnet} (Timeout: {timeout}s, Retries: {retry})...")

    # Construct Layer 2 broadcast ARP request to discover active hosts
    broadcast_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
    answered, _ = srp(broadcast_request, timeout=timeout, retry=retry, verbose=False)

    devices = []
    for sent, received in answered:
        ip = received.psrc
        mac = received.hwsrc
        vendor = get_vendor(mac)
        hostname = resolve_hostname(ip)

        devices.append({
            "ip": ip,
            "mac": mac,
            "vendor": vendor,
            "hostname": hostname
        })

    return devices

def display_scan(subnet: str = "192.168.1.0/24"):
    """Displays findings in a formatted table."""
    results = scan_network(subnet)

    header = f"{'IP Address':<16} {'MAC Address':<18} {'Vendor':<22} {'Hostname'}"
    print("\n" + "=" * (len(header) + 10))
    print(header)
    print("=" * (len(header) + 10))

    if not results:
        print("No devices found or scan timed out.")
    else:
        for dev in results:
            print(f"{dev['ip']:<16} {dev['mac']:<18} {dev['vendor']:<22} {dev['hostname']}")

    print("=" * (len(header) + 10))
    print(f"[+] Found {len(results)} active device(s).\n")

if __name__ == "__main__":
    display_scan()