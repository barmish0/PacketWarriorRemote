import socket
import ipaddress
from scapy.all import conf, get_if_hwaddr


def get_my_ip() -> str:
    """Finds the local IP address used for outbound internet traffic."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Connecting to an external address (without sending data) forces
        # the OS routing table to select the primary outbound interface.
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


def get_default_gateway() -> str:
    """
    Extracts the true router IP (default gateway) from the routing table,
    ensuring it does not accidentally return the host's own local IP.
    """
    my_ip = get_my_ip()

    try:
        # Search all routes in Scapy's table
        # Format of each entry: (destination, netmask, gateway, iface, output_ip, metric)
        default_routes = []
        for dest, mask, gw, iface, out_ip, metric in conf.route.routes:
            # A default gateway route targets 0.0.0.0/0
            if dest == 0 and mask == 0:
                # The gateway must be a real remote address, not 0.0.0.0 and not our own host IP
                if gw not in ("0.0.0.0", my_ip):
                    default_routes.append((metric, gw))

        if default_routes:
            # Pick the default route with the lowest metric (highest priority)
            default_routes.sort(key=lambda x: x[0])
            return default_routes[0][1]
    except Exception:
        pass

    # Safe fallback if running in an environment without internet/routes
    octets = my_ip.split(".")
    return f"{octets[0]}.{octets[1]}.{octets[2]}.1"


def get_my_mac(iface=None) -> str:
    """Resolves the MAC address cleanly across Windows, macOS, and Linux."""
    try:
        target_iface = iface or conf.route.route("8.8.8.8")[0]
        return get_if_hwaddr(target_iface)
    except Exception:
        # Fallback to general default interface
        try:
            return get_if_hwaddr(conf.iface)
        except Exception:
            return "00:00:00:00:00:00"


def get_my_subnet() -> str:
    """
    Calculates the CIDR subnet (e.g., '192.168.1.0/24')
    for the primary network interface.
    """
    my_ip = get_my_ip()
    # Search Scapy routing table for matching interface route
    for net, mask, gw, iface, addr, metric in conf.route.routes:
        if addr == my_ip and net != 0 and mask != 0:
            try:
                # Convert 32-bit int netmask to prefix length
                cidr = ipaddress.IPv4Network((net, mask), strict=False)
                return str(cidr)
            except Exception:
                pass

    # Fallback to standard /24 assumption if routing lookup fails
    octets = my_ip.split(".")
    return f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"