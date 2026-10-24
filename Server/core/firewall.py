import platform
import subprocess
from Server.core.logger import log_security_event
from Server.core.network_info import get_my_ip, get_default_gateway

# Set of currently blocked IP addresses in this session
blocked_ips = set()


def block_ip(ip_address: str, reason: str = "Malicious Traffic") -> bool:
    """
    Dynamically blocks an offending IP address at the OS firewall level
    across Windows, macOS, and Linux.
    """
    my_ip = get_my_ip()
    gateway_ip = get_default_gateway()

    # Safety check: Never block loopback, broadcast, our own host IP, or our router!
    if (
        not ip_address
        or ip_address in blocked_ips
        or ip_address in ("0.0.0.0", "255.255.255.255", "127.0.0.1", my_ip, gateway_ip)
    ):
        return False

    os_type = platform.system()
    rule_name = f"PacketWarrior_Block_{ip_address}"

    try:
        if os_type == "Windows":
            cmd = (
                f'netsh advfirewall firewall add rule name="{rule_name}" '
                f'dir=in action=block remoteip={ip_address}'
            )
            subprocess.run(cmd, shell=True, capture_output=True, text=True)
            print(f"[FIREWALL] Windows Firewall rule injected: Blocked {ip_address} ({reason})")

        elif os_type == "Darwin":  # macOS
            # Add offending IP to a dedicated macOS pfctl table
            cmd = (
                f'pfctl -t packetwarrior_blocks -T add {ip_address} 2>/dev/null || '
                f'(echo "table <packetwarrior_blocks> persist\\nblock in quick from <packetwarrior_blocks>" '
                f'| pfctl -a packetwarrior -f - 2>/dev/null && pfctl -t packetwarrior_blocks -T add {ip_address} 2>/dev/null)'
            )
            subprocess.run(cmd, shell=True, capture_output=True, text=True)
            print(f"[FIREWALL] macOS pfctl rule injected: Blocked {ip_address} ({reason})")

        elif os_type == "Linux":
            cmd = f"iptables -A INPUT -s {ip_address} -j DROP"
            subprocess.run(cmd, shell=True, capture_output=True, text=True)
            print(f"[FIREWALL] Linux iptables rule injected: Dropped {ip_address} ({reason})")

        blocked_ips.add(ip_address)
        log_security_event(
            module="Firewall",
            event_type="IP Blocked",
            source=ip_address,
            target=my_ip,
            action_taken=f"OS Firewall Drop ({os_type})",
            details=reason
        )
        return True

    except Exception as err:
        print(f"[-] Could not inject firewall rule for {ip_address}: {err}")
        return False


def unblock_ip(ip_address: str) -> bool:
    """Removes a previously injected firewall block for a specific IP."""
    if ip_address not in blocked_ips:
        return False

    os_type = platform.system()
    rule_name = f"PacketWarrior_Block_{ip_address}"

    try:
        if os_type == "Windows":
            cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
            subprocess.run(cmd, shell=True, capture_output=True, text=True)

        elif os_type == "Darwin":  # macOS
            cmd = f"pfctl -t packetwarrior_blocks -T delete {ip_address} 2>/dev/null"
            subprocess.run(cmd, shell=True, capture_output=True, text=True)

        elif os_type == "Linux":
            cmd = f"iptables -D INPUT -s {ip_address} -j DROP"
            subprocess.run(cmd, shell=True, capture_output=True, text=True)

        blocked_ips.discard(ip_address)
        print(f"[FIREWALL] Removed firewall block for {ip_address}")
        return True

    except Exception as err:
        print(f"[-] Failed to remove firewall rule for {ip_address}: {err}")
        return False


def unblock_all_ips():
    """Cleans up all firewall rules created during the current session."""
    if not blocked_ips:
        return

    print(f"[*] Cleaning up {len(blocked_ips)} firewall rule(s)...")
    for ip in list(blocked_ips):
        unblock_ip(ip)