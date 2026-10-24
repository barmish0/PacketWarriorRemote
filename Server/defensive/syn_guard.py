import time
from collections import defaultdict, deque
from scapy.layers.inet import IP, TCP
from Server.core.firewall import block_ip
from Server.core.logger import log_security_event
from Server.core.network_info import get_my_ip
from Server.core.remote_output import remote_print

# Attack tracking parameters
RATE_LIMIT_WINDOW = 2.0  # Lookback period in seconds
MAX_SYNS_IN_WINDOW = 15  # Threshold for SYN flood detection per IP
COOLDOWN_PERIOD = 3.0  # Minimum seconds between repeated alert banners per IP

syn_history = defaultdict(deque)  # {src_ip: deque([timestamps])}
last_alert_times = {}


def check_syn_packet(packet):
    """
    Inspects TCP traffic for half-open connection floods (SYN packets).
    """
    if not packet.haslayer(IP) or not packet.haslayer(TCP):
        return

    # Filter for pure SYN packets (flags == 'S'), ignoring SYN-ACK ('SA') or ACKs ('A')
    if packet[TCP].flags != "S":
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    my_ip = get_my_ip()

    # Ignore outbound traffic originating from our own host
    if src_ip == my_ip:
        return

    current_time = time.time()

    # Update sliding window for this source IP
    history = syn_history[src_ip]
    history.append(current_time)

    while history and history[0] < current_time - RATE_LIMIT_WINDOW:
        history.popleft()

    # Check if attack threshold is breached
    if len(history) >= MAX_SYNS_IN_WINDOW:
        last_alert = last_alert_times.get(src_ip, 0.0)

        if current_time - last_alert > COOLDOWN_PERIOD:
            remote_print("\n" + "!" * 65)
            remote_print(f"[BLUE ALERT] TCP SYN Flood detected from {src_ip}!")
            remote_print(f"[!] Rate: {len(history)} SYN packets in {RATE_LIMIT_WINDOW}s")
            remote_print("!" * 65)
            last_alert_times[src_ip] = current_time

            # Log security event to logs/security_alerts.log and logs/events.jsonl
            log_security_event(
                module="SYN Guard",
                event_type="TCP SYN Flood",
                source=src_ip,
                target=dst_ip,
                action_taken="OS Firewall Drop",
                details=f"{len(history)} SYNs in {RATE_LIMIT_WINDOW}s"
            )

            # Block offending IP across Windows, macOS, or Linux firewall
            block_ip(src_ip, reason="TCP SYN Flood Saturation")