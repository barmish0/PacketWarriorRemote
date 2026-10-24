import threading
from scapy.all import sniff, conf


class NetworkSniffer:
    def __init__(self, packet_filter="", action_on_packet=None, iface=None):
        self.packet_filter = packet_filter
        self.action_on_packet = action_on_packet
        # Bind directly to the active outbound network interface so Scapy
        # does not fall back to a virtual or loopback adapter
        try:
            self.iface = iface or conf.route.route("8.8.8.8")[0]
        except Exception:
            self.iface = conf.iface
        self.is_running = False
        self.thread = None

    def _sniff_loop(self):
        # store=False ensures we do not consume unnecessary RAM during long captures
        sniff(
            iface=self.iface,
            filter=self.packet_filter,
            prn=self.action_on_packet,
            store=False,
            stop_filter=lambda pkt: not self.is_running
        )

    def start(self):
        """Starts the packet sniffer in a background daemon thread."""
        self.is_running = True
        self.thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self.thread.start()

    def stop(self):
        """Signals the sniffing loop to terminate."""
        self.is_running = False