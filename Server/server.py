import socket
import queue
import rpyc

from rpyc.utils.server import ThreadedServer

from core.scanner import scan_network
from core.network_info import (
    get_my_ip,
    get_my_mac,
    get_default_gateway,
    get_my_subnet,
)
from core.remote_output import set_callback
from core.sniffer import NetworkSniffer

from defensive.arp_guard import (
    check_packet,
    seed_baseline,
    poll_os_arp_table,
    stop_os_arp_polling,
    cleanup_static_routes,
)

from defensive.dhcp_guard import (
    check_dhcp_packet,
    start_dhcp_reaper,
    stop_dhcp_reaper,
)

from defensive.syn_guard import check_syn_packet
from defensive.icmp_guard import check_icmp_packet

from core.firewall import unblock_all_ips


PORT = 18861

output_queue = queue.Queue()

arp_sniffer = None
dhcp_sniffer = None
syn_sniffer = None
icmp_sniffer = None


def output(message):
    print(message, flush=True)
    output_queue.put(str(message))


class PacketWarriorService(rpyc.Service):

    def on_connect(self, connection):
        set_callback(output)
        output("[+] Client connected.")

    def on_disconnect(self, connection):
        set_callback(None)
        print("[+] Client disconnected.", flush=True)

    # ---------------- SERVER INFO ----------------

    def exposed_get_server_info(self):

        return {
            "hostname": socket.gethostname(),
            "ip": get_my_ip(),
            "mac": get_my_mac(),
            "gateway": get_default_gateway(),
            "subnet": get_my_subnet(),
        }

    # ---------------- LIVE OUTPUT ----------------

    def exposed_get_output(self):

        messages = []

        while True:
            try:
                messages.append(
                    output_queue.get_nowait()
                )
            except queue.Empty:
                break

        return messages

    # ---------------- SCAN ----------------

    def exposed_scan_network(self, subnet=None):

        if not subnet:
            subnet = get_my_subnet()

        output(
            f"[SERVER] Scanning {subnet}..."
        )

        try:

            results = scan_network(subnet)

            output(
                f"[SERVER] Scan complete: "
                f"{len(results)} device(s) found."
            )

            return {
                "success": True,
                "devices": results,
                "subnet": subnet,
            }

        except Exception as error:

            output(
                f"[SERVER] Scan error: {error}"
            )

            return {
                "success": False,
                "devices": [],
                "subnet": subnet,
                "error": str(error),
            }

    # ---------------- ARP ----------------

    def exposed_start_arp_guard(self):

        global arp_sniffer

        try:

            seed_baseline()
            poll_os_arp_table()

            arp_sniffer = NetworkSniffer(
                packet_filter="arp",
                action_on_packet=check_packet
            )

            arp_sniffer.start()

            output("[SERVER] ARP Guard started.")

            return True

        except Exception as error:

            output(
                f"[SERVER] ARP Guard error: {error}"
            )

            return False

    def exposed_stop_arp_guard(self):

        global arp_sniffer

        if arp_sniffer:
            arp_sniffer.stop()
            arp_sniffer = None

        stop_os_arp_polling()

        try:
            cleanup_static_routes(
                get_default_gateway()
            )
        except Exception:
            pass

        output("[SERVER] ARP Guard stopped.")

        return True

    # ---------------- DHCP ----------------

    def exposed_start_dhcp_guard(self, server_ip):

        global dhcp_sniffer

        try:

            start_dhcp_reaper(
                server_ip=server_ip
            )

            dhcp_sniffer = NetworkSniffer(
                packet_filter="udp and (port 67 or port 68)",
                action_on_packet=lambda packet:
                    check_dhcp_packet(
                        packet,
                        server_ip=server_ip
                    )
            )

            dhcp_sniffer.start()

            output(
                f"[SERVER] DHCP Guard started."
            )

            output(
                f"[SERVER] DHCP server: {server_ip}"
            )

            return True

        except Exception as error:

            output(
                f"[SERVER] DHCP Guard error: {error}"
            )

            return False

    def exposed_stop_dhcp_guard(self):

        global dhcp_sniffer

        if dhcp_sniffer:
            dhcp_sniffer.stop()
            dhcp_sniffer = None

        stop_dhcp_reaper()

        try:
            unblock_all_ips()
        except Exception:
            pass

        output("[SERVER] DHCP Guard stopped.")

        return True

    # ---------------- SYN ----------------

    def exposed_start_syn_guard(self):

        global syn_sniffer

        try:

            syn_sniffer = NetworkSniffer(
                packet_filter="tcp[13] & 2 != 0",
                action_on_packet=check_syn_packet
            )

            syn_sniffer.start()

            output("[SERVER] SYN Guard started.")

            return True

        except Exception as error:

            output(
                f"[SERVER] SYN Guard error: {error}"
            )

            return False

    def exposed_stop_syn_guard(self):

        global syn_sniffer

        if syn_sniffer:
            syn_sniffer.stop()
            syn_sniffer = None

        try:
            unblock_all_ips()
        except Exception:
            pass

        output("[SERVER] SYN Guard stopped.")

        return True

    # ---------------- ICMP ----------------

    def exposed_start_icmp_guard(self):

        global icmp_sniffer

        try:

            icmp_sniffer = NetworkSniffer(
                packet_filter="icmp[icmptype] == icmp-echo",
                action_on_packet=check_icmp_packet
            )

            icmp_sniffer.start()

            output("[SERVER] ICMP Guard started.")

            return True

        except Exception as error:

            output(
                f"[SERVER] ICMP Guard error: {error}"
            )

            return False

    def exposed_stop_icmp_guard(self):

        global icmp_sniffer

        if icmp_sniffer:
            icmp_sniffer.stop()
            icmp_sniffer = None

        try:
            unblock_all_ips()
        except Exception:
            pass

        output("[SERVER] ICMP Guard stopped.")

        return True


def main():

    print("=" * 60)
    print("       PACKETWARRIOR REMOTE SERVER")
    print("=" * 60)

    print("IP:", get_my_ip())
    print("Gateway:", get_default_gateway())
    print("Subnet:", get_my_subnet())
    print("Port:", PORT)

    print()
    print("[*] Waiting for client...")

    server = ThreadedServer(
        PacketWarriorService,
        hostname="0.0.0.0",
        port=PORT,
        protocol_config={
            "allow_public_attrs": True
        }
    )

    try:
        server.start()

    except KeyboardInterrupt:
        server.close()


if __name__ == "__main__":
    main()