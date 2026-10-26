import socket
import time
import threading
import rpyc


DISCOVERY_PORT = 18863
SERVER_PORT = 18864
DISCOVERY_MESSAGE = "PACKETWARRIOR_CONNECT"


def connect():

    print("=" * 60)
    print("       PACKETWARRIOR REMOTE CLIENT")
    print("=" * 60)

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM
    )

    sock.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )

    try:

        sock.bind(
            ("0.0.0.0", DISCOVERY_PORT)
        )

        print(
            f"[*] Waiting for server on UDP "
            f"port {DISCOVERY_PORT}..."
        )

        while True:

            data, address = sock.recvfrom(1024)

            message = data.decode(
                "utf-8",
                errors="ignore"
            ).strip()

            if message != DISCOVERY_MESSAGE:
                continue

            server_host = address[0]

            print(
                f"[+] Server found: "
                f"{server_host}"
            )

            break

    except Exception as error:

        print("[!] Discovery failed:")
        print(error)

        sock.close()
        return None

    finally:

        sock.close()

    print(
        f"[*] Connecting to "
        f"{server_host}:{SERVER_PORT}..."
    )

    try:

        connection = rpyc.connect(
            server_host,
            SERVER_PORT,
            config={
                "sync_request_timeout": 120
            }
        )

        print("[+] Connected.")

        return connection

    except Exception as error:

        print("[!] Connection failed:")
        print(error)

        return None

def get_output(connection):

    try:

        messages = connection.root.get_output()

        for message in messages:
            print(message, flush=True)

    except Exception:
        pass


def server_info(connection):

    info = connection.root.get_server_info()

    print()
    print("SERVER INFORMATION")
    print("------------------")
    print("Hostname:", info["hostname"])
    print("IP:", info["ip"])
    print("MAC:", info["mac"])
    print("Gateway:", info["gateway"])
    print("Subnet:", info["subnet"])


def scan(connection):

    info = connection.root.get_server_info()

    subnet = input(
        f"Subnet [{info['subnet']}]: "
    ).strip()

    if not subnet:
        subnet = info["subnet"]

    result = connection.root.scan_network(subnet)

    get_output(connection)

    if not result["success"]:
        return

    print()
    print("SCAN RESULTS")
    print("------------")

    for device in result["devices"]:

        print(
            device["ip"],
            device["mac"],
            device["hostname"]
        )


def run_guard(connection, start, stop):

    if not start():
        return

    print()
    print("[*] Guard running.")
    print("[*] Live server output:")
    print("[*] Press Enter to stop.")
    print()

    running = threading.Event()
    running.set()

    def output_loop():

        while running.is_set():

            get_output(connection)

            time.sleep(0.1)

    thread = threading.Thread(
        target=output_loop,
        daemon=True
    )

    thread.start()

    input()

    running.clear()

    thread.join(timeout=1)

    stop()

    time.sleep(0.2)

    get_output(connection)

    print("[*] Guard stopped.")

def defensive_menu(connection):

    while True:

        print()
        print("DEFENSIVE MODE")
        print("--------------")
        print("[1] ARP Guard")
        print("[2] DHCP Guard")
        print("[3] SYN Guard")
        print("[4] ICMP Guard")
        print("[5] DNS Guard")
        print("[0] Back")

        choice = input("Select: ")

        if choice == "1":

            run_guard(
                connection,
                connection.root.start_arp_guard,
                connection.root.stop_arp_guard
            )

        elif choice == "2":

            info = connection.root.get_server_info()

            ip = input(
                f"DHCP Server IP [{info['gateway']}]: "
            ).strip()

            if not ip:
                ip = info["gateway"]

            run_guard(
                connection,
                lambda:
                    connection.root.start_dhcp_guard(ip),
                connection.root.stop_dhcp_guard
            )

        elif choice == "3":

            run_guard(
                connection,
                connection.root.start_syn_guard,
                connection.root.stop_syn_guard
            )

        elif choice == "4":

            run_guard(
                connection,
                connection.root.start_icmp_guard,
                connection.root.stop_icmp_guard
            )

        elif choice == "5":

            run_guard(
                connection,
                connection.root.start_dns_guard,
                connection.root.stop_dns_guard
            )

        elif choice == "0":

            return

        else:

            print("[!] Invalid choice.")

def offensive_menu(connection):

    while True:

        print()
        print("OFFENSIVE MODE")
        print("--------------")
        print("[1] ARP Spoofing")
        print("[2] DHCP Starvation")
        print("[3] SYN Flood")
        print("[4] ICMP Flood")
        print("[5] DNS Spoofing")
        print("[0] Back")

        choice = input("Select: ").strip()

        if choice == "1":

            victim = input(
                "Victim IP: "
            ).strip()

            if not victim:
                print("[!] Victim IP is required.")
                continue

            info = connection.root.get_server_info()

            gateway = input(
                f"Gateway IP [{info['gateway']}]: "
            ).strip()

            if not gateway:
                gateway = info["gateway"]

            connection.root.start_arp_spoof(
                victim,
                gateway,
                info["mac"],
            )

            print(
                "[*] ARP spoof started."
            )

            input("Press Enter to stop ARP spoofing...")

            try:
                stopped = connection.root.stop_arp_spoof()
                if stopped:
                    print("[+] Stop request sent to server.")
            except Exception as error:
                print(f"[!] Failed to stop ARP spoofing: {error}")

        elif choice == "2":

            info = connection.root.get_server_info()

            server_ip = input(
                f"DHCP Server IP [{info['gateway']}]: "
            ).strip()

            if not server_ip:
                server_ip = info["gateway"]

            connection.root.start_dhcp_starvation(
                server_ip
            )

            print(
                "[*] DHCP starvation started."
            )

            input(
                "Press Enter to stop..."
            )

            connection.root.stop_dhcp_starvation()

        elif choice == "3":

            victim = input(
                "Target IP: "
            ).strip()

            if not victim:
                print("[!] Target IP is required.")
                continue

            port = input(
                "Target port [80]: "
            ).strip()

            if not port.isdigit():
                port = 80
            else:
                port = int(port)

            connection.root.start_syn_flood(
                victim,
                port,
            )

            print(
                "[*] SYN flood started."
            )

            input(
                "Press Enter to return to menu..."
            )

        elif choice == "4":

            victim = input(
                "Target IP: "
            ).strip()

            if not victim:
                print("[!] Target IP is required.")
                continue

            connection.root.start_icmp_flood(
                victim
            )

            print(
                "[*] ICMP flood started."
            )

            input(
                "Press Enter to return to menu..."
            )

        elif choice == "5":

            victim = input(
                "Victim IP: "
            ).strip()

            if not victim:
                print(
                    "[!] Victim IP is required."
                )
                continue

            domain = input(
                "Target domain [example.com]: "
            ).strip()

            if not domain:
                domain = "example.com"

            spoof_ip = input(
                "Spoof IP [127.0.0.1]: "
            ).strip()

            if not spoof_ip:
                spoof_ip = "127.0.0.1"

            connection.root.start_dns_spoof(
                victim,
                domain,
                spoof_ip
            )

            print(
                "[*] DNS spoofing started."
            )

            input(
                "Press Enter to return..."
            )

        elif choice == "0":
            return

        else:
            print("[!] Invalid choice.")

def main():

    connection = connect()

    if not connection:
        return

    try:

        while True:

            print()
            print("=" * 60)
            print("             PACKETWARRIOR")
            print("=" * 60)

            print("[1] Network Scan")
            print("[2] Defensive Mode")
            print("[3] Offensive Mode")
            print("[4] Server Information")
            print("[0] Exit")

            choice = input("Select: ")

            if choice == "1":
                scan(connection)

            elif choice == "2":
                defensive_menu(connection)

            elif choice == "3":
                offensive_menu(connection)

            elif choice == "4":
                server_info(connection)

            elif choice == "0":
                break

            else:
                print("[!] Invalid choice.")

    finally:

        connection.close()

        print("[+] Disconnected.")


if __name__ == "__main__":
    main()