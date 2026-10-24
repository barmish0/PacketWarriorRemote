import time
import threading
import rpyc


SERVER_HOST = "0.0.0.0"
SERVER_PORT = 18861


def connect():

    print("=" * 60)
    print("       PACKETWARRIOR REMOTE CLIENT")
    print("=" * 60)

    print(
        f"[*] Connecting to "
        f"{SERVER_HOST}:{SERVER_PORT}..."
    )

    try:

        connection = rpyc.connect(
            SERVER_HOST,
            SERVER_PORT,
            config={
                "allow_public_attrs": True
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

    stopped = False

    def wait():

        nonlocal stopped

        input()

        stopped = True

    thread = threading.Thread(
        target=wait,
        daemon=True
    )

    thread.start()

    while not stopped:

        get_output(connection)

        time.sleep(0.25)

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
            print("[3] Server Information")
            print("[0] Exit")

            choice = input("Select: ")

            if choice == "1":
                scan(connection)

            elif choice == "2":
                defensive_menu(connection)

            elif choice == "3":
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