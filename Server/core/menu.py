from Server.core.sniffer import NetworkSniffer
from Server.core.scanner import display_scan
from Server.core.network_info import get_my_ip, get_my_mac, get_default_gateway, get_my_subnet
from Server.core.firewall import unblock_all_ips
#from Server.offensive.arp_spoofer import continuous_arp_dos
#from Server.offensive.dhcp_starvation import start_starve
#from Server.offensive.syn_flood import start_syn_flood
#from Server.offensive.icmp_flood import start_icmp_flood
from Server.defensive.arp_guard import check_packet, seed_baseline, poll_os_arp_table, stop_os_arp_polling, cleanup_static_routes
from Server.defensive.dhcp_guard import check_dhcp_packet, start_dhcp_reaper, stop_dhcp_reaper
from Server.defensive.syn_guard import check_syn_packet
from Server.defensive.icmp_guard import check_icmp_packet


def offensive_menu():
    """Handles the Red Team (Offensive) interactive submenu."""
    # Automatically fetch local networking configuration details
    my_ip = get_my_ip()
    my_mac = get_my_mac()
    gateway = get_default_gateway()
    subnet = get_my_subnet()

    while True:
        # Display current host status and available attack simulation options
        print("\n--- Offensive Mode (Red Team) ---")
        print(f"[*] Host IP: {my_ip} | MAC: {my_mac}")
        print(f"[*] Gateway: {gateway} | Subnet: {subnet}")
        print("=" * 50)
        print("[1] Scan Network")
        print("[2] ARP Spoofer (L2)")
        print("[3] DHCP Starvation (L2)")
        print("[4] SYN Flood (L4)")
        print("[5] ICMP Ping Flood (L3)")
        print("[0] Back to Main Menu")

        choice = input("Select: ").strip()

        # Option 1: Trigger network reconnaissance scan
        if choice == "1":
            user_subnet = input(f"Enter subnet to scan [default {subnet}]: ").strip()
            display_scan(user_subnet if user_subnet else subnet)

        # Option 2: Execute Layer 2 ARP poisoning/DoS attack
        elif choice == "2":
            victim = input("Victim IP: ").strip()
            if not victim:
                print("[-] Victim IP is required.")
                continue

            user_gw = input(f"Gateway IP [default {gateway}]: ").strip()
            user_mac = input(f"Attacker MAC [default {my_mac}]: ").strip()

            continuous_arp_dos(
                victim_ip=victim,
                gateway_ip=user_gw if user_gw else gateway,
                attacker_mac=user_mac if user_mac else my_mac
            )

        # Option 3: Execute Layer 2 DHCP starvation attack
        elif choice == "3":
            dhcp_server = input(f"Enter DHCP Server IP [default {gateway}]: ").strip()
            start_starve(target_ip=dhcp_server if dhcp_server else gateway)

        # Option 4: Execute Layer 4 TCP SYN flood
        elif choice == "4":
            victim = input("Victim IP: ").strip()
            if not victim:
                print("[-] Victim IP is required.")
                continue

            port = input("Enter target port [default 80]: ").strip()
            start_syn_flood(
                target_ip=victim,
                target_port=int(port) if port.isdigit() else 80
            )

        # Option 5: Execute Layer 3 ICMP ping flood
        elif choice == "5":
            victim = input(f"Enter target IP [default {gateway}]: ").strip()
            start_icmp_flood(target_ip=victim if victim else gateway)

        # Exit submenu loop
        elif choice == "0":
            break


def defensive_menu():
    """Handles the Blue Team (Defensive) interactive submenu."""
    # Automatically fetch local networking configuration details
    my_ip = get_my_ip()
    my_mac = get_my_mac()
    gateway = get_default_gateway()
    subnet = get_my_subnet()

    while True:
        # Display current host status and available defensive monitoring options
        print("\n--- Defensive Mode (Blue Team) ---")
        print(f"[*] Host IP: {my_ip} | MAC: {my_mac}")
        print(f"[*] Gateway: {gateway} | Subnet: {subnet}")
        print("=" * 50)
        print("[1] Run ARP Guard (L2)")
        print("[2] Run DHCP Guard (L2)")
        print("[3] SYN Guard (L4)")
        print("[4] ICMP Guard (L3)")
        print("[0] Back to Main Menu")

        choice = input("Select: ").strip()

        # Option 1: Start real-time ARP spoofing detector and auto-healer
        if choice == "1":
            # Pre-seed the real gateway MAC and start the OS cache monitor
            print("[*] Initializing ARP baseline...")
            seed_baseline()
            poll_os_arp_table()

            print("[*] ARP Guard started. Listening...")
            sniffer = NetworkSniffer(packet_filter="arp", action_on_packet=check_packet)
            sniffer.start()
            input("Press Enter to stop ARP Guard...\n")

            # Cleanly stop the packet sniffer, OS cache monitor, and restore dynamic ARP
            sniffer.stop()
            stop_os_arp_polling()
            cleanup_static_routes(gateway)
            print("[*] ARP Guard stopped.")

        # Option 2: Start DHCP starvation detector, lease releaser, and firewall blocker
        elif choice == "2":
            dhcp_server = input(f"Enter DHCP Server IP [default {gateway}]: ").strip()
            target_gw = dhcp_server if dhcp_server else gateway

            print(f"[*] DHCP Guard active. Monitoring ports 67/68 for attacks against {target_gw}...")
            start_dhcp_reaper(server_ip=target_gw)
            sniffer = NetworkSniffer(
                packet_filter="udp and (port 67 or port 68)",
                action_on_packet=lambda pkt: check_dhcp_packet(pkt, server_ip=target_gw)
            )
            sniffer.start()
            input("Press Enter to stop DHCP Guard...\n")

            sniffer.stop()
            stop_dhcp_reaper()
            unblock_all_ips()
            print("[*] DHCP Guard stopped.")

        # Option 3: Start SYN flood detector and firewall blocker
        elif choice == "3":
            print("[*] SYN Guard active. Monitoring TCP SYN packets...")
            sniffer = NetworkSniffer(
                packet_filter="tcp[13] & 2 != 0",  # BPF filter matching TCP SYN flag
                action_on_packet=check_syn_packet
            )
            sniffer.start()
            input("Press Enter to stop SYN Guard...\n")
            sniffer.stop()
            unblock_all_ips()
            print("[*] SYN Guard stopped.")

        # Option 4: Start ICMP flood detector and firewall blocker
        elif choice == "4":
            print("[*] ICMP Guard active. Monitoring ICMP Echo Requests...")
            sniffer = NetworkSniffer(
                packet_filter="icmp[icmptype] == icmp-echo",
                action_on_packet=check_icmp_packet
            )
            sniffer.start()
            input("Press Enter to stop ICMP Guard...\n")
            sniffer.stop()
            unblock_all_ips()
            print("[*] ICMP Guard stopped.")

        # Exit submenu loop
        elif choice == "0":
            break