import platform
import subprocess

from scapy.layers.inet import IP
from scapy.layers.dns import DNS

from Server.core.logger import log_security_event


def flush_os_dns_cache():

    os_name = platform.system()

    try:

        if os_name == "Windows":

            subprocess.run(
                "ipconfig /flushdns",
                shell=True,
                capture_output=True,
                text=True
            )

            print("[FIREWALL] Flushed Windows DNS Cache.")

        elif os_name == "Darwin":

            subprocess.run(
                "sudo dscacheutil -flushcache; "
                "sudo killall -HUP mDNSResponder",
                shell=True,
                capture_output=True,
                text=True
            )

            print("[FIREWALL] Flushed macOS DNS Cache.")

        elif os_name == "Linux":

            subprocess.run(
                "systemctl restart systemd-resolved "
                "2>/dev/null || service nscd restart 2>/dev/null",
                shell=True,
                capture_output=True,
                text=True
            )

            print("[FIREWALL] Flushed Linux DNS Cache.")

    except Exception as error:

        print(
            f"[-] Failed to flush OS DNS cache: {error}"
        )


def check_dns_packet(packet):

    if not packet.haslayer(DNS):
        return

    if packet[DNS].qr != 1:
        return

    dns = packet[DNS]

    if not dns.an:
        return

    src_ip = (
        packet[IP].src
        if packet.haslayer(IP)
        else "Unknown"
    )

    dst_ip = (
        packet[IP].dst
        if packet.haslayer(IP)
        else "Local"
    )

    for i in range(dns.ancount):

        try:

            ans = dns.an[i]

            if not hasattr(ans, "rdata"):
                continue

            if not hasattr(ans, "rrname"):
                continue

            rdata = str(ans.rdata)

            if isinstance(ans.rrname, bytes):
                rrname = ans.rrname.decode(
                    "utf-8",
                    errors="ignore"
                )
            else:
                rrname = str(ans.rrname)

            clean_name = rrname.strip(".")

            major_brands = [
                "google",
                "microsoft",
                "github",
                "apple",
                "facebook",
                "login",
                "auth",
                "update",
            ]

            suspicious = any(
                brand in clean_name.lower()
                for brand in major_brands
            )

            private_ip = rdata.startswith(
                (
                    "192.168.",
                    "10.",
                    "172.16.",
                    "127.",
                    "0.",
                )
            )

            if suspicious and private_ip:

                print()
                print("!" * 65)
                print(
                    "[BLUE ALERT] "
                    "Rogue DNS Spoofing / Cache Poisoning detected!"
                )
                print(
                    f"[!] Domain '{clean_name}' "
                    f"resolved to suspicious IP: {rdata}"
                )
                print("!" * 65)

                log_security_event(
                    module="DNS Guard",
                    event_type="DNS Cache Poisoning / Spoofing",
                    source=src_ip,
                    target=dst_ip,
                    action_taken="OS DNS Cache Flush",
                    details=(
                        f"Fake resolution: "
                        f"{clean_name} -> {rdata}"
                    )
                )

                flush_os_dns_cache()

                break

        except Exception:
            pass