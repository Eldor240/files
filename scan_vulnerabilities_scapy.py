from scapy.all import *
import sys


def scan_vulnerabilities(target):
    # Send a SYN packet to the target host
    syn_packet = IP(dst=target) / TCP(dport=80, flags="S")
    syn_ack_packet = sr1(syn_packet, timeout=1, verbose=0)

    if syn_ack_packet is None:
        print(f"Host {target} is down or unresponsive.")
        return

    # Check for common vulnerabilities based on the response
    if syn_ack_packet.haslayer(TCP) and syn_ack_packet[TCP].flags == 'SA':
        print(f"Host {target} is potentially vulnerable to Heartbleed.")
    elif syn_ack_packet.haslayer(TCP) and syn_ack_packet[TCP].window == 0:
        print(f"Host {target} is potentially vulnerable to CVE-2019-9511.")
    else:
        print(f"Host {target} is not vulnerable to known vulnerabilities.")


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python script.py <target>")
        sys.exit(1)

    target = sys.argv[1]
    scan_vulnerabilities(target)
