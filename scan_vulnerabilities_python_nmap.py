import nmap
import sys


def scan_vulnerabilities(target):
    nm = nmap.PortScanner()
    nm.scan(target, arguments='-sV --script vuln')

    for host in nm.all_hosts():
        print(f"Host: {host}")
        for port in nm[host].all_tcp():
            if 'script' in nm[host][port] and 'vuln' in nm[host][port]['script']:
                print(f"Port: {port}")
                print(nm[host][port]['script']['vuln'])


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python script.py <target>")
        sys.exit(1)

    target = sys.argv[1]
    scan_vulnerabilities(target)