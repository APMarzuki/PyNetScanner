import argparse
import sys
import ipaddress
import threading
from scapy.all import srp, Ether, ARP, conf, get_if_list, get_if_addr, get_if_hwaddr
from typing import List, Optional, Tuple

# Disable verbose output from scapy
conf.verb = 0
conf.iface = None  # Ensure no default interface is set globally


# --- Utility Functions ---

def generate_ip_list(ip_range: str) -> Optional[List[str]]:
    """Parses a single IP address or an IP range (CIDR notation) into a list of IPs."""
    try:
        if '/' in ip_range:
            network = ipaddress.ip_network(ip_range, strict=False)
            # Only include host IPs
            return [str(ip) for ip in network.hosts()]
        else:
            ipaddress.ip_address(ip_range)
            return [ip_range]

    except ValueError as e:
        print(f"[-] Error: Invalid IP address or CIDR range specified: {e}", file=sys.stderr)
        return None


def find_default_interface(target_ip: str) -> Optional[str]:
    """Tries to find the most suitable interface based on the target IP's network."""
    target_net = ipaddress.ip_network(f"{target_ip}/24", strict=False)

    # Iterate through all available interfaces
    for iface_name in get_if_list():
        try:
            # Check the IP address of the interface
            iface_ip = get_if_addr(iface_name)
            if iface_ip and iface_ip != '127.0.0.1':
                # Check if the interface IP belongs to the target network
                iface_net = ipaddress.ip_network(f"{iface_ip}/24", strict=False)
                if iface_net == target_net:
                    return iface_name  # Found a match!
        except:
            # Skip interfaces that don't have a valid IP or cause errors
            continue
    return None


# --- Discovery Function ---

def host_discovery(ip_range: str, interface: Optional[str]):
    """
    Performs host discovery using ARP requests.
    """
    ip_list = generate_ip_list(ip_range)
    if not ip_list:
        return

    print(f"[*] Starting Host Discovery on {ip_range}...")

    # Determine the interface to use
    if not interface:
        # If no interface is specified, try to find the best one automatically
        interface = find_default_interface(ip_list[0])
        if interface:
            print(f"[*] Auto-detected interface: {interface}")
        else:
            print("[*] Could not auto-detect the optimal interface. Using Scapy's default.")

    else:
        # Use the user-provided interface name
        print(f"[*] Using user-specified interface: {interface}")

    print("--------------------------------------------------")

    live_hosts: List[Tuple[str, str]] = []

    # --- ARP SCAN (Local Network Only) ---
    print("[*] Performing fast ARP scan (for local networks)...")

    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)

    try:
        # srp sends and receives packets at layer 2 (Ethernet). Use the determined interface.
        answered, unanswered = srp(arp_request, timeout=2, iface=interface)

        for sent, received in answered:
            ip = received.psrc
            mac = received.hwsrc
            live_hosts.append((ip, mac))

    except Exception as e:
        print(f"\n[!!!] CRITICAL ERROR during packet send/receive. Check Npcap installation and admin rights.")
        print(f"      Error detail: {e}", file=sys.stderr)
        sys.exit(1)

    print("--------------------------------------------------")

    if live_hosts:
        print(f"[!] Total {len(live_hosts)} live host(s) found.")
        print("\n  -- LIVE HOSTS SUMMARY --")
        for ip, mac in sorted(live_hosts, key=lambda x: ipaddress.ip_address(x[0])):
            print(f"  [+] IP: {ip:<15} | MAC: {mac}")
    else:
        print("[!] Scan completed. No live hosts found in the specified range.")


# --- Main Logic ---

def get_arguments() -> argparse.Namespace:
    """Handles command-line arguments for target IP range and interface."""
    parser = argparse.ArgumentParser(
        description="HostDiscoverer: Finds live hosts on a network using ARP sweeps.",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument("-r", "--range", dest="ip_range", required=True,
                        help="IP range in CIDR notation (e.g., 192.168.1.0/24).")

    parser.add_argument("-i", "--interface", dest="interface", required=False,
                        help="Network interface name (e.g., 'Wi-Fi' or 'Ethernet').\n"
                             "Optional: The script will attempt to auto-detect if omitted.")

    args = parser.parse_args()
    return args


if __name__ == '__main__':
    try:
        args = get_arguments()
        host_discovery(args.ip_range, args.interface)

    except KeyboardInterrupt:
        print("\n[*] Host discovery interrupted by user (Ctrl+C). Exiting.")
        sys.exit(0)
    except PermissionError:
        print("\n[!!!] ERROR: Scapy requires elevated privileges (root/Administrator) to send raw packets.")
        print("[*] Please ensure PyCharm or the terminal is run with 'Run as Administrator'.")
        sys.exit(1)
    except Exception as e:
        print(f"\n[-] An unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)