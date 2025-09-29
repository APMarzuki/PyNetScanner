import socket
import sys
import argparse
import threading
from typing import List, Optional

# Global list to store open ports and their banners
# Storing tuples of (port, banner)
OPEN_PORTS_DATA = []


# --- Utility Function ---

def sanitize_banner(banner: bytes) -> str:
    """Cleans and truncates the received banner for clean printing."""
    try:
        # Decode the bytes to a string, ignoring common network errors
        banner_str = banner.decode('utf-8', errors='ignore').strip()

        # Replace newlines/carriage returns with spaces for single-line output
        banner_str = banner_str.replace('\r', ' ').replace('\n', ' ')

        # Truncate to a manageable length for the console
        max_length = 70
        if len(banner_str) > max_length:
            return banner_str[:max_length] + "..."
        return banner_str
    except:
        return "[Non-standard data]"


# --- Scanning Function ---

def scan_port(ip: str, port: int, semaphore: threading.BoundedSemaphore) -> None:
    """
    Attempts to establish a TCP connection and perform banner grabbing if successful.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1.5)  # Increased timeout slightly to allow time for banner receive
    banner = None

    try:
        s.connect((ip, port))

        # --- Banner Grabbing Logic ---
        # Try to receive a banner (up to 1024 bytes)
        banner = s.recv(1024)

        # If we successfully received data, sanitize it
        if banner:
            clean_banner = sanitize_banner(banner)

            # Print success message with the banner
            print(f"[+] Port {port:<5} is OPEN  | Service: {clean_banner}")

            # Add data to the global list
            OPEN_PORTS_DATA.append((port, clean_banner))

        else:
            # If connect succeeded but no immediate banner was sent
            print(f"[+] Port {port:<5} is OPEN  | Service: [No banner received]")
            OPEN_PORTS_DATA.append((port, "[No banner received]"))

    except socket.error:
        # Catches connection failures
        pass
    except Exception as e:
        # Catch unexpected errors during the scan
        pass
    finally:
        # Always close the socket connection
        s.close()
        # IMPORTANT: Release the semaphore
        semaphore.release()


# --- Argument Handling Functions (UNCHANGED) ---

def get_arguments() -> argparse.Namespace:
    """Handles command-line arguments for target IP and ports."""
    parser = argparse.ArgumentParser(
        description="PyNetScanner: A fast, multithreaded TCP port scanner with Banner Grabbing.",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument("-t", "--target", dest="target", required=True,
                        help="Target IP address or hostname to scan.")

    parser.add_argument("-p", "--ports", dest="ports", required=True,
                        help="Ports to scan, supporting:\n"
                             " - Single: 80\n"
                             " - List: 21,22,80,443\n"
                             " - Range: 1-1024")

    parser.add_argument("-c", "--concurrency", dest="concurrency", type=int, default=50,
                        help="Maximum number of threads (concurrent connections) to use. Default is 50.")

    args = parser.parse_args()
    return args


def parse_ports(port_input: str) -> List[int]:
    """Converts the input string (e.g., '80,443' or '1-10') into a list of integers."""
    ports = set()

    if ',' in port_input:
        for p in port_input.split(','):
            try:
                ports.add(int(p.strip()))
            except ValueError:
                print(f"[-] Warning: Skipping invalid port value: {p}", file=sys.stderr)

    elif '-' in port_input:
        try:
            start, end = map(int, port_input.split('-'))
            if start > end or start < 1 or end > 65535:
                raise ValueError("Invalid port range.")
            ports.update(range(start, end + 1))
        except ValueError:
            print("[-] Error: Invalid port range format (e.g., 1-1024 required).", file=sys.stderr)
            sys.exit(1)

    else:
        try:
            p = int(port_input.strip())
            if 1 <= p <= 65535:
                ports.add(p)
            else:
                raise ValueError
        except ValueError:
            print("[-] Error: Invalid single port value (must be 1-65535).", file=sys.stderr)
            sys.exit(1)

    return sorted(list(ports))


# --- Main Logic with Multithreading and Argparse (SLIGHTLY MODIFIED FINAL SUMMARY) ---

if __name__ == '__main__':
    try:
        # 1. Get Arguments
        args = get_arguments()
        target_ip = args.target
        ports_to_scan = parse_ports(args.ports)
        max_threads = args.concurrency

        if not ports_to_scan:
            print("[-] Error: No valid ports specified for scanning.")
            sys.exit(1)

        # 2. Setup Threading Limits (Semaphore)
        semaphore = threading.BoundedSemaphore(value=max_threads)
        threads = []

        print(f"[*] Starting PyNetScanner on target: {target_ip}")
        print(f"[*] Scanning {len(ports_to_scan)} ports with a concurrency limit of {max_threads} threads.")
        print("--------------------------------------------------")

        # 3. Start Scanning Threads
        for port in ports_to_scan:
            semaphore.acquire()
            t = threading.Thread(target=scan_port, args=(target_ip, port, semaphore))
            threads.append(t)
            t.start()

        # 4. Wait for All Threads
        for t in threads:
            t.join()

        print("--------------------------------------------------")

        if OPEN_PORTS_DATA:
            OPEN_PORTS_DATA.sort(key=lambda x: x[0])
            print(f"[!] Scan completed successfully. Total {len(OPEN_PORTS_DATA)} port(s) found open.")
            print("\n  -- SUMMARY OF OPEN PORTS --")
            for port, banner in OPEN_PORTS_DATA:
                print(f"  [+] Port {port:<5} | Service: {banner}")

        else:
            print("[!] Scan completed. No open ports found in the specified range.")

    except KeyboardInterrupt:
        print("\n[*] Scan interrupted by user (Ctrl+C). Exiting.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[-] An unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)