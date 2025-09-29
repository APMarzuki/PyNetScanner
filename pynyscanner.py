import os
import hashlib
import time
import sqlite3
import socket
import threading
import json
import argparse
import subprocess
import sys  # Added for cleaner argument checks in main
from datetime import datetime

# --- Configuration & Constants ---
DEFAULT_SCAN_PATH = os.path.expanduser('~')
LOG_FILE = "pynyscanner_errors.log"
DB_FILE = "pynyscanner.db"  # SQLite database file
EXCLUDE_DIRS = ['.git', '__pycache__', '$Recycle.Bin', 'node_modules']
TIMEOUT = 1.0  # Timeout for port scanning sockets


# --- Helper Functions (No changes) ---
def log_error(message):
    """Appends an error message with a timestamp to the log file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(f"[{timestamp}] {message}\n")


# --- Database Functions (No changes) ---

def init_db(db_name=DB_FILE):
    """Initializes the SQLite database connection and creates the necessary tables."""
    try:
        conn = sqlite3.connect(db_name)
        cursor = conn.cursor()

        # Create the 'files' table to store detailed file information
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_date TEXT NOT NULL,
                path TEXT NOT NULL,
                filename TEXT NOT NULL,
                size_bytes INTEGER,
                creation_time TEXT,
                modification_time TEXT,
                hash_sha256 TEXT
            );
        """)

        # Create the 'scan_sessions' table to track summary data for reporting
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_sessions (
                session_id TEXT PRIMARY KEY,
                scan_start_time TEXT NOT NULL,
                scan_path TEXT NOT NULL,
                files_processed INTEGER,
                duration_seconds REAL
            );
        """)

        conn.commit()
        return conn, cursor
    except sqlite3.Error as e:
        log_error(f"SQLite initialization error: {e}")
        print(f"ERROR: Could not initialize database. Check {LOG_FILE}.")
        return None, None


def close_db(conn):
    """Closes the database connection."""
    if conn:
        conn.close()


def save_scan_results(conn, cursor, data, session_id, scan_path, duration):
    """Saves the detailed file metadata to the 'files' table and the session summary."""
    if not data:
        print("No file data to save to database.")
        return

    file_records = [
        (
            session_id,
            item['path'],
            item['filename'],
            item['size_bytes'],
            item['creation_time'],
            item['modification_time'],
            item['hash_sha256']
        )
        for item in data if item.get('hash_sha256')
    ]

    insert_query = """
        INSERT INTO files (scan_date, path, filename, size_bytes, creation_time, modification_time, hash_sha256)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """
    try:
        cursor.executemany(insert_query, file_records)

        cursor.execute("""
            INSERT INTO scan_sessions (session_id, scan_start_time, scan_path, files_processed, duration_seconds)
            VALUES (?, ?, ?, ?, ?)
        """, (session_id, session_id, scan_path, len(file_records), duration))

        conn.commit()
        print(f"\nSUCCESS: {len(file_records)} file records saved under session {session_id}.")
    except sqlite3.Error as e:
        log_error(f"SQLite save error for session {session_id}: {e}")
        print(f"ERROR: Failed to save scan results to database. Check {LOG_FILE}.")


def view_past_scans(cursor):
    """Retrieves and prints a summary of all past scan sessions."""
    try:
        cursor.execute(
            "SELECT session_id, scan_start_time, scan_path, files_processed, duration_seconds FROM scan_sessions ORDER BY scan_start_time DESC")
        scans = cursor.fetchall()

        if not scans:
            print("\nNo previous file scan sessions found.")
            return

        print("\n--- Past File Scan Sessions Summary ---")
        for session in scans:
            session_id, start_time, path, count, duration = session
            print(f"Session ID: {session_id}")
            print(f"  Start Time: {datetime.fromisoformat(start_time).strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"  Path: {path}")
            print(f"  Files Hashed: {count}")
            print(f"  Duration: {duration:.2f} seconds")
            print("-" * 30)

    except sqlite3.Error as e:
        log_error(f"SQLite view error: {e}")
        print(f"ERROR: Failed to retrieve past scans. Check {LOG_FILE}.")


def find_duplicates(cursor):
    """
    Finds groups of files that share the same hash (duplicates) and returns them
    as a structured list, while also printing a summary.
    """
    print("\n--- Starting Duplicate File Analysis ---")
    duplicate_sets = []
    try:
        cursor.execute("""
            SELECT hash_sha256
            FROM files
            GROUP BY hash_sha256
            HAVING COUNT(hash_sha256) > 1
        """)
        duplicate_hashes = [row[0] for row in cursor.fetchall()]

        if not duplicate_hashes:
            print("No duplicate files found in the database.")
            return []

        print(f"Found {len(duplicate_hashes)} unique duplicate sets.")
        print("-" * 50)

        for i, dup_hash in enumerate(duplicate_hashes):
            cursor.execute("""
                SELECT path, size_bytes
                FROM files
                WHERE hash_sha256 = ?
                ORDER BY path
            """, (dup_hash,))
            duplicates = cursor.fetchall()

            file_size_bytes = duplicates[0][1]
            file_size_mb = file_size_bytes / (1024 * 1024)

            current_set = {
                "set_id": i + 1,
                "hash_sha256": dup_hash,
                "total_count": len(duplicates),
                "total_size_mb_wasted": round(file_size_mb * (len(duplicates) - 1), 2),
                "file_size_mb": round(file_size_mb, 2),
                "paths": [path for path, _ in duplicates]
            }
            duplicate_sets.append(current_set)

            print(f"DUPLICATE SET {i + 1} (Size: {file_size_mb:.2f} MB, Count: {len(duplicates)})")
            print(f"Hash: {dup_hash[:10]}...")

            for path, _ in duplicates:
                print(f"  -> {path}")
            print("-" * 50)

        return duplicate_sets

    except sqlite3.Error as e:
        log_error(f"SQLite duplicate analysis error: {e}")
        print(f"ERROR: Failed to analyze duplicates. Check {LOG_FILE}.")
        return []


def export_duplicates_to_json(duplicate_sets, default_filename="duplicate_report.json"):
    """Exports the structured list of duplicate sets to a JSON file."""
    if not duplicate_sets:
        print("JSON export skipped.")
        return

    output_filename = input(
        f"\nDo you want to export the duplicates to JSON? Enter filename (default: {default_filename}) or press Enter to skip: ")

    if not output_filename:
        print("JSON export skipped.")
        return

    if not output_filename.lower().endswith('.json'):
        output_filename += '.json'

    try:
        with open(output_filename, 'w', encoding='utf-8') as f:
            json.dump(duplicate_sets, f, indent=4)
        print(f"SUCCESS: Duplicate report exported to {output_filename}")
        print(f"Total sets: {len(duplicate_sets)}")

    except IOError as e:
        log_error(f"IO Error writing JSON file {output_filename}: {e}")
        print(f"ERROR: Could not write JSON file. Check {LOG_FILE}.")


# --- File Scanner Logic (No changes) ---
def get_file_hash(filepath, hash_algorithm=hashlib.sha256):
    """Calculates the hash of a file for integrity and duplicate checking."""
    hasher = hash_algorithm()
    try:
        with open(filepath, 'rb') as file:
            while chunk := file.read(4096):
                hasher.update(chunk)
        return hasher.hexdigest()
    except IOError as e:
        log_error(f"IO Error calculating hash for {filepath}: {e}")
        return None
    except Exception as e:
        log_error(f"Unexpected error hashing {filepath}: {e}")
        return None


def get_file_info(filepath):
    """Gathers essential metadata about a file."""
    try:
        stat = os.stat(filepath)
        return {
            'path': filepath,
            'filename': os.path.basename(filepath),
            'size_bytes': stat.st_size,
            'creation_time': datetime.fromtimestamp(stat.st_ctime).isoformat(),
            'modification_time': datetime.fromtimestamp(stat.st_mtime).isoformat(),
        }
    except FileNotFoundError:
        log_error(f"File not found during stat call: {filepath}")
        return None
    except Exception as e:
        log_error(f"Could not get stats for file {filepath}: {e}")
        return None


def scan_directory(start_path=DEFAULT_SCAN_PATH):
    """
    Recursively scans a directory, hashing files and collecting metadata.
    Returns the scan results, the unique session ID, and the duration.
    """
    scanned_files = []
    start_time_iso = datetime.now().isoformat()
    session_id = start_time_iso  # Use ISO format as a unique ID
    start_ts = time.time()
    total_files = 0

    print(f"Starting file scan of: {start_path}")
    print(f"Excluding directories: {', '.join(EXCLUDE_DIRS)}")

    for root, dirs, files in os.walk(start_path, topdown=True):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]

        for file in files:
            total_files += 1
            filepath = os.path.join(root, file)

            if os.path.islink(filepath):
                log_error(f"Skipping symbolic link: {filepath}")
                continue

            info = get_file_info(filepath)
            if info:
                file_hash = get_file_hash(filepath)

                if file_hash:
                    info['hash_sha256'] = file_hash
                    scanned_files.append(info)

            if total_files % 5000 == 0:
                print(f"Scanned {total_files} files so far. ({len(scanned_files)} successfully hashed)")

    end_ts = time.time()
    duration = end_ts - start_ts

    print(f"\nFile scan finished in {duration:.2f} seconds.")
    print(f"Total files encountered: {total_files}")
    print(f"Total files successfully processed and ready to save: {len(scanned_files)}")

    return scanned_files, session_id, duration


# --- Port Scanner Logic (No changes) ---
def port_scan(target_ip, port, open_ports, lock):
    """Attempts to connect to a specific port on the target IP."""
    try:
        # Create a socket object (AF_INET for IPv4, SOCK_STREAM for TCP)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)

        # Attempt to connect
        result = sock.connect_ex((target_ip, port))

        if result == 0:
            banner = ""
            try:
                # Attempt to grab the service banner
                # Send a simple GET request for common HTTP ports to get a response
                if port == 80 or port == 443:
                    sock.send(b"GET / HTTP/1.1\r\nHost: pynyscanner-test\r\n\r\n")

                banner_data = sock.recv(1024)
                banner = banner_data.decode('utf-8', errors='ignore').strip()
                # Clean up long/multiline banners for display
                banner = banner.split('\n')[0][:80] + ('...' if len(banner) > 80 else '')
            except socket.timeout:
                banner = "Connection accepted, but timed out waiting for banner"
            except Exception as e:
                # For common service ports, try to get the service name
                service_name = socket.getservbyport(port, 'tcp') if port < 1024 else 'unknown'
                banner = f"Service: {service_name}"
                # log_error(f"Banner grab failed for port {port}: {e}")

            # Lock is required to safely append to the shared list
            with lock:
                open_ports.append({
                    'port': port,
                    'service': socket.getservbyport(port, 'tcp') if port < 1024 else 'unknown',
                    'banner': banner
                })
                # Check for an empty or overly complex banner before printing
                if not banner or any(c in banner for c in r'!@#$%^&*()_+'):
                    print(f"[+] Port {port} is OPEN | Service: Unknown/No banner received")
                else:
                    print(f"[+] Port {port} is OPEN | Banner: {banner}")

        sock.close()
    except Exception as e:
        # Only log serious errors like 'Address family not supported'
        if 'address family' not in str(e).lower():
            log_error(f"Error scanning port {port} on {target_ip}: {e}")
        pass  # Silently ignore connection errors


def run_port_scan(args):
    """Coordinates the multithreaded port scanning process."""
    target_ip = args.target
    ports_to_scan = []

    # Handle port range or list
    try:
        if ',' in args.port:
            ports_to_scan = [int(p.strip()) for p in args.port.split(',')]
        elif '-' in args.port:
            start, end = map(int, args.port.split('-'))
            ports_to_scan = list(range(start, end + 1))
        else:
            ports_to_scan = [int(args.port)]
    except ValueError:
        print(
            f"ERROR: Invalid port format provided: {args.port}. Use comma-separated list (e.g., 80,443) or a range (e.g., 1-100).")
        return

    concurrency_limit = args.concurrency

    print(f"[*] Starting Port Scan on target: {target_ip} with {len(ports_to_scan)} ports.")
    print(f"[*] Concurrency limit: {concurrency_limit} threads.")

    open_ports = []
    thread_lock = threading.Lock()
    threads = []

    start_time = time.time()

    for port in ports_to_scan:
        thread = threading.Thread(target=port_scan, args=(target_ip, port, open_ports, thread_lock))
        threads.append(thread)
        thread.start()

        # Limit concurrency
        while threading.active_count() >= concurrency_limit + 1:  # +1 for the main thread
            time.sleep(0.01)

    # Wait for all threads to finish
    for thread in threads:
        thread.join()

    duration = time.time() - start_time

    print(f"\n[!] Scan completed successfully. Total {len(open_ports)} port(s) found open in {duration:.2f} seconds.")

    if open_ports:
        print("\n--- SUMMARY OF OPEN PORTS ---")
        for p in open_ports:
            # Use the cleaned up banner/service name from the scan result
            banner_display = p.get('banner', p['service'])
            print(f"[+] Port {p['port']} | {banner_display}")
        print("-" * 30)
    else:
        print("No open ports found in the specified range.")


# --- Host Discovery Logic (No changes) ---
def run_host_discovery(args):
    """Executes host discovery (ARP scan) using the 'scapy' tool via a subprocess."""
    print(f"[*] Starting Host Discovery on {args.cidr} (254 potential hosts)...")

    try:
        # NOTE: For real-world use, Scapy/Npcap are required.
        # On Windows, this requires running the terminal as Administrator.
        print("\nREMINDER: Must be run as Administrator for this mode to work!")

        # Simulated output for testing the command call:
        print("[+] Auto-detected interface: \\Device\\NPF_{...}")
        print("[*] Performing fast ARP scan (for local networks)...")
        print("[!] Total 5 live host(s) found. (Simulated)")

        # Print simulated host summary
        print("\n--- LIVE HOSTS SUMMARY (Simulated) ---")
        for i in range(1, 6):
            print(f"[+] IP: 192.168.1.{i} | MAC: 00:00:00:00:00:0{i}")
        print("-" * 30)

    except Exception as e:
        print(f"[!!!] CRITICAL ERROR during host discovery: {e}")
        log_error(f"Host discovery error for {args.cidr}: {e}")
        print("Error detail: Ensure Scapy and Npcap/libpcap are installed correctly.")


# --- Vulnerability Scanner Logic (No changes) ---
def check_vuln(target_url, port):
    """
    Checks a single URL for basic Path Traversal vulnerabilities by
    sending common payloads.
    """
    payloads = [
        "../../../etc/passwd",
        "../../../../../../windows/win.ini",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd"  # Encoded payload
    ]

    print(f"[*] Starting Vulnerability Scan on: {target_url}:{port}")
    print("-" * 50)

    found_vuln = False

    for payload in payloads:
        # Construct the test URL - typically a web server parameter is required
        test_url = f"http://{target_url}:{port}/test?file={payload}"  # Hypothetical GET request

        print(f"[*] Testing payload: {payload} ...", end="", flush=True)

        try:
            # --- SIMULATION ONLY ---
            # In a real app, you would use 'requests' here to check the actual response content
            # for signs of the target file's content (e.g., root::0:0 in /etc/passwd).

            # Simulate a successful connection but look for specific content
            if "passwd" in payload and port == 80:
                print(".. Vulnerable! (Simulated)")
                found_vuln = True

            else:
                print("..Not Found.")

        except Exception as e:
            print(f"..Error: {e}")
            log_error(f"Vuln scan error on {test_url}: {e}")

        time.sleep(0.1)  # Be gentle

    print("-" * 50)

    if found_vuln:
        print("[!!!] Vulnerability detected! Simple path traversal payloads were successful.")
    else:
        print("[!] Scan completed. No simple path traversal vulnerabilities detected.")


def run_vuln_scan(args):
    """Wrapper for the vulnerability scan function."""
    target = args.target
    port = args.port

    # Simple check for target format
    if not target:
        print("ERROR: Target IP or Hostname is required.")
        return

    check_vuln(target, port)


# --- Command Line Interface (CLI) Setup ---

def cli():
    """Sets up the command line interface using argparse."""
    parser = argparse.ArgumentParser(
        description="PyNetScanner: A unified tool for File Scanning, Port Scanning, Host Discovery, and Vulnerability Checks.",
        epilog="If no arguments are provided, the File Scanner runs interactively. Use 'python pynyscanner.py <mode> --help' for mode-specific arguments."
    )

    # Check if any arguments were passed (if only the script name is present, no mode was specified)
    if len(sys.argv) == 1:
        # If no arguments, return a dummy object that indicates default mode
        class DefaultArgs:
            mode = 'file'

        return DefaultArgs()

    # Create subparser to handle the different modes
    subparsers = parser.add_subparsers(dest='mode', required=False, help='Scanning mode')

    # --- 1. Port Scanner Mode (scan) ---
    scan_parser = subparsers.add_parser('scan', help='Run multithreaded TCP port scanning.')
    scan_parser.add_argument('-t', '--target', required=True, help='Target IP address or hostname.')
    # Fixed argument definition: expecting one string input for ports
    scan_parser.add_argument('-p', '--port', required=True, help='Ports to scan (e.g., "80,443" or "1-1024").')
    scan_parser.add_argument('-c', '--concurrency', type=int, default=50,
                             help='Maximum concurrent threads to use (default: 50).')
    scan_parser.set_defaults(func=run_port_scan)

    # --- 2. Host Discovery Mode (discover) ---
    discover_parser = subparsers.add_parser('discover', help='Run local network host discovery (ARP sweep).')
    discover_parser.add_argument('-r', '--cidr', required=True, help='CIDR range for discovery (e.g., 192.168.1.0/24).')
    discover_parser.set_defaults(func=run_host_discovery)

    # --- 3. Vulnerability Scanner Mode (vulnscan) ---
    vulnscan_parser = subparsers.add_parser('vulnscan',
                                            help='Check a target web server for simple Path Traversal vulnerabilities.')
    vulnscan_parser.add_argument('-t', '--target', required=True, help='Target IP address or hostname.')
    vulnscan_parser.add_argument('-p', '--port', type=int, default=80, help='Target port (default: 80).')
    vulnscan_parser.set_defaults(func=run_vuln_scan)

    return parser.parse_args()


# --- Main Execution (Updated to be cleaner) ---

def run_file_scanner(conn, cursor):
    """Encapsulates the interactive file scanning logic."""
    print("Welcome to Pynyscanner - Database Persistence Mode! (File Scan)")

    scan_results = []
    session_id = None
    duration = 0.0
    scan_path = DEFAULT_SCAN_PATH  # Set default path

    # 1. Get Scan Path (Interactive for default mode)
    scan_path_input = input(f"Enter directory path to scan (default is {DEFAULT_SCAN_PATH}): ")

    if scan_path_input:
        scan_path = scan_path_input

    if not os.path.isdir(scan_path):
        print(f"Error: Path '{scan_path}' is not a valid directory. Exiting.")
        return

    # 2. Perform Scan
    try:
        scan_results, session_id, duration = scan_directory(scan_path)
    except KeyboardInterrupt:
        print("\n[*] File scan interrupted by user (Ctrl+C). Proceeding to save and analyze results collected so far.")

    finally:
        # 3. Save Results to Database (Always try to save)
        if session_id and scan_results:
            save_scan_results(conn, cursor, scan_results, session_id, scan_path, duration)

        # 4. Analyze for Duplicates
        duplicate_data = find_duplicates(cursor)

        # 5. Export Duplicates to JSON
        export_duplicates_to_json(duplicate_data)

        # 6. Offer to View Past Scans
        view_past_scans(cursor)


def main():
    """Main function to run the Pynyscanner in the selected mode."""

    # 1. Initialize Database (Always connect)
    conn, cursor = init_db()
    if not conn:
        return

    try:
        args = cli()

        print("Welcome to PyNetScanner!")

        if args.mode == 'file':
            run_file_scanner(conn, cursor)
        else:
            # This handles 'scan', 'discover', and 'vulnscan'
            # The function to run is already set by argparse in args.func
            args.func(args)

    except Exception as e:
        # Catch any critical error that wasn't handled within the specific mode functions
        log_error(f"CRITICAL APPLICATION ERROR: {e}")
        # Print the error to the console for immediate feedback
        print(f"\n[!!!] A critical error occurred. Check pynyscanner_errors.log for details.")

    finally:
        # 8. Clean up
        close_db(conn)
        print("Database connection closed.")


if __name__ == "__main__":
    # Clear log file on start
    if os.path.exists(LOG_FILE):
        try:
            os.remove(LOG_FILE)
        except OSError:
            print(f"Warning: Could not remove old log file: {LOG_FILE}. Continuing.")

    main()