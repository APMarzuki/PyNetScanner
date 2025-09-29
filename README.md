PyNetScanner: Unified Network Analysis Tool
PyNetScanner is a modular, command-line utility built in Python for basic network reconnaissance and security assessment. It provides a simple, unified interface for three common networking tasks.

Features
Port Scanning (scan): Performs fast, multithreaded TCP port scanning and attempts to grab basic service banners.

Host Discovery (discover): Executes an ARP sweep on a local network range to identify all live hosts (requires elevated privileges).

Vulnerability Scanning (vulnscan): Conducts a basic, signature-based check for common Path Traversal vulnerabilities on a target web server.

Setup and Installation
Prerequisites
You must have Python 3 installed. For the discover mode, you will need the Scapy library, which may also require the Npcap driver (especially on Windows) for raw packet transmission.

Install Npcap/WinPcap (Windows users only): Download and install the appropriate driver for your system.

Install Python Dependencies:

pip install scapy

Note: scapy often includes other necessary dependencies like argparse and ipaddress.

Running the Tool
Navigate to the project directory in your terminal.

Run the script using the desired subcommand (scan, discover, or vulnscan).

Usage Examples
PyNetScanner uses subcommands and arguments for execution. Remember to run the discover mode with Administrator/root privileges.

1. Port Scan Mode (scan)
Scans a range of TCP ports on a single target IP address.

Argument

Description

Example Value

-t / --target

Target IP address or hostname.

127.0.0.1

-p / --ports

Ports to scan (comma-separated or range).

1-1000 or 21,22,80,443

-c / --concurrency

Number of threads to use (optional, default 20).

-c 50

Example:

python pynyscanner.py scan -t 192.168.1.1 -p 1-1000

2. Host Discovery Mode (discover)
Performs a fast ARP sweep to find all live devices on a local subnet.

Argument

Description

Example Value

-r / --range

IP range in CIDR notation.

192.168.100.0/24

-i / --interface

Network interface name (optional, e.g., 'Wi-Fi' or 'eth0').

-i "Wi-Fi"

Example:

python pynyscanner.py discover -r 192.168.100.0/24

3. Vulnerability Scan Mode (vulnscan)
Checks a target web server for basic Path Traversal vulnerabilities by testing system file paths.

Argument

Description

Default

-t / --target

Target IP address or hostname.

N/A

-p / --port

Target port.

80

Example:

python pynyscanner.py vulnscan -t 127.0.0.1 -p 8080
