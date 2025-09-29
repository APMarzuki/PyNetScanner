PyNetScanner: Unified Network Analysis Tool
PyNetScanner is a modular, command-line utility built in Python for basic network reconnaissance, security assessment, and local file integrity checking. It provides a simple, unified interface for four key operational modes.

Setup and Installation
This tool requires Python 3. You should install the necessary dependencies (like requests and scapy) using a virtual environment:

# Create a virtual environment (if you haven't already)
python -m venv .venv
# Activate the environment
# On Windows PowerShell:
.venv\Scripts\Activate.ps1
# On Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install requests
# Note: Host Discovery mode relies on Scapy, which often requires
# elevated privileges (sudo/Administrator) to function fully.
# If using Windows, you may need to install the Npcap driver for raw packet access.
pip install scapy

Usage
The tool operates via the command line using the format: python pynyscanner.py [mode] [arguments]

1. File Scanner Mode (Default)
Used for local file integrity checks, duplicate detection via SHA-256 hashing, and persistence to an SQLite database. If no mode is specified, this interactive mode runs by default.

Argument

Description

Example

(Interactive)

Prompts the user for a directory path and stores results in pynyscanner.db.

python pynyscanner.py

2. Port Scanner Mode (scan)
Performs a multithreaded TCP port scan to check for open ports and attempts to grab basic service banners.

Argument

Description

Default

Example

-t, --target

Target IP address or hostname.

N/A

-t 192.168.1.1

-p, --ports

Comma-separated list of ports (e.g., 80,443,22).

80,443,21,22

-p 20-100

-c, --concurrency

Max number of concurrent threads.

20

-c 10

Example: python pynyscanner.py scan -t 127.0.0.1 -p 80,443,22,21 -c 10

3. Vulnerability Scan Mode (vulnscan)
Conducts a basic, signature-based check for common Path Traversal vulnerabilities on a target web server.

Argument

Description

Default

Example

-t, --target

Target IP address or hostname.

N/A

-t 10.0.0.5

-p, --port

Target port.

80

-p 8080

Example: python pynyscanner.py vulnscan -t 127.0.0.1 -p 80

4. Host Discovery Mode (discover)
Executes an ARP sweep on a local network range to identify all live hosts. Requires elevated (Administrator/sudo) privileges.

Argument

Description

Default

Example

-r, --range

Network range in CIDR notation.

N/A

-r 192.168.1.0/24

Example: python pynyscanner.py discover -r 192.168.1.0/24
