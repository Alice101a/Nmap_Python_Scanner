# Nmap_Python_Scanner
The Python script is an enhanced and flexible port scanner using the nmap library. It allows users to scan multiple target IP addresses, detect open ports, and optionally enable service and version detection.


The Python script is an enhanced and flexible port scanner using the nmap library. It allows users to scan multiple target IP addresses, detect open ports, and optionally enable service and version detection. Users can customize the scan options and save the scan results to a file for later analysis.

Features:

Custom Scan Options: Users can specify custom Nmap scan options, such as -T4 for aggressive timing and -F for fast scan, or any other valid Nmap options.

Service and Version Detection: Users can choose to enable service and version detection during the scan. If enabled, the script will display detected services and their versions.

Saving Scan Results: Users can optionally save the scan results to a file in a human-readable format. The scan results include information about open ports, their states, and any detected services and versions.

IP Address Validation: The script validates the provided IP addresses to ensure they are valid IPv4 or IPv6 addresses.

Usage on Kali Linux:
To use the enhanced script on Kali Linux, follow these steps:

Save the code to a Python file (e.g., port_scanner.py) on your Kali Linux system.

Install the required Python library (python-nmap) if you haven't already:

pip install python-nmap


Run the script from the terminal with the desired options:

python port_scanner.py 192.168.1.1 192.168.1.2 -o '-T4 -F' --service-detect --version-detect -f scan_results.txt


Replace 192.168.1.1 and 192.168.1.2 with the target IP addresses you want to scan. You can provide as many IP addresses as needed. The script will display the open ports and their states for each target IP, along with detected service versions if available.

If you enable --service-detect or --version-detect, the script will also print the detected services and their versions. The scan results will be saved to a file named scan_results.txt.
