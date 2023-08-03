import nmap
import argparse
import os

def scan_for_open_ports(target_ips, scan_options='-T4 -F', service_detect=False, version_detect=False, output_file=None):
    nm = nmap.PortScanner()

    scan_options += ' -sV' if version_detect else ''
    scan_options += ' -sV -sC' if service_detect else ''

    results = {}

    for target_ip in target_ips:
        try:
            nm.scan(hosts=target_ip, arguments=scan_options)

            for host in nm.all_hosts():
                print(f"Scanning: {host}")

                if version_detect or service_detect:
                    results[host] = {}
                
                for proto in nm[host].all_protocols():
                    if version_detect or service_detect:
                        results[host][proto] = []

                    ports = nm[host][proto].keys()
                    for port in ports:
                        state = nm[host][proto][port]['state']
                        print(f"Port: {port} => State: {state}")

                        if 'product' in nm[host][proto][port] and 'version' in nm[host][proto][port]:
                            product = nm[host][proto][port]['product']
                            version = nm[host][proto][port]['version']
                            print(f"  Service: {product} {version}")
                            if version_detect or service_detect:
                                results[host][proto].append({'port': port, 'state': state, 'service': product, 'version': version})
                        
        except nmap.nmap.PortScannerError as e:
            print(f"Error while scanning {target_ip}: {e}")
    
    if output_file:
        save_results_to_file(results, output_file)

def save_results_to_file(results, output_file):
    with open(output_file, "w") as file:
        for host, protocols in results.items():
            file.write(f"Host: {host}\n")
            for proto, ports in protocols.items():
                file.write(f"Protocol: {proto}\n")
                for port_info in ports:
                    file.write(f"  Port: {port_info['port']} => State: {port_info['state']}\n")
                    file.write(f"    Service: {port_info['service']} {port_info['version']}\n")
            file.write("\n")

def validate_ips(ip_list):
    import ipaddress
    try:
        for ip in ip_list:
            ipaddress.ip_address(ip)
        return ip_list
    except ValueError:
        raise argparse.ArgumentTypeError("Invalid IP address provided.")

def validate_file(file_path):
    if not os.path.isfile(file_path):
        raise argparse.ArgumentTypeError("File not found.")
    return file_path

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Enhanced Port Scanner")
    parser.add_argument("target_ips", nargs="+", type=validate_ips, help="Target IP addresses to scan")
    parser.add_argument("-o", "--options", default='-T4 -F', help="Scan options (default: '-T4 -F')")
    parser.add_argument("--service-detect", action="store_true", help="Enable service detection")
    parser.add_argument("--version-detect", action="store_true", help="Enable version detection")
    parser.add_argument("-f", "--file", type=validate_file, help="Save scan results to a file")

    args = parser.parse_args()

    scan_for_open_ports(args.target_ips, args.options, args.service_detect, args.version_detect, args.file)

