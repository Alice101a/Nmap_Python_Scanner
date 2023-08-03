import nmap

def scan_for_open_ports(target_ip):
    nm = nmap.PortScanner()
    nm.scan(hosts=target_ip, arguments='-T4 -F')

    for host in nm.all_hosts():
        print(f"Host: {host}")
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                print(f"Port: {port} => State: {nm[host][proto][port]['state']}")

if __name__ == "__main__":
    target_ip = "127.0.0.1"
    scan_for_open_ports(target_ip)
