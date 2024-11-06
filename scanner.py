import socket
import ipaddress
import argparse
import time
import json
from concurrent.futures import ThreadPoolExecutor
import os

# Default configuration for easy customization
DEFAULT_PORT_RANGE = range(1, 10001)         # Default ports to scan if -p is not specified
DEFAULT_OUTPUT_FILE = "scan_results.json"    # Default output file for JSON results
DEFAULT_TIMEOUT = 1                          # Timeout in seconds for each port scan

# Port scanning function with results storage
def scan_port(target, port, results):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(DEFAULT_TIMEOUT)
    try:
        s.connect((target, port))
        results["open_ports"].append(port)
    except socket.error:
        results["closed_ports"].append(port)
    finally:
        s.close()

# Function to perform port scan and return results
def scan_ports(target, ports):
    print(f"\nStarting port scan on {target}...")
    start_time = time.time()
    results = {
        "host": target,
        "open_ports": [],
        "closed_ports": []
    }

    with ThreadPoolExecutor(max_workers=100) as executor:
        for port in ports:
            executor.submit(scan_port, target, port, results)
    
    end_time = time.time()
    results["scan_time"] = end_time - start_time
    print(f"Scan complete for {target}.")
    print(f"Open ports: {results['open_ports'] if results['open_ports'] else 'None'}")
    print(f"Total open ports: {len(results['open_ports'])}")
    print(f"Closed ports: {len(results['closed_ports'])}")
    print(f"Time taken: {results['scan_time']:.2f} seconds.\n")
    return results

# Host reachability check function
def check_host_alive(target):
    try:
        ip_address = socket.gethostbyname(target)
        print(f"Host {target} ({ip_address}) is up.")
        return {"host": target, "status": "up"}
    except socket.error:
        print(f"Host {target} is down or unreachable.")
        return {"host": target, "status": "down"}

# Function to get specified ports
def get_ports(args):
    if args.p == "-":
        return range(1, 65536)   # All ports
    elif args.p:
        return [int(p) for p in args.p.split(",")]  # Specific ports
    else:
        return DEFAULT_PORT_RANGE  # Default port range (1-10000)

# Scan hosts from a file, collecting results
def scan_hosts_from_file(filename, ports, check_only):
    results = []
    if os.path.exists(filename):
        with open(filename, "r") as file:
            hosts = file.read().splitlines()
        for host in hosts:
            if check_only:
                results.append(check_host_alive(host))
            else:
                results.append(scan_ports(host, ports))
    else:
        print(f"Error: File '{filename}' not found.")
    return results

# CIDR range scanning function
def scan_cidr(cidr, ports, check_only):
    network = ipaddress.ip_network(cidr, strict=False)
    print(f"\nScanning network: {cidr}")
    results = []
    for ip in network.hosts():
        ip_str = str(ip)
        if check_only:
            results.append(check_host_alive(ip_str))
        else:
            results.append(scan_ports(ip_str, ports))
    return results

# Save results to JSON file
def save_results_to_json(results, filename):
    with open(filename, "w") as file:
        json.dump(results, file, indent=4)
    print(f"\nResults saved to {filename}")

# Main function with improved help menu and user-friendly defaults
# Modify the argument parsing in the main function
def main():
    parser = argparse.ArgumentParser(
        description="Python Network Port Scanner\n\n"
                    "Options:\n"
                    "  <target>      Specify a target IP, hostname, CIDR (e.g., 192.168.1.0/24), or use -f to scan from a file.\n"
                    "  -p <ports>    Ports to scan, separated by commas (e.g., '80,443'). Use '-p-' to scan all ports (1-65535).\n"
                    "  -f <filename> Specify a file with a list of hosts to scan, one per line.\n"
                    "  -sn           Only check if hosts are alive without scanning ports.\n"
                    "  --discover    Discover available hosts in the specified network without scanning ports.\n"
                    "  -o <filename> Specify an output file to save the results in JSON format.\n\n",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument("target",
                        nargs="?",
                        help="Specify a target IP, hostname, CIDR (e.g., 192.168.1.0/24), or use -f to scan from a file.")
    parser.add_argument("-p",
                        help="Ports to scan, separated by commas (e.g., '80,443'). Use '-p-' to scan all ports (1-65535).",
                        default=None)
    parser.add_argument("-f",
                        help="Specify a file with a list of hosts to scan, one per line.")
    parser.add_argument("-sn",
                        action="store_true",
                        help="Only check if hosts are alive without scanning ports.")
    parser.add_argument("--discover",
                        action="store_true",
                        help="Discover available hosts in the specified network without scanning ports.")
    parser.add_argument("-o", "--output",
                        help="Specify an output file to save the results in JSON format.",
                        default=DEFAULT_OUTPUT_FILE)

    args = parser.parse_args()

    # Check if both target and file (-f) are missing, and display an error
    if not args.target and not args.f:
        parser.error("Either <target> or -f <filename> must be specified.")

    ports = get_ports(args)
    start_time = time.time()
    scan_results = []

    # Process based on the specified arguments
    if args.f:
        print(f"\nScanning hosts from file '{args.f}'...")
        scan_results = scan_hosts_from_file(args.f, ports, check_only=args.sn)
    elif args.discover:
        print(f"\nDiscovering live hosts in network '{args.target}'...")
        scan_results = scan_cidr(args.target, ports, check_only=True)
    elif "/" in args.target:
        print(f"\nScanning CIDR range '{args.target}'...")
        scan_results = scan_cidr(args.target, ports, check_only=args.sn)
    else:
        print(f"\nScanning target '{args.target}'...")
        if args.sn:
            scan_results.append(check_host_alive(args.target))
        else:
            scan_results.append(scan_ports(args.target, ports))

    end_time = time.time()
    print(f"\nTotal execution time: {end_time - start_time:.2f} seconds.")
    save_results_to_json(scan_results, filename=args.output)


if __name__ == "__main__":
    main()
