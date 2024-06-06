#!/bin/python3

import argparse
import sys
import threading
from queue import Queue
import re
import requests
from bs4 import BeautifulSoup

VERSION = "v0.1.7b"
IPV4_REGEX = re.compile(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')

# Class to hold Shodan response data
class ShodanResponse:
    def __init__(self, ports, asn):
        self.ports = ports
        self.asn = asn

# Function to check domain and resolve its IP address
def check_domain(domain):
    try:
        response = requests.get(f'https://dns.google/resolve?name={domain}&type=A').json()
        ip = response['Answer'][0]['data']
        return ip
    except Exception as e:
        print(f"Failed to resolve {domain}: {e}")
        return None

# Function to fetch Shodan data for a given IP address
def fetch_shodan_data(ip_address, api_key):
    url = f"https://api.shodan.io/shodan/host/{ip_address}?key={api_key}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        ports = data.get('ports', [])
        asn = data.get('asn', '')
        return ShodanResponse(ports, asn)
    except Exception as e:
        print(f"Failed to fetch Shodan data for {ip_address}: {e}")
        return None

# Function to fetch IPs from Shodan based on a query
def fetch_ips_from_shodan(query, ipv4_only=False):
    url = f"https://www.shodan.io/search/facet?query={query}&facet=ip"
    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        ip_elements = soup.find_all('strong')
        ips = [element.text.replace('"', '').replace("'", "") for element in ip_elements]
        if ipv4_only:
            ips = [ip for ip in ips if IPV4_REGEX.match(ip)]
        return ips
    except Exception as e:
        print(f"Failed to fetch IPs from Shodan: {e}")
        return []

# Function to filter ports based on exclude_ports list
def filter_ports(ports, exclude_ports):
    return [port for port in ports if port not in exclude_ports]

# Worker function for each domain
def worker(domain, show_asn, show_ip, exclude_ports, output, lock, api_key, verbose=False):
    ip_address = check_domain(domain)
    if ip_address is None:
        return

    data = fetch_shodan_data(ip_address, api_key)
    if data is None:
        return

    if data.ports:
        asn = data.asn if show_asn else ""
        ip = ip_address if show_ip else ""
        ports = filter_ports(data.ports, exclude_ports)
        for port in ports:
            if verbose:
                output_str = f"{domain}:{port} {asn} {ip}\n"
            else:
                output_str = f"{domain}:{port}\n"
            with lock:
                output.write(output_str)
                output.flush()

# Function to process domains with threading
def check_domains(domains, threads, show_asn, show_ip, exclude_ports, output, api_key, verbose=False):
    queue = Queue()
    lock = threading.Lock()

    for domain in domains:
        queue.put(domain)

    def thread_worker():
        while not queue.empty():
            domain = queue.get()
            if domain is None:
                break
            worker(domain, show_asn, show_ip, exclude_ports, output, lock, api_key, verbose)
            queue.task_done()

    threads_list = []
    for _ in range(threads):
        t = threading.Thread(target=thread_worker)
        t.start()
        threads_list.append(t)

    for t in threads_list:
        t.join()

# Function to parse port string to a list of integers
def parse_ports(s):
    if not s:
        return []
    return [int(port) for port in s.split(',')]

# Main function
def main():
    parser = argparse.ArgumentParser(description='Spymap')
    parser.add_argument('-c', type=int, default=8, help='Number of threads to use')
    parser.add_argument('--asn', action='store_true', help='Show ASN')
    parser.add_argument('--ip', action='store_true', help='Show IP address')
    parser.add_argument('--exclude-ports', type=str, default='', help='Exclude ports (comma-separated)')
    parser.add_argument('-o', type=str, default='', help='Output file')
    parser.add_argument('-v', action='store_true', help='Prints current version')
    parser.add_argument('-s', type=str, required=False, help='Shodan API key')
    parser.add_argument('--dl', type=str, help='Shodan search query to download IPs')
    parser.add_argument('--ipv4-only', action='store_true', help='Download only IPv4 addresses')
    parser.add_argument('--file', type=str, help='File containing search queries')
    parser.add_argument('--verbose', action='store_true', help='Print verbose output')

    args = parser.parse_args()

    # Print version and exit if -v flag is provided
    if args.v:
        print(f"Spymap version: {VERSION}")
        sys.exit(0)

    # Parse exclude-ports argument
    exclude_ports = parse_ports(args.exclude_ports)

    # Set output file or default to stdout
    output = sys.stdout
    if args.o:
        try:
            output = open(args.o, 'w')
        except IOError as e:
            sys.stderr.write(f"error creating output file: {e}\n")
            sys.exit(1)

    # Download IPs from Shodan if --dl flag is provided
    if args.dl:
        ips = fetch_ips_from_shodan(args.dl, args.ipv4_only)
        if ips:
            with open("ips.txt", "w") as f:
                f.write("\n".join(ips))
            print("IPs downloaded and saved to ips.txt")
        else:
            print("No IPs found or failed to fetch IPs from Shodan")
        return

    # Process file containing search queries if --file flag is provided
    if args.file:
        with open(args.file, 'r') as file:
            queries = [line.strip() for line in file if line.strip()]
        all_ips = []
        for query in queries:
            query_formatted = f'ssl.cert.subject.CN%3A"{query}"+200+OK'
            ips = fetch_ips_from_shodan(query_formatted, args.ipv4_only)
            all_ips.extend(ips)
        if all_ips:
            with open("ips.txt", "w") as f:
                f.write("\n".join(all_ips))
            print("IPs downloaded and saved to ips.txt")
        else:
            print("No IPs found or failed to fetch IPs from Shodan")
        return

    domains = [line.strip() for line in sys.stdin if line.strip()]
    if not domains:
        print("No domains provided in stdin")
        sys.exit(1)

    check_domains(domains, args.c, args.asn, args.ip, exclude_ports, output, args.s, args.verbose)

    if args.o:
        output.close()

if __name__ == '__main__':
    main()
