import socket
import threading
import argparse
import itertools
import ipaddress

class PortScanner:
    """Module for port scanning."""

    def __init__(self, target, ports):
        self.target = target
        self.ports = ports

    def scan_port(self, port):
        """Scans a single port."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))
            if result == 0:
                print(f"Port {port} is open")
            sock.close()
        except Exception as e:
            print(f"Error scanning port {port}: {e}")

    def run(self):
        """Runs the port scanner."""
        threads = []
        for port in self.ports:
            thread = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

class BruteForcer:
    """Module for brute-forcing."""

    def __init__(self, target, username, password_list):
        self.target = target
        self.username = username
        self.password_list = password_list

    def brute_force(self, password):
        """Attempts to brute-force with a single password."""
        try:
            # Replace with your actual brute-forcing logic (e.g., SSH, FTP)
            # This is a placeholder for demonstration purposes.
            print(f"Trying password: {password}") #replace this with actual login attempt.
            # Example SSH implementation (requires paramiko):
            # import paramiko
            # ssh = paramiko.SSHClient()
            # ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            # try:
            #   ssh.connect(self.target, username=self.username, password=password, timeout=5)
            #   print(f"Password found: {password}")
            #   ssh.close()
            #   return True
            # except paramiko.AuthenticationException:
            #   return False
            # except Exception as e:
            #   print(f"Error: {e}")
            #   return False
            return False #placeholder.
        except Exception as e:
            print(f"Error brute-forcing with password {password}: {e}")
            return False

    def run(self):
        """Runs the brute-forcer."""
        for password in self.password_list:
            if self.brute_force(password):
                break

def parse_ports(port_range_str):
    """Parses a port range string (e.g., "22,80,443,100-200")."""
    ports = []
    ranges = port_range_str.split(',')
    for r in ranges:
        if '-' in r:
            start, end = map(int, r.split('-'))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(r))
    return ports

def parse_ip_range(ip_range_str):
    """Parses an IP range string (e.g., "192.168.1.0/24")."""
    try:
        return [str(ip) for ip in ipaddress.IPv4Network(ip_range_str, strict=False)]
    except ValueError:
        return [ip_range_str] #If it is not an IP range, return the single IP.

def main():
    """Main function to run the toolkit."""
    parser = argparse.ArgumentParser(description="Penetration Testing Toolkit")
    parser.add_argument("-t", "--target", help="Target IP address or hostname")
    parser.add_argument("-p", "--ports", help="Ports to scan (e.g., 22,80,443,100-200)")
    parser.add_argument("-u", "--username", help="Username for brute-forcing")
    parser.add_argument("-P", "--password_list", help="Password list file")
    parser.add_argument("-r", "--ip_range", help="IP range to scan (e.g., 192.168.1.0/24)")

    args = parser.parse_args()

    if args.target and args.ports:
        ports = parse_ports(args.ports)
        targets = parse_ip_range(args.target) #Allow IP Ranges.
        for target in targets:
            print(f"Scanning target: {target}")
            scanner = PortScanner(target, ports)
            scanner.run()

    if args.target and args.username and args.password_list:
        try:
            with open(args.password_list, "r") as f: