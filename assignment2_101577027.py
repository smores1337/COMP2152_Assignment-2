"""
Author: Benz Stephen Farinas
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports
"""

import socket
import threading
import sqlite3
import os
import platform
import datetime

# Print Python version and OS name
print(f"Python Version: {platform.python_version()}")
print(f"Operating System: {os.name}")

# Dictionary that stores port numbers and the name of the service that uses that port
common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt"
}


class NetworkTool:
    def __init__(self, target):
        self.__target = target

    # Q3: What is the benefit of using @property and @target.setter?
    # Instead of letting any part of the program change the target directly,
    # @property and @target.setter act like a security guard — they control
    # how the target is read and changed. This way, we can add a rule that
    # stops someone from accidentally setting the target to an empty string,
    # which would break the scanner.
    @property
    def target(self):
        return self.__target

    @target.setter
    def target(self, value):
        if value == "":
            print("Error: Target cannot be empty")
        else:
            self.__target = value

    def __del__(self):
        print("NetworkTool instance destroyed")


# Q1: How does PortScanner reuse code from NetworkTool?
# PortScanner is built on top of NetworkTool, like a child class inheriting
# from a parent. This means PortScanner automatically gets the target storage,
# the getter, the setter, and the destructor from NetworkTool without writing
# them again. For example, calling super().__init__(target) lets PortScanner
# use NetworkTool's constructor to save the target IP address.
class PortScanner(NetworkTool):
    def __init__(self, target):
        super().__init__(target)
        self.scan_results = []
        self.lock = threading.Lock()

    def __del__(self):
        print("PortScanner instance destroyed")
        super().__del__()

    def scan_port(self, port):
        # Q4: What would happen without try-except here?
        # If we removed try-except and tried to scan a port that is not
        # reachable, Python would crash with an error and stop the whole
        # program. The try-except block catches that error quietly and lets
        # the program keep scanning the other ports without stopping.
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))
            status = "Open" if result == 0 else "Closed"
            service_name = common_ports.get(port, "Unknown")
            self.lock.acquire()
            self.scan_results.append((port, status, service_name))
            self.lock.release()
        except socket.error as e:
            print(f"Error scanning port {port}: {e}")
        finally:
            sock.close()

    def get_open_ports(self):
        return [result for result in self.scan_results if result[1] == "Open"]

    # Q2: Why do we use threading instead of scanning one port at a time?
    # Think of threading like having many workers doing tasks at the same time
    # instead of one worker doing everything one by one. If we scanned 1024
    # ports one at a time and each took 1 second to time out, it would take
    # over 17 minutes. With threading, all ports are checked at the same time,
    # so the whole scan finishes in just a few seconds.
    def scan_range(self, start_port, end_port):
        threads = []
        for port in range(start_port, end_port + 1):
            t = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(t)
        for t in threads:
            t.start()
        for t in threads:
            t.join()


def save_results(target, results):
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("""CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            port INTEGER,
            status TEXT,
            service TEXT,
            scan_date TEXT
        )""")
        for result in results:
            port, status, service = result
            cursor.execute(
                "INSERT INTO scans (target, port, status, service, scan_date) VALUES (?, ?, ?, ?, ?)",
                (target, port, status, service, str(datetime.datetime.now()))
            )
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        print(f"Database error: {e}")


def load_past_scans():
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans")
        rows = cursor.fetchall()
        if not rows:
            print("No past scans found.")
        for row in rows:
            _, target, port, status, service, scan_date = row
            print(f"[{scan_date}] {target} : Port {port} ({service}) - {status}")
        conn.close()
    except sqlite3.Error:
        print("No past scans found.")


if __name__ == "__main__":
    # Get the target IP
    target_ip = input("Enter target IP address (press Enter for 127.0.0.1): ").strip()
    if target_ip == "":
        target_ip = "127.0.0.1"

    # Getting start port
    start_port = None
    while start_port is None:
        try:
            start_port = int(input("Enter start port (1-1024): "))
            if not (1 <= start_port <= 1024):
                print("Port must be between 1 and 1024.")
                start_port = None
        except ValueError:
            print("Invalid input. Please enter a valid integer.")

    # Get end port
    end_port = None
    while end_port is None:
        try:
            end_port = int(input("Enter end port (1-1024): "))
            if not (1 <= end_port <= 1024):
                print("Port must be between 1 and 1024.")
                end_port = None
            elif end_port < start_port:
                print("End port must be greater than or equal to start port.")
                end_port = None
        except ValueError:
            print("Invalid input. Please enter a valid integer.")

    # Running scan
    scanner = PortScanner(target_ip)
    print(f"Scanning {target_ip} from port {start_port} to {end_port}...")
    scanner.scan_range(start_port, end_port)

    open_ports = scanner.get_open_ports()
    print(f"\n--- Scan Results for {target_ip} ---")
    for port, status, service in open_ports:
        print(f"Port {port}: {status} ({service})")
    print("------")
    print(f"Total open ports found: {len(open_ports)}")

    save_results(target_ip, scanner.scan_results)

    history = input("\nWould you like to see past scan history? (yes/no): ").strip().lower()
    if history == "yes":
        load_past_scans()

# Q5: New Feature Proposal
# A cool feature to add would be a risk checker that looks at all the open ports
# and warns you if any of them are known to be unsafe, like Telnet (port 23) or
# FTP (port 21). It would use a list comprehension like:
# risky = [p for p in open_ports if p[0] in risky_ports] to quickly find the
# dangerous ones and print a warning message for each one found.
# Diagram: See diagram_101577027.png in the repository root