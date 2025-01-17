import socket
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

# Map common ports to their services
COMMON_PORTS = {
    20: "FTP (Data Transfer)",
    21: "FTP (Control)",
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
}

# Function to scan a single port
def scan_port(target, port, open_ports):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)  # Timeout for faster scanning
            result = s.connect_ex((target, port))  # Returns 0 if successful
            if result == 0:
                # Port is open
                service = COMMON_PORTS.get(port, "Unknown Service")
                banner = grab_banner(s, target, port)
                open_ports.append((port, service, banner))
                print(f"[+] Port {port} is open ({service})")
                if banner:
                    print(f"    Banner: {banner}")
    except Exception as e:
        pass  # Ignore errors for closed or inaccessible ports

# Function to grab the banner from a port
def grab_banner(sock, target, port):
    try:
        sock.sendall(b"HEAD / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
        return sock.recv(1024).decode().strip()
    except Exception:
        return None

# Main port scanner function
def port_scanner(target, start_port, end_port, max_threads):
    print(f"Starting scan on target: {target}")
    print(f"Scanning ports {start_port} to {end_port}...\n")

    open_ports = []
    start_time = datetime.now()

    with ThreadPoolExecutor(max_threads) as executor:
        futures = [executor.submit(scan_port, target, port, open_ports) for port in range(start_port, end_port + 1)]
        for future in futures:
            future.result()  # Wait for all threads to complete

    end_time = datetime.now()
    duration = end_time - start_time

    # Save results to file
    save_results(target, open_ports, duration)

    # Print summary
    print("\nScan completed!")
    if open_ports:
        print("Open Ports:")
        for port, service, banner in open_ports:
            print(f"Port {port}: {service} ({banner or 'No banner'})")
    else:
        print("No open ports found.")
    print(f"Scan duration: {duration}")

# Save scan results to a file
def save_results(target, open_ports, duration):
    with open("scan_results.txt", "w") as file:
        file.write(f"Scan Results for {target}\n")
        file.write(f"Scan Duration: {duration}\n\n")
        if open_ports:
            file.write("Open Ports:\n")
            for port, service, banner in open_ports:
                file.write(f"Port {port}: {service} ({banner or 'No banner'})\n")
        else:
            file.write("No open ports found.\n")
    print("\n[+] Results saved to scan_results.txt")

# Main program loop
def main():
    print("Welcome to the Enhanced Port Scanner!")
    target = input("Enter the target IP or hostname: ").strip()
    start_port = int(input("Enter the starting port (default 1): ") or 1)
    end_port = int(input("Enter the ending port (default 1024): ") or 1024)
    max_threads = int(input("Enter the number of threads (default 50): ") or 50)

    print("\nInitializing scan...")
    port_scanner(target, start_port, end_port, max_threads)

if __name__ == "__main__":
    main()
