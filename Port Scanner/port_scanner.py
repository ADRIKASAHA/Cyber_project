import socket
import threading
import argparse
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(
    filename="port_scan.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def scan_port(host, port, timeout=1):
    """
    Attempt to connect to a given host and port.
    Logs and prints whether the port is open, closed, or timed out.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))  # 0 = success
        if result == 0:
            print(f"[OPEN]   {host}:{port}")
            logging.info(f"OPEN - {host}:{port}")
        else:
            print(f"[CLOSED] {host}:{port}")
            logging.info(f"CLOSED - {host}:{port}")
        sock.close()
    except socket.timeout:
        print(f"[TIMEOUT] {host}:{port}")
        logging.warning(f"TIMEOUT - {host}:{port}")
    except Exception as e:
        print(f"[ERROR] {host}:{port} -> {e}")
        logging.error(f"ERROR - {host}:{port} -> {e}")

def scan_range(host, start_port, end_port):
    """
    Scan a range of ports on a given host using threads.
    """
    print(f"\nStarting scan on {host} from port {start_port} to {end_port}")
    logging.info(f"Scanning {host} ports {start_port}-{end_port}")

    threads = []
    for port in range(start_port, end_port + 1):
        t = threading.Thread(target=scan_port, args=(host, port))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    print("\nScan complete.")
    logging.info("Scan complete.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple TCP Port Scanner")
    parser.add_argument("host", help="Target host (IP or domain)")
    parser.add_argument("-p", "--port", type=int, help="Single port to scan")
    parser.add_argument("-r", "--range", nargs=2, type=int, help="Range of ports to scan (start end)")
    args = parser.parse_args()

    start_time = datetime.now()
    print(f"Port scan started at {start_time}\n")

    if args.port:
        scan_port(args.host, args.port)
    elif args.range:
        scan_range(args.host, args.range[0], args.range[1])
    else:
        print("Please specify either a single port (-p) or a range (-r start end).")

    end_time = datetime.now()
    print(f"\nPort scan finished at {end_time}")
    print(f"Duration: {end_time - start_time}")
