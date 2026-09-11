#!/usr/bin/env python3
"""
ReconX - A fast, multithreaded TCP port scanner
Author: Frostcy

Usage:
    reconx <target> -p <ports> [options]

Examples:
    reconx 192.168.1.1 -p 1-1000
    reconx example.com -p 22,80,443 -o results.json
    reconx 10.0.0.5 -p 1-65535 -t 200
"""

import socket
import threading
import argparse
import sys
import time
import json
import csv
import subprocess
import re
from queue import Queue
from datetime import datetime

# ---------------------------------------------------------------------------
# Colors for terminal output (ANSI codes, no external deps needed)
# ---------------------------------------------------------------------------
class C:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    END = "\033[0m"


BANNER = rf"""{C.CYAN}{C.BOLD}
 ____                      __  __
|  _ \ ___  ___ ___  _ __  \ \/ /
| |_) / _ \/ __/ _ \| '_ \  \  /
|  _ <  __/ (_| (_) | | | | /  \
|_| \_\___|\___\___/|_| |_|/_/\_\

        ReconX Port Scanner  |  by Frostcy
{C.END}"""

# Small well-known service map (extend as needed)
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MSRPC",
    139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 1723: "PPTP", 3306: "MySQL",
    3389: "RDP", 5900: "VNC", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
}


def parse_ports(port_str):
    """Parse '80,443' or '1-1000' or mixed '22,80,1000-2000' into a list."""
    ports = set()
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            ports.update(range(int(start), int(end) + 1))
        elif part:
            ports.add(int(part))
    return sorted(p for p in ports if 1 <= p <= 65535)


def resolve_target(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        print(f"{C.RED}[!] Could not resolve host: {target}{C.END}")
        sys.exit(1)


def grab_banner(sock):
    """Try to read a short service banner from an open socket."""
    try:
        sock.settimeout(0.8)
        data = sock.recv(128)
        if data:
            return data.decode(errors="ignore").strip().replace("\n", " ")[:60]
    except Exception:
        pass
    return ""


def os_fingerprint(ip):
    """
    Lightweight OS guess based on ICMP TTL (like a simplified version of
    nmap's TTL-based OS hints). Not as accurate as full TCP/IP stack
    fingerprinting, but good enough for a resume-project heuristic.
    """
    try:
        proc = subprocess.run(
            ["ping", "-c", "1", "-W", "1", ip],
            capture_output=True, text=True, timeout=3
        )
        match = re.search(r"ttl=(\d+)", proc.stdout, re.IGNORECASE)
        if not match:
            return "Unknown (host did not respond to ping)"

        ttl = int(match.group(1))
        if ttl <= 64:
            guess = "Linux / Unix (likely)"
        elif ttl <= 128:
            guess = "Windows (likely)"
        else:
            guess = "Network device / Solaris (likely)"
        return f"{guess} — TTL={ttl}"
    except Exception:
        return "Unknown (fingerprinting failed)"


def scan_port(ip, port, timeout, results, lock, grab, retries=1):
    """Try to connect to a port, retrying on failure/timeout before
    marking it closed. A single dropped attempt under thread load
    shouldn't produce a false negative on a genuinely open port."""
    for attempt in range(retries + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            result = sock.connect_ex((ip, port))
            if result == 0:
                service = COMMON_PORTS.get(port, "unknown")
                banner = grab_banner(sock) if grab else ""
                with lock:
                    results.append({"port": port, "service": service, "banner": banner})
                return
        except Exception:
            pass
        finally:
            sock.close()


def worker(ip, q, timeout, results, lock, grab, progress, retries):
    while not q.empty():
        try:
            port = q.get_nowait()
        except Exception:
            return
        scan_port(ip, port, timeout, results, lock, grab, retries)
        with lock:
            progress[0] += 1
        q.task_done()


def run_scan(target, ports, threads, timeout, grab, retries=1):
    ip = resolve_target(target)
    print(f"{C.YELLOW}[*] Target:{C.END} {target} ({ip})")
    print(f"{C.YELLOW}[*] Ports:{C.END}  {len(ports)} port(s)")
    print(f"{C.YELLOW}[*] Threads:{C.END} {threads}\n")

    q = Queue()
    for p in ports:
        q.put(p)

    results = []
    lock = threading.Lock()
    progress = [0]
    total = len(ports)

    start = time.time()
    thread_list = []
    for _ in range(min(threads, total or 1)):
        t = threading.Thread(target=worker, args=(ip, q, timeout, results, lock, grab, progress, retries))
        t.daemon = True
        t.start()
        thread_list.append(t)

    # Simple progress indicator
    while any(t.is_alive() for t in thread_list):
        with lock:
            done = progress[0]
        pct = (done / total * 100) if total else 100
        print(f"\r{C.CYAN}[+] Scanning... {done}/{total} ({pct:.1f}%){C.END}", end="", flush=True)
        time.sleep(0.2)

    for t in thread_list:
        t.join()

    elapsed = time.time() - start
    print(f"\r{C.CYAN}[+] Scan complete in {elapsed:.2f}s{' ' * 20}{C.END}\n")

    results.sort(key=lambda r: r["port"])
    return ip, results, elapsed


def print_results(ip, results):
    if not results:
        print(f"{C.RED}[-] No open ports found.{C.END}")
        return

    print(f"{C.BOLD}{'PORT':<12}{'STATE':<8}{'SERVICE':<15}{'BANNER'}{C.END}")
    print("-" * 60)
    for r in results:
        port_label = f"{r['port']}/tcp"
        banner = r["banner"] if r["banner"] else "-"
        print(f"{port_label:<12}{C.GREEN}{'open':<8}{C.END}{r['service']:<15}{banner}")
    print(f"\n{C.YELLOW}[*] {len(results)} open port(s) found on {ip}{C.END}")


def export_results(ip, results, elapsed, target, filepath, os_guess=None):
    data = {
        "target": target,
        "ip": ip,
        "scan_time": datetime.now().isoformat(),
        "duration_seconds": round(elapsed, 2),
        "open_ports": results,
    }
    if os_guess:
        data["os_guess"] = os_guess
    if filepath.endswith(".json"):
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)
    elif filepath.endswith(".csv"):
        with open(filepath, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["port", "service", "banner"])
            for r in results:
                writer.writerow([r["port"], r["service"], r["banner"]])
    else:
        # default to json if no known extension given
        filepath = filepath + ".json"
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)
    print(f"{C.CYAN}[+] Results saved to {filepath}{C.END}")


EPILOG = """
examples:
  reconx 192.168.1.1                       scan ALL 65535 ports (default — nothing skipped)
  reconx example.com -p 22,80,443          scan specific ports only (much faster)
  reconx 10.0.0.5 -p 1-1000 -t 100          scan a smaller range with fewer threads
  reconx 192.168.1.1 -b                    grab service banners
  reconx 192.168.1.1 -X                    full scan: banners + OS guess (like nmap -A)
  reconx 192.168.1.1 -o out.json           save results to a file

notes:
  Default scans every port (1-65535) so nothing is missed — this is slower
  than a top-ports scan but thorough. Narrow with -p for a quicker scan.
  Each port gets 1 retry by default (-r) to avoid false negatives from a
  dropped connection attempt under thread load.
  -X performs a heuristic OS guess using ICMP TTL analysis. It is not as
  precise as full TCP/IP stack fingerprinting (e.g. nmap -O), but gives a
  reasonable hint without needing raw sockets / root privileges.
"""


def main():
    parser = argparse.ArgumentParser(
        prog="reconx",
        description="ReconX - A fast, multithreaded TCP port scanner",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("-p", "--ports", default="1-65535",
                         help="Ports to scan, e.g. '80,443' or '1-1000' "
                              "(default: 1-65535, i.e. every port — nothing gets skipped)")
    parser.add_argument("-t", "--threads", type=int, default=300,
                         help="Number of concurrent threads (default: 300 — full range scans "
                              "benefit from more threads)")
    parser.add_argument("--timeout", type=float, default=1.0,
                         help="Per-port connection timeout in seconds (default: 1.0)")
    parser.add_argument("-r", "--retries", type=int, default=1,
                         help="Retry attempts per port before marking closed (default: 1)")
    parser.add_argument("-b", "--banner", action="store_true",
                         help="Attempt to grab service banners from open ports")
    parser.add_argument("-X", "--full", action="store_true",
                         help="Full scan: banner grabbing + OS fingerprint guess (like nmap -A)")
    parser.add_argument("-o", "--output", help="Save results to file (.json or .csv)")
    parser.add_argument("--no-banner-art", action="store_true",
                         help="Suppress the ASCII art banner on startup")
    parser.add_argument("-v", "--version", action="version", version="ReconX 1.1")

    args = parser.parse_args()

    if args.full:
        args.banner = True

    if not args.no_banner_art:
        print(BANNER)

    try:
        ports = parse_ports(args.ports)
    except ValueError:
        print(f"{C.RED}[!] Invalid port format. Use e.g. '80,443' or '1-1000'{C.END}")
        sys.exit(1)

    if not ports:
        print(f"{C.RED}[!] No valid ports to scan.{C.END}")
        sys.exit(1)

    os_guess = None
    if args.full:
        print(f"{C.YELLOW}[*] Running OS fingerprint...{C.END}")
        os_guess = os_fingerprint(args.target)

    try:
        ip, results, elapsed = run_scan(args.target, ports, args.threads, args.timeout, args.banner, args.retries)
    except KeyboardInterrupt:
        print(f"\n{C.RED}[!] Scan interrupted by user.{C.END}")
        sys.exit(1)

    print_results(ip, results)

    if args.full:
        print(f"\n{C.BOLD}OS Guess:{C.END} {os_guess}")

    if args.output:
        export_results(ip, results, elapsed, args.target, args.output, os_guess)


if __name__ == "__main__":
    main()
