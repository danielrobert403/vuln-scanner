#!/usr/bin/env python3
"""
vuln_scanner.py
Basic vulnerability scanner: port scanning, banner grabbing, basic HTTP header checks.
Usage: python3 vuln_scanner.py --target example.com --ports 21,22,80,443 --threads 50 --output results.json
"""

import socket
import argparse
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import requests
from colorama import init, Fore, Style

# silence urllib3 warnings when verify=False used
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

init(autoreset=True)

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 139, 143, 161, 389, 443, 445, 587,
    636, 3306, 3389, 8080, 8443
]

def parse_args():
    p = argparse.ArgumentParser(description="Basic Vulnerability Scanner")
    p.add_argument("--target", required=True, help="Target domain or IP")
    p.add_argument("--ports", default=None, help="Comma-separated ports or range like 1-1024")
    p.add_argument("--threads", type=int, default=50, help="Threads for concurrent scanning")
    p.add_argument("--timeout", type=float, default=1.5, help="Socket timeout seconds")
    p.add_argument("--output", default=None, help="Output JSON filename (optional)")
    return p.parse_args()

def build_port_list(ports_arg):
    if not ports_arg:
        return COMMON_PORTS
    # support "80,443,8080" or "1-1024"
    parts = ports_arg.split(",")
    ports = set()
    for part in parts:
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            ports.update(range(int(a), int(b)+1))
        else:
            ports.add(int(part))
    return sorted(ports)

def scan_port(target_ip, port, timeout=1.5):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        start = time.time()
        s.connect((target_ip, port))
        duration = time.time() - start
        banner = None
        try:
            s.settimeout(1.0)
            banner = s.recv(1024).decode(errors="ignore").strip()
        except Exception:
            banner = None
        s.close()
        return {"port": port, "open": True, "banner": banner, "rtt": round(duration, 3)}
    except Exception:
        return {"port": port, "open": False, "banner": None, "rtt": None}

def http_header_check(target, timeout=3):
    hints = []
    url = None
    try:
        # try https first then http
        url = f"https://{target}"
        resp = requests.get(url, timeout=timeout, allow_redirects=True, verify=False)
    except Exception:
        try:
            url = f"http://{target}"
            resp = requests.get(url, timeout=timeout, allow_redirects=True)
        except Exception:
            return {"reachable": False, "url": None, "headers": None, "hints": ["No HTTP(S) service detected or blocked"]}

    headers = dict(resp.headers)
    # basic hints:
    if resp.status_code == 200 and "Strict-Transport-Security" not in headers and url.startswith("https://"):
        hints.append("No HSTS header present on HTTPS site (adds security risk).")
    if "X-Frame-Options" not in headers:
        hints.append("Missing X-Frame-Options header (clickjacking risk).")
    if "Content-Security-Policy" not in headers:
        hints.append("Missing Content-Security-Policy header (XSS protection improvement).")
    if "Server" in headers:
        server_banner = headers.get("Server")
        if any(x in server_banner.lower() for x in ["apache", "nginx", "iis"]):
            hints.append(f"Server header reveals server: {server_banner}")
    return {"reachable": True, "url": url, "headers": headers, "hints": hints}

def human_friendly_hint(port, banner):
    hints = []
    if port == 21:
        hints.append("FTP open — check for anonymous login and weak credentials.")
    if port == 22:
        hints.append("SSH open — ensure strong key-based auth and no password auth if possible.")
    if port in (80, 8080):
        hints.append("HTTP open — consider redirecting to HTTPS and check headers.")
    if port == 443:
        hints.append("HTTPS open — verify TLS configuration and use modern ciphers.")
    if port in (3306,):
        hints.append("Database exposed (MySQL) — should be internal-only.")
    if port in (3389,):
        hints.append("RDP exposed — ensure strong authentication or VPN access only.")
    if banner:
        low = banner.lower()
        if "openssl" in low or "apache" in low or "nginx" in low:
            hints.append(f"Banner reveals service/version: {banner}")
    return hints

def resolve_target(target):
    try:
        ip = socket.gethostbyname(target)
        return ip
    except Exception as e:
        raise RuntimeError(f"Cannot resolve target {target}: {e}")

def run_scan(target, ports, threads, timeout):
    target_ip = resolve_target(target)
    results = {"target": target, "ip": target_ip, "scanned_at": datetime.utcnow().isoformat()+"Z", "ports": [], "http": {}}
    with ThreadPoolExecutor(max_workers=threads) as exe:
        futures = {exe.submit(scan_port, target_ip, port, timeout): port for port in ports}
        for fut in as_completed(futures):
            r = fut.result()
            port = r["port"]
            r["hints"] = human_friendly_hint(port, r.get("banner"))
            results["ports"].append(r)

    # sort ports ascending
    results["ports"] = sorted(results["ports"], key=lambda x: x["port"])

    # do HTTP header checks if HTTP(S) ports open
    http_ports = [p for p in results["ports"] if p["open"] and p["port"] in (80, 443, 8080, 8443)]
    if http_ports:
        results["http"] = http_header_check(target, timeout=timeout)
    else:
        results["http"] = {"reachable": False}

    # Basic summary hints
    summary = []
    for p in results["ports"]:
        if p["open"]:
            if p["port"] in (21, 23, 3306, 3389):
                summary.append(f"Open sensitive port: {p['port']}")
    results["summary_hints"] = summary
    return results

def pretty_print(results):
    print(Fore.CYAN + f"\nScanning target: {results['target']} ({results['ip']})")
    print(Fore.CYAN + "-"*40)
    for p in results["ports"]:
        if p["open"]:
            print(Fore.GREEN + f"[OPEN] Port {p['port']:5d}   RTT={p['rtt']}s   Banner: {p['banner'] or 'N/A'}")
            if p["hints"]:
                for h in p["hints"]:
                    print(Fore.YELLOW + "  - " + h)
        else:
            print(Fore.WHITE + f"[CLOSED] Port {p['port']:5d}")
    print(Fore.CYAN + "-"*40)
    if results.get("http") and results["http"].get("reachable"):
        print(Fore.MAGENTA + f"HTTP reachable at {results['http']['url']}")
        for h in results["http"]["hints"]:
            print(Fore.YELLOW + "  - " + h)
    else:
        print(Fore.MAGENTA + "No HTTP(S) service detected on common ports.")
    if results.get("summary_hints"):
        print(Fore.RED + "\nPotential issues summary:")
        for s in results["summary_hints"]:
            print(Fore.RED + " - " + s)

def main():
    args = parse_args()
    ports = build_port_list(args.ports)
    print("Starting basic vuln scanner...")
    start = time.time()
    results = run_scan(args.target, ports, args.threads, args.timeout)
    duration = time.time() - start
    pretty_print(results)
    print("\nScan finished in %.2fs" % duration)
    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"Results written to {args.output}")

if __name__ == "__main__":
    main()
