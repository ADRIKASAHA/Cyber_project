#!/usr/bin/env python3
import socket
import ssl
import json
import time
import re
from typing import List, Dict, Optional, Tuple

import requests
from tabulate import tabulate
import csv

# Optional: use nmap if installed
try:
    import nmap
    HAS_NMAP = True
except ImportError:
    HAS_NMAP = False

TIMEOUT = 5
USER_AGENT = "Lightweight-CVE-Scanner/1.0"
HEADERS = {"User-Agent": USER_AGENT}

# --- Banner grabbing ---
def grab_banner(host: str, port: int, use_tls: bool = False) -> str:
    banner = ""
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            sock.settimeout(TIMEOUT)
            s = sock
            if use_tls:
                context = ssl.create_default_context()
                s = context.wrap_socket(sock, server_hostname=host)
            # Try protocol-specific probes
            if port in (80, 8080, 8000, 8888):
                s.sendall(b"GET / HTTP/1.0\r\nHost: %b\r\n\r\n" % host.encode())
            elif port == 443:
                s.sendall(b"GET / HTTP/1.0\r\nHost: %b\r\n\r\n" % host.encode())
            elif port in (21, 22, 25, 110, 143, 993, 995):
                # Many services send banners on connect
                pass
            else:
                # Generic probe
                s.sendall(b"\r\n")
            data = s.recv(4096)
            banner = data.decode(errors="ignore")
    except Exception as e:
        banner = f"ERROR: {e}"
    return banner.strip()

# --- Nmap service detection (optional) ---
def nmap_detect(host: str, ports: List[int]) -> List[Dict]:
    if not HAS_NMAP:
        return []
    nm = nmap.PortScanner()
    port_str = ",".join(map(str, ports))
    try:
        nm.scan(hosts=host, arguments=f"-sV -p {port_str}")
    except Exception:
        return []
    results = []
    for h in nm.all_hosts():
        for proto in nm[h].all_protocols():
            for p in nm[h][proto].keys():
                svc = nm[h][proto][p]
                results.append({
                    "host": h,
                    "port": p,
                    "name": svc.get("name", ""),
                    "product": svc.get("product", ""),
                    "version": svc.get("version", ""),
                    "extrainfo": svc.get("extrainfo", ""),
                    "cpe": svc.get("cpe", "")
                })
    return results

# --- Simple banner parsing ---
def parse_service_from_banner(banner: str) -> Tuple[str, str]:
    if not banner or banner.startswith("ERROR"):
        return ("unknown", "")
    patterns = [
        r"Server:\s*([^\r\n]+)",
        r"^HTTP/[\d.]+\s.*\r?\n([^\r\n]+)",
        r"OpenSSH[_/ ]([\d.]+)",
        r"nginx/?\s*([\d.]+)?",
        r"Apache/?\s*([\d.]+)?",
        r"Postfix\s*([\d.]+)?",
        r"Exim\s*([\d.]+)?",
        r"vsftpd\s*([\d.]+)?",
        r"ProFTPD\s*([\d.]+)?",
    ]
    for pat in patterns:
        m = re.search(pat, banner, re.IGNORECASE | re.MULTILINE)
        if m:
            product_line = m.group(0)
            version = m.group(1) if m.lastindex else ""
            product = re.split(r"[:/ ]", product_line)[0]
            return (product.strip(), version.strip())
    tokens = re.split(r"[\r\n]", banner)
    first = tokens[0] if tokens else banner
    return (first[:32], "")

# --- CVE queries ---
def query_circl(product: str, version: str) -> List[Dict]:
    if not product:
        return []
    url = f"https://cve.circl.lu/api/search/{product}"
    try:
        r = requests.get(url, headers=HEADERS, timeout=10)
        if r.status_code == 200:
            data = r.json()
            results = []
            for item in data.get("results", []):
                summary = item.get("summary", "") or ""
                results.append({
                    "cve": item.get("id"),
                    "summary": summary,
                    "cvss": item.get("cvss", None)
                })
            return results[:20]
    except Exception:
        return []
    return []

def query_nvd(keyword: str) -> List[Dict]:
    if not keyword:
        return []
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"keywordSearch": keyword, "resultsPerPage": 20}
    try:
        r = requests.get(url, params=params, headers=HEADERS, timeout=10)
        if r.status_code == 200:
            data = r.json()
            out = []
            for v in data.get("vulnerabilities", []):
                cve = v.get("cve", {})
                metrics = cve.get("metrics", {})
                score = None
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if key in metrics and metrics[key]:
                        score = metrics[key][0]["cvssData"]["baseScore"]
                        break
                out.append({
                    "cve": cve.get("id"),
                    "summary": cve.get("descriptions", [{}])[0].get("value", ""),
                    "cvss": score
                })
            return out
    except Exception:
        return []
    return []

# --- Severity helper ---
def severity_label(score: Optional[float]) -> str:
    if score is None:
        return "Unknown"
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low"

# --- Main scan workflow ---
def scan_targets(targets: List[Tuple[str, int]]) -> List[Dict]:
    results = []
    for host, port in targets:
        use_tls = (port == 443)
        banner = grab_banner(host, port, use_tls=use_tls)
        product, version = parse_service_from_banner(banner)
        keyword = f"{product} {version}".strip()
        circl = query_circl(product, version)
        nvd = query_nvd(keyword)
        findings = circl + nvd
        seen = set()
        unique = []
        for f in findings:
            cid = f.get("cve")
            if cid and cid not in seen:
                seen.add(cid)
                unique.append(f)
        results.append({
            "host": host,
            "port": port,
            "banner": banner,
            "product": product,
            "version": version,
            "findings": unique
        })
        time.sleep(0.5)
    return results

def print_report(results: List[Dict]) -> str:
    rows = []
    for r in results:
        if not r["findings"]:
            rows.append([r["host"], r["port"], r["product"], r["version"], "-", "-", "No matches"])
            continue
        for f in r["findings"]:
            score = f.get("cvss")
            rows.append([
                r["host"],
                r["port"],
                r["product"],
                r["version"],
                f.get("cve"),
                severity_label(score),
                (f.get("summary") or "")[:120]
            ])
    headers = ["Host", "Port", "Product", "Version", "CVE", "Severity", "Summary"]
    report = tabulate(rows, headers=headers, tablefmt="github")
    print(report)
    return report

def save_report(results: List[Dict]) -> None:
    # Save as text
    report_text = print_report(results)
    with open("cve_report.txt", "w", encoding="utf-8") as f:
        f.write(report_text)

    # Save as CSV
    with open("cve_report.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Host","Port","Product","Version","CVE","Severity","Summary"])
        for r in results:
            if not r["findings"]:
                writer.writerow([r["host"], r["port"], r["product"], r["version"], "-", "-", "No matches"])
                continue
            for fnd in r["findings"]:
                writer.writerow([r["host"], r["port"], r["product"], r["version"],
                                 fnd.get("cve"), severity_label(fnd.get("cvss")), fnd.get("summary")])

if __name__ == "__main__":
    # Example targets—replace with your own
    targets = [
        ("example.com", 80),
        ("example.com", 443),
        ("127.0.0.1", 22),
    ]

    # Optional: enrich with nmap detection if installed
    #if HAS_NMAP:
       # nm_info = nmap_detect("127.0.0.1", [22, 80, 443])
       # for svc in nm_info:
          #  targets.append((svc["host"], svc["port"]))

    # Run the scan
    results = scan_targets(targets)

    # Print to terminal
    report_text = print_report(results)

    # Save to text file
    with open("cve_report.txt", "w", encoding="utf-8") as f:
        f.write(report_text)

    # Save to CSV file
    import csv
    with open("cve_report.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Host","Port","Product","Version","CVE","Severity","Summary"])
        for r in results:
            if not r["findings"]:
                writer.writerow([r["host"], r["port"], r["product"], r["version"], "-", "-", "No matches"])
                continue
            for fnd in r["findings"]:
                writer.writerow([
                    r["host"], r["port"], r["product"], r["version"],
                    fnd.get("cve"), severity_label(fnd.get("cvss")), fnd.get("summary")
                ])
