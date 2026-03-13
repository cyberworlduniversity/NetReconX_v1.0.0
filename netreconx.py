#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════╗
║              NetReconX v1.0 - Network Recon Engine        ║
║         Inspired by Nmap + Shodan | Ethical Use Only      ║
║   Author: Your Name | For authorized pentesting ONLY      ║
╚═══════════════════════════════════════════════════════════╝

WARNING: Only use on systems you OWN or have WRITTEN permission to test.
Unauthorized scanning is illegal under the Computer Fraud and Abuse Act (CFAA)
and equivalent laws worldwide.

Requirements:
    pip install requests python-nmap colorama tabulate dnspython

Usage:
    python netreconx.py --target 192.168.1.1
    python netreconx.py --target example.com --ports 1-1000 --output report.html
    python netreconx.py --target 192.168.1.0/24 --mode full
"""

import argparse
import socket
import subprocess
import json
import os
import sys
import time
import threading
import ipaddress
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

# ── Optional imports with graceful fallback ────────────────────────────────────
try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

try:
    import nmap
    NMAP_OK = True
except ImportError:
    NMAP_OK = False

try:
    from colorama import init, Fore, Style, Back
    init(autoreset=True)
    COLORAMA_OK = True
except ImportError:
    COLORAMA_OK = False
    class _Stub:
        def __getattr__(self, _): return ""
    Fore = Style = Back = _Stub()

try:
    from tabulate import tabulate
    TABULATE_OK = True
except ImportError:
    TABULATE_OK = False

try:
    import dns.resolver
    DNS_OK = True
except ImportError:
    DNS_OK = False


# ══════════════════════════════════════════════════════════════════════════════
# CONSTANTS & CONFIG
# ══════════════════════════════════════════════════════════════════════════════

VERSION = "1.0.0"
BANNER = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║  {Fore.GREEN}███╗   ██╗███████╗████████╗██████╗ ███████╗ ██████╗ ███╗  ██╗{Fore.CYAN}  ║
║  {Fore.GREEN}████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██╔════╝██╔════╝ ████╗ ██║{Fore.CYAN}  ║
║  {Fore.GREEN}██╔██╗ ██║█████╗     ██║   ██████╔╝█████╗  ██║      ██╔██╗██║{Fore.CYAN}  ║
║  {Fore.GREEN}██║╚██╗██║██╔══╝     ██║   ██╔══██╗██╔══╝  ██║      ██║╚████║{Fore.CYAN}  ║
║  {Fore.GREEN}██║ ╚████║███████╗   ██║   ██║  ██║███████╗╚██████╗ ██║ ╚███║{Fore.CYAN}  ║
║  {Fore.GREEN}╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚══╝{Fore.CYAN}  ║
║          {Fore.YELLOW}Network Reconnaissance Engine v{VERSION}              {Fore.CYAN}     ║
║          {Fore.RED}⚠  FOR AUTHORIZED PENETRATION TESTING ONLY  ⚠       {Fore.CYAN}     ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""

# Common service banners / well-known ports
KNOWN_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 8888: "Jupyter", 9200: "Elasticsearch", 27017: "MongoDB",
}

# Severity mapping for open services
SERVICE_RISK = {
    "Telnet": "CRITICAL",   # unencrypted
    "FTP": "HIGH",          # often anonymous
    "RDP": "HIGH",
    "SMB": "HIGH",
    "NetBIOS": "HIGH",
    "VNC": "HIGH",
    "Redis": "HIGH",        # often unauthenticated
    "Elasticsearch": "HIGH",
    "MongoDB": "MEDIUM",
    "MySQL": "MEDIUM",
    "MSSQL": "MEDIUM",
    "PostgreSQL": "MEDIUM",
    "HTTP": "LOW",
    "HTTPS": "INFO",
    "SSH": "INFO",
    "DNS": "LOW",
}


# ══════════════════════════════════════════════════════════════════════════════
# UTILITIES
# ══════════════════════════════════════════════════════════════════════════════

def print_section(title: str):
    print(f"\n{Fore.CYAN}{'─'*62}")
    print(f"  {Fore.YELLOW}▶ {Fore.WHITE}{title}")
    print(f"{Fore.CYAN}{'─'*62}{Style.RESET_ALL}")


def print_ok(msg: str):
    print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} {msg}")


def print_warn(msg: str):
    print(f"  {Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")


def print_err(msg: str):
    print(f"  {Fore.RED}[-]{Style.RESET_ALL} {msg}")


def print_info(msg: str):
    print(f"  {Fore.BLUE}[*]{Style.RESET_ALL} {msg}")


def severity_color(severity: str) -> str:
    colors = {
        "CRITICAL": Fore.RED,
        "HIGH": Fore.YELLOW,
        "MEDIUM": Fore.CYAN,
        "LOW": Fore.GREEN,
        "INFO": Fore.BLUE,
    }
    return colors.get(severity, Fore.WHITE)


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 1 — DNS RESOLUTION & HOST DISCOVERY
# ══════════════════════════════════════════════════════════════════════════════

class DNSRecon:
    """Resolve hostnames, enumerate subdomains, pull DNS records."""

    RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    COMMON_SUBS = [
        "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
        "smtp", "secure", "vpn", "m", "shop", "ftp", "api", "dev", "staging",
        "admin", "portal", "cdn", "static", "assets", "support",
    ]

    def __init__(self, target: str):
        self.target = target
        self.results: dict = {"hostname": target, "records": {}, "subdomains": [], "ip": None}

    def resolve(self) -> Optional[str]:
        try:
            ip = socket.gethostbyname(self.target)
            self.results["ip"] = ip
            print_ok(f"Resolved {self.target} → {Fore.GREEN}{ip}")
            return ip
        except socket.gaierror as e:
            print_err(f"DNS resolution failed: {e}")
            return None

    def enumerate_records(self):
        if not DNS_OK:
            print_warn("dnspython not installed — skipping DNS record enumeration")
            return
        for rtype in self.RECORD_TYPES:
            try:
                answers = dns.resolver.resolve(self.target, rtype, lifetime=3)
                self.results["records"][rtype] = [str(r) for r in answers]
                print_ok(f"{rtype:6s} → {', '.join(str(r) for r in answers)}")
            except Exception:
                pass

    def enumerate_subdomains(self):
        print_info(f"Brute-forcing {len(self.COMMON_SUBS)} common subdomains...")
        found = []

        def check(sub):
            fqdn = f"{sub}.{self.target}"
            try:
                ip = socket.gethostbyname(fqdn)
                return (fqdn, ip)
            except socket.gaierror:
                return None

        with ThreadPoolExecutor(max_workers=30) as ex:
            futures = {ex.submit(check, s): s for s in self.COMMON_SUBS}
            for f in as_completed(futures):
                result = f.result()
                if result:
                    fqdn, ip = result
                    found.append({"subdomain": fqdn, "ip": ip})
                    print_ok(f"Found: {Fore.GREEN}{fqdn}{Style.RESET_ALL} → {ip}")

        self.results["subdomains"] = found
        print_info(f"Subdomain enumeration complete — {len(found)} found")

    def run(self) -> dict:
        print_section("DNS RESOLUTION & RECORD ENUMERATION")
        self.resolve()
        self.enumerate_records()
        self.enumerate_subdomains()
        return self.results


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 2 — PORT SCANNING
# ══════════════════════════════════════════════════════════════════════════════

class PortScanner:
    """TCP connect port scanner with banner grabbing."""

    def __init__(self, host: str, port_range: tuple = (1, 1024), timeout: float = 1.0, threads: int = 200):
        self.host = host
        self.start_port, self.end_port = port_range
        self.timeout = timeout
        self.threads = threads
        self.open_ports: list = []
        self._lock = threading.Lock()
        self._scanned = 0
        self._total = self.end_port - self.start_port + 1

    def _scan_port(self, port: int):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                result = s.connect_ex((self.host, port))
                if result == 0:
                    banner = self._grab_banner(s, port)
                    service = KNOWN_PORTS.get(port, "Unknown")
                    risk = SERVICE_RISK.get(service, "INFO")
                    with self._lock:
                        self.open_ports.append({
                            "port": port,
                            "state": "open",
                            "service": service,
                            "banner": banner,
                            "risk": risk,
                        })
                        print_ok(
                            f"Port {Fore.GREEN}{port:5d}{Style.RESET_ALL}/tcp  "
                            f"{Fore.CYAN}{service:<15}{Style.RESET_ALL}  "
                            f"{severity_color(risk)}[{risk}]{Style.RESET_ALL}"
                            + (f"  {banner[:60]}" if banner else "")
                        )
        except Exception:
            pass
        finally:
            with self._lock:
                self._scanned += 1

    def _grab_banner(self, sock: socket.socket, port: int) -> str:
        """Try to grab service banner."""
        try:
            # Send HTTP request for web ports
            if port in (80, 8080, 8888):
                sock.sendall(b"HEAD / HTTP/1.0\r\nHost: " + self.host.encode() + b"\r\n\r\n")
            elif port == 22:
                pass  # SSH sends banner automatically
            else:
                sock.sendall(b"\r\n")
            sock.settimeout(2)
            return sock.recv(256).decode("utf-8", errors="ignore").strip().split("\n")[0]
        except Exception:
            return ""

    def scan(self) -> list:
        print_section(f"PORT SCAN  {self.host}  [{self.start_port}–{self.end_port}]")
        print_info(f"Scanning {self._total} ports with {self.threads} threads, timeout={self.timeout}s")
        start = time.time()

        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            ex.map(self._scan_port, range(self.start_port, self.end_port + 1))

        elapsed = time.time() - start
        self.open_ports.sort(key=lambda x: x["port"])
        print_info(f"Scan complete in {elapsed:.1f}s — {len(self.open_ports)} open port(s) found")
        return self.open_ports


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 3 — OS & SERVICE FINGERPRINTING (nmap wrapper)
# ══════════════════════════════════════════════════════════════════════════════

class Fingerprinter:
    """Use python-nmap for OS detection and service version fingerprinting."""

    def __init__(self, host: str, ports: list):
        self.host = host
        self.ports = ports
        self.results: dict = {}

    def run(self) -> dict:
        print_section("OS & SERVICE FINGERPRINTING")
        if not NMAP_OK:
            print_warn("python-nmap not installed — skipping OS fingerprinting")
            print_warn("Install with: pip install python-nmap")
            return {}
        if not self.ports:
            print_warn("No open ports to fingerprint")
            return {}

        port_str = ",".join(str(p["port"]) for p in self.ports[:20])  # limit to first 20
        nm = nmap.PortScanner()

        try:
            print_info(f"Running nmap service detection on ports: {port_str}")
            nm.scan(self.host, port_str, arguments="-sV --version-intensity 5")

            for host in nm.all_hosts():
                self.results["os"] = nm[host].get("osmatch", [{}])
                self.results["hostnames"] = nm[host].hostname()
                for proto in nm[host].all_protocols():
                    for port in nm[host][proto]:
                        info = nm[host][proto][port]
                        print_ok(
                            f"Port {port:5d}  {info.get('name','?'):<12}  "
                            f"v{info.get('version','?')}  {info.get('product','')}"
                        )
                        self.results[port] = info

            if self.results.get("os"):
                top = self.results["os"][0]
                print_ok(f"OS Guess: {Fore.YELLOW}{top.get('name','Unknown')} "
                         f"(accuracy: {top.get('accuracy','?')}%)")

        except Exception as e:
            print_err(f"Fingerprinting error: {e}")

        return self.results


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 4 — HTTP HEADER SECURITY AUDIT
# ══════════════════════════════════════════════════════════════════════════════

class HTTPAuditor:
    """Check HTTP security headers and basic web recon."""

    REQUIRED_HEADERS = {
        "Strict-Transport-Security": ("HSTS missing — MITM risk", "HIGH"),
        "X-Frame-Options": ("Clickjacking protection absent", "MEDIUM"),
        "X-Content-Type-Options": ("MIME sniffing not disabled", "MEDIUM"),
        "Content-Security-Policy": ("CSP not set — XSS risk elevated", "HIGH"),
        "X-XSS-Protection": ("XSS filter header missing", "LOW"),
        "Referrer-Policy": ("Referrer leakage possible", "LOW"),
        "Permissions-Policy": ("Feature policy not configured", "INFO"),
    }

    def __init__(self, host: str, open_ports: list):
        self.host = host
        self.open_ports = open_ports
        self.results: dict = {"headers": {}, "missing": [], "server": None, "findings": []}

    def _get_url(self) -> Optional[str]:
        ports = {p["port"] for p in self.open_ports}
        if 443 in ports:
            return f"https://{self.host}"
        if 80 in ports:
            return f"http://{self.host}"
        if 8443 in ports:
            return f"https://{self.host}:8443"
        if 8080 in ports:
            return f"http://{self.host}:8080"
        return None

    def run(self) -> dict:
        print_section("HTTP SECURITY HEADER AUDIT")
        if not REQUESTS_OK:
            print_warn("requests not installed — skipping HTTP audit")
            return self.results

        url = self._get_url()
        if not url:
            print_warn("No HTTP/HTTPS port detected — skipping header audit")
            return self.results

        try:
            print_info(f"Fetching headers from {url}")
            r = requests.get(url, timeout=8, verify=False, allow_redirects=True,
                             headers={"User-Agent": "NetReconX/1.0 (Security Scanner)"})

            self.results["status_code"] = r.status_code
            self.results["final_url"] = r.url
            self.results["headers"] = dict(r.headers)

            # Server banner leak
            server = r.headers.get("Server", "")
            if server:
                self.results["server"] = server
                print_warn(f"Server header leaks: {Fore.RED}{server}")
                self.results["findings"].append(
                    {"check": "Server Banner Leak", "detail": server, "severity": "LOW"}
                )

            # X-Powered-By
            powered = r.headers.get("X-Powered-By", "")
            if powered:
                print_warn(f"X-Powered-By leaks: {Fore.RED}{powered}")
                self.results["findings"].append(
                    {"check": "Tech Stack Leak (X-Powered-By)", "detail": powered, "severity": "LOW"}
                )

            # Missing security headers
            for header, (desc, sev) in self.REQUIRED_HEADERS.items():
                if header not in r.headers:
                    self.results["missing"].append(header)
                    self.results["findings"].append(
                        {"check": f"Missing: {header}", "detail": desc, "severity": sev}
                    )
                    print_warn(f"{severity_color(sev)}[{sev}]{Style.RESET_ALL} {desc}")
                else:
                    print_ok(f"{header}: {r.headers[header][:60]}")

            # HTTPS check
            if url.startswith("http://"):
                self.results["findings"].append(
                    {"check": "No HTTPS", "detail": "Site accessible over plain HTTP", "severity": "HIGH"}
                )
                print_warn(f"{Fore.RED}[HIGH]{Style.RESET_ALL} Site served over unencrypted HTTP")

        except requests.exceptions.SSLError:
            print_warn("SSL certificate error (possible self-signed or expired cert)")
            self.results["findings"].append(
                {"check": "SSL Error", "detail": "Invalid or self-signed certificate", "severity": "HIGH"}
            )
        except requests.exceptions.ConnectionError as e:
            print_err(f"Connection failed: {e}")
        except Exception as e:
            print_err(f"HTTP audit error: {e}")

        return self.results


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 5 — RESULTS SUMMARY & REPORT GENERATION
# ══════════════════════════════════════════════════════════════════════════════

class ReportGenerator:
    def __init__(self, target: str, dns: dict, ports: list, http: dict, fingerprint: dict):
        self.target = target
        self.dns = dns
        self.ports = ports
        self.http = http
        self.fingerprint = fingerprint
        self.timestamp = datetime.now().isoformat()

    def _risk_score(self) -> float:
        """Compute composite risk score 0–10."""
        score = 0.0
        weights = {"CRITICAL": 3.5, "HIGH": 2.0, "MEDIUM": 1.0, "LOW": 0.4, "INFO": 0.1}
        for p in self.ports:
            score += weights.get(p.get("risk", "INFO"), 0.1)
        for f in self.http.get("findings", []):
            score += weights.get(f.get("severity", "INFO"), 0.1)
        return min(round(score, 1), 10.0)

    def print_summary(self):
        print_section("SCAN SUMMARY")
        risk = self._risk_score()
        risk_label = "CRITICAL" if risk >= 8 else "HIGH" if risk >= 6 else "MEDIUM" if risk >= 4 else "LOW"
        color = severity_color(risk_label)

        print(f"\n  {Fore.WHITE}Target        {Fore.CYAN}{self.target}")
        print(f"  {Fore.WHITE}IP Address    {Fore.CYAN}{self.dns.get('ip','N/A')}")
        print(f"  {Fore.WHITE}Scan Time     {Fore.CYAN}{self.timestamp}")
        print(f"  {Fore.WHITE}Open Ports    {Fore.GREEN}{len(self.ports)}")
        print(f"  {Fore.WHITE}Subdomains    {Fore.GREEN}{len(self.dns.get('subdomains',[]))}")
        print(f"  {Fore.WHITE}HTTP Findings {Fore.YELLOW}{len(self.http.get('findings',[]))}")
        print(f"  {Fore.WHITE}Risk Score    {color}{risk}/10  [{risk_label}]{Style.RESET_ALL}\n")

        if self.ports:
            if TABULATE_OK:
                rows = [[p["port"], p["service"], p["risk"],
                         (p["banner"][:50] if p["banner"] else "—")] for p in self.ports]
                print(tabulate(rows, headers=["PORT", "SERVICE", "RISK", "BANNER"],
                               tablefmt="rounded_outline"))
            else:
                for p in self.ports:
                    print(f"  {p['port']:5d}/tcp  {p['service']:<15}  {p['risk']:<8}  {p['banner'][:40]}")

    def save_json(self, path: str):
        data = {
            "meta": {"tool": "NetReconX", "version": VERSION, "timestamp": self.timestamp, "target": self.target},
            "risk_score": self._risk_score(),
            "dns": self.dns,
            "open_ports": self.ports,
            "http_audit": self.http,
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        print_ok(f"JSON report saved → {Fore.GREEN}{path}")

    def save_html(self, path: str):
        risk = self._risk_score()
        risk_label = "CRITICAL" if risk >= 8 else "HIGH" if risk >= 6 else "MEDIUM" if risk >= 4 else "LOW"
        risk_color = {"CRITICAL": "#ff2d55", "HIGH": "#ff6b00", "MEDIUM": "#ffd60a", "LOW": "#30d158"}[risk_label]
        sev_colors = {"CRITICAL": "#ff2d55", "HIGH": "#ff6b00", "MEDIUM": "#ffd60a", "LOW": "#30d158", "INFO": "#0a84ff"}

        ports_rows = ""
        for p in self.ports:
            sc = sev_colors.get(p["risk"], "#aaa")
            ports_rows += f"""<tr>
                <td>{p['port']}/tcp</td>
                <td>{p['service']}</td>
                <td><span class="badge" style="background:{sc}22;color:{sc};border:1px solid {sc}44">{p['risk']}</span></td>
                <td class="banner">{p['banner'][:80] or '—'}</td>
            </tr>"""

        findings_rows = ""
        for f in self.http.get("findings", []):
            sc = sev_colors.get(f["severity"], "#aaa")
            findings_rows += f"""<tr>
                <td><span class="badge" style="background:{sc}22;color:{sc};border:1px solid {sc}44">{f['severity']}</span></td>
                <td>{f['check']}</td>
                <td>{f['detail']}</td>
            </tr>"""

        subs_rows = ""
        for s in self.dns.get("subdomains", []):
            subs_rows += f"<tr><td>{s['subdomain']}</td><td>{s['ip']}</td></tr>"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>NetReconX Report — {self.target}</title>
<style>
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{ background:#080c10; color:#e8e8e8; font-family:'Courier New',monospace; padding:32px; }}
  h1 {{ color:#0af; font-size:22px; letter-spacing:4px; }}
  h2 {{ color:#ffd60a; font-size:13px; letter-spacing:3px; margin:28px 0 12px; padding-bottom:6px; border-bottom:1px solid rgba(255,255,255,0.08); }}
  .header {{ display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid rgba(10,132,255,0.3); padding-bottom:20px; margin-bottom:28px; }}
  .meta {{ font-size:11px; color:rgba(255,255,255,0.35); line-height:2; }}
  .risk {{ font-size:52px; font-weight:900; color:{risk_color}; line-height:1; }}
  .risk-label {{ font-size:11px; color:{risk_color}; letter-spacing:2px; }}
  table {{ width:100%; border-collapse:collapse; font-size:12px; margin-bottom:20px; }}
  th {{ background:rgba(255,255,255,0.04); padding:10px 14px; text-align:left; font-size:10px; letter-spacing:2px; color:rgba(255,255,255,0.4); }}
  td {{ padding:10px 14px; border-bottom:1px solid rgba(255,255,255,0.04); }}
  tr:hover td {{ background:rgba(255,255,255,0.03); }}
  .badge {{ padding:2px 8px; border-radius:3px; font-size:10px; letter-spacing:1px; font-weight:700; }}
  .banner {{ color:rgba(255,255,255,0.35); font-size:11px; }}
  .footer {{ margin-top:40px; font-size:10px; color:rgba(255,255,255,0.2); text-align:center; letter-spacing:1px; }}
</style>
</head>
<body>
<div class="header">
  <div>
    <h1>NETRECONX</h1>
    <div class="meta">
      Target: {self.target} ({self.dns.get('ip','N/A')})<br>
      Scan: {self.timestamp}<br>
      Open Ports: {len(self.ports)} &nbsp;|&nbsp; HTTP Findings: {len(self.http.get('findings',[]))} &nbsp;|&nbsp; Subdomains: {len(self.dns.get('subdomains',[]))}
    </div>
  </div>
  <div style="text-align:right">
    <div class="risk">{risk}</div>
    <div class="risk-label">/10 RISK SCORE · {risk_label}</div>
  </div>
</div>

<h2>OPEN PORTS</h2>
<table><thead><tr><th>PORT</th><th>SERVICE</th><th>RISK</th><th>BANNER</th></tr></thead>
<tbody>{ports_rows or '<tr><td colspan="4" style="color:rgba(255,255,255,0.2)">No open ports found</td></tr>'}</tbody></table>

<h2>HTTP SECURITY FINDINGS</h2>
<table><thead><tr><th>SEVERITY</th><th>CHECK</th><th>DETAIL</th></tr></thead>
<tbody>{findings_rows or '<tr><td colspan="3" style="color:rgba(255,255,255,0.2)">No HTTP findings</td></tr>'}</tbody></table>

<h2>SUBDOMAIN ENUMERATION</h2>
<table><thead><tr><th>SUBDOMAIN</th><th>IP ADDRESS</th></tr></thead>
<tbody>{subs_rows or '<tr><td colspan="2" style="color:rgba(255,255,255,0.2)">No subdomains found</td></tr>'}</tbody></table>

<div class="footer">⚠ NetReconX v{VERSION} · FOR AUTHORIZED PENETRATION TESTING ONLY · {self.timestamp}</div>
</body></html>"""

        with open(path, "w") as f:
            f.write(html)
        print_ok(f"HTML report saved → {Fore.GREEN}{path}")


# ══════════════════════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def parse_args():
    p = argparse.ArgumentParser(
        description="NetReconX — Network Reconnaissance Engine",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="⚠  FOR AUTHORIZED PENETRATION TESTING ONLY"
    )
    p.add_argument("--target", required=True, help="Target hostname or IP (e.g., example.com or 192.168.1.1)")
    p.add_argument("--ports", default="1-1024",
                   help="Port range to scan (e.g., 1-65535 or 80,443,8080). Default: 1-1024")
    p.add_argument("--threads", type=int, default=200, help="Number of scanner threads (default: 200)")
    p.add_argument("--timeout", type=float, default=1.0, help="Port connection timeout in seconds (default: 1.0)")
    p.add_argument("--mode", choices=["quick", "standard", "full"], default="standard",
                   help="Scan mode: quick=ports only, standard=+DNS+HTTP, full=+subdomains+fingerprint")
    p.add_argument("--output", default=None, help="Output file prefix (e.g., report → report.json + report.html)")
    p.add_argument("--no-dns", action="store_true", help="Skip DNS enumeration")
    p.add_argument("--no-http", action="store_true", help="Skip HTTP header audit")
    return p.parse_args()


def parse_ports(port_str: str) -> tuple:
    """Parse '1-1024' or '80,443,8080' into (start, end)."""
    if "-" in port_str:
        parts = port_str.split("-")
        return int(parts[0]), int(parts[1])
    elif "," in port_str:
        ports = list(map(int, port_str.split(",")))
        return min(ports), max(ports)
    else:
        p = int(port_str)
        return p, p


def main():
    print(BANNER)
    args = parse_args()
    target = args.target.strip().replace("https://", "").replace("http://", "").split("/")[0]

    print(f"\n{Fore.CYAN}  Target   : {Fore.WHITE}{target}")
    print(f"{Fore.CYAN}  Mode     : {Fore.WHITE}{args.mode.upper()}")
    print(f"{Fore.CYAN}  Ports    : {Fore.WHITE}{args.ports}")
    print(f"{Fore.CYAN}  Threads  : {Fore.WHITE}{args.threads}")
    print(f"{Fore.RED}\n  ⚠  Confirm you have WRITTEN authorization to scan {target}")
    confirm = input(f"  Type 'yes' to continue: {Style.RESET_ALL}").strip().lower()
    if confirm != "yes":
        print_err("Scan aborted.")
        sys.exit(0)

    start_time = time.time()

    # ── Phase 1: DNS ──────────────────────────────────────────────────────────
    dns_results = {"hostname": target, "records": {}, "subdomains": [], "ip": None}
    if not args.no_dns:
        recon = DNSRecon(target)
        dns_results = recon.run()
        if args.mode == "full":
            recon.enumerate_subdomains()
            dns_results = recon.results

    # Determine scan host
    scan_host = dns_results.get("ip") or target

    # ── Phase 2: Port scan ────────────────────────────────────────────────────
    start_port, end_port = parse_ports(args.ports)
    scanner = PortScanner(scan_host, (start_port, end_port), args.timeout, args.threads)
    open_ports = scanner.scan()

    # ── Phase 3: Fingerprinting (full mode only) ──────────────────────────────
    fingerprint = {}
    if args.mode == "full" and open_ports:
        fp = Fingerprinter(scan_host, open_ports)
        fingerprint = fp.run()

    # ── Phase 4: HTTP audit ───────────────────────────────────────────────────
    http_results = {"headers": {}, "missing": [], "server": None, "findings": []}
    if not args.no_http and args.mode in ("standard", "full"):
        auditor = HTTPAuditor(target, open_ports)
        http_results = auditor.run()

    # ── Phase 5: Report ───────────────────────────────────────────────────────
    reporter = ReportGenerator(target, dns_results, open_ports, http_results, fingerprint)
    reporter.print_summary()

    elapsed = time.time() - start_time
    print_info(f"Total scan time: {elapsed:.1f}s")

    if args.output:
        reporter.save_json(f"{args.output}.json")
        reporter.save_html(f"{args.output}.html")
    else:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        reporter.save_json(f"netreconx_{target}_{ts}.json")
        reporter.save_html(f"netreconx_{target}_{ts}.html")

    print(f"\n{Fore.GREEN}  Scan complete. Stay ethical. 🛡{Style.RESET_ALL}\n")


if __name__ == "__main__":
    main()
