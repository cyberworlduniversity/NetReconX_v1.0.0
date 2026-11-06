# ⬡ NetReconX v1.0.0


## Get this repository

Clone the current project (this repository's canonical GitHub URL), then follow the installation and usage steps below.

```bash
git clone https://github.com/cyberworlduniversity/NetReconX_v1.0.0.git
cd NetReconX_v1.0.0
```
### Network Reconnaissance Engine — Ethical Penetration Testing Tool

```
███╗   ██╗███████╗████████╗██████╗ ███████╗ ██████╗ ███╗  ██╗
████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██╔════╝██╔════╝ ████╗ ██║
██╔██╗ ██║█████╗     ██║   ██████╔╝█████╗  ██║      ██╔██╗██║
██║╚██╗██║██╔══╝     ██║   ██╔══██╗██╔══╝  ██║      ██║╚████║
██║ ╚████║███████╗   ██║   ██║  ██║███████╗╚██████╗ ██║ ╚███║
╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚══╝
```

> ⚠️ **FOR AUTHORIZED PENETRATION TESTING ONLY.**  
> Only use this tool on systems you own or have explicit written permission to test.  
> Unauthorized scanning is illegal under the CFAA and equivalent laws worldwide.

---

## 📋 Overview

NetReconX is a professional-grade network reconnaissance tool built in Python, inspired by industry tools like **Nmap** and **Shodan**. It performs multi-phase scanning including DNS enumeration, port scanning with banner grabbing, HTTP security header auditing, and generates detailed reports.

A companion **React dashboard** (`NetReconX_Dashboard.jsx`) provides a live visual interface for the scan results.

---

## 🗂️ Project Structure

```
NetReconX/
├── README.md                    ← This file
├── netreconx.py                 ← Main Python scanner (CLI tool)
└── NetReconX_Dashboard.jsx      ← React live dashboard UI
```

---

## ✨ Features

### Python Backend (`netreconx.py`)
| Phase | Module | Description |
|-------|--------|-------------|
| 1 | DNS Recon | Hostname resolution, A/MX/NS/TXT records, subdomain brute-force |
| 2 | Port Scanner | Multi-threaded TCP connect scan + banner grabbing |
| 3 | Fingerprinting | OS detection & service version identification (via nmap) |
| 4 | HTTP Auditor | Security header grading (HSTS, CSP, X-Frame-Options, etc.) |
| 5 | Report Generator | JSON + styled HTML report output |

### React Dashboard (`NetReconX_Dashboard.jsx`)
- 🖥️ Live animated terminal log playback
- 📊 Risk score gauge + severity breakdown chart
- 🗂️ Tabbed results: Open Ports / HTTP Audit / Subdomains
- 🌐 DNS records panel
- 🔴 Real-time pulsing scan indicators

---

## 🔧 Requirements

### Python Dependencies
```bash
pip install requests python-nmap colorama tabulate dnspython
```

### System Requirements
- Python 3.8+
- Nmap installed on system (for OS fingerprinting in `--mode full`)
  - Ubuntu/Debian: `sudo apt install nmap`
  - macOS: `brew install nmap`
  - Windows: Download from https://nmap.org/download.html

### React Dashboard Dependencies
- Node.js 16+
- React 18+
- No additional npm packages required (uses only React built-ins)

---

## 🚀 Usage

### Basic Scan (Ports 1–1024 + DNS + HTTP)
```bash
python netreconx.py --target example.com
```

### Scan Specific Port Range
```bash
python netreconx.py --target 192.168.1.1 --ports 1-65535
```

### Full Scan (Subdomains + OS Fingerprinting)
```bash
python netreconx.py --target example.com --mode full --output report
```

### Quick Scan (Ports Only)
```bash
python netreconx.py --target 192.168.1.1 --mode quick --ports 80,443,8080,3306
```

### All Options
```
--target       Target hostname or IP address (required)
--ports        Port range: 1-1024, 1-65535, or 80,443,8080 (default: 1-1024)
--threads      Number of scanner threads (default: 200)
--timeout      Connection timeout in seconds (default: 1.0)
--mode         quick | standard | full (default: standard)
--output       Output file prefix (e.g. "report" → report.json + report.html)
--no-dns       Skip DNS enumeration
--no-http      Skip HTTP header audit
```

---

## 📤 Output

NetReconX generates two report files automatically:

### JSON Report (`report.json`)
Machine-readable structured data including all scan results, risk scores, and findings. Useful for integrating with other tools or pipelines.

### HTML Report (`report.html`)
A styled, dark-themed visual report with:
- Overall risk score (0–10)
- Open ports table with service banners
- HTTP security findings with severity levels
- Subdomain enumeration results

---

## 🔍 What NetReconX Detects

### Port Scanning
- Open TCP ports with service identification
- Banner grabbing (server version, software info)
- Risk classification per service type

### High-Risk Services Flagged
| Service | Risk | Reason |
|---------|------|--------|
| Telnet | CRITICAL | Unencrypted protocol |
| FTP | HIGH | Often allows anonymous login |
| RDP | HIGH | Common brute-force target |
| Redis | HIGH | Frequently runs unauthenticated |
| SMB | HIGH | Lateral movement vector |
| VNC | HIGH | Remote access exposure |

### HTTP Security Headers Audited
- `Strict-Transport-Security` (HSTS)
- `Content-Security-Policy` (CSP)
- `X-Frame-Options`
- `X-Content-Type-Options`
- `X-XSS-Protection`
- `Referrer-Policy`
- `Permissions-Policy`
- Server banner / tech stack leakage

### DNS Enumeration
- A, AAAA, MX, NS, TXT, CNAME, SOA records
- Subdomain brute-force (24 common names)

---

## 🖥️ Running the React Dashboard

The dashboard (`NetReconX_Dashboard.jsx`) is a standalone React component.

**Option 1 — Claude.ai Artifacts**  
Paste the `.jsx` file directly into a Claude artifact renderer.

**Option 2 — Create React App**
```bash
npx create-react-app netreconx-ui
cd netreconx-ui
# Replace src/App.js content with NetReconX_Dashboard.jsx
npm start
```

**Option 3 — Vite**
```bash
npm create vite@latest netreconx-ui -- --template react
cd netreconx-ui && npm install
# Replace src/App.jsx with NetReconX_Dashboard.jsx
npm run dev
```

---

## 🛡️ Legal & Ethical Use

This tool is built for:
- ✅ Authorized penetration testing engagements
- ✅ CTF (Capture the Flag) competitions
- ✅ Testing infrastructure you own
- ✅ Security research in isolated lab environments

**Never use on:**
- ❌ Systems without explicit written authorization
- ❌ Public infrastructure
- ❌ Any system you do not own

---

## 📚 Inspired By

- [Nmap](https://nmap.org/) — Network scanner
- [Shodan](https://www.shodan.io/) — Internet intelligence
- [OWASP ZAP](https://www.zaproxy.org/) — Web app security
- [THC Hydra](https://github.com/vanhauser-thc/thc-hydra) — Network login auditor

---

## 📄 License

MIT License — Free to use, modify, and distribute for ethical purposes.

---

*NetReconX v1.0.0 · Built for ethical security professionals · Stay legal. Stay ethical. 🛡️*
