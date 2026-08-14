# 🔍 VeilScan v2.0

**Beginner-friendly network security audit tool.**
Scan any authorized target, identify every open service, and get a full
color-coded HTML report with plain-English explanations of every finding.

![Python](https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square)
![Version](https://img.shields.io/badge/version-2.0.0-purple?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)

---

## ⚠️ Legal Notice

Only scan systems **you own** or have **written permission** to test.
Unauthorized port scanning is illegal in most countries.

**Safe authorized test target:** `scanme.nmap.org` (authorized by Nmap Project)

---

## ✨ What VeilScan Does

1. **Scans** every port you specify — TCP and optionally UDP
2. **Identifies** the service on each open port (SSH, HTTP, MySQL, RDP...)
3. **Grabs banners** — detects exact version strings (OpenSSH 8.9, Apache 2.4...)
4. **Explains** every finding in plain English
5. **Rates risk** — CRITICAL / HIGH / MEDIUM / LOW / INFO
6. **Saves** a full HTML report — open in any browser

---

## 🚀 Quickstart

**No install needed — run directly:**
```bash
git clone https://github.com/AqibTayyab/veilscan
cd veilscan

# Interactive wizard (beginner mode)
python main.py

# Direct scan
python main.py scanme.nmap.org --profile quick --agree
```

**Or install via pip:**
```bash
pip install veilscan
veilscan scanme.nmap.org --profile quick --agree
```

---

## 📊 Example Output

```
  Target  : scanme.nmap.org
  Ports   : top100  |  Profile: quick

  [TCP]     ████████████████████  100/100  100%
  [BANNER]  ████████████████████  2/2  100%

╔══════════════════════════════════════════════════════════╗
║  Host: scanme.nmap.org (45.33.32.156)                    ║
║  OS Hint: Linux/Unix (TTL=48)                            ║
╚══════════════════════════════════════════════════════════╝
PORT    PROTO  STATE   SERVICE   VERSION
22      tcp    OPEN    SSH       OpenSSH_6.6.1p1
80      tcp    OPEN    HTTP      Apache/2.4.7 (Ubuntu)

  2 open port(s) found  |  2.09s
```

The HTML report explains every finding:
- 🔴 **CRITICAL** — SMB, MySQL, Redis, rexec
- 🟠 **HIGH** — RDP, VNC, NFS, RPCbind
- 🟡 **MEDIUM** — HTTP, SMTP, DNS, FTP
- 🟢 **LOW** — SSH, HTTPS
- 🔵 **INFO** — normal services

---

## 🛡️ Scan Profiles

| Profile | Ports | Threads | Time | Use For |
|---------|-------|---------|------|---------|
| `quick` | top 100 | 200 | ~3s | First look |
| `standard` | top 1000 | 100 | ~30s | General audit |
| `full` | all 65535 | 50 | ~30min | Complete audit |
| `stealth` | top 100 | 10 | ~2min | Quiet scan |

---

## ⚙️ All Options

```
usage: veilscan [-h] [-p PORTS] [-T N] [-t SEC] [-r N]
                [--udp] [--no-banners] [--profile PROFILE]
                [-o FILE] [-f {json,csv,txt}]
                [--auto-report] [-v] [--agree] [--log FILE]
                [target]

  target            IP, hostname, or CIDR (e.g. 192.168.1.0/24)
  -p / --ports      top100, top1000, full, 1-1024, 22,80,443
  -T / --threads    Concurrent workers (default: 100)
  -t / --timeout    Seconds per port (default: 1.0)
  -r / --retries    Retry count on timeout (default: 1)
  --udp             Also scan UDP ports
  --no-banners      Skip version detection (faster)
  --profile         quick | standard | full | stealth
  -o / --output     Save to file
  -f / --format     json | csv | txt
  --auto-report     Auto-save HTML+JSON+CSV to reports/
  --agree           Skip consent prompt (for scripts)
```

---

## 💡 Usage Examples

```bash
# Beginner mode — interactive wizard
python main.py

# Quick overview of a machine
python main.py 192.168.1.1 --profile quick --agree

# Full audit with auto-saved report
python main.py 192.168.1.1 --profile standard --agree --auto-report

# Specific ports, save as CSV
python main.py 192.168.1.1 -p 22,80,443,3306,8080 -o scan.csv -f csv --agree

# Scan entire subnet
python main.py 192.168.1.0/24 -p top100 --agree --auto-report

# TCP + UDP scan
python main.py 192.168.1.1 --udp --agree

# Metasploitable lab
python main.py 192.168.140.130 --profile standard --agree --auto-report
```

---

## 🐍 Python API

```python
from veilscan.config import ScanConfig
from veilscan.scanner import Scanner
from veilscan.html_reporter import generate_html

config = ScanConfig(
    target  = "192.168.1.1",
    ports   = "22,80,443,3306",
    banners = True,
)

result = Scanner(config).scan()

# Save HTML report
with open("report.html", "w") as f:
    f.write(generate_html(result))

# Access results programmatically
for host in result.hosts:
    for port in host.open_ports:
        print(f"{port.port}/{port.protocol}  {port.service}  {port.version}")
```

---

## 📁 Project Structure

```
veilscan/
├── main.py                  ← Run directly: python main.py
├── veilscan/                ← Main package
│   ├── cli.py               ← CLI + interactive wizard
│   ├── scanner.py           ← Orchestrates full scan pipeline
│   ├── tcp_scanner.py       ← TCP port scanning engine
│   ├── udp_scanner.py       ← UDP scanning with ICMP detection
│   ├── banner_grabber.py    ← Service version fingerprinting
│   ├── reporter.py          ← JSON / CSV / TXT output
│   ├── html_reporter.py     ← HTML report generator
│   ├── vuln_hints.py        ← 42 service risk explanations
│   ├── models.py            ← Data structures
│   ├── utils.py             ← Port map, helpers
│   └── config.py            ← ScanConfig + profiles
├── reports/                 ← Your HTML/JSON/CSV reports
├── logs/                    ← Audit trail
└── tests/                   ← Test suite
```

---

## 🧪 Running Tests

```bash
pip install pytest
pytest tests/ -v
```

---

## 📄 License

MIT — free for educational and authorized use.

**Author:** Aqib Tayyab — [github.com/AqibTayyab](https://github.com/AqibTayyab)

If VeilScan helped you learn, give it a ⭐ on GitHub!
