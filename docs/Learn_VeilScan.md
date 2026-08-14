# Learn VeilScan — Complete Technical Guide
# Everything you need to know about this project

**Author:** Aqib Tayyab  
**Project:** VeilScan v2.0 — Network Security Audit Tool

---

## Part 1 — What Is VeilScan and Why Does It Exist?

### The Problem
When you learn network security, one of the first things you do is scan a target. The go-to tool is **Nmap** — powerful, fast, industry standard. But Nmap output looks like this:

```
22/tcp  open  ssh     OpenSSH 6.6.1p1
80/tcp  open  http    Apache httpd 2.2.8
3306/tcp open  mysql   MySQL 5.0.51a-3ubuntu5
```

A beginner looks at this and asks: *"Okay... so what? Is this dangerous? What do I do now?"*

Nmap doesn't tell you. It just lists ports. You have to already know what MySQL 5.0.51a means, why rexec on port 512 is critical, or that VNC without a password means anyone can control the machine.

**VeilScan solves this.** It does the same scan, but then explains every finding in plain English, rates its risk level, and tells you exactly what to check. A complete beginner can scan Metasploitable and immediately understand they have 8 CRITICAL vulnerabilities — and what each one means.

### What VeilScan Actually Does
1. **Connects to ports** — tries to establish a TCP (or UDP) connection to each port number
2. **Records open ports** — any port that accepts the connection is "open"
3. **Reads the banner** — most services send a greeting message with their name and version
4. **Identifies the service** — matches the banner to known protocol formats
5. **Rates the risk** — looks up the port in a database of 42 service explanations
6. **Generates reports** — terminal table + HTML file + JSON + CSV

---

## Part 2 — Core Networking Concepts You Must Know

### What is a Port?
A port is a number (1–65535) that identifies a specific service on a machine. It's like a door number in a building. The building is the IP address, the door number is the port.

- Port 22 → SSH (secure remote access)
- Port 80 → HTTP (web server)
- Port 3306 → MySQL database
- Port 445 → SMB (Windows file sharing)

### TCP vs UDP
**TCP (Transmission Control Protocol):**
- Has a 3-way handshake before data transfers
- Connection either succeeds (OPEN) or fails (CLOSED/REFUSED)
- Used by: SSH, HTTP, MySQL, FTP, SMTP — almost everything

**UDP (User Datagram Protocol):**
- No handshake — just send and hope
- Can't tell if port is open from silence alone
- If you get ICMP Port Unreachable → CLOSED (definitive)
- If you get a UDP response → OPEN (definitive)
- If you get nothing → OPEN|FILTERED (uncertain)
- Used by: DNS, NTP, SNMP, DHCP

### What is Banner Grabbing?
When you connect to most services, they send a greeting before you say anything. This is called a "banner":

```
SSH connects:   SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1
FTP connects:   220 ProFTPD 1.3.6 Server
MySQL connects: (binary bytes with) 5.0.51a-3ubuntu5
HTTP (after GET /): HTTP/1.1 200 OK\r\nServer: Apache/2.2.8
```

VeilScan reads these banners and extracts the version string. This is how it knows you're running **OpenSSH_8.9p1** specifically, not just "SSH".

### What is OS Fingerprinting?
Every packet sent over a network has a TTL (Time to Live) value — a counter that decreases by 1 at each router hop. When you receive a response from a target, its TTL reveals the OS family:

| OS | Default TTL | What you see at 16 hops away |
|----|-------------|------------------------------|
| Linux/Unix | 64 | ~48 (64-16=48) |
| Windows | 128 | ~112 (128-16=112) |
| Cisco/Solaris | 255 | ~239 (255-16=239) |

VeilScan sends a UDP packet to a closed port, gets back an ICMP "Port Unreachable" response, and reads the TTL from byte 8 of the IP header. This gives the **remote host's TTL**, not your own machine's default TTL (a previous bug returned your own TTL).

---

## Part 3 — The Metasploitable Scan Explained

Your scan found 19 open ports. Here is what each one means:

### The CRITICAL ones (most dangerous)

**Port 23 — Telnet** (`CRITICAL`)
Telnet is like SSH but sends everything — including your password — as plain text. Anyone on the same network can sniff your login credentials with Wireshark in seconds. This was the standard before SSH was invented in 1995. Finding it in 2026 means this machine is ancient or catastrophically misconfigured.

**Port 445 — SMB (Windows File Sharing)** (`CRITICAL`)
SMB is how Windows machines share files. EternalBlue (leaked NSA exploit) targeted this port — it's what WannaCry ransomware (2017) used to spread to 300,000 machines in 150 countries. Even though Metasploitable is Linux, it runs Samba (SMB for Linux). Port 445 on the internet is almost always blocked by ISPs because it's so dangerous.

**Port 512 — rexec (Remote Execution)** (`CRITICAL`)
rexec lets you execute commands on a remote Unix machine. It was designed in the 1980s before network security was a concept. It sends credentials in plain text and on Metasploitable, it often requires NO authentication at all. This is why it's labeled CRITICAL — anyone who can reach port 512 can potentially run commands on the machine.

**Port 513 — rlogin (Remote Login)** (`CRITICAL`)
rlogin is like SSH but from the 1980s — no encryption, no strong authentication. It uses a trust system called `.rhosts` files. If a machine is listed in `.rhosts`, it can log in without a password at all. On Metasploitable, this is exploitable immediately.

**Port 514 — rsh (Remote Shell)** (`CRITICAL`)
Same family as rexec and rlogin — the "r-services" trio. rsh allows running commands on a remote shell with the same .rhosts trust system. These three ports (512, 513, 514) are the classic first thing a beginner exploits on Metasploitable.

**Port 1099 — Java-RMI** (`CRITICAL`)
Java Remote Method Invocation — allows one Java program to call methods on another Java program running on a different machine. The vulnerability is in Java's deserialization — you can send specially crafted Java objects that execute arbitrary code when deserialized. Metasploit has a module `exploit/multi/misc/java_rmi_server` that gives you a shell from this port in seconds.

**Port 3306 — MySQL 5.0.51a** (`CRITICAL`)
A MySQL database exposed directly on the network. The version 5.0.51a is from 2008 — ancient, full of CVEs, no longer receives security patches. Databases should NEVER be directly reachable from outside the server. Your application code connects to it internally on localhost — nobody else should ever reach port 3306.

**Port 5432 — PostgreSQL** (`CRITICAL`)
Same as MySQL — a database exposed on the network. Your scan showed no version because PostgreSQL sends a binary authentication challenge, not a version string in the banner (our banner grabber reads what it gets, and PostgreSQL sends an auth request first).

### The HIGH ones

**Port 21 — FTP vsFTPd 2.3.4** (`HIGH`)
FTP sends passwords in plain text. But more importantly: **vsFTPd 2.3.4 has a backdoor (CVE-2011-2523)**. The backdoor was introduced by an attacker who hacked the vsFTPd distribution server. Any username that ends with `:)` (a smiley face) triggers the backdoor and gives a root shell on port 6200. This is a famous Metasploitable exploitation exercise.

**Port 111 — RPCbind** (`HIGH`)
RPCbind maps RPC program numbers to actual ports. It's the "telephone directory" for RPC services. Attackers query it first to discover what services are running: `rpcinfo -p 192.168.140.130` shows all RPC services. This is reconnaissance infrastructure — it tells attackers what else to target.

**Port 139 — NetBIOS Session Service** (`HIGH`)
Legacy Windows networking. NetBIOS predates modern Windows and DNS. It broadcasts computer names and workgroup information, helping attackers enumerate the network. Combined with SMB (445), it was responsible for many Windows worm outbreaks.

**Port 2049 — NFS (Network File System)** (`HIGH`)
NFS lets servers share directories over the network. Metasploitable's `/etc/exports` file exports `/` (the entire root filesystem) to everyone. This means: `mount -t nfs 192.168.140.130:/ /mnt/target` and you have the entire filesystem including `/etc/shadow` (password hashes) without any authentication.

**Port 5900 — VNC 003.003** (`HIGH`)
VNC gives full graphical control of a desktop. The version 003.003 (RFB protocol version 3.3) is ancient and uses no encryption. On Metasploitable, the VNC password is `msfadmin`. One Metasploit auxiliary module (`scanner/vnc/vnc_login`) can brute-force it in under a second.

### The MEDIUM ones

**Port 25 — SMTP Postfix** (`MEDIUM`)
Postfix email server. The risk is being an "open relay" — accepting email from anyone and forwarding it, enabling spam. You need to test: `telnet 192.168.140.130 25` then `HELO test` then `MAIL FROM: test@example.com` then `RCPT TO: victim@gmail.com` — if it accepts, it's an open relay.

**Port 53 — DNS** (`MEDIUM`)
DNS on TCP (usually UDP). The risk: open resolver that accepts queries from anyone (DDoS amplification) and zone transfers that expose internal network maps. `dig axfr @192.168.140.130 localdomain` would attempt a zone transfer.

**Port 80 — Apache 2.2.8 PHP 5.2.4** (`MEDIUM`)
Apache from 2008 (latest is 2.4.x). PHP 5.2.4 from 2007 (latest is 8.x). Both are end-of-life, no security patches. The HTTP header reveals both versions. Metasploitable runs DVWA (Damn Vulnerable Web Application) on this port — intentionally vulnerable web app for practice.

**Port 6667 — IRC UnrealIRCd** (`MEDIUM`)
The famous UnrealIRCd 3.2.8.1 backdoor. An attacker compromised the UnrealIRCd distribution in 2009 and added a backdoor to the source code. The backdoor is triggered by sending `AB` followed by a system command to port 6667. Metasploit module: `exploit/unix/irc/unreal_ircd_3281_backdoor` — instant root shell.

---

## Part 4 — How the Code Works (Technical Deep Dive)

### How TCP Scanning Works

```python
# Simplified version of what happens
import socket

def is_port_open(ip, port, timeout=1.0):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    result = sock.connect_ex((ip, port))
    sock.close()
    return result == 0  # 0 means connected successfully
```

`connect_ex()` returns 0 if the connection succeeded (port is OPEN), or an error code if it failed:
- `111` on Linux = ECONNREFUSED = port is actively rejecting connections (CLOSED)
- `10061` on Windows = WSAECONNREFUSED = same thing
- Timeout = either filtered (firewall) or just slow

VeilScan does this for every port in the list, using 100-200 threads simultaneously so 1000 ports take seconds instead of 1000 seconds.

### The Race Condition That Was Fixed

In v1.0, scanning used this pattern:
```python
# BROKEN — race condition
while not queue.empty():        # Thread 1 checks: "queue not empty"
    port = queue.get()          # Thread 2 steals the last item
                                # Thread 1: queue.get() blocks forever!
```

This is a classic threading race condition: two operations (`empty()` check and `get()`) are not atomic. Between the check and the get, another thread can grab the item.

v2.0 fix:
```python
# CORRECT — atomic
try:
    port = queue.get_nowait()   # Gets item OR raises Empty — one atomic operation
except queue.Empty:
    return                       # Queue is done, worker exits cleanly
```

`get_nowait()` is a single atomic operation. Either you get the item, or you get an exception — there's no window for another thread to interfere.

### How Banner Grabbing Works

```python
# Simplified banner grabbing
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(2.0)
sock.connect((ip, port))

# For HTTP: send a request first
sock.sendall(b"GET / HTTP/1.0\r\nHost: target\r\n\r\n")

# For SSH, FTP, SMTP: just read (they speak first)
banner = sock.recv(4096)
print(banner.decode("utf-8"))
# → b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n"
```

For HTTPS (port 443), we need TLS:
```python
import ssl

ctx = ssl.create_default_context()
ctx.check_hostname = False   # lab certs are self-signed
ctx.verify_mode = ssl.CERT_NONE
tls_sock = ctx.wrap_socket(raw_sock, server_hostname=ip)
tls_sock.sendall(b"GET / HTTP/1.0\r\n\r\n")
banner = tls_sock.recv(4096)
# → b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n..."
```

### How the HTML Report is Generated

The HTML report is a Python f-string template — no external templating library needed:

```python
def generate_html(result: ScanResult) -> str:
    # Build risk summary pills
    risk_counts = count_risks(result)
    
    # Build one card per open port
    port_cards = ""
    for port in sorted_by_risk(host.open_ports):
        hint = HINTS.get(port.port)  # look up our explanation database
        port_cards += f"""
        <div style="border:1.5px solid {c['border']};background:{c['bg']};">
          <strong>{port.port}</strong> {port.protocol} {hint.service}
          <p>{html.escape(hint.what)}</p>
          <p>{html.escape(hint.why)}</p>
        </div>"""
    
    return f"""<!DOCTYPE html>
    <html>
    ...{risk_summary}...{port_cards}...
    </html>"""
```

Everything from the network (`port.banner`, `port.version`, `host.os_hint`) goes through `html.escape()` first. If a malicious target sends `<script>alert('xss')</script>` as its SSH banner, it shows up as `&lt;script&gt;` in the HTML — harmless text, not executable code.

### How Threading Works

```
main thread
    │
    ├── queue = [22, 80, 443, 3306, 5432, 6379, ...]  (all ports)
    │
    ├── Thread 1 ──→ gets port 22 → scans → appends to results
    ├── Thread 2 ──→ gets port 80 → scans → appends to results
    ├── Thread 3 ──→ gets port 443 → scans → appends to results
    ...
    ├── Thread 100 → gets port 3306 → scans → appends to results
    │
    └── queue.join()  ← BLOCKS until every port has been processed
    
    then → process results
```

The `Lock` protects the `results` list:
```python
results = []
lock = threading.Lock()

def worker():
    while True:
        port = queue.get_nowait()
        info = scan_tcp_port(ip, port, timeout)
        with lock:          # Only one thread at a time
            results.append(info)
        queue.task_done()   # Signal: this port is done
```

Without the lock, two threads could try to `append()` simultaneously, potentially corrupting the list.

---

## Part 5 — How to Use Every Feature

### Basic Usage
```bash
# No args → interactive wizard
python main.py

# Quick scan (top 100 ports, 200 threads, 0.5s timeout)
python main.py 192.168.1.1 --profile quick --agree

# Standard scan (top 1000 ports, balanced)
python main.py 192.168.1.1 --profile standard --agree

# Full scan (all 65535 ports — takes 20-40 minutes)
python main.py 192.168.1.1 --profile full --agree

# Stealth scan (quiet, 10 threads, 3s timeout)
python main.py 192.168.1.1 --profile stealth --agree
```

### Specific Ports
```bash
# Scan only these ports
python main.py 192.168.1.1 -p 22,80,443,3306,8080 --agree

# Scan port range
python main.py 192.168.1.1 -p 1-1024 --agree

# Mix range and list
python main.py 192.168.1.1 -p 22,80-90,443,8000-8100 --agree
```

### Subnet Scanning
```bash
# Scan all 254 machines on 192.168.1.0/24
python main.py 192.168.1.0/24 -p top100 --agree

# Scan small lab network
python main.py 192.168.140.0/24 --profile quick --agree --auto-report
```

### Output Formats
```bash
# Auto-save HTML + JSON + CSV (recommended)
python main.py 192.168.1.1 --agree --auto-report

# Save to specific file
python main.py 192.168.1.1 --agree -o scan.json
python main.py 192.168.1.1 --agree -o scan.csv -f csv
python main.py 192.168.1.1 --agree -o scan.txt -f txt

# Pipe-friendly (no colors in stdout)
python main.py 192.168.1.1 --agree -o results.json 2>/dev/null
```

### UDP Scanning
```bash
# TCP + UDP (requires admin on Windows)
python main.py 192.168.1.1 --udp --agree

# UDP specific ports
python main.py 192.168.1.1 -p 53,123,161,1900 --udp --agree

# On Linux (requires root for accurate ICMP detection)
sudo python3 main.py 192.168.1.1 --udp --agree
```

### Advanced Options
```bash
# More threads = faster (more load on network)
python main.py 192.168.1.1 -T 500 --agree

# Longer timeout = more accurate on slow networks
python main.py 192.168.1.1 -t 3.0 --agree

# Skip banner grabbing (faster, less info)
python main.py 192.168.1.1 --no-banners --agree

# Show filtered ports too
python main.py 192.168.1.1 -v --agree

# Log debug info
python main.py 192.168.1.1 --agree --log debug.log
```

### Python API
```python
from veilscan.config import ScanConfig
from veilscan.scanner import Scanner
from veilscan.reporter import Reporter
from veilscan.html_reporter import generate_html

# Create config
config = ScanConfig(
    target  = "192.168.140.130",
    ports   = "top100",
    threads = 200,
    timeout = 0.5,
    banners = True,
    profile = "quick",
)

# Run scan
result = Scanner(config).scan()

# Print terminal table
Reporter(result).print_table()

# Save HTML report
with open("report.html", "w") as f:
    f.write(generate_html(result))

# Access results programmatically
for host in result.hosts:
    print(f"Host: {host.host} ({host.ip})")
    print(f"OS: {host.os_hint}")
    for port in host.open_ports:
        print(f"  {port.port}/{port.protocol}  {port.service}  {port.version}")
        if port.banner:
            print(f"    Banner: {port.banner[:80]}")
```

---

## Part 6 — Reading and Understanding Reports

### Terminal Output
```
╔══════════════════════════════════════════════════════════╗
║  Host: 192.168.140.130 (192.168.140.130)                 ║  ← hostname and IP
║  OS Hint: Linux/Unix (TTL=64)                            ║  ← OS from TTL
╚══════════════════════════════════════════════════════════╝
PORT    PROTO   STATE         SERVICE         VERSION
──────────────────────────────────────────────────────────
22      tcp     OPEN          SSH             OpenSSH_4.7p1  ← exact version
3306    tcp     OPEN          MySQL           5.0.51a-3ubuntu5
```

**PORT** — the number. Important ones: 22(SSH), 80(HTTP), 443(HTTPS), 3306(MySQL), 445(SMB)

**STATE:**
- `OPEN` (green) — connection accepted, service is running
- `OPEN|FILTERED` (yellow) — no response (UDP), could be open or firewall
- `CLOSED` (dim) — connection refused, nothing there

**VERSION** — exact software version from banner. Critical for finding CVEs.

### HTML Report Sections

**Risk Summary pills** — count of findings at each level. 8 CRITICAL means fix 8 things immediately.

**Overall status line:**
- 🔴 Red = CRITICAL findings → act now
- 🟠 Orange = HIGH findings → this week
- 🟡 Yellow = MEDIUM findings → this month
- 🟢 Green = No critical findings → good baseline

**Finding cards** — sorted by severity (CRITICAL first). Each card has:
- **What it is** — plain English: what does this service do?
- **Why it matters** — plain English: what's the risk?
- **What to check** — specific steps to verify if it's secure
- **💡 Tip** — one actionable takeaway

### Understanding Version Strings

| Version Found | What It Means |
|--------------|---------------|
| `OpenSSH_4.7p1` | OpenSSH from 2007 — ancient, many CVEs |
| `Apache/2.2.8` | Apache from 2008 — end of life since 2018 |
| `vsFTPd 2.3.4` | Has a backdoor (CVE-2011-2523) |
| `MySQL 5.0.51a` | MySQL from 2008 — end of life since 2012 |
| `PHP/5.2.4` | PHP from 2007 — end of life since 2011 |

**Rule of thumb:** Search `{service} {version} CVE` in Google or search.cve.mitre.org. Old software always has CVEs.

---

## Part 7 — Project Structure for Contributors

### Adding a New Service to the Hints Database

1. Open `veilscan/vuln_hints.py`
2. Add entry to `HINTS` dict:
```python
HINTS: dict[int, ServiceHint] = {
    # ... existing entries ...
    
    8888: ServiceHint(
        service="Jupyter Notebook",
        what="Jupyter is an interactive Python notebook server used for data science.",
        risk="HIGH",
        why="Default Jupyter has no authentication. Anyone who can reach port 8888 "
            "can execute arbitrary Python code on the server.",
        check="Verify Jupyter requires a token or password. "
              "It should not be publicly accessible.",
        learn="Jupyter with no auth = remote code execution for anyone on the network.",
    ),
}
```

3. Add test to `tests/test_vuln_hints.py`
4. Run `pytest tests/test_vuln_hints.py`

### Adding a New Protocol to Banner Grabbing

1. Open `veilscan/banner_grabber.py`
2. Add to `PROBE_MAP` (or `TLS_PORTS` if it uses TLS):
```python
PROBE_MAP: dict[int, bytes | None] = {
    # ... existing entries ...
    27017: None,  # MongoDB — read-first, sends wire protocol on connect
}
```

3. Add parser to `_parse_banner()`:
```python
def _parse_banner(port: int, banner: str):
    # ... existing parsers ...
    
    # MongoDB
    if port == 27017:
        return ("MongoDB", "", banner[:60])
```

4. Add test to `tests/test_banner_grabber.py`

### Adding a New CLI Flag

1. Open `veilscan/cli.py`
2. Add to `build_parser()`:
```python
p.add_argument("--new-flag", action="store_true", dest="new_flag",
               help="Description of what this flag does")
```

3. Add to `build_config()` or handle in `_run_scan()`
4. Update `ScanConfig` in `veilscan/config.py` if needed

---

## Part 8 — Skills You Learned Building This Project

By studying or building VeilScan, you learned:

### Python Skills
- Dataclasses (`@dataclass`, `__post_init__`, `field()`)
- Enums (`class X(str, Enum)`)
- Threading (`threading.Thread`, `threading.Lock`, `threading.Event`)
- Queue (`queue.Queue`, `get_nowait()`, `task_done()`, `join()`)
- Context managers (`with socket.socket() as sock:`)
- Type hints (`dict[int, str]`, `List[PortInfo]`, `Optional[str]`, `X | Y`)
- Dataclasses serialization (`dataclasses.asdict()`)
- F-string templates for HTML generation
- `argparse` for CLI parsing

### Networking Skills
- TCP/UDP socket programming from scratch
- Reading raw ICMP packets
- TLS/SSL socket wrapping
- Protocol-specific banner parsing (SSH, HTTP, FTP, MySQL, Redis...)
- CIDR notation and IP address manipulation
- Port scanning methodology
- OS fingerprinting via TTL

### Security Skills
- Risk assessment and classification (CRITICAL/HIGH/MEDIUM/LOW/INFO)
- Understanding of common network service vulnerabilities
- XSS prevention via HTML escaping
- Secure output handling
- Ethical scanning practices
- Reading CVE descriptions and understanding their impact
- How real vulnerabilities work (WannaCry/EternalBlue, backdoors, r-services)

### Software Engineering Skills
- Race condition identification and prevention
- Thread-safe data structures
- Error isolation (never let one failure crash the whole system)
- Test-driven development (368 tests, all mocked)
- Package architecture for pip install compatibility
- Progressive enhancement (graceful degradation without optional deps)
- Documentation at multiple levels (code, module, user guide)

---

## Part 9 — What to Learn Next

### If you want to go deeper on network scanning
- Study Nmap scripting engine (NSE) and how .nse scripts work
- Learn about SYN scanning (raw sockets, no full connection)
- Study Scapy for raw packet crafting
- Read RFC 793 (TCP) and RFC 768 (UDP) specifications

### If you want to go deeper on security
- Set up Metasploitable 2 and exploit every port VeilScan found
- Take TryHackMe or HackTheBox beginner rooms
- Study CVE database: https://cve.mitre.org
- Learn about CVSS (Common Vulnerability Scoring System) — the industry standard for risk scoring

### If you want to improve VeilScan
- Add CVE lookup using NVD API (https://nvd.nist.gov/developers/vulnerabilities)
- Add IPv6 support
- Add scan comparison (diff two JSON results)
- Add multi-target file input (`-f targets.txt`)
- Implement SYN scan (raw sockets, needs admin)

### Certifications that use these skills
- **CompTIA Security+** — covers network scanning, vulnerability assessment
- **CEH (Certified Ethical Hacker)** — covers Nmap, scanning methodology
- **OSCP (Offensive Security Certified Professional)** — heavy manual exploitation
- **CompTIA Network+** — deep networking fundamentals

---

## Part 10 — Glossary

| Term | Definition |
|------|-----------|
| Port | A number (1-65535) identifying a service on a machine |
| TCP | Connection-based protocol — reliable, ordered, handshake required |
| UDP | Connectionless protocol — fast, no handshake, no guarantee |
| Banner | Greeting message a service sends when you connect |
| TTL | Time To Live — IP packet counter decremented at each hop |
| ICMP | Internet Control Message Protocol — ping, unreachable messages |
| CVE | Common Vulnerabilities and Exposures — ID for known security flaws |
| CIDR | Classless Inter-Domain Routing — `192.168.1.0/24` notation for subnets |
| RCE | Remote Code Execution — running commands on a machine you don't own |
| r-services | rexec/rlogin/rsh — legacy Unix remote services, all CRITICAL risk |
| EternalBlue | NSA exploit for SMB (port 445) — used by WannaCry |
| .rhosts | Unix trust file — lists hosts allowed to log in without passwords |
| Deserialization | Converting stored/transmitted data back to objects — vulnerable in Java/PHP |
| SNMP | Simple Network Management Protocol — used to manage network devices |
| NFS | Network File System — share directories over a network |
| VNC | Virtual Network Computing — graphical remote desktop |
| TLS | Transport Layer Security — encryption for HTTPS, IMAPS, etc. |
| OPEN\|FILTERED | UDP result meaning "no response — could be open or firewalled" |
