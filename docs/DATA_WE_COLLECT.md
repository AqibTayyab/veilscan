# Data We Collect
# VeilScan v2.0 — Complete Data Disclosure

**Effective Date:** August 2026
**Author:** Aqib Tayyab
**Purpose:** Full transparency about every piece of data VeilScan touches,
stores, sends, and processes — before, during, and after a scan.

---

## The Short Version

```
Data sent to VeilScan servers:     NONE (no servers exist)
Data stored on your machine:       Minimal local log only
Data sent to scan targets:         Standard network probes only
Data shared with third parties:    NONE
Telemetry or analytics:            NONE
```

---

## 1. Before You Scan — Setup Phase

### What happens when you install VeilScan

**Via pip (`pip install veilscan`):**
- pip downloads the package from PyPI (Python Package Index)
- PyPI may log your IP address and download timestamp — this is PyPI's standard behavior, not VeilScan's
- VeilScan itself logs nothing during installation

**Via GitHub download:**
- GitHub may log your IP address — this is GitHub's standard behavior
- VeilScan logs nothing during download or extraction

**After installation:**
- VeilScan creates no files, no registry entries, no background processes
- Nothing runs until you explicitly run a scan command

### Data collected during setup: NONE by VeilScan

---

## 2. During a Scan — Active Phase

### 2.1 Data You Provide

| What you type | Where it goes | Stored? |
|--------------|--------------|---------|
| Target IP or hostname | Used for network connection only | Only in audit log (minimal) |
| Port specification | Used for scan configuration only | Not stored |
| Profile selection | Used for scan settings only | Not stored |
| `--agree` confirmation | Bypasses consent prompt | Not stored |
| Output file path | Used to save your report | Not stored by VeilScan |

### 2.2 Data Sent to Your Scan Target

VeilScan sends the following to the target machine you specify. This is inherent to how port scanning works — the target will see connections from your IP address.

#### TCP Connections
For each TCP port scanned:
```
Source:      Your IP address + random high port
Destination: Target IP + scanned port number
Data sent:   Standard TCP SYN handshake only (no application data)
```

#### Banner Grabbing (for open TCP ports)
After a port is found open, VeilScan sends a small probe to read the service version:

| Port | Probe Sent | Size |
|------|-----------|------|
| 80, 8080, 8443, etc. | `GET / HTTP/1.0\r\nHost: target\r\nUser-Agent: VeilScan/2.0\r\n\r\n` | ~60 bytes |
| 443, 8443 (HTTPS) | Same HTTP probe over TLS | ~60 bytes + TLS handshake |
| 6379 (Redis) | `*1\r\n$4\r\nPING\r\n` | 14 bytes |
| 21 (FTP) | Nothing — reads first | 0 bytes |
| 22 (SSH) | Nothing — reads first | 0 bytes |
| 25, 110, 143, etc. | Nothing — reads first | 0 bytes |
| All other ports | `\r\n` | 2 bytes |

**No credentials, no personal data, no exploit code is ever sent.**

#### UDP Probes (if `--udp` flag used)
For each UDP port scanned, one of these probes is sent:

| Port | Probe | Size |
|------|-------|------|
| 53 (DNS) | DNS version query | ~35 bytes |
| 123 (NTP) | NTP client request | 48 bytes |
| 161 (SNMP) | SNMP GetRequest (community: "public") | ~40 bytes |
| 67 (DHCP) | DHCP Discover | ~45 bytes |
| 137 (NetBIOS-NS) | Node status request | ~50 bytes |
| 138 (NetBIOS-DGM) | Broadcast datagram | ~50 bytes |
| 69 (TFTP) | Read request for "test" | ~15 bytes |
| 514 (Syslog) | Test syslog message | ~25 bytes |
| 5353 (mDNS) | Service discovery | ~30 bytes |
| 1900 (UPnP/SSDP) | M-SEARCH discovery | ~100 bytes |
| 19 (Chargen) | Empty | 0 bytes |
| All other UDP | `\x00` | 1 byte |

#### OS Fingerprinting (if admin/root available)
```
Sends:   b"\x00" to port 45678 (UDP — almost certainly closed)
Purpose: Triggers ICMP Port Unreachable response
Reads:   TTL value from the ICMP response (byte 8 of IP header)
Stored:  Only as "Linux/Unix (TTL=64)" string in the scan result
```

### 2.3 Data Received FROM the Target

VeilScan reads what the target sends back:

| Response Type | Example | How VeilScan Uses It |
|--------------|---------|---------------------|
| TCP SYN-ACK | Connection accepted | Records port as OPEN |
| TCP RST | Connection refused | Records port as CLOSED |
| Service banner | `SSH-2.0-OpenSSH_8.9p1` | Parses for service + version |
| HTTP response | `HTTP/1.1 200 OK\r\nServer: Apache/2.4\r\n` | Extracts Server header |
| ICMP Unreachable | Port Unreachable message | Records UDP port as CLOSED |
| TTL in ICMP | Value 64 in IP header | Derives OS hint |

**All received data is:**
- Truncated to 256 characters before storage
- HTML-escaped before insertion into HTML reports
- Stored only locally in your report files
- Never sent to any VeilScan server

---

## 3. After a Scan — Storage Phase

### 3.1 Audit Log Entry

**Every scan** appends exactly one line to `logs/scan_history.log`:

```
[2026-08-08 03:37:35]  target=192.168.140.130  open_ports=16  duration=25.78s
```

**Fields stored:**
| Field | Example | Why |
|-------|---------|-----|
| Timestamp | `2026-08-08 03:37:35` | When the scan ran |
| Target | `192.168.140.130` | What was scanned |
| Open port count | `open_ports=16` | How many ports found open |
| Duration | `duration=25.78s` | How long the scan took |

**NOT stored in the log:**
- Which specific ports were open
- Service names or versions
- Banner content
- Risk assessments
- Your username or any personal information

**File location:** `logs/scan_history.log` (inside VeilScan folder, your machine only)
**Accessible by:** Only you (local file, no network access)
**Delete by:** `del logs\scan_history.log` (Windows) or `rm logs/scan_history.log` (Linux/Mac)

### 3.2 Scan Reports (Only When You Request Them)

Created only when you use `--auto-report` or `-o`:

#### HTML Report (`reports/scan_*.html`)
Contains:
- Target hostname/IP
- Scan timestamp and duration
- Scan configuration (ports, threads, timeout)
- List of open ports with service names and versions
- Banner content (truncated, HTML-escaped)
- Risk assessments and explanations
- OS fingerprint hint

Does NOT contain:
- Your username or personal information
- Credentials or authentication data
- Data from your own machine

#### JSON Report (`reports/scan_*.json`)
Contains the same data as HTML report, in machine-readable format.

Serialized structure:
```json
{
  "hosts": [
    {
      "host": "192.168.140.130",
      "ip": "192.168.140.130",
      "os_hint": "Linux/Unix (TTL=64)",
      "ports": [
        {
          "port": 22,
          "protocol": "tcp",
          "state": "open",
          "service": "SSH",
          "version": "OpenSSH_4.7p1",
          "banner": "SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1"
        }
      ]
    }
  ],
  "start_time": "2026-08-08T03:37:35",
  "duration": 25.78,
  "scanner_version": "2.0.0",
  "config": {
    "target": "192.168.140.130",
    "ports": "top100",
    "threads": 200,
    "timeout": 0.5
  }
}
```

#### CSV Report (`reports/scan_*.csv`)
Contains one row per open port:
```
host,ip,os_hint,port,protocol,state,service,version,banner
192.168.140.130,192.168.140.130,Linux/Unix (TTL=64),22,tcp,open,SSH,OpenSSH_4.7p1,...
```

**All report files:**
- Stored locally only — never uploaded
- Listed in `.gitignore` — not included in git commits
- Your responsibility to keep secure (contain sensitive network info)

---

## 4. What VeilScan Never Does

This section exists for absolute clarity:

| Action | Does VeilScan do this? |
|--------|----------------------|
| Send scan results to a remote server | ❌ Never |
| Phone home or check for updates | ❌ Never |
| Collect usage statistics | ❌ Never |
| Record keystrokes or commands | ❌ Never |
| Access files outside VeilScan folder | ❌ Never |
| Create background processes | ❌ Never |
| Access your browser or cookies | ❌ Never |
| Read other applications' data | ❌ Never |
| Store passwords or credentials | ❌ Never |
| Execute code received from network | ❌ Never |
| Connect to advertising networks | ❌ Never |
| Share data with third parties | ❌ Never |

---

## 5. Data Minimization Principles Applied

VeilScan was designed with data minimization from the start:

| Principle | How VeilScan Applies It |
|-----------|------------------------|
| Collect only what's needed | Audit log stores only target, port count, duration |
| Store locally, not remotely | All data stays on your machine |
| Truncate at collection | Banners limited to 256 chars on read |
| Escape at storage | HTML report escapes all network data |
| User controls deletion | Delete files manually at any time |
| No hidden data flows | Open source — every line verifiable |

---

## 6. Data You Should Protect

While VeilScan collects minimal data, the reports it generates contain sensitive security information. You should:

**Protect report files because they contain:**
- Open port lists (useful for attackers if your target is not a lab)
- Software version strings (useful for finding CVEs)
- Network topology information
- Service banners with detailed software info

**Best practices:**
- Store reports in an encrypted folder for production networks
- Do not commit reports to public git repositories (`.gitignore` already prevents this)
- Delete reports when no longer needed
- Do not share reports via unencrypted email or chat

---

## 7. Data Flow Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                        YOUR MACHINE                          │
│                                                              │
│  You type: python main.py 192.168.140.130 --agree           │
│                    │                                         │
│                    ▼                                         │
│            [VeilScan Process]                                │
│                    │                                         │
│     ┌──────────────┼──────────────┐                         │
│     ▼              ▼              ▼                          │
│  TCP probe     UDP probe      HTTP GET/                      │
│  (port check)  (optional)     (banner)                       │
│     │              │              │                          │
└─────┼──────────────┼──────────────┼─────────────────────────┘
      │              │              │
      ▼              ▼              ▼
┌─────────────────────────────────────────────────────────────┐
│                    SCAN TARGET (your lab)                     │
│              192.168.140.130 (Metasploitable)                │
│    Sends back: SYN-ACK / RST / Banner / ICMP response        │
└─────────────────────────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────────────┐
│                        YOUR MACHINE                          │
│                                                              │
│  VeilScan processes results (local only)                     │
│                    │                                         │
│     ┌──────────────┼──────────────┐                         │
│     ▼              ▼              ▼                          │
│  Terminal       reports/         logs/                        │
│  output         *.html           scan_history.log            │
│  (stdout)       *.json           (minimal: target,           │
│                 *.csv            port count, duration)        │
│                                                              │
│  ❌ NO DATA leaves your machine to VeilScan servers          │
└─────────────────────────────────────────────────────────────┘
```

---

## 8. Verification

Because VeilScan is fully open source, you can verify every claim in this document:

| Claim | Where to verify in source code |
|-------|-------------------------------|
| No external HTTP calls | Search codebase: `grep -r "requests\|urllib\|httpx" veilscan/` |
| Audit log stores only 4 fields | `veilscan/cli.py` → `log_scan_history()` function |
| Banner truncated at 256 chars | `veilscan/banner_grabber.py` → `grab_banner()` return |
| HTML content escaped | `veilscan/html_reporter.py` → `_esc()` function |
| No background processes | No `subprocess`, `daemon`, or `schedule` imports |
| No credential storage | Search: `grep -r "password\|credential\|token" veilscan/` |

**Source code:** https://github.com/AqibTayyab/veilscan
