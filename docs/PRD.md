# PRD.md — Product Requirements Document
# VeilScan v2.0 — Network Security Audit Tool

**Version:** 2.0.0 | **Author:** Aqib Tayyab | **Status:** Released

---

## 1. Problem Statement

Existing network scanning tools have one of two problems:

| Tool | Problem |
|------|---------|
| Nmap | Powerful but cryptic — output is raw port numbers, no explanations |
| Online scanners | Limited features, cloud-dependent, no local lab support |
| Metasploit | Exploitation focus — too advanced for audit/education |

**No existing beginner tool explains what each open port means, rates risk in plain English, and produces a professional report.**

---

## 2. Target Users

### Primary — Security Beginners
Students, CTF participants, home lab users (Metasploitable, DVWA, VulnHub).
**Need:** Simple UI, plain-English explanations, guided output.

### Secondary — Network Administrators
Sysadmins auditing infrastructure, small business IT staff doing security baselines.
**Need:** Fast scanning, professional reports, JSON/CSV output.

### Tertiary — Security Professionals
Pentesters doing initial recon, developers integrating scanning into pipelines.
**Need:** Python API, flexible CLI, reliable structured output.

---

## 3. Core Features

### 3.1 TCP Port Scanning
- Thread-pool with configurable threads (1–1000)
- `socket.connect_ex()` — full TCP connect scan
- Retry logic for flaky networks
- Race condition free (atomic `get_nowait()`)
- Live progress bar per phase

### 3.2 UDP Port Scanning
- ICMP Port Unreachable detection for CLOSED state
- 11 service-specific probes (DNS, NTP, SNMP, DHCP, NetBIOS, TFTP, mDNS, UPnP, syslog, chargen)
- Clear admin privilege warning on Windows without Administrator
- Results: OPEN / CLOSED / OPEN|FILTERED

### 3.3 Banner Grabbing / Service Fingerprinting
- TLS support for HTTPS (443, 8443) via stdlib `ssl` module
- 15+ protocol parsers: SSH, HTTP/S, FTP, SMTP, POP3, IMAP, MySQL, MariaDB, PostgreSQL, Redis, Memcached, VNC (RFB), IRC, Telnet, MongoDB
- Returns: service name + exact version string + raw banner (truncated 256 chars)
- Never raises — `("", "", "")` on any failure

### 3.4 OS Fingerprinting
- TTL-based: sends UDP to closed port, reads TTL from ICMP response byte 8
- Actual remote TTL (not local default — previous bug was reading local TTL)
- Returns "" gracefully when ICMP unavailable (no admin)

### 3.5 Vulnerability Hints Database
- 42 entries covering all ports commonly found in lab environments
- Per entry: service, what, risk, why, check, learn
- Full Metasploitable coverage: r-services (512/513/514), Java-RMI, NFS, IRC backdoor

### 3.6 HTML Report
- Standalone — opens in any browser, no server required
- CRITICAL findings sorted to top
- Fallback cards for ports not in database
- All content HTML-escaped (XSS-safe)
- Print CSS for clean paper output

### 3.7 Output Formats
- HTML — human-readable, color-coded, beginner-friendly
- JSON — complete data, for scripts/SIEM
- CSV — one row per port, for Excel/Sheets
- TXT — ANSI-free, for logs/emails

### 3.8 Interactive Wizard
- Launched automatically when no arguments given
- Step-by-step: target → scan type → UDP → reports
- No CLI knowledge required

### 3.9 Scan Profiles
| Profile | Ports | Threads | Timeout | Use Case |
|---------|-------|---------|---------|----------|
| quick | top 100 | 200 | 0.5s | First look |
| standard | top 1000 | 100 | 1.0s | General audit |
| full | all 65535 | 50 | 2.0s | Complete audit |
| stealth | top 100 | 10 | 3.0s | Quiet scan |

---

## 4. Non-Goals

- No exploitation — finds and explains vulnerabilities, does not exploit them
- No authentication bypass — only connects as a normal client
- No raw packet crafting (SYN scan) — full TCP connect only
- No brute forcing — no password guessing
- No IPv6 — IPv4 only in v2.0
- No cloud scanning API — local execution only

---

## 5. Constraints

- **Language:** Python 3.10+ only
- **Dependencies:** Zero mandatory (pure stdlib)
- **Optional:** `colorama` for Windows CMD colors
- **OS:** Windows / Linux / macOS

---

## 6. Legal and Ethical Requirements

- Consent prompt for all non-private-IP targets (skippable with `--agree`)
- "For authorized use only" on every output
- Audit trail: `logs/scan_history.log` records every scan
- Educational framing — explains findings, does not enable exploitation
- Reports in `.gitignore` — users cannot accidentally commit scan data

---

## 7. Success Metrics

| Metric | Target |
|--------|--------|
| Beginner completes first scan | < 60 seconds from download |
| Metasploitable port coverage | 100% of standard ports detected with explanations |
| Test coverage | 368 tests, all modules covered |
| Zero mandatory dependencies | ✅ |
| pip install works | ✅ |
| Verified real scan: 19 ports on Metasploitable | ✅ |
