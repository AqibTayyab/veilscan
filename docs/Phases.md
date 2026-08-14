# Phases.md — Development Phases
# VeilScan v2.0

Complete breakdown of how VeilScan was built, phase by phase.
Each phase had a clear goal, specific files, and a verifiable test.

---

## Phase 1 — Data Models & Configuration
**Goal:** Define the data structures everything else depends on.
**Status:** ✅ Complete

### Files Created
- `veilscan/models.py` — PortState, PortInfo, HostResult, ScanResult
- `veilscan/config.py` — ScanConfig dataclass + 4 scan profiles

### Key Decisions
- `PortState` inherits `str` so it serialises to JSON without custom encoder
- `ScanConfig.__post_init__` validates all fields immediately — errors surface at startup, not mid-scan
- `PROFILES` use `target=""` as a sentinel — overwritten before every scan
- Config lives inside `veilscan/` package (not root) — required for pip install

### Tests Written
- `tests/test_models.py` — 38 tests
- `tests/test_config.py` — 30 tests

### Acceptance Criteria
- [x] `PortState.OPEN == "open"` (inherits str)
- [x] `ScanConfig(target="x", threads=0)` raises `ValueError`
- [x] `ScanConfig.from_dict(cfg.to_dict())` roundtrip is lossless
- [x] All 4 profiles have correct thread/timeout/port values

---

## Phase 2 — Utilities & Port Map
**Goal:** Build all helper functions needed by the scanner.
**Status:** ✅ Complete

### Files Created
- `veilscan/utils.py` — port map, TOP_100, parse_ports, expand_cidr, os_hint, validate_target, estimate_scan_time

### Key Decisions
- `TOP_100` is manually curated to exactly 100 ports — verified unique, no duplicates
- `parse_ports()` catches non-numeric input with helpful message not raw Python error
- `validate_target()` blocks 0.0.0.0, broadcast, multicast, IPv6 before any socket opens
- `estimate_scan_time()` added for large-scan warning in CLI
- `os_hint()` interprets TTL values: ≤64=Linux, ≤128=Windows, ≤255=Network device

### Tests Written
- `tests/test_utils.py` — 50 tests

### Acceptance Criteria
- [x] `len(TOP_100) == 100` with no duplicates
- [x] `parse_ports("22,80-82,443")` returns `[22, 80, 81, 82, 443]`
- [x] `expand_cidr("192.168.1.0/24")` returns 254 hosts
- [x] `validate_target("0.0.0.0")` raises ValueError
- [x] `os_hint(48)` returns "Linux/Unix (TTL=48)"

---

## Phase 3 — TCP Scanning Engine
**Goal:** Fast, race-condition-free TCP port scanning.
**Status:** ✅ Complete

### Files Created
- `veilscan/tcp_scanner.py` — scan_tcp_port + scan_tcp_batch

### Key Bug Fixed (from v1.0)
**v1.0 race condition:**
```python
# BROKEN — two separate operations, thread can steal item between them
while not queue.empty():
    port = queue.get()
```
**v2.0 fix:**
```python
# ATOMIC — single operation, no race possible
try:
    port = queue.get_nowait()
except queue.Empty:
    return
```

### Key Decisions
- `ECONNREFUSED` (111/10061) = definitive CLOSED, never retry
- Timeout = retryable — flaky networks get a second chance
- `task_done()` in `finally` — queue.join() never deadlocks
- `stop_event` drains queue completely on abort — clean Ctrl+C
- Thread count capped at `len(ports)` — no idle threads

### Tests Written
- `tests/test_tcp_scanner.py` — 21 tests

### Acceptance Criteria
- [x] Open port → `PortState.OPEN`
- [x] `ECONNREFUSED` → `PortState.CLOSED` with 0 retries
- [x] Timeout → retries, then `PortState.CLOSED`
- [x] 200 ports, 20 threads → no duplicate results
- [x] `stop_event.set()` → scan aborts early

---

## Phase 4 — UDP Scanning Engine
**Goal:** UDP scanning with ICMP feedback and service probes.
**Status:** ✅ Complete

### Files Created
- `veilscan/udp_scanner.py` — UDP_PROBES, check_udp_privileges, scan_udp_port, scan_udp_batch

### Key Bug Fixed (from previous version)
**Previous behavior:** Raw ICMP socket failure silently made ALL ports `OPEN|FILTERED`. No warning printed. 200 useless identical results.

**v2.0 fix:** `check_udp_privileges()` tests ICMP socket availability BEFORE the scan starts. Prints clear warning if unavailable:
```
[!] UDP SCAN — LIMITED ACCURACY
Raw ICMP socket requires Administrator on Windows.
→ Right-click CMD → Run as Administrator for accurate results.
```

### UDP Probes Added (v1.0 had 4, v2.0 has 11)
| Port | Service | Probe Type |
|------|---------|-----------|
| 53 | DNS | Version query |
| 123 | NTP | Client mode request |
| 161 | SNMP | GetRequest sysDescr |
| 67 | DHCP | Discover packet |
| 137 | NetBIOS-NS | Node status |
| 138 | NetBIOS-DGM | Broadcast datagram |
| 69 | TFTP | Read request |
| 514 | Syslog | RFC 3164 test message |
| 5353 | mDNS | Service discovery |
| 1900 | UPnP/SSDP | M-SEARCH request |
| 19 | Chargen | Empty (server sends) |

### Tests Written
- `tests/test_udp_scanner.py` — 26 tests

### Acceptance Criteria
- [x] UDP response → `PortState.OPEN`
- [x] No response, no ICMP → `PortState.OPEN_FILTERED`
- [x] `check_udp_privileges()` returns `(bool, str)` tuple
- [x] Thread cap ≤ 50 regardless of config
- [x] All 11 probes present in `UDP_PROBES`

---

## Phase 5 — Banner Grabbing / Fingerprinting
**Goal:** Connect to open ports and detect exact service versions.
**Status:** ✅ Complete

### Files Created
- `veilscan/banner_grabber.py` — _parse_banner, grab_banner, _connect

### Key Bug Fixed (from previous version)
**Previous behavior:** Port 443 (HTTPS) sent plaintext `b"\r\n"` to a TLS socket. Server closed connection. HTTPS version strings never captured.

**v2.0 fix:** `_connect()` wraps HTTPS ports with `ssl.create_default_context()`:
```python
TLS_PORTS = {443, 8443, 993, 995, 465}
if port in TLS_PORTS:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False  # scanning, not verifying
    ctx.verify_mode = ssl.CERT_NONE
    return ctx.wrap_socket(raw, server_hostname=ip)
```

### Protocol Parsers Added
- SSH: `SSH-2.0-OpenSSH_8.9p1` → service="SSH", version="OpenSSH_8.9p1"
- HTTP: `Server: Apache/2.4.54` header → service="HTTP", version="Apache/2.4.54"
- HTTPS: same but service="HTTPS" for port 443
- FTP: `220 ProFTPD 1.3.6` → service="FTP", version="ProFTPD 1.3.6"
- SMTP: `220 mail ESMTP Postfix` → service="SMTP", version contains Postfix
- POP3/IMAP: greeting parsing
- Redis: `+PONG` or `-ERR` → service="Redis"
- Memcached: `VERSION 1.6.17` → version="1.6.17"
- MySQL/MariaDB: version string from binary handshake
- PostgreSQL: protocol detection by port
- VNC: `RFB 003.003` → service="VNC", version="003.003" (not "RFB 003.003")
- IRC: `:server NOTICE AUTH` → service="IRC"
- Telnet: port 23 detection

### Tests Written
- `tests/test_banner_grabber.py` — 44 tests

### Acceptance Criteria
- [x] SSH version parsed: "OpenSSH_8.9p1"
- [x] HTTPS (443) → service="HTTPS" not "HTTP"
- [x] VNC version: "003.003" not "RFB 003.003"
- [x] Banner truncated to 256 chars
- [x] Any exception → `("", "", "")` — never raises
- [x] Binary MySQL handshake decoded safely

---

## Phase 6 — Scanner Orchestrator
**Goal:** Wire all modules into a complete scan pipeline.
**Status:** ✅ Complete

### Files Created
- `veilscan/scanner.py` — Scanner class

### Key Bug Fixed (from previous version)
**Previous OS hint behavior:** Used `getsockopt(IPPROTO_IP, IP_TTL)` which on Windows returns the LOCAL outgoing TTL (always 128). Every scan showed "Windows (TTL=128)" regardless of target OS.

**v2.0 fix:** Send UDP to closed port, read TTL from byte 8 of ICMP response:
```python
raw = socket.socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
udp.sendto(b"\x00", (ip, 45678))  # triggers ICMP Port Unreachable
data, addr = raw.recvfrom(1024)
if addr[0] == ip and len(data) >= 9:
    ttl = data[8]  # actual REMOTE host TTL
    return os_hint(ttl)
```

**Result verified:** Metasploitable (Linux) now correctly shows "Linux/Unix (TTL=64)" not "Windows (TTL=128)".

### Banner Timeout Fix
Quick profile: `timeout=0.5s`, so previous `banner_timeout = timeout * 2 = 1.0s`. TLS handshake takes 0.8–1.5s → HTTPS banners consistently failed.

**v2.0 fix:** `banner_timeout = max(cfg.timeout * 2, 3.0)` — minimum 3 seconds for banners regardless of profile.

### Tests Written
- `tests/test_scanner.py` — 30 tests

### Acceptance Criteria
- [x] Returns `ScanResult` always (never raises)
- [x] `scanner_version = "2.0.0"` in result
- [x] CIDR /30 → 2 hosts scanned
- [x] Unresolvable host → `HostResult(ip="unresolved")`
- [x] Banner timeout ≥ 3.0s even with quick profile (timeout=0.5s)
- [x] `stop_event` aborts subnet scan early

---

## Phase 7 — Vulnerability Hints Database
**Goal:** Plain-English explanations for 42 common services.
**Status:** ✅ Complete

### Files Created
- `veilscan/vuln_hints.py` — HINTS dict, ServiceHint dataclass, lookup functions

### Critical Additions (were missing in earlier versions)
| Port | Service | Risk | Why Critical |
|------|---------|------|--------------|
| 111 | RPCbind | HIGH | Maps all RPC services for attackers |
| 512 | rexec | CRITICAL | No auth, no encryption, 1980s relic |
| 513 | rlogin | CRITICAL | .rhosts trust = passwordless login |
| 514 | rsh | CRITICAL | Same .rhosts exploit as rlogin |
| 1099 | Java-RMI | CRITICAL | RCE via deserialization |
| 2049 | NFS | HIGH | Exports /root on Metasploitable |
| 6667 | IRC | MEDIUM | UnrealIRCd backdoor CVE-2010-2075 |

These are all ports found on Metasploitable — having them explain themselves in the HTML report is the core educational value.

### Tests Written
- `tests/test_vuln_hints.py` — 47 tests

### Acceptance Criteria
- [x] All Metasploitable ports covered
- [x] All 42 hints have 6 non-empty fields
- [x] All risk levels are valid (CRITICAL/HIGH/MEDIUM/LOW/INFO)
- [x] `risk_sort_key("CRITICAL") > risk_sort_key("HIGH")`
- [x] `RISK_COLORS` has bg/border/text/badge for all 5 levels

---

## Phase 8 — Reporter & HTML Report
**Goal:** Format results for terminal, files, and browser.
**Status:** ✅ Complete

### Files Created
- `veilscan/reporter.py` — CLI table + JSON/CSV/TXT
- `veilscan/html_reporter.py` — HTML report generator

### Key Bug Fixed — Dynamic Table Columns
Previous: fixed column widths caused `VMware-Auth-Alt` (15 chars) to overflow the SERVICE column (14 chars), misaligning VERSION for all subsequent rows.

**v2.0 fix:** Column widths calculated from actual content at render time:
```python
max_service = max(len(p.service) for p in ports_to_show)
w_service   = max(max_service, 14)  # minimum 14, grows as needed
```

### Key Bug Fixed — Blank INFO Cards
Previous: ports not in `HINTS` database got blank HTML card (just port number and "INFO" badge, no explanation).

**v2.0 fix:** Generic fallback card:
```
Port 9999/TCP is open. Not in VeilScan's hints database.
Identify what service is running. Verify it should be accessible.
Search online for "port 9999 security" to learn about this service.
```

### Key Bug Fixed — HTML Injection
Previous: banner text inserted with only `<` and `>` replaced. Quotes and `&` could break HTML structure.

**v2.0 fix:** `html.escape(str(text), quote=True)` on all user-derived content.

### Tests Written
- `tests/test_html_reporter.py` — 42 tests

### Acceptance Criteria
- [x] `<script>` in banner → `&lt;script&gt;` in HTML
- [x] Unknown port → fallback card with "hints database" text
- [x] CRITICAL ports sorted before LOW/INFO
- [x] OS hint shown in findings section
- [x] CSV has header + one row per port (banner newlines removed)

---

## Phase 9 — CLI, Wizard & Packaging
**Goal:** Full command-line interface, interactive wizard, pip install support.
**Status:** ✅ Complete

### Files Created
- `veilscan/cli.py` — CLI + wizard
- `veilscan/__main__.py` — `python -m veilscan` support
- `main.py` — root entry point (delegates to `veilscan.cli`)
- `pyproject.toml` — pip packaging
- `requirements.txt`, `.gitignore`, `README.md`

### Key Fix — pip Install Architecture
Previous: entry point → `veilscan.__main__:main` → `from main import main` (root file, not installed by pip) → `ModuleNotFoundError`.

**v2.0 fix chain:**
```
pip install veilscan
→ installs veilscan/ package
→ veilscan command → pyproject.toml entry point
→ veilscan.__main__:main
→ veilscan/__main__.py: from veilscan.cli import main
→ veilscan/cli.py: main()  ✅ works everywhere
```

### New Features in CLI
- **Interactive wizard** — launched when no target given
- **Python version check** — clear error on < 3.10
- **Target validation** — checks before scan starts
- **Scan size warning** — estimates time, asks confirmation if > 5 minutes
- **Audit log** — `logs/scan_history.log` records every scan
- **`--auto-report`** — saves HTML + JSON + CSV to `reports/`

### Tests Written
- All CLI logic covered through `tests/test_scanner.py` + manual testing

### Acceptance Criteria
- [x] `python main.py` → interactive wizard launches
- [x] `python main.py scanme.nmap.org --profile quick --agree` → scans and prints results
- [x] `python main.py 192.168.140.130 --profile standard --agree --auto-report` → saves 3 report files
- [x] `pip install veilscan && veilscan --version` → works without `main.py`
- [x] HTML report opens in browser and shows risk cards

---

## Phase 10 — Full Test Suite
**Goal:** 368 tests covering all 9 modules.
**Status:** ✅ Complete

### Test Summary
| File | Tests | Coverage |
|------|-------|----------|
| test_models.py | 38 | PortState, PortInfo, HostResult, ScanResult |
| test_utils.py | 50 | parse_ports, expand_cidr, os_hint, validate_target |
| test_config.py | 30 | ScanConfig, validation, profiles |
| test_tcp_scanner.py | 21 | scan_tcp_port, scan_tcp_batch, race conditions |
| test_udp_scanner.py | 26 | scan_udp_port, ICMP, probes, batch |
| test_banner_grabber.py | 44 | _parse_banner, grab_banner, TLS, VNC, IRC |
| test_scanner.py | 30 | full pipeline, UDP/banner integration |
| test_html_reporter.py | 42 | HTML structure, escaping, fallback cards |
| test_vuln_hints.py | 47 | all 42 hints, risk levels, Metasploitable coverage |
| **Total** | **368** | |

### Run Tests
```bash
pip install pytest
pytest tests/ -v
```

---

## Phase 11 — Documentation & GitHub (Current Phase)
**Goal:** Professional documentation for GitHub and LinkedIn.
**Status:** 🔄 In Progress

### Files Being Created
- `PRD.md` — Product Requirements Document
- `Architecture.md` — Technical Architecture
- `Rules.md` — Development Rules
- `Phases.md` — This file
- `Design.md` — Visual Design
- `Memory.md` — Project Memory
- `Security.md` — Security Parameters

### Next Steps
1. Push all code to GitHub
2. Create GitHub release v2.0.0 with release notes
3. Write LinkedIn post
4. Publish to PyPI: `pip install veilscan`

---

## Phase 12 — v2.1 Roadmap (Future)
**Goal:** Add CVE lookup and multi-target file input.

### Planned Features
- [ ] CVE version lookup — "Apache/2.2.8 → 28 known CVEs, EOL since 2017"
- [ ] Service version age check — flag software > 3 years old
- [ ] Multi-target file input — `python main.py -f targets.txt`
- [ ] Scan comparison — diff two scan results
- [ ] Nmap XML import/export compatibility
- [ ] IPv6 support
