# Security.md — Security Parameters & Code Hardening
# VeilScan v2.0

This document defines every security concern in the VeilScan codebase —
both the security of the tool itself and the security of the code that runs it.

---

## 1. Threat Model

VeilScan runs on the attacker's machine (or the auditor's machine) and connects
outbound to a target. The threat model covers:

| Threat | Source | Impact | Status |
|--------|--------|--------|--------|
| XSS in HTML report | Malicious banner from target | Report shows attacker script | ✅ Fixed |
| HTML injection | Special chars in banner/version | Broken report layout | ✅ Fixed |
| Scanning unauthorized targets | User error or malice | Legal liability | ✅ Mitigated |
| Credentials in audit log | Log captures sensitive data | Privacy breach | ✅ Not a risk |
| Arbitrary code execution via network | eval() on received data | Full compromise | ✅ Never happens |
| Sensitive data in reports committed to git | Accidental git add | Data exposure | ✅ .gitignore |
| Malformed ICMP crashing scanner | Crafted ICMP response | Scanner crash | ✅ Length checked |
| Buffer overflow via huge banner | Target sends GB of data | Memory exhaustion | ✅ Capped at 4KB recv |

---

## 2. Input Security

### 2.1 Target Validation
**File:** `veilscan/utils.py` → `validate_target()`

All scan targets are validated before any socket is opened:

```python
def validate_target(target: str) -> None:
    if not target: raise ValueError("Target cannot be empty.")
    host = target.split("/")[0].strip()
    if ":" in host:
        raise ValueError(f"IPv6 '{target}' not yet supported.")
    try:
        addr = ipaddress.ip_address(host)
        if str(addr) == "0.0.0.0":
            raise ValueError("Target '0.0.0.0' is not a valid scan target.")
        if addr.is_multicast:
            raise ValueError(f"'{target}' is a multicast address.")
        if str(addr) == "255.255.255.255":
            raise ValueError("'255.255.255.255' is the broadcast address.")
    except ValueError:
        pass  # hostname — let DNS resolution handle it
```

**Blocked targets:**
- Empty string
- `0.0.0.0` — scanning all interfaces (almost certainly a mistake)
- `255.255.255.255` — broadcast
- `224.0.0.0/4` — multicast ranges
- IPv6 addresses — not yet supported, would cause confusing errors

**Not blocked (by design):**
- Private IPs — intentional, lab scanning is primary use case
- Hostnames — validated later by `resolve_host()`

### 2.2 Port Specification Validation
**File:** `veilscan/utils.py` → `parse_ports()`

Port numbers validated to be in range 1–65535 with helpful error messages:
```python
if not 1 <= n <= 65535:
    raise ValueError(f"Port {n} is out of bounds. Valid ports are 1–65535.")
```

Range order validated:
```python
if start > end:
    raise ValueError(f"Invalid range '{part}': start ({start}) > end ({end}).")
```

### 2.3 ScanConfig Validation
**File:** `veilscan/config.py` → `ScanConfig.__post_init__()`

All config values validated immediately on creation:
```python
_clamp_or_raise("threads", self.threads, 1, 1000)
_clamp_or_raise("timeout", self.timeout, 0.1, 30.0)
_clamp_or_raise("retries", self.retries, 0, 5)
if self.output_fmt not in {"json","csv","txt"}:
    raise ValueError(...)
```

**Why this matters:** Validation at config creation means errors surface immediately with a clear message, not 30 seconds into a scan inside a worker thread.

---

## 3. Output Security — HTML Report

### 3.1 XSS Prevention
**File:** `veilscan/html_reporter.py` → `_esc()`

**Risk:** A malicious target could serve a crafted banner containing JavaScript:
```
SSH-2.0-<script>alert('xss')</script>
```

If inserted raw into HTML, this script executes when the victim opens the report.

**Fix:** All user-derived content is HTML-escaped before insertion:
```python
import html as _html

def _esc(text: str) -> str:
    return _html.escape(str(text), quote=True)
```

`quote=True` escapes single and double quotes as well as `<`, `>`, `&`.

**Applied to:**
- `p.banner` — raw service banner from network
- `p.version` — version string from banner
- `p.service` — service name
- `host.host` — target hostname/IP
- `host.ip` — resolved IP address
- `host.os_hint` — OS fingerprint string
- `result.config["target"]` — target as provided by user
- `result.scanner_version` — version string

**Not applied to:**
- HTML structural elements (our own templates) — these are safe by design
- CSS values — not derived from user input
- Risk levels — only from our own HINTS database

### 3.2 HTML Structure Safety
The HTML report uses Python f-strings for template construction. Structural HTML (tags, attributes, CSS) is never derived from network data. Only content between tags is user-derived and always escaped.

```python
# CORRECT — _esc() wraps all network-derived content
f'<span style="font-size:14px;">{_esc(hint.what)}</span>'

# Never done — structural tags never from network data
f'<{user_tag}>{content}</{user_tag}>'  # This never appears in codebase
```

### 3.3 No JavaScript in Reports
The HTML report contains no JavaScript whatsoever. No `<script>` tags, no `onclick` handlers, no event listeners. The report is purely HTML + CSS.

This means:
- No XSS execution surface even if escaping somehow fails
- Works with JavaScript disabled in browser
- No Content Security Policy issues

---

## 4. Network Data Security

### 4.1 Never Execute Network Data
VeilScan reads network responses and parses them as text. It never:
- `eval()` or `exec()` network content
- `subprocess.run()` with network-derived strings
- `pickle.loads()` any received data
- Follow redirects (no HTTP redirect support)
- Run received code in any interpreter

### 4.2 Banner Size Limits
**File:** `veilscan/banner_grabber.py`

Socket reads are limited to 4KB per connection:
```python
raw = sock.recv(4096)  # Max 4KB from network
```

Banner text is truncated to 256 chars before storage:
```python
truncated = text[:256]
return (svc, ver, truncated)
```

HTML report further truncates to 150 chars for display:
```python
short = _esc(p.banner[:150])
```

This prevents memory exhaustion if a target sends a huge response.

### 4.3 SSL Certificate Validation Disabled (By Design)
**File:** `veilscan/banner_grabber.py` → `_connect()`

```python
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
```

**Why this is correct for a scanner:**
- We are connecting to unknown targets, not known services
- Self-signed certs are extremely common in lab environments
- Expired certs are extremely common on legacy targets
- Certificate validation would prevent reading banners from most real-world targets

**Security note:** This does NOT make VeilScan vulnerable. We are not sending credentials or sensitive data to the target — we are reading their banner. Man-in-the-middle of our outbound connection would only let an attacker show us a different banner, which has no security impact.

### 4.4 No Credential Handling
VeilScan never sends usernames, passwords, tokens, or keys to target services. The only data sent to targets are:
- TCP SYN (connection attempt)
- UDP probes (static bytes, no credentials)
- HTTP GET / (anonymous request)
- Redis PING command
- DNS version query

---

## 5. Audit and Logging Security

### 5.1 Audit Log Contents
**File:** `veilscan/cli.py` → `log_scan_history()`

The audit log records exactly:
```
[2026-08-08 03:37:35]  target=192.168.140.130  open_ports=16  duration=25.78s
```

**NOT logged:**
- Specific open ports or service names
- Banner content or version strings
- User credentials or tokens
- File contents or scan reports

### 5.2 Report Files in .gitignore
```
reports/*.html
reports/*.json
reports/*.csv
logs/*.log
```

Scan results are excluded from git. A beginner will not accidentally commit their scan results of a corporate network to a public GitHub repository.

### 5.3 Log File Failure Safety
```python
try:
    with open("logs/scan_history.log", "a") as f:
        f.write(line)
except OSError:
    pass  # Logging must never crash the scanner
```

If the log directory is read-only or the disk is full, the scan continues silently. Audit logging failure is never a blocker.

---

## 6. Ethical and Legal Security Controls

### 6.1 Consent Prompt
**File:** `veilscan/cli.py` → `check_consent()`

For any non-private-IP target, users must explicitly confirm they have permission:
```
Do you have permission to scan this target? [y/N]
```

Bypassed only with explicit `--agree` flag (documented as "for authorized use").
Automatically bypassed for RFC 1918 / loopback / link-local addresses.

### 6.2 Legal Notice on Every Output
Every report footer:
```
For authorized security testing and education only
```

Every scan banner:
```
For authorized use only
```

### 6.3 No Unauthorized Port Ranges
VeilScan does not default to scanning any system-reserved ports or private ranges specifically. `TOP_100` and `TOP_1000` are selected for their security audit value, not for any malicious targeting.

### 6.4 No Exploitation
VeilScan finds and explains vulnerabilities. It does not:
- Attempt to exploit any service
- Attempt authentication (no login attempts)
- Attempt to read files, change configuration, or execute commands

---

## 7. Code Security Issues to Monitor

### 7.1 Thread Safety
**Status:** ✅ Handled correctly

The `results` list is protected by `threading.Lock()` in both TCP and UDP batch scanners. The `done_count` uses a list container (mutable reference) for atomic-like updates in closures.

**Risk if broken:** Race conditions leading to duplicate results or missing results.

### 7.2 Queue Deadlock Prevention
**Status:** ✅ Handled correctly

`task_done()` is always called in a `finally` block. If a worker thread crashes with an uncaught exception, `task_done()` is still called, allowing `queue.join()` to unblock.

**Risk if broken:** Scan hangs indefinitely — `queue.join()` blocks forever.

### 7.3 ICMP Response Validation
**File:** `veilscan/scanner.py` → `_get_os_hint()`

Raw ICMP socket receives potentially crafted responses. Length is checked before reading:
```python
if addr[0] == ip and len(data) >= 9:
    ttl = data[8]
```

IP address is verified to match the target. Minimum length is verified before byte access.

**Risk if broken:** Index out of range exception or incorrect TTL from wrong host.

### 7.4 UDP Probe Injection Prevention
UDP probes are hardcoded bytes in `UDP_PROBES`. They are never constructed from user input:
```python
UDP_PROBES: dict[int, bytes] = {
    53: b"\x00\x00\x01\x00...",  # hardcoded
}
```

**Risk if this changed:** A user-controlled port could inject crafted probe data.

---

## 8. Security Checklist for New Features

Before adding any feature to VeilScan, check:

- [ ] Does it take user input? → Validate and sanitise before use
- [ ] Does it insert network data into HTML? → Use `_esc()` everywhere
- [ ] Does it make network connections? → Handle all socket exceptions
- [ ] Does it spawn threads? → Ensure `task_done()` in finally
- [ ] Does it write files? → Try/except OSError, return bool not raise
- [ ] Does it log anything? → Never log credentials or sensitive data
- [ ] Does it use external libraries? → Check `Rules.md` first
- [ ] Does it execute network data? → NEVER — use parse/read only
- [ ] Does it store credentials? → NEVER allowed
- [ ] Does it bypass consent prompt? → Only with explicit `--agree`

---

## 9. Known Security Trade-offs

| Trade-off | Decision | Justification |
|-----------|----------|---------------|
| SSL cert validation disabled | Accepted | Scanner cannot work with validation on lab certs |
| Raw ICMP socket (OS hint) | Accepted | Requires admin, gracefully skipped without it |
| Banner content stored in memory | Accepted | Truncated to 256 chars, not persisted to log |
| Full TCP connect scan (not SYN) | Accepted | SYN scan requires raw sockets/admin, connect scan is universal |
| No rate limiting on scans | Accepted | User controls thread count and timeout |

---

## 10. Reporting Security Issues

If you find a security issue in VeilScan:

1. **Do not open a public GitHub issue** for security vulnerabilities
2. Email the maintainer directly: GitHub profile → contact info
3. Include: description, reproduction steps, impact assessment
4. Allow 30 days for a fix before public disclosure

Security issues that would be taken seriously:
- XSS in HTML report from crafted network response
- Remote code execution via crafted banner
- Bypass of consent prompt without `--agree`
- Credential exposure in any output format
