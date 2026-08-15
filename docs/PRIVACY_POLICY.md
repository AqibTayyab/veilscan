# Privacy Policy
# VeilScan v2.0 — Network Security Audit Tool

**Effective Date:** August 2026
**Last Updated:** August 2026
**Author / Maintainer:** Aqib Tayyab
**GitHub:** https://github.com/AqibTayyab/veilscan

---

## Our Commitment in One Sentence

**VeilScan collects no personal data, sends nothing to any server, and stores only a minimal local audit log on your own machine.**

---

## 1. Overview

VeilScan is an **offline, locally-executed tool**. It runs entirely on your computer. There is no VeilScan cloud service, no VeilScan servers, no accounts, no registration, and no internet connection required to run scans.

This Privacy Policy explains:
- What data VeilScan stores locally on your machine
- What data VeilScan does NOT collect
- What data is sent over the network (only to scan targets you specify)
- How scan reports are handled
- Your rights regarding locally stored data

---

## 2. Data VeilScan Does NOT Collect

VeilScan does **not** collect, store, transmit, or process any of the following:

| Data Type | Collected? | Notes |
|-----------|-----------|-------|
| Your name | ❌ No | No registration required |
| Your email address | ❌ No | No accounts, no newsletter |
| Your IP address | ❌ No | Tool runs locally, no server to log it |
| Your location | ❌ No | No geolocation features |
| Your device information | ❌ No | No hardware fingerprinting |
| Your operating system | ❌ No | Not logged or reported |
| Usage analytics | ❌ No | No telemetry whatsoever |
| Crash reports | ❌ No | No automatic error reporting |
| Scan targets you enter | ❌ No | Not sent to any VeilScan server |
| Scan results | ❌ No | Not uploaded anywhere |
| Your network topology | ❌ No | Not shared externally |
| Cookies | ❌ No | No web interface, no cookies |
| Payment information | ❌ No | VeilScan is free and open source |

---

## 3. Data VeilScan Stores Locally

VeilScan creates the following files on your local machine only:

### 3.1 Scan History Log
**File:** `logs/scan_history.log`
**Location:** Inside the VeilScan folder on your machine
**Created when:** You run any scan
**What it contains:**
```
[2026-08-08 03:37:35]  target=192.168.140.130  open_ports=16  duration=25.78s
[2026-08-08 03:41:19]  target=192.168.140.130  open_ports=19  duration=50.82s
[2026-08-08 03:20:09]  target=scanme.nmap.org   open_ports=2   duration=3.20s
```

**What it does NOT contain:**
- The specific ports that were open
- Service names or version strings
- Banner content from scanned services
- Your username or any personal information
- Any credentials or sensitive data

**Purpose:** Provides you with a personal record of what you scanned and when. Useful for audits and tracking your own scanning activity.

**Stored:** Locally only. Never sent anywhere.

**How to delete:** Simply delete the file: `logs/scan_history.log`

---

### 3.2 Scan Reports
**Files:** `reports/scan_*.html`, `reports/scan_*.json`, `reports/scan_*.csv`
**Location:** Inside the `reports/` folder in your VeilScan directory
**Created when:** You use `--auto-report` or save with `-o`
**What they contain:** The full results of your scan — open ports, service versions, banners, risk assessments

**Who can see them:** Only you, on your local machine. These files are never uploaded.

**Stored:** Locally only. `.gitignore` excludes them from git to prevent accidental sharing.

**How to delete:** Delete files from the `reports/` folder at any time.

---

### 3.3 Debug Log (Optional)
**File:** `logs/debug.log` (only when `--log` flag is used)
**Created when:** You explicitly run with `--log debug.log`
**What it contains:** Technical debugging information — scan phases, timing, error messages
**Stored:** Locally only. Never created unless you explicitly request it.

---

## 4. Network Connections VeilScan Makes

VeilScan makes network connections **only to the targets you specify**. It does not connect to any VeilScan servers, analytics services, update servers, or any third-party services.

### What is sent to your scan target:
| Connection Type | What is Sent | Purpose |
|----------------|-------------|---------|
| TCP SYN/connect | Standard TCP handshake bytes | Port availability check |
| UDP probe | Small hardcoded bytes (DNS query, NTP request, etc.) | UDP port detection |
| HTTP GET / | `GET / HTTP/1.0\r\nHost: target\r\nUser-Agent: VeilScan/2.0\r\n\r\n` | HTTP banner grab |
| Redis PING | `*1\r\n$4\r\nPING\r\n` | Redis detection |
| ICMP UDP trigger | `b"\x00"` sent to port 45678 | OS fingerprinting via ICMP response |

### What VeilScan does NOT send to targets:
- Your identity or username
- Your IP address beyond what TCP/IP inherently reveals
- Exploit payloads or malicious data
- Credentials of any kind
- Any data from your machine

**Note:** Any scan target will be able to see your IP address in their logs — this is inherent to how networking works. VeilScan does not attempt to hide your IP address (it is not a proxy or anonymization tool).

---

## 5. Third-Party Services

VeilScan has **no integrations with any third-party services**. It does not use:
- Google Analytics
- Sentry or Bugsnag (crash reporting)
- Segment or Mixpanel (analytics)
- AWS, Google Cloud, or Azure (cloud storage)
- Any CDN or external font/script loading
- Any API that sends data externally

The HTML report is a completely standalone file that loads no external resources.

---

## 6. Open Source Transparency

VeilScan is fully open source under the MIT License. Every line of code that runs on your machine is publicly readable at:

**https://github.com/AqibTayyab/veilscan**

You can verify our privacy claims by reading the source code directly:
- Network connections: `veilscan/tcp_scanner.py`, `veilscan/udp_scanner.py`, `veilscan/banner_grabber.py`
- Local storage: `veilscan/cli.py` → `log_scan_history()`
- No external calls: search the entire codebase for `requests`, `urllib`, `httpx` — none exist

---

## 7. Data Retention

| Data | Retention | How to Delete |
|------|-----------|--------------|
| Scan history log | Until you delete it | Delete `logs/scan_history.log` |
| Scan reports | Until you delete them | Delete files from `reports/` folder |
| Debug logs | Until you delete them | Delete `logs/debug.log` |
| Python cache | Standard Python cache | Delete `__pycache__` folders |

VeilScan does not have a "delete my data" mechanism for external servers because no data is ever sent to external servers.

---

## 8. Children's Privacy

VeilScan is a technical security tool intended for users who understand network security concepts and legal requirements around scanning. It is not directed at children under 13 (COPPA) or under 16 (GDPR). We do not knowingly collect data from children — though given VeilScan collects no personal data at all, this is a moot point.

---

## 9. GDPR Compliance (European Users)

For users in the European Union:

- **Legal basis for processing:** There is none — VeilScan does not process your personal data
- **Data controller:** You are your own data controller for scan results on your machine
- **Right of access:** Your data is entirely on your machine — you have full access
- **Right to erasure:** Delete the files from `logs/` and `reports/` folders
- **Data transfers:** No data is transferred to VeilScan or any third party
- **DPO:** Not applicable — no personal data is processed

---

## 10. California Privacy Rights (CCPA)

For California residents:

VeilScan does not sell personal information. VeilScan does not collect personal information as defined by CCPA. There is nothing to disclose, request, or delete from VeilScan's servers because no such servers exist and no such data is held.

---

## 11. Changes to This Policy

This Privacy Policy may be updated. Changes will be reflected in the `PRIVACY_POLICY.md` file in the VeilScan repository and the "Last Updated" date at the top of this document. Since VeilScan collects no personal data, changes to this policy will primarily be clarifications rather than material changes to data practices.

---

## 12. Contact

Questions about this Privacy Policy:
- **GitHub Issues:** https://github.com/AqibTayyab/veilscan/issues
- **GitHub Profile:** https://github.com/AqibTayyab

---

## 13. Summary

| Question | Answer |
|---------|--------|
| Does VeilScan send data to any server? | No |
| Does VeilScan track my usage? | No |
| Does VeilScan store my scan results remotely? | No |
| What does VeilScan store locally? | Only a minimal log: timestamp, target, port count, duration |
| Can I delete local data? | Yes — delete files from logs/ and reports/ folders |
| Is VeilScan open source so I can verify? | Yes — 100% open source on GitHub |
| Does VeilScan need internet access? | No — fully offline for all core scanning features |
