# Architecture.md — Technical Architecture
# VeilScan v2.0

---

## 1. Technology Stack

| Layer | Technology | Why |
|-------|-----------|-----|
| Language | Python 3.10+ | Modern type hints, stdlib only |
| Networking | `socket` (stdlib) | Full TCP/UDP/ICMP control, zero deps |
| TLS | `ssl` (stdlib) | HTTPS banner grabbing without external libs |
| Threading | `threading` + `queue` | Thread-pool scanning, race-condition-free |
| CLI | `argparse` (stdlib) | No click/typer dependency |
| HTML Output | f-strings + `html.escape` | No Jinja2 needed |
| Tests | `pytest` + `unittest.mock` | Industry standard, offline mocking |
| Packaging | `setuptools` + `pyproject.toml` | Modern pip-compatible |
| Optional | `colorama` | Windows CMD ANSI colors |

---

## 2. File Structure

```
veilscan/
├── main.py                  ← Root entry point (delegates to veilscan.cli)
├── pyproject.toml           ← pip packaging, entry points, metadata
├── requirements.txt         ← Optional: colorama
├── .gitignore
├── README.md
├── reports/                 ← Auto-saved reports (HTML/JSON/CSV)
├── logs/                    ← Audit trail (scan_history.log)
└── veilscan/                ← Main Python package
    ├── __init__.py          ← v2.0.0, re-exports key classes
    ├── __main__.py          ← python -m veilscan support
    ├── config.py            ← ScanConfig dataclass + 4 scan profiles
    ├── models.py            ← PortState, PortInfo, HostResult, ScanResult
    ├── utils.py             ← Port map, CIDR, OS hint, validation, estimate
    ├── tcp_scanner.py       ← TCP thread-pool engine
    ├── udp_scanner.py       ← UDP engine with ICMP detection
    ├── banner_grabber.py    ← Service fingerprinting (15+ protocols)
    ├── scanner.py           ← Orchestrator (wires all modules)
    ├── reporter.py          ← CLI table + JSON/CSV/TXT output
    ├── html_reporter.py     ← HTML report generator
    ├── vuln_hints.py        ← 42-entry risk explanation database
    └── cli.py               ← Full CLI + interactive wizard

tests/
├── test_models.py           (38 tests)
├── test_utils.py            (50 tests)
├── test_config.py           (30 tests)
├── test_tcp_scanner.py      (21 tests)
├── test_udp_scanner.py      (26 tests)
├── test_banner_grabber.py   (44 tests)
├── test_scanner.py          (30 tests)
├── test_html_reporter.py    (42 tests)
└── test_vuln_hints.py       (47 tests)
                              Total: 368 tests
```

---

## 3. Module Responsibilities

### `config.py` — Configuration & Validation
- `ScanConfig` dataclass: all scan parameters with `__post_init__` validation
- Validates threads (1-1000), timeout (0.1-30.0), retries (0-5) at creation time
- `PROFILES`: quick / standard / full / stealth presets
- Lives inside `veilscan/` package — required for `pip install` to work

### `models.py` — Data Structures
- `PortState(str, Enum)` — inherits str for clean JSON serialisation
- `PortInfo` — single port result: port, protocol, state, service, version, banner
- `HostResult` — one host's results with computed properties: `open_ports`, `tcp_ports`, `udp_ports`
- `ScanResult` — top-level container: hosts, timing, scanner version, config snapshot

### `utils.py` — Shared Helpers
- `PORT_SERVICES` — 100+ port→name mappings
- `TOP_100` — exactly 100 curated ports (verified unique, no duplicates)
- `parse_ports()` — flexible spec: `top100` / `full` / `1-1024` / `22,80,443` / mixed
- `expand_cidr()` — `192.168.1.0/24` → 254 host IPs
- `validate_target()` — blocks 0.0.0.0, broadcast, multicast, IPv6
- `estimate_scan_time()` — rough duration for large-scan warning

### `tcp_scanner.py` — TCP Engine
```
scan_tcp_batch()
  ├── pre-loads all ports into queue
  ├── spawns min(threads, len(ports)) workers
  ├── each worker: get_nowait() [atomic] → scan_tcp_port() → append result
  ├── task_done() in finally → queue.join() never deadlocks
  └── stop_event drains queue cleanly on abort
```
**Key fix:** `get_nowait()` is atomic — eliminates v1.0 race condition from `empty()+get()`

### `udp_scanner.py` — UDP Engine
```
scan_udp_port()
  ├── send service-specific UDP probe
  ├── UDP response received → OPEN (definitive)
  ├── ICMP Port Unreachable → CLOSED (definitive)
  └── no response → OPEN|FILTERED (uncertain)
```
- Thread cap: 50 max (prevents ICMP rate-limiting)
- `check_udp_privileges()` → clear warning if ICMP unavailable (no admin)

### `banner_grabber.py` — Fingerprinting
- `PROBE_MAP`: None=read-first (SSH, FTP), bytes=send-first (HTTP)
- `TLS_PORTS = {443, 8443, 993, 995, 465}` — wrapped with `ssl.create_default_context()`
- `_parse_banner()` — 15+ protocol parsers in specificity order
- **Never raises** — `("", "", "")` on any failure (critical for reliability)

### `scanner.py` — Orchestrator
```
Scanner.scan()
  ├── expand_cidr(target) → host list
  ├── parse_ports(ports)  → port numbers
  └── per host:
        ├── resolve_host() → IP
        ├── _run_tcp()     → TCP scan results
        ├── _run_udp()     → UDP results (optional)
        ├── _run_banners() → service/version/banner updates
        └── _get_os_hint() → reads TTL from ICMP response byte 8
```
**OS hint fix:** Reads actual remote TTL from ICMP packet (not local `getsockopt` default)
**Banner timeout fix:** `max(cfg.timeout * 2, 3.0)` — minimum 3s for TLS handshake

### `reporter.py` — Output Formatting
- `print_table()` — dynamic column widths (no overflow on long service names)
- `to_json()` — `dataclasses.asdict()` + JSON
- `to_csv()` — header + one row per open/open|filtered port
- `to_txt()` — ANSI-free version of print_table
- `save()` — returns bool, never raises

### `html_reporter.py` — HTML Report
- `generate_html(result)` → complete standalone HTML string
- All network content through `html.escape()` (XSS prevention)
- Ports sorted by risk (CRITICAL first)
- Fallback card for ports not in HINTS database
- No JavaScript — pure HTML + CSS

### `vuln_hints.py` — Risk Database
- 42 `ServiceHint` entries
- `get_hint(port)` → ServiceHint or None
- `get_risk(port)` → "CRITICAL" / "HIGH" / "MEDIUM" / "LOW" / "INFO"
- `risk_sort_key(risk)` → int for sorting

### `cli.py` — Command Line Interface
- Python version check at startup (`sys.version_info < (3, 10)`)
- Interactive wizard when no target given
- `validate_target()` before scan
- `warn_if_large_scan()` — time estimate + confirmation for large scans
- `log_scan_history()` → `logs/scan_history.log`

---

## 4. Data Flow

```
User input (CLI / wizard)
       ↓
  ScanConfig (validated)
       ↓
  Scanner.scan()
    ├── expand_cidr() → host list
    ├── parse_ports() → port list
    └── per host:
          ├── TCP scan → List[PortInfo]
          ├── UDP scan → List[PortInfo]    (optional)
          ├── grab_banner() per open port  (optional)
          └── _get_os_hint() → OS string
       ↓
  ScanResult (hosts, timing, config)
       ↓
  Reporter.print_table()   → terminal
  generate_html(result)    → reports/*.html
  Reporter.save(*.json)    → reports/*.json
  Reporter.save(*.csv)     → reports/*.csv
  log_scan_history()       → logs/scan_history.log
```

---

## 5. Threading Model

```
Main thread
  └── scan_tcp_batch()
        ├── queue = [22, 80, 443, 3306, ...]  (all ports pre-loaded)
        ├── Thread 1: get_nowait() → scan_tcp_port() → lock → results.append()
        ├── Thread 2: get_nowait() → scan_tcp_port() → lock → results.append()
        ...
        ├── Thread N: get_nowait() → scan_tcp_port() → lock → results.append()
        └── queue.join() ← blocks until every port has task_done() called
```

**Thread safety:**
- `queue.Queue` — atomic port distribution
- `threading.Lock` — protects `results` list
- `threading.Event` — stop_event for clean abort
- `task_done()` in `finally` — never deadlocks

---

## 6. pip Install Architecture

**Problem:** Previous version had `from config import ScanConfig` (root-level file). pip only installs the `veilscan/` package directory — root files are not installed. Result: `ModuleNotFoundError` after `pip install veilscan`.

**Solution:**
```
pip install veilscan
    ↓ installs veilscan/ package
    ↓ entry point: pyproject.toml → veilscan.__main__:main
    ↓ veilscan/__main__.py → from veilscan.cli import main
    ↓ veilscan/cli.py → from veilscan.config import ScanConfig ✅
```

All imports now use `from veilscan.X import Y` — works whether running from source or after pip install.

---

## 7. Test Architecture

All tests mock socket calls — no real network connections:

```python
def mk(code=0, err=None):
    m = MagicMock()
    m.__enter__ = MagicMock(return_value=m)
    m.__exit__  = MagicMock(return_value=False)
    if err: m.connect_ex.side_effect = err
    else:   m.connect_ex.return_value = code
    return m

with patch("socket.socket", return_value=mk(0)):
    result = scan_tcp_port("127.0.0.1", 80)
assert result.state == PortState.OPEN
```

**Critical rule:** Factory functions used as `side_effect` must accept `*args, **kwargs` — mock calls them with the same args as the patched function (`AF_INET, SOCK_STREAM`). Without `*args`, the test hangs because the thread crashes without calling `task_done()`.
