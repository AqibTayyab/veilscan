"""
veilscan/cli.py
===============
Command-line interface for VeilScan v2.0.

Why cli.py instead of root main.py
------------------------------------
Previously the CLI lived in root main.py. pip only installs the
veilscan/ package — so main.py was not installed and 'veilscan'
command failed with ModuleNotFoundError after pip install.

Moving all CLI logic here means:
  - pip install veilscan && veilscan scanme.nmap.org  ← works
  - python -m veilscan scanme.nmap.org                ← works
  - python main.py scanme.nmap.org                    ← works (main.py imports from here)

New features in v2.0
--------------------
- Python version check at startup (clear error on 3.8/3.9)
- Interactive wizard when no arguments given (beginner mode)
- Target validation before scan starts
- Scan size warning with time estimate for large scans
- --auto-report flag: saves HTML + JSON + CSV automatically
- Audit log: every scan appended to logs/scan_history.log

Public API
----------
    from veilscan.cli import main
    exit_code = main()   # parses sys.argv
"""

from __future__ import annotations

import argparse
import datetime
import logging
import os
import sys

# ─── Python Version Check ─────────────────────────────────────────────────────
# Must happen before any other veilscan imports so the error message
# is readable even on Python 3.9 where our type hints would crash first.

if sys.version_info < (3, 10):
    print(
        f"\n  [ERROR] VeilScan requires Python 3.10 or newer.\n"
        f"  You have Python {sys.version_info.major}.{sys.version_info.minor}.\n"
        f"  Download the latest Python from: https://python.org\n",
        file=sys.stderr,
    )
    sys.exit(1)

from veilscan import __version__
from veilscan.config import ScanConfig, PROFILES
from veilscan.scanner import Scanner
from veilscan.reporter import Reporter
from veilscan.html_reporter import generate_html
from veilscan.utils import (
    is_private_ip, resolve_host, expand_cidr,
    parse_ports, validate_target,
    estimate_scan_time, format_duration,
)


# ─── ASCII Banner ─────────────────────────────────────────────────────────────

BANNER = r"""
 ██╗   ██╗███████╗██╗██╗     ███████╗ ██████╗ █████╗ ███╗   ██╗
 ██║   ██║██╔════╝██║██║     ██╔════╝██╔════╝██╔══██╗████╗  ██║
 ██║   ██║█████╗  ██║██║     ███████╗██║     ███████║██╔██╗ ██║
 ╚██╗ ██╔╝██╔══╝  ██║██║     ╚════██║██║     ██╔══██║██║╚██╗██║
  ╚████╔╝ ███████╗██║███████╗███████║╚██████╗██║  ██║██║ ╚████║
   ╚═══╝  ╚══════╝╚═╝╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
  Professional Network Intelligence Suite  |  v{version}
  github.com/AqibTayyab/veilscan          |  For authorized use only
""".format(version=__version__)


# ─── Argument Parser ──────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="veilscan",
        description="VeilScan v2.0 — Professional network security audit tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Port formats:
  top100       100 most common ports (default)
  top1000      1000 most common ports
  full         All 65535 ports
  1-1024       Port range (inclusive)
  22,80,443    Comma-separated list
  22,80-90,443 Mixed range and list

Examples:
  veilscan scanme.nmap.org --profile quick --agree
  veilscan 192.168.1.1 -p 22,80,443,3306 --agree
  veilscan 10.0.0.0/24 -p top100 --agree --auto-report
  veilscan 192.168.1.1 -p full -T 50 --udp --agree
        """,
    )

    p.add_argument("target", nargs="?", default=None,
                   help="IP, hostname, or CIDR subnet (e.g. 192.168.1.0/24)")
    p.add_argument("-p", "--ports",   default="top100", metavar="PORTS",
                   help="Port spec (default: top100)")
    p.add_argument("-T", "--threads", type=int,   default=100,  metavar="N",
                   help="Concurrent threads (default: 100)")
    p.add_argument("-t", "--timeout", type=float, default=1.0,  metavar="SEC",
                   help="Per-port timeout in seconds (default: 1.0)")
    p.add_argument("-r", "--retries", type=int,   default=1,    metavar="N",
                   help="Retry count on timeout (default: 1)")
    p.add_argument("--udp",        action="store_true",
                   help="Also scan UDP ports")
    p.add_argument("--no-banners", action="store_true", dest="no_banners",
                   help="Skip banner grabbing (faster)")
    p.add_argument("--profile",    choices=list(PROFILES.keys()), metavar="PROFILE",
                   help="Preset: quick | standard | full | stealth")
    p.add_argument("-o", "--output", default=None, metavar="FILE",
                   help="Save results to a specific file")
    p.add_argument("-f", "--format", choices=["json","csv","txt"],
                   default="json", dest="fmt",
                   help="Output format when using -o (default: json)")
    p.add_argument("--auto-report", action="store_true", dest="auto_report",
                   help="Auto-save HTML + JSON + CSV to reports/ folder")
    p.add_argument("--report-base", default=None, dest="report_base",
                   metavar="PATH",
                   help="Base path for auto-report files (no extension)")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Show filtered ports too, not just open ones")
    p.add_argument("--agree", action="store_true",
                   help="Confirm you have permission (skips consent prompt)")
    p.add_argument("--log",   default=None, metavar="FILE",
                   help="Write debug log to file")
    p.add_argument("--version", action="version",
                   version=f"VeilScan {__version__}")
    return p


# ─── Config Builder ───────────────────────────────────────────────────────────

def build_config(args: argparse.Namespace) -> ScanConfig:
    """
    Build a ScanConfig from parsed CLI arguments.

    If --profile is given, start from profile defaults then apply
    any explicit CLI overrides on top.
    """
    if args.profile:
        base = PROFILES[args.profile]
        cfg  = ScanConfig(
            target  = args.target or "",
            ports   = base.ports,
            threads = base.threads,
            timeout = base.timeout,
            retries = base.retries,
            banners = base.banners,
            profile = args.profile,
        )
    else:
        cfg = ScanConfig(target=args.target or "")

    # Apply explicit CLI overrides
    parser = build_parser()
    defaults = {a.dest: a.default for a in parser._actions if hasattr(a,"dest")}

    if args.ports   != defaults.get("ports"):   cfg.ports   = args.ports
    if args.threads != defaults.get("threads"): cfg.threads = args.threads
    if args.timeout != defaults.get("timeout"): cfg.timeout = args.timeout
    if args.retries != defaults.get("retries"): cfg.retries = args.retries

    cfg.udp         = args.udp
    cfg.banners     = not args.no_banners
    cfg.output_file = args.output
    cfg.output_fmt  = args.fmt
    cfg.verbose     = args.verbose
    cfg.agree       = args.agree

    return cfg


# ─── Consent Check ────────────────────────────────────────────────────────────

def check_consent(target: str, agree: bool) -> bool:
    """
    Ask user to confirm they have permission to scan the target.

    Skipped if:
    - --agree flag given
    - Target resolves to a private/loopback IP
    """
    if agree:
        return True

    # Skip for private IPs (local network scans)
    try:
        host = target.split("/")[0]
        ip   = resolve_host(host)
        if is_private_ip(ip):
            return True
    except ValueError:
        pass

    print("\n" + "─" * 60)
    print("  ⚠  LEGAL WARNING")
    print("─" * 60)
    print(f"  Target: {target}")
    print("  Scanning systems without explicit written permission")
    print("  is illegal in many countries (US CFAA, UK CMA, EU).")
    print("─" * 60)
    try:
        ans = input("\n  Do you have permission to scan this target? [y/N] ")
    except (KeyboardInterrupt, EOFError):
        print("\n  Aborted.")
        return False
    return ans.strip().lower() == "y"


# ─── Progress Bar ─────────────────────────────────────────────────────────────

class ProgressBar:
    """
    Live progress bar written to stderr.

    Shows phase name, filled bar, done/total count, and percentage.
    Uses carriage return to update in place — does not scroll.
    Pads line to 72 chars so shorter renders overwrite longer ones
    (prevents leftover characters from previous render).
    """
    BAR_WIDTH = 20
    PHASE_LABELS = {
        "tcp":    "[TCP]   ",
        "udp":    "[UDP]   ",
        "banner": "[BANNER]",
    }

    def __init__(self) -> None:
        self._enabled = (
            hasattr(sys.stderr, "isatty") and sys.stderr.isatty()
        )
        self._last_phase = ""

    def update(self, phase: str, done: int, total: int) -> None:
        if not self._enabled or total == 0:
            return

        # Print newline when phase changes
        if phase != self._last_phase:
            if self._last_phase:
                print(file=sys.stderr)
            self._last_phase = phase

        pct    = done / total
        filled = int(self.BAR_WIDTH * pct)
        bar    = "█" * filled + "░" * (self.BAR_WIDTH - filled)
        label  = self.PHASE_LABELS.get(phase, phase.upper()[:8])
        core   = f"  {label}  {bar}  {done}/{total}  {pct:.0%}"

        # Pad to 72 chars — overwrites any longer previous render
        sys.stderr.write(f"\r{core:<72}")
        sys.stderr.flush()

        if done >= total:
            # Clear line then print clean final state
            sys.stderr.write(f"\r{' ' * 72}\r{core}")
            sys.stderr.flush()
            print(file=sys.stderr)
            self._last_phase = ""

    def finish(self) -> None:
        """Ensure final newline if stopped mid-phase."""
        if self._enabled and self._last_phase:
            print(file=sys.stderr)
            self._last_phase = ""


# ─── Scan Estimate Warning ────────────────────────────────────────────────────

def warn_if_large_scan(
    targets:  list[str],
    ports:    list[int],
    cfg:      ScanConfig,
) -> bool:
    """
    Warn and ask for confirmation if the scan is very large.

    Returns True if the user confirms, False to abort.
    Auto-confirms when cfg.agree is set.
    """
    estimated = estimate_scan_time(
        num_hosts   = len(targets),
        num_ports   = len(ports),
        num_threads = cfg.threads,
        timeout     = cfg.timeout,
        banners     = cfg.banners,
    )

    # Only warn if estimated > 5 minutes
    if estimated < 300:
        return True

    duration_str = format_duration(estimated)
    print(f"\n  ⚠  Large scan detected:")
    print(f"     {len(targets)} host(s) × {len(ports)} port(s)")
    print(f"     Estimated time: ~{duration_str}")

    if estimated > 3600 and not cfg.agree:
        print(f"\n  This scan may take over an hour.")
        try:
            ans = input("  Continue? [y/N] ")
            if ans.strip().lower() != "y":
                print("  Scan cancelled.")
                return False
        except (KeyboardInterrupt, EOFError):
            print("\n  Aborted.")
            return False

    return True


# ─── Auto Report Saver ────────────────────────────────────────────────────────

def save_auto_reports(result, base_path: str) -> None:
    """
    Save HTML + JSON + CSV reports to the reports/ folder.

    Called when --auto-report flag is set.
    """
    os.makedirs("reports", exist_ok=True)
    reporter = Reporter(result)

    # HTML — beginner-friendly report
    html_path = f"{base_path}.html"
    try:
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(generate_html(result))
        print(f"\n  📄 HTML report  → {html_path}")
    except Exception as e:
        print(f"\n  [ERROR] Could not save HTML report: {e}", file=sys.stderr)

    # JSON — machine-readable
    json_path = f"{base_path}.json"
    if reporter.save(json_path, "json"):
        print(f"  📊 JSON report  → {json_path}")

    # CSV — open in Excel
    csv_path = f"{base_path}.csv"
    if reporter.save(csv_path, "csv"):
        print(f"  📋 CSV report   → {csv_path}")

    print(f"\n  Open {html_path} in any browser for the full report.")


# ─── Audit Log ────────────────────────────────────────────────────────────────

def log_scan_history(
    target:     str,
    open_ports: int,
    duration:   float,
) -> None:
    """Append one-line entry to logs/scan_history.log."""
    os.makedirs("logs", exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = (
        f"[{timestamp}]  target={target}  "
        f"open_ports={open_ports}  duration={duration:.2f}s\n"
    )
    try:
        with open("logs/scan_history.log", "a", encoding="utf-8") as f:
            f.write(line)
    except OSError:
        pass  # Logging must never crash the scanner


# ─── Logging Setup ────────────────────────────────────────────────────────────

def setup_logging(log_file: str | None) -> None:
    handlers: list[logging.Handler] = []
    if log_file:
        os.makedirs(
            os.path.dirname(log_file) if os.path.dirname(log_file) else ".",
            exist_ok=True,
        )
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter(
            "%(asctime)s  %(levelname)-8s  %(name)s  %(message)s"
        ))
        handlers.append(fh)
    sh = logging.StreamHandler(sys.stderr)
    sh.setLevel(logging.WARNING)
    handlers.append(sh)
    logging.basicConfig(level=logging.DEBUG, handlers=handlers)


# ─── Interactive Wizard ───────────────────────────────────────────────────────

def run_wizard() -> int:
    """
    Interactive scan wizard for beginners.

    Launched automatically when no target is given on the command line.
    Guides the user through choosing a target, scan type, and options.
    """
    print(BANNER)
    print("  No target specified. Starting interactive wizard...\n")
    print("  " + "─" * 56)
    print("  Welcome to VeilScan v2.0")
    print("  " + "─" * 56)
    print()

    # Target
    try:
        target = input("  Enter target IP or domain\n"
                       "  (e.g. 192.168.1.1  or  scanme.nmap.org): ").strip()
    except (KeyboardInterrupt, EOFError):
        print("\n\n  Cancelled.")
        return 0

    if not target:
        print("  No target entered. Exiting.")
        return 1

    # Validate target
    try:
        validate_target(target)
    except ValueError as e:
        print(f"\n  [ERROR] {e}")
        return 1

    print()

    # Scan profile
    print("  Select scan type:")
    print("  [1] Quick    — Top 100 ports, fast  (recommended for beginners)")
    print("  [2] Standard — Top 1000 ports, balanced")
    print("  [3] Full     — All 65535 ports, thorough (slow)")
    print("  [4] Stealth  — Quiet, minimal traffic")
    print("  [5] Custom   — Choose your own settings")
    print()

    try:
        choice = input("  Choice (1-5, default 1): ").strip() or "1"
    except (KeyboardInterrupt, EOFError):
        print("\n\n  Cancelled.")
        return 0

    profile_map = {"1":"quick","2":"standard","3":"full","4":"stealth"}
    profile = profile_map.get(choice)

    if profile:
        cfg = ScanConfig(**{**vars(PROFILES[profile]), "target": target})
        cfg.agree = True
    else:
        # Custom
        print()
        try:
            ports   = input("  Ports (top100/top1000/full/22,80,443): ").strip() or "top100"
            threads = int(input("  Threads (default 100): ").strip() or "100")
            timeout = float(input("  Timeout in seconds (default 1.0): ").strip() or "1.0")
        except (KeyboardInterrupt, EOFError, ValueError):
            print("\n\n  Cancelled or invalid input.")
            return 1
        cfg = ScanConfig(
            target=target, ports=ports,
            threads=threads, timeout=timeout,
            agree=True,
        )

    # UDP option
    print()
    try:
        udp_ans = input("  Also scan UDP ports? [y/N]: ").strip().lower()
        cfg.udp = udp_ans == "y"
    except (KeyboardInterrupt, EOFError):
        pass

    # Auto-report
    print()
    try:
        report_ans = input("  Auto-save HTML + JSON + CSV reports? [Y/n]: ").strip().lower()
        auto_report = report_ans != "n"
    except (KeyboardInterrupt, EOFError):
        auto_report = True

    # Build timestamp for report filename
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace(".", "_").replace("/", "_")
    report_base = f"reports/scan_{safe_target}_{ts}"

    # Run the scan
    print()
    return _run_scan(
        cfg         = cfg,
        auto_report = auto_report,
        report_base = report_base if auto_report else None,
        output_file = None,
        output_fmt  = "json",
    )


# ─── Core Scan Runner ─────────────────────────────────────────────────────────

def _run_scan(
    cfg:         ScanConfig,
    auto_report: bool,
    report_base: str | None,
    output_file: str | None,
    output_fmt:  str,
) -> int:
    """
    Execute the scan and save results.

    Shared by both wizard mode and direct CLI mode.
    Returns exit code (0=success, 1=error).
    """
    # Validate target
    try:
        validate_target(cfg.target)
    except ValueError as exc:
        print(f"\n  [ERROR] {exc}", file=sys.stderr)
        return 1

    # Parse ports and expand CIDR for size estimate
    try:
        port_list = parse_ports(cfg.ports)
    except ValueError as exc:
        print(f"\n  [ERROR] Invalid port spec: {exc}", file=sys.stderr)
        return 1

    targets = []
    try:
        from veilscan.utils import expand_cidr
        targets = expand_cidr(cfg.target)
    except Exception:
        targets = [cfg.target]

    # Warn for large scans
    if not warn_if_large_scan(targets, port_list, cfg):
        return 0

    # Print scan summary
    print(f"\n  Target  : {cfg.target}")
    print(f"  Ports   : {cfg.ports}")
    print(f"  Threads : {cfg.threads}  |  "
          f"Timeout: {cfg.timeout}s  |  "
          f"Retries: {cfg.retries}")
    print(f"  UDP     : {'yes' if cfg.udp else 'no'}  |  "
          f"Banners: {'yes' if cfg.banners else 'no'}")
    if cfg.profile and cfg.profile != "custom":
        print(f"  Profile : {cfg.profile}")
    print()

    # Run scan
    bar     = ProgressBar()
    scanner = Scanner(cfg, progress_cb=bar.update)

    try:
        result = scanner.scan()
    except KeyboardInterrupt:
        scanner.stop()
        bar.finish()
        print("\n\n  Scan interrupted by user.")
        return 0

    bar.finish()

    # Print results table
    Reporter(result).print_table()

    # Audit log
    log_scan_history(cfg.target, result.total_open_ports, result.duration)

    # Auto-report
    if auto_report and report_base:
        save_auto_reports(result, report_base)

    # Manual output file
    if output_file:
        reporter = Reporter(result)
        if reporter.save(output_file, output_fmt):
            print(f"\n  Results saved → {output_file} ({output_fmt.upper()})")
        else:
            return 1

    return 0


# ─── Main Entry Point ─────────────────────────────────────────────────────────

def main() -> int:
    """
    Parse arguments and dispatch to wizard or direct scan.

    Returns exit code for sys.exit().
    """
    parser = build_parser()
    args   = parser.parse_args()

    # Setup logging
    log_file = args.log
    if args.auto_report and not log_file:
        log_file = "logs/debug.log"
    setup_logging(log_file)

    # No target given → interactive wizard
    if args.target is None:
        return run_wizard()

    # Direct scan mode
    print(BANNER)

    # Consent check
    if not check_consent(args.target, args.agree):
        print("\n  Scan cancelled.")
        return 0

    # Build config
    try:
        cfg = build_config(args)
        cfg.target = args.target
    except ValueError as exc:
        print(f"\n  [ERROR] {exc}", file=sys.stderr)
        return 1

    # Report base path
    report_base = None
    if args.auto_report:
        base = args.report_base or (
            "reports/scan_"
            + args.target.replace(".", "_").replace("/", "_")
            + "_"
            + datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        )
        report_base = base

    return _run_scan(
        cfg         = cfg,
        auto_report = args.auto_report,
        report_base = report_base,
        output_file = args.output,
        output_fmt  = args.fmt,
    )
