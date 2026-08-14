"""tests/test_scanner.py — Unit tests for veilscan/scanner.py"""
import sys, os, threading
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pytest
from unittest.mock import patch, MagicMock
from veilscan.config import ScanConfig
from veilscan.scanner import Scanner
from veilscan.models import PortInfo, PortState, ScanResult, HostResult


# ── Test helpers ──────────────────────────────────────────────────────────────

def fake_tcp(open_ports=()):
    """Return a scan_tcp_batch mock that marks given ports OPEN."""
    def batch(ip, ports, timeout, num_threads, stop_event,
              retries=1, progress_cb=None):
        results = []
        for p in ports:
            state = PortState.OPEN if p in open_ports else PortState.CLOSED
            results.append(PortInfo(port=p, protocol="tcp", state=state))
        if progress_cb:
            for i in range(len(ports)):
                progress_cb(i + 1, len(ports))
        return results
    return batch


def fake_udp(open_ports=()):
    """Return a scan_udp_batch mock."""
    def batch(ip, ports, timeout, stop_event, progress_cb=None):
        return [
            PortInfo(port=p, protocol="udp",
                     state=PortState.OPEN_FILTERED if p in open_ports
                     else PortState.CLOSED)
            for p in ports
        ]
    return batch


def no_os_hint(self, ip):
    return ""


# ── Scanner.__init__ ──────────────────────────────────────────────────────────

class TestScannerInit:
    def test_config_stored(self):
        cfg = ScanConfig(target="127.0.0.1")
        s   = Scanner(cfg)
        assert s.config is cfg

    def test_stop_event_clear(self):
        s = Scanner(ScanConfig(target="127.0.0.1"))
        assert not s._stop_event.is_set()

    def test_progress_cb_none_default(self):
        s = Scanner(ScanConfig(target="127.0.0.1"))
        assert s.progress_cb is None

    def test_progress_cb_stored(self):
        cb = lambda p, d, t: None
        s  = Scanner(ScanConfig(target="127.0.0.1"), progress_cb=cb)
        assert s.progress_cb is cb

    def test_stop_sets_event(self):
        s = Scanner(ScanConfig(target="127.0.0.1"))
        s.stop()
        assert s._stop_event.is_set()


# ── scan() return type and metadata ───────────────────────────────────────────

class TestScanResult:
    def test_returns_scan_result(self):
        cfg = ScanConfig(target="127.0.0.1", ports="80", banners=False, udp=False)
        with patch("veilscan.scanner.scan_tcp_batch", side_effect=fake_tcp([80])), \
             patch.object(Scanner, "_get_os_hint", no_os_hint):
            result = Scanner(cfg).scan()
        assert isinstance(result, ScanResult)

    def test_scanner_version(self):
        cfg = ScanConfig(target="127.0.0.1", ports="80", banners=False, udp=False)
        with patch("veilscan.scanner.scan_tcp_batch", side_effect=fake_tcp([80])), \
             patch.object(Scanner, "_get_os_hint", no_os_hint):
            result = Scanner(cfg).scan()
        assert result.scanner_version == "2.0.0"

    def test_timing_populated(self):
        cfg = ScanConfig(target="127.0.0.1", ports="80", banners=False, udp=False)
        with patch("veilscan.scanner.scan_tcp_batch", side_effect=fake_tcp([80])), \
             patch.object(Scanner, "_get_os_hint", no_os_hint):
            result = Scanner(cfg).scan()
        assert result.start_time != ""
        assert result.end_time   != ""
        assert result.duration   >= 0.0

    def test_config_snapshot(self):
        cfg = ScanConfig(target="127.0.0.1", ports="80", banners=False, udp=False)
        with patch("veilscan.scanner.scan_tcp_batch", side_effect=fake_tcp([80])), \
             patch.object(Scanner, "_get_os_hint", no_os_hint):
            result = Scanner(cfg).scan()
        assert result.config["target"] == "127.0.0.1"
        assert result.config["ports"]  == "80"

    def test_one_host(self):
        cfg = ScanConfig(target="127.0.0.1", ports="80", banners=False, udp=False)
        with patch("veilscan.scanner.scan_tcp_batch", side_effect=fake_tcp([80])), \
             patch.object(Scanner, "_get_os_hint", no_os_hint):
            result = Scanner(cfg).scan()
        assert len(result.hosts) == 1

    def test_host_fields(self):
        cfg = ScanConfig(target="127.0.0.1", ports="80", banners=False, udp=False)
        with patch("veilscan.scanner.scan_tcp_batch", side_effect=fake_tcp([80])), \
             patch.object(Scanner, "_get_os_hint", no_os_hint):
            result = Scanner(cfg).scan()
        h = result.hosts[0]
        assert h.host == "127.0.0.1"
        assert h.ip   == "127.0.0.1"


# ── Open port detection ───────────────────────────────────────────────────────

class TestOpenPorts:
    def test_open_ports_detected(self):
        cfg = ScanConfig(target="127.0.0.1", ports="22,80,443",
                         banners=False, udp=False)
        with patch("veilscan.scanner.scan_tcp_batch",
                   side_effect=fake_tcp([22, 80])), \
             patch.object(Scanner, "_get_os_hint", no_os_hint):
            result = Scanner(cfg).scan()
        ports = sorted(p.port for p in result.hosts[0].open_ports)
        assert ports == [22, 80]

    def test_closed_ports_not_stored(self):
        cfg = ScanConfig(target="127.0.0.1", ports="80,9999",
                         banners=False, udp=False, verbose=False)
        with patch("veilscan.scanner.scan_tcp_batch",
                   side_effect=fake_tcp([80])), \
             patch.object(Scanner, "_get_os_hint", no_os_hint):
            result = Scanner(cfg).scan()
        assert len(result.hosts[0].ports) == 1
        assert result.hosts[0].ports[0].port == 80

    def test_ports_sorted_numerically(self):
        cfg = ScanConfig(target="127.0.0.1", ports="443,22,80",
                         banners=False, udp=False)
        with patch("veilscan.scanner.scan_tcp_batch",
                   side_effect=fake_tcp([22, 80, 443])), \
             patch.object(Scanner, "_get_os_hint", no_os_hint):
            result = Scanner(cfg).scan()
        pnums = [p.port for p in result.hosts[0].ports]
        assert pnums == sorted(pnums)

    def test_service_name_backfilled(self):
        """Ports returned with empty service get filled from PORT_SERVICES."""
        def batch_no_service(ip, ports, timeout, num_threads,
                             stop_event, retries=1, progress_cb=None):
            return [PortInfo(port=80, protocol="tcp",
                             state=PortState.OPEN, service="")]
        cfg = ScanConfig(target="127.0.0.1", ports="80",
                         banners=False, udp=False)
        with patch("veilscan.scanner.scan_tcp_batch",
                   side_effect=batch_no_service), \
             patch.object(Scanner, "_get_os_hint", no_os_hint):
            result = Scanner(cfg).scan()
        assert result.hosts[0].open_ports[0].service == "HTTP"


# ── CIDR / subnet scan ────────────────────────────────────────────────────────

class TestCidrScan:
    def test_slash30_gives_two_hosts(self):
        cfg = ScanConfig(target="127.0.0.0/30", ports="80",
                         banners=False, udp=False)
        with patch("veilscan.scanner.scan_tcp_batch",
                   side_effect=fake_tcp([80])), \
             patch.object(Scanner, "_get_os_hint", no_os_hint):
            result = Scanner(cfg).scan()
        assert len(result.hosts) == 2

    def test_unresolvable_host(self):
        cfg = ScanConfig(target="totally.invalid.hostname.xyz",
                         ports="80", banners=False, udp=False)
        with patch.object(Scanner, "_get_os_hint", no_os_hint):
            result = Scanner(cfg).scan()
        assert result.hosts[0].ip == "unresolved"

    def test_stop_event_aborts_subnet(self):
        cfg = ScanConfig(target="127.0.0.0/28", ports="80",
                         banners=False, udp=False)
        call_count = [0]

        def counting(ip, ports, timeout, num_threads, stop_event,
                     retries=1, progress_cb=None):
            call_count[0] += 1
            if call_count[0] >= 2:
                stop_event.set()
            return [PortInfo(port=80, protocol="tcp", state=PortState.OPEN)]

        with patch("veilscan.scanner.scan_tcp_batch",
                   side_effect=counting), \
             patch.object(Scanner, "_get_os_hint", no_os_hint):
            result = Scanner(cfg).scan()
        assert len(result.hosts) < 14


# ── UDP integration ───────────────────────────────────────────────────────────

class TestUdpIntegration:
    def test_udp_results_stored(self):
        cfg = ScanConfig(target="127.0.0.1", ports="53,161",
                         banners=False, udp=True)
        with patch("veilscan.scanner.scan_tcp_batch",
                   side_effect=fake_tcp([])), \
             patch("veilscan.scanner.scan_udp_batch",
                   side_effect=fake_udp([53])), \
             patch.object(Scanner, "_get_os_hint", no_os_hint):
            result = Scanner(cfg).scan()
        udp = result.hosts[0].udp_ports
        assert len(udp) == 1 and udp[0].port == 53

    def test_udp_skipped_when_disabled(self):
        called = [False]
        def spy(*a, **k): called[0] = True; return []
        cfg = ScanConfig(target="127.0.0.1", ports="53",
                         banners=False, udp=False)
        with patch("veilscan.scanner.scan_tcp_batch",
                   side_effect=fake_tcp([])), \
             patch("veilscan.scanner.scan_udp_batch", side_effect=spy), \
             patch.object(Scanner, "_get_os_hint", no_os_hint):
            Scanner(cfg).scan()
        assert not called[0]


# ── Banner integration ────────────────────────────────────────────────────────

class TestBannerIntegration:
    def test_banner_updates_port(self):
        cfg = ScanConfig(target="127.0.0.1", ports="80",
                         banners=True, udp=False)
        with patch("veilscan.scanner.scan_tcp_batch",
                   side_effect=fake_tcp([80])), \
             patch("veilscan.scanner.grab_banner",
                   return_value=("HTTP", "nginx/1.24", "HTTP/1.1 200 OK")), \
             patch.object(Scanner, "_get_os_hint", no_os_hint):
            result = Scanner(cfg).scan()
        port = result.hosts[0].open_ports[0]
        assert port.version == "nginx/1.24"
        assert "HTTP" in port.banner

    def test_banner_skipped_when_disabled(self):
        called = [False]
        def spy(*a, **k): called[0] = True; return ("", "", "")
        cfg = ScanConfig(target="127.0.0.1", ports="80",
                         banners=False, udp=False)
        with patch("veilscan.scanner.scan_tcp_batch",
                   side_effect=fake_tcp([80])), \
             patch("veilscan.scanner.grab_banner", side_effect=spy), \
             patch.object(Scanner, "_get_os_hint", no_os_hint):
            Scanner(cfg).scan()
        assert not called[0]

    def test_empty_grab_preserves_service(self):
        cfg = ScanConfig(target="127.0.0.1", ports="80",
                         banners=True, udp=False)
        with patch("veilscan.scanner.scan_tcp_batch",
                   side_effect=fake_tcp([80])), \
             patch("veilscan.scanner.grab_banner",
                   return_value=("", "", "")), \
             patch.object(Scanner, "_get_os_hint", no_os_hint):
            result = Scanner(cfg).scan()
        assert result.hosts[0].open_ports[0].service == "HTTP"

    def test_banner_timeout_at_least_3s(self):
        timeouts = []
        def capture(ip, port, timeout):
            timeouts.append(timeout)
            return ("", "", "")
        cfg = ScanConfig(target="127.0.0.1", ports="80",
                         banners=True, udp=False, timeout=0.5)
        with patch("veilscan.scanner.scan_tcp_batch",
                   side_effect=fake_tcp([80])), \
             patch("veilscan.scanner.grab_banner",
                   side_effect=capture), \
             patch.object(Scanner, "_get_os_hint", no_os_hint):
            Scanner(cfg).scan()
        assert timeouts[0] >= 3.0


# ── Progress callback ─────────────────────────────────────────────────────────

class TestProgressCallback:
    def test_tcp_phase_reported(self):
        phases = []
        cb = lambda phase, done, total: phases.append(phase)
        cfg = ScanConfig(target="127.0.0.1", ports="80,443",
                         banners=False, udp=False)
        with patch("veilscan.scanner.scan_tcp_batch",
                   side_effect=fake_tcp([80])), \
             patch.object(Scanner, "_get_os_hint", no_os_hint):
            Scanner(cfg, progress_cb=cb).scan()
        assert "tcp" in phases

    def test_banner_phase_reported(self):
        phases = []
        cb = lambda phase, done, total: phases.append(phase)
        cfg = ScanConfig(target="127.0.0.1", ports="80",
                         banners=True, udp=False)
        with patch("veilscan.scanner.scan_tcp_batch",
                   side_effect=fake_tcp([80])), \
             patch("veilscan.scanner.grab_banner",
                   return_value=("HTTP", "nginx", "HTTP/1.1")), \
             patch.object(Scanner, "_get_os_hint", no_os_hint):
            Scanner(cfg, progress_cb=cb).scan()
        assert "banner" in phases
