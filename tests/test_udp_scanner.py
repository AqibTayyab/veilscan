"""tests/test_udp_scanner.py — Unit tests for veilscan/udp_scanner.py"""
import sys, os, socket, threading
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pytest
from unittest.mock import MagicMock, patch
from veilscan.models import PortInfo, PortState
from veilscan.udp_scanner import (
    scan_udp_port, scan_udp_batch,
    check_udp_privileges, UDP_PROBES,
)


class TestUdpProbes:
    def test_count(self):
        assert len(UDP_PROBES) >= 11

    def test_required_ports(self):
        for port in [53, 123, 161, 67, 137, 138, 69, 514, 5353, 1900, 19]:
            assert port in UDP_PROBES, f"Missing probe for port {port}"

    def test_dns_probe_not_empty(self):
        assert len(UDP_PROBES[53]) > 0

    def test_ntp_probe_length(self):
        assert len(UDP_PROBES[123]) == 48


class TestCheckUdpPrivileges:
    def test_returns_tuple(self):
        can, msg = check_udp_privileges()
        assert isinstance(can, bool)
        assert isinstance(msg, str)

    def test_no_privilege_returns_false(self):
        with patch("socket.socket", side_effect=PermissionError()):
            can, msg = check_udp_privileges()
        assert can == False
        assert len(msg) > 0

    def test_no_privilege_msg_has_guidance(self):
        with patch("socket.socket", side_effect=PermissionError()):
            _, msg = check_udp_privileges()
        # Message should mention admin or root
        assert any(word in msg.lower() for word in ["admin", "root", "sudo", "administrator"])

    def test_privilege_available(self):
        m = MagicMock()
        with patch("socket.socket", return_value=m):
            can, msg = check_udp_privileges()
        assert can == True and msg == ""


class TestScanUdpPort:
    def _mock_udp(self, resp=b"", timeout=False):
        m = MagicMock()
        m.__enter__ = MagicMock(return_value=m)
        m.__exit__  = MagicMock(return_value=False)
        if timeout:
            m.recvfrom.side_effect = socket.timeout()
        else:
            m.recvfrom.return_value = (resp, ("1.2.3.4", 0))
        return m

    def test_udp_response_open(self):
        udp = self._mock_udp(resp=b"DNS response data")
        with patch("socket.socket") as cls:
            cls.side_effect = [udp]
            r = scan_udp_port("1.2.3.4", 53, timeout=0.1, can_icmp=False)
        assert r.state == PortState.OPEN

    def test_udp_response_port_correct(self):
        udp = self._mock_udp(resp=b"data")
        with patch("socket.socket") as cls:
            cls.side_effect = [udp]
            r = scan_udp_port("1.2.3.4", 53, timeout=0.1, can_icmp=False)
        assert r.port == 53

    def test_udp_response_protocol(self):
        udp = self._mock_udp(resp=b"data")
        with patch("socket.socket") as cls:
            cls.side_effect = [udp]
            r = scan_udp_port("1.2.3.4", 53, timeout=0.1, can_icmp=False)
        assert r.protocol == "udp"

    def test_no_response_open_filtered(self):
        udp = self._mock_udp(timeout=True)
        with patch("socket.socket") as cls:
            cls.side_effect = [udp]
            r = scan_udp_port("1.2.3.4", 9999, timeout=0.1, can_icmp=False)
        assert r.state == PortState.OPEN_FILTERED

    def test_known_port_gets_service(self):
        udp = self._mock_udp(resp=b"data")
        with patch("socket.socket") as cls:
            cls.side_effect = [udp]
            r = scan_udp_port("1.2.3.4", 53, timeout=0.1, can_icmp=False)
        assert r.service == "DNS"

    def test_unknown_port_empty_service(self):
        udp = self._mock_udp(timeout=True)
        with patch("socket.socket") as cls:
            cls.side_effect = [udp]
            r = scan_udp_port("1.2.3.4", 39999, timeout=0.1, can_icmp=False)
        assert r.service == ""

    def test_banner_from_response(self):
        udp = self._mock_udp(resp=b"NTP response data here")
        with patch("socket.socket") as cls:
            cls.side_effect = [udp]
            r = scan_udp_port("1.2.3.4", 123, timeout=0.1, can_icmp=False)
        assert r.state == PortState.OPEN

    def test_ntp_service_name(self):
        udp = self._mock_udp(resp=b"data")
        with patch("socket.socket") as cls:
            cls.side_effect = [udp]
            r = scan_udp_port("1.2.3.4", 123, timeout=0.1, can_icmp=False)
        assert r.service == "NTP"


class TestScanUdpBatch:
    def _fake(self, state=PortState.OPEN_FILTERED):
        def fake_scan(ip, port, timeout, can_icmp=True):
            return PortInfo(port=port, protocol="udp", state=state)
        return fake_scan

    def test_empty_returns_empty(self):
        stop = threading.Event()
        assert scan_udp_batch("1.2.3.4", [], 0.1, stop) == []

    def test_all_ports_returned(self):
        ports = [53, 123, 161, 1900]
        stop  = threading.Event()
        with patch("veilscan.udp_scanner.scan_udp_port", side_effect=self._fake()):
            results = scan_udp_batch("1.2.3.4", ports, 0.1, stop)
        assert sorted(r.port for r in results) == sorted(ports)

    def test_no_duplicates(self):
        ports = list(range(53, 103))
        stop  = threading.Event()
        with patch("veilscan.udp_scanner.scan_udp_port", side_effect=self._fake()):
            results = scan_udp_batch("1.2.3.4", ports, 0.1, stop)
        pnums = [r.port for r in results]
        assert len(pnums) == len(set(pnums)) == 50

    def test_thread_cap_at_50(self):
        """Even with 200 ports, thread count never exceeds 50."""
        ports = list(range(1, 201))
        stop  = threading.Event()
        with patch("veilscan.udp_scanner.scan_udp_port", side_effect=self._fake()):
            results = scan_udp_batch("1.2.3.4", ports, 0.1, stop)
        assert len(results) == 200

    def test_stop_event_aborts(self):
        ports = list(range(1, 101))
        stop  = threading.Event()
        count = [0]

        def slow(ip, port, timeout, can_icmp=True):
            count[0] += 1
            if count[0] > 5: stop.set()
            return PortInfo(port=port, protocol="udp", state=PortState.OPEN_FILTERED)

        with patch("veilscan.udp_scanner.scan_udp_port", side_effect=slow):
            results = scan_udp_batch("1.2.3.4", ports, 0.1, stop)
        assert len(results) < len(ports)

    def test_progress_callback(self):
        calls = []
        stop  = threading.Event()
        with patch("veilscan.udp_scanner.scan_udp_port", side_effect=self._fake()):
            scan_udp_batch("1.2.3.4", [53, 123], 0.1, stop,
                           progress_cb=lambda d, t: calls.append((d, t)))
        assert len(calls) == 2

    def test_bad_callback_no_crash(self):
        stop = threading.Event()
        def bad(d, t): raise RuntimeError("broken")
        with patch("veilscan.udp_scanner.scan_udp_port", side_effect=self._fake()):
            results = scan_udp_batch("1.2.3.4", [53, 123], 0.1, stop,
                                     progress_cb=bad)
        assert len(results) == 2

    def test_open_state_returned(self):
        stop = threading.Event()
        def fake_open(ip, port, timeout, can_icmp=True):
            return PortInfo(port=port, protocol="udp", state=PortState.OPEN)
        with patch("veilscan.udp_scanner.scan_udp_port", side_effect=fake_open):
            results = scan_udp_batch("1.2.3.4", [53], 0.1, stop)
        assert results[0].state == PortState.OPEN

    def test_closed_state_returned(self):
        stop = threading.Event()
        def fake_closed(ip, port, timeout, can_icmp=True):
            return PortInfo(port=port, protocol="udp", state=PortState.CLOSED)
        with patch("veilscan.udp_scanner.scan_udp_port", side_effect=fake_closed):
            results = scan_udp_batch("1.2.3.4", [53], 0.1, stop)
        assert results[0].state == PortState.CLOSED
