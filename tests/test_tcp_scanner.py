"""tests/test_tcp_scanner.py — Unit tests for veilscan/tcp_scanner.py"""
import sys, os, socket, threading
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pytest
from unittest.mock import MagicMock, patch
from veilscan.models import PortState
from veilscan.tcp_scanner import scan_tcp_port, scan_tcp_batch


def mk(code=0, err=None):
    """Build a mock socket that returns given connect_ex code or raises err."""
    m = MagicMock()
    m.__enter__ = MagicMock(return_value=m)
    m.__exit__  = MagicMock(return_value=False)
    if err: m.connect_ex.side_effect = err
    else:   m.connect_ex.return_value = code
    return m


class TestScanTcpPort:
    def test_open_port(self):
        with patch("socket.socket", return_value=mk(0)):
            r = scan_tcp_port("127.0.0.1", 80)
        assert r.state == PortState.OPEN

    def test_open_port_service(self):
        with patch("socket.socket", return_value=mk(0)):
            r = scan_tcp_port("127.0.0.1", 80)
        assert r.service == "HTTP"

    def test_open_port_protocol(self):
        with patch("socket.socket", return_value=mk(0)):
            r = scan_tcp_port("127.0.0.1", 22)
        assert r.protocol == "tcp"

    def test_econnrefused_linux(self):
        with patch("socket.socket", return_value=mk(111)):
            r = scan_tcp_port("127.0.0.1", 9999)
        assert r.state == PortState.CLOSED

    def test_econnrefused_windows(self):
        with patch("socket.socket", return_value=mk(10061)):
            r = scan_tcp_port("127.0.0.1", 9999)
        assert r.state == PortState.CLOSED

    def test_timeout_no_retry(self):
        with patch("socket.socket", return_value=mk(err=socket.timeout())):
            r = scan_tcp_port("127.0.0.1", 80, retries=0)
        assert r.state == PortState.CLOSED

    def test_retry_on_timeout(self):
        m = mk()
        m.connect_ex.side_effect = [socket.timeout(), 0]
        with patch("socket.socket", return_value=m):
            r = scan_tcp_port("127.0.0.1", 22, retries=1)
        assert r.state == PortState.OPEN
        assert m.connect_ex.call_count == 2

    def test_no_retry_on_refused(self):
        m = mk(111)
        with patch("socket.socket", return_value=m):
            scan_tcp_port("127.0.0.1", 9999, retries=5)
        assert m.connect_ex.call_count == 1

    def test_version_banner_empty(self):
        with patch("socket.socket", return_value=mk(0)):
            r = scan_tcp_port("127.0.0.1", 80)
        assert r.version == "" and r.banner == ""

    def test_unknown_port_empty_service(self):
        with patch("socket.socket", return_value=mk(0)):
            r = scan_tcp_port("127.0.0.1", 39999)
        assert r.service == ""

    def test_ssh_port_service(self):
        with patch("socket.socket", return_value=mk(0)):
            r = scan_tcp_port("127.0.0.1", 22)
        assert r.service == "SSH"

    def test_mysql_port_service(self):
        with patch("socket.socket", return_value=mk(0)):
            r = scan_tcp_port("127.0.0.1", 3306)
        assert r.service == "MySQL"


class TestScanTcpBatch:
    def test_empty_list(self):
        stop = threading.Event()
        assert scan_tcp_batch("127.0.0.1", [], 1.0, 10, stop) == []

    def test_scans_all_ports(self):
        ports = [22, 80, 443]
        stop  = threading.Event()
        with patch("socket.socket", return_value=mk(0)):
            results = scan_tcp_batch("127.0.0.1", ports, 1.0, 3, stop)
        assert sorted(r.port for r in results) == sorted(ports)

    def test_no_duplicates(self):
        ports = list(range(1, 51))
        stop  = threading.Event()
        with patch("socket.socket", return_value=mk(0)):
            results = scan_tcp_batch("127.0.0.1", ports, 1.0, 20, stop)
        pnums = [r.port for r in results]
        assert len(pnums) == len(set(pnums)) == 50

    def test_all_results_returned(self):
        ports = [22, 80, 443, 3306, 5432]
        stop  = threading.Event()
        with patch("socket.socket", return_value=mk(0)):
            results = scan_tcp_batch("127.0.0.1", ports, 1.0, 5, stop)
        assert len(results) == 5

    def test_progress_callback_called(self):
        calls = []
        stop  = threading.Event()
        with patch("socket.socket", return_value=mk(0)):
            scan_tcp_batch("127.0.0.1", [80, 443], 1.0, 2, stop,
                           progress_cb=lambda d, t: calls.append((d, t)))
        assert len(calls) == 2
        assert all(t == 2 for _, t in calls)

    def test_bad_progress_cb_no_crash(self):
        stop = threading.Event()
        def bad(d, t): raise RuntimeError("broken")
        with patch("socket.socket", return_value=mk(0)):
            results = scan_tcp_batch("127.0.0.1", [80, 443], 1.0, 2, stop,
                                     progress_cb=bad)
        assert len(results) == 2

    def test_stop_event_aborts(self):
        ports = list(range(1, 201))
        stop  = threading.Event()
        count = [0]

        def slow_socket(*_args, **_kw):
            m = mk()
            def side(addr):
                count[0] += 1
                if count[0] > 5: stop.set()
                return 0
            m.connect_ex.side_effect = side
            return m

        with patch("socket.socket", side_effect=slow_socket):
            results = scan_tcp_batch("127.0.0.1", ports, 0.01, 1, stop)
        assert len(results) < len(ports)

    def test_thread_count_capped(self):
        """More threads than ports is fine — capped at len(ports)."""
        ports = [80, 443]
        stop  = threading.Event()
        with patch("socket.socket", return_value=mk(0)):
            results = scan_tcp_batch("127.0.0.1", ports, 1.0, 1000, stop)
        assert len(results) == 2

    def test_open_and_closed_both_returned(self):
        ports = [80, 9999]
        stop  = threading.Event()

        def sock_factory(*_args, **_kw):
            m = mk()
            call_count = [0]
            def side(addr):
                call_count[0] += 1
                return 0 if addr[1] == 80 else 111
            m.connect_ex.side_effect = side
            return m

        with patch("socket.socket", side_effect=sock_factory):
            results = scan_tcp_batch("127.0.0.1", ports, 1.0, 2, stop)

        states = {r.port: r.state for r in results}
        assert states[80]   == PortState.OPEN
        assert states[9999] == PortState.CLOSED
