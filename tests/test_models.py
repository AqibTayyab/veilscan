"""tests/test_models.py — Unit tests for veilscan/models.py"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pytest
from veilscan.models import PortInfo, HostResult, ScanResult, PortState


class TestPortState:
    def test_values(self):
        assert PortState.OPEN          == "open"
        assert PortState.CLOSED        == "closed"
        assert PortState.FILTERED      == "filtered"
        assert PortState.OPEN_FILTERED == "open|filtered"

    def test_is_string(self):
        assert isinstance(PortState.OPEN, str)

    def test_comparison(self):
        p = PortInfo(port=80, protocol="tcp", state=PortState.OPEN)
        assert p.state == PortState.OPEN
        assert p.state != PortState.CLOSED

    def test_string_comparison(self):
        assert PortState.OPEN == "open"
        assert PortState.OPEN_FILTERED == "open|filtered"


class TestPortInfo:
    def test_required_fields(self):
        p = PortInfo(port=80, protocol="tcp", state=PortState.OPEN)
        assert p.port == 80 and p.protocol == "tcp" and p.state == PortState.OPEN

    def test_optional_defaults(self):
        p = PortInfo(port=80, protocol="tcp", state=PortState.OPEN)
        assert p.service == "" and p.version == "" and p.banner == ""

    def test_optional_settable(self):
        p = PortInfo(port=80, protocol="tcp", state=PortState.OPEN,
                     service="HTTP", version="Apache/2.4", banner="HTTP/1.1 200")
        assert p.service == "HTTP" and p.version == "Apache/2.4"

    def test_mutable(self):
        p = PortInfo(port=22, protocol="tcp", state=PortState.OPEN)
        p.service = "SSH"; p.version = "OpenSSH_8.9"
        assert p.service == "SSH" and p.version == "OpenSSH_8.9"

    def test_str_repr(self):
        p = PortInfo(port=80, protocol="tcp", state=PortState.OPEN, service="HTTP")
        s = str(p)
        assert "80" in s and "tcp" in s

    def test_udp_protocol(self):
        p = PortInfo(port=53, protocol="udp", state=PortState.OPEN_FILTERED)
        assert p.protocol == "udp" and p.state == PortState.OPEN_FILTERED


class TestHostResult:
    def _host(self):
        return HostResult(host="test.com", ip="1.2.3.4", ports=[
            PortInfo(port=22,   protocol="tcp", state=PortState.OPEN),
            PortInfo(port=80,   protocol="tcp", state=PortState.OPEN),
            PortInfo(port=9999, protocol="tcp", state=PortState.CLOSED),
            PortInfo(port=53,   protocol="udp", state=PortState.OPEN_FILTERED),
        ])

    def test_open_ports(self):
        h = self._host()
        assert len(h.open_ports) == 2
        assert all(p.state == PortState.OPEN for p in h.open_ports)

    def test_open_filtered_ports(self):
        h = self._host()
        assert len(h.open_filtered_ports) == 3  # OPEN + OPEN_FILTERED

    def test_tcp_ports(self):
        h = self._host()
        assert len(h.tcp_ports) == 3
        assert all(p.protocol == "tcp" for p in h.tcp_ports)

    def test_udp_ports(self):
        h = self._host()
        assert len(h.udp_ports) == 1
        assert h.udp_ports[0].port == 53

    def test_empty_defaults(self):
        h = HostResult(host="x", ip="1.1.1.1")
        assert h.os_hint == "" and h.ports == []

    def test_summary(self):
        h = self._host()
        s = h.summary()
        assert "test.com" in s and "1.2.3.4" in s

    def test_append_ports(self):
        h = HostResult(host="x", ip="1.1.1.1")
        h.ports.append(PortInfo(port=80, protocol="tcp", state=PortState.OPEN))
        assert len(h.open_ports) == 1


class TestScanResult:
    def _result(self):
        return ScanResult(hosts=[
            HostResult(host="a", ip="1.1.1.1", ports=[
                PortInfo(port=22, protocol="tcp", state=PortState.OPEN),
                PortInfo(port=80, protocol="tcp", state=PortState.OPEN),
            ]),
            HostResult(host="b", ip="2.2.2.2", ports=[
                PortInfo(port=443, protocol="tcp", state=PortState.OPEN),
            ]),
            HostResult(host="c", ip="3.3.3.3"),
        ], duration=3.0, scanner_version="2.0.0")

    def test_total_open_ports(self):
        assert self._result().total_open_ports == 3

    def test_hosts_with_open_ports(self):
        r = self._result()
        active = r.hosts_with_open_ports
        assert len(active) == 2
        assert all(len(h.open_ports) > 0 for h in active)

    def test_empty_result(self):
        r = ScanResult()
        assert r.total_open_ports == 0
        assert r.hosts_with_open_ports == []

    def test_defaults(self):
        r = ScanResult()
        assert r.hosts == [] and r.duration == 0.0
        assert r.start_time == "" and r.scanner_version == ""

    def test_summary(self):
        s = self._result().summary()
        assert "3" in s and "3.00" in s

    def test_config_stored(self):
        r = ScanResult(config={"target": "192.168.1.1"})
        assert r.config["target"] == "192.168.1.1"
