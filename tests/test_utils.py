"""tests/test_utils.py — Unit tests for veilscan/utils.py"""
import sys, os, socket
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pytest
from unittest.mock import patch
from veilscan.utils import (
    parse_ports, expand_cidr, resolve_host, os_hint,
    is_private_ip, get_service_name, validate_target,
    estimate_scan_time, format_duration, TOP_100, TOP_1000,
)


class TestTop100:
    def test_length(self):        assert len(TOP_100) == 100
    def test_no_duplicates(self): assert len(TOP_100) == len(set(TOP_100))
    def test_sorted(self):        assert TOP_100 == sorted(TOP_100)
    def test_valid_range(self):   assert all(1 <= p <= 65535 for p in TOP_100)

class TestTop1000:
    def test_no_duplicates(self): assert len(TOP_1000) == len(set(TOP_1000))
    def test_larger_than_100(self): assert len(TOP_1000) > 100
    def test_valid_range(self):   assert all(1 <= p <= 65535 for p in TOP_1000)


class TestParsePorts:
    def test_top100(self):   assert len(parse_ports("top100"))  == 100
    def test_top1000(self):  assert len(parse_ports("top1000")) > 100
    def test_full(self):     assert len(parse_ports("full"))    == 65535

    def test_single(self):   assert parse_ports("80")           == [80]
    def test_list(self):     assert parse_ports("22,80,443")    == [22, 80, 443]
    def test_range(self):    assert parse_ports("80-85")        == [80,81,82,83,84,85]
    def test_mixed(self):    assert parse_ports("22,80-82,443") == [22,80,81,82,443]
    def test_sorted(self):   assert parse_ports("443,22,80")    == [22,80,443]
    def test_deduped(self):  assert parse_ports("80,80,80")     == [80]
    def test_spaces(self):   assert parse_ports(" 22 , 80 ")    == [22,80]

    def test_invalid_text(self):
        with pytest.raises(ValueError): parse_ports("abc")
    def test_port_zero(self):
        with pytest.raises(ValueError): parse_ports("0")
    def test_port_too_high(self):
        with pytest.raises(ValueError): parse_ports("65536")
    def test_bad_range(self):
        with pytest.raises(ValueError): parse_ports("1000-500")


class TestExpandCidr:
    def test_single_ip(self):
        assert expand_cidr("192.168.1.1") == ["192.168.1.1"]
    def test_slash30(self):
        assert expand_cidr("192.168.1.0/30") == ["192.168.1.1","192.168.1.2"]
    def test_slash24(self):
        result = expand_cidr("192.168.1.0/24")
        assert len(result) == 254
        assert result[0]  == "192.168.1.1"
        assert result[-1] == "192.168.1.254"
    def test_slash32(self):
        result = expand_cidr("10.0.0.1/32")
        assert result == ["10.0.0.1"]
    def test_no_network_addr(self):
        result = expand_cidr("10.0.0.0/24")
        assert "10.0.0.0"   not in result
        assert "10.0.0.255" not in result
    def test_hostname_passthrough(self):
        assert expand_cidr("example.com") == ["example.com"]
    def test_invalid_passthrough(self):
        assert expand_cidr("not-cidr") == ["not-cidr"]


class TestResolveHost:
    def test_ip_passthrough(self):
        assert resolve_host("127.0.0.1") == "127.0.0.1"

    def test_hostname_resolved(self):
        with patch("socket.gethostbyname", return_value="1.2.3.4"):
            assert resolve_host("example.com") == "1.2.3.4"

    def test_invalid_raises_valueerror(self):
        with patch("socket.gethostbyname", side_effect=socket.gaierror("fail")):
            with pytest.raises(ValueError) as exc:
                resolve_host("bad.host")
        assert "bad.host" in str(exc.value)


class TestOsHint:
    def test_linux_64(self):    assert "Linux"   in os_hint(64)
    def test_linux_48(self):    assert "Linux"   in os_hint(48)
    def test_windows_128(self): assert "Windows" in os_hint(128)
    def test_windows_100(self): assert "Windows" in os_hint(100)
    def test_network_255(self): assert "Network" in os_hint(255)
    def test_none(self):        assert os_hint(None) == ""
    def test_always_string(self):
        for ttl in [1, 64, 65, 128, 129, 255]:
            assert isinstance(os_hint(ttl), str)


class TestIsPrivateIp:
    def test_rfc1918_10(self):   assert is_private_ip("10.0.0.1")
    def test_rfc1918_172(self):  assert is_private_ip("172.16.0.1")
    def test_rfc1918_192(self):  assert is_private_ip("192.168.1.1")
    def test_loopback(self):     assert is_private_ip("127.0.0.1")
    def test_link_local(self):   assert is_private_ip("169.254.0.1")
    def test_public_google(self):assert not is_private_ip("8.8.8.8")
    def test_public_other(self): assert not is_private_ip("45.33.32.156")
    def test_invalid(self):      assert not is_private_ip("not-an-ip")
    def test_empty(self):        assert not is_private_ip("")


class TestGetServiceName:
    def test_http(self):    assert get_service_name(80)    == "HTTP"
    def test_ssh(self):     assert get_service_name(22)    == "SSH"
    def test_https(self):   assert get_service_name(443)   == "HTTPS"
    def test_mysql(self):   assert get_service_name(3306)  == "MySQL"
    def test_redis(self):   assert get_service_name(6379)  == "Redis"
    def test_unknown(self): assert get_service_name(19999) == ""
    def test_returns_str(self):
        assert isinstance(get_service_name(80), str)
        assert isinstance(get_service_name(99999), str)


class TestValidateTarget:
    def test_valid_ip(self):       validate_target("192.168.1.1")
    def test_valid_cidr(self):     validate_target("192.168.1.0/24")
    def test_valid_hostname(self): validate_target("scanme.nmap.org")

    def test_empty_raises(self):
        with pytest.raises(ValueError): validate_target("")

    def test_ipv6_raises(self):
        with pytest.raises(ValueError): validate_target("::1")

    def test_zero_raises(self):
        with pytest.raises(ValueError): validate_target("0.0.0.0")

    def test_broadcast_raises(self):
        with pytest.raises(ValueError): validate_target("255.255.255.255")

    def test_multicast_raises(self):
        with pytest.raises(ValueError): validate_target("224.0.0.1")


class TestEstimateScanTime:
    def test_positive(self):
        t = estimate_scan_time(1, 100, 200, 0.5, banners=False)
        assert t > 0

    def test_banners_add_time(self):
        t_no  = estimate_scan_time(1, 100, 100, 1.0, banners=False)
        t_yes = estimate_scan_time(1, 100, 100, 1.0, banners=True)
        assert t_yes > t_no

    def test_more_hosts_more_time(self):
        t1 = estimate_scan_time(1,  100, 100, 1.0, banners=False)
        t10= estimate_scan_time(10, 100, 100, 1.0, banners=False)
        assert t10 > t1

    def test_more_threads_less_time(self):
        t1  = estimate_scan_time(1, 1000, 10,  1.0, banners=False)
        t2  = estimate_scan_time(1, 1000, 100, 1.0, banners=False)
        assert t1 > t2


class TestFormatDuration:
    def test_seconds(self):  assert "second" in format_duration(30)
    def test_minutes(self):  assert "minute" in format_duration(90)
    def test_hours(self):    assert "hour"   in format_duration(3700)
    def test_one_second(self):
        s = format_duration(1)
        assert "1 second" in s and "seconds" not in s
    def test_zero(self):     assert "0 second" in format_duration(0)
