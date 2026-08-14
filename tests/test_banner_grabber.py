"""tests/test_banner_grabber.py — Unit tests for veilscan/banner_grabber.py"""
import sys, os, socket, ssl
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pytest
from unittest.mock import MagicMock, patch
from veilscan.banner_grabber import grab_banner, _parse_banner, TLS_PORTS, PROBE_MAP


def mk_sock(resp=b"", refuse=False, timeout=False, reset=False):
    """Build a connected mock socket."""
    m = MagicMock()
    m.__enter__ = MagicMock(return_value=m)
    m.__exit__  = MagicMock(return_value=False)
    if refuse:
        m.connect.side_effect = ConnectionRefusedError()
    elif timeout:
        m.connect.side_effect = socket.timeout()
    elif reset:
        m.connect.side_effect = ConnectionResetError()
    else:
        m.connect.return_value = None
        m.recv.return_value = resp
    return m


class TestParseBanner:
    # ── SSH ──────────────────────────────────────────────────────────────────
    def test_ssh_service(self):
        s, v, _ = _parse_banner(22, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3")
        assert s == "SSH"

    def test_ssh_version(self):
        s, v, _ = _parse_banner(22, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3")
        assert "OpenSSH_8.9p1" in v

    def test_ssh_v1(self):
        s, v, _ = _parse_banner(22, "SSH-1.99-Cisco-1.25")
        assert s == "SSH"

    # ── HTTP ─────────────────────────────────────────────────────────────────
    def test_http_service(self):
        s, v, _ = _parse_banner(80, "HTTP/1.1 200 OK\r\nServer: Apache/2.4.54\r\n")
        assert s == "HTTP"

    def test_http_version(self):
        s, v, _ = _parse_banner(80, "HTTP/1.1 200 OK\r\nServer: Apache/2.4.54\r\n")
        assert v == "Apache/2.4.54"

    def test_https_port_443(self):
        s, v, _ = _parse_banner(443, "HTTP/1.1 200 OK\r\nServer: nginx/1.24\r\n")
        assert s == "HTTPS"

    def test_https_port_8443(self):
        s, v, _ = _parse_banner(8443, "HTTP/1.1 200 OK\r\nServer: nginx\r\n")
        assert s == "HTTPS"

    def test_http_no_server_header(self):
        s, v, _ = _parse_banner(80, "HTTP/1.1 404 Not Found\r\n\r\n")
        assert s == "HTTP" and v == ""

    # ── FTP ──────────────────────────────────────────────────────────────────
    def test_ftp_service(self):
        s, v, _ = _parse_banner(21, "220 ProFTPD 1.3.6 Server ready")
        assert s == "FTP"

    def test_ftp_filezilla(self):
        s, v, _ = _parse_banner(21, "220 FileZilla Server 1.8.0")
        assert s == "FTP"

    def test_ftp_vsftpd(self):
        s, v, _ = _parse_banner(21, "220 (vsFTPd 3.0.3)")
        assert s == "FTP"

    # ── SMTP ─────────────────────────────────────────────────────────────────
    def test_smtp_service(self):
        s, v, _ = _parse_banner(25, "220 mail.example.com ESMTP Postfix (Ubuntu)")
        assert s == "SMTP"

    def test_smtp_version_has_postfix(self):
        s, v, _ = _parse_banner(25, "220 mail.example.com ESMTP Postfix (Ubuntu)")
        assert "Postfix" in v

    # ── POP3 / IMAP ──────────────────────────────────────────────────────────
    def test_pop3_service(self):
        s, _, _ = _parse_banner(110, "+OK Dovecot ready.")
        assert s == "POP3"

    def test_imap_service(self):
        s, _, _ = _parse_banner(143, "* OK Dovecot IMAP ready.")
        assert s == "IMAP"

    # ── Redis ─────────────────────────────────────────────────────────────────
    def test_redis_pong(self):
        s, _, _ = _parse_banner(6379, "+PONG")
        assert s == "Redis"

    def test_redis_err_auth(self):
        s, _, _ = _parse_banner(6379, "-ERR operation not permitted")
        assert s == "Redis"

    # ── Memcached ─────────────────────────────────────────────────────────────
    def test_memcached_service(self):
        s, v, _ = _parse_banner(11211, "VERSION 1.6.17")
        assert s == "Memcached"

    def test_memcached_version(self):
        s, v, _ = _parse_banner(11211, "VERSION 1.6.17")
        assert v == "1.6.17"

    # ── MySQL / MariaDB ───────────────────────────────────────────────────────
    def test_mysql_service(self):
        s, v, _ = _parse_banner(3306, "\x00\x00\x00\x0a8.0.32\x00")
        assert s == "MySQL"

    def test_mysql_version(self):
        s, v, _ = _parse_banner(3306, "\x00\x00\x00\x0a8.0.32\x00")
        assert "8.0.32" in v

    def test_mariadb_detected(self):
        s, v, _ = _parse_banner(3306, "\x005.5.5-10.6.12-MariaDB\x00")
        assert s == "MariaDB"

    # ── VNC ───────────────────────────────────────────────────────────────────
    def test_vnc_service(self):
        s, v, _ = _parse_banner(5900, "RFB 003.003\n")
        assert s == "VNC"

    def test_vnc_version_no_rfb_prefix(self):
        s, v, _ = _parse_banner(5900, "RFB 003.003\n")
        assert v == "003.003"
        assert "RFB" not in v

    def test_vnc_version_008(self):
        s, v, _ = _parse_banner(5900, "RFB 003.008\n")
        assert v == "003.008"

    # ── IRC ───────────────────────────────────────────────────────────────────
    def test_irc_service(self):
        s, _, _ = _parse_banner(6667,
            ":irc.Metasploitable.LAN NOTICE AUTH :*** Looking up your hostname...")
        assert s == "IRC"

    # ── Edge cases ────────────────────────────────────────────────────────────
    def test_empty_banner(self):
        assert _parse_banner(80, "") == ("", "", "")

    def test_unknown_banner(self):
        s, v, b = _parse_banner(12345, "some unknown protocol response")
        assert s == "" and v == ""
        assert "unknown protocol" in b

    def test_postgresql(self):
        s, _, _ = _parse_banner(5432, "\x00\x00\x00\x08\x04\xd2\x16/")
        assert s == "PostgreSQL"


class TestGrabBanner:
    def test_ssh_grab(self):
        with patch("veilscan.banner_grabber._connect",
                   return_value=mk_sock(b"SSH-2.0-OpenSSH_8.9p1\r\n")):
            s, v, banner = grab_banner("127.0.0.1", 22, 1.0)
        assert s == "SSH" and "OpenSSH" in v

    def test_http_grab(self):
        with patch("veilscan.banner_grabber._connect",
                   return_value=mk_sock(b"HTTP/1.1 200 OK\r\nServer: Apache/2.4\r\n")):
            s, v, banner = grab_banner("127.0.0.1", 80, 1.0)
        assert s == "HTTP" and v == "Apache/2.4"

    def test_redis_grab(self):
        with patch("veilscan.banner_grabber._connect",
                   return_value=mk_sock(b"+PONG\r\n")):
            s, v, banner = grab_banner("127.0.0.1", 6379, 1.0)
        assert s == "Redis"

    def test_banner_truncated_to_256(self):
        long_resp = b"HTTP/1.1 200 OK\r\nServer: test\r\n" + b"X" * 1000
        with patch("veilscan.banner_grabber._connect",
                   return_value=mk_sock(long_resp)):
            _, _, banner = grab_banner("127.0.0.1", 80, 1.0)
        assert len(banner) <= 256

    def test_connection_refused_returns_empty(self):
        with patch("veilscan.banner_grabber._connect",
                   side_effect=ConnectionRefusedError()):
            result = grab_banner("127.0.0.1", 9999, 1.0)
        assert result == ("", "", "")

    def test_timeout_returns_empty(self):
        with patch("veilscan.banner_grabber._connect",
                   side_effect=socket.timeout()):
            result = grab_banner("127.0.0.1", 80, 0.1)
        assert result == ("", "", "")

    def test_any_exception_returns_empty(self):
        with patch("veilscan.banner_grabber._connect",
                   side_effect=Exception("unexpected")):
            result = grab_banner("127.0.0.1", 80, 1.0)
        assert result == ("", "", "")

    def test_empty_response_returns_empty(self):
        with patch("veilscan.banner_grabber._connect",
                   return_value=mk_sock(b"")):
            result = grab_banner("127.0.0.1", 80, 1.0)
        assert result == ("", "", "")

    def test_binary_response_safe(self):
        with patch("veilscan.banner_grabber._connect",
                   return_value=mk_sock(bytes(range(256)))):
            result = grab_banner("127.0.0.1", 3306, 1.0)
        assert isinstance(result, tuple) and len(result) == 3

    def test_never_raises(self):
        """grab_banner must NEVER raise — always returns tuple."""
        m = MagicMock()
        m.__enter__ = MagicMock(return_value=m)
        m.__exit__  = MagicMock(return_value=False)
        m.recv.side_effect = Exception("crash during recv")
        m.connect.return_value = None
        with patch("veilscan.banner_grabber._connect", return_value=m):
            result = grab_banner("127.0.0.1", 80, 1.0)
        assert isinstance(result, tuple) and len(result) == 3

    def test_result_is_tuple_of_three(self):
        with patch("veilscan.banner_grabber._connect",
                   return_value=mk_sock(b"SSH-2.0-test\r\n")):
            result = grab_banner("127.0.0.1", 22, 1.0)
        assert isinstance(result, tuple) and len(result) == 3


class TestTlsPorts:
    def test_443_in_tls(self):  assert 443  in TLS_PORTS
    def test_8443_in_tls(self): assert 8443 in TLS_PORTS
    def test_993_in_tls(self):  assert 993  in TLS_PORTS
    def test_995_in_tls(self):  assert 995  in TLS_PORTS
    def test_465_in_tls(self):  assert 465  in TLS_PORTS
    def test_80_not_tls(self):  assert 80   not in TLS_PORTS
    def test_22_not_tls(self):  assert 22   not in TLS_PORTS


class TestProbeMap:
    def test_ssh_is_none(self):
        assert PROBE_MAP.get(22) is None  # read-first

    def test_ftp_is_none(self):
        assert PROBE_MAP.get(21) is None  # read-first

    def test_http_has_probe(self):
        assert PROBE_MAP.get(80) is not None
        assert b"GET" in PROBE_MAP[80]

    def test_redis_has_ping(self):
        assert PROBE_MAP.get(6379) is not None
        assert b"PING" in PROBE_MAP[6379]
