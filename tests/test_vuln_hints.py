"""tests/test_vuln_hints.py — Unit tests for veilscan/vuln_hints.py"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pytest
from veilscan.vuln_hints import (
    HINTS, ServiceHint, get_hint, get_risk,
    risk_sort_key, RISK_COLORS, RISK_ICONS,
)


# ── Database completeness ─────────────────────────────────────────────────────

class TestHintsDatabase:
    def test_minimum_entries(self):
        assert len(HINTS) >= 40

    def test_all_values_are_service_hints(self):
        for port, hint in HINTS.items():
            assert isinstance(hint, ServiceHint), \
                f"Port {port} value is not a ServiceHint"

    def test_all_keys_are_ints(self):
        for port in HINTS:
            assert isinstance(port, int), f"Key {port!r} is not an int"

    def test_all_ports_valid(self):
        for port in HINTS:
            assert 1 <= port <= 65535, f"Port {port} out of range"

    def test_all_fields_non_empty(self):
        for port, hint in HINTS.items():
            assert hint.service, f"Port {port}: service is empty"
            assert hint.what,    f"Port {port}: what is empty"
            assert hint.risk,    f"Port {port}: risk is empty"
            assert hint.why,     f"Port {port}: why is empty"
            assert hint.check,   f"Port {port}: check is empty"
            assert hint.learn,   f"Port {port}: learn is empty"

    def test_all_risk_levels_valid(self):
        valid = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
        for port, hint in HINTS.items():
            assert hint.risk in valid, \
                f"Port {port}: invalid risk level {hint.risk!r}"


# ── Risk levels for specific ports ────────────────────────────────────────────

class TestRiskLevels:
    # CRITICAL ports
    def test_smb_critical(self):    assert get_risk(445)   == "CRITICAL"
    def test_mysql_critical(self):  assert get_risk(3306)  == "CRITICAL"
    def test_postgres_critical(self): assert get_risk(5432) == "CRITICAL"
    def test_mongodb_critical(self):  assert get_risk(27017) == "CRITICAL"
    def test_redis_critical(self):  assert get_risk(6379)  == "CRITICAL"
    def test_telnet_critical(self): assert get_risk(23)    == "CRITICAL"
    def test_tftp_critical(self):   assert get_risk(69)    == "CRITICAL"
    def test_rexec_critical(self):  assert get_risk(512)   == "CRITICAL"
    def test_rlogin_critical(self): assert get_risk(513)   == "CRITICAL"
    def test_rsh_critical(self):    assert get_risk(514)   == "CRITICAL"
    def test_java_rmi_critical(self): assert get_risk(1099) == "CRITICAL"
    def test_docker_critical(self): assert get_risk(2375)  == "CRITICAL"
    def test_k8s_critical(self):    assert get_risk(6443)  == "CRITICAL"
    def test_memcached_critical(self): assert get_risk(11211) == "CRITICAL"

    # HIGH ports
    def test_rdp_high(self):        assert get_risk(3389)  == "HIGH"
    def test_vnc_high(self):        assert get_risk(5900)  == "HIGH"
    def test_ftp_high(self):        assert get_risk(21)    == "HIGH"
    def test_ms_rpc_high(self):     assert get_risk(135)   == "HIGH"
    def test_netbios_high(self):    assert get_risk(139)   == "HIGH"
    def test_snmp_high(self):       assert get_risk(161)   == "HIGH"
    def test_nfs_high(self):        assert get_risk(2049)  == "HIGH"
    def test_rpcbind_high(self):    assert get_risk(111)   == "HIGH"
    def test_webmin_high(self):     assert get_risk(10000) == "HIGH"

    # MEDIUM ports
    def test_http_medium(self):     assert get_risk(80)    == "MEDIUM"
    def test_smtp_medium(self):     assert get_risk(25)    == "MEDIUM"
    def test_dns_medium(self):      assert get_risk(53)    == "MEDIUM"
    def test_pop3_medium(self):     assert get_risk(110)   == "MEDIUM"
    def test_imap_medium(self):     assert get_risk(143)   == "MEDIUM"
    def test_irc_medium(self):      assert get_risk(6667)  == "MEDIUM"

    # LOW ports
    def test_ssh_low(self):         assert get_risk(22)    == "LOW"

    # INFO ports
    def test_https_info(self):      assert get_risk(443)   == "INFO"


# ── Metasploitable coverage ───────────────────────────────────────────────────

class TestMetasploitableCoverage:
    """All ports found on Metasploitable must have hints."""

    METASPLOITABLE_PORTS = [
        21,   # FTP
        22,   # SSH
        23,   # Telnet
        25,   # SMTP
        53,   # DNS
        80,   # HTTP
        111,  # RPCbind
        139,  # NetBIOS
        445,  # SMB
        512,  # rexec
        513,  # rlogin
        514,  # rsh
        1099, # Java-RMI
        2049, # NFS
        5432, # PostgreSQL
        5900, # VNC
        6667, # IRC
    ]

    def test_all_metasploitable_ports_have_hints(self):
        missing = [p for p in self.METASPLOITABLE_PORTS
                   if get_hint(p) is None]
        assert not missing, \
            f"Missing hints for Metasploitable ports: {missing}"

    def test_metasploitable_critical_ports(self):
        critical_ports = [445, 512, 513, 514, 1099]
        for port in critical_ports:
            assert get_risk(port) == "CRITICAL", \
                f"Port {port} should be CRITICAL"


# ── get_hint() function ───────────────────────────────────────────────────────

class TestGetHint:
    def test_known_port_returns_hint(self):
        h = get_hint(22)
        assert h is not None
        assert isinstance(h, ServiceHint)

    def test_unknown_port_returns_none(self):
        assert get_hint(39999) is None

    def test_ssh_hint_mentions_ssh(self):
        h = get_hint(22)
        assert "SSH" in h.what

    def test_smb_hint_mentions_wannacry(self):
        h = get_hint(445)
        assert "WannaCry" in h.why or "EternalBlue" in h.why

    def test_redis_hint_mentions_auth(self):
        h = get_hint(6379)
        assert "auth" in h.why.lower() or "authentication" in h.why.lower()

    def test_rexec_hint_has_check(self):
        h = get_hint(512)
        assert h.check != ""
        assert "SSH" in h.learn or "ssh" in h.learn.lower()


# ── get_risk() function ───────────────────────────────────────────────────────

class TestGetRisk:
    def test_known_port_returns_risk(self):
        assert get_risk(22) == "LOW"

    def test_unknown_port_returns_info(self):
        assert get_risk(39999) == "INFO"

    def test_returns_string(self):
        assert isinstance(get_risk(80),    str)
        assert isinstance(get_risk(39999), str)


# ── risk_sort_key() function ──────────────────────────────────────────────────

class TestRiskSortKey:
    def test_ordering(self):
        keys = {r: risk_sort_key(r)
                for r in ["INFO","LOW","MEDIUM","HIGH","CRITICAL"]}
        assert keys["INFO"]     < keys["LOW"]
        assert keys["LOW"]      < keys["MEDIUM"]
        assert keys["MEDIUM"]   < keys["HIGH"]
        assert keys["HIGH"]     < keys["CRITICAL"]

    def test_unknown_risk(self):
        k = risk_sort_key("UNKNOWN")
        assert isinstance(k, int)

    def test_critical_highest(self):
        assert risk_sort_key("CRITICAL") == max(
            risk_sort_key(r) for r in ["INFO","LOW","MEDIUM","HIGH","CRITICAL"]
        )


# ── RISK_COLORS dict ──────────────────────────────────────────────────────────

class TestRiskColors:
    def test_all_five_levels(self):
        assert set(RISK_COLORS.keys()) == {
            "INFO","LOW","MEDIUM","HIGH","CRITICAL"
        }

    def test_each_level_has_required_keys(self):
        for level, colors in RISK_COLORS.items():
            assert "bg"     in colors, f"{level}: missing 'bg'"
            assert "border" in colors, f"{level}: missing 'border'"
            assert "text"   in colors, f"{level}: missing 'text'"
            assert "badge"  in colors, f"{level}: missing 'badge'"

    def test_color_values_are_strings(self):
        for level, colors in RISK_COLORS.items():
            for key, val in colors.items():
                assert isinstance(val, str), \
                    f"{level}[{key}] is not a string"

    def test_colors_look_like_hex(self):
        for level, colors in RISK_COLORS.items():
            for key, val in colors.items():
                assert val.startswith("#"), \
                    f"{level}[{key}] = {val!r} doesn't start with #"


# ── RISK_ICONS dict ───────────────────────────────────────────────────────────

class TestRiskIcons:
    def test_all_five_levels(self):
        assert set(RISK_ICONS.keys()) == {
            "INFO","LOW","MEDIUM","HIGH","CRITICAL"
        }

    def test_values_are_strings(self):
        for level, icon in RISK_ICONS.items():
            assert isinstance(icon, str), \
                f"RISK_ICONS[{level}] is not a string"

    def test_values_non_empty(self):
        for level, icon in RISK_ICONS.items():
            assert icon, f"RISK_ICONS[{level}] is empty"
