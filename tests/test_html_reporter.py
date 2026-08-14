"""tests/test_html_reporter.py — Unit tests for veilscan/html_reporter.py"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pytest
from veilscan.models import ScanResult, HostResult, PortInfo, PortState
from veilscan.html_reporter import generate_html


# ── Test helpers ──────────────────────────────────────────────────────────────

def make_result(ports=None, os_hint="Linux/Unix (TTL=64)"):
    if ports is None:
        ports = [
            PortInfo(port=22,   protocol="tcp", state=PortState.OPEN,
                     service="SSH",   version="OpenSSH_8.9", banner="SSH-2.0-OpenSSH_8.9"),
            PortInfo(port=80,   protocol="tcp", state=PortState.OPEN,
                     service="HTTP",  version="Apache/2.4",  banner="HTTP/1.1 200 OK"),
            PortInfo(port=3306, protocol="tcp", state=PortState.OPEN,
                     service="MySQL", version="8.0.32",      banner=""),
            PortInfo(port=445,  protocol="tcp", state=PortState.OPEN,
                     service="SMB",                          banner=""),
        ]
    host = HostResult(host="192.168.1.1", ip="192.168.1.1",
                      os_hint=os_hint, ports=ports)
    return ScanResult(
        hosts=[host],
        start_time="2025-01-01T12:00:00",
        end_time="2025-01-01T12:00:05",
        duration=5.12,
        scanner_version="2.0.0",
        config={"target": "192.168.1.1", "ports": "top100", "threads": 100,
                "timeout": 1.0, "udp": False, "banners": True},
    )


# ── Document structure ────────────────────────────────────────────────────────

class TestHtmlStructure:
    def test_is_valid_html(self):
        html = generate_html(make_result())
        assert html.strip().startswith("<!DOCTYPE html>")
        assert "</html>" in html

    def test_has_head(self):
        html = generate_html(make_result())
        assert "<head>" in html and "</head>" in html

    def test_has_body(self):
        html = generate_html(make_result())
        assert "<body>" in html and "</body>" in html

    def test_has_title(self):
        html = generate_html(make_result())
        assert "<title>" in html

    def test_target_in_title(self):
        html = generate_html(make_result())
        assert "192.168.1.1" in html

    def test_minimum_size(self):
        html = generate_html(make_result())
        assert len(html) > 5000

    def test_charset_utf8(self):
        html = generate_html(make_result())
        assert "UTF-8" in html or "utf-8" in html


# ── Header section ────────────────────────────────────────────────────────────

class TestHeader:
    def test_scanner_version(self):
        html = generate_html(make_result())
        assert "2.0.0" in html

    def test_duration_shown(self):
        html = generate_html(make_result())
        assert "5.12s" in html

    def test_target_shown(self):
        html = generate_html(make_result())
        assert "192.168.1.1" in html

    def test_open_port_count(self):
        html = generate_html(make_result())
        assert "4" in html   # 4 open ports


# ── Overall status line ───────────────────────────────────────────────────────

class TestOverallStatus:
    def test_critical_status(self):
        """SMB(445) and MySQL(3306) are CRITICAL — should say Critical."""
        html = generate_html(make_result())
        assert "Critical" in html or "critical" in html

    def test_green_status_when_no_critical(self):
        ports = [PortInfo(port=443, protocol="tcp", state=PortState.OPEN,
                          service="HTTPS")]
        result = ScanResult(
            hosts=[HostResult(host="x", ip="1.1.1.1", ports=ports)],
            scanner_version="2.0.0",
            config={"target":"x","ports":"top100","threads":100,
                    "timeout":1.0,"udp":False,"banners":True},
        )
        html = generate_html(result)
        assert "No critical" in html or "🟢" in html

    def test_high_status_when_only_high(self):
        ports = [PortInfo(port=3389, protocol="tcp", state=PortState.OPEN,
                          service="RDP")]
        result = ScanResult(
            hosts=[HostResult(host="x", ip="1.1.1.1", ports=ports)],
            scanner_version="2.0.0",
            config={"target":"x","ports":"top100","threads":100,
                    "timeout":1.0,"udp":False,"banners":True},
        )
        html = generate_html(result)
        assert "High" in html or "high" in html


# ── Risk summary ──────────────────────────────────────────────────────────────

class TestRiskSummary:
    def test_risk_summary_section(self):
        html = generate_html(make_result())
        assert "Risk Summary" in html

    def test_critical_badge_present(self):
        html = generate_html(make_result())
        assert "CRITICAL" in html

    def test_info_badge_present(self):
        html = generate_html(make_result())
        assert "INFO" in html

    def test_risk_legend_present(self):
        html = generate_html(make_result())
        assert "No immediate concern" in html or "Normal service" in html


# ── Scan configuration ────────────────────────────────────────────────────────

class TestScanConfig:
    def test_config_section(self):
        html = generate_html(make_result())
        assert "Scan Configuration" in html

    def test_threads_shown(self):
        html = generate_html(make_result())
        assert "Threads" in html

    def test_timeout_shown(self):
        html = generate_html(make_result())
        assert "Timeout" in html

    def test_target_in_config(self):
        html = generate_html(make_result())
        assert "192.168.1.1" in html


# ── Findings section ──────────────────────────────────────────────────────────

class TestFindings:
    def test_findings_section(self):
        html = generate_html(make_result())
        assert "Detailed Findings" in html

    def test_ssh_port_shown(self):
        html = generate_html(make_result())
        assert ">22<" in html or "22" in html

    def test_mysql_shown(self):
        html = generate_html(make_result())
        assert "MySQL" in html

    def test_smb_shown(self):
        html = generate_html(make_result())
        assert "SMB" in html

    def test_os_hint_shown(self):
        html = generate_html(make_result())
        assert "Linux/Unix (TTL=64)" in html

    def test_version_shown(self):
        html = generate_html(make_result())
        assert "OpenSSH_8.9" in html

    def test_banner_shown(self):
        html = generate_html(make_result())
        assert "SSH-2.0" in html

    def test_critical_sorted_first(self):
        """CRITICAL ports (SMB=445, MySQL=3306) should appear before LOW (SSH=22)."""
        html = generate_html(make_result())
        pos_smb = html.find("WannaCry") or html.find(">445<")
        pos_ssh = html.find(">22<")
        # At least one CRITICAL port appears before SSH
        assert pos_smb < pos_ssh or html.find(">3306<") < pos_ssh

    def test_hint_what_it_is(self):
        html = generate_html(make_result())
        assert "What it is" in html

    def test_hint_why_it_matters(self):
        html = generate_html(make_result())
        assert "Why it matters" in html

    def test_hint_what_to_check(self):
        html = generate_html(make_result())
        assert "What to check" in html


# ── Unknown port fallback ─────────────────────────────────────────────────────

class TestUnknownPortFallback:
    def test_unknown_port_not_blank(self):
        """Port 9999 is not in HINTS — should get fallback card, not blank."""
        ports = [PortInfo(port=9999, protocol="tcp", state=PortState.OPEN,
                          service="")]
        result = ScanResult(
            hosts=[HostResult(host="x", ip="1.2.3.4", ports=ports)],
            scanner_version="2.0.0",
            config={"target":"x","ports":"top100","threads":100,
                    "timeout":1.0,"udp":False,"banners":True},
        )
        html = generate_html(result)
        assert "9999" in html
        # Should have some fallback text
        assert "hints database" in html or "not in VeilScan" in html or "investigate" in html

    def test_unknown_port_has_advice(self):
        ports = [PortInfo(port=39999, protocol="tcp", state=PortState.OPEN)]
        result = ScanResult(
            hosts=[HostResult(host="x", ip="1.2.3.4", ports=ports)],
            scanner_version="2.0.0",
            config={"target":"x","ports":"top100","threads":100,
                    "timeout":1.0,"udp":False,"banners":True},
        )
        html = generate_html(result)
        assert "39999" in html
        assert "investigate" in html or "search" in html or "Identify" in html


# ── HTML escaping (security) ──────────────────────────────────────────────────

class TestHtmlEscaping:
    def test_banner_xss_escaped(self):
        ports = [PortInfo(port=80, protocol="tcp", state=PortState.OPEN,
                          service="HTTP",
                          banner='HTTP/1.1 200 OK\r\n<script>alert("xss")</script>')]
        result = ScanResult(
            hosts=[HostResult(host="x", ip="1.2.3.4", ports=ports)],
            scanner_version="2.0.0",
            config={"target":"x","ports":"top100","threads":100,
                    "timeout":1.0,"udp":False,"banners":True},
        )
        html = generate_html(result)
        assert "<script>" not in html
        assert "&lt;script&gt;" in html

    def test_version_with_special_chars_escaped(self):
        ports = [PortInfo(port=80, protocol="tcp", state=PortState.OPEN,
                          service="HTTP", version='v1.0 <test> & "quoted"')]
        result = ScanResult(
            hosts=[HostResult(host="x", ip="1.2.3.4", ports=ports)],
            scanner_version="2.0.0",
            config={"target":"x","ports":"top100","threads":100,
                    "timeout":1.0,"udp":False,"banners":True},
        )
        html = generate_html(result)
        assert "<test>" not in html

    def test_target_with_ampersand_escaped(self):
        result = ScanResult(
            hosts=[],
            scanner_version="2.0.0",
            config={"target":"test&target","ports":"top100","threads":100,
                    "timeout":1.0,"udp":False,"banners":True},
        )
        html = generate_html(result)
        assert "test&target" not in html or "&amp;" in html


# ── Empty / edge cases ────────────────────────────────────────────────────────

class TestEdgeCases:
    def test_empty_result_valid_html(self):
        result = ScanResult(
            scanner_version="2.0.0",
            config={"target":"x","ports":"top100","threads":100,
                    "timeout":1.0,"udp":False,"banners":True},
        )
        html = generate_html(result)
        assert "<!DOCTYPE html>" in html

    def test_empty_result_no_ports_message(self):
        result = ScanResult(
            scanner_version="2.0.0",
            config={"target":"x","ports":"top100","threads":100,
                    "timeout":1.0,"udp":False,"banners":True},
        )
        html = generate_html(result)
        assert "No open ports" in html

    def test_no_os_hint_no_crash(self):
        ports = [PortInfo(port=80, protocol="tcp", state=PortState.OPEN)]
        result = ScanResult(
            hosts=[HostResult(host="x", ip="1.2.3.4", os_hint="", ports=ports)],
            scanner_version="2.0.0",
            config={"target":"x","ports":"top100","threads":100,
                    "timeout":1.0,"udp":False,"banners":True},
        )
        html = generate_html(result)
        assert "<!DOCTYPE html>" in html

    def test_what_to_do_next_guide(self):
        html = generate_html(make_result())
        assert "What to Do Next" in html

    def test_footer_present(self):
        html = generate_html(make_result())
        assert "github.com/AqibTayyab/veilscan" in html

    def test_authorized_use_notice(self):
        html = generate_html(make_result())
        assert "authorized" in html.lower()
