"""
veilscan/html_reporter.py
=========================
Generates a beginner-friendly standalone HTML security report.

Opens in any web browser — no server, no internet required.

Features
--------
- Dark theme, color-coded risk cards
- Plain English explanation for every open port
- CRITICAL findings sorted to the top
- Generic fallback card for ports not in vuln_hints database
- Proper HTML escaping for banner content (security fix)
- OS hint displayed per host in findings section
- "What to do next" guide for beginners
- Scan configuration table for audit trail

Fixes over previous version
----------------------------
1. Blank cards for unknown ports
   Previous: ports not in HINTS got an empty card — no explanation.
   Fixed: generic fallback text explains what the port is and
   encourages the user to investigate what service is running.

2. HTML injection in banner content
   Previous: banner text inserted into HTML with only < and > replaced.
   Quotes and & could break HTML structure.
   Fixed: html.escape() applied to all user-derived content.

3. OS hint shown in findings
   Previous: OS hint only in host header box, not in findings section.
   Fixed: OS hint displayed prominently in each host's findings card.

Public API
----------
    from veilscan.html_reporter import generate_html
    html = generate_html(result)        # returns complete HTML string
    with open("report.html", "w") as f: f.write(html)
"""

from __future__ import annotations

import datetime
import html as _html
from veilscan.models import ScanResult
from veilscan.vuln_hints import (
    HINTS, RISK_COLORS, RISK_ICONS,
    get_risk, risk_sort_key,
)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _esc(text: str) -> str:
    """HTML-escape user-derived content (banners, version strings, etc.)."""
    return _html.escape(str(text), quote=True)


def _risk_badge(risk: str) -> str:
    """Return an inline HTML risk badge span."""
    c    = RISK_COLORS.get(risk, RISK_COLORS["INFO"])
    icon = RISK_ICONS.get(risk, "")
    return (
        f'<span style="background:{c["badge"]};color:#fff;'
        f'padding:3px 12px;border-radius:12px;font-size:12px;'
        f'font-weight:700;letter-spacing:.4px;white-space:nowrap;">'
        f'{icon} {risk}</span>'
    )


# ─── Port Card Builder ────────────────────────────────────────────────────────

def _port_card(port_info, host) -> str:
    """
    Build the HTML card for a single open port.

    Structure
    ---------
    ┌─ Header bar ──────────────────────────────────────────────────┐
    │  PORT   PROTO   Service Name   Version   [RISK BADGE]         │
    ├─ Banner (if any) ─────────────────────────────────────────────┤
    │  Raw service banner in monospace                              │
    ├─ Explanation ─────────────────────────────────────────────────┤
    │  What it is / Why it matters / What to check / Tip            │
    └───────────────────────────────────────────────────────────────┘

    For ports not in the HINTS database, a generic fallback is shown
    instead of a blank card.
    """
    p    = port_info
    hint = HINTS.get(p.port)
    risk = hint.risk if hint else "INFO"
    c    = RISK_COLORS.get(risk, RISK_COLORS["INFO"])

    # Service display name
    service_display = hint.service if hint else (p.service or f"Port {p.port}")

    # Version string
    ver_html = ""
    if p.version:
        ver_html = (
            f'<span style="color:#888;font-size:13px;margin-left:8px;">'
            f'{_esc(p.version)}</span>'
        )

    # Banner block
    banner_html = ""
    if p.banner:
        short = _esc(p.banner[:150])
        banner_html = (
            f'<div style="margin:0;padding:8px 16px;'
            f'background:#0d1117;font-family:monospace;font-size:12px;'
            f'color:#86efac;white-space:pre-wrap;word-break:break-all;'
            f'border-bottom:1px solid {c["border"]}20;">'
            f'{short}</div>'
        )

    # Explanation content
    if hint:
        explanation_html = f"""
        <div style="padding:14px 18px;font-size:14px;line-height:1.8;color:#444;">
          <p style="margin:0 0 8px;">
            <strong>What it is:</strong> {_esc(hint.what)}
          </p>
          <p style="margin:0 0 8px;">
            <strong>Why it matters:</strong> {_esc(hint.why)}
          </p>
          <p style="margin:0 0 8px;">
            <strong>What to check:</strong> {_esc(hint.check)}
          </p>
          <p style="margin:0;color:#666;font-style:italic;font-size:13px;">
            💡 {_esc(hint.learn)}
          </p>
        </div>"""
    else:
        # Generic fallback for ports not in database
        explanation_html = f"""
        <div style="padding:14px 18px;font-size:14px;line-height:1.8;color:#555;">
          <p style="margin:0 0 8px;">
            <strong>What it is:</strong>
            Port {p.port}/{p.protocol.upper()} is open
            {"and running " + _esc(p.service) if p.service else ""}.
            This port is not in VeilScan's hints database.
          </p>
          <p style="margin:0 0 8px;">
            <strong>What to check:</strong>
            Identify what service is running on this port.
            Verify it is supposed to be publicly accessible.
            If unexpected, investigate why it is open.
          </p>
          <p style="margin:0;color:#666;font-style:italic;font-size:13px;">
            💡 Search online for "port {p.port} security" to learn
            about this service and known risks.
          </p>
        </div>"""

    return f"""
    <div style="border:1.5px solid {c['border']};border-radius:8px;
                background:{c['bg']};margin-bottom:18px;overflow:hidden;">
      <div style="padding:12px 18px;display:flex;align-items:center;
                  gap:12px;flex-wrap:wrap;
                  border-bottom:1px solid {c['border']}30;">
        <span style="font-size:22px;font-weight:700;color:{c['text']};
                     min-width:55px;">{p.port}</span>
        <span style="font-size:12px;color:#888;font-weight:600;
                     text-transform:uppercase;">{_esc(p.protocol)}</span>
        <span style="font-weight:600;color:{c['text']};flex:1;font-size:14px;">
          {_esc(service_display)}
        </span>
        {ver_html}
        {_risk_badge(risk)}
      </div>
      {banner_html}
      {explanation_html}
    </div>"""


# ─── Main Generator ───────────────────────────────────────────────────────────

def generate_html(result: ScanResult) -> str:
    """
    Generate a complete standalone HTML security report.

    Parameters
    ----------
    result: ScanResult from Scanner.scan()

    Returns
    -------
    Complete HTML document as a string.
    Write to a .html file and open in any browser.
    """
    now        = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total_open = result.total_open_ports
    target     = _esc(result.config.get("target", "Unknown"))

    # ── Risk summary counts ───────────────────────────────────────────────────
    risk_counts: dict[str, int] = {
        "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0,
    }
    for host in result.hosts:
        for p in host.open_ports:
            r = get_risk(p.port)
            risk_counts[r] = risk_counts.get(r, 0) + 1

    # ── Overall status line ───────────────────────────────────────────────────
    if risk_counts["CRITICAL"] > 0:
        overall = "🔴 Critical findings detected — immediate attention required."
        overall_color = "#c0392b"
    elif risk_counts["HIGH"] > 0:
        overall = "🟠 High-risk services found — review carefully."
        overall_color = "#d35400"
    elif risk_counts["MEDIUM"] > 0:
        overall = "🟡 Medium-risk items found — worth investigating."
        overall_color = "#d4ac0d"
    else:
        overall = "🟢 No critical findings. Good baseline security posture."
        overall_color = "#1e8449"

    # ── Risk summary pills ────────────────────────────────────────────────────
    summary_pills = ""
    for risk in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = risk_counts.get(risk, 0)
        if count > 0:
            c = RISK_COLORS[risk]
            summary_pills += f"""
            <div style="text-align:center;padding:14px 20px;
                        background:{c['bg']};border:1.5px solid {c['border']};
                        border-radius:8px;min-width:80px;">
              <div style="font-size:30px;font-weight:700;color:{c['text']};">
                {count}
              </div>
              <div style="font-size:12px;font-weight:700;color:{c['badge']};
                          letter-spacing:.4px;margin-top:2px;">{risk}</div>
            </div>"""

    # ── Risk legend ───────────────────────────────────────────────────────────
    legend = ""
    for risk, label in [
        ("INFO",     "Normal service — no immediate concern"),
        ("LOW",      "Low risk when properly configured"),
        ("MEDIUM",   "Could be a problem if misconfigured"),
        ("HIGH",     "Commonly targeted — review carefully"),
        ("CRITICAL", "Serious exposure — act immediately"),
    ]:
        c = RISK_COLORS[risk]
        legend += f"""
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:7px;">
          <span style="background:{c['badge']};color:#fff;padding:2px 10px;
                       border-radius:10px;font-size:11px;font-weight:700;
                       min-width:72px;text-align:center;">{risk}</span>
          <span style="font-size:13px;color:#555;">{label}</span>
        </div>"""

    # ── Config table ──────────────────────────────────────────────────────────
    def cfg_item(label: str, value: str) -> str:
        return f"""
        <div style="background:#f8f9fa;border-radius:6px;padding:10px 14px;">
          <div style="font-size:11px;color:#999;text-transform:uppercase;
                      letter-spacing:.5px;margin-bottom:3px;">{label}</div>
          <div style="font-size:14px;font-weight:600;color:#333;">{value}</div>
        </div>"""

    cfg = result.config
    config_grid = "".join([
        cfg_item("Target",         _esc(cfg.get("target", "—"))),
        cfg_item("Ports Scanned",  _esc(str(cfg.get("ports", "—")))),
        cfg_item("Threads",        _esc(str(cfg.get("threads", "—")))),
        cfg_item("Timeout",        f"{cfg.get('timeout', '—')}s"),
        cfg_item("UDP Scan",       "Yes" if cfg.get("udp") else "No"),
        cfg_item("Banner Grabbing","Yes" if cfg.get("banners", True) else "No"),
        cfg_item("Hosts Scanned",  str(len(result.hosts))),
        cfg_item("Open Ports",     str(total_open)),
    ])

    # ── Detailed findings per host ────────────────────────────────────────────
    findings_html = ""
    for host in result.hosts:
        if not host.open_ports:
            continue

        # Sort by risk (CRITICAL first), then by port number
        sorted_ports = sorted(
            host.open_ports,
            key=lambda p: (-risk_sort_key(get_risk(p.port)), p.port),
        )

        port_cards = "".join(_port_card(p, host) for p in sorted_ports)

        os_line = (
            f'<span style="color:#888;font-size:13px;"> &nbsp;·&nbsp; '
            f'OS Hint: {_esc(host.os_hint)}</span>'
            if host.os_hint else ""
        )

        findings_html += f"""
        <div style="margin-bottom:40px;">
          <h2 style="font-size:18px;margin:0 0 4px;color:#1a1a2e;">
            🖥️ {_esc(host.host)}
            <span style="font-size:14px;font-weight:400;color:#888;">
              ({_esc(host.ip)})
            </span>
            {os_line}
          </h2>
          <p style="color:#888;font-size:13px;margin:0 0 18px;">
            {len(host.open_ports)} open port(s) found
          </p>
          {port_cards}
        </div>"""

    if not findings_html:
        findings_html = (
            '<p style="color:#888;text-align:center;padding:30px;">'
            'No open ports found.</p>'
        )

    # ── Assemble full document ────────────────────────────────────────────────
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>VeilScan Report — {target}</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI',
                   Roboto, sans-serif;
      background: #f0f2f5;
      color: #1a1a2e;
      line-height: 1.6;
    }}
    .container {{ max-width: 920px; margin: 0 auto; padding: 30px 20px; }}
    .card {{
      background: #fff;
      border-radius: 12px;
      padding: 28px;
      box-shadow: 0 2px 12px rgba(0,0,0,.07);
      margin-bottom: 24px;
    }}
    h1 {{ font-size: 26px; font-weight: 700; }}
    .section-title {{
      font-size: 15px;
      font-weight: 700;
      color: #444;
      margin-bottom: 18px;
      padding-bottom: 10px;
      border-bottom: 2px solid #f0f0f0;
    }}
    .overall {{
      font-size: 15px;
      font-weight: 600;
      padding: 14px 18px;
      border-radius: 8px;
      margin-top: 16px;
      background: {overall_color}15;
      color: {overall_color};
      border-left: 4px solid {overall_color};
    }}
    .summary-grid {{
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
      margin-bottom: 20px;
    }}
    .config-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
      gap: 10px;
    }}
    footer {{
      text-align: center;
      color: #aaa;
      font-size: 12px;
      padding: 24px 0 8px;
    }}
    @media print {{
      body {{ background: #fff; }}
      .card {{ box-shadow: none; border: 1px solid #ddd; }}
    }}
  </style>
</head>
<body>
<div class="container">

  <!-- Header -->
  <div class="card">
    <div style="display:flex;align-items:flex-start;
                justify-content:space-between;flex-wrap:wrap;gap:12px;">
      <div>
        <h1>🔍 VeilScan Security Report</h1>
        <div style="color:#888;font-size:13px;margin-top:6px;">
          Generated: {now} &nbsp;·&nbsp;
          Target: <strong>{target}</strong> &nbsp;·&nbsp;
          Duration: {result.duration:.2f}s &nbsp;·&nbsp;
          VeilScan v{_esc(result.scanner_version)}
        </div>
      </div>
      <div style="text-align:right;">
        <div style="font-size:36px;font-weight:700;color:#1a1a2e;">
          {total_open}
        </div>
        <div style="font-size:12px;color:#888;">open ports found</div>
      </div>
    </div>
    <div class="overall">{overall}</div>
  </div>

  <!-- Risk Summary -->
  <div class="card">
    <div class="section-title">Risk Summary</div>
    <div class="summary-grid">{summary_pills}</div>
    {legend}
    <div style="margin-top:18px;padding:12px 16px;background:#fffbf0;
                border-radius:6px;border-left:3px solid #d4ac0d;
                font-size:13px;color:#7d6608;">
      ⚠ <strong>Important:</strong>
      Risk levels indicate misconfiguration risk — not confirmed vulnerabilities.
      Always verify findings before taking action.
      Only scan systems you own or have written permission to test.
    </div>
  </div>

  <!-- Scan Configuration -->
  <div class="card">
    <div class="section-title">Scan Configuration</div>
    <div class="config-grid">{config_grid}</div>
  </div>

  <!-- Detailed Findings -->
  <div class="card">
    <div class="section-title">Detailed Findings</div>
    {findings_html}
  </div>

  <!-- What to do next -->
  <div class="card">
    <div class="section-title">What to Do Next — Beginner Guide</div>
    <div style="font-size:14px;line-height:1.9;color:#444;">
      <p style="margin-bottom:12px;">
        <strong>1. Start with CRITICAL and HIGH</strong> —
        these need immediate attention. Close or secure those
        services before looking at anything else.
      </p>
      <p style="margin-bottom:12px;">
        <strong>2. Check service versions</strong> —
        old versions often have known vulnerabilities. Search the
        version string (e.g. "Apache/2.2.8 CVE") to find patches.
      </p>
      <p style="margin-bottom:12px;">
        <strong>3. Firewall what isn't needed</strong> —
        if a port doesn't need to be public, block it at the firewall.
        Fewer open ports = smaller attack surface.
      </p>
      <p style="margin-bottom:12px;">
        <strong>4. Replace insecure protocols</strong> —
        Telnet → SSH, FTP → SFTP, HTTP → HTTPS.
        These are direct swaps that eliminate entire risk categories.
      </p>
      <p style="margin-bottom:0;">
        <strong>5. Re-scan after making changes</strong> —
        use VeilScan again to verify that changes actually took effect.
      </p>
    </div>
  </div>

  <footer>
    VeilScan v{_esc(result.scanner_version)} &nbsp;·&nbsp;
    github.com/AqibTayyab/veilscan &nbsp;·&nbsp;
    For authorized security testing and education only
  </footer>

</div>
</body>
</html>"""
