# Design.md — Visual Design System
# VeilScan v2.0

---

## 1. Design Philosophy

VeilScan has two distinct visual surfaces:
1. **Terminal (CLI)** — colored ASCII art, progress bars, result tables
2. **HTML Report** — browser-based, dark theme, risk cards

Both surfaces share the same design principle: **information density over decoration**. Every visual element serves a purpose — nothing is decorative only.

**Core principle:** A beginner opening the HTML report for the first time should immediately understand what is dangerous (red), what is concerning (orange), and what is safe (green) — without reading a single word.

---

## 2. Terminal Design

### 2.1 ASCII Banner
```
 ██╗   ██╗███████╗██╗██╗     ███████╗ ██████╗ █████╗ ███╗   ██╗
 ██║   ██║██╔════╝██║██║     ██╔════╝██╔════╝██╔══██╗████╗  ██║
 ██║   ██║█████╗  ██║██║     ███████╗██║     ███████║██╔██╗ ██║
 ╚██╗ ██╔╝██╔══╝  ██║██║     ╚════██║██║     ██╔══██║██║╚██╗██║
  ╚████╔╝ ███████╗██║███████╗███████║╚██████╗██║  ██║██║ ╚████║
   ╚═══╝  ╚══════╝╚═╝╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
  Professional Network Intelligence Suite  |  v2.0.0
  github.com/AqibTayyab/veilscan          |  For authorized use only
```

- Font: Block-style box-drawing characters (Unicode box art)
- Color: Cyan (`\033[96m`) on terminals that support ANSI
- Purpose: Immediate brand recognition, professional appearance

### 2.2 Terminal Color Palette

| Color | ANSI Code | Use |
|-------|-----------|-----|
| Cyan `\033[96m` | `_CYAN` | Host box borders, section headers, footer |
| Bold `\033[1m` | `_BOLD` | Column headers, scan complete line |
| Green `\033[92m` | `_GREEN` | OPEN port state |
| Yellow `\033[93m` | `_YELLOW` | OPEN\|FILTERED port state |
| Dim `\033[2m` | `_DIM` | Separator lines, closed ports |
| White `\033[97m` | `_WHITE` | Port numbers |
| Reset `\033[0m` | `_RESET` | After every colored element |

### 2.3 Host Result Box
```
╔══════════════════════════════════════════════════════════╗
║  Host: scanme.nmap.org (45.33.32.156)                    ║
║  OS Hint: Linux/Unix (TTL=48)                            ║
╚══════════════════════════════════════════════════════════╝
```
- Box width: 60 characters fixed
- Unicode box-drawing: ╔ ═ ╗ ║ ╚ ╝
- Color: Cyan
- Shows: hostname, IP, OS hint (when available)

### 2.4 Results Table
```
PORT    PROTO   STATE         SERVICE         VERSION
────────────────────────────────────────────────────────────
22      tcp     OPEN          SSH             OpenSSH_6.6.1p1
80      tcp     OPEN          HTTP            Apache/2.4.7 (Ubuntu)
```
- Column widths: **dynamic** — calculated from content at render time
- Separator: `─` (Unicode, not ASCII `-`)
- STATE colors: OPEN=green, OPEN|FILTERED=yellow, CLOSED=dim
- PORT: white bold
- Version: truncated at 32 chars if longer

### 2.5 Progress Bar
```
  [TCP]     ████████████████████  100/100  100%
  [BANNER]  ████████████████████  2/2  100%
```
- Bar width: 20 characters
- Filled: `█` (U+2588)
- Empty: `░` (U+2591)
- Updates in place with `\r` (carriage return)
- Padded to 72 chars to overwrite longer previous renders
- Written to `stderr` (not stdout — so it doesn't pollute piped output)

### 2.6 Windows Compatibility
- `colorama.init()` called before output on Windows to enable ANSI
- Graceful fallback to plain text if colorama not installed
- Block chars `█░` may show as `?` without colorama — install prompt in README

---

## 3. HTML Report Design

### 3.1 Color System

#### Risk Level Colors
| Level | Background | Border | Text | Badge |
|-------|-----------|--------|------|-------|
| CRITICAL | `#fdedec` | `#c0392b` | `#78281f` | `#c0392b` |
| HIGH | `#fef5e7` | `#d35400` | `#784212` | `#d35400` |
| MEDIUM | `#fef9e7` | `#d4ac0d` | `#7d6608` | `#d4ac0d` |
| LOW | `#eafaf1` | `#1e8449` | `#145a32` | `#1e8449` |
| INFO | `#e8f4fd` | `#1a7abf` | `#0d4a7a` | `#1a7abf` |

**Design rationale:** Light pastel backgrounds with strong colored borders — readable in both light environments and print. Badge uses solid color with white text for maximum contrast.

#### Page Colors
| Element | Color | Hex |
|---------|-------|-----|
| Page background | Light gray | `#f0f2f5` |
| Card background | White | `#ffffff` |
| Primary text | Near-black | `#1a1a2e` |
| Secondary text | Dark gray | `#444444` |
| Muted text | Medium gray | `#888888` |
| Card shadow | Subtle | `rgba(0,0,0,0.07)` |

### 3.2 Typography

| Use | Font | Size | Weight |
|-----|------|------|--------|
| Body | System UI stack | 9.5–14px | 400 |
| Port numbers | System UI | 22px | 700 |
| Section titles | System UI | 15px | 700 |
| Banners | Monospace | 12px | 400 |
| Risk badges | System UI | 12px | 700 |

**Font stack:** `-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif`

This is the native system font on every OS — no external font downloads, instant load, familiar appearance.

**Monospace for banners:** `font-family: monospace` — banners are raw protocol output, must be displayed as-is.

### 3.3 Layout

- **Max width:** 920px centered — comfortable reading width on any screen
- **Container padding:** 30px top/bottom, 20px left/right
- **Card border-radius:** 12px — modern rounded style
- **Card margin-bottom:** 24px — clear visual separation between sections
- **Card box-shadow:** `0 2px 12px rgba(0,0,0,0.07)` — subtle depth

### 3.4 Risk Summary Pills

```
┌─────────────────────────────────────────────┐
│  8         5          3        1       2     │
│ CRITICAL  HIGH     MEDIUM    LOW    INFO     │
│ (red)    (orange)  (yellow)  (green) (blue)  │
└─────────────────────────────────────────────┘
```

- Each pill: 80px min-width, centered number (30px bold), centered label (12px bold)
- Color coded by risk level
- Uses flexbox with `flex-wrap: wrap` for mobile

### 3.5 Port Finding Card

```
┌──────────────────────────────────────────────────────────┐
│  PORT  PROTO  Service Name           Version  [BADGE]    │ ← header bar
├──────────────────────────────────────────────────────────┤
│  > raw banner text in monospace green font               │ ← banner (if any)
├──────────────────────────────────────────────────────────┤
│  What it is: plain English description                   │
│  Why it matters: risk explanation                        │
│  What to check: actionable steps                         │
│  💡 One-line tip                                         │
└──────────────────────────────────────────────────────────┘
```

- Card background: risk-level-specific pastel
- Left border: 1.5px solid risk-level color
- Header: `display: flex` with gap and flex-wrap for responsive
- Banner: dark background (`#0d1117`) with green monospace text (`#86efac`)

### 3.6 Risk Badges (Inline)

```html
<span style="background:#c0392b; color:#fff; 
             padding:3px 12px; border-radius:12px;
             font-size:12px; font-weight:700;">
  🚫 CRITICAL
</span>
```

Icons used:
| Level | Icon | Unicode |
|-------|------|---------|
| INFO | ℹ | `&#9432;` |
| LOW | ✓ | `&#10003;` |
| MEDIUM | ⚠ | `&#9888;` |
| HIGH | ⚠ | `&#9888;` |
| CRITICAL | 🚫 | `&#128683;` |

### 3.7 Overall Status Line

Appears at top of report, left border color matches severity:

```
🔴 Critical findings detected — immediate attention required.
```
or:
```
🟢 No critical findings. Good baseline security posture.
```

- Background: `{color}15` (15% opacity hex)
- Border-left: `4px solid {color}`
- Font: 15px bold, color matches severity

---

## 4. Interactive Wizard Design

```
  ────────────────────────────────────────────────────────
  Welcome to VeilScan v2.0
  ────────────────────────────────────────────────────────

  Enter target IP or domain
  (e.g. 192.168.1.1  or  scanme.nmap.org): _

  Select scan type:
  [1] Quick    — Top 100 ports, fast  (recommended for beginners)
  [2] Standard — Top 1000 ports, balanced
  [3] Full     — All 65535 ports, thorough (slow)
  [4] Stealth  — Quiet, minimal traffic
  [5] Custom   — Choose your own settings

  Choice (1-5, default 1): _
```

**Design principles:**
- 2 leading spaces before every prompt
- 56-dash separator lines
- Default value shown in brackets: `(default 1)`
- Simple numbered menu — no arrow keys or complex input
- Works in any terminal: Windows CMD, PowerShell, bash, zsh

---

## 5. Print Styling

The HTML report includes print CSS:
```css
@media print {
    body { background: #fff; }
    .card { box-shadow: none; border: 1px solid #ddd; }
}
```

Removes shadows and changes background to white for clean printing. Risk cards retain their colored borders in print.

---

## 6. Report Filename Convention

```
reports/scan_{target}_{YYYYMMDD}_{HHMMSS}.html
reports/scan_{target}_{YYYYMMDD}_{HHMMSS}.json
reports/scan_{target}_{YYYYMMDD}_{HHMMSS}.csv
```

Example:
```
reports/scan_192_168_140_130_20260808_033709.html
```

- Dots replaced with underscores for filesystem compatibility
- Slashes replaced with underscores for CIDR targets
- Timestamp ensures no report is ever overwritten
- All 3 formats share the same base name for easy matching
