#!/usr/bin/env python3
"""
health-dashboard-html.py — render docs/HEALTH_DASHBOARD.html

Single static HTML file: health stamp, summary cards, freshness SVG chart,
coverage table, cross-links. Pure stdlib, offline-only.

If a source report is missing it falls back to "N/A" and warns on stderr;
never crashes. Exit 0 unconditionally.
"""
from __future__ import annotations
import html, json, re, subprocess, sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
OUT = DOCS / "HEALTH_DASHBOARD.html"
WARN = lambda m: print(f"[health-dashboard-html] WARN: {m}", file=sys.stderr)


# ─── collectors ──────────────────────────────────────────────────────────────

def collect_parity() -> dict:
    try:
        r = subprocess.run(
            ["python3", str(ROOT / "tools" / "parity-report.py"), "--json"],
            cwd=ROOT, capture_output=True, text=True, timeout=60,
        )
        if r.returncode == 0 and r.stdout.strip():
            return json.loads(r.stdout)
    except Exception as e:
        WARN(f"parity-report failed: {e}")
    md = DOCS / "R94_PARITY_REPORT.md"
    if md.exists():
        t = md.read_text()
        g = lambda rx: (re.search(rx, t) or [None, None])[1]
        try:
            return {
                "solidity_total": int(g(r"Solidity active patterns:\*\*\s*(\d+)") or 0),
                "rust_total":     int(g(r"Rust active detectors:\*\*\s*(\d+)") or 0),
                "parity_pct_bidirectional": float(g(r"Bidirectional parity:\*\*\s*\*\*([\d.]+)%") or 0),
            }
        except Exception as e:
            WARN(f"parity md parse failed: {e}")
    return {}


def collect_freshness() -> dict:
    f = DOCS / "PATTERN_FRESHNESS_AUDIT.md"
    if not f.exists():
        return {}
    t = f.read_text()
    counts: dict[str, tuple[str, int]] = {}
    for m in re.finditer(r"\|\s*(H\d)\s*\|\s*([^|]+?)\s*\|\s*(\d+)\s*\|", t):
        counts[m.group(1)] = (m.group(2).strip(), int(m.group(3)))
    total = (re.search(r"Patterns scanned:\*\*\s*(\d+)", t) or [None, 0])[1]
    return {"heuristics": counts, "total": int(total or 0)}


def collect_coverage() -> list[tuple[str, int, int, str]]:
    f = DOCS / "DETECTOR_COVERAGE_MATRIX.md"
    if not f.exists():
        return []
    rows: list[tuple[str, int, int, str]] = []
    in_tbl = False
    for line in f.read_text().splitlines():
        if line.startswith("| topic "):
            in_tbl = True; continue
        if in_tbl and line.startswith("|---"):
            continue
        if in_tbl:
            if not line.startswith("|"):
                break
            cells = [c.strip() for c in line.split("|")[1:-1]]
            if len(cells) >= 4:
                try:
                    rows.append((cells[0], int(cells[1]), int(cells[2]), cells[3]))
                except ValueError:
                    pass
    return rows


def collect_tests() -> tuple[int, int]:
    try:
        r = subprocess.run(["make", "test"], cwd=ROOT,
                           capture_output=True, text=True, timeout=300)
        m = re.search(r"(\d+)\s*/\s*(\d+)\s*passed", r.stdout + r.stderr)
        if m:
            return int(m.group(1)), int(m.group(2))
    except Exception as e:
        WARN(f"make test failed: {e}")
    return 0, 0


def collect_compile() -> int:
    try:
        r = subprocess.run(["make", "compile"], cwd=ROOT,
                           capture_output=True, text=True, timeout=300)
        m = re.search(r"compiled\s+(\d+)\s+patterns", r.stdout + r.stderr)
        if m:
            return int(m.group(1))
    except Exception as e:
        WARN(f"make compile failed: {e}")
    return 0


def collect_skill_issues() -> tuple[int, int]:
    f = ROOT / "SKILL_ISSUES.md"
    if not f.exists():
        return 0, 0
    t = f.read_text()
    done = len(re.findall(r"Status:\*\*\s*DONE", t, re.I))
    open_ = len(re.findall(r"Status:\*\*\s*(open|in progress)", t, re.I))
    return open_, done


# ─── render helpers ──────────────────────────────────────────────────────────

def svg_bars(counts: dict, total: int) -> str:
    if not counts:
        return "<p><em>N/A — PATTERN_FRESHNESS_AUDIT.md missing</em></p>"
    items = sorted(counts.items())
    W, H, pad, bw, gap = 640, 220, 40, 60, 20
    maxv = max((cnt for _, (_d, cnt) in items), default=1) or 1
    out = [f'<svg viewBox="0 0 {W} {H}" role="img" aria-label="freshness bars">']
    out.append(f'<rect width="{W}" height="{H}" fill="#fafafa" stroke="#ccc"/>')
    for i, (hid, (desc, cnt)) in enumerate(items):
        x = pad + i * (bw + gap)
        bh = int((H - 60) * cnt / maxv)
        y = H - 30 - bh
        color = "#d9534f" if cnt > total * 0.2 else "#f0ad4e" if cnt > 0 else "#5cb85c"
        tip = html.escape(f"{hid}: {desc} = {cnt}")
        out.append(f'<rect x="{x}" y="{y}" width="{bw}" height="{bh}" '
                   f'fill="{color}"><title>{tip}</title></rect>')
        out.append(f'<text x="{x+bw/2}" y="{H-10}" text-anchor="middle" '
                   f'font-size="12" font-family="monospace">{hid}</text>')
        out.append(f'<text x="{x+bw/2}" y="{y-4}" text-anchor="middle" '
                   f'font-size="11" font-family="monospace">{cnt}</text>')
    out.append("</svg>")
    return "\n".join(out)


def card(label: str, value: str, sub: str = "", color: str = "#333") -> str:
    return (f'<div class="card"><div class="lbl">{html.escape(label)}</div>'
            f'<div class="val" style="color:{color}">{html.escape(value)}</div>'
            f'<div class="sub">{html.escape(sub)}</div></div>')


def stamp(test_pct: float, parity_pct: float, open_issues: int) -> tuple[str, str]:
    if test_pct >= 99 and parity_pct >= 99 and open_issues <= 5:
        return "GREEN", "#5cb85c"
    if test_pct >= 90 and parity_pct >= 90:
        return "YELLOW", "#f0ad4e"
    return "RED", "#d9534f"


# ─── render ──────────────────────────────────────────────────────────────────

def render() -> str:
    parity = collect_parity()
    fresh = collect_freshness()
    cov = collect_coverage()
    t_pass, t_total = collect_tests()
    compiled = collect_compile()
    open_issues, done_issues = collect_skill_issues()

    test_pct = (100.0 * t_pass / t_total) if t_total else 0.0
    parity_pct = float(parity.get("parity_pct_bidirectional") or 0)
    wave17 = parity.get("solidity_total") or compiled or 0
    rust_w1 = parity.get("rust_total") or 0
    level, color = stamp(test_pct, parity_pct, open_issues)

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    cards = "\n".join([
        card("tests", f"{t_pass}/{t_total}" if t_total else "N/A",
             f"{test_pct:.1f}%" if t_total else "missing",
             "#5cb85c" if test_pct >= 99 else "#d9534f"),
        card("parity", f"{parity_pct:.1f}%" if parity else "N/A",
             "bidirectional", "#5cb85c" if parity_pct >= 99 else "#f0ad4e"),
        card("wave17", str(wave17) if wave17 else "N/A", "sol patterns"),
        card("rust_wave1", str(rust_w1) if rust_w1 else "N/A", "detectors"),
        card("skill issues", f"{open_issues} open",
             f"{done_issues} done",
             "#5cb85c" if open_issues <= 5 else "#f0ad4e"),
        card("compiled", str(compiled) if compiled else "N/A", "patterns"),
    ])

    if cov:
        cov_sorted = sorted(cov, key=lambda r: -(r[1] + r[2]))[:10]
        rows = "\n".join(
            f"<tr><td>{html.escape(t)}</td><td>{r}</td><td>{s}</td>"
            f"<td>{html.escape(st)}</td></tr>"
            for t, r, s, st in cov_sorted)
        cov_html = (
            "<table><thead><tr><th>topic</th><th>rust</th><th>sol</th>"
            "<th>status</th></tr></thead><tbody>" + rows + "</tbody></table>"
        )
    else:
        cov_html = "<p><em>N/A — DETECTOR_COVERAGE_MATRIX.md missing</em></p>"

    fresh_svg = svg_bars(fresh.get("heuristics", {}), fresh.get("total", 0))

    links = [
        ("R94_PARITY_REPORT.md", DOCS / "R94_PARITY_REPORT.md"),
        ("PATTERN_FRESHNESS_AUDIT.md", DOCS / "PATTERN_FRESHNESS_AUDIT.md"),
        ("DETECTOR_COVERAGE_MATRIX.md", DOCS / "DETECTOR_COVERAGE_MATRIX.md"),
        ("SKILL_ISSUES.md", ROOT / "SKILL_ISSUES.md"),
        ("SKILL_ISSUES_STATUS.md", DOCS / "SKILL_ISSUES_STATUS.md"),
    ]
    def _href(p: Path) -> str:
        # HTML lives in docs/, so use relative path from docs/
        try:
            return str(p.relative_to(DOCS))
        except ValueError:
            return "../" + str(p.relative_to(ROOT))

    link_html = " · ".join(
        (f'<a href="{html.escape(_href(p))}">{html.escape(n)}</a>'
         if p.exists() else f'<span class="dim">{html.escape(n)}</span>')
        for n, p in links
    )

    css = """
      body{font-family:-apple-system,system-ui,sans-serif;margin:24px;color:#222;background:#fff;}
      h1{margin:0 0 4px 0;}
      .stamp{display:inline-block;padding:6px 14px;border-radius:6px;color:#fff;font-weight:700;font-size:18px;}
      .meta{color:#666;font-size:13px;margin-bottom:18px;}
      .cards{display:flex;flex-wrap:wrap;gap:12px;margin:12px 0 24px 0;}
      .card{flex:1 1 140px;min-width:140px;padding:12px 14px;border:1px solid #ddd;border-radius:8px;background:#fafafa;}
      .card .lbl{font-size:11px;text-transform:uppercase;color:#888;letter-spacing:.05em;}
      .card .val{font-size:26px;font-weight:700;margin:4px 0;}
      .card .sub{font-size:11px;color:#888;}
      h2{border-bottom:1px solid #eee;padding-bottom:4px;margin-top:28px;}
      table{border-collapse:collapse;margin-top:8px;}
      th,td{border:1px solid #ddd;padding:6px 10px;text-align:left;font-size:13px;}
      th{background:#f0f0f0;}
      .links{margin:18px 0;font-size:13px;}
      .links a{color:#06c;text-decoration:none;} .links a:hover{text-decoration:underline;}
      .dim{color:#bbb;}
      svg{max-width:100%;height:auto;}
    """

    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>auditooor — health dashboard</title><style>{css}</style></head><body>
<h1>auditooor — health dashboard</h1>
<div class="meta">Generated {ts} · overall
 <span class="stamp" style="background:{color}">{level}</span></div>
<div class="cards">{cards}</div>
<h2>Source reports</h2><div class="links">{link_html}</div>
<h2>Freshness heuristics (H1–H6)</h2>{fresh_svg}
<h2>Coverage matrix — top 10 topics</h2>{cov_html}
<p class="meta">Generated by <code>tools/health-dashboard-html.py</code> · Phase 30 · PR #84</p>
</body></html>"""


def main() -> int:
    try:
        DOCS.mkdir(parents=True, exist_ok=True)
        OUT.write_text(render())
        print(f"[health-dashboard-html] wrote {OUT}")
    except Exception as e:
        WARN(f"render failed: {e}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
