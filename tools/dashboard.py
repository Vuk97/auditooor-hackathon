#!/usr/bin/env python3
"""
dashboard.py — R73 C2: self-contained HTML dashboard of auditooor skill state.

Pulls data from:
  - reference/stop_criteria_status.md
  - detectors/_hits_ledger.yaml
  - detectors/_tier_registry.yaml
  - SKILL_ISSUES.md (status counts)
  - reference/bug_family_atlas.md (if present)
  - git log for round progression

Output: reference/dashboard.html (single file, inlines minimal CSS)

Usage:
  python3 tools/dashboard.py
  python3 tools/dashboard.py --open   # open in default browser after write

Run on every round close via flow-gate.sh --dashboard.
"""

import os, sys, re, yaml, json, subprocess, datetime, pathlib
from collections import Counter
from typing import Dict

AUDITOOOR_DIR = pathlib.Path(__file__).resolve().parent.parent
LEDGER = AUDITOOOR_DIR / "detectors/_hits_ledger.yaml"
TIER_REG = AUDITOOOR_DIR / "detectors/_tier_registry.yaml"
SKILL_ISSUES = AUDITOOOR_DIR / "SKILL_ISSUES.md"
OUT_HTML = AUDITOOOR_DIR / "reference/dashboard.html"

def load_yaml_safe(p):
    try:
        return yaml.safe_load(p.read_text()) or {}
    except Exception:
        return {}

def git_log_rounds():
    """Extract 'Round N' and 'RNN' prefixes from recent commits."""
    try:
        log = subprocess.check_output(
            ["git", "-C", str(AUDITOOOR_DIR), "log", "--format=%s", "-n", "100"],
            text=True, stderr=subprocess.DEVNULL
        )
    except Exception:
        return []
    rounds = []
    for line in log.splitlines():
        m = re.match(r'^R(\d+)\b|^Round\s+(\d+)\b', line)
        if m:
            n = int(m.group(1) or m.group(2))
            rounds.append(n)
    return sorted(set(rounds), reverse=True)

def ledger_stats():
    led = load_yaml_safe(LEDGER)
    dets = led.get('detectors', led) if isinstance(led, dict) else {}
    total_tp = 0; total_fp = 0; total_unk = 0; paid = 0
    workspaces = Counter()
    tp_by_det = []
    for name, det in (dets or {}).items():
        if not isinstance(det, dict): continue
        tp = det.get('tp', 0) or 0
        fp = det.get('fp', 0) or 0
        unk = det.get('unknown', 0) or 0
        total_tp += tp; total_fp += fp; total_unk += unk
        for h in det.get('_history', []) or []:
            if isinstance(h, dict):
                workspaces[h.get('workspace', '?')] += 1
                if h.get('outcome','').lower() == 'paid':
                    paid += 1
        if tp > 0:
            tp_by_det.append((name, tp, fp))
    tp_by_det.sort(key=lambda x: -x[1])
    return {
        'tp': total_tp, 'fp': total_fp, 'unknown': total_unk,
        'paid': paid, 'workspaces': dict(workspaces),
        'top_detectors': tp_by_det[:10],
        'total_detectors': len(dets or {}),
    }

def tier_stats():
    t = load_yaml_safe(TIER_REG)
    tiers = t.get('detectors', t) if isinstance(t, dict) else {}
    c = Counter()
    for name, det in (tiers or {}).items():
        if isinstance(det, dict):
            c[det.get('tier', '?')] += 1
    return dict(c)

def skill_issues_stats():
    if not SKILL_ISSUES.exists():
        return {'open': 0, 'closed': 0, 'done': 0, 'total': 0}
    txt = SKILL_ISSUES.read_text()
    total = len(re.findall(r'^### Issue \d+:', txt, flags=re.M))
    open_c = len(re.findall(r'Status:\*\*\s*OPEN', txt))
    closed = len(re.findall(r'Status:\*\*\s*CLOSED', txt))
    done = len(re.findall(r'Status:\*\*\s*DONE', txt))
    return {'total': total, 'open': open_c, 'closed': closed, 'done': done}

def count_patterns():
    dsl = AUDITOOOR_DIR / "reference/patterns.dsl"
    if not dsl.exists(): return 0
    return len(list(dsl.glob("*.yaml")))

def count_compiled_detectors():
    wave17 = AUDITOOOR_DIR / "detectors/wave17"
    if not wave17.exists(): return 0
    return len([p for p in wave17.glob("*.py") if not p.name.startswith("__")])

def scan_workspace_submissions(ws: pathlib.Path) -> Dict:
    """Scan a workspace for submission files and return counts by status."""
    subs_dir = ws / "submissions"
    if not subs_dir.exists():
        return {}
    
    # Look for .md files in submissions/ and staging/
    files = list(subs_dir.rglob("*.md")) + list(subs_dir.rglob("*.block.md"))
    
    # Also check for draft files
    drafts_dir = ws / "drafts"
    drafts = list(drafts_dir.rglob("*.md")) if drafts_dir.exists() else []
    
    counts = {"drafts": len(drafts), "submissions": len(files), "by_status": {}}
    for f in files:
        text = f.read_text(errors="ignore").lower()
        if "ready for submission" in text or "status: ready" in text:
            counts["by_status"]["ready"] = counts["by_status"].get("ready", 0) + 1
        elif "submitted" in text:
            counts["by_status"]["submitted"] = counts["by_status"].get("submitted", 0) + 1
        elif "in review" in text or "in_review" in text:
            counts["by_status"]["in_review"] = counts["by_status"].get("in_review", 0) + 1
        elif "accepted" in text or "paid" in text:
            counts["by_status"]["accepted"] = counts["by_status"].get("accepted", 0) + 1
        elif "rejected" in text or "duplicate" in text:
            counts["by_status"]["rejected"] = counts["by_status"].get("rejected", 0) + 1
    return counts

def open_submissions():
    count = 0; workspaces = []
    for ws in pathlib.Path("/Users/wolf/audits").glob("*"):
        state = ws / ".auditooor-state.yaml"
        sub_counts = scan_workspace_submissions(ws)
        
        # Legacy state file support
        if state.exists():
            d = load_yaml_safe(state)
            opens = d.get('open_submissions', []) or []
            if opens:
                count += len(opens)
        
        # New file-based scanning
        total_subs = sub_counts.get("submissions", 0)
        ready = sub_counts.get("by_status", {}).get("ready", 0)
        in_review = sub_counts.get("by_status", {}).get("in_review", 0)
        
        if total_subs > 0 or sub_counts.get("drafts", 0) > 0:
            workspaces.append({
                'name': ws.name,
                'drafts': sub_counts.get("drafts", 0),
                'total_subs': total_subs,
                'ready': ready,
                'in_review': in_review,
                'accepted': sub_counts.get("by_status", {}).get("accepted", 0),
                'rejected': sub_counts.get("by_status", {}).get("rejected", 0),
            })
            count += ready + in_review
    return count, workspaces

# ── Collect state ──

recent_rounds = git_log_rounds()[:30]
ls = ledger_stats()
tiers = tier_stats()
issues = skill_issues_stats()
patterns_yaml = count_patterns()
detectors_py = count_compiled_detectors()
open_subs_total, open_subs_list = open_submissions()

# Round trajectory chart data (counts per round, crude)
round_counts = Counter()
try:
    log = subprocess.check_output(
        ["git", "-C", str(AUDITOOOR_DIR), "log", "--format=%s%x09%at", "-n", "500"],
        text=True, stderr=subprocess.DEVNULL
    )
    for line in log.splitlines():
        subject, ts = line.split('\t', 1) if '\t' in line else (line, '0')
        m = re.match(r'^R(\d+)\b|^Round\s+(\d+)\b', subject)
        if m:
            rn = int(m.group(1) or m.group(2))
            if rn not in round_counts:
                round_counts[rn] = int(ts)
except Exception:
    pass

sorted_rounds = sorted(round_counts.items())

# ── Emit HTML ──

html = f"""<!doctype html>
<html>
<head>
<meta charset="utf-8"/>
<title>auditooor dashboard · round R{recent_rounds[0] if recent_rounds else '?'}</title>
<style>
  body {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; max-width: 1100px; margin: 2em auto; padding: 0 1em; color: #1a1a1a; line-height: 1.5; }}
  h1, h2 {{ border-bottom: 2px solid #333; padding-bottom: 0.2em; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 1em; margin: 1em 0; }}
  .card {{ border: 1px solid #ccc; border-radius: 6px; padding: 1em; background: #fafafa; }}
  .stat {{ font-size: 2.2em; font-weight: bold; color: #0a5; }}
  .label {{ font-size: 0.85em; color: #555; text-transform: uppercase; letter-spacing: 0.05em; }}
  table {{ border-collapse: collapse; width: 100%; margin: 0.5em 0; font-size: 0.9em; }}
  th, td {{ border: 1px solid #ddd; padding: 0.35em 0.6em; text-align: left; }}
  th {{ background: #eee; }}
  td.num {{ text-align: right; font-variant-numeric: tabular-nums; }}
  .small {{ font-size: 0.8em; color: #666; }}
  .warn {{ color: #c80; }}
  .fail {{ color: #c22; }}
  .pass {{ color: #0a5; }}
</style>
</head>
<body>
<h1>auditooor dashboard</h1>
<div class="small">Generated {datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')} · recent round: R{recent_rounds[0] if recent_rounds else '?'}</div>

<h2>Pattern library</h2>
<div class="grid">
  <div class="card"><div class="stat">{patterns_yaml}</div><div class="label">DSL pattern YAMLs</div></div>
  <div class="card"><div class="stat">{detectors_py}</div><div class="label">compiled detectors</div></div>
  <div class="card"><div class="stat">{tiers.get('S', 0)}</div><div class="label">Tier S</div></div>
  <div class="card"><div class="stat">{tiers.get('E', 0)}</div><div class="label">Tier E</div></div>
  <div class="card"><div class="stat">{tiers.get('D', 0)}</div><div class="label">Tier D (graveyard)</div></div>
</div>

<h2>Real-engagement ledger</h2>
<div class="grid">
  <div class="card"><div class="stat pass">{ls['tp']}</div><div class="label">TP (confirmed)</div></div>
  <div class="card"><div class="stat">{ls['fp']}</div><div class="label">FP (rejected)</div></div>
  <div class="card"><div class="stat warn">{ls['unknown']}</div><div class="label">UNKNOWN (pending)</div></div>
  <div class="card"><div class="stat pass">{ls['paid']}</div><div class="label">PAID outcomes</div></div>
</div>

<h3>Top TP detectors</h3>
<table>
  <thead><tr><th>Pattern</th><th class="num">TP</th><th class="num">FP</th></tr></thead>
  <tbody>
  {''.join(f"<tr><td>{n}</td><td class='num'>{tp}</td><td class='num'>{fp}</td></tr>" for n, tp, fp in ls['top_detectors']) or "<tr><td colspan='3' class='small'>no TPs yet</td></tr>"}
  </tbody>
</table>

<h2>Engagements</h2>
<table>
  <thead><tr><th>Workspace</th><th class="num">Ledger rows</th></tr></thead>
  <tbody>
  {''.join(f"<tr><td>{ws}</td><td class='num'>{n}</td></tr>" for ws, n in sorted(ls['workspaces'].items(), key=lambda x: -x[1]))}
  </tbody>
</table>

<h2>Submissions across workspaces</h2>
<div class="grid">
  <div class="card"><div class="stat">{open_subs_total}</div><div class="label">ready / in-review</div></div>
  <div class="card"><div class="stat">{sum(w.get('drafts',0) for w in open_subs_list)}</div><div class="label">drafts</div></div>
  <div class="card"><div class="stat pass">{sum(w.get('accepted',0) for w in open_subs_list)}</div><div class="label">accepted/paid</div></div>
  <div class="card"><div class="stat fail">{sum(w.get('rejected',0) for w in open_subs_list)}</div><div class="label">rejected/duped</div></div>
</div>
<table>
  <thead><tr><th>Workspace</th><th class="num">Drafts</th><th class="num">Ready</th><th class="num">In Review</th><th class="num">Accepted</th><th class="num">Rejected</th></tr></thead>
  <tbody>
  {''.join(f"<tr><td>{w['name']}</td><td class='num'>{w.get('drafts',0)}</td><td class='num'>{w.get('ready',0)}</td><td class='num'>{w.get('in_review',0)}</td><td class='num pass'>{w.get('accepted',0)}</td><td class='num fail'>{w.get('rejected',0)}</td></tr>" for w in open_subs_list) or "<tr><td colspan='6' class='small'>none</td></tr>"}
  </tbody>
</table>

<h2>Skill issues</h2>
<div class="grid">
  <div class="card"><div class="stat">{issues['total']}</div><div class="label">total</div></div>
  <div class="card"><div class="stat warn">{issues['open']}</div><div class="label">open</div></div>
  <div class="card"><div class="stat pass">{issues['closed']}</div><div class="label">closed</div></div>
  <div class="card"><div class="stat pass">{issues['done']}</div><div class="label">done</div></div>
</div>

<h2>Round trajectory</h2>
<table>
  <thead><tr><th>Round</th><th>Timestamp</th></tr></thead>
  <tbody>
  {''.join(f"<tr><td>R{rn}</td><td class='small'>{datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime('%Y-%m-%d') if ts else '—'}</td></tr>" for rn, ts in sorted_rounds[-20:])}
  </tbody>
</table>

<div class="small" style="margin-top: 3em;">
  Regenerate: <code>python3 tools/dashboard.py</code>
  · Source of truth: <code>detectors/_hits_ledger.yaml</code>,
  <code>detectors/_tier_registry.yaml</code>, <code>SKILL_ISSUES.md</code>.
</div>
</body>
</html>
"""

OUT_HTML.write_text(html)
print(f"[ok] dashboard: {OUT_HTML}")
print(f"     {patterns_yaml} patterns / {detectors_py} detectors / {ls['tp']} TP / {ls['paid']} paid / {issues['open']} open issues")

if '--open' in sys.argv:
    os.system(f"open {OUT_HTML}" if sys.platform == 'darwin' else f"xdg-open {OUT_HTML}")
