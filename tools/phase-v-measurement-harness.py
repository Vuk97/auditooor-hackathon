#!/usr/bin/env python3
"""phase-v-measurement-harness.py - Phase NEG-V (verification) measurement harness.

Closes the WF-10 methodology trap: before Phase 0 falsification, MEASURE actual
workflow shift produced by Phase -1 wiring across 7-day windows. NEG-E's WF-10
correction (R-rules ARE catching; 99 fails across 5 'zero-activation' rules)
revealed PLAN-X's 'never caught anything' was wrong because the MEASUREMENT
was wrong, not the rules. The same trap exists for RESTORE-1 + Phase -1
deliverables (hunt-starter, dispatch-preflight auto-invoke, spawn-worker.sh,
lane-integrator.py).

What this harness tracks across a 7-day measurement window:

  - hunt-starter verdicts per workspace per day
    (HUNT-READY / OOS-SKIP / DUPE-SKIP / DESIGN-CHOICE-SKIP / RUBRIC-NO-ROW-SKIP /
     PAID-FINDING-MATCH counts)
  - pattern-migration-alert hits (PAID-finding match candidates surfaced)
  - dispatch-preflight prebriefing-injection rate (% of dispatches that got
    Section 15a/15b)
  - lane-integrator.py usage count + R36/R55 hook fire rate
  - scan-report-thicken classifier scores per scan run
  - End-to-end: paste-ready output count per workspace per week
    (the THING we are trying to move)

Log sources read:

  .auditooor/mcp_call_log.jsonl                         (60-day window cap)
  .auditooor/spawn_worker_log.jsonl                     (P-1-C output)
  .auditooor/dispatch_audit.jsonl                       (dispatch-preflight)
  <ws>/.auditooor/hunt_candidates_ranked.jsonl|json     (P-1-A output)
  <ws>/.auditooor/hunt_candidates_ranked.json           (P-1-A latest snapshot)
  <ws>/.auditooor/pattern_migration_alerts.json|.md     (WIRE-1 wiring)
  workspace SUBMISSIONS.md files                        (paste-ready ground truth)

Modes:

  --baseline    Write reports/phase_v_baseline_<date>.json with current-state
                metrics (BEFORE the measurement window begins).
  --measure     Poll once and APPEND one row to
                reports/phase_v_measurement_<date>.jsonl
                Designed to be run daily by cron during a 7-day window.
  --report      Compute deltas vs baseline, run Wilson confidence intervals,
                emit reports/phase_v_report_<window>.md with per-pillar verdict:
                  SHIFTED-POSITIVELY / NO-MEASURABLE-SHIFT / SHIFTED-NEGATIVELY

Flags:

  --workspaces <comma-list>   Override workspace auto-discovery (default:
                              all dirs under ~/audits except dotfiles and
                              _archive/_worklist).
  --baseline-file <path>      Path to baseline file (default: latest under
                              reports/phase_v_baseline_*.json).
  --measure-file <path>       Path to measurement jsonl (default: latest
                              under reports/phase_v_measurement_*.jsonl).
  --window-days <N>           Window size for --report (default: 7).
  --strict                    Fail-closed instead of warn-only on missing logs.
  --json                      Emit machine-readable JSON instead of human text.

Schema: auditooor.phase_v_measurement.v1
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import math
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

SCHEMA = "auditooor.phase_v_measurement.v1"

THIS_FILE = Path(__file__).resolve()
TOOLS_DIR = THIS_FILE.parent
ROOT = TOOLS_DIR.parent
REPORTS_DIR = ROOT / "reports"
AUDITS_ROOT = Path.home() / "audits"

# Pillars we measure. Each pillar has a key + display label + the metric name
# we extract per measurement.
PILLARS: List[Dict[str, str]] = [
    {"key": "hunt_starter_verdicts", "label": "Hunt-starter verdicts (per-workspace)"},
    {"key": "pattern_migration_hits", "label": "Pattern-migration PAID matches"},
    {"key": "dispatch_prebriefing_rate", "label": "Dispatch-preflight prebriefing injection rate"},
    {"key": "lane_integrator_usage", "label": "lane-integrator.py usage count"},
    {"key": "r36_r55_hook_fires", "label": "R36/R55 hook fire rate"},
    {"key": "scan_report_thicken_runs", "label": "scan-report-thicken classifier runs"},
    {"key": "paste_ready_output", "label": "Paste-ready output per workspace per week"},
]

# Hunt-starter verdict labels (extend if hunt-starter adds more).
HUNT_VERDICT_KEYS: List[str] = [
    "HUNT-READY",
    "LIKELY-DUPE-SKIP",
    "LIKELY-OOS-SKIP",
    "RUBRIC-NO-ROW-SKIP",
    "DESIGN-CHOICE-SKIP",
    "PAID-FINDING-MATCH-HIGH-PRIORITY",
]


# ---------------------------------------------------------------------------
# Log readers - each returns a list of {"ts": iso, ...} rows or an empty list.


def _iter_jsonl(path: Path) -> Iterable[Dict[str, Any]]:
    """Yield JSON rows from a .jsonl file; tolerate malformed lines."""
    if not path.exists() or not path.is_file():
        return
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    # Malformed line - skip silently in non-strict; the gate
                    # itself handles missing data.
                    continue
    except OSError:
        return


def _parse_iso(ts: Optional[str]) -> Optional[dt.datetime]:
    if not ts or not isinstance(ts, str):
        return None
    # Normalize trailing Z to +00:00 for fromisoformat.
    s = ts.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        return dt.datetime.fromisoformat(s)
    except ValueError:
        return None


def _within_window(row_ts: Optional[dt.datetime], window_start: Optional[dt.datetime]) -> bool:
    if window_start is None:
        return True
    if row_ts is None:
        return False
    return row_ts >= window_start


def discover_workspaces(audits_root: Path = AUDITS_ROOT) -> List[Path]:
    """List active audit workspaces. Skips dotfiles, files, and known meta dirs."""
    if not audits_root.exists():
        return []
    skip = {"_archive", "_worklist", "source-mirrors", "<project>", "--help"}
    out: List[Path] = []
    for child in sorted(audits_root.iterdir()):
        if not child.is_dir():
            continue
        if child.name.startswith(".") or child.name in skip:
            continue
        out.append(child)
    return out


# ---------------------------------------------------------------------------
# Pillar measurement functions.


def measure_hunt_starter(workspace: Path) -> Dict[str, Any]:
    """Read <ws>/.auditooor/hunt_candidates_ranked.json and tally verdicts."""
    ranked = workspace / ".auditooor" / "hunt_candidates_ranked.json"
    out = {
        "snapshot_exists": False,
        "snapshot_path": str(ranked),
        "generated_at_utc": None,
        "candidate_count": 0,
        "verdict_counts": {k: 0 for k in HUNT_VERDICT_KEYS},
        "verdict_unknown": 0,
    }
    if not ranked.exists():
        return out
    try:
        data = json.loads(ranked.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return out
    out["snapshot_exists"] = True
    out["generated_at_utc"] = data.get("generated_at_utc")
    verdicts = data.get("verdicts") or []
    out["candidate_count"] = len(verdicts)
    for v in verdicts:
        label = v.get("verdict")
        if label in out["verdict_counts"]:
            out["verdict_counts"][label] += 1
        else:
            out["verdict_unknown"] += 1
    return out


def measure_pattern_migration(workspace: Path, global_root: Path = AUDITS_ROOT) -> Dict[str, Any]:
    """Read pattern_migration_alerts.{json,md} - per-ws first, global fallback."""
    out = {
        "alerts_source": None,
        "paid_match_count": 0,
        "high_roi_count": 0,
        "any_alerts": False,
    }
    paths = [
        workspace / ".auditooor" / "pattern_migration_alerts.json",
        workspace / ".auditooor" / "pattern_migration_alerts.md",
        global_root / ".auditooor" / "pattern_migration_alerts.json",
        global_root / ".auditooor" / "pattern_migration_alerts.md",
    ]
    for p in paths:
        if not p.exists():
            continue
        out["alerts_source"] = str(p)
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        parsed_json = False
        if p.suffix == ".json":
            try:
                data = json.loads(text)
                alerts = data.get("alerts") or data.get("candidates") or []
                if isinstance(alerts, list):
                    out["paid_match_count"] = sum(
                        1 for a in alerts if isinstance(a, dict) and a.get("paid_match")
                    )
                    out["high_roi_count"] = sum(
                        1 for a in alerts if isinstance(a, dict) and a.get("high_roi")
                    )
                    out["any_alerts"] = len(alerts) > 0
                    parsed_json = True
            except (json.JSONDecodeError, ValueError):
                # Fall through to text-based heuristics.
                pass
        if not parsed_json:
            # Markdown / text scan only when JSON parse did not succeed.
            out["paid_match_count"] = max(
                out["paid_match_count"], len(re.findall(r"\[PAID\]|paid_match", text))
            )
            n_alerts = len([ln for ln in text.splitlines() if ln.strip().startswith("[alert]")])
            # Treat the "no high-ROI" sentinel as zero matches.
            if "No high-ROI pattern migrations" in text:
                n_alerts = 0
            out["high_roi_count"] = max(out["high_roi_count"], n_alerts)
            out["any_alerts"] = out["any_alerts"] or n_alerts > 0
        break
    return out


def measure_dispatch_prebriefing(log_path: Path, window_start: Optional[dt.datetime]) -> Dict[str, Any]:
    """Read .auditooor/dispatch_audit.jsonl - rate of prebriefing-injected dispatches."""
    out = {
        "log_path": str(log_path),
        "log_exists": log_path.exists(),
        "rows_in_window": 0,
        "rows_with_prebriefing": 0,
        "injection_rate": 0.0,
    }
    if not out["log_exists"]:
        return out
    for row in _iter_jsonl(log_path):
        ts = _parse_iso(row.get("ts"))
        if not _within_window(ts, window_start):
            continue
        out["rows_in_window"] += 1
        # Dispatch-preflight emits {"prebriefing": {...}} or
        # {"prebriefing_status": "..."} on dispatched rows. Tolerate both.
        prebr = row.get("prebriefing") or row.get("prebriefing_status")
        if prebr:
            out["rows_with_prebriefing"] += 1
    if out["rows_in_window"] > 0:
        out["injection_rate"] = round(out["rows_with_prebriefing"] / out["rows_in_window"], 4)
    return out


def measure_lane_integrator(log_path: Path, window_start: Optional[dt.datetime]) -> Dict[str, Any]:
    """Count lane-integrator.py usages from spawn_worker_log.jsonl + commit log."""
    out = {
        "log_path": str(log_path),
        "log_exists": log_path.exists(),
        "rows_in_window": 0,
        "lane_integrator_usages": 0,
    }
    if not out["log_exists"]:
        return out
    for row in _iter_jsonl(log_path):
        ts = _parse_iso(row.get("ts"))
        if not _within_window(ts, window_start):
            continue
        out["rows_in_window"] += 1
        tool = row.get("tool") or row.get("integrator") or ""
        if "lane-integrator" in str(tool):
            out["lane_integrator_usages"] += 1
    return out


def measure_r36_r55_hooks(log_path: Path, window_start: Optional[dt.datetime]) -> Dict[str, Any]:
    """R36 + R55 hook fire stats. Reads mcp_call_log.jsonl as proxy + checks
    for r36/r55 rebuttal markers in recent staged work via the audit log."""
    out = {
        "log_path": str(log_path),
        "log_exists": log_path.exists(),
        "rows_in_window": 0,
        "r36_fires": 0,
        "r55_fires": 0,
    }
    if not out["log_exists"]:
        return out
    for row in _iter_jsonl(log_path):
        ts = _parse_iso(row.get("ts"))
        if not _within_window(ts, window_start):
            continue
        out["rows_in_window"] += 1
        # mcp_call_log rows are MCP-callable rows; we look for the integration
        # commit pathway markers. r36/r55 fires are surfaced via the dispatch
        # log + spawn_worker log too, so we union the count.
        body = json.dumps(row)
        if "r36" in body.lower() or "R36" in body:
            out["r36_fires"] += 1
        if "r55" in body.lower() or "R55" in body:
            out["r55_fires"] += 1
    return out


def measure_scan_report_thicken(workspace: Path) -> Dict[str, Any]:
    """Count thickened scan reports in the workspace's recent scan runs."""
    out = {
        "thickened_reports": 0,
        "scan_report_dir_exists": False,
    }
    candidates = [
        workspace / "SCAN_REPORT_THICK.md",
        workspace / "scan_report_thick.md",
        workspace / ".auditooor" / "scan_report_thick.md",
    ]
    for c in candidates:
        if c.exists():
            out["thickened_reports"] += 1
            out["scan_report_dir_exists"] = True
    # Also count thickened reports under the workspace's scan_reports/ dir.
    scan_dir = workspace / "scan_reports"
    if scan_dir.is_dir():
        out["scan_report_dir_exists"] = True
        try:
            out["thickened_reports"] += sum(
                1 for p in scan_dir.iterdir()
                if p.is_file() and "thick" in p.name.lower()
            )
        except OSError:
            pass
    return out


def measure_paste_ready_output(workspace: Path) -> Dict[str, Any]:
    """Count paste-ready drafts under submissions/. R41-aware: prefer per-folder."""
    out = {
        "paste_ready_count": 0,
        "filed_count": 0,
        "submissions_dir_exists": False,
    }
    sub_root = workspace / "submissions"
    if not sub_root.is_dir():
        # Sometimes paste_ready/ is at workspace root.
        sub_root = workspace
    out["submissions_dir_exists"] = sub_root.is_dir()
    if not sub_root.is_dir():
        return out
    for status, key in [("paste_ready", "paste_ready_count"), ("filed", "filed_count")]:
        status_dir = sub_root / status
        if not status_dir.is_dir():
            continue
        try:
            # Count per-folder drafts AND flat .md files.
            n = 0
            for entry in status_dir.iterdir():
                if entry.is_dir():
                    # R41 layout: <slug>/<slug>.md
                    md = entry / f"{entry.name}.md"
                    if md.exists():
                        n += 1
                        continue
                    # Some lanes ship multiple .md per folder; count uniques.
                    n += sum(1 for f in entry.iterdir() if f.is_file() and f.suffix == ".md")
                elif entry.is_file() and entry.suffix == ".md" and entry.name not in {"README.md", "SUBMISSIONS.md"}:
                    n += 1
            out[key] = n
        except OSError:
            continue
    return out


# ---------------------------------------------------------------------------
# Composite snapshot for one workspace + one wall-clock time.


def measure_snapshot(workspaces: List[Path], window_start: Optional[dt.datetime] = None) -> Dict[str, Any]:
    """Take a measurement snapshot across all pillars."""
    snap: Dict[str, Any] = {
        "schema": SCHEMA,
        "measurement_ts_utc": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "workspaces": [],
        "global": {},
    }
    # Per-workspace.
    for ws in workspaces:
        ws_snap: Dict[str, Any] = {
            "workspace": str(ws),
            "workspace_name": ws.name,
            "hunt_starter": measure_hunt_starter(ws),
            "pattern_migration": measure_pattern_migration(ws),
            "scan_report_thicken": measure_scan_report_thicken(ws),
            "paste_ready_output": measure_paste_ready_output(ws),
        }
        snap["workspaces"].append(ws_snap)
    # Global (logs under auditooor-mcp itself).
    dispatch_log = ROOT / ".auditooor" / "dispatch_audit.jsonl"
    spawn_log = ROOT / ".auditooor" / "spawn_worker_log.jsonl"
    mcp_log = ROOT / ".auditooor" / "mcp_call_log.jsonl"
    snap["global"]["dispatch_prebriefing"] = measure_dispatch_prebriefing(dispatch_log, window_start)
    snap["global"]["lane_integrator"] = measure_lane_integrator(spawn_log, window_start)
    snap["global"]["r36_r55_hooks"] = measure_r36_r55_hooks(mcp_log, window_start)
    # Aggregate totals across workspaces.
    snap["aggregate"] = aggregate_snapshot(snap)
    return snap


def aggregate_snapshot(snap: Dict[str, Any]) -> Dict[str, Any]:
    """Roll up per-workspace metrics into one record."""
    agg: Dict[str, Any] = {
        "workspace_count": len(snap.get("workspaces", [])),
        "hunt_total_candidates": 0,
        "hunt_verdict_counts": {k: 0 for k in HUNT_VERDICT_KEYS},
        "pattern_migration_paid_matches": 0,
        "pattern_migration_high_roi": 0,
        "scan_report_thicken_total": 0,
        "paste_ready_total": 0,
        "filed_total": 0,
    }
    for ws in snap.get("workspaces", []):
        hs = ws.get("hunt_starter", {})
        agg["hunt_total_candidates"] += hs.get("candidate_count", 0)
        for k, v in (hs.get("verdict_counts") or {}).items():
            if k in agg["hunt_verdict_counts"]:
                agg["hunt_verdict_counts"][k] += v
        pm = ws.get("pattern_migration", {})
        agg["pattern_migration_paid_matches"] += pm.get("paid_match_count", 0)
        agg["pattern_migration_high_roi"] += pm.get("high_roi_count", 0)
        srt = ws.get("scan_report_thicken", {})
        agg["scan_report_thicken_total"] += srt.get("thickened_reports", 0)
        pr = ws.get("paste_ready_output", {})
        agg["paste_ready_total"] += pr.get("paste_ready_count", 0)
        agg["filed_total"] += pr.get("filed_count", 0)
    return agg


# ---------------------------------------------------------------------------
# Wilson confidence interval.


def wilson_ci(successes: int, trials: int, z: float = 1.96) -> Tuple[float, float, float]:
    """Wilson score interval for a binomial proportion.

    Returns (point_estimate, lower, upper). For trials==0 returns (0.0, 0.0, 0.0).
    """
    if trials <= 0:
        return 0.0, 0.0, 0.0
    if successes < 0:
        successes = 0
    if successes > trials:
        successes = trials
    p = successes / trials
    denom = 1.0 + (z * z) / trials
    centre = p + (z * z) / (2.0 * trials)
    margin = z * math.sqrt((p * (1.0 - p) / trials) + ((z * z) / (4.0 * trials * trials)))
    lower = (centre - margin) / denom
    upper = (centre + margin) / denom
    return round(p, 6), round(max(0.0, lower), 6), round(min(1.0, upper), 6)


def delta_verdict(
    baseline_successes: int,
    baseline_trials: int,
    measured_successes: int,
    measured_trials: int,
) -> Dict[str, Any]:
    """Compare two binomial samples with Wilson CIs.

    Verdict vocabulary:
      SHIFTED-POSITIVELY    measured CI strictly above baseline point estimate
      SHIFTED-NEGATIVELY    measured CI strictly below baseline point estimate
      NO-MEASURABLE-SHIFT   otherwise
    """
    base_p, base_lo, base_hi = wilson_ci(baseline_successes, baseline_trials)
    meas_p, meas_lo, meas_hi = wilson_ci(measured_successes, measured_trials)
    if measured_trials == 0 or baseline_trials == 0:
        verdict = "NO-MEASURABLE-SHIFT"
    elif meas_lo > base_p:
        verdict = "SHIFTED-POSITIVELY"
    elif meas_hi < base_p:
        verdict = "SHIFTED-NEGATIVELY"
    else:
        verdict = "NO-MEASURABLE-SHIFT"
    return {
        "baseline": {"successes": baseline_successes, "trials": baseline_trials,
                      "p": base_p, "lower": base_lo, "upper": base_hi},
        "measured": {"successes": measured_successes, "trials": measured_trials,
                      "p": meas_p, "lower": meas_lo, "upper": meas_hi},
        "verdict": verdict,
    }


def count_delta_verdict(baseline_count: int, measured_count: int) -> Dict[str, Any]:
    """Verdict for non-binomial pure-count metrics. Uses a >=10% threshold
    rule because we cannot run Wilson without trials. SHIFTED-POSITIVELY when
    measured is at least baseline + ceil(10% of baseline) and baseline >= 0;
    SHIFTED-NEGATIVELY mirror; otherwise NO-MEASURABLE-SHIFT.
    """
    delta = measured_count - baseline_count
    abs_threshold = max(1, math.ceil(0.1 * max(1, baseline_count)))
    if delta >= abs_threshold:
        verdict = "SHIFTED-POSITIVELY"
    elif -delta >= abs_threshold:
        verdict = "SHIFTED-NEGATIVELY"
    else:
        verdict = "NO-MEASURABLE-SHIFT"
    return {
        "baseline_count": baseline_count,
        "measured_count": measured_count,
        "delta": delta,
        "abs_threshold": abs_threshold,
        "verdict": verdict,
    }


# ---------------------------------------------------------------------------
# Baseline + measurement file I/O.


def write_baseline(snapshot: Dict[str, Any], baseline_path: Path) -> None:
    baseline_path.parent.mkdir(parents=True, exist_ok=True)
    baseline_path.write_text(json.dumps(snapshot, indent=2, sort_keys=True), encoding="utf-8")


def append_measurement(snapshot: Dict[str, Any], measure_path: Path) -> None:
    measure_path.parent.mkdir(parents=True, exist_ok=True)
    with measure_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(snapshot, sort_keys=True) + "\n")


def find_latest(pattern: str, base: Path = REPORTS_DIR) -> Optional[Path]:
    if not base.exists():
        return None
    paths = sorted(base.glob(pattern))
    return paths[-1] if paths else None


def load_baseline(path: Optional[Path]) -> Optional[Dict[str, Any]]:
    if path is None or not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def load_measurements(path: Optional[Path]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if path is None or not path.exists():
        return out
    for row in _iter_jsonl(path):
        out.append(row)
    return out


# ---------------------------------------------------------------------------
# Report renderer.


def render_report(
    baseline: Optional[Dict[str, Any]],
    measurements: List[Dict[str, Any]],
    window_days: int,
) -> Tuple[str, Dict[str, Any]]:
    """Build a per-pillar markdown report + structured verdict dict."""
    summary: Dict[str, Any] = {
        "schema": SCHEMA,
        "rendered_at_utc": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "window_days": window_days,
        "baseline_present": baseline is not None,
        "measurement_row_count": len(measurements),
        "pillars": {},
    }
    if baseline is None or not measurements:
        body = (
            "# Phase NEG-V measurement report\n\n"
            f"- schema: `{SCHEMA}`\n"
            f"- rendered_at_utc: {summary['rendered_at_utc']}\n"
            f"- window_days: {window_days}\n"
            f"- baseline_present: {baseline is not None}\n"
            f"- measurement_row_count: {len(measurements)}\n\n"
            "VERDICT: insufficient data (need both --baseline and --measure rows).\n"
        )
        return body, summary
    # Use the LATEST measurement as the comparison point.
    latest = measurements[-1]
    base_agg = baseline.get("aggregate", {})
    meas_agg = latest.get("aggregate", {})

    # Pillar 1: hunt-starter total candidates.
    p1 = count_delta_verdict(
        base_agg.get("hunt_total_candidates", 0),
        meas_agg.get("hunt_total_candidates", 0),
    )
    summary["pillars"]["hunt_starter_total"] = p1

    # Pillar 1b: hunt-starter HUNT-READY ratio (binomial).
    base_hv = base_agg.get("hunt_verdict_counts", {})
    meas_hv = meas_agg.get("hunt_verdict_counts", {})
    p1b = delta_verdict(
        base_hv.get("HUNT-READY", 0),
        base_agg.get("hunt_total_candidates", 0),
        meas_hv.get("HUNT-READY", 0),
        meas_agg.get("hunt_total_candidates", 0),
    )
    summary["pillars"]["hunt_starter_hunt_ready_rate"] = p1b

    # Pillar 2: pattern-migration paid-matches.
    p2 = count_delta_verdict(
        base_agg.get("pattern_migration_paid_matches", 0),
        meas_agg.get("pattern_migration_paid_matches", 0),
    )
    summary["pillars"]["pattern_migration_paid_matches"] = p2

    # Pillar 3: dispatch-preflight prebriefing-injection rate (binomial).
    base_d = baseline.get("global", {}).get("dispatch_prebriefing", {})
    meas_d = latest.get("global", {}).get("dispatch_prebriefing", {})
    p3 = delta_verdict(
        base_d.get("rows_with_prebriefing", 0),
        base_d.get("rows_in_window", 0),
        meas_d.get("rows_with_prebriefing", 0),
        meas_d.get("rows_in_window", 0),
    )
    summary["pillars"]["dispatch_prebriefing_rate"] = p3

    # Pillar 4: lane-integrator usage count.
    base_li = baseline.get("global", {}).get("lane_integrator", {})
    meas_li = latest.get("global", {}).get("lane_integrator", {})
    p4 = count_delta_verdict(
        base_li.get("lane_integrator_usages", 0),
        meas_li.get("lane_integrator_usages", 0),
    )
    summary["pillars"]["lane_integrator_usage"] = p4

    # Pillar 5: R36/R55 hook fires.
    base_hf = baseline.get("global", {}).get("r36_r55_hooks", {})
    meas_hf = latest.get("global", {}).get("r36_r55_hooks", {})
    p5 = count_delta_verdict(
        base_hf.get("r36_fires", 0) + base_hf.get("r55_fires", 0),
        meas_hf.get("r36_fires", 0) + meas_hf.get("r55_fires", 0),
    )
    summary["pillars"]["r36_r55_hook_fires"] = p5

    # Pillar 6: scan-report-thicken runs.
    p6 = count_delta_verdict(
        base_agg.get("scan_report_thicken_total", 0),
        meas_agg.get("scan_report_thicken_total", 0),
    )
    summary["pillars"]["scan_report_thicken_runs"] = p6

    # Pillar 7: paste-ready output (end-to-end ground truth).
    p7 = count_delta_verdict(
        base_agg.get("paste_ready_total", 0),
        meas_agg.get("paste_ready_total", 0),
    )
    summary["pillars"]["paste_ready_output"] = p7

    lines: List[str] = []
    lines.append("# Phase NEG-V measurement report")
    lines.append("")
    lines.append(f"- schema: `{SCHEMA}`")
    lines.append(f"- rendered_at_utc: {summary['rendered_at_utc']}")
    lines.append(f"- window_days: {window_days}")
    lines.append(f"- baseline_present: True")
    lines.append(f"- measurement_row_count: {len(measurements)}")
    lines.append(f"- baseline_ts: {baseline.get('measurement_ts_utc')}")
    lines.append(f"- latest_measurement_ts: {latest.get('measurement_ts_utc')}")
    lines.append("")
    lines.append("## Per-pillar verdicts")
    lines.append("")
    lines.append("| Pillar | Baseline | Measured | Delta | Verdict |")
    lines.append("|---|---|---|---|---|")
    for label, key in [
        ("Hunt-starter total candidates", "hunt_starter_total"),
        ("Hunt-starter HUNT-READY rate", "hunt_starter_hunt_ready_rate"),
        ("Pattern-migration paid matches", "pattern_migration_paid_matches"),
        ("Dispatch-preflight prebriefing rate", "dispatch_prebriefing_rate"),
        ("lane-integrator.py usages", "lane_integrator_usage"),
        ("R36/R55 hook fires (combined)", "r36_r55_hook_fires"),
        ("scan-report-thicken runs", "scan_report_thicken_runs"),
        ("Paste-ready output (end-to-end)", "paste_ready_output"),
    ]:
        cell = summary["pillars"].get(key, {})
        if "baseline_count" in cell:
            base_str = str(cell.get("baseline_count"))
            meas_str = str(cell.get("measured_count"))
            delta_str = f"{cell.get('delta'):+d}"
        else:
            base_str = f"{cell.get('baseline', {}).get('successes', 0)}/{cell.get('baseline', {}).get('trials', 0)} (p={cell.get('baseline', {}).get('p', 0)})"
            meas_str = f"{cell.get('measured', {}).get('successes', 0)}/{cell.get('measured', {}).get('trials', 0)} (p={cell.get('measured', {}).get('p', 0)})"
            delta_str = "see CIs"
        lines.append(f"| {label} | {base_str} | {meas_str} | {delta_str} | **{cell.get('verdict', '?')}** |")
    lines.append("")
    lines.append("## Methodology")
    lines.append("")
    lines.append(
        "Binomial pillars (HUNT-READY rate, prebriefing-injection rate) use Wilson 95% "
        "confidence intervals on baseline vs measured proportions; SHIFTED-POSITIVELY "
        "requires the measured lower bound strictly above the baseline point estimate. "
        "Pure-count pillars use a >=10% (min +/-1) absolute-delta threshold."
    )
    lines.append("")
    lines.append(
        "Closes the WF-10 methodology trap: before Phase 0 falsification, measure "
        "whether Phase -1 wiring actually shifted the workflow."
    )
    lines.append("")
    return "\n".join(lines) + "\n", summary


# ---------------------------------------------------------------------------
# CLI.


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--baseline", action="store_true", help="Write baseline snapshot.")
    mode.add_argument("--measure", action="store_true", help="Append one measurement row.")
    mode.add_argument("--report", action="store_true", help="Render delta report.")
    p.add_argument("--workspaces", help="Comma-separated workspace paths. Defaults to ~/audits/*.")
    p.add_argument("--baseline-file", help="Override baseline file path.")
    p.add_argument("--measure-file", help="Override measurement jsonl path.")
    p.add_argument("--report-file", help="Override report output path.")
    p.add_argument("--window-days", type=int, default=7, help="Window for --report (default 7).")
    p.add_argument("--strict", action="store_true", help="Fail-closed on missing logs.")
    p.add_argument("--json", dest="emit_json", action="store_true", help="Emit JSON instead of human text.")
    return p.parse_args(argv)


def resolve_workspaces(args: argparse.Namespace) -> List[Path]:
    if args.workspaces:
        return [Path(p).expanduser().resolve() for p in args.workspaces.split(",") if p.strip()]
    return discover_workspaces()


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    today = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")

    if args.baseline:
        workspaces = resolve_workspaces(args)
        snap = measure_snapshot(workspaces, window_start=None)
        baseline_path = Path(args.baseline_file) if args.baseline_file else REPORTS_DIR / f"phase_v_baseline_{today}.json"
        write_baseline(snap, baseline_path)
        out = {
            "ok": True,
            "schema": SCHEMA,
            "mode": "baseline",
            "baseline_path": str(baseline_path),
            "workspace_count": snap["aggregate"]["workspace_count"],
            "aggregate": snap["aggregate"],
        }
        print(json.dumps(out, indent=2) if args.emit_json else f"[baseline] wrote {baseline_path} ({snap['aggregate']['workspace_count']} workspaces, "
              f"{snap['aggregate']['hunt_total_candidates']} hunt-candidates, {snap['aggregate']['paste_ready_total']} paste-ready drafts).")
        return 0

    if args.measure:
        workspaces = resolve_workspaces(args)
        window_start = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=args.window_days)
        snap = measure_snapshot(workspaces, window_start=window_start)
        measure_path = Path(args.measure_file) if args.measure_file else REPORTS_DIR / f"phase_v_measurement_{today}.jsonl"
        append_measurement(snap, measure_path)
        out = {
            "ok": True,
            "schema": SCHEMA,
            "mode": "measure",
            "measure_path": str(measure_path),
            "appended_ts_utc": snap["measurement_ts_utc"],
            "aggregate": snap["aggregate"],
        }
        print(json.dumps(out, indent=2) if args.emit_json else f"[measure] appended snapshot to {measure_path} at {snap['measurement_ts_utc']}.")
        return 0

    # --report
    baseline_path = Path(args.baseline_file) if args.baseline_file else find_latest("phase_v_baseline_*.json")
    measure_path = Path(args.measure_file) if args.measure_file else find_latest("phase_v_measurement_*.jsonl")
    baseline = load_baseline(baseline_path)
    measurements = load_measurements(measure_path)
    if baseline is None and args.strict:
        print(f"[report] missing baseline file (looked for {baseline_path})", file=sys.stderr)
        return 1
    if not measurements and args.strict:
        print(f"[report] missing measurement rows (looked for {measure_path})", file=sys.stderr)
        return 1
    body, summary = render_report(baseline, measurements, args.window_days)
    report_path = Path(args.report_file) if args.report_file else REPORTS_DIR / f"phase_v_report_{today}.md"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(body, encoding="utf-8")
    out = {
        "ok": True,
        "schema": SCHEMA,
        "mode": "report",
        "report_path": str(report_path),
        "baseline_path": str(baseline_path) if baseline_path else None,
        "measure_path": str(measure_path) if measure_path else None,
        "summary": summary,
    }
    if args.emit_json:
        print(json.dumps(out, indent=2))
    else:
        print(f"[report] wrote {report_path}")
        for pkey, pcell in summary["pillars"].items():
            print(f"  {pkey}: {pcell.get('verdict', '?')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
