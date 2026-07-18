#!/usr/bin/env python3
"""
cross-workspace-state-aggregator.py — Repo-level state dashboard

Aggregates state from every workspace into:
  - reports/cross_workspace_state.json
  - docs/CROSS_WORKSPACE_STATE_<date>.md

Reads from:
  - <ws>/.auditooor/outcome_linkage_manifest.json
  - <ws>/submissions/SUBMISSIONS.md (submission counts, status)
  - outcome-telemetry.py --json (filed/paid/rejected totals)
  - workspace-state.py (phase info)

Scheduled via launchd every 6 hours (see docs/CROSS_WORKSPACE_COORDINATION.md
for the plist).

Usage:
    python3 tools/cross-workspace-state-aggregator.py [--audits-dir ~/audits]
        [--out reports/cross_workspace_state.json]
        [--md-out docs/CROSS_WORKSPACE_STATE_{date}.md]
        [--quiet]
"""

import argparse
import json
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

AUDITOOOR_DIR = Path(__file__).parent.parent
REPORTS_DIR = AUDITOOOR_DIR / "reports"
DOCS_DIR = AUDITOOOR_DIR / "docs"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


# ---------------------------------------------------------------------------
# Workspace discovery
# ---------------------------------------------------------------------------

def discover_workspaces(audits_dir: Path) -> List[Path]:
    """Return all real workspace dirs under audits_dir."""
    if not audits_dir.exists():
        return []
    workspaces: List[Path] = []
    skip = {"auditooor", "test-dogfood-r48", "_worklist", "economic_hypotheses_ir", "--help"}
    for ws_dir in sorted(audits_dir.iterdir()):
        if not ws_dir.is_dir():
            continue
        if ws_dir.name.startswith(".") or ws_dir.name in skip:
            continue
        # Must have at least one indicator of a real workspace
        indicators = [
            ws_dir / "submissions",
            ws_dir / "SUBMISSIONS.md",
            ws_dir / ".auditooor",
            ws_dir / "src",
        ]
        if any(p.exists() for p in indicators):
            workspaces.append(ws_dir)
    return workspaces


# ---------------------------------------------------------------------------
# Data loaders
# ---------------------------------------------------------------------------

def load_outcome_linkage_manifest(ws_path: Path) -> Dict[str, Any]:
    """Load .auditooor/outcome_linkage_manifest.json if it exists."""
    manifest_path = ws_path / ".auditooor" / "outcome_linkage_manifest.json"
    if manifest_path.exists():
        try:
            return json.loads(manifest_path.read_text())
        except Exception:
            pass
    return {}


def parse_submissions_md(ws_path: Path) -> Dict[str, Any]:
    """
    Parse SUBMISSIONS.md to count candidates/staged/submitted/outcomes.
    Returns a summary dict.
    """
    sub_file = ws_path / "submissions" / "SUBMISSIONS.md"
    if not sub_file.exists():
        sub_file = ws_path / "SUBMISSIONS.md"
    if not sub_file.exists():
        return {"found": False}

    text = sub_file.read_text(errors="replace")

    # Count table rows (submitted findings)
    submitted = 0
    pending = 0
    in_review = 0
    rejected = 0
    paid = 0
    duplicate = 0

    # Match table rows with status
    row_re = re.compile(
        r"^\|\s*\**[\w\-]+\**\s*\|[^|]*\|[^|]*\|([^|]+)\|[^|]*\|",
        re.MULTILINE,
    )
    for m in row_re.finditer(text):
        status_raw = m.group(1).strip().lower()
        submitted += 1
        if "pending" in status_raw:
            pending += 1
        elif "in review" in status_raw or "in_review" in status_raw:
            in_review += 1
        elif "reject" in status_raw:
            rejected += 1
        elif "paid" in status_raw or "awarded" in status_raw:
            paid += 1
        elif "duplicate" in status_raw or "dup" in status_raw:
            duplicate += 1

    # Count staging files
    staging_dir = ws_path / "submissions" / "staging"
    staged_count = 0
    if staging_dir.is_dir():
        staged_count = sum(
            1 for f in staging_dir.glob("*.md")
            if not f.name.startswith("BLOCKED_") and f.stat().st_size > 100
        )

    # Count paste-ready drafts (not BLOCKED)
    paste_ready_count = staged_count  # staging = paste-ready zone

    return {
        "found": True,
        "submitted": submitted,
        "pending": pending,
        "in_review": in_review,
        "rejected": rejected,
        "paid": paid,
        "duplicate": duplicate,
        "staged_paste_ready": staged_count,
        "paste_ready_count": paste_ready_count,
    }


def get_workspace_phase(ws_path: Path, audits_dir: Path) -> Dict[str, Any]:
    """Get workspace phase from workspace-state.py."""
    state_tool = AUDITOOOR_DIR / "tools" / "workspace-state.py"
    if not state_tool.exists():
        return {"phase": 0, "phase_name": "unknown"}
    try:
        env = os.environ.copy()
        env["AUDITS_DIR"] = str(audits_dir)
        result = subprocess.run(
            [sys.executable, str(state_tool), "get", str(ws_path)],
            capture_output=True, text=True, timeout=5, env=env
        )
        if result.returncode == 0 and result.stdout.strip():
            return json.loads(result.stdout)
    except Exception:
        pass
    return {"phase": 0, "phase_name": "unknown"}


def get_outcome_records(audits_dir: Path) -> List[Dict[str, Any]]:
    """Run outcome-telemetry.py --json."""
    telemetry_tool = AUDITOOOR_DIR / "tools" / "outcome-telemetry.py"
    if not telemetry_tool.exists():
        return []
    try:
        env = os.environ.copy()
        env["AUDITS_DIR"] = str(audits_dir)
        result = subprocess.run(
            [sys.executable, str(telemetry_tool), "--json"],
            capture_output=True, text=True, timeout=30, env=env
        )
        if result.returncode == 0 and result.stdout.strip():
            data = json.loads(result.stdout)
            return data.get("records", [])
    except Exception:
        pass
    return []


# ---------------------------------------------------------------------------
# Per-workspace summary
# ---------------------------------------------------------------------------

def build_workspace_summary(
    ws_path: Path,
    audits_dir: Path,
    outcome_records: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Build a comprehensive per-workspace state summary."""
    ws_name = ws_path.name

    # Manifest
    manifest = load_outcome_linkage_manifest(ws_path)
    manifest_summary = manifest.get("summary", {})

    # Submissions
    sub_stats = parse_submissions_md(ws_path)

    # Phase
    phase_info = get_workspace_phase(ws_path, audits_dir)

    # Outcome records for this workspace
    ws_records = [r for r in outcome_records if r.get("workspace") == ws_name]
    outcome_counter = Counter(r.get("outcome", "unknown") for r in ws_records)

    # Blocked files
    blocked_count = 0
    for d in [ws_path / "submissions" / "staging", ws_path / "submissions"]:
        if d.is_dir():
            blocked_count += sum(1 for f in d.glob("BLOCKED_*.md"))

    return {
        "workspace": ws_name,
        "workspace_path": str(ws_path),
        "phase": phase_info.get("phase", 0),
        "phase_name": phase_info.get("phase_name", "unknown"),
        # Submission funnel
        "candidates_open": sub_stats.get("pending", 0) + sub_stats.get("in_review", 0),
        "candidates_blocked": blocked_count,
        "paste_readies_staged": sub_stats.get("staged_paste_ready", 0),
        "submitted": sub_stats.get("submitted", 0),
        "outcomes": {
            "pending": outcome_counter.get("pending", 0),
            "in_review": outcome_counter.get("in_review", 0),
            "paid": outcome_counter.get("paid", 0),
            "rejected": outcome_counter.get("rejected", 0),
            "unknown": outcome_counter.get("unknown", 0),
        },
        "outcome_record_count": len(ws_records),
        # Manifest data
        "manifest_total_rows": manifest_summary.get("total_rows", 0),
        "manifest_complete_rows": manifest_summary.get("complete_rows", 0),
        "manifest_incomplete_rows": manifest_summary.get("incomplete_rows", 0),
    }


# ---------------------------------------------------------------------------
# Cross-workspace aggregates
# ---------------------------------------------------------------------------

def compute_cross_workspace_aggregates(
    ws_summaries: List[Dict[str, Any]],
    outcome_records: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Compute repo-level aggregate statistics."""
    total_submitted = sum(ws.get("submitted", 0) for ws in ws_summaries)
    total_paid = sum(ws["outcomes"].get("paid", 0) for ws in ws_summaries)
    total_rejected = sum(ws["outcomes"].get("rejected", 0) for ws in ws_summaries)
    total_pending = sum(ws["outcomes"].get("pending", 0) for ws in ws_summaries)
    total_in_review = sum(ws["outcomes"].get("in_review", 0) for ws in ws_summaries)
    total_staged = sum(ws.get("paste_readies_staged", 0) for ws in ws_summaries)
    total_blocked = sum(ws.get("candidates_blocked", 0) for ws in ws_summaries)

    # Top recurring patterns: count workspace appearances per outcome record title token
    from collections import defaultdict
    title_ws_map: Dict[str, set] = defaultdict(set)
    for rec in outcome_records:
        title = rec.get("title", "").lower()
        ws = rec.get("workspace", "")
        # Extract 3-grams from title as rough pattern keys
        tokens = re.findall(r"[a-z]{4,}", title)
        for tok in tokens:
            title_ws_map[tok].add(ws)

    top_recurring = sorted(
        [(tok, len(wss)) for tok, wss in title_ws_map.items() if len(wss) >= 2],
        key=lambda x: -x[1],
    )[:10]

    return {
        "total_workspaces": len(ws_summaries),
        "total_submitted": total_submitted,
        "total_paid": total_paid,
        "total_rejected": total_rejected,
        "total_pending": total_pending,
        "total_in_review": total_in_review,
        "total_paste_readies_staged": total_staged,
        "total_blocked": total_blocked,
        "top_recurring_surface_tokens": [
            {"token": tok, "workspace_count": cnt} for tok, cnt in top_recurring
        ],
    }


# ---------------------------------------------------------------------------
# Markdown output
# ---------------------------------------------------------------------------

def build_markdown(
    ws_summaries: List[Dict[str, Any]],
    aggregates: Dict[str, Any],
    generated_at: str,
) -> str:
    lines: List[str] = [
        f"# Cross-Workspace State — {_today()}",
        "",
        f"> Generated: {generated_at}",
        f"> Tool: `tools/cross-workspace-state-aggregator.py`",
        "",
        "## Summary",
        "",
        f"| Metric | Value |",
        f"|---|---|",
        f"| Total workspaces | {aggregates['total_workspaces']} |",
        f"| Total submitted | {aggregates['total_submitted']} |",
        f"| Total paid | {aggregates['total_paid']} |",
        f"| Total rejected | {aggregates['total_rejected']} |",
        f"| Total pending triage | {aggregates['total_pending']} |",
        f"| Total in review | {aggregates['total_in_review']} |",
        f"| Paste-readies staged | {aggregates['total_paste_readies_staged']} |",
        f"| Blocked (dedup) | {aggregates['total_blocked']} |",
        "",
        "## Per-Workspace State",
        "",
        "| Workspace | Phase | Submitted | Open | Staged | Paid | Rejected | Blocked |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for ws in sorted(ws_summaries, key=lambda w: w["workspace"]):
        lines.append(
            f"| {ws['workspace']} "
            f"| {ws['phase_name']} "
            f"| {ws['submitted']} "
            f"| {ws['candidates_open']} "
            f"| {ws['paste_readies_staged']} "
            f"| {ws['outcomes']['paid']} "
            f"| {ws['outcomes']['rejected']} "
            f"| {ws['candidates_blocked']} |"
        )

    lines += [
        "",
        "## Outcome Funnel (all workspaces)",
        "",
        "```",
        f"Submitted   : {aggregates['total_submitted']:>5}",
        f"  Paid      : {aggregates['total_paid']:>5}",
        f"  Rejected  : {aggregates['total_rejected']:>5}",
        f"  In Review : {aggregates['total_in_review']:>5}",
        f"  Pending   : {aggregates['total_pending']:>5}",
        f"Staged/Ready: {aggregates['total_paste_readies_staged']:>5}",
        f"Blocked     : {aggregates['total_blocked']:>5}",
        "```",
        "",
        "## Top Recurring Surface Tokens (≥2 workspaces)",
        "",
        "| Token | Workspace Count |",
        "|---|---|",
    ]
    for item in aggregates.get("top_recurring_surface_tokens", []):
        lines.append(f"| {item['token']} | {item['workspace_count']} |")

    lines += [
        "",
        "---",
        "",
        f"*Auto-generated by `cross-workspace-state-aggregator.py`. "
        f"Run `python3 tools/cross-workspace-state-aggregator.py` to refresh.*",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--audits-dir",
        default=os.environ.get("AUDITS_DIR", str(Path.home() / "audits")),
    )
    parser.add_argument(
        "--out",
        default=str(REPORTS_DIR / "cross_workspace_state.json"),
    )
    parser.add_argument("--md-out", default=None, help="Override markdown output path")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    audits_dir = Path(args.audits_dir).expanduser()
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    date_str = _today()
    if args.md_out:
        md_path = Path(args.md_out)
    else:
        md_path = DOCS_DIR / f"CROSS_WORKSPACE_STATE_{date_str}.md"
    md_path.parent.mkdir(parents=True, exist_ok=True)

    if not args.quiet:
        print(f"[state-aggregator] audits_dir={audits_dir}")

    # 1. Discover workspaces
    workspaces = discover_workspaces(audits_dir)
    if not args.quiet:
        print(f"[state-aggregator] {len(workspaces)} workspaces: "
              f"{[ws.name for ws in workspaces]}")

    # 2. Load outcome records once
    outcome_records = get_outcome_records(audits_dir)
    if not args.quiet:
        print(f"[state-aggregator] {len(outcome_records)} outcome records loaded")

    # 3. Build per-workspace summaries
    ws_summaries: List[Dict[str, Any]] = []
    for ws_path in workspaces:
        summary = build_workspace_summary(ws_path, audits_dir, outcome_records)
        ws_summaries.append(summary)
        if not args.quiet:
            print(f"  [{ws_path.name}] "
                  f"submitted={summary['submitted']} "
                  f"staged={summary['paste_readies_staged']} "
                  f"phase={summary['phase_name']}")

    # 4. Cross-workspace aggregates
    aggregates = compute_cross_workspace_aggregates(ws_summaries, outcome_records)

    generated_at = _now()

    # 5. Write JSON
    output = {
        "generated_at": generated_at,
        "audits_dir": str(audits_dir),
        "workspaces": ws_summaries,
        "aggregates": aggregates,
        "honest_limits": [
            "submission counts parsed from SUBMISSIONS.md table rows; may miss non-table formats.",
            "outcome counts from outcome-telemetry.py; sparse ledger gives low paid/rejected counts.",
            "phase info from workspace-state.py ~/.auditooor/workspace_state.json; may be stale.",
            "top_recurring_surface_tokens is a rough keyword frequency, not semantic dedup.",
        ],
    }
    out_path.write_text(json.dumps(output, indent=2))

    # 6. Write markdown
    md_content = build_markdown(ws_summaries, aggregates, generated_at)
    md_path.write_text(md_content)

    print(f"[state-aggregator] done")
    print(f"  JSON: {out_path}")
    print(f"  Markdown: {md_path}")
    print(f"  workspaces={len(workspaces)} "
          f"submitted={aggregates['total_submitted']} "
          f"paid={aggregates['total_paid']} "
          f"staged={aggregates['total_paste_readies_staged']}")


if __name__ == "__main__":
    main()
