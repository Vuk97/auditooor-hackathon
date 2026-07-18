#!/usr/bin/env python3
"""engagement-dashboard.py — Operator visibility into the engagement pipeline.

Read-only single-command summary aggregating state across `~/audits/*/`
workspaces + packaging reports under `projects/<workspace>/`. Intended as a
single-glance answer to "how close are we to PR 206's ≥3-engagement gate?"

Scope (intentionally narrow):

  * Reads `<audits-dir>/*/reference/outcomes.jsonl` row counts by `outcome`.
    Uses ONLY the playbook §5 status vocabulary: `pending`, `accepted`,
    `paid`, `duplicate`, `rejected`. Any row with an unknown value is
    surfaced as `unknown:<value>` in the warnings section and NOT folded
    into any §5 bucket. No new strings introduced.
  * Counts packaging reports (`projects/<workspace>/ITER*_PACKAGING_REPORT.md`).
    A report is considered a completed-packaging-attempt marker — it does
    NOT promote to "engagement" unless either:
      (a) the workspace has ≥1 ledger row in `reference/outcomes.jsonl`,
      (b) the latest packaging report shows 0 ❌ (packaging succeeded).
  * Emits a markdown table (default) or machine-readable JSON (`--json`).
  * Trailing section: "Progress toward PR 206 ≥N-engagement gate" citing
    current validated-engagement count, the threshold, and how many more
    are needed.

Truth-audit
-----------

  1. Overclaim risk: "validated engagement" here is a local heuristic
     (≥1 ledger row OR a 0-❌ packaging report). It is NOT Codex-validated
     acceptance; PR 206 gate promotion remains a manual reviewer decision.
     The markdown output says this verbatim.
  2. Status vocabulary: exactly `{pending, accepted, paid, duplicate,
     rejected}` from §5. No synonyms emitted.
  3. Artifact class: dashboard output is operator telemetry, not proof.
     The operator decides gate promotability; the tool only counts.
  4. Cannot-judge: an `outcomes.jsonl` with malformed rows logs a warning
     to stderr and skips the row — the dashboard never crashes on bad
     data; that's the iteration-speed property.
  5. Read-only: the tool never writes to `reference/outcomes.jsonl`,
     never touches packaging reports, never mutates any workspace. The
     only write path is its own `stdout`/`--output` file.

Usage
-----

    python3 tools/engagement-dashboard.py
    python3 tools/engagement-dashboard.py --audits-dir ~/audits --threshold 3
    python3 tools/engagement-dashboard.py --json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Status vocabulary (playbook §5 — locked)
# ---------------------------------------------------------------------------

# These are the only outcome values the dashboard will bucket. Any other
# value is surfaced as a warning and folded into an "unknown" count; no new
# status strings are introduced by this tool.
STATUS_VOCAB = ("pending", "accepted", "paid", "duplicate", "rejected")

DEFAULT_THRESHOLD = 3  # PR 206 gate value


# ---------------------------------------------------------------------------
# Ledger reader (read-only)
# ---------------------------------------------------------------------------

def _read_outcomes_jsonl(path: Path) -> Tuple[Dict[str, int], List[str]]:
    """Count rows by outcome. Return (counts_by_state, warnings)."""
    counts: Dict[str, int] = {k: 0 for k in STATUS_VOCAB}
    warnings: List[str] = []
    if not path.exists():
        return counts, warnings

    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        warnings.append(f"{path}: unreadable ({exc})")
        return counts, warnings

    # Latest-row-per-report_id semantics: authoritative state is the LAST
    # matching row for each report_id (matches track-submissions.py /
    # outcome_reweight.py contract). We walk rows twice — once to gather
    # final state per report_id, then to tally.
    latest: Dict[str, str] = {}
    order: List[str] = []
    for idx, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            row = json.loads(stripped)
        except json.JSONDecodeError as exc:
            warnings.append(f"{path}:{idx}: malformed JSON ({exc.msg})")
            continue
        if not isinstance(row, dict):
            warnings.append(f"{path}:{idx}: not an object")
            continue
        report_id = str(row.get("report_id") or "").strip()
        outcome = str(row.get("outcome") or row.get("state") or "").strip().lower()
        if not report_id:
            warnings.append(f"{path}:{idx}: row missing report_id")
            continue
        if report_id not in latest:
            order.append(report_id)
        latest[report_id] = outcome

    for rid in order:
        outcome = latest[rid]
        if outcome in counts:
            counts[outcome] += 1
        else:
            warnings.append(
                f"{path}: report_id={rid} has unknown outcome='{outcome}' (skipped)"
            )
    return counts, warnings


# ---------------------------------------------------------------------------
# Packaging report reader (read-only)
# ---------------------------------------------------------------------------

ITER_REPORT_RE = re.compile(r"^ITER(\d+)_PACKAGING_REPORT\.md$")


# ---------------------------------------------------------------------------
# ccia-rust report reader (read-only)
# ---------------------------------------------------------------------------

# Angle vocabulary surfaced by `tools/ccia-rust.py` (iter10 T1). Kept in
# sync with `ALLOWED_ANGLES` there; this tool does not introduce any new
# angle labels — it only counts what ccia-rust already emits.
CCIA_RUST_ANGLES = ("A-AUTH", "A-ORACLE", "A-ROUNDING", "A-REENT", "A-ARITHMETIC")
# Confidence vocabulary — ccia-rust emits low/medium only (never high).
CCIA_RUST_CONFIDENCES = ("low", "medium")


def _read_ccia_rust_report(path: Path) -> Optional[Dict[str, Any]]:
    """Parse `<workspace>/ccia_rust_report.json` if present.

    Returns None if the report is absent OR if the file is unreadable /
    malformed JSON / not an object / missing the `angles` list. Silent
    absence is intentional: a missing report is an operator-visible
    "did not run ccia-rust here", not a finding. Never synthesizes zero
    counts (FM-016: honest absence, not fake presence).
    """
    if not path.exists():
        return None
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    angles = payload.get("angles")
    if not isinstance(angles, list):
        return None

    by_angle: Dict[str, int] = {k: 0 for k in CCIA_RUST_ANGLES}
    by_confidence: Dict[str, int] = {k: 0 for k in CCIA_RUST_CONFIDENCES}
    total = 0
    for entry in angles:
        if not isinstance(entry, dict):
            continue
        total += 1
        a = str(entry.get("angle") or "").strip()
        if a in by_angle:
            by_angle[a] += 1
        c = str(entry.get("confidence") or "").strip().lower()
        if c in by_confidence:
            by_confidence[c] += 1

    total_files = payload.get("total_files_scanned")
    if not isinstance(total_files, int):
        total_files = None

    return {
        "total_angles": total,
        "total_files_scanned": total_files,
        "by_angle": by_angle,
        "by_confidence": by_confidence,
    }


def _find_packaging_reports(projects_dir: Path, workspace: str) -> List[Path]:
    """Return packaging reports for this workspace, sorted by iter number."""
    ws_dir = projects_dir / workspace
    if not ws_dir.exists() or not ws_dir.is_dir():
        return []
    found: List[Tuple[int, Path]] = []
    try:
        entries = list(ws_dir.iterdir())
    except OSError:
        return []
    for entry in entries:
        if not entry.is_file():
            continue
        match = ITER_REPORT_RE.match(entry.name)
        if match:
            found.append((int(match.group(1)), entry))
    found.sort(key=lambda x: x[0])
    return [p for _, p in found]


def _packaging_report_has_zero_failures(path: Path) -> Optional[bool]:
    """Heuristic: returns True if report shows 0 ❌ (no failing drafts).

    Looks for the per-draft outcome table row "0 ❌? | yes |" OR a summary
    line indicating zero blocks. Returns None if indeterminate (neither
    clear PASS nor clear BLOCKED markers).
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    low = text.lower()
    # "BLOCKED" in the per-draft verdict column is the iter7 snowbridge
    # signal; its presence means at least one draft failed packaging.
    if "blocked" in low and "verdict" in low:
        return False
    # Explicit "0 ❌" marker or "zero blocks" phrase.
    if "0 ❌" in text or "zero blocks" in low:
        return True
    # Look for rows like "| 0 ❌?" — that's the header, ignore.
    # Default: indeterminate.
    return None


# ---------------------------------------------------------------------------
# Workspace aggregation
# ---------------------------------------------------------------------------

def _scan_audits_dir(audits_dir: Path) -> List[str]:
    """Return workspace directory names under <audits-dir>/*/. Sorted."""
    if not audits_dir.exists():
        return []
    names: List[str] = []
    try:
        for entry in audits_dir.iterdir():
            # Skip hidden directories and leading-dash entries (e.g. "--help"
            # left behind from argparse misuse).
            if entry.name.startswith(".") or entry.name.startswith("-"):
                continue
            if entry.is_dir():
                names.append(entry.name)
    except OSError:
        return []
    names.sort()
    return names


def _aggregate_workspace(
    audits_dir: Path, projects_dir: Path, workspace: str
) -> Dict[str, Any]:
    outcomes_path = audits_dir / workspace / "reference" / "outcomes.jsonl"
    counts, warnings = _read_outcomes_jsonl(outcomes_path)
    total_rows = sum(counts.values())

    reports = _find_packaging_reports(projects_dir, workspace)
    report_names = [p.name for p in reports]
    latest_report_name = report_names[-1] if report_names else None
    latest_zero_fail: Optional[bool] = None
    if reports:
        latest_zero_fail = _packaging_report_has_zero_failures(reports[-1])

    # "Validated engagement" heuristic: ≥1 ledger row OR latest packaging
    # report shows 0 ❌. Explicit honest-zero packaging (BLOCKED) does NOT
    # count.
    validated = total_rows > 0 or latest_zero_fail is True

    # Optional: ccia-rust report at <workspace>/ccia_rust_report.json.
    # Silent absence — no section emitted when the file is missing or
    # malformed; we do NOT synthesize a zero to hide the fact that the
    # tool never ran. `ccia_rust` key is None when absent.
    ccia_rust = _read_ccia_rust_report(
        audits_dir / workspace / "ccia_rust_report.json"
    )

    return {
        "workspace": workspace,
        "counts": counts,
        "total_rows": total_rows,
        "packaging_reports": report_names,
        "latest_packaging_report": latest_report_name,
        "latest_packaging_zero_failures": latest_zero_fail,
        "validated_engagement": validated,
        "ccia_rust": ccia_rust,
        "warnings": warnings,
    }


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------

def _render_markdown(
    rows: List[Dict[str, Any]],
    threshold: int,
    audits_dir: Path,
    projects_dir: Path,
) -> str:
    out: List[str] = []
    out.append("# Engagement Dashboard")
    out.append("")
    out.append(f"**Audits dir:** `{audits_dir}`")
    out.append(f"**Projects dir:** `{projects_dir}`")
    out.append(f"**Threshold (PR 206 gate):** {threshold}")
    out.append("")

    if not rows:
        out.append("_No workspaces found._")
    else:
        out.append(
            "| Workspace | pending | accepted | paid | duplicate | rejected "
            "| total | packaging reports | validated? |"
        )
        out.append(
            "|---|---|---|---|---|---|---|---|---|"
        )
        for r in rows:
            c = r["counts"]
            reports = r["packaging_reports"]
            pkg_display = (
                f"{len(reports)} ({', '.join(reports)})" if reports else "0"
            )
            validated = "yes" if r["validated_engagement"] else "no"
            out.append(
                "| {ws} | {pend} | {acc} | {paid} | {dupe} | {rej} "
                "| {tot} | {pkg} | {val} |".format(
                    ws=r["workspace"],
                    pend=c["pending"],
                    acc=c["accepted"],
                    paid=c["paid"],
                    dupe=c["duplicate"],
                    rej=c["rejected"],
                    tot=r["total_rows"],
                    pkg=pkg_display,
                    val=validated,
                )
            )

    out.append("")

    # Per-workspace "CCIA Rust angles" subsections. Silent on absence —
    # workspaces without a `ccia_rust_report.json` emit no block. Counts
    # are raw mechanical-detector output, not confirmed vulnerabilities
    # (see caveat line below each block).
    ccia_present = [r for r in rows if r.get("ccia_rust")]
    if ccia_present:
        out.append("## CCIA Rust angles (if available)")
        out.append("")
        for r in ccia_present:
            cr = r["ccia_rust"]
            total = cr["total_angles"]
            files = cr["total_files_scanned"]
            files_str = f"{files}" if files is not None else "?"
            out.append(f"### {r['workspace']}")
            out.append("")
            out.append(
                f"Total angles: **{total}** across {files_str} files scanned."
            )
            out.append("")
            out.append("| angle | count |")
            out.append("|---|---|")
            for a in CCIA_RUST_ANGLES:
                out.append(f"| {a} | {cr['by_angle'].get(a, 0)} |")
            out.append("")
            out.append("| confidence | count |")
            out.append("|---|---|")
            for c in CCIA_RUST_CONFIDENCES:
                out.append(f"| {c} | {cr['by_confidence'].get(c, 0)} |")
            out.append("")
            out.append(
                "_Note: raw mechanical-detector output; tool caps confidence "
                "at `medium` and never claims `high`. Counts are surface "
                "candidates for triage, not confirmed findings._"
            )
            out.append("")

    # Warnings block.
    all_warnings = [w for r in rows for w in r["warnings"]]
    if all_warnings:
        out.append("## Warnings")
        out.append("")
        for w in all_warnings:
            out.append(f"- {w}")
        out.append("")

    # Gate progress.
    validated_count = sum(1 for r in rows if r["validated_engagement"])
    needed = max(0, threshold - validated_count)
    gate_state = "PASS" if validated_count >= threshold else "FAIL"

    out.append("## Progress toward PR 206 ≥%d-engagement gate" % threshold)
    out.append("")
    out.append(
        f"**{validated_count} of {threshold} validated engagement(s). "
        f"Gate: {gate_state}.**"
    )
    if needed > 0:
        out.append("")
        out.append(f"{needed} more needed to reach gate.")
    else:
        out.append("")
        out.append("Gate reached — awaiting Codex-side promotion review.")
    out.append("")
    out.append(
        "_Note: 'validated engagement' here is a local heuristic "
        "(≥1 ledger row OR latest packaging report shows 0 failed drafts). "
        "Gate promotion is still a manual Codex review decision on the "
        "roadmap track._"
    )
    out.append("")
    return "\n".join(out)


def _render_json(
    rows: List[Dict[str, Any]],
    threshold: int,
    audits_dir: Path,
    projects_dir: Path,
) -> str:
    validated_count = sum(1 for r in rows if r["validated_engagement"])
    needed = max(0, threshold - validated_count)
    payload: Dict[str, Any] = {
        "audits_dir": str(audits_dir),
        "projects_dir": str(projects_dir),
        "threshold": threshold,
        "status_vocab": list(STATUS_VOCAB),
        "workspaces": rows,
        "validated_engagements": validated_count,
        "needed_to_reach_gate": needed,
        "gate_state": "PASS" if validated_count >= threshold else "FAIL",
    }
    return json.dumps(payload, indent=2, sort_keys=True)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _default_projects_dir() -> Path:
    # Repo-relative default — resolve to <repo-root>/projects/ from the
    # tool's own location (tools/engagement-dashboard.py → repo-root).
    return Path(__file__).resolve().parents[1] / "projects"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="engagement-dashboard.py",
        description=(
            "Read-only dashboard of engagement pipeline state. Aggregates "
            "reference/outcomes.jsonl ledger rows and packaging reports "
            "across all audit workspaces. Shows progress toward PR 206's "
            "≥N-engagement gate."
        ),
    )
    parser.add_argument(
        "--audits-dir",
        default=str(Path.home() / "audits"),
        help="Directory containing per-workspace audits (default: ~/audits/).",
    )
    parser.add_argument(
        "--projects-dir",
        default=str(_default_projects_dir()),
        help="Directory containing per-workspace packaging reports "
             "(default: <repo>/projects/).",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=DEFAULT_THRESHOLD,
        help="Engagement-count threshold for PR 206 gate (default: 3).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON instead of markdown.",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    audits_dir = Path(args.audits_dir).expanduser().resolve()
    projects_dir = Path(args.projects_dir).expanduser().resolve()
    threshold = int(args.threshold)
    if threshold < 0:
        print("[engagement-dashboard] --threshold must be >= 0", file=sys.stderr)
        return 2

    workspaces = _scan_audits_dir(audits_dir)
    rows = [_aggregate_workspace(audits_dir, projects_dir, ws) for ws in workspaces]

    # Stream row-level warnings to stderr too (for pipeline visibility),
    # even though they're also embedded in markdown output.
    for r in rows:
        for w in r["warnings"]:
            print(f"[engagement-dashboard] WARN {w}", file=sys.stderr)

    if args.json:
        sys.stdout.write(_render_json(rows, threshold, audits_dir, projects_dir))
        sys.stdout.write("\n")
    else:
        sys.stdout.write(_render_markdown(rows, threshold, audits_dir, projects_dir))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
