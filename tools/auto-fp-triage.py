#!/usr/bin/env python3
"""tools/auto-fp-triage.py — auto-triage FP-calibration hits into action bins.

Phase 29 follow-up to SKILL_ISSUES #52 (tools/fp-calibration.sh). The calibration
script scans OZ / Solady / Solmate and writes a per-detector hit table to
docs/archive/FP_CALIBRATION_REPORT.md. Every hit on those known-clean libs is a candidate
false-positive. This tool reads that table and classifies each detector:

    >20 hits    → GRAVEYARD    (detector precondition too broad)
     5-20 hits  → TIGHTEN      (add an FP-guard to the DSL)
     1-4  hits  → WHITELIST    (add to fixture-clean whitelist)
       0 hits   → OK           (no action)

For every non-OK detector the tool emits a recommended remediation patch —
but only as a *suggestion*. It never moves files or rewrites YAMLs; the
operator applies what they agree with. See docs/AUTO_FP_TRIAGE.md.

Graceful when no calibration report is present: prints SKIPPED and exits 0,
so CI doesn't break before operators have cloned the calibration workspaces.

Usage:
    python3 tools/auto-fp-triage.py
    python3 tools/auto-fp-triage.py --calibration-report path/to/report.md
    python3 tools/auto-fp-triage.py --json
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import pathlib
import re
import sys
from typing import Iterable

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_REPORT = REPO_ROOT / "docs" / "archive" / "FP_CALIBRATION_REPORT.md"
OUTPUT_MD = REPO_ROOT / "docs" / "AUTO_FP_TRIAGE.md"
PATTERNS_DIR = REPO_ROOT / "reference" / "patterns.dsl"
GRAVEYARD_DIR = REPO_ROOT / "reference" / "patterns.dsl.graveyard"
FIXTURE_CLEAN_DIR = REPO_ROOT / "detectors" / "test_fixtures" / "clean"

GRAVEYARD_THRESHOLD = 20
TIGHTEN_THRESHOLD = 5

# Parser for the "Per-detector FP counts" table written by fp-calibration.sh.
# Row shape: | <detector> | <n> | <n> | ... | <total> |
ROW_RE = re.compile(r"^\|\s*`?([A-Za-z0-9_\-./]+)`?\s*\|(.+)\|\s*(\d+)\s*\|\s*$")


def parse_report(report_path: pathlib.Path) -> list[tuple[str, int]]:
    """Return [(detector, total_hits)] sorted by hits desc."""
    lines = report_path.read_text(errors="ignore").splitlines()
    in_table = False
    rows: list[tuple[str, int]] = []
    for line in lines:
        if line.startswith("## Per-detector FP counts"):
            in_table = True
            continue
        if in_table and line.startswith("## "):
            break
        if not in_table:
            continue
        m = ROW_RE.match(line.strip())
        if not m:
            continue
        name = m.group(1)
        if name.lower() in {"detector", "---"}:
            continue
        try:
            total = int(m.group(3))
        except ValueError:
            continue
        rows.append((name, total))
    rows.sort(key=lambda kv: kv[1], reverse=True)
    return rows


def classify(hits: int) -> str:
    if hits == 0:
        return "OK"
    if hits < TIGHTEN_THRESHOLD:
        return "WHITELIST"
    if hits <= GRAVEYARD_THRESHOLD:
        return "TIGHTEN"
    return "GRAVEYARD"


def _candidate_dsl(name: str) -> pathlib.Path | None:
    """Best-effort guess at the DSL YAML for a detector name."""
    if not PATTERNS_DIR.is_dir():
        return None
    direct = PATTERNS_DIR / f"{name}.yaml"
    if direct.exists():
        return direct
    # Fallback: fuzzy match on stem (detectors prefix with wave_*/tier_* sometimes).
    stem = name.split(".")[-1]
    for p in PATTERNS_DIR.glob(f"*{stem}*.yaml"):
        return p
    return None


def remediation(name: str, hits: int, verdict: str) -> dict:
    """Build a patch-suggestion payload for one detector."""
    dsl = _candidate_dsl(name)
    dsl_rel = str(dsl.relative_to(REPO_ROOT)) if dsl else f"reference/patterns.dsl/{name}.yaml (NOT FOUND — check detector registry)"

    if verdict == "GRAVEYARD":
        return {
            "action": "GRAVEYARD",
            "rationale": f"{hits} FPs on OZ/Solady/Solmate — precondition is catastrophically broad.",
            "suggested_shell": f"mv {dsl_rel} {GRAVEYARD_DIR.relative_to(REPO_ROOT)}/",
            "followup": "Remove from detectors/test_detectors.sh and BUG_CLASSES.md.",
        }
    if verdict == "TIGHTEN":
        guard_snippet = (
            "# TODO(auto-fp-triage): ADD FP-GUARD HERE\n"
            "# e.g. `path_exclude: [/openzeppelin/, /solady/, /solmate/]`\n"
            "# or a more restrictive `where:` clause on the existing match."
        )
        return {
            "action": "TIGHTEN",
            "rationale": f"{hits} FPs — needs a stricter precondition, not full removal.",
            "suggested_dsl_edit": {
                "file": dsl_rel,
                "insert_comment_at_top_of_rule": guard_snippet,
            },
            "followup": "Re-run `make fp-calibration` after tightening; re-triage.",
        }
    if verdict == "WHITELIST":
        fx = f"{FIXTURE_CLEAN_DIR.relative_to(REPO_ROOT)}/{name}.clean.sol"
        return {
            "action": "WHITELIST",
            "rationale": f"{hits} FP(s) — low enough to absorb via an explicit fixture.",
            "suggested_fixture": fx,
            "followup": "Copy the flagged OZ/Solady snippet into the fixture so the hit is a known-accepted expectation.",
        }
    return {"action": "OK", "rationale": "No FPs on clean corpus."}


def render_markdown(triage: list[dict], source: pathlib.Path) -> str:
    now = _dt.datetime.now().isoformat(timespec="seconds")
    total = len(triage)
    by_action: dict[str, int] = {}
    for row in triage:
        by_action[row["verdict"]] = by_action.get(row["verdict"], 0) + 1

    out: list[str] = []
    out.append("# Auto-FP Triage")
    out.append("")
    out.append(f"*Generated:* {now}")
    try:
        src_display = source.relative_to(REPO_ROOT)
    except ValueError:
        src_display = source
    out.append(f"*Input:* `{src_display}` (produced by `tools/fp-calibration.sh`, SKILL_ISSUES #52)")
    out.append("")
    out.append("Auto-classifies detectors by FP count into action bins. "
               "**Recommendations only** — no files moved, no patterns edited.")
    out.append("")
    out.append("## Summary")
    out.append("")
    out.append(f"- Detectors triaged: **{total}**")
    for key in ("GRAVEYARD", "TIGHTEN", "WHITELIST", "OK"):
        out.append(f"- {key}: **{by_action.get(key, 0)}**")
    out.append("")
    out.append("## Thresholds")
    out.append("")
    out.append(f"| Bin | Hit range | Action |")
    out.append("|---|---|---|")
    out.append(f"| GRAVEYARD | > {GRAVEYARD_THRESHOLD} | move YAML to graveyard dir |")
    out.append(f"| TIGHTEN   | {TIGHTEN_THRESHOLD}–{GRAVEYARD_THRESHOLD} | add FP-guard to DSL |")
    out.append(f"| WHITELIST | 1–{TIGHTEN_THRESHOLD - 1} | add to fixture-clean |")
    out.append("| OK        | 0 | no action |")
    out.append("")
    out.append("## Per-detector recommendations")
    out.append("")
    for row in triage:
        out.append(f"### `{row['detector']}` — {row['verdict']} ({row['hits']} FPs)")
        out.append("")
        rem = row["remediation"]
        out.append(f"- **Rationale:** {rem.get('rationale', '')}")
        if "suggested_shell" in rem:
            out.append("- **Suggested shell (do NOT auto-run):**")
            out.append(f"  ```sh\n  {rem['suggested_shell']}\n  ```")
        if "suggested_dsl_edit" in rem:
            edit = rem["suggested_dsl_edit"]
            out.append(f"- **Suggested DSL edit in** `{edit['file']}`:")
            out.append("  ```yaml")
            for ln in edit["insert_comment_at_top_of_rule"].splitlines():
                out.append(f"  {ln}")
            out.append("  ```")
        if "suggested_fixture" in rem:
            out.append(f"- **Suggested fixture:** `{rem['suggested_fixture']}`")
        if "followup" in rem:
            out.append(f"- **Follow-up:** {rem['followup']}")
        out.append("")
    return "\n".join(out)


def main(argv: Iterable[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--calibration-report", default=str(DEFAULT_REPORT),
                    help="Path to FP_CALIBRATION_REPORT.md (default: docs/archive/FP_CALIBRATION_REPORT.md)")
    ap.add_argument("--json", action="store_true", help="Emit JSON triage to stdout instead of markdown summary.")
    ap.add_argument("--output", default=str(OUTPUT_MD), help="Where to write the markdown report.")
    args = ap.parse_args(list(argv) if argv is not None else None)

    report_path = pathlib.Path(args.calibration_report)
    if not report_path.exists():
        print(f"[auto-fp-triage] SKIPPED — no calibration report at {report_path}.")
        print("[auto-fp-triage] Run `make fp-calibration` first (see tools/fp-calibration.sh, SKILL_ISSUES #52).")
        return 0

    rows = parse_report(report_path)
    if not rows:
        print(f"[auto-fp-triage] SKIPPED — report parsed but no detector rows found in {report_path}.")
        return 0

    triage = []
    for detector, hits in rows:
        verdict = classify(hits)
        triage.append({
            "detector": detector,
            "hits": hits,
            "verdict": verdict,
            "remediation": remediation(detector, hits, verdict),
        })

    output_path = pathlib.Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(render_markdown(triage, report_path))
    print(f"[auto-fp-triage] wrote {output_path} ({len(triage)} detectors triaged)")

    if args.json:
        json.dump(triage, sys.stdout, indent=2)
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
