#!/usr/bin/env python3
"""triager-amend-asymmetry.py — Rule 14 upside-asymmetric severity filing advisor.

Scans an engagement workspace's filed/ directory for triager-amendment history
and computes an asymmetry score: how often did the triager push severity UP vs
DOWN vs LEAVE? When the historical asymmetry favors UP (triager escalates more
than downgrades), worker briefs for the current loop should default toward
filing at the higher candidate severity (Rule 14: upside-asymmetric calculus —
worst case downgrade = same outcome as filing at the lower severity directly).

Empirical anchor
----------------
dydx engagement (2026-05-08..05-11): cantina-048 (HIGH→CRITICAL by triager),
cantina-202 (HIGH→CRITICAL by orchestrator override per cantina-048 parity).
2 of 2 attempted escalations succeeded; 0 downgrades observed. Asymmetry ratio
= ∞ (no denominator). Recommendation: for future ambiguous-severity findings
in this engagement, file at the higher tier with discretionary argument.

CLI
---
    --workspace <ws>          : scan <ws>/submissions/{filed,paste_ready/filed}/
    --filed-dir <dir>         : alternative explicit dir to scan
    --advise [--candidate-severity SEV]
                              : emit JSON advisory + exit 0
    --json                    : machine-readable output (default = human)

Scoring
-------
Filename convention from `docs/FINAL_OPERATOR_PASTE_HYGIENE.md`:
  AMENDED-*-CRITICAL_*  → triager-escalated to CRITICAL
  AMENDED-cluster_*     → triager-amended w/ cluster impact, no severity bump
  FILED_*               → filed as-is, no amendment
  SUPERSEDED_*          → operator-superseded (count separately)

Returns:
  escalations  = count of files matching AMENDED-*-CRITICAL_
  amendments   = count of AMENDED-* w/o severity bump
  unchanged    = count of FILED_*
  superseded   = count of SUPERSEDED_*
  asymmetry_score = escalations / max(1, escalations + amendments + unchanged)
  verdict      = "lean-upside" if asymmetry_score >= 0.25 else "balanced"

Exit codes
----------
0 — advice emitted
1 — no filed/ directory found
2 — usage error
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


AMENDED_CRITICAL_RE = re.compile(r"^AMENDED-[a-z-]+-CRITICAL_", re.IGNORECASE)
AMENDED_PLAIN_RE = re.compile(r"^AMENDED-[a-z-]+_", re.IGNORECASE)
FILED_PLAIN_RE = re.compile(r"^FILED_", re.IGNORECASE)
SUPERSEDED_RE = re.compile(r"^SUPERSEDED_", re.IGNORECASE)


def _scan_dir(d: Path) -> dict[str, int]:
    out = {"escalations": 0, "amendments": 0, "unchanged": 0, "superseded": 0}
    for p in d.iterdir():
        if not p.is_file() or not p.name.endswith(".md"):
            continue
        name = p.name
        if AMENDED_CRITICAL_RE.match(name):
            out["escalations"] += 1
        elif AMENDED_PLAIN_RE.match(name):
            out["amendments"] += 1
        elif FILED_PLAIN_RE.match(name):
            out["unchanged"] += 1
        elif SUPERSEDED_RE.match(name):
            out["superseded"] += 1
    return out


def _resolve_filed_dirs(workspace: Path) -> list[Path]:
    candidates = [
        workspace / "submissions" / "filed",
        workspace / "submissions" / "paste_ready" / "filed",
        workspace / "paste_ready" / "filed",
        workspace / "filed",
    ]
    return [c for c in candidates if c.is_dir()]


def compute(filed_dirs: list[Path]) -> dict:
    totals = {"escalations": 0, "amendments": 0, "unchanged": 0, "superseded": 0}
    per_dir = []
    for d in filed_dirs:
        counts = _scan_dir(d)
        per_dir.append({"dir": str(d), **counts})
        for k, v in counts.items():
            totals[k] += v
    denom = max(1, totals["escalations"] + totals["amendments"] + totals["unchanged"])
    asym = totals["escalations"] / denom
    if asym >= 0.25:
        verdict = "lean-upside"
        recommendation = (
            "Historical triager asymmetry favors escalation. For ambiguous-severity "
            "findings in this engagement, file at the higher candidate tier with a "
            "discretionary argument (Rule 14)."
        )
    elif totals["unchanged"] + totals["amendments"] >= 3 and asym < 0.1:
        verdict = "lean-conservative"
        recommendation = (
            "Historical triager rarely escalates. File at the strict-rubric "
            "severity; do not invoke discretionary upside argument."
        )
    else:
        verdict = "balanced"
        recommendation = (
            "Insufficient signal or balanced history. Use case-by-case Rule 14 "
            "judgment based on the specific finding's evidence depth."
        )
    return {
        "totals": totals,
        "per_dir": per_dir,
        "asymmetry_score": round(asym, 3),
        "verdict": verdict,
        "recommendation": recommendation,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--workspace", help="engagement workspace path")
    src.add_argument("--filed-dir", help="explicit filed/ directory path")
    ap.add_argument("--candidate-severity", default=None,
                    help="proposed severity (HIGH/CRITICAL) for context-aware advice")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args()

    if args.workspace:
        ws = Path(args.workspace).expanduser()
        filed_dirs = _resolve_filed_dirs(ws)
        if not filed_dirs:
            print(f"error: no filed/ directory under {ws}/submissions/", file=sys.stderr)
            return 1
    else:
        d = Path(args.filed_dir).expanduser()
        if not d.is_dir():
            print(f"error: not a directory: {d}", file=sys.stderr)
            return 1
        filed_dirs = [d]

    result = compute(filed_dirs)
    if args.candidate_severity:
        result["candidate_severity"] = args.candidate_severity.upper()

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        t = result["totals"]
        print(f"Triager-amend asymmetry advisor")
        print(f"  filed dirs scanned: {len(result['per_dir'])}")
        print(f"  escalations (AMENDED-*-CRITICAL_): {t['escalations']}")
        print(f"  amendments  (AMENDED-* no sev bump): {t['amendments']}")
        print(f"  unchanged   (FILED_*):              {t['unchanged']}")
        print(f"  superseded  (SUPERSEDED_*):         {t['superseded']}")
        print(f"  asymmetry score: {result['asymmetry_score']}")
        print(f"  verdict: {result['verdict']}")
        print(f"  recommendation: {result['recommendation']}")
        if args.candidate_severity:
            print(f"  candidate severity: {args.candidate_severity.upper()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
