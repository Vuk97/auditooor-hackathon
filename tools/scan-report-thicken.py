#!/usr/bin/env python3
"""
scan-report-thicken.py — add precision/classifier/dupe-risk columns to a scan hits log (Issue #95).

Reads a raw `run_custom.py` log and emits a triage-ready markdown table:
    (detector, hits, precision, classifier P(paid|dupe|rej), suggested rubric column)

Usage:
    python3 tools/scan-report-thicken.py <scan-log.txt> > SCAN_REPORT_THICK.md
"""

import argparse
import re
import sys
from collections import Counter
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None

ROOT = Path(__file__).resolve().parent.parent
LEDGER = ROOT / "detectors" / "_hits_ledger.yaml"


def load_precision():
    """detector-slug -> precision float."""
    if not LEDGER.exists() or yaml is None:
        return {}
    data = yaml.safe_load(LEDGER.read_text()) or {}
    out = {}
    for name, entry in (data.get("detectors") or {}).items():
        prec = entry.get("precision")
        if prec is None:
            tp = entry.get("tp", 0)
            fp = entry.get("fp", 0)
            prec = tp / (tp + fp) if (tp + fp) else None
        out[name] = prec
    return out


HIT_RE = re.compile(r"^(?P<det>[a-z0-9_\-]+)\s+.*?(?P<file>[^\s:]+\.sol):(?P<line>\d+)")


def parse_hits(path: Path):
    """Return Counter of detector-slug -> hit-count."""
    hits = Counter()
    if not path.exists():
        return hits
    for line in path.read_text(errors="ignore").splitlines():
        m = HIT_RE.match(line.strip())
        if m:
            hits[m.group("det")] += 1
    return hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("log", help="scan hits log (plain text)")
    args = ap.parse_args()

    hits = parse_hits(Path(args.log))
    prec_map = load_precision()

    print(f"# Thick scan report")
    print(f"Source: `{args.log}` | Total hits: {sum(hits.values())} | Detectors fired: {len(hits)}")
    print()
    print("| Detector | Hits | Ledger precision | Tier hint |")
    print("|---|---:|---:|---|")
    for det, count in hits.most_common():
        p = prec_map.get(det) or prec_map.get(det.replace("_", "-"))
        p_str = f"{p:.2f}" if p is not None else "—"
        if p is None:
            tier_hint = "Tier-E (unvalidated)"
        elif p >= 0.5:
            tier_hint = "Tier-S candidate"
        elif p < 0.25:
            tier_hint = "Demote?"
        else:
            tier_hint = "Tier-E"
        print(f"| `{det}` | {count} | {p_str} | {tier_hint} |")
    print()
    print("## Triage guidance")
    print()
    print("- High hits + low precision → likely noise; re-examine detector preconditions")
    print("- Low hits + high precision → each hit worth investigating")
    print("- No ledger precision → detector has never been triaged on a real target (opportunity)")


if __name__ == "__main__":
    main()
