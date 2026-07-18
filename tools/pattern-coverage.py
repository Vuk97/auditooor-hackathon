#!/usr/bin/env python3
"""
pattern-coverage.py — coverage matrix over the hit ledger (Issue #96).

For every pattern in reference/patterns.dsl/, report triage history from
detectors/_hits_ledger.yaml and emit a precision-sorted table.

Usage:
    python3 tools/pattern-coverage.py                # print table
    python3 tools/pattern-coverage.py --json         # emit JSON
    python3 tools/pattern-coverage.py --demote       # list demotion candidates
    python3 tools/pattern-coverage.py --promote      # list promotion candidates
    python3 tools/pattern-coverage.py --by-workspace # (pattern, workspace) matrix
"""

import argparse
import json
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("need PyYAML: pip install pyyaml", file=sys.stderr)
    sys.exit(1)

ROOT = Path(__file__).resolve().parent.parent
PATTERNS_DIR = ROOT / "reference" / "patterns.dsl"
LEDGER = ROOT / "detectors" / "_hits_ledger.yaml"


def load_patterns():
    """Return list of pattern slugs from YAML files."""
    return sorted(p.stem for p in PATTERNS_DIR.glob("*.yaml"))


def load_ledger():
    if not LEDGER.exists():
        return {}
    data = yaml.safe_load(LEDGER.read_text()) or {}
    return data.get("detectors", {}) or {}


def build_table():
    patterns = load_patterns()
    ledger = load_ledger()
    rows = []
    for p in patterns:
        entry = ledger.get(p, {}) or ledger.get(p.replace("-", "_"), {}) or {}
        # Ledger schema: tp/fp/unknown are scalars; real_catches is a list of wins.
        tp = int(entry.get("tp", 0) or 0)
        fp = int(entry.get("fp", 0) or 0)
        unk = int(entry.get("unknown", 0) or 0)
        triaged = tp + fp
        precision = (tp / triaged) if triaged else None
        rows.append({
            "pattern": p,
            "triaged": triaged,
            "tp": tp,
            "fp": fp,
            "unknown": unk,
            "precision": precision,
            "last_triaged": entry.get("last_triaged"),
        })
    return rows


def print_table(rows):
    print(f"{'pattern':<60} {'triaged':>8} {'tp':>4} {'fp':>4} {'prec':>6}")
    print("-" * 88)
    for r in sorted(rows, key=lambda x: (-(x["precision"] or -1), -x["triaged"], x["pattern"])):
        prec = f"{r['precision']:.2f}" if r["precision"] is not None else "  — "
        print(f"{r['pattern']:<60} {r['triaged']:>8} {r['tp']:>4} {r['fp']:>4} {prec:>6}")
    # Summary
    triaged = sum(1 for r in rows if r["triaged"] > 0)
    tp_ever = sum(1 for r in rows if r["tp"] > 0)
    print(f"\nsummary: {len(rows)} patterns; {triaged} with ≥1 triage; {tp_ever} with ≥1 TP")


def demote_candidates(rows, min_triaged=5):
    """Patterns with triaged ≥ N and 0 TP."""
    return [r for r in rows if r["triaged"] >= min_triaged and r["tp"] == 0]


def promote_candidates(rows, min_tp=3, min_prec=0.5):
    """Patterns with tp ≥ N and precision ≥ P."""
    return [r for r in rows if r["tp"] >= min_tp and (r["precision"] or 0) >= min_prec]


def build_workspace_matrix():
    """Group ledger entries by (pattern, workspace) -> {tp, fp, unknown}."""
    patterns = load_patterns()
    ledger = load_ledger()
    cells = {}  # (pattern, ws) -> {"tp": n, "fp": n, "unknown": n}
    workspaces = set()
    for p in patterns:
        entry = ledger.get(p, {}) or ledger.get(p.replace("-", "_"), {}) or {}
        history = entry.get("_history") or []
        # Real-catches list: count as TP (legacy entries pre-_history schema).
        for c in entry.get("real_catches") or []:
            ws = c.get("workspace") or "(unknown)"
            workspaces.add(ws)
            cell = cells.setdefault((p, ws), {"tp": 0, "fp": 0, "unknown": 0})
            # Only count from real_catches if no _history — avoid double-count.
            if not history:
                cell["tp"] += 1
        for h in history:
            ws = h.get("workspace") or "(unknown)"
            workspaces.add(ws)
            verdict = (h.get("verdict") or "").upper()
            cell = cells.setdefault((p, ws), {"tp": 0, "fp": 0, "unknown": 0})
            if verdict == "TP":
                cell["tp"] += 1
            elif verdict == "FP":
                cell["fp"] += 1
            else:
                cell["unknown"] += 1
    return patterns, sorted(workspaces), cells


def print_workspace_matrix(patterns, workspaces, cells):
    # Only show patterns that have ≥1 cell.
    active = [p for p in patterns if any((p, ws) in cells for ws in workspaces)]
    if not active:
        print("(no triaged patterns in ledger)")
        return
    name_w = max(40, min(60, max(len(p) for p in active)))
    print(f"{'pattern':<{name_w}}  " + "  ".join(f"{ws[:14]:>14}" for ws in workspaces))
    print("-" * (name_w + 2 + 16 * len(workspaces)))
    for p in active:
        cells_row = []
        for ws in workspaces:
            c = cells.get((p, ws))
            if c is None:
                cells_row.append(f"{'·':>14}")
            else:
                cells_row.append(f"{c['tp']}T/{c['fp']}F/{c['unknown']}?".rjust(14))
        print(f"{p:<{name_w}}  " + "  ".join(cells_row))
    print(f"\nlegend: NT/MF/K? = N true-positives / M false-positives / K unknown per (pattern, workspace)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--demote", action="store_true")
    ap.add_argument("--promote", action="store_true")
    ap.add_argument("--by-workspace", action="store_true",
                    help="emit (pattern, workspace) verdict-count matrix")
    args = ap.parse_args()

    if args.by_workspace:
        patterns, workspaces, cells = build_workspace_matrix()
        if args.json:
            out = [
                {"pattern": p, "workspace": ws, **cells[(p, ws)]}
                for (p, ws) in cells
            ]
            print(json.dumps(out, indent=2, default=str))
            return
        print_workspace_matrix(patterns, workspaces, cells)
        return

    rows = build_table()
    if args.json:
        print(json.dumps(rows, indent=2, default=str))
        return
    if args.demote:
        cands = demote_candidates(rows)
        print(f"Demotion candidates ({len(cands)}): triaged ≥ 5 AND tp = 0")
        for r in cands:
            print(f"  {r['pattern']}  triaged={r['triaged']}  fp={r['fp']}")
        return
    if args.promote:
        cands = promote_candidates(rows)
        print(f"Promotion candidates ({len(cands)}): tp ≥ 3 AND precision ≥ 0.5")
        for r in cands:
            print(f"  {r['pattern']}  tp={r['tp']}  precision={r['precision']:.2f}")
        return
    print_table(rows)


if __name__ == "__main__":
    main()
