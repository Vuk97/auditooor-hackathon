#!/usr/bin/env python3
"""Early structural GUARD-TRIAGE: a cheap, no-fuzz pass that ranks in-scope
functions by guard-risk BEFORE the expensive per-fn hunt / mutation work, so the
hunt works the riskiest surface first and coverage can skip no-logic fns.

WHY (operator 2026-06-23): guard analysis (guard-negative-space + sibling-path-
guard-diff) currently runs at STEP-4, AFTER the expensive step-2 fuzz + step-4b
mutation. But "does fn A have an access-control / balance / bounds guard, and does
its sibling lack one?" is a STRUCTURAL question answerable cheaply + early. Running
it up front (a) surfaces missing-guard findings sooner and (b) prioritizes the
hunt toward guard-risky functions instead of spending the first agents on view
proxies. It does NOT replace mutation-verified coverage (different question) - it
FOCUSES it.

This synthesizes the existing guard artifacts (sibling_guard_asymmetries.jsonl +
negative_space_worklist.jsonl, produced by the step-4 analyzers) into a ranked
guard-risk map at .auditooor/guard_triage.json. ADDITIVE + advisory: it never
weakens a gate; it emits a priority ordering the hunt can consume. Generic across
any workspace that has run the guard analyzers (run them first; this tool degrades
to an empty triage with a hint when the inputs are absent).

Risk signals (per function):
  +2  a sibling pair where THIS fn is missing a guard its sibling has (real .sol)
  +1  a negative-space guard whose `kinds` mention access-control / balance /
      bounds / reentrancy on THIS fn's file_line
Functions are ranked desc by score; ties broken by name for determinism.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

SCHEMA = "auditooor.guard_triage.v1"
_HI_KINDS = ("access", "owner", "auth", "balance", "bound", "reentran", "overflow",
             "underflow", "fee", "liquidat")


def _read_jsonl(p: Path) -> list[dict]:
    if not p.is_file():
        return []
    out = []
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def _is_sol(s: str) -> bool:
    return str(s or "").endswith(".sol")


def triage(ws: Path) -> dict:
    asym = _read_jsonl(ws / ".auditooor" / "sibling_guard_asymmetries.jsonl")
    nspace = _read_jsonl(ws / ".auditooor" / "negative_space_worklist.jsonl")

    score: dict[str, int] = defaultdict(int)
    why: dict[str, list[str]] = defaultdict(list)
    fn_loc: dict[str, str] = {}

    # (1) sibling asymmetries: a real .sol pair where a guard is missing on one side.
    real_pairs = 0
    for row in asym:
        pa, pb = row.get("path_a") or {}, row.get("path_b") or {}
        fa, fb = pa.get("file", ""), pb.get("file", "")
        if not (_is_sol(fa) and _is_sol(fb)):
            continue  # tooling-noise (non-.sol heuristic pair)
        real_pairs += 1
        # fn missing a guard its sibling has = the higher-risk side
        if row.get("guard_on_b_missing_on_a") and pa.get("name"):
            key = f"{fa}:{pa['name']}"
            score[key] += 2
            why[key].append("missing %s vs sibling %s" % (
                ",".join(row["guard_on_b_missing_on_a"][:3]), pb.get("name", "?")))
            fn_loc[key] = f"{fa}:{pa.get('line','')}"
        if row.get("guard_on_a_missing_on_b") and pb.get("name"):
            key = f"{fb}:{pb['name']}"
            score[key] += 2
            why[key].append("missing %s vs sibling %s" % (
                ",".join(row["guard_on_a_missing_on_b"][:3]), pa.get("name", "?")))
            fn_loc[key] = f"{fb}:{pb.get('line','')}"

    # (2) negative-space guards with a high-value kind.
    for row in nspace:
        kinds = " ".join(str(k) for k in (row.get("kinds") or [])) + " " + \
                str(row.get("invariant_hint") or "")
        if not any(h in kinds.lower() for h in _HI_KINDS):
            continue
        fl = row.get("file_line") or ""
        key = fl  # file:line key (negative-space rows are guard-site keyed)
        score[key] += 1
        why[key].append("neg-space guard (%s)" % (kinds.strip()[:40]))
        fn_loc.setdefault(key, fl)

    ranked = sorted(score.items(), key=lambda kv: (-kv[1], kv[0]))
    risk_fns = [{
        "unit": k,
        "loc": fn_loc.get(k, k),
        "score": v,
        "signals": why[k][:4],
    } for k, v in ranked]

    return {
        "schema": SCHEMA,
        "workspace": str(ws),
        "inputs_present": bool(asym or nspace),
        "real_sibling_pairs": real_pairs,
        "negative_space_guards": len(nspace),
        "guard_risk_units": len(risk_fns),
        "hunt_priority_order": [r["unit"] for r in risk_fns],
        "risk_units": risk_fns,
        "note": ("Advisory early guard-triage: hunt these guard-risk units FIRST. "
                 "Does not replace mutation-verified coverage. If inputs absent, run "
                 "guard-negative-space-analyzer + sibling-path-guard-diff first."),
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--out", default=None)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    ws = Path(args.workspace).resolve()
    rep = triage(ws)
    out = Path(args.out) if args.out else ws / ".auditooor" / "guard_triage.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(rep, indent=2) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps(rep, indent=2))
    else:
        print("[guard-triage] %d guard-risk unit(s) ranked (%d real sibling pairs, "
              "%d neg-space guards) -> %s"
              % (rep["guard_risk_units"], rep["real_sibling_pairs"],
                 rep["negative_space_guards"], out))
        for r in rep["risk_units"][:8]:
            print("   [%d] %s  (%s)" % (r["score"], r["loc"], "; ".join(r["signals"][:2])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
