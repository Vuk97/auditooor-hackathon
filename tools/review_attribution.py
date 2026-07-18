#!/usr/bin/env python3
"""review_attribution - the reverse-evolution defense (article Part III, point 3).

Two jobs:

1. ATTRIBUTE. When an audit-complete gate FAILS (or a finding is missed), record
   WHICH of the four causes it was, per the methodology:
     - task-design      : the task/threat-model was under-specified (no witness,
                          wrong target, no completion contract)
     - context          : the brief lacked the key paths/states/variables/scope
     - reasoning        : task+context were fine but the reasoner/model failed
     - verification-artifacts : found-but-not-proven / not-preserved / bad report
   The record lands in a CROSS-WORKSPACE ledger (`audit/review_attributions.jsonl`).

2. ADMIT (the anti-inflation gate). A change to the GLOBAL layer (CLAUDE.md, a
   global rule/gate, a prompt preamble) is admitted ONLY when the same
   (subject, attribution_class) repeats across >= N DISTINCT workspaces. A
   single-workspace miss is fixed LOCALLY, never by growing the global prompt.
   This is the direct defense against reverse evolution: it stops one miss from
   spawning one permanent global rule (the mechanism that bloated CLAUDE.md).

Language- and platform-agnostic: it keys on gate names + workspace identity,
never on Solidity/Go/Rust specifics. Deterministic + offline. Timestamps honor
AUDITOOOR_FAKE_UTC (mirrors the repo convention) so tests/resume are stable.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import sys
from pathlib import Path

ATTRIBUTION_CLASSES = ("task-design", "context", "reasoning", "verification-artifacts")

_REPO = Path(__file__).resolve().parent.parent
LEDGER = _REPO / "audit" / "review_attributions.jsonl"

# Provisional attribution of a FAILING audit-complete gate to its most likely
# root-cause class. This is a STARTING point (the operator/analysis can override
# via an explicit `record`), chosen so the cross-workspace signal accumulates
# automatically. Grouped by gate family:
_GATE_ATTRIBUTION = {
    # coverage / enumeration gaps => the task space was not fully decomposed
    "coverage-map": "task-design",
    "function-coverage": "task-design",
    "cross-function-coverage": "task-design",
    "completeness-matrix": "task-design",
    "rubric-coverage": "task-design",
    "hacker-questions": "task-design",
    "unhunted-followthrough": "task-design",
    # scope / rubric mis-framing => the brief carried the wrong context
    "inscope-disposition": "context",
    "impact-methodology-corpus": "context",
    "fork-divergence": "context",
    # the hunt ran but under-produced => reasoning
    "hunt-trust": "reasoning",
    "hunt-complete": "reasoning",
    "novel-vector": "reasoning",
    "adversarial-panel": "reasoning",
    # evidence / harness / proof honesty => verification & artifacts
    "hollow-not-genuinely-audited": "verification-artifacts",
    "engine-harness": "verification-artifacts",
    "invariant-fuzz": "verification-artifacts",
    "core-coverage": "verification-artifacts",
    "exploit-class": "verification-artifacts",
    "depth-certificate": "verification-artifacts",
    "live-engines": "verification-artifacts",
    "exploit-queue": "verification-artifacts",
    "prove-top-leads": "verification-artifacts",
    "evm-0day-proof": "verification-artifacts",
}


def classify_gate(gate_name: str) -> str:
    """Provisional attribution class for a failing gate (default reasoning)."""
    return _GATE_ATTRIBUTION.get((gate_name or "").strip(), "reasoning")


def _utc_now() -> str:
    inj = os.environ.get("AUDITOOOR_FAKE_UTC")
    if inj:
        return inj
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ws_name(ws: str) -> str:
    return Path(ws).name or str(ws)


def record(ws: str, subject: str, klass: str, note: str = "",
           ledger: Path = LEDGER) -> dict:
    if klass not in ATTRIBUTION_CLASSES:
        raise ValueError(f"attribution_class must be one of {ATTRIBUTION_CLASSES}, got {klass!r}")
    row = {
        "schema": "auditooor.review_attribution.v1",
        "workspace": _ws_name(ws),
        "subject": str(subject).strip(),
        "attribution_class": klass,
        "note": str(note)[:500],
        "ts": _utc_now(),
    }
    ledger.parent.mkdir(parents=True, exist_ok=True)
    with ledger.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, sort_keys=True) + "\n")
    return row


def _load_ledger(ledger: Path = LEDGER) -> list:
    rows = []
    try:
        for line in ledger.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if isinstance(r, dict):
                rows.append(r)
    except OSError:
        pass
    return rows


def admit(subject: str, klass: str, threshold: int = 3, ledger: Path = LEDGER) -> dict:
    """Admission gate: is a GLOBAL change to `subject` (of attribution class
    `klass`) justified? YES iff the same (subject, class) is attributed across
    >= threshold DISTINCT workspaces. Otherwise it is a single/few-workspace
    issue -> fix locally, do NOT globalize (anti reverse-evolution)."""
    subject = str(subject).strip()
    rows = _load_ledger(ledger)
    wss = {r.get("workspace") for r in rows
           if r.get("subject") == subject and r.get("attribution_class") == klass}
    wss.discard(None)
    n = len(wss)
    ok = n >= threshold
    return {
        "verdict": "pass-admit-global-change" if ok else "hold-fix-locally",
        "subject": subject, "attribution_class": klass,
        "distinct_workspaces": n, "threshold": threshold,
        "workspaces": sorted(w for w in wss if w),
        "reason": (f"attributed across {n} distinct workspace(s) (>= {threshold}) - "
                   "a repeating cross-workspace pattern, safe to lift to the global layer"
                   if ok else
                   f"only {n} distinct workspace(s) (< {threshold}) - a local issue; "
                   "fix it in the workspace / a local tool, do NOT grow the global prompt "
                   "(reverse-evolution guard)"),
    }


def from_audit_complete(ws: str, ledger: Path = LEDGER) -> dict:
    """Read the workspace's audit-complete result and record a provisional
    attribution for every FAILING gate, so the cross-workspace signal builds
    automatically. Idempotent-ish: appends one row per failing gate per call
    (dedup on read is by (ws,subject,class) set, so repeats do not inflate the
    admission count)."""
    res_path = Path(ws) / ".auditooor" / "audit_complete_last_result.json"
    recorded = []
    try:
        data = json.loads(res_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"recorded": [], "note": f"no audit_complete_last_result.json at {res_path}"}
    signals = data.get("signals") or data.get("results") or []
    fails = []
    if isinstance(signals, list):
        for s in signals:
            if isinstance(s, dict) and s.get("ok") is False:
                fails.append(str(s.get("signal") or s.get("name") or ""))
    for gate in fails:
        if not gate:
            continue
        klass = classify_gate(gate)
        row = record(ws, subject=f"gate:{gate}", klass=klass,
                     note="auto-attributed from audit-complete FAIL", ledger=ledger)
        recorded.append(row)
    return {"recorded": recorded, "fail_gates": fails}


def from_missed_findings(ws: str, ledger: Path = LEDGER) -> dict:
    """The second attribution feed (P3): every MISSED FINDING, not just a gate
    FAIL. Reads <ws>/.auditooor/missed_findings.jsonl - one row per finding the
    audit should have caught but did not (written by a post-mortem / outcome ETL:
    a rejected-as-real submission, a bug found by another party, a prior-audit
    finding we re-derived late). Each carries its own attribution_class; default
    'reasoning' (task+context were there, the hunt missed it). Records
    subject=miss:<finding_id> so a recurring miss-class accumulates toward the
    admission threshold like a gate-fail does."""
    p = Path(ws) / ".auditooor" / "missed_findings.jsonl"
    recorded = []
    try:
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return {"recorded": [], "note": f"no missed_findings.jsonl at {p}"}
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except ValueError:
            continue
        if not isinstance(r, dict):
            continue
        fid = str(r.get("finding_id") or r.get("id") or r.get("title") or "").strip()
        if not fid:
            continue
        klass = str(r.get("attribution_class") or "reasoning").strip()
        if klass not in ATTRIBUTION_CLASSES:
            klass = "reasoning"
        row = record(ws, subject=f"miss:{fid}", klass=klass,
                     note=str(r.get("note") or "missed finding (post-mortem)")[:300],
                     ledger=ledger)
        recorded.append(row)
    return {"recorded": recorded, "missed_count": len(recorded)}


def report(ledger: Path = LEDGER) -> dict:
    rows = _load_ledger(ledger)
    by_subject: dict = {}
    for r in rows:
        key = (r.get("subject"), r.get("attribution_class"))
        by_subject.setdefault(key, set()).add(r.get("workspace"))
    ranked = sorted(
        ({"subject": k[0], "attribution_class": k[1],
          "distinct_workspaces": len({w for w in v if w})} for k, v in by_subject.items()),
        key=lambda x: -x["distinct_workspaces"])
    return {"total_rows": len(rows), "distinct_subjects": len(by_subject), "ranked": ranked}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    pr = sub.add_parser("record", help="record an attribution")
    pr.add_argument("--workspace", required=True)
    pr.add_argument("--subject", required=True)
    pr.add_argument("--class", dest="klass", required=True, choices=ATTRIBUTION_CLASSES)
    pr.add_argument("--note", default="")

    pa = sub.add_parser("admit", help="admission gate for a global change")
    pa.add_argument("--subject", required=True)
    pa.add_argument("--class", dest="klass", required=True, choices=ATTRIBUTION_CLASSES)
    pa.add_argument("--threshold", type=int, default=3)

    pf = sub.add_parser("from-audit-complete", help="auto-attribute failing gates")
    pf.add_argument("--workspace", required=True)

    pm = sub.add_parser("from-missed-findings", help="attribute missed findings (post-mortem feed)")
    pm.add_argument("--workspace", required=True)

    sub.add_parser("report", help="cross-workspace attribution summary")

    for p in (pr, pa, pf, pm):
        p.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    if args.cmd == "record":
        row = record(args.workspace, args.subject, args.klass, args.note)
        print(json.dumps(row, indent=2) if getattr(args, "json", False) else
              f"[review-attribution] recorded {row['subject']} -> {row['attribution_class']} ({row['workspace']})")
        return 0
    if args.cmd == "admit":
        rep = admit(args.subject, args.klass, args.threshold)
        print(json.dumps(rep, indent=2) if getattr(args, "json", False) else
              f"[review-attribution] {rep['verdict']}: {rep['reason']}")
        return 0 if rep["verdict"].startswith("pass-") else 1
    if args.cmd == "from-audit-complete":
        rep = from_audit_complete(args.workspace)
        print(json.dumps(rep, indent=2) if getattr(args, "json", False) else
              f"[review-attribution] recorded {len(rep['recorded'])} failing-gate attribution(s)")
        return 0
    if args.cmd == "from-missed-findings":
        rep = from_missed_findings(args.workspace)
        print(json.dumps(rep, indent=2) if getattr(args, "json", False) else
              f"[review-attribution] recorded {len(rep['recorded'])} missed-finding attribution(s)")
        return 0
    if args.cmd == "report":
        print(json.dumps(report(), indent=2))
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
