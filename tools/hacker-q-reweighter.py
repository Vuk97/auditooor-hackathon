#!/usr/bin/env python3
"""hacker-q-reweighter.py - auto-deprioritize high-NO-rate hacker questions.

r36-rebuttal: registered lane reweighter-persist-fix (canonical .auditooor/agent_pathspec.json); persist + learning-closeout wiring.

Operator's "no detector auto-tune from KILL frequency" gap. A hypothesis
class with 95% applies=no rate is mostly noise - should be deprioritized
in the next harness batch.

This tool:
  1. Scans all mimo_harness_<ws>* sidecars
  2. For each hypothesis (by source_question_id), computes
     applies=yes / maybe / no rate
  3. Assigns a `signal_score`: yes_count * 5 + maybe_count * 1 - no_count * 0.1
  4. Writes a reweight ledger at:
     audit/corpus_tags/derived/hacker_q_reweight_<date>.jsonl
  5. Tool mimo-harness-batch-gen.py can consume this to weight sampling.

USAGE:
  python3 tools/hacker-q-reweighter.py [--min-evals 3] [--out <path>] [--json]
"""
from __future__ import annotations

import argparse
import collections
import glob
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

AUDITOOOR_ROOT = Path(__file__).resolve().parent.parent
SCHEMA = "auditooor.hacker_q_reweight.v1"

# <!-- r36-rebuttal: registered lane reweighter-persist-fix in .auditooor/agent_pathspec.json -->
# Canonical, stable reweight ledger path (always updated when --out is omitted),
# so the wired Makefile call (`--json`, no --out) persists durable learning instead
# of being print-only. Consumers that glob hacker_q_reweight_*.jsonl pick the most
# recent file; the canonical name is the predictable handle for tooling that wants
# "the current reweight scores".
CANONICAL_REWEIGHT_LEDGER = (
    AUDITOOOR_ROOT / "audit/corpus_tags/derived" / "hacker_q_reweight_latest.jsonl"
)


def iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def scan_sidecars() -> dict:
    """Return {source_q_id: [list of applies values]}."""
    by_q = collections.defaultdict(list)
    pattern = str(AUDITOOOR_ROOT / "audit/corpus_tags/derived/mimo_harness_*/*.json")
    n_scanned = 0
    for f in glob.glob(pattern):
        try:
            d = json.loads(Path(f).read_text())
        except Exception:
            continue
        n_scanned += 1
        if d.get("status") != "ok":
            continue
        r = d.get("result", "")
        if not isinstance(r, str) or not r.strip():
            continue
        body = r.strip().strip("`").lstrip("json").strip()
        try:
            j = json.loads(body)
        except json.JSONDecodeError:
            continue
        if not isinstance(j, dict):
            continue
        qid = d.get("source_question_id") or "<unknown>"
        applies = j.get("applies_to_target", "?")
        by_q[qid].append(applies)
    sys.stderr.write(f"[reweighter] scanned {n_scanned} sidecars; "
                     f"{len(by_q)} unique hacker questions\n")
    return by_q


def score(applies_list: list) -> dict:
    yes = sum(1 for a in applies_list if a == "yes")
    maybe = sum(1 for a in applies_list if a == "maybe")
    no = sum(1 for a in applies_list if a == "no")
    total = yes + maybe + no
    score_val = yes * 5 + maybe * 1 - no * 0.1
    return {
        "yes_count": yes, "maybe_count": maybe, "no_count": no,
        "total_evals": total,
        "yes_rate": (yes / total) if total else 0.0,
        "maybe_rate": (maybe / total) if total else 0.0,
        "no_rate": (no / total) if total else 0.0,
        "signal_score": round(score_val, 3),
    }


def classify(metrics: dict) -> str:
    """Bucket the hypothesis."""
    if metrics["yes_count"] > 0:
        return "HIGH-SIGNAL"
    if metrics["maybe_count"] >= 2 and metrics["maybe_rate"] >= 0.2:
        return "MEDIUM-SIGNAL"
    if metrics["no_rate"] >= 0.95 and metrics["total_evals"] >= 3:
        return "LOW-SIGNAL-DEPRIORITIZE"
    return "INSUFFICIENT-DATA"


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--min-evals", type=int, default=2,
                   help="Min eval count to assign signal (default: 2)")
    p.add_argument("--out", default=None,
                   help="Output JSONL path (default: audit/corpus_tags/derived/hacker_q_reweight_<date>.jsonl)")
    p.add_argument("--json", action="store_true", help="Emit summary JSON to stdout")
    args = p.parse_args(argv)

    by_q = scan_sidecars()
    records = []
    for qid, applies_list in sorted(by_q.items()):
        metrics = score(applies_list)
        if metrics["total_evals"] < args.min_evals:
            continue
        records.append({
            "schema_version": SCHEMA,
            "question_id": qid,
            **metrics,
            "signal_class": classify(metrics),
            "promoted_at_utc": iso_now(),
        })

    # <!-- r36-rebuttal: registered lane reweighter-persist-fix in .auditooor/agent_pathspec.json -->
    # Persistence policy:
    #  - Explicit --out  : honor it exactly (back-compat; manual form unchanged).
    #  - --out omitted    : ALWAYS persist a durable ledger so the wired Makefile
    #                       call (`--json`, no --out) is never print-only. We write
    #                       the canonical stable ledger (predictable handle for
    #                       downstream tooling) PLUS a dated snapshot (history /
    #                       glob-latest consumers).
    written_paths: list[Path] = []
    if args.out:
        out_paths = [Path(args.out)]
    else:
        dated_snapshot = (
            AUDITOOOR_ROOT / "audit/corpus_tags/derived" /
            f"hacker_q_reweight_{datetime.now().strftime('%Y-%m-%d')}.jsonl"
        )
        out_paths = [CANONICAL_REWEIGHT_LEDGER, dated_snapshot]

    for out_path in out_paths:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w") as f:
            for r in records:
                f.write(json.dumps(r) + "\n")
        written_paths.append(out_path)
        sys.stderr.write(
            f"[reweighter] wrote {len(records)} reweight records to {out_path}\n"
        )

    # Reported path for the summary = the primary (first) ledger written.
    out_path = written_paths[0]

    by_class = collections.Counter(r["signal_class"] for r in records)
    summary = {
        "schema_version": "auditooor.hacker_q_reweight_summary.v1",
        "timestamp": iso_now(),
        "unique_questions": len(records),
        "by_class": dict(by_class),
        "out_path": str(out_path),
        # <!-- r36-rebuttal: registered lane reweighter-persist-fix -->
        "written_paths": [str(p) for p in written_paths],
    }
    # Top 10 deprioritize + top 10 high-signal
    deprioritize = sorted(
        [r for r in records if r["signal_class"] == "LOW-SIGNAL-DEPRIORITIZE"],
        key=lambda x: x["no_rate"], reverse=True,
    )[:10]
    high_signal = sorted(
        [r for r in records if r["signal_class"] == "HIGH-SIGNAL"],
        key=lambda x: -x["signal_score"],
    )[:10]
    summary["top_deprioritize"] = [{"question_id": r["question_id"][:80],
                                    "no_count": r["no_count"], "no_rate": r["no_rate"]}
                                    for r in deprioritize]
    summary["top_high_signal"] = [{"question_id": r["question_id"][:80],
                                   "yes_count": r["yes_count"],
                                   "signal_score": r["signal_score"]}
                                   for r in high_signal]

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"reweight records: {len(records)} | by class: {dict(by_class)}")
        print("\nTop 5 to deprioritize (high NO rate):")
        for r in deprioritize[:5]:
            print(f"  {r['no_count']}/{r['total_evals']} NO ({r['no_rate']:.0%}): {r['question_id'][:80]}")
        print("\nTop 5 high-signal (best yield):")
        for r in high_signal[:5]:
            print(f"  score={r['signal_score']} yes={r['yes_count']}: {r['question_id'][:80]}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
