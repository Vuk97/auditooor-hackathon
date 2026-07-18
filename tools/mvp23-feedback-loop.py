#!/usr/bin/env python3
"""mvp23-feedback-loop.py - close the loop from MIMO verdicts back to corpora.

r36-rebuttal: registered lane per-fn-mimo-upgrade-2026-05-27.

After a per-fn MIMO pilot batch completes, this tool:

  1. Reads the pilot's sidecar dir (audit/corpus_tags/derived/mimo_harness_<ws>_perfn_*/)
  2. Per task, joins back to its source (function + invariant + question_class)
  3. Computes per-class yes/no/maybe rates for the pilot
  4. Emits:
     a) Updated hacker-q reweight ledger (per-class signal_score)
     b) Promoted YES candidates -> triage-kill-promoter pipeline (or paste-ready stage)
     c) Killed NO candidates -> known_dead_ends (via existing PostToolUse hook)
     d) Per-fn coverage map (which functions did we actually scrutinize)
     e) Pattern-recommendation file: which hacker-question templates need
        attack_class label correction (e.g. flashloan questions emitted against
        contracts with no flashloan surface should be reclassified)

Output:
  reports/mvp23_feedback_<ws>_<date>.json - summary + recommendations
  audit/corpus_tags/derived/hacker_q_reweight_per_fn_<date>.jsonl - reweight ledger

USAGE:
  python3 tools/mvp23-feedback-loop.py --sidecar-dir <dir> --workspace <ws>
"""
from __future__ import annotations

import argparse
import collections
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = "auditooor.mvp23_feedback.v1"
AUDITOOOR_ROOT = Path(__file__).resolve().parent.parent


def iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_sidecar(p: Path) -> dict | None:
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None
    if d.get("status") != "ok":
        return None
    r = d.get("result", "")
    if not isinstance(r, str) or not r.strip():
        return None
    body = r.strip().strip("`").lstrip("json").strip()
    try:
        j = json.loads(body)
    except json.JSONDecodeError:
        return None
    if not isinstance(j, dict):
        return None
    return {"meta": d, "verdict": j}


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--sidecar-dir", required=True,
                   help="Pilot sidecar dir (e.g. audit/corpus_tags/derived/mimo_harness_hyperbridge_perfn_pilot)")
    p.add_argument("--workspace", required=True)
    p.add_argument("--batch-jsonl", default=None,
                   help="Original per-fn batch JSONL (for joining back to fn metadata)")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)

    sd = Path(args.sidecar_dir)
    ws_name = Path(args.workspace).name

    # Load batch metadata if available (for joining task_id -> fn/class)
    batch_meta = {}
    if args.batch_jsonl:
        try:
            with open(args.batch_jsonl) as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        t = json.loads(line)
                        batch_meta[t.get("task_id")] = t
                    except json.JSONDecodeError:
                        continue
        except (OSError, FileNotFoundError):
            pass

    # Parse all sidecars
    rows = []
    for f in sorted(sd.glob("*.json")):
        parsed = parse_sidecar(f)
        if parsed:
            rows.append(parsed)

    sys.stderr.write(f"[feedback] parsed {len(rows)} verdicts from {sd}\n")
    if not rows:
        return 1

    # Per-class yes/no/maybe
    by_class = collections.defaultdict(lambda: collections.Counter())
    by_fn = collections.defaultdict(lambda: collections.Counter())
    yes_findings = []
    kill_recommendations = []
    hallucination_recommendations = []
    coverage_fns = set()

    for r in rows:
        v = r["verdict"]
        task_id = r["meta"].get("task_id", "?")
        applies = v.get("applies_to_target", "?")
        klass = "generic"
        fn = "?"
        file_anchor = ""
        if task_id in batch_meta:
            m = batch_meta[task_id]
            klass_split = (m.get("source_question_id") or "").split(":")
            if len(klass_split) >= 2:
                klass = klass_split[-1]
            fa = m.get("function_anchor", {})
            fn = fa.get("fn", "?")
            file_anchor = fa.get("file", "")
        by_class[klass][applies] += 1
        if fn != "?":
            by_fn[f"{file_anchor}::{fn}"][applies] += 1
            coverage_fns.add(f"{file_anchor}::{fn}")

        if applies == "yes":
            yes_findings.append({
                "task_id": task_id,
                "finding": v.get("candidate_finding", "")[:200],
                "severity": v.get("severity_estimate", "?"),
                "file_line": v.get("file_line", "?"),
                "code_excerpt": v.get("code_excerpt", "")[:300],
                "rubric": v.get("rubric_row_cited", "")[:120],
                "class": klass,
                "fn": fn,
            })
        elif applies == "no":
            reason = v.get("notes", "") or v.get("falsification_attempt", "")
            kill_recommendations.append({
                "task_id": task_id,
                "fn": fn,
                "class": klass,
                "reason": reason[:200],
            })
            # If the NO is because the surface doesn't exist, flag for class-correction
            if any(k in reason.lower() for k in ("unable-to-anchor", "not in", "does not exist",
                                                  "not found", "no such function", "absent")):
                hallucination_recommendations.append({
                    "task_id": task_id,
                    "fn": fn,
                    "class": klass,
                    "evidence": reason[:200],
                })

    # Compute signal scores per class
    class_scores = {}
    for klass, counts in by_class.items():
        yes = counts.get("yes", 0)
        no = counts.get("no", 0)
        maybe = counts.get("maybe", 0)
        total = yes + no + maybe
        if total > 0:
            class_scores[klass] = {
                "yes": yes, "no": no, "maybe": maybe, "total": total,
                "yes_rate": yes / total,
                "signal_score": round(yes * 5 + maybe * 1 - no * 0.1, 3),
                "signal_class": (
                    "HIGH-SIGNAL" if yes > 0 else
                    "MEDIUM-SIGNAL" if maybe >= 2 and maybe / total >= 0.2 else
                    "LOW-SIGNAL-DEPRIORITIZE" if no / total >= 0.95 and total >= 5 else
                    "INSUFFICIENT-DATA"
                ),
            }

    # Output reports
    date = datetime.now().strftime("%Y-%m-%d")
    out_dir = AUDITOOOR_ROOT / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    summary_path = out_dir / f"mvp23_feedback_{ws_name}_{date}.json"
    reweight_path = AUDITOOOR_ROOT / "audit/corpus_tags/derived" / f"hacker_q_reweight_per_fn_{date}.jsonl"

    summary = {
        "schema_version": SCHEMA,
        "timestamp": iso_now(),
        "workspace": ws_name,
        "sidecar_dir": str(sd),
        "total_verdicts": len(rows),
        "yes_count": len(yes_findings),
        "no_count": sum(1 for r in rows if r["verdict"].get("applies_to_target") == "no"),
        "maybe_count": sum(1 for r in rows if r["verdict"].get("applies_to_target") == "maybe"),
        "yes_rate": (len(yes_findings) / len(rows)) if rows else 0,
        "unique_fns_covered": len(coverage_fns),
        "class_scores": class_scores,
        "yes_findings": yes_findings,
        "kill_recommendations_count": len(kill_recommendations),
        "hallucination_recommendations_count": len(hallucination_recommendations),
        "hallucination_class_distribution": dict(
            collections.Counter(h["class"] for h in hallucination_recommendations).most_common(10)
        ),
    }
    summary_path.write_text(json.dumps(summary, indent=2))

    # Reweight ledger
    with reweight_path.open("w") as fh:
        for klass, sc in class_scores.items():
            fh.write(json.dumps({
                "schema_version": "auditooor.hacker_q_reweight.v1",
                "question_class": klass,
                "workspace": ws_name,
                **sc,
                "promoted_at_utc": iso_now(),
            }) + "\n")

    sys.stderr.write(f"[feedback] summary: {summary_path}\n")
    sys.stderr.write(f"[feedback] reweight: {reweight_path}\n")

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"verdicts: {summary['total_verdicts']}")
        print(f"YES: {summary['yes_count']} ({summary['yes_rate']:.1%}) | "
              f"MAYBE: {summary['maybe_count']} | "
              f"NO: {summary['no_count']}")
        print(f"unique fns scrutinized: {summary['unique_fns_covered']}")
        print(f"\nPer-class signal:")
        for klass, sc in sorted(class_scores.items(),
                                 key=lambda x: -x[1].get("signal_score", 0)):
            print(f"  {klass:30s} yes={sc['yes']:3d} maybe={sc['maybe']:3d} no={sc['no']:3d} "
                  f"({sc['yes_rate']:.1%} yes) score={sc['signal_score']} "
                  f"[{sc['signal_class']}]")
        if summary["hallucination_recommendations_count"] > 0:
            print(f"\nHallucination recommendations: {summary['hallucination_recommendations_count']} "
                  f"questions hit non-existent surface")
            print(f"  by class: {summary['hallucination_class_distribution']}")
        if yes_findings:
            print(f"\nYES findings (top 5):")
            for f in yes_findings[:5]:
                print(f"  {f['severity']:8s} [{f['class']:20s}] {f['fn']}: {f['finding'][:100]}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
