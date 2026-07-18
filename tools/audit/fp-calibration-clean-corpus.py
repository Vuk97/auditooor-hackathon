#!/usr/bin/env python3
"""Universal-FP known-clean calibration runner (Wave-5 lane W5-A3 / S06 FP-2).

The universal FP runner (``tools/audit/universal_fp_runner.py``) fires
FP-01..FP-06 regex/structural shapes against a target workspace. The W4.7
FP/TP feedback loop (``tools/audit/fp_tp_feedback_loop.py``) joins those
hits to a verdict ledger to compute per-FP-shape precision - but the
ledger ships empty, so every shape classifies ``insufficient`` and
precision is unknown.

This tool closes that day-one gap. It runs the universal FP runner against
the known-clean calibration corpus
(``tests/fixtures/fp_clean_corpus/`` - released OpenZeppelin / Solady /
Solmate library source vendored at pinned tags). Those files are presumed
clean by construction: any runner hit on them is, by definition, a FALSE
POSITIVE.

It then:

  1. Treats every hit as an FP.
  2. Emits one ``auditooor.fp_verdict_ledger.v1`` row per hit, verdict
     ``FP``, ``recorded_by`` ``calibration``, ``workspace`` tagged
     ``calibration-clean`` so calibration verdicts are distinguishable
     from real-hunt verdicts.
  3. Computes a per-FP-shape FP rate on the clean corpus: the count of
     hits each FP shape fired (since every hit is an FP, the "rate" is
     the absolute calibration-FP count per shape - a shape that fires 0
     hits on the clean corpus has a clean calibration baseline).
  4. Emits an ``auditooor.fp_clean_corpus_calibration.v1`` JSON summary.

Append-safety: the verdict ledger is append-only JSONL. Re-running this
tool appends fresh calibration rows with a newer ``recorded_at``; the
feedback loop dedupes by ``(fp_id, file_basename, line)`` so re-runs never
double-count. Use ``--dedupe-prune`` to drop prior calibration rows for
the same corpus before appending (keeps the ledger from growing on every
CI run).

Stdlib only. No network. No mutation of the corpus.

CLI surface:

  --corpus <path>     Clean corpus root (default:
                      <repo>/tests/fixtures/fp_clean_corpus).
  --fp-dir <path>     FP YAML dir (default: <repo>/audit/corpus_tags/tags).
  --ledger <path>     Verdict ledger to append to (default:
                      <repo>/audit/fp_verdict_ledger.jsonl).
  --runner <path>     universal_fp_runner.py path (default: sibling).
  --json              Emit the calibration summary JSON to stdout.
  --output <path>     Write the calibration summary JSON to a file.
  --no-append         Compute + report only; do NOT touch the ledger.
  --dedupe-prune      Drop prior recorded_by=calibration rows for this
                      corpus before appending the fresh set.
  --strict            Exit 1 if any FP shape fires above
                      --max-clean-hits on the clean corpus.
  --max-clean-hits N  Per-shape clean-corpus hit ceiling for --strict
                      (default 0: a clean library should produce 0).
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import subprocess
import sys
from pathlib import Path

SCHEMA_VERSION = "auditooor.fp_clean_corpus_calibration.v1"
LEDGER_SCHEMA = "auditooor.fp_verdict_ledger.v1"
CALIBRATION_WORKSPACE = "calibration-clean"
CALIBRATION_RECORDER = "calibration"


def _repo_root() -> Path:
    """Repo root: this file lives at <root>/tools/audit/."""
    return Path(__file__).resolve().parents[2]


def _utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def run_universal_fp_runner(runner: Path, corpus: Path, fp_dir: Path) -> dict:
    """Invoke the universal FP runner as a subprocess against the corpus.

    The clean corpus deliberately uses ``--no-blacklist`` so every hit
    is surfaced - the corpus contains only library source, so there are
    no test/mock subtrees to suppress, and a calibration run must see
    EVERY hit to be honest about the FP rate.
    """
    cmd = [
        sys.executable,
        str(runner),
        "--workspace",
        str(corpus),
        "--fp-dir",
        str(fp_dir),
        "--json",
        "--no-blacklist",
        "--target-language",
        "solidity",
    ]
    proc = subprocess.run(
        cmd, capture_output=True, text=True, check=False
    )
    if proc.returncode not in (0, 1):
        sys.stderr.write(
            "[fp-calibration-clean-corpus] runner failed rc=%d\n%s\n"
            % (proc.returncode, proc.stderr)
        )
        raise SystemExit(2)
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        sys.stderr.write(
            "[fp-calibration-clean-corpus] runner emitted non-JSON: %s\n"
            % exc
        )
        raise SystemExit(2)


def hits_to_verdict_rows(hits: list, recorded_at: str) -> list:
    """Map every runner hit to an FP verdict-ledger row.

    Every hit on the known-clean corpus is an FP by construction.
    """
    rows = []
    for h in hits:
        rows.append(
            {
                "schema": LEDGER_SCHEMA,
                "fp_id": h.get("fp_id", ""),
                "workspace": CALIBRATION_WORKSPACE,
                "file": h.get("file", ""),
                "line": int(h.get("line", 0) or 0),
                "verdict": "FP",
                "function": h.get("function", ""),
                "note": (
                    "calibration: hit on known-clean library corpus "
                    "(presumed-clean by construction)"
                ),
                "recorded_at": recorded_at,
                "recorded_by": CALIBRATION_RECORDER,
            }
        )
    return rows


def per_fp_calibration_table(envelope: dict, rows: list) -> list:
    """Per-FP-shape clean-corpus FP rate.

    For each FP shape evaluated by the runner, report the number of
    hits it fired on the clean corpus. Since every clean-corpus hit is
    an FP, that count IS the calibration-FP count. A shape with 0 hits
    has a clean baseline; a shape with N>0 has a measured day-one FP
    floor of N on audited library code.
    """
    hits_per_fp = envelope.get("hits_per_fp", {}) or {}
    table = []
    for fp in envelope.get("fps_evaluated", []):
        fp_id = fp.get("fp_id", "")
        n = int(hits_per_fp.get(fp_id, 0) or 0)
        if n == 0:
            verdict = "clean-baseline"
        elif n <= 3:
            verdict = "low-noise"
        else:
            verdict = "noisy-on-clean-corpus"
        table.append(
            {
                "fp_id": fp_id,
                "bug_class": fp.get("bug_class", ""),
                "attack_class": fp.get("attack_class", ""),
                "strategy_available": fp.get("strategy_available", False),
                "clean_corpus_hits": n,
                "clean_corpus_fp_rate": n,
                "calibration_verdict": verdict,
            }
        )
    return sorted(table, key=lambda r: r["fp_id"])


def append_rows(ledger: Path, rows: list, dedupe_prune: bool) -> int:
    """Append calibration verdict rows to the JSONL ledger.

    With ``dedupe_prune`` set, prior ``recorded_by=calibration`` rows
    whose ``workspace`` is the calibration workspace are dropped first,
    so the ledger does not accumulate one stale calibration set per
    run. Real-hunt verdict rows are never touched.
    """
    existing_lines = []
    if ledger.exists():
        existing_lines = ledger.read_text().splitlines()

    kept = []
    for ln in existing_lines:
        stripped = ln.strip()
        if not stripped or stripped.startswith("#"):
            kept.append(ln)
            continue
        if dedupe_prune:
            try:
                obj = json.loads(stripped)
            except json.JSONDecodeError:
                kept.append(ln)
                continue
            is_calib = (
                obj.get("recorded_by") == CALIBRATION_RECORDER
                and obj.get("workspace") == CALIBRATION_WORKSPACE
            )
            if is_calib:
                continue
            kept.append(ln)
        else:
            kept.append(ln)

    out_lines = list(kept)
    for r in rows:
        out_lines.append(json.dumps(r, sort_keys=True))

    ledger.write_text("\n".join(out_lines) + "\n")
    return len(rows)


def build_summary(corpus: Path, envelope: dict, rows: list,
                  table: list, recorded_at: str,
                  appended: int) -> dict:
    return {
        "schema": SCHEMA_VERSION,
        "lane": "W5-A3",
        "generated_at": recorded_at,
        "corpus_root": str(corpus),
        "corpus_files_scanned": _count_sol_files(corpus),
        "total_clean_corpus_hits": envelope.get("total_hits", 0),
        "verdict_rows_emitted": len(rows),
        "verdict_rows_appended_to_ledger": appended,
        "per_fp_calibration": table,
        "interpretation": (
            "Every hit on this corpus is an FP by construction; the "
            "clean_corpus_hits column is the measured day-one FP floor "
            "of each universal FP shape on audited library code."
        ),
    }


def _count_sol_files(corpus: Path) -> int:
    return sum(1 for _ in corpus.rglob("*.sol"))


def main(argv: list) -> int:
    repo = _repo_root()
    p = argparse.ArgumentParser(
        description=(
            "Run the universal FP runner against the known-clean "
            "calibration corpus and seed the FP verdict ledger."
        )
    )
    p.add_argument(
        "--corpus",
        default=str(repo / "tests" / "fixtures" / "fp_clean_corpus"),
    )
    p.add_argument(
        "--fp-dir",
        default=str(repo / "audit" / "corpus_tags" / "tags"),
    )
    p.add_argument(
        "--ledger",
        default=str(repo / "audit" / "fp_verdict_ledger.jsonl"),
    )
    p.add_argument(
        "--runner",
        default=str(repo / "tools" / "audit" / "universal_fp_runner.py"),
    )
    p.add_argument("--json", action="store_true", default=True)
    p.add_argument("--output", default="")
    p.add_argument("--no-append", action="store_true")
    p.add_argument("--dedupe-prune", action="store_true")
    p.add_argument("--strict", action="store_true")
    p.add_argument("--max-clean-hits", type=int, default=0)
    args = p.parse_args(argv)

    corpus = Path(args.corpus).expanduser().resolve()
    fp_dir = Path(args.fp_dir).expanduser().resolve()
    ledger = Path(args.ledger).expanduser().resolve()
    runner = Path(args.runner).expanduser().resolve()

    if not corpus.is_dir():
        sys.stderr.write(
            "[fp-calibration-clean-corpus] corpus not found: %s\n" % corpus
        )
        return 2
    if not runner.is_file():
        sys.stderr.write(
            "[fp-calibration-clean-corpus] runner not found: %s\n" % runner
        )
        return 2

    recorded_at = _utc_now()
    envelope = run_universal_fp_runner(runner, corpus, fp_dir)
    hits = envelope.get("hits", []) or []
    rows = hits_to_verdict_rows(hits, recorded_at)
    table = per_fp_calibration_table(envelope, rows)

    appended = 0
    if not args.no_append:
        appended = append_rows(ledger, rows, args.dedupe_prune)

    summary = build_summary(
        corpus, envelope, rows, table, recorded_at, appended
    )

    payload = json.dumps(summary, indent=2, sort_keys=True)
    if args.output:
        Path(args.output).write_text(payload + "\n")
    if args.json or not args.output:
        print(payload)

    if args.strict:
        for r in table:
            if r["clean_corpus_hits"] > args.max_clean_hits:
                sys.stderr.write(
                    "[fp-calibration-clean-corpus] strict: %s fired %d "
                    "hits on clean corpus (> %d)\n"
                    % (r["fp_id"], r["clean_corpus_hits"],
                       args.max_clean_hits)
                )
                return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
