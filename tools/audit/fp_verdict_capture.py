#!/usr/bin/env python3
"""fp-verdict-capture.py - capture FP-runner triage verdicts at hunt closeout.

Wave-5 lane W5-A2 (Section 06 FP-1 + Section 07 W5.5 merge).

Background
----------
The FP/TP feedback loop (``tools/audit/fp_tp_feedback_loop.py``) consumes
``audit/fp_verdict_ledger.jsonl`` (schema ``auditooor.fp_verdict_ledger.v1``)
and computes per-FP-shape precision = TP / (TP + FP). The loop has shipped
since Wave-4, but the ledger has ZERO verdict rows: nothing in the workflow
ever PRODUCES a verdict. The loop is built to consume; this tool is the
missing producer.

What this tool does
-------------------
At hunt closeout it reads:

  1. A universal-fp-runner JSON envelope (``--runner-output``,
     schema ``auditooor.universal_fp_runner.v1``) - the hits.
  2. An operator triage file (``--triage``, default
     ``<ws>/.audit_logs/fp_triage_verdicts.jsonl``) - the genuine
     TP / FP / NEGATIVE judgements the operator recorded during the
     hunt. Each triage record keys a runner hit by
     ``(fp_id, file_basename, line)`` and carries a ``verdict``.

It joins triage records to runner hits on the stable
``(fp_id, file_basename, line)`` key (the same key the feedback loop
uses, tolerant of absolute-path drift), then APPENDS one
``auditooor.fp_verdict_ledger.v1`` row per matched hit to the ledger.

Honesty discipline (M14-trap)
-----------------------------
This tool NEVER fabricates verdicts. It only captures verdicts an
operator genuinely recorded:

  * If no triage file exists, it captures nothing and reports an
    honest empty result (exit 0). The ledger stays empty - that is
    correct, not a failure.
  * A triage record that does not join to any runner hit is reported
    as ``unmatched`` and is NOT written (a verdict with no hit is
    not evidence).
  * ``--auto-negative`` is the ONLY auto-derivation, and it is
    opt-in. It marks hits whose ``path_classification`` is in
    {test, mock, lib, script} as NEGATIVE (reviewed, not a finding,
    not a shape misfire) with ``recorded_by`` ``auto-path-class``.
    This is honest because path-classification is a structural fact,
    not a judgement: a hit in a test file is by-construction not a
    production finding. NEGATIVE rows are excluded from the
    precision denominator, so this cannot inflate precision.

Idempotency / append-safety
---------------------------
The ledger is append-only. Before appending, this tool reads the
existing ledger and skips any verdict whose
``(fp_id, file_basename, line, verdict, recorded_by)`` tuple already
appears - so re-running closeout never double-counts. A genuine
re-triage (verdict flip) is captured because the verdict value is
part of the dedupe tuple: an FP->TP flip is a new tuple and is
appended; the feedback loop's newest-row-wins dedupe then honours it.

Triage file schema (``auditooor.fp_triage_verdicts.v1``), one JSON
object per line (lines beginning ``#`` are comments):

  {
    "schema": "auditooor.fp_triage_verdicts.v1",
    "fp_id": "FP-01",
    "file": "contracts/Staking.sol",   # path OR basename - basename is joined
    "line": 412,
    "verdict": "TP",                   # TP | FP | NEGATIVE
    "note": "missing onlyOwner guard", # optional
    "recorded_by": "operator"          # optional, defaults to "operator"
  }

CLI surface
-----------
  --workspace PATH         Workspace root (used to default --triage
                           and --runner-output, and to label rows).
  --runner-output P[,P..]  universal-fp-runner JSON envelope(s).
                           Defaults to
                           <ws>/.audit_logs/audit_deep/universal-fp-runner.output.json
                           then <ws>/.audit_logs/universal-fp-runner.output.json.
  --triage PATH            operator triage JSONL. Defaults to
                           <ws>/.audit_logs/fp_triage_verdicts.jsonl.
  --ledger PATH            verdict ledger to append to. Defaults to
                           audit/fp_verdict_ledger.jsonl in this repo.
  --auto-negative          additionally emit NEGATIVE rows for
                           test/mock/lib/script-classified hits.
  --workspace-label STR    short label for the ``workspace`` field
                           (default: basename of --workspace).
  --json                   emit a JSON summary to stdout (default on).
  --dry-run                compute and report but do NOT write the
                           ledger.

Stdlib only. No network. Per Rule 37 this tool is a CONSUMER of
runner / triage records and does not emit tier-bearing corpus
records, so emit-time tier discipline is not in scope. Per Rule 36
the tool makes no git-state changes and is invoked under explicit
pathspec.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path


LEDGER_SCHEMA = "auditooor.fp_verdict_ledger.v1"
TRIAGE_SCHEMA = "auditooor.fp_triage_verdicts.v1"
SUMMARY_SCHEMA = "auditooor.fp_verdict_capture.v1"
VALID_VERDICTS = {"TP", "FP", "NEGATIVE"}
AUTO_NEGATIVE_CLASSES = {"test", "mock", "lib", "script"}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def hit_key(fp_id: str, file_path: str, line) -> tuple:
    """Stable join key tolerant of absolute-path drift.

    Identical to the feedback loop's key: (fp_id, basename, line).
    """
    base = os.path.basename(str(file_path).strip())
    try:
        line_i = int(line)
    except (TypeError, ValueError):
        line_i = 0
    return (str(fp_id).strip(), base, line_i)


def load_runner_hits(paths: list) -> list:
    """Load hits from one or more universal-fp-runner envelopes.

    Returns a list of dicts (the raw asdict hit) with an added
    ``_workspace_hint`` from the envelope. Malformed / missing
    envelopes are skipped with a stderr note (never fatal).
    """
    hits = []
    for raw_path in paths:
        p = Path(raw_path)
        if not p.is_file():
            sys.stderr.write(
                "[fp-verdict-capture] runner envelope absent: %s\n" % p
            )
            continue
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            sys.stderr.write(
                "[fp-verdict-capture] skip malformed envelope %s: %s\n"
                % (p, exc)
            )
            continue
        ws_hint = str(doc.get("workspace", "")).strip()
        for h in doc.get("hits", []) or []:
            if not isinstance(h, dict):
                continue
            rec = dict(h)
            rec["_workspace_hint"] = ws_hint
            hits.append(rec)
    return hits


def load_triage(triage_path: Path) -> list:
    """Read an operator triage JSONL.

    Returns a list of dicts with normalised verdict. Comment / blank
    lines and malformed lines are skipped with a stderr note. An
    absent triage file returns [] - the honest-empty path.
    """
    out = []
    if not triage_path.is_file():
        return out
    for lineno, raw in enumerate(
        triage_path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        raw = raw.strip()
        if not raw or raw.startswith("#"):
            continue
        try:
            doc = json.loads(raw)
        except json.JSONDecodeError as exc:
            sys.stderr.write(
                "[fp-verdict-capture] skip malformed triage line %d: %s\n"
                % (lineno, exc)
            )
            continue
        verdict = str(doc.get("verdict", "")).strip().upper()
        if verdict not in VALID_VERDICTS:
            sys.stderr.write(
                "[fp-verdict-capture] skip triage line %d: bad verdict %r\n"
                % (lineno, doc.get("verdict"))
            )
            continue
        fp_id = str(doc.get("fp_id", "")).strip()
        if not fp_id:
            sys.stderr.write(
                "[fp-verdict-capture] skip triage line %d: missing fp_id\n"
                % lineno
            )
            continue
        out.append(
            {
                "fp_id": fp_id,
                "file": str(doc.get("file", "")).strip(),
                "line": doc.get("line", 0),
                "verdict": verdict,
                "note": str(doc.get("note", "")).strip(),
                "recorded_by": str(
                    doc.get("recorded_by", "operator")
                ).strip()
                or "operator",
            }
        )
    return out


def load_existing_keys(ledger_path: Path) -> set:
    """Return the set of dedupe tuples already present in the ledger.

    Dedupe tuple = (fp_id, basename, line, verdict, recorded_by).
    The verdict is part of the tuple so a genuine re-triage flip is
    NOT suppressed; only an identical row is.
    """
    seen = set()
    if not ledger_path.is_file():
        return seen
    for raw in ledger_path.read_text(encoding="utf-8").splitlines():
        raw = raw.strip()
        if not raw or raw.startswith("#"):
            continue
        try:
            doc = json.loads(raw)
        except json.JSONDecodeError:
            continue
        k = hit_key(doc.get("fp_id", ""), doc.get("file", ""), doc.get("line"))
        seen.add(
            k
            + (
                str(doc.get("verdict", "")).strip().upper(),
                str(doc.get("recorded_by", "")).strip(),
            )
        )
    return seen


def capture(
    runner_hits: list,
    triage: list,
    workspace_label: str,
    auto_negative: bool,
    existing_keys: set,
) -> dict:
    """Join triage verdicts to runner hits and build ledger rows.

    Returns a dict with ``rows`` (new ledger rows to append),
    ``unmatched`` (triage records with no runner hit), and counters.
    """
    # Index runner hits by join key. A key may map to several hits
    # (same fp_id/basename/line in different dirs); keep the first
    # for function / path metadata - the join is intentionally
    # basename-tolerant.
    hits_by_key: dict = {}
    for h in runner_hits:
        k = hit_key(h.get("fp_id", ""), h.get("file", ""), h.get("line"))
        hits_by_key.setdefault(k, h)

    now = _utc_now()
    rows = []
    unmatched = []
    captured_keys = set()

    # 1. Operator triage verdicts (the genuine judgements).
    for t in triage:
        k = hit_key(t["fp_id"], t["file"], t["line"])
        hit = hits_by_key.get(k)
        if hit is None:
            unmatched.append(
                {"fp_id": t["fp_id"], "file": t["file"], "line": t["line"]}
            )
            continue
        row = {
            "schema": LEDGER_SCHEMA,
            "fp_id": k[0],
            "workspace": workspace_label,
            "file": hit.get("file", t["file"]),
            "line": k[2],
            "verdict": t["verdict"],
            "function": str(hit.get("function", "")).strip(),
            "note": t["note"],
            "recorded_at": now,
            "recorded_by": t["recorded_by"],
        }
        dedupe = k + (t["verdict"], t["recorded_by"])
        captured_keys.add(k)
        if dedupe in existing_keys:
            continue
        rows.append(row)

    # 2. Opt-in auto-NEGATIVE for structurally non-production hits
    #    that the operator did NOT already triage.
    auto_negatives = 0
    if auto_negative:
        for k, hit in sorted(hits_by_key.items()):
            if k in captured_keys:
                continue
            pclass = str(hit.get("path_classification", "")).strip().lower()
            if pclass not in AUTO_NEGATIVE_CLASSES:
                continue
            row = {
                "schema": LEDGER_SCHEMA,
                "fp_id": k[0],
                "workspace": workspace_label,
                "file": hit.get("file", ""),
                "line": k[2],
                "verdict": "NEGATIVE",
                "function": str(hit.get("function", "")).strip(),
                "note": "auto: path_classification=%s" % pclass,
                "recorded_at": now,
                "recorded_by": "auto-path-class",
            }
            dedupe = k + ("NEGATIVE", "auto-path-class")
            if dedupe in existing_keys:
                continue
            auto_negatives += 1
            rows.append(row)

    by_verdict: dict = {"TP": 0, "FP": 0, "NEGATIVE": 0}
    for r in rows:
        by_verdict[r["verdict"]] = by_verdict.get(r["verdict"], 0) + 1

    return {
        "rows": rows,
        "unmatched": unmatched,
        "by_verdict": by_verdict,
        "auto_negatives": auto_negatives,
        "runner_hit_count": len(runner_hits),
        "triage_record_count": len(triage),
    }


def append_rows(ledger_path: Path, rows: list) -> None:
    """Append ledger rows as JSONL. Creates the file if absent."""
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    with ledger_path.open("a", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, sort_keys=True) + "\n")


def _default_runner_outputs(ws: Path) -> list:
    """Probe the conventional locations for the runner envelope."""
    candidates = [
        ws / ".audit_logs" / "audit_deep" / "universal-fp-runner.output.json",
        ws / ".audit_logs" / "universal-fp-runner.output.json",
    ]
    found = [str(c) for c in candidates if c.is_file()]
    return found or [str(candidates[0])]


def main(argv: list) -> int:
    p = argparse.ArgumentParser(
        description=(
            "Capture FP-runner triage verdicts into the verdict "
            "ledger at hunt closeout."
        )
    )
    p.add_argument(
        "--workspace",
        required=True,
        help="workspace root (defaults --triage / --runner-output)",
    )
    p.add_argument(
        "--runner-output",
        action="append",
        default=[],
        help="universal-fp-runner JSON envelope (repeatable / comma-list)",
    )
    p.add_argument(
        "--triage",
        default="",
        help="operator triage JSONL "
        "(default <ws>/.audit_logs/fp_triage_verdicts.jsonl)",
    )
    p.add_argument(
        "--ledger",
        default="",
        help="verdict ledger to append (default repo "
        "audit/fp_verdict_ledger.jsonl)",
    )
    p.add_argument(
        "--auto-negative",
        action="store_true",
        help="also emit NEGATIVE rows for test/mock/lib/script hits",
    )
    p.add_argument(
        "--workspace-label",
        default="",
        help="short label for the workspace field (default ws basename)",
    )
    p.add_argument("--json", action="store_true", default=True)
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="compute and report but do NOT write the ledger",
    )
    args = p.parse_args(argv)

    ws = Path(args.workspace).expanduser()
    if not ws.is_dir():
        sys.stderr.write(
            "[fp-verdict-capture] workspace not a directory: %s\n" % ws
        )
        return 2

    label = args.workspace_label.strip() or ws.name

    runner_paths: list = []
    for item in args.runner_output:
        runner_paths.extend(x.strip() for x in item.split(",") if x.strip())
    if not runner_paths:
        runner_paths = _default_runner_outputs(ws)

    triage_path = (
        Path(args.triage).expanduser()
        if args.triage
        else ws / ".audit_logs" / "fp_triage_verdicts.jsonl"
    )

    if args.ledger:
        ledger_path = Path(args.ledger).expanduser()
    else:
        # Repo-root-relative default: this file lives at
        # tools/audit/fp_verdict_capture.py.
        repo_root = Path(__file__).resolve().parents[2]
        ledger_path = repo_root / "audit" / "fp_verdict_ledger.jsonl"

    runner_hits = load_runner_hits(runner_paths)
    triage = load_triage(triage_path)
    existing_keys = load_existing_keys(ledger_path)

    result = capture(
        runner_hits=runner_hits,
        triage=triage,
        workspace_label=label,
        auto_negative=args.auto_negative,
        existing_keys=existing_keys,
    )

    rows = result["rows"]
    wrote = 0
    if rows and not args.dry_run:
        append_rows(ledger_path, rows)
        wrote = len(rows)

    triage_present = triage_path.is_file()
    honest_empty = (
        not triage_present and not args.auto_negative
    ) or (len(triage) == 0 and result["auto_negatives"] == 0)

    summary = {
        "schema": SUMMARY_SCHEMA,
        "generated_at": _utc_now(),
        "workspace": str(ws),
        "workspace_label": label,
        "runner_outputs": runner_paths,
        "triage_file": str(triage_path),
        "triage_file_present": triage_present,
        "ledger": str(ledger_path),
        "dry_run": bool(args.dry_run),
        "auto_negative_enabled": bool(args.auto_negative),
        "runner_hit_count": result["runner_hit_count"],
        "triage_record_count": result["triage_record_count"],
        "new_rows": len(rows),
        "rows_written": wrote,
        "rows_by_verdict": result["by_verdict"],
        "auto_negative_rows": result["auto_negatives"],
        "unmatched_triage": result["unmatched"],
        "honest_empty": honest_empty,
    }

    if honest_empty and not rows:
        sys.stderr.write(
            "[fp-verdict-capture] no triage data for %s - captured "
            "nothing (honest empty)\n" % label
        )

    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
