#!/usr/bin/env python3
"""Pre-hunt ORDER producer: negative-space + sibling-asymmetry + invariant-ledger ingest.

WHY THIS EXISTS (LOGIC_ARSENAL_ROADMAP.md "ORDER" break)
--------------------------------------------------------
The three enumeration producers below historically ran ONLY inside `make
audit-depth`, which the pipeline runs AFTER the scoped hunt (README step-4).
So the per-fn hunt could never STEER on them: the negative-space worklist and
the sibling-path guard-asymmetry index were built too late to feed an
OPEN-OBLIGATIONS block into the per-fn prompt, and the INVARIANT_LEDGER was
never (re)ingested from the exploit_queue before the hunt read it.

This helper moves that ingest INTO the pre-hunt window (`_hunt-prehunt-enum`,
dispatched from `make hunt-scoped`). It runs each producer under a STALENESS
check keyed to `.auditooor/inscope_units.jsonl` (the same freshness contract the
coverage_plane materialize step uses), so a warm re-run is cheap and a
scope/HEAD change forces a rebuild. It is ADVISORY-FIRST: an empty
negspace/asym index only WARNs today; pass --fail-closed (next wave) to make an
empty index a hard non-zero exit so the hunt never silently consumes a blind
index. STRICT is also engaged by the env flag AUDITOOOR_PREHUNT_STRICT=1 so the
pipeline can opt the whole hunt into fail-closed without changing the CLI call.

Producers (same invocations the drivers already use):
  guard-negative-space-analyzer.py --emit-worklist
      -> .auditooor/negative_space_worklist.jsonl
  sibling-path-guard-diff.py --check
      -> .auditooor/sibling_guard_asymmetries.jsonl
  exploit-queue-to-invariant-ledger.py            (merge; preserves edits)
      -> INVARIANT_LEDGER.md + .auditooor/invariant_ledger.json

Outputs a summary receipt at
  .auditooor/prehunt_negspace_asym_ingest.json
so downstream/tests can PROVE the ingest ran BEFORE the hunt and see whether
each index is non-empty.

Schema: auditooor.prehunt_negspace_asym_ingest.v1
Exit codes:
  0  every producer ran (or was fresh) and, under --fail-closed, no index empty
  0  advisory mode (default) even if an index is empty (warns to stderr)
  3  --fail-closed AND a negspace/asym index is absent/empty AFTER the run
  2  usage / workspace error
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

SCHEMA = "auditooor.prehunt_negspace_asym_ingest.v1"
TOOLS_DIR = Path(__file__).resolve().parent

# Env flag that flips the empty-index guard fail-closed WITHOUT the --fail-closed
# CLI flag, so the pipeline (make _hunt-prehunt-enum) can opt the whole hunt into
# STRICT mode. Default advisory THIS wave; the STRICT path exists + is tested so
# the next wave can flip the default on.
STRICT_ENV = "AUDITOOOR_PREHUNT_STRICT"


def _strict_env_enabled(environ=None) -> bool:
    """True if AUDITOOOR_PREHUNT_STRICT is set to a truthy value (1/true/yes/on)."""
    if environ is None:
        environ = os.environ
    return str(environ.get(STRICT_ENV, "")).strip().lower() in {
        "1", "true", "yes", "on",
    }


def _count_jsonl_rows(path: Path) -> int:
    """Count non-blank lines in a JSONL file; 0 if absent."""
    if not path.is_file():
        return 0
    n = 0
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.strip():
                    n += 1
    except OSError:
        return 0
    return n


def _is_stale(index_path: Path, inscope_path: Path) -> bool:
    """True if the index is absent, or older than inscope_units.jsonl.

    If inscope_units.jsonl is absent we cannot prove freshness, so we treat the
    index as stale ONLY when it is also absent (a present index with no freshness
    anchor is reused - avoids needless rebuilds on a workspace that never
    materialized inscope_units).
    """
    if not index_path.is_file():
        return True
    if not inscope_path.is_file():
        return False
    try:
        return inscope_path.stat().st_mtime > index_path.stat().st_mtime
    except OSError:
        return True


def _run_producer(argv: list[str], *, timeout: int) -> dict:
    """Run a producer subprocess; return a small status dict (never raises)."""
    try:
        proc = subprocess.run(
            argv,
            cwd=str(TOOLS_DIR.parent),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return {
            "argv": argv,
            "rc": proc.returncode,
            "stderr_tail": (proc.stderr or "").strip().splitlines()[-3:],
        }
    except subprocess.TimeoutExpired:
        return {"argv": argv, "rc": 124, "stderr_tail": ["timeout"]}
    except OSError as exc:
        return {"argv": argv, "rc": 127, "stderr_tail": [str(exc)]}


def run(ws: Path, *, fail_closed: bool, timeout: int) -> dict:
    audit_dir = ws / ".auditooor"
    audit_dir.mkdir(parents=True, exist_ok=True)
    inscope = audit_dir / "inscope_units.jsonl"

    negspace_idx = audit_dir / "negative_space_worklist.jsonl"
    sibling_idx = audit_dir / "sibling_guard_asymmetries.jsonl"
    ledger_json = audit_dir / "invariant_ledger.json"

    py = sys.executable or "python3"
    producers = [
        {
            "name": "negative-space-worklist",
            "index": negspace_idx,
            "index_key": "negspace",
            "argv": [
                py,
                str(TOOLS_DIR / "guard-negative-space-analyzer.py"),
                "--workspace",
                str(ws),
                "--emit-worklist",
            ],
            "gate_empty": True,
        },
        {
            "name": "sibling-path-guard-asymmetry",
            "index": sibling_idx,
            "index_key": "asym",
            "argv": [
                py,
                str(TOOLS_DIR / "sibling-path-guard-diff.py"),
                "--workspace",
                str(ws),
                "--check",
            ],
            "gate_empty": True,
        },
        {
            "name": "invariant-ledger-ingest",
            "index": ledger_json,
            "index_key": "invariant_ledger",
            "argv": [
                py,
                str(TOOLS_DIR / "exploit-queue-to-invariant-ledger.py"),
                "--workspace",
                str(ws),
            ],
            # The ledger can be legitimately empty on a workspace with no
            # exploit_queue rows yet, so an empty ledger is NEVER a fail-closed
            # trigger; only negspace/asym gate the hunt.
            "gate_empty": False,
        },
    ]

    results = []
    empty_gated = []
    for p in producers:
        idx: Path = p["index"]
        stale = _is_stale(idx, inscope)
        rec = {
            "name": p["name"],
            "index_path": str(idx),
            "index_key": p["index_key"],
            "stale_before": stale,
            "regenerated": False,
        }
        if stale:
            rec["producer"] = _run_producer(p["argv"], timeout=timeout)
            rec["regenerated"] = True
        rec["rows_after"] = _count_jsonl_rows(idx)
        rec["empty_after"] = rec["rows_after"] == 0
        if p["gate_empty"] and rec["empty_after"]:
            empty_gated.append(p["index_key"])
        results.append(rec)

    strict = bool(fail_closed)
    summary = {
        "schema": SCHEMA,
        "workspace": str(ws),
        "ran_before_hunt": True,
        "fail_closed": strict,
        "strict_source": (
            (f"env:{STRICT_ENV}" if _strict_env_enabled() else "cli:--fail-closed")
            if strict else "advisory"
        ),
        "producers": results,
        "empty_gated_indices": empty_gated,
        "status": (
            "ok" if not empty_gated
            else ("empty-index-fail" if strict else "empty-index-warn")
        ),
    }
    return summary


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--workspace", required=True, help="workspace root")
    ap.add_argument(
        "--fail-closed",
        action="store_true",
        help="exit non-zero (3) if a negspace/asym index is empty after the run "
        "(next-wave blocking; default is advisory-warn)",
    )
    ap.add_argument("--timeout", type=int, default=90,
                    help="per-producer subprocess timeout seconds (default 90)")
    ap.add_argument("--json", action="store_true", help="print the summary JSON")
    args = ap.parse_args(argv)

    ws = Path(args.workspace).expanduser().resolve()
    if not ws.is_dir():
        print(f"[prehunt-ingest] ERROR workspace not a directory: {ws}",
              file=sys.stderr)
        return 2

    # STRICT is engaged by EITHER the --fail-closed CLI flag OR the
    # AUDITOOOR_PREHUNT_STRICT env flag (so the pipeline can opt in without
    # changing the invocation). Default remains advisory this wave.
    strict = bool(args.fail_closed) or _strict_env_enabled()
    summary = run(ws, fail_closed=strict, timeout=args.timeout)

    receipt = ws / ".auditooor" / "prehunt_negspace_asym_ingest.json"
    try:
        receipt.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    except OSError as exc:
        print(f"[prehunt-ingest] WARN could not write receipt: {exc}",
              file=sys.stderr)

    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        for r in summary["producers"]:
            state = "regenerated" if r["regenerated"] else (
                "fresh-reused" if not r["stale_before"] else "absent")
            print(f"[prehunt-ingest] {r['name']}: {state}; "
                  f"rows_after={r['rows_after']}")

    if summary["empty_gated_indices"]:
        msg = ("[prehunt-ingest] WARN empty index after pre-hunt ingest: "
               + ", ".join(summary["empty_gated_indices"])
               + " - the scoped hunt would consume a BLIND negspace/asym index")
        print(msg, file=sys.stderr)
        if strict:
            print("[prehunt-ingest] FAIL-CLOSED: refusing to proceed with an "
                  "empty negspace/asym index "
                  f"(strict via {summary['strict_source']})", file=sys.stderr)
            return 3

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
