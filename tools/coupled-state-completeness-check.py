#!/usr/bin/env python3
"""coupled-state-completeness-check.py - audit-complete signal for the
coupled-state completeness dimension (the Aptos-desync axis).

Mirrors guard-completeness-check.py's env-strict pattern. It (re)emits the
coupled-state worklist for the workspace, runs the fail-closed --check on
tools/coupled-state-completeness.py, and writes:

  <ws>/.auditooor/coupled_state_completeness.json   (verdict + open_rows, ALWAYS)
  <ws>/.auditooor/coupled_state_completeness_pass.marker  (ONLY when 0 open rows)

The runbook step's how_to_verify_done is a file_exists on the pass marker, so the
step is RED (advisory) whenever coupled-state rows are open (unprobed).

ADVISORY-FIRST: WARN by default (rc 0 even with open rows). HARD FAIL (rc 1) ONLY
under AUDITOOOR_L37_STRICT=1 when open coupled-state rows exist. This lands the
gate WARN and flips to strict only after it proves clean on >=3 workspaces.

Usage: python3 tools/coupled-state-completeness-check.py --workspace <ws> [--json]
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent


def _load_csc():
    spec = importlib.util.spec_from_file_location(
        "csc", _HERE / "coupled-state-completeness.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--workspace", type=Path, required=True)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--no-emit", action="store_true",
                    help="use the existing worklist (do not re-emit)")
    a = ap.parse_args(argv)
    ws = a.workspace.resolve()
    aud = ws / ".auditooor"
    aud.mkdir(parents=True, exist_ok=True)
    csc = _load_csc()

    if not a.no_emit:
        csc.main(["--workspace", str(ws), "--emit-worklist"])

    wl = aud / "coupled_state_worklist.jsonl"
    gaps = aud / "coupled_state_gaps.jsonl"
    rows = [json.loads(l) for l in wl.read_text().splitlines() if l.strip()] \
        if wl.is_file() else []
    probed: set[str] = set()
    if gaps.is_file():
        for l in gaps.read_text().splitlines():
            if l.strip():
                g = json.loads(l)
                if g.get("set_id") and g.get("probe_verdict"):
                    probed.add(g["set_id"])
    open_rows = [r for r in rows
                 if not r.get("probe_verdict") and r.get("set_id") not in probed]
    strict = os.environ.get("AUDITOOOR_L37_STRICT") == "1"
    verdict = "pass-coupled-state-completeness" if not open_rows else \
        ("fail-coupled-state-open" if strict else "warn-coupled-state-open")

    result = {
        "schema_version": "auditooor.coupled_state_completeness_signal.v1",
        "verdict": verdict,
        "total_rows": len(rows),
        "open_rows": len(open_rows),
        "strict": strict,
        "advisory": not strict,
        "open_set_ids": [r["set_id"] for r in open_rows][:50],
    }
    (aud / "coupled_state_completeness.json").write_text(
        json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    marker = aud / "coupled_state_completeness_pass.marker"
    if not open_rows:
        marker.write_text(verdict + "\n", encoding="utf-8")
    elif marker.is_file():
        marker.unlink()  # stale pass -> remove so the runbook step goes RED

    if a.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        tag = "PASS" if not open_rows else ("FAIL" if strict else "WARN")
        print(f"[coupled-state-completeness-check] {tag}: {len(open_rows)} open / "
              f"{len(rows)} row(s) (strict={strict}, advisory={not strict})")
    return 1 if (open_rows and strict) else 0


if __name__ == "__main__":
    raise SystemExit(main())
