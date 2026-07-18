#!/usr/bin/env python3
"""phase-b-prime-wirer.py — wire Phase B-prime synthesized fixtures.

For each LLM output JSON in --inputs-dir:
  1. Parse delimiter format (===BEGIN_VULNERABLE_SOL=== / ===BEGIN_CLEAN_SOL=== / ===BEGIN_METADATA===)
  2. Write fixtures to detectors/test_fixtures/<snake>_{vulnerable,clean}.sol
  3. Run `python3 detectors/run_custom.py --tier=ALL <fixture> <argument>` for each
  4. If clean=0 + vuln>=1: add to promote_queue
  5. If smoke fails: leave fixtures on disk but don't promote

Output: phase_b_prime_smoke_summary.json + promote_queue.json (compatible with
inventory-bulk-promote.py).
"""
from __future__ import annotations

import argparse
import datetime
import json
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
RUN_CUSTOM = REPO / "detectors" / "run_custom.py"
TEST_FIXTURES_DIR = REPO / "detectors" / "test_fixtures"
SLITHER_PYTHON = "/opt/homebrew/opt/python@3.13/bin/python3.13"

_DELIM_RE = re.compile(
    r"===BEGIN_VULNERABLE_SOL===\s*(.*?)\s*===END_VULNERABLE_SOL==="
    r".*?===BEGIN_CLEAN_SOL===\s*(.*?)\s*===END_CLEAN_SOL==="
    r".*?===BEGIN_METADATA===\s*(.*?)\s*===END_METADATA===",
    re.DOTALL,
)
_DONE_HITS_RE = re.compile(r"\[done\]\s+total hits:\s+(\d+)")


def parse_delimited(raw: str) -> dict | None:
    m = _DELIM_RE.search(raw.strip())
    if not m:
        return None
    vuln, clean, meta_block = m.groups()
    meta = {}
    for line in meta_block.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            meta[k.strip()] = v.strip()
    return {"vuln": vuln, "clean": clean, **meta}


def smoke(arg: str, fixture: Path) -> int:
    cmd = [SLITHER_PYTHON, str(RUN_CUSTOM), "--tier=ALL", str(fixture), arg]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120, cwd=REPO)
    except subprocess.TimeoutExpired:
        return -1
    out = (proc.stdout or "") + "\n" + (proc.stderr or "")
    m = _DONE_HITS_RE.search(out)
    return int(m.group(1)) if m else -1


def find_py_path(arg: str) -> Path | None:
    snake = arg.replace("-", "_")
    for wave in (REPO / "detectors").glob("wave*"):
        if not wave.is_dir():
            continue
        cand = wave / f"{snake}.py"
        if cand.exists():
            return cand
    return None


def wire_one(input_path: Path, dry_run: bool = False) -> dict:
    result = {
        "input": str(input_path.relative_to(REPO)) if input_path.is_relative_to(REPO) else str(input_path),
        "argument": None,
        "status": "?",
        "vuln_hits": None,
        "clean_hits": None,
        "vuln_fixture": None,
        "clean_fixture": None,
        "py_path": None,
    }
    raw = input_path.read_text(encoding="utf-8")
    blob = parse_delimited(raw)
    if blob is None:
        result["status"] = "parse_failed"
        return result
    arg = blob.get("argument", "").strip()
    snake = blob.get("snake", arg.replace("-", "_")).strip()
    if not arg or not snake:
        result["status"] = "missing_metadata"
        return result
    result["argument"] = arg

    py_path = find_py_path(arg)
    if py_path is None:
        result["status"] = "no_py_for_arg"
        return result
    result["py_path"] = str(py_path.relative_to(REPO))

    vuln_path = TEST_FIXTURES_DIR / f"{snake}_vulnerable.sol"
    clean_path = TEST_FIXTURES_DIR / f"{snake}_clean.sol"
    result["vuln_fixture"] = str(vuln_path.relative_to(REPO))
    result["clean_fixture"] = str(clean_path.relative_to(REPO))

    if dry_run:
        result["status"] = "dry_run_ok"
        return result

    # Write fixtures
    TEST_FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
    vuln_path.write_text(blob["vuln"], encoding="utf-8")
    clean_path.write_text(blob["clean"], encoding="utf-8")

    vh = smoke(arg, vuln_path)
    ch = smoke(arg, clean_path)
    result["vuln_hits"] = vh
    result["clean_hits"] = ch

    if vh < 0 or ch < 0:
        result["status"] = "parse_error"
    elif ch == 0 and vh >= 1:
        result["status"] = "smoke_pass"
    elif ch > 0:
        result["status"] = "false_positive"
    else:
        result["status"] = "silent"
    return result


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--inputs-dir", required=True)
    ap.add_argument("--summary-out", required=True)
    ap.add_argument("--promote-queue-out", required=True)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    inputs = sorted(p for p in Path(args.inputs_dir).glob("*.json")
                    if not p.name.endswith(".stderr"))
    if args.limit:
        inputs = inputs[: args.limit]

    results: list[dict] = []
    for i, inp in enumerate(inputs, 1):
        r = wire_one(inp, dry_run=args.dry_run)
        results.append(r)
        print(f"[{i}/{len(inputs)}] {r['status']:15} {r.get('argument','?')}: vh={r.get('vuln_hits')} ch={r.get('clean_hits')}",
              file=sys.stderr, flush=True)

    by_status: dict[str, int] = {}
    for r in results:
        by_status[r["status"]] = by_status.get(r["status"], 0) + 1

    passing = [r for r in results if r["status"] == "smoke_pass"]
    promote = [
        {
            "argument": r["argument"],
            "py_path": r["py_path"],
            "wave": Path(r["py_path"]).parent.name if r["py_path"] else "phase-b-prime",
            "vuln_fixture": r["vuln_fixture"],
            "clean_fixture": r["clean_fixture"],
            "vuln_hits": r["vuln_hits"],
            "clean_hits": r["clean_hits"],
        }
        for r in passing
    ]

    summary = {
        "schema": "auditooor.phase_b_prime_wirer.v1",
        "ran_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "inputs_dir": args.inputs_dir,
        "input_count": len(inputs),
        "by_status": by_status,
        "results": results,
    }
    Path(args.summary_out).write_text(json.dumps(summary, indent=2))
    Path(args.promote_queue_out).write_text(json.dumps(promote, indent=2))
    print()
    for s, n in sorted(by_status.items(), key=lambda kv: -kv[1]):
        pct = 100*n // len(inputs) if inputs else 0
        print(f"  {s:18} {n:3d} ({pct:>3}%)")
    print(f"  passes -> {args.promote_queue_out} ({len(passing)} ready for bulk-promote)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
