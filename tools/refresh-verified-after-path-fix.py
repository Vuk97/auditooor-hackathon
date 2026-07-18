#!/usr/bin/env python3
"""refresh-verified-after-path-fix.py

Takes the drift_322 path-fix queue, runs smoke on corrected fixture paths
(using the correct runner per language), and refreshes verified metadata
in _tier_registry.yaml for rows that pass.

Smoke logic:
  - Solidity (.sol): run_custom.py --tier=ALL <fixture> <arg>  -> parse [done] total hits
  - Rust (.rs):      rust-detect.py <FIXTURES_DIR> --only <arg> --file <fixture> --log <tmp>
                     -> parse "=== <arg>  (N hits)" from log

Pass criteria: vuln_hits >= 1 AND clean_hits == 0.

For each passing row, the registry row gets:
  - verified: true (refresh / ensure)
  - verified_at: <ISO8601 now>
  - smoke_test_vuln_hits / smoke_test_clean_hits (refreshed)
  - smoke_recheck_2026_05_04: drift_322_path_fix_refresh

Writes atomically via .yaml.tmp rename. Does NOT downgrade or alter tier.

Usage:
  python3 tools/refresh-verified-after-path-fix.py \\
    --queue /private/tmp/auditooor-inventory/drift_322_path_fix_queue.json \\
    --summary-out /private/tmp/auditooor-inventory/refresh_verified_summary.json \\
    [--dry-run] [--limit N] [--workers N]
"""
from __future__ import annotations

import argparse
import concurrent.futures
import datetime
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
TIER_REGISTRY = REPO / "detectors" / "_tier_registry.yaml"
RUN_CUSTOM = REPO / "detectors" / "run_custom.py"
RUST_DETECT = Path(__file__).resolve().parent / "rust-detect.py"
RUST_FIXTURES_DIR = REPO / "detectors" / "rust_wave1" / "test_fixtures"
SLITHER_PYTHON = "/opt/homebrew/opt/python@3.13/bin/python3.13"

_DONE_HITS_RE = re.compile(r"\[done\]\s+total hits:\s+(\d+)")
_RUST_HITS_RE = re.compile(r"^===\s+(\S+)\s+\((\d+) hits\)", re.MULTILINE)


def run_smoke_sol(arg: str, fixture: Path) -> int:
    """Solidity: run run_custom.py, return hit count or -1."""
    smoke_env = {**os.environ, "AUDITOOOR_FIXTURE_SMOKE_MODE": "1"}
    cmd = [SLITHER_PYTHON, str(RUN_CUSTOM), "--tier=ALL", str(fixture), arg]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=120, cwd=REPO, env=smoke_env
        )
    except subprocess.TimeoutExpired:
        return -1
    out = (proc.stdout or "") + "\n" + (proc.stderr or "")
    m = _DONE_HITS_RE.search(out)
    return int(m.group(1)) if m else -1


def run_smoke_rust(arg: str, fixture: Path) -> int:
    """Rust: run rust-detect.py --only <arg> --file <fixture> --log <tmp>, return hit count."""
    with tempfile.NamedTemporaryFile(suffix=".log", delete=False, mode="w") as tf:
        log_path = Path(tf.name)
    try:
        subprocess.run(
            [
                sys.executable,
                str(RUST_DETECT),
                str(RUST_FIXTURES_DIR),
                "--only", arg,
                "--file", str(fixture),
                "--log", str(log_path),
            ],
            capture_output=True,
            timeout=60,
            cwd=REPO,
        )
        try:
            text = log_path.read_text(errors="ignore")
        except FileNotFoundError:
            return 0
        for m in _RUST_HITS_RE.finditer(text):
            if m.group(1) == arg:
                return int(m.group(2))
        return 0
    except subprocess.TimeoutExpired:
        return -1
    finally:
        try:
            log_path.unlink()
        except FileNotFoundError:
            pass


def smoke_pair(arg: str, vuln_path: Path, clean_path: Path, language: str) -> tuple[int, int]:
    """Return (vuln_hits, clean_hits) for the fixture pair."""
    if language == "rust":
        vh = run_smoke_rust(arg, vuln_path)
        ch = run_smoke_rust(arg, clean_path)
    else:
        vh = run_smoke_sol(arg, vuln_path)
        ch = run_smoke_sol(arg, clean_path)
    return vh, ch


def process_row(r: dict) -> dict:
    arg = r["argument"]
    lang = r.get("language", "sol")
    vuln_path = REPO / r["alt_vuln"]
    clean_path = REPO / r["alt_clean"]

    if not vuln_path.exists() or not clean_path.exists():
        return {"argument": arg, "status": "skipped_missing_fixture", "vuln_hits": None, "clean_hits": None}

    vh, ch = smoke_pair(arg, vuln_path, clean_path, lang)
    passed = vh >= 1 and ch == 0
    return {
        "argument": arg,
        "language": lang,
        "status": "smoke_pass" if passed else "smoke_fail",
        "vuln_hits": vh,
        "clean_hits": ch,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--queue", required=True)
    ap.add_argument("--summary-out", required=True)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--workers", type=int, default=8)
    args = ap.parse_args()

    queue_data = json.loads(Path(args.queue).read_text(encoding="utf-8"))
    rows = queue_data["rows"]
    if args.limit > 0:
        rows = rows[: args.limit]

    reg = yaml.safe_load(TIER_REGISTRY.read_text(encoding="utf-8"))
    tiers = reg.setdefault("tiers", {})

    iso_now = datetime.datetime.now(datetime.timezone.utc).isoformat()

    total = len(rows)
    print(f"[refresh] Processing {total} rows with {args.workers} workers ...", flush=True)

    results: list[dict] = [None] * total  # type: ignore

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(process_row, r): i for i, r in enumerate(rows)}
        done_count = 0
        for fut in concurrent.futures.as_completed(futs):
            i = futs[fut]
            res = fut.result()
            results[i] = res
            done_count += 1
            if done_count % 20 == 0 or done_count == total:
                print(f"  [{done_count}/{total}] last={res['argument'][:55]} status={res['status']}", flush=True)

    smoke_pass = [r for r in results if r["status"] == "smoke_pass"]
    smoke_fail = [r for r in results if r["status"] == "smoke_fail"]
    skipped_missing = [r for r in results if r["status"] == "skipped_missing_fixture"]

    print(f"\n[refresh] smoke_pass={len(smoke_pass)}  smoke_fail={len(smoke_fail)}  skipped_missing={len(skipped_missing)}")

    if not args.dry_run and smoke_pass:
        for r in smoke_pass:
            arg = r["argument"]
            row = tiers.setdefault(arg, {})
            row["verified"] = True
            row["verified_at"] = iso_now
            row["smoke_test_vuln_hits"] = r["vuln_hits"]
            row["smoke_test_clean_hits"] = r["clean_hits"]
            row["smoke_recheck_2026_05_04"] = "drift_322_path_fix_refresh"

        tmp = TIER_REGISTRY.with_suffix(".yaml.tmp")
        tmp.write_text(
            yaml.safe_dump(reg, default_flow_style=False, sort_keys=False),
            encoding="utf-8",
        )
        tmp.replace(TIER_REGISTRY)
        print(f"[refresh] Registry written: {TIER_REGISTRY}")

    summary = {
        "schema": "auditooor.refresh_verified_after_path_fix.v1",
        "ran_at": iso_now,
        "queue": args.queue,
        "dry_run": args.dry_run,
        "rows_processed": total,
        "smoke_pass_count": len(smoke_pass),
        "smoke_fail_count": len(smoke_fail),
        "skipped_missing_fixture_count": len(skipped_missing),
        "smoke_pass": [r["argument"] for r in smoke_pass],
        "smoke_fail": smoke_fail,
        "skipped_missing": [r["argument"] for r in skipped_missing],
    }
    Path(args.summary_out).write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"[refresh] summary -> {args.summary_out}")
    return 0 if not smoke_fail else 1


if __name__ == "__main__":
    sys.exit(main())
