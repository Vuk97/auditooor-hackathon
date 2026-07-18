#!/usr/bin/env python3
"""inventory-smoke-rust.py — smoke-test every rust_wave1 detector against its fixtures.

For each .py detector in detectors/rust_wave1/ (skipping _util.py):
  1. Locate test_fixtures/<id>_positive.rs  and  <id>_negative.rs
  2. Run rust-detect.py --only <id> --file <fixture> and parse hit count from log
  3. Classify:
       smoke_pass        — positive >=1 hit AND negative 0 hits
       false_positive    — negative >=1 hit
       silent            — positive 0 hits AND negative 0 hits
       skipped_no_fix    — fixture pair missing (one or both)

Output:
  inventory_smoke_rust_summary.json       — full per-detector result
  inventory_smoke_rust_promote_queue.json — smoke_pass entries (bulk-promote compatible)

Usage:
  python3 tools/inventory-smoke-rust.py \\
    [--output-dir /tmp/auditooor-rust-smoke] \\
    [--workers 8] [--limit N]
"""
from __future__ import annotations

import argparse
import concurrent.futures as futures
import datetime
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DETECTORS_DIR = REPO / "detectors" / "rust_wave1"
FIXTURES_DIR = DETECTORS_DIR / "test_fixtures"
RUST_DETECT = Path(__file__).resolve().parent / "rust-detect.py"
PYTHON = sys.executable

_LOG_HIT_RE = re.compile(r"^=== (\S+)\s+\((\d+) hits\)")


def parse_hit_count(log_path: Path, det_id: str) -> int:
    """Return hit count for det_id from rust-detect log."""
    try:
        text = log_path.read_text(errors="ignore")
    except FileNotFoundError:
        return 0
    for line in text.splitlines():
        m = _LOG_HIT_RE.match(line)
        if m and m.group(1) == det_id:
            return int(m.group(2))
    return 0


def run_detector(det_id: str, fixture: Path) -> int:
    """Run rust-detect.py for det_id against fixture; return hit count."""
    with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as tf:
        log_path = Path(tf.name)
    try:
        subprocess.run(
            [
                PYTHON, str(RUST_DETECT),
                str(FIXTURES_DIR),   # workspace arg (ignored with --file)
                "--only", det_id,
                "--file", str(fixture),
                "--log", str(log_path),
            ],
            capture_output=True,
            timeout=60,
        )
        return parse_hit_count(log_path, det_id)
    except subprocess.TimeoutExpired:
        return -1  # sentinel: timeout
    finally:
        try:
            log_path.unlink()
        except FileNotFoundError:
            pass


def smoke_one(det_py: Path) -> dict:
    det_id = det_py.stem
    pos_fix = FIXTURES_DIR / f"{det_id}_positive.rs"
    neg_fix = FIXTURES_DIR / f"{det_id}_negative.rs"

    missing = []
    if not pos_fix.exists():
        missing.append("positive")
    if not neg_fix.exists():
        missing.append("negative")

    if missing:
        return {
            "id": det_id,
            "py_path": str(det_py.relative_to(REPO)),
            "status": "skipped_no_fix",
            "missing_fixtures": missing,
            "pos_hits": None,
            "neg_hits": None,
        }

    pos_hits = run_detector(det_id, pos_fix)
    neg_hits = run_detector(det_id, neg_fix)

    if pos_hits < 0 or neg_hits < 0:
        status = "timeout"
    elif neg_hits >= 1:
        status = "false_positive"
    elif pos_hits >= 1:
        status = "smoke_pass"
    else:
        status = "silent"

    return {
        "id": det_id,
        "py_path": str(det_py.relative_to(REPO)),
        "pos_fixture": str(pos_fix.relative_to(REPO)),
        "neg_fixture": str(neg_fix.relative_to(REPO)),
        "status": status,
        "pos_hits": pos_hits,
        "neg_hits": neg_hits,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--output-dir", default="/tmp/auditooor-rust-smoke")
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Discover detectors, including named subdirectories that require
    # `rust-detect.py --only <stem>` exact-match loading.
    det_files = sorted(
        p for p in DETECTORS_DIR.rglob("*.py")
        if not p.name.startswith("_")
        and "__pycache__" not in p.parts
        and "test_fixtures" not in p.parts
    )
    if args.limit:
        det_files = det_files[:args.limit]

    total = len(det_files)
    print(f"[info] {total} detectors found in {DETECTORS_DIR}")
    print(f"[info] output → {out_dir}")
    t0 = time.monotonic()

    results: list[dict] = []
    done_count = 0

    with futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        fmap = {pool.submit(smoke_one, p): p for p in det_files}
        for fut in futures.as_completed(fmap):
            res = fut.result()
            results.append(res)
            done_count += 1
            if done_count % 20 == 0 or done_count == total:
                elapsed = time.monotonic() - t0
                print(
                    f"  [{done_count}/{total}]  {elapsed:.0f}s  last={res['id']}  status={res['status']}"
                )

    # Sort by id for stable output
    results.sort(key=lambda r: r["id"])

    # Bucket counts
    buckets: dict[str, list[dict]] = {}
    for r in results:
        buckets.setdefault(r["status"], []).append(r)

    elapsed = time.monotonic() - t0
    iso_now = datetime.datetime.now(datetime.timezone.utc).isoformat()

    print()
    print("=== Rust wave1 smoke results ===")
    for status in ("smoke_pass", "false_positive", "silent", "skipped_no_fix", "timeout"):
        n = len(buckets.get(status, []))
        print(f"  {status:<22} {n:4d}")
    print(f"  {'TOTAL':<22} {total:4d}")
    print(f"  elapsed: {elapsed:.1f}s")

    # Write summary
    summary = {
        "generated_at": iso_now,
        "total": total,
        "counts": {s: len(v) for s, v in buckets.items()},
        "results": results,
    }
    summary_path = out_dir / "inventory_smoke_rust_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"\n[ok] summary → {summary_path}")

    # Write promote queue (bulk-promote compatible shape, engine=rust)
    promote_queue = [
        {
            "argument": r["id"],          # det_id used as argument key
            "py_path": r["py_path"],
            "vuln_fixture": r.get("pos_fixture", ""),
            "clean_fixture": r.get("neg_fixture", ""),
            "vuln_hits": r["pos_hits"],    # positive = vuln
            "clean_hits": r["neg_hits"],   # negative = clean
            "engine": "rust",
            "status": r["status"],
        }
        for r in buckets.get("smoke_pass", [])
    ]
    queue_path = out_dir / "inventory_smoke_rust_promote_queue.json"
    queue_path.write_text(json.dumps(promote_queue, indent=2), encoding="utf-8")
    print(f"[ok] promote queue ({len(promote_queue)} entries) → {queue_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
