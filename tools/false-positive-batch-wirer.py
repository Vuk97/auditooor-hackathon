#!/usr/bin/env python3
"""false-positive-batch-wirer.py — wire LLM outputs from fp_repair_queue.

For each task whose LLM output exists:
  1. Parse delimiter-format output (===BEGIN_REFINED_YAML=== ... etc.)
  2. Write the refined YAML to reference/patterns.dsl/<arg>.yaml
  3. Run `python3 tools/pattern-compile.py <yaml>` to (re)compile.
  4. Smoke-test: run detectors/run_custom.py on the clean and vuln fixtures.
       PASS  -> clean_hits == 0 AND vuln_hits >= 1
       FAIL  -> revert YAML to its prior contents (and remove the freshly
                compiled detector if the prior YAML did not exist), log
                to the retry queue.
  5. For PASS rows, append a bulk-promote payload to the promote queue
     (consumable by tools/inventory-bulk-promote.py).

Usage:
  python3 tools/false-positive-batch-wirer.py \\
    --queue /private/tmp/auditooor-inventory/fp_repair_queue.jsonl \\
    --promote-queue-out /private/tmp/auditooor-inventory/fp_repair_promote_queue.json \\
    --retry-queue-out   /private/tmp/auditooor-inventory/fp_repair_retry_queue.jsonl \\
    --summary-out       /private/tmp/auditooor-inventory/fp_repair_wirer_summary.json \\
    [--dry-run]   # parse + smoke test, do NOT write YAML or modify registry
"""
from __future__ import annotations

import argparse
import datetime
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DSL_DIR = REPO / "reference" / "patterns.dsl"
DETECTORS_DIR = REPO / "detectors"
PATTERN_COMPILE = REPO / "tools" / "pattern-compile.py"
RUN_CUSTOM = DETECTORS_DIR / "run_custom.py"

# Slither is installed under python3.13 in this environment; default
# `python3` is 3.14 without it. Use 3.13 for the smoke-test subprocesses
# so detectors actually run instead of silently returning 0 hits.
import shutil as _shutil
_PY = _shutil.which("python3.13") or "python3"

_DELIM_RE = re.compile(
    r"===BEGIN_REFINED_YAML===\s*(.*?)\s*===END_REFINED_YAML==="
    r".*?===BEGIN_RATIONALE===\s*(.*?)\s*===END_RATIONALE==="
    r".*?===BEGIN_METADATA===\s*(.*?)\s*===END_METADATA===",
    re.DOTALL,
)


def _parse_delimited(raw: str) -> dict | None:
    m = _DELIM_RE.search(raw)
    if not m:
        return None
    yaml_text, rationale, meta_block = m.groups()
    meta: dict[str, str] = {}
    for line in meta_block.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            meta[k.strip()] = v.strip()
    return {"yaml": yaml_text, "rationale": rationale, **meta}


def _smoke_run(arg: str, fixture: Path, timeout_sec: int = 90) -> tuple[int, str]:
    """Run run_custom.py, return (hits, last-line-tail)."""
    cmd = [_PY, str(RUN_CUSTOM), "--tier=ALL", str(fixture), arg]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout_sec, cwd=str(REPO))
    except subprocess.TimeoutExpired:
        return -1, "timeout"
    out = (proc.stdout or "") + (proc.stderr or "")
    # run_custom.py emits "[done] total hits: N" — that's a sum across all
    # custom detectors. Since we pass `<arg>` as the only filter, this
    # equals the count for our pattern. Also count individual finding
    # bullets ("  [LOW] ..." / "  [MEDIUM] ...") as a fallback.
    hits = 0
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("[done]"):
            m = re.search(r"total hits:\s*(\d+)", s) or re.search(r"hits=(\d+)", s)
            if m:
                hits = max(hits, int(m.group(1)))
    if hits == 0:
        # Fallback: count finding bullet lines that mention this pattern
        for line in out.splitlines():
            if arg in line and re.match(r"\s*\[(HIGH|MEDIUM|LOW|INFO)\]", line):
                hits += 1
    tail = "\n".join(out.splitlines()[-5:])
    return hits, tail


def _process_task(task: dict, dry_run: bool) -> dict:
    # Robust argument extraction: prefer "argument", fall back to task_id prefix strip
    arg = (
        task.get("argument")
        or task.get("task_id", "").removeprefix("fp-repair-")
        or ""
    )
    if not arg:
        return {"argument": "?", "status": "exception",
                "note": "KeyError: task missing 'argument' and 'task_id'"}
    snake = task.get("snake") or arg.replace("-", "_")
    out_path = Path(task["output_path"])
    if not out_path.exists():
        return {"argument": arg, "status": "no_output", "note": str(out_path)}

    raw = out_path.read_text(encoding="utf-8", errors="replace")
    parsed = _parse_delimited(raw)
    if parsed is None:
        return {"argument": arg, "status": "parse_error",
                "note": "delimiters not found"}
    if parsed.get("argument") and parsed["argument"] != arg:
        return {"argument": arg, "status": "metadata_mismatch",
                "note": f"meta arg={parsed['argument']}"}

    new_yaml_path = DSL_DIR / f"{arg}.yaml"
    prior_yaml_existed = new_yaml_path.exists()
    prior_yaml_bytes = new_yaml_path.read_bytes() if prior_yaml_existed else None

    # Locate the freshly compiled detector path (pattern-compile defaults to wave17)
    new_detector_path = DETECTORS_DIR / "wave17" / f"{snake}.py"
    prior_detector_existed = new_detector_path.exists()
    prior_detector_bytes = new_detector_path.read_bytes() if prior_detector_existed else None

    # Original auto-mined detector (wave14) — must be shadowed for the smoke test
    # to attribute hits to the new compiled detector, not both.
    original_py = REPO / task["py_path_original"]
    shadow_path = original_py.with_suffix(".py.fp_archived")

    if dry_run:
        return {"argument": arg, "status": "dry_run_parse_ok"}

    # 2. Write the refined YAML
    DSL_DIR.mkdir(parents=True, exist_ok=True)
    new_yaml_path.write_text(parsed["yaml"], encoding="utf-8")

    # 3. Compile (strict — hallucinated predicate keys must fail loud,
    # not become silent no-op predicates that yield silent_after_refine)
    # Trust-calibration audit 2026-05-04: prevent fake detectors with unknown predicate keys.
    compile_proc = subprocess.run(
        [_PY, str(PATTERN_COMPILE), "--strict-unsupported-keys",
         str(new_yaml_path)],
        capture_output=True, text=True, cwd=str(REPO), timeout=60,
    )
    if compile_proc.returncode != 0:
        # Revert YAML
        if prior_yaml_existed:
            new_yaml_path.write_bytes(prior_yaml_bytes)
        else:
            new_yaml_path.unlink(missing_ok=True)
        return {"argument": arg, "status": "compile_error",
                "note": (compile_proc.stderr or compile_proc.stdout)[-400:]}

    # Shadow the original wave14 detector while we run the smoke test
    shadowed = False
    if original_py.exists() and original_py != new_detector_path:
        shutil.move(str(original_py), str(shadow_path))
        shadowed = True

    try:
        # 4. Smoke test
        vuln_fix = REPO / task["vuln_fixture"]
        clean_fix = REPO / task["clean_fixture"]
        vuln_hits, _ = _smoke_run(arg, vuln_fix)
        clean_hits, _ = _smoke_run(arg, clean_fix)
    finally:
        # Always restore the original detector regardless of pass/fail; the
        # operator decides separately whether to retire the auto-mined one.
        if shadowed and shadow_path.exists():
            shutil.move(str(shadow_path), str(original_py))

    if vuln_hits >= 1 and clean_hits == 0:
        return {
            "argument": arg,
            "status": "pass",
            "vuln_hits": vuln_hits,
            "clean_hits": clean_hits,
            "py_path": str(new_detector_path.relative_to(REPO)),
            "vuln_fixture": task["vuln_fixture"],
            "clean_fixture": task["clean_fixture"],
            "rationale": parsed.get("rationale", ""),
        }

    # 6. Revert: restore prior YAML and prior detector
    if prior_yaml_existed:
        new_yaml_path.write_bytes(prior_yaml_bytes)
    else:
        new_yaml_path.unlink(missing_ok=True)
    if prior_detector_existed:
        new_detector_path.write_bytes(prior_detector_bytes)
    else:
        new_detector_path.unlink(missing_ok=True)

    return {
        "argument": arg,
        "status": "still_fp" if clean_hits > 0 else "silent_after_refine",
        "vuln_hits": vuln_hits,
        "clean_hits": clean_hits,
        "rationale": parsed.get("rationale", ""),
    }


def _build_task_from_output_file(
    out_file: Path,
    queue_index: dict[str, dict],
) -> dict | None:
    """Reconstruct a task dict from an output filename.

    Filename convention: fp_repair_<snake>.txt
    Derives argument (<snake> with _ → -) then looks up full metadata from
    queue_index if available, falling back to a minimal synthesised dict.
    """
    stem = out_file.stem  # e.g. fp_repair_a_cross_chain_...
    # Strip leading "fp_repair_" prefix if present
    snake = stem.removeprefix("fp_repair_")
    argument = snake.replace("_", "-")

    if argument in queue_index:
        task = dict(queue_index[argument])
        # Override output_path to point to the actual file we found
        task["output_path"] = str(out_file)
        return task

    # Minimal synthesised task — no fixture paths; smoke test will be skipped
    return {
        "argument": argument,
        "snake": snake,
        "output_path": str(out_file),
        "py_path_original": f"detectors/wave14/{snake}.py",
        "vuln_fixture": f"detectors/test_fixtures/{snake}_vulnerable.sol",
        "clean_fixture": f"detectors/test_fixtures/{snake}_clean.sol",
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--queue", default=None,
                    help="JSONL queue file (mutually exclusive with --inputs-dir)")
    ap.add_argument("--inputs-dir", default=None,
                    help="Directory of LLM output .txt files; scans for tasks "
                         "instead of reading --queue. Looks up full metadata "
                         "from --queue-index if provided.")
    ap.add_argument("--queue-index", default=None,
                    help="Optional JSONL queue to use as metadata index when "
                         "--inputs-dir is specified.")
    ap.add_argument("--promote-queue-out", required=True)
    ap.add_argument("--retry-queue-out", default=None,
                    help="Optional path for retry JSONL; omitted if not provided.")
    ap.add_argument("--summary-out", required=True)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    if args.inputs_dir is None and args.queue is None:
        ap.error("One of --queue or --inputs-dir is required.")

    # Build queue index for metadata lookup (used by --inputs-dir mode)
    queue_index: dict[str, dict] = {}
    queue_src = args.queue_index or args.queue
    if queue_src and Path(queue_src).exists():
        with Path(queue_src).open() as f:
            for line in f:
                line = line.strip()
                if line:
                    row = json.loads(line)
                    key = (
                        row.get("argument")
                        or row.get("task_id", "").removeprefix("fp-repair-")
                    )
                    if key:
                        queue_index[key] = row

    tasks: list[dict] = []

    if args.inputs_dir:
        inputs_dir = Path(args.inputs_dir)
        for out_file in sorted(inputs_dir.iterdir()):
            if out_file.suffix != ".txt" or out_file.name.endswith(".tmp"):
                continue
            task = _build_task_from_output_file(out_file, queue_index)
            if task:
                tasks.append(task)
    else:
        with Path(args.queue).open() as f:
            for line in f:
                line = line.strip()
                if line:
                    tasks.append(json.loads(line))

    promote_payload: list[dict] = []
    retry_rows: list[dict] = []
    results: list[dict] = []

    for t in tasks:
        try:
            r = _process_task(t, args.dry_run)
        except Exception as e:  # pragma: no cover — defensive
            r = {"argument": t.get("argument", "?"), "status": "exception",
                 "note": f"{type(e).__name__}: {e}"}
        results.append(r)

        if r["status"] == "pass":
            promote_payload.append({
                "argument": r["argument"],
                "py_path": r["py_path"],
                "vuln_fixture": r["vuln_fixture"],
                "clean_fixture": r["clean_fixture"],
                "vuln_hits": r["vuln_hits"],
                "clean_hits": r["clean_hits"],
            })
        elif r["status"] in ("still_fp", "silent_after_refine",
                             "compile_error", "parse_error",
                             "metadata_mismatch", "no_output", "exception"):
            retry_rows.append({**t, "wirer_status": r["status"],
                               "wirer_note": r.get("note", "")})

    Path(args.promote_queue_out).write_text(json.dumps(promote_payload, indent=2))
    if args.retry_queue_out:
        with Path(args.retry_queue_out).open("w") as f:
            for row in retry_rows:
                f.write(json.dumps(row) + "\n")

    summary = {
        "schema": "auditooor.fp_repair_wirer.v1",
        "ran_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "dry_run": args.dry_run,
        "queue": args.queue or args.inputs_dir,
        "by_status": {},
        "promote_count": len(promote_payload),
        "retry_count": len(retry_rows),
        "results": results,
    }
    for r in results:
        summary["by_status"][r["status"]] = summary["by_status"].get(r["status"], 0) + 1
    Path(args.summary_out).write_text(json.dumps(summary, indent=2))

    print(f"[fp-repair-wirer] dry_run={args.dry_run}")
    print(f"  total tasks:    {len(tasks)}")
    for k, v in sorted(summary["by_status"].items()):
        print(f"    {k:<24s} {v}")
    print(f"  promote queue:  {args.promote_queue_out} ({len(promote_payload)})")
    if args.retry_queue_out:
        print(f"  retry queue:    {args.retry_queue_out} ({len(retry_rows)})")
    print(f"  summary:        {args.summary_out}")
    print(f"  -> next: python3 tools/inventory-bulk-promote.py "
          f"--promote-queue {args.promote_queue_out} "
          "--summary-out /private/tmp/auditooor-inventory/fp_repair_bulk_promote_summary.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
