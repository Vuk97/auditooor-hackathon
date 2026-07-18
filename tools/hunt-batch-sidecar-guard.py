#!/usr/bin/env python3
"""hunt-batch-sidecar-guard.py - Sidecar count guard for batch hunt dispatch.

WHY THIS EXISTS:
  At high batch sizes (>10) the haiku-fanout-dispatcher can silently truncate
  tail tasks - the final Agent batch runs but produces zero sidecar files for
  the last N tasks in the batch. The gate catches this BEFORE the operator
  proceeds to mimo-corpus-mine and gets a false-clean coverage signal.

USAGE:
  # Hard-fail if count mismatch (default):
  python3 tools/hunt-batch-sidecar-guard.py \\
    --expected 42 \\
    --sidecar-dir audit/corpus_tags/derived/hunt_bodypack_dispatch_myws

  # Warn-only (exit 0 even on mismatch; used during plan phase before dispatch):
  python3 tools/hunt-batch-sidecar-guard.py \\
    --expected 42 \\
    --sidecar-dir audit/corpus_tags/derived/hunt_bodypack_dispatch_myws \\
    --warn-only

INTEGRATION:
  Called automatically by `make hunt-batch-bodypack-dispatch` with --warn-only
  (plan phase; sidecars not yet written). After all Agent batches complete, run
  WITHOUT --warn-only to hard-fail on missing sidecars:

    python3 tools/hunt-batch-sidecar-guard.py \\
      --expected <N> --sidecar-dir <outdir>

OUTPUT CODES:
  0  - count matches expected (PASS) or --warn-only was set
  1  - count mismatch without --warn-only (FAIL LOUD)
  2  - bad arguments / missing directory with --strict-dir
"""

import argparse
import json
import sys
from pathlib import Path


def count_sidecars(sidecar_dir: Path) -> int:
    """Count *.json sidecar files in sidecar_dir (non-recursive, top-level only).

    We exclude the manifest.json written by haiku-fanout-dispatcher (name starts
    with "manifest") and any agent_batch_* plan files that may be co-located.
    """
    if not sidecar_dir.is_dir():
        return 0
    return sum(
        1
        for f in sidecar_dir.iterdir()
        if f.suffix == ".json"
        and not f.name.startswith("manifest")
        and not f.name.startswith("agent_batch_")
        and f.is_file()
    )


def run(args: argparse.Namespace) -> int:
    sidecar_dir = Path(args.sidecar_dir)
    expected = args.expected

    if expected < 0:
        print(
            "[hunt-batch-sidecar-guard] ERROR: --expected must be >= 0",
            file=sys.stderr,
        )
        return 2

    if not sidecar_dir.exists():
        if args.strict_dir:
            print(
                f"[hunt-batch-sidecar-guard] ERROR: sidecar-dir does not exist: {sidecar_dir}",
                file=sys.stderr,
            )
            return 2
        # Directory absent = 0 sidecars emitted (acceptable in warn-only / plan phase)
        actual = 0
    else:
        actual = count_sidecars(sidecar_dir)

    status = "PASS" if actual >= expected else "FAIL"

    result = {
        "guard": "hunt-batch-sidecar-guard",
        "expected": expected,
        "actual": actual,
        "status": status,
        "sidecar_dir": str(sidecar_dir),
        "warn_only": args.warn_only,
    }

    # Optional receipt for the readme-conformance gate (status normalized lowercase).
    # The step-3 check is file_absent_or_field_equals on /status with ok_values [pass, null]:
    # absent => path not used (other hunt path) => OK; present => must be 'pass' (catches
    # silent tail-task truncation as a fail-closed coverage-hole gate).
    if getattr(args, "receipt", None):
        try:
            rp = Path(args.receipt)
            rp.parent.mkdir(parents=True, exist_ok=True)
            rp.write_text(json.dumps({**result, "status": status.lower()}), encoding="utf-8")
        except OSError as e:
            print(f"[hunt-batch-sidecar-guard] WARN could not write receipt: {e}", file=sys.stderr)

    if args.json:
        print(json.dumps(result))
    else:
        print(
            f"[hunt-batch-sidecar-guard] {status}: expected={expected} actual={actual} dir={sidecar_dir}"
            + (" (warn-only)" if args.warn_only else "")
        )

    if status == "FAIL":
        missing = expected - actual
        message = (
            f"[hunt-batch-sidecar-guard] COVERAGE HOLE DETECTED: {missing} sidecar(s) "
            f"missing (expected {expected}, got {actual}). "
            f"Tail-task truncation likely at high batch sizes. "
            f"Re-dispatch missing Agent batches before running mimo-corpus-mine."
        )
        if args.warn_only:
            print(f"WARN {message}", file=sys.stderr)
            return 0
        else:
            print(f"ERROR {message}", file=sys.stderr)
            return 1

    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Guard: fail loudly if sidecar count < expected after batch dispatch.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "--expected",
        type=int,
        required=True,
        help="Expected number of sidecar .json files (= number of tasks dispatched).",
    )
    p.add_argument(
        "--sidecar-dir",
        required=True,
        help="Directory where Agent subagents write per-task sidecar *.json files.",
    )
    p.add_argument(
        "--warn-only",
        action="store_true",
        default=False,
        help="Exit 0 even on mismatch; emit a WARN to stderr instead of failing.",
    )
    p.add_argument(
        "--strict-dir",
        action="store_true",
        default=False,
        help="Exit 2 if sidecar-dir does not exist (default: treat as 0 sidecars).",
    )
    p.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Emit JSON result to stdout instead of human-readable text.",
    )
    p.add_argument(
        "--receipt",
        default=None,
        help="Write a {status: pass|fail, ...} receipt JSON to this path for the readme-conformance "
             "step-3 gate (recommended: <ws>/.auditooor/hunt_batch_sidecar_guard_receipt.json).",
    )
    return p


def main() -> None:
    args = build_parser().parse_args()
    sys.exit(run(args))


if __name__ == "__main__":
    main()
