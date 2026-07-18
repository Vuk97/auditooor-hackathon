#!/usr/bin/env python3
"""promotion-candidate-sanity-gate.py — Cheap pre-filter for FP-heavy scanner output.

Wave O-E. Closes Gap #5.

Runs ONLY Steps 1 and 3 of the 5-check protocol from
``feedback_llm_hallucinates_oos_paths_into_in_scope_tree.md``:

  1. **audit-tree existence** — file must exist at
     ``<workspace>/external/<asset>/<path>``
  3. **SCOPE.md OOS check** — path must NOT fall under any OOS marker block
     in ``<workspace>/SCOPE.md``

Both checks are filesystem-only, sub-millisecond per candidate.  Most FPs
(path doesn't exist OR path is OOS) are killed in ~10ms instead of the ~10s
consumed by the full 5-check upstream-equivalent-gate.

Recommended pipeline::

    scanner output
      → promotion-candidate-sanity-gate (Steps 1+3, ~10ms/candidate)
      → upstream-equivalent-gate (full 5-check, ~10s/candidate)
      → M14-trap Opus dispatch (~30s/candidate)

The output's ``survivors_inline`` field is a clean candidate-list ready to
feed directly into ``tools/upstream-equivalent-gate.py``.

Usage::

    python3 tools/promotion-candidate-sanity-gate.py \\
        --workspace ~/audits/base-azul \\
        --candidate path/to/promotion_candidates.json \\
        --output /tmp/sanity_gate_out.json \\
        [--print-json] \\
        [--fast-fail]

Exit codes:
  0  — at least one candidate survived (or no candidates; empty pass)
  1  — ``--fast-fail`` was given and zero candidates survived
  2  — harness error (missing workspace, bad JSON)

Wave O-E, PR #[next].
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "auditooor.promotion_candidate_sanity_gate.v1"

# ---------------------------------------------------------------------------
# Import Step 1 and Step 3 helpers from upstream-equivalent-gate.py
# ---------------------------------------------------------------------------

def _load_upstream_gate_module():
    """Load upstream-equivalent-gate.py as a module (hyphen in name)."""
    gate_path = Path(__file__).resolve().parent / "upstream-equivalent-gate.py"
    if not gate_path.exists():
        raise ImportError(
            f"upstream-equivalent-gate.py not found at {gate_path}; "
            "cannot import Step 1 / Step 3 helpers."
        )
    spec = importlib.util.spec_from_file_location("upstream_equivalent_gate", gate_path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_GATE = _load_upstream_gate_module()

# Bind to the public helpers — Step 1 and Step 3.
check_step1_existence: Any = _GATE.check_step1_existence   # (workspace, path) → (bool, str)
check_step3_scope: Any = _GATE.check_step3_scope            # (workspace, path) → str
_rows_from_payload: Any = _GATE._rows_from_payload


# ---------------------------------------------------------------------------
# Core per-row logic
# ---------------------------------------------------------------------------

def _run_sanity_checks(
    row: dict[str, Any],
    row_index: int,
    workspace: Path,
) -> dict[str, Any]:
    """Run Steps 1 and 3 on a single candidate row; return a verdict record."""
    production_path = str(
        row.get("production_path", row.get("file", ""))
    ).strip()

    # --- Step 1: audit-tree existence ---
    step1_exists, _resolved = check_step1_existence(workspace, production_path)

    if not step1_exists:
        return {
            "row_index": row_index,
            "production_path": production_path,
            "step_1_audit_tree_exists": False,
            "step_3_scope_status": "skipped",
            "verdict": "killed_step_1_path_missing",
            "reason": f"Path not found under {workspace}/external/*/",
        }

    # --- Step 3: SCOPE.md OOS ---
    step3_scope = check_step3_scope(workspace, production_path)

    if step3_scope == "oos":
        return {
            "row_index": row_index,
            "production_path": production_path,
            "step_1_audit_tree_exists": True,
            "step_3_scope_status": "oos",
            "verdict": "killed_step_3_oos",
            "reason": "Production path is out-of-scope per SCOPE.md",
        }

    return {
        "row_index": row_index,
        "production_path": production_path,
        "step_1_audit_tree_exists": True,
        "step_3_scope_status": step3_scope,
        "verdict": "survived_to_full_gate",
        "reason": "Passed Steps 1 and 3; ready for upstream-equivalent-gate",
    }


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run(
    workspace: Path,
    candidate_path: Path,
    output_path: Path,
    *,
    print_json: bool = False,
    fast_fail: bool = False,
) -> int:
    """Execute the sanity gate. Returns process exit code."""
    # Load candidate JSON
    try:
        raw = candidate_path.read_text(encoding="utf-8")
        payload = json.loads(raw)
    except FileNotFoundError:
        print(
            f"[sanity-gate] ERR candidate file not found: {candidate_path}",
            file=sys.stderr,
        )
        return 2
    except json.JSONDecodeError as exc:
        print(
            f"[sanity-gate] ERR invalid JSON in {candidate_path}: {exc}",
            file=sys.stderr,
        )
        return 2

    rows = _rows_from_payload(payload)

    killed_step1 = 0
    killed_step3 = 0
    survived_rows_inline: list[dict[str, Any]] = []
    result_rows: list[dict[str, Any]] = []

    for idx, row in enumerate(rows):
        verdict_record = _run_sanity_checks(row, idx, workspace)
        result_rows.append(verdict_record)

        v = verdict_record["verdict"]
        if v == "killed_step_1_path_missing":
            killed_step1 += 1
        elif v == "killed_step_3_oos":
            killed_step3 += 1
        else:
            survived_rows_inline.append(row)

    survived_count = len(survived_rows_inline)

    output: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "input_candidate_file": str(candidate_path),
        "input_row_count": len(rows),
        "survived_row_count": survived_count,
        "killed_at_step_1_count": killed_step1,
        "killed_at_step_3_count": killed_step3,
        "passed_to_full_gate_count": survived_count,
        "rows": result_rows,
        "survivors_inline": survived_rows_inline,
    }

    # Write output file
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(output, indent=2), encoding="utf-8")

    if print_json:
        # JSON to stdout so callers can pipe; summary to stderr
        print(json.dumps(output, indent=2))
        _sink = sys.stderr
    else:
        _sink = sys.stdout

    for r in result_rows:
        status = "PASS" if r["verdict"] == "survived_to_full_gate" else "KILL"
        print(
            f"[sanity-gate] {status} row={r['row_index']} "
            f"verdict={r['verdict']} path={r['production_path']!r}",
            file=_sink,
        )

    print(
        f"[sanity-gate] in={len(rows)} survived={survived_count} "
        f"killed_step1={killed_step1} killed_step3={killed_step3}",
        file=_sink,
    )

    if fast_fail and survived_count == 0:
        print(
            "[sanity-gate] FAST-FAIL: zero candidates survived.",
            file=sys.stderr,
        )
        return 1

    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="promotion-candidate-sanity-gate.py",
        description=(
            "Cheap pre-filter: runs Steps 1 (audit-tree existence) and 3 "
            "(SCOPE.md OOS) only. Filesystem-only, ~10ms per candidate. "
            "Wave O-E, Gap #5."
        ),
    )
    parser.add_argument(
        "--workspace",
        type=Path,
        required=True,
        help="Audit workspace root (contains external/, SCOPE.md).",
    )
    parser.add_argument(
        "--candidate",
        type=Path,
        required=True,
        help="Path to candidate JSON (promotion_candidates.json, any wave schema).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Where to write the filtered + per-row verdicts JSON.",
    )
    parser.add_argument(
        "--print-json",
        action="store_true",
        dest="print_json",
        help="Also print the output JSON to stdout.",
    )
    parser.add_argument(
        "--fast-fail",
        action="store_true",
        dest="fast_fail",
        help="Exit 1 if zero candidates survive.",
    )
    args = parser.parse_args(argv)

    if not args.workspace.is_dir():
        print(
            f"[sanity-gate] ERR workspace not found: {args.workspace}",
            file=sys.stderr,
        )
        return 2

    return run(
        workspace=args.workspace,
        candidate_path=args.candidate,
        output_path=args.output,
        print_json=args.print_json,
        fast_fail=args.fast_fail,
    )


if __name__ == "__main__":
    raise SystemExit(main())
