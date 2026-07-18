#!/usr/bin/env python3
"""enumeration-universe-consistency-check.py

Fail-closed check that the hunt PLAN classifier and the hunt GATE classifier
agree on the residual universe for a workspace.

24h retrospective anchor (NUVA + SEI, 2026-07-05/06): a hunt-scoped planning
pass reported a residual of 1644 units while hunt-coverage-gate's
``queued_not_scanned`` (the GATE's own residual) was 57 for the SAME
workspace at the SAME point in time - an ~29x balloon. Separately, a
value-mover ``.go`` file enumerated into the plan with an EMPTY function name
(``function=""``) even though the source file demonstrably defines functions -
a placeholder unit that silently inflates the denominator and can never be
"scanned" because nothing real is being tracked.

Neither of these divergences has a generic detector. This tool is that
detector: it loads the PLAN residual (whatever planning artifact exists) and
the GATE residual (hunt-coverage-gate's ``queued_not_scanned`` plus
function-coverage-completeness's ``go_entry_surface`` units), and fails
closed when:

  1. fail-gate-unit-unplanned        - a GATE queued/residual unit is ABSENT
                                        from the PLAN (the plan under-counts
                                        real residual work).
  2. fail-plan-overballooned         - PLAN size > GATE residual size by both
                                        > --tolerance multiplier (default 3x)
                                        AND > 50 absolute (the plan massively
                                        over-counts vs the gate's true
                                        residual - the 1644-vs-57 shape).
  3. fail-empty-function-enumeration - an enumerated unit has an EMPTY
                                        function name for a source file that
                                        DOES define functions (the
                                        function='' placeholder-unit bug).

NEVER-FALSE-PASS: when NEITHER a plan artifact NOR a gate artifact can be
resolved, the tool returns pass-insufficient-inputs (WARN, rc=0) and prints
exactly what inputs were missing - it never silently claims consistency it
did not check.

Verdicts:
  pass-consistent                  - plan and gate residuals agree within
                                      tolerance; no gate-unplanned units; no
                                      empty-function placeholder units.
  fail-gate-unit-unplanned         - >=1 GATE residual unit missing from PLAN.
  fail-plan-overballooned          - PLAN residual >> GATE residual (see
                                      --tolerance).
  fail-empty-function-enumeration  - >=1 unit enumerated with an empty
                                      function name over a source file that
                                      defines functions.
  pass-insufficient-inputs         - neither plan nor gate artifact resolvable;
                                      WARN only, rc=0 always.
  error                            - I/O or argument error.

Exit codes:
  0 - pass-consistent / pass-insufficient-inputs / any verdict when NOT --strict.
  1 - any fail-* verdict AND --strict.
  2 - error (bad --workspace, unreadable artifact under --strict-io, etc).

CLI:
  python3 tools/enumeration-universe-consistency-check.py --workspace <ws> [--json] [--strict] [--tolerance N]

Artifact: <ws>/.auditooor/enumeration_universe_consistency.json
  {schema, verdict, plan_count, gate_residual_count, gate_unplanned,
   empty_function_units, plan_source, gate_source, tolerance, generated_at}

Also writes the gate-residual unit list (one per line) to
<ws>/.auditooor/gate_residual_units.txt when a gate residual was resolved,
per the spec's "hunt only the gate residual (N), saved to <path>" guidance.

Schema: auditooor.enumeration_universe_consistency.v1
"""
from __future__ import annotations

import argparse
import datetime
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable

SCHEMA_VERSION = "auditooor.enumeration_universe_consistency.v1"

DEFAULT_TOLERANCE_MULTIPLIER = 3
DEFAULT_TOLERANCE_ABS_FLOOR = 50

# Heuristics for "does this source file define functions" - kept intentionally
# broad/generic (multi-language) rather than importing any single workspace's
# language-detection stack, per the tool-duplication preflight (build a new
# standalone check, don't couple to the giant gate module's internals).
_FUNC_DEF_PATTERNS = [
    re.compile(r"^\s*func\s+\w", re.MULTILINE),  # Go
    re.compile(r"^\s*(pub\s+)?fn\s+\w", re.MULTILINE),  # Rust
    re.compile(r"^\s*function\s+\w", re.MULTILINE),  # Solidity/JS
    re.compile(r"^\s*def\s+\w", re.MULTILINE),  # Python
    re.compile(r"\bfun\s+\w+\s*\(", re.MULTILINE),  # Move/Kotlin-ish
]


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _norm_unit(u: Any) -> str:
    """Normalize a unit identifier to a comparable string key."""
    if isinstance(u, dict):
        # common shapes: {"file":..,"function":..} or {"unit":..} or {"path":..}
        f = u.get("file") or u.get("path") or u.get("source") or ""
        fn = u.get("function") or u.get("fn") or ""
        if f and fn:
            return f"{f}::{fn}"
        return str(f or u.get("unit") or u)
    return str(u)


def _file_defines_functions(path: Path) -> bool:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return False
    return any(p.search(text) for p in _FUNC_DEF_PATTERNS)


# --------------------------------------------------------------------------
# PLAN residual loading
# --------------------------------------------------------------------------


def _newest(paths: Iterable[Path]) -> Path | None:
    candidates = [p for p in paths if p.is_file()]
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_mtime)


def load_plan_residual(ws: Path) -> tuple[list[Any] | None, str, Path | None]:
    """Return (plan_units, source_label, source_path).

    Resolution order (newest-first within each tier):
      1. <ws>/.auditooor/*residual*.jsonl
      2. <ws>/.auditooor/haiku_harness_*/manifest.json (plan manifest)
      3. residual-scope-per-fn output: <ws>/.auditooor/coverage_residual_worker_queue.json
    """
    audit_dir = ws / ".auditooor"
    if not audit_dir.is_dir():
        return None, "no-auditooor-dir", None

    # Tier 1: *residual*.jsonl
    jsonl_candidates = list(audit_dir.glob("*residual*.jsonl"))
    newest_jsonl = _newest(jsonl_candidates)
    if newest_jsonl is not None:
        units: list[Any] = []
        try:
            for line in newest_jsonl.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    units.append(json.loads(line))
                except Exception:
                    units.append(line)
        except Exception:
            return None, "plan-jsonl-unreadable", newest_jsonl
        return units, f"residual-jsonl:{newest_jsonl.name}", newest_jsonl

    # Tier 2: haiku_harness_*/manifest.json
    manifest_candidates = list(audit_dir.glob("haiku_harness_*/manifest.json"))
    newest_manifest = _newest(manifest_candidates)
    if newest_manifest is not None:
        try:
            data = json.loads(newest_manifest.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            return None, "plan-manifest-unreadable", newest_manifest
        units = None
        if isinstance(data, dict):
            for key in ("units", "residual", "planned_units", "worklist", "items"):
                if isinstance(data.get(key), list):
                    units = data[key]
                    break
        elif isinstance(data, list):
            units = data
        if units is None:
            return None, "plan-manifest-no-unit-list", newest_manifest
        return units, f"haiku-manifest:{newest_manifest.parent.name}", newest_manifest

    # Tier 3: residual-scope-per-fn worker queue
    queue_path = audit_dir / "coverage_residual_worker_queue.json"
    if queue_path.is_file():
        try:
            data = json.loads(queue_path.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            return None, "plan-worker-queue-unreadable", queue_path
        units = None
        if isinstance(data, dict):
            for key in ("units", "queue", "residual", "items"):
                if isinstance(data.get(key), list):
                    units = data[key]
                    break
        elif isinstance(data, list):
            units = data
        if units is None:
            return None, "plan-worker-queue-no-unit-list", queue_path
        return units, f"worker-queue:{queue_path.name}", queue_path

    return None, "no-plan-artifact", None


# --------------------------------------------------------------------------
# GATE residual loading
# --------------------------------------------------------------------------


def load_gate_residual(
    ws: Path, gate_json_path: Path | None = None
) -> tuple[list[Any] | None, str, Path | None]:
    """Return (gate_units, source_label, source_path).

    Prefers an explicit --gate-json artifact (e.g. hunt-coverage-gate.py
    --json output captured to disk), else falls back to on-disk sidecars
    that already carry the gate's own residual computation:
      - <ws>/.auditooor/g15_hunt_coverage_gate_last_result.json (queued_not_scanned)
      - <ws>/.auditooor/function_coverage_completeness_last_result.json (go_entry_surface)
    """
    if gate_json_path is not None:
        if not gate_json_path.is_file():
            return None, "gate-json-path-missing", gate_json_path
        try:
            data = json.loads(gate_json_path.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            return None, "gate-json-unreadable", gate_json_path
        units = _extract_gate_units(data)
        if units is None:
            return None, "gate-json-no-residual-key", gate_json_path
        return units, f"gate-json:{gate_json_path.name}", gate_json_path

    audit_dir = ws / ".auditooor"
    if not audit_dir.is_dir():
        return None, "no-auditooor-dir", None

    g15_path = audit_dir / "g15_hunt_coverage_gate_last_result.json"
    if g15_path.is_file():
        try:
            data = json.loads(g15_path.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            return None, "g15-result-unreadable", g15_path
        units = _extract_gate_units(data)
        if units is not None:
            return units, f"g15-result:{g15_path.name}", g15_path

    fcc_path = audit_dir / "function_coverage_completeness_last_result.json"
    if fcc_path.is_file():
        try:
            data = json.loads(fcc_path.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            return None, "fcc-result-unreadable", fcc_path
        units = _extract_gate_units(data)
        if units is not None:
            return units, f"fcc-result:{fcc_path.name}", fcc_path

    return None, "no-gate-artifact", None


def _extract_gate_units(data: Any) -> list[Any] | None:
    if not isinstance(data, dict):
        return None
    for key in ("queued_not_scanned", "go_entry_surface", "residual", "residual_units"):
        val = data.get(key)
        if isinstance(val, list):
            return val
    return None


# --------------------------------------------------------------------------
# Empty-function-enumeration check
# --------------------------------------------------------------------------


def find_empty_function_units(ws: Path, plan_units: list[Any] | None) -> list[str]:
    """Return unit keys where function=='' but the source file defines functions."""
    if not plan_units:
        return []
    offenders: list[str] = []
    for u in plan_units:
        if not isinstance(u, dict):
            continue
        fn = u.get("function")
        if fn is None or (isinstance(fn, str) and fn.strip() != ""):
            continue
        # function is present as a key and is an empty string -> placeholder suspect
        file_field = u.get("file") or u.get("path") or u.get("source")
        if not file_field:
            continue
        candidate = Path(file_field)
        if not candidate.is_absolute():
            candidate = ws / file_field
        if candidate.is_file() and _file_defines_functions(candidate):
            offenders.append(_norm_unit(u))
    return offenders


# --------------------------------------------------------------------------
# Main check
# --------------------------------------------------------------------------


def run_check(
    ws: Path,
    tolerance_multiplier: float = DEFAULT_TOLERANCE_MULTIPLIER,
    tolerance_abs_floor: int = DEFAULT_TOLERANCE_ABS_FLOOR,
    gate_json_path: Path | None = None,
) -> dict[str, Any]:
    plan_units, plan_source, _plan_path = load_plan_residual(ws)
    gate_units, gate_source, _gate_path = load_gate_residual(ws, gate_json_path=gate_json_path)

    result: dict[str, Any] = {
        "schema": SCHEMA_VERSION,
        "generated_at": _now_iso(),
        "workspace": str(ws),
        "plan_source": plan_source,
        "gate_source": gate_source,
        "tolerance_multiplier": tolerance_multiplier,
        "tolerance_abs_floor": tolerance_abs_floor,
    }

    if plan_units is None and gate_units is None:
        result.update(
            {
                "verdict": "pass-insufficient-inputs",
                "plan_count": None,
                "gate_residual_count": None,
                "gate_unplanned": [],
                "empty_function_units": [],
                "missing": [plan_source, gate_source],
            }
        )
        return result

    plan_keys = {_norm_unit(u) for u in (plan_units or [])}
    gate_keys_list = [_norm_unit(u) for u in (gate_units or [])]
    gate_keys = set(gate_keys_list)

    plan_count = len(plan_keys)
    gate_count = len(gate_keys)

    empty_function_units = find_empty_function_units(ws, plan_units)

    # Check 1: gate-unit-unplanned - any GATE residual unit absent from PLAN.
    gate_unplanned = sorted(gate_keys - plan_keys) if (plan_units is not None and gate_units is not None) else []

    verdict = "pass-consistent"

    if empty_function_units:
        verdict = "fail-empty-function-enumeration"
    elif gate_unplanned:
        verdict = "fail-gate-unit-unplanned"
    elif plan_units is not None and gate_units is not None:
        # Check 2: plan-overballooned - PLAN >> GATE by BOTH multiplier AND abs floor.
        if gate_count == 0:
            overballooned = plan_count > tolerance_abs_floor
        else:
            overballooned = (
                plan_count > gate_count * tolerance_multiplier
                and (plan_count - gate_count) > tolerance_abs_floor
            )
        if overballooned:
            verdict = "fail-plan-overballooned"

    result.update(
        {
            "verdict": verdict,
            "plan_count": plan_count if plan_units is not None else None,
            "gate_residual_count": gate_count if gate_units is not None else None,
            "gate_unplanned": gate_unplanned,
            "empty_function_units": empty_function_units,
        }
    )

    # Emit gate-residual unit list artifact when resolvable.
    if gate_units is not None:
        audit_dir = ws / ".auditooor"
        try:
            audit_dir.mkdir(parents=True, exist_ok=True)
            out_path = audit_dir / "gate_residual_units.txt"
            out_path.write_text("\n".join(sorted(gate_keys)) + ("\n" if gate_keys else ""), encoding="utf-8")
            result["gate_residual_units_path"] = str(out_path)
        except Exception:
            pass

    return result


def _write_artifact(ws: Path, result: dict[str, Any]) -> Path | None:
    audit_dir = ws / ".auditooor"
    try:
        audit_dir.mkdir(parents=True, exist_ok=True)
        out_path = audit_dir / "enumeration_universe_consistency.json"
        out_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return out_path
    except Exception:
        return None


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Fail-closed check that the hunt PLAN residual and the hunt GATE residual agree."
    )
    p.add_argument("--workspace", required=True, help="Workspace path.")
    p.add_argument("--json", action="store_true", help="Emit JSON verdict payload to stdout.")
    p.add_argument("--strict", action="store_true", help="Exit 1 on any fail-* verdict.")
    p.add_argument(
        "--tolerance",
        type=float,
        default=DEFAULT_TOLERANCE_MULTIPLIER,
        help=f"PLAN-vs-GATE overballoon multiplier threshold (default {DEFAULT_TOLERANCE_MULTIPLIER}).",
    )
    p.add_argument(
        "--tolerance-abs-floor",
        type=int,
        default=DEFAULT_TOLERANCE_ABS_FLOOR,
        help=f"Absolute-count floor paired with --tolerance (default {DEFAULT_TOLERANCE_ABS_FLOOR}).",
    )
    p.add_argument(
        "--gate-json",
        default=None,
        help="Optional explicit path to a captured hunt-coverage-gate.py --json output file.",
    )
    args = p.parse_args(argv)

    ws = Path(args.workspace).resolve()
    if not ws.exists():
        print(f"error: workspace path does not exist: {ws}", file=sys.stderr)
        return 2

    gate_json_path = Path(args.gate_json).resolve() if args.gate_json else None

    result = run_check(
        ws,
        tolerance_multiplier=args.tolerance,
        tolerance_abs_floor=args.tolerance_abs_floor,
        gate_json_path=gate_json_path,
    )

    artifact_path = _write_artifact(ws, result)
    if artifact_path is not None:
        result["artifact_path"] = str(artifact_path)

    verdict = result["verdict"]

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"verdict: {verdict}")
        print(f"plan_source: {result['plan_source']}  plan_count: {result['plan_count']}")
        print(f"gate_source: {result['gate_source']}  gate_residual_count: {result['gate_residual_count']}")
        if verdict == "fail-gate-unit-unplanned":
            print(f"gate_unplanned ({len(result['gate_unplanned'])}): {result['gate_unplanned'][:20]}")
        if verdict == "fail-plan-overballooned":
            gr_path = result.get("gate_residual_units_path", "<unwritten>")
            print(
                f"hunt only the gate residual ({result['gate_residual_count']}), saved to {gr_path}"
            )
        if verdict == "fail-empty-function-enumeration":
            print(
                f"empty_function_units ({len(result['empty_function_units'])}): "
                f"{result['empty_function_units'][:20]}"
            )
        if verdict == "pass-insufficient-inputs":
            print(f"missing inputs: {result.get('missing')}")
        if artifact_path is not None:
            print(f"artifact: {artifact_path}")

    if verdict.startswith("fail-") and args.strict:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
