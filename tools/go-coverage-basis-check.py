#!/usr/bin/env python3
"""go-coverage-basis-check - fail CLOSED when a Cosmos-SDK / CometBFT Go-L1
workspace measured its function-coverage denominator on the WRONG basis.

THE generic backstop for the 2026-07-04 entry-point-basis class (commit
bccc99da1b shipped tools/go_entrypoint_surface.py + a Cosmos/Go-L1 narrowing of
the function-coverage denominator from every-exported-symbol to the true
external ENTRY-POINT surface: msg-server / ABCI / precompile / ante / IBC / RPC /
genesis+lifecycle+ValidateBasic). A Go `export` is a LINKAGE property, the
Solidity-`internal` analog - reached transitively through an entry point - so
scoring coverage over every exported keeper helper is wrong-basis: it inflates
the denominator and lets a Go L1 silently pass (or fail) on a surface that is
not the external attack surface.

The narrowing is fail-open (any uncertainty keeps every-exported = the safe /
stricter direction) and carries an env kill-switch
AUDITOOOR_FCC_GO_ENTRYPOINT_SCOPE=0. THIS gate is the whole-workspace safety net
that catches the case the producer cannot: the workspace IS a confident
Cosmos-Go-L1 but the fcc result does NOT record go_entry_surface.applied=True -
the kill-switch was left on, detection regressed, or the fcc result is a stale
pre-capability artifact. In any of those cases the coverage number was computed
on the every-exported denominator and must not silently green a Go L1.

READ-ONLY over tools/go_entrypoint_surface.py + function-coverage-completeness.py
output (the stable go_entry_surface.applied field); this gate never edits them.

Cosmos-detection is INTRINSIC here (independent of the kill-switch): it reuses
go_entrypoint_surface._has_cosmos_gomod / _has_cosmos_layout directly rather than
is_cosmos_go_workspace(), because is_cosmos_go_workspace() returns False when the
kill-switch is set - which is exactly the state this gate must still classify as
Cosmos-Go so it can flag the wrong-basis fcc result.

Verdicts:
  pass-not-cosmos-go     - not a confident Cosmos-Go-L1; entry-point narrowing is
                           N/A. Silent pass (Solidity/Rust/Move/Cairo unaffected).
  pass-entry-point-basis - Cosmos-Go-L1 AND fcc result records
                           go_entry_surface.applied=True (right denominator).
  fail-fcc-missing       - Cosmos-Go-L1 but no fcc result on disk (Step 3/5 fcc
                           never ran) - cannot assert the basis; NEVER a false
                           green (WARN advisory / FAIL strict).
  fail-wrong-basis       - Cosmos-Go-L1 but fcc go_entry_surface.applied != True
                           (kill-switch left on / detection failed / stale
                           pre-capability artifact) - coverage was scored on the
                           every-exported denominator (WARN advisory / FAIL
                           strict).

Advisory-first: WARN + rc 0 by default; the fail-* verdicts return ok=False (and
the CLI exits 1) ONLY under strict = AUDITOOOR_L37_STRICT=1 or the per-gate
AUDITOOOR_L37_GO_COVERAGE_BASIS_STRICT=1. Never green-passes on a missing/degraded
input: a missing fcc result on a Cosmos-Go-L1 is fail-fcc-missing, not a pass.

Exit 0 on pass-* (and on WARN-advisory fail-*); exit 1 only on a strict fail-*.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent

# The fcc artifact whose go_entry_surface.applied field we read (written by
# tools/function-coverage-completeness.py --json --write). READ-ONLY.
_FCC_RESULT_REL = ".auditooor/function_coverage_completeness.json"

# Instruction string surfaced on a fail-* verdict so the model knows the exact
# remediation (no em/en-dash; ascii only).
REMEDIATION = (
    "Re-run the Cosmos/Go-L1 function-coverage gate with the entry-point "
    "narrowing ENABLED so the denominator is the external entry-point surface, "
    "not every exported Go helper: unset (or =1) the kill-switch "
    "AUDITOOOR_FCC_GO_ENTRYPOINT_SCOPE, then rebuild the fcc result via "
    "`python3 tools/function-coverage-completeness.py --workspace <ws> --json --write` and "
    "confirm the written .auditooor/function_coverage_completeness.json carries "
    "go_entry_surface.applied=true. Do NOT hand-edit the fcc result."
)


def _load_go_entrypoint_surface():
    """Import tools/go_entrypoint_surface.py for its intrinsic Cosmos detectors.
    READ-ONLY reuse; returns None on any import failure (degrades to a
    detection-unavailable WARN-pass rather than a false classification)."""
    tool_path = _HERE / "go_entrypoint_surface.py"
    if not tool_path.is_file():
        return None
    try:
        spec = importlib.util.spec_from_file_location(
            "_go_entrypoint_surface_basis", tool_path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules["_go_entrypoint_surface_basis"] = mod
        spec.loader.exec_module(mod)
        return mod
    except Exception:
        return None


def _is_cosmos_go_intrinsic(ws: Path, ges_mod) -> bool | None:
    """Kill-switch-INDEPENDENT Cosmos-Go detection. Returns True/False, or None
    when the detector module is unavailable (caller degrades to WARN-pass)."""
    if ges_mod is None:
        return None
    try:
        has_gomod = getattr(ges_mod, "_has_cosmos_gomod", None)
        has_layout = getattr(ges_mod, "_has_cosmos_layout", None)
        if not callable(has_gomod) or not callable(has_layout):
            return None
        return bool(has_gomod(ws) or has_layout(ws))
    except Exception:
        return None


def _load_fcc_result(ws: Path) -> tuple[dict | None, Path]:
    p = ws / _FCC_RESULT_REL
    if not p.is_file():
        return None, p
    try:
        return json.loads(p.read_text(encoding="utf-8", errors="replace")), p
    except (OSError, ValueError):
        return None, p


def _strict() -> bool:
    """Advisory-first strict toggle: hard-fail only under the global L37 strict
    umbrella OR the dedicated per-gate env. Mirrors tools/audit-completeness-
    check.py::_l37_gate_strict('GO_COVERAGE_BASIS')."""
    if os.environ.get(
            "AUDITOOOR_L37_GO_COVERAGE_BASIS_STRICT", "").strip() == "1":
        return True
    if os.environ.get("AUDITOOOR_L37_STRICT", "").strip() == "1":
        return True
    return False


def evaluate(ws) -> dict:
    """Return a verdict dict. Never raises for expected inputs; NEVER green-passes
    on a missing/degraded input for a Cosmos-Go-L1 workspace."""
    ws = Path(ws)
    strict = _strict()
    ges = _load_go_entrypoint_surface()

    if ges is None:
        # Detector module unavailable: cannot classify. Degrade to a genuine
        # WARN-pass (tooling-absence does not block L37), never a false green
        # AND never a false Cosmos classification.
        return {
            "gate": "go-coverage-basis",
            "verdict": "pass-detector-unavailable",
            "ok": True,
            "strict": strict,
            "reason": ("go_entrypoint_surface.py unavailable; cannot classify "
                       "workspace basis - WARN-pass (tooling-absence)"),
            "is_cosmos_go": None,
            "fcc_present": None,
            "go_entry_surface_applied": None,
            "instruction": None,
        }

    is_cosmos = _is_cosmos_go_intrinsic(ws, ges)
    if is_cosmos is None:
        return {
            "gate": "go-coverage-basis",
            "verdict": "pass-detector-unavailable",
            "ok": True,
            "strict": strict,
            "reason": ("Cosmos-Go detectors unavailable in go_entrypoint_surface.py; "
                       "WARN-pass (tooling-absence)"),
            "is_cosmos_go": None,
            "fcc_present": None,
            "go_entry_surface_applied": None,
            "instruction": None,
        }

    if not is_cosmos:
        # Non-Cosmos workspace: the entry-point narrowing is N/A. Silent pass -
        # Solidity/Rust/Move/Cairo coverage basis is unaffected by this gate.
        return {
            "gate": "go-coverage-basis",
            "verdict": "pass-not-cosmos-go",
            "ok": True,
            "strict": strict,
            "reason": ("not a confident Cosmos-SDK/CometBFT Go-L1 workspace; "
                       "entry-point coverage-basis narrowing is N/A"),
            "is_cosmos_go": False,
            "fcc_present": None,
            "go_entry_surface_applied": None,
            "instruction": None,
        }

    fcc, fcc_path = _load_fcc_result(ws)
    if fcc is None:
        # Cosmos-Go-L1 but no fcc result: cannot assert the basis was correct.
        # NEVER a false green - WARN advisory / FAIL strict.
        reason = (
            f"Cosmos-Go-L1 workspace but no function-coverage result at "
            f"{_FCC_RESULT_REL}; the coverage basis cannot be asserted (Step 3/5 "
            f"fcc not run over this workspace). {REMEDIATION}")
        return {
            "gate": "go-coverage-basis",
            "verdict": "fail-fcc-missing",
            "ok": not strict,
            "strict": strict,
            "reason": ("WARN: " + reason) if not strict else reason,
            "is_cosmos_go": True,
            "fcc_present": False,
            "fcc_path": str(fcc_path),
            "go_entry_surface_applied": None,
            "instruction": REMEDIATION,
        }

    ges_block = fcc.get("go_entry_surface")
    applied = bool(isinstance(ges_block, dict) and ges_block.get("applied") is True)

    if applied:
        return {
            "gate": "go-coverage-basis",
            "verdict": "pass-entry-point-basis",
            "ok": True,
            "strict": strict,
            "reason": ("Cosmos-Go-L1 function-coverage denominator narrowed to the "
                       "external entry-point surface (go_entry_surface.applied=True)"),
            "is_cosmos_go": True,
            "fcc_present": True,
            "fcc_path": str(fcc_path),
            "go_entry_surface_applied": True,
            "entry_points": (ges_block.get("entry_points")
                             if isinstance(ges_block, dict) else None),
            "internal_helpers_excluded": (ges_block.get("internal_helpers_excluded")
                                          if isinstance(ges_block, dict) else None),
            "instruction": None,
        }

    # Cosmos-Go-L1 but go_entry_surface.applied != True: the denominator was the
    # every-exported set (kill-switch left on / detection failed / stale
    # pre-capability artifact with no go_entry_surface block at all).
    reason = (
        f"Cosmos-Go-L1 workspace but the fcc result does NOT record "
        f"go_entry_surface.applied=True (found: "
        f"{ges_block if ges_block is not None else 'no go_entry_surface block'}); "
        f"the function-coverage denominator was the every-exported set, not the "
        f"external entry-point surface - a Go L1 must not silently pass/fail on "
        f"the wrong basis. {REMEDIATION}")
    return {
        "gate": "go-coverage-basis",
        "verdict": "fail-wrong-basis",
        "ok": not strict,
        "strict": strict,
        "reason": ("WARN: " + reason) if not strict else reason,
        "is_cosmos_go": True,
        "fcc_present": True,
        "fcc_path": str(fcc_path),
        "go_entry_surface_applied": False,
        "instruction": REMEDIATION,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Fail-closed Cosmos/Go-L1 coverage-basis gate.")
    ap.add_argument("workspace", help="path to the audit workspace")
    ap.add_argument("--json", action="store_true", help="emit the verdict dict as JSON")
    args = ap.parse_args(argv)

    res = evaluate(args.workspace)
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print(f"go-coverage-basis  workspace: {args.workspace}")
        print(f"  verdict : {res['verdict']}")
        print(f"  strict  : {res['strict']}")
        print(f"  reason  : {res['reason']}")
        if res.get("instruction"):
            print(f"  INSTRUCTION: {res['instruction']}")
    return 0 if res.get("ok", True) else 1


if __name__ == "__main__":
    raise SystemExit(main())
