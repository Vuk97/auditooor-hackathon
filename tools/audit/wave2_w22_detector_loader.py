#!/usr/bin/env python3
"""wave2_w22_detector_loader.py - PREVIEW-ONLY loader for the W2.2 Phase-1
detector roster.

Reads ``tools/audit/detector_previews/wave2_w22_phase1_roster.json`` (20
hand-curated tier-1 detector entries shipped in Wave-1) and emits a per-
detector dispatch spec compatible with the existing detector-runner shape
(``tools/{go,rust,anchor,reth,cosmos}-detector-runner.py``).

Default behavior: **OFF**. The environment variable
``AUDITOOOR_W22_PHASE1_ENABLED`` gates execution. When unset / ``0`` / ``""``
the loader returns an empty dispatch plan and the only valid load result is
the static roster (no dispatch). The operator flips the flag to ``1`` to opt
in for an actual scan; until then this loader is a structural preview.

Not yet wired into ``make audit``. Wiring is Phase 2 and is operator-gated.

Schema of a dispatch spec entry::

    {
        "detector_id":     str,    # e.g. w22_sol_reentrancy_curve_stable
        "language":        str,    # solidity | vyper | go | rust | circom | ...
        "attack_class":    str,
        "severity_floor":  str,    # HIGH | CRITICAL
        "cluster_group":   str,
        "fixture_path":    str|None,
        "runner":          str,    # path to the existing per-language runner
        "runner_status":   str,    # available | not_yet_supported
        "args":            list[str],  # CLI args to invoke runner with
        "enabled":         bool,   # gated by AUDITOOOR_W22_PHASE1_ENABLED
        "phase":           "wave2_w22_phase_1",
        "rationale":       str,
    }

The loader does NOT execute any runner. Callers (e.g. a future ``make audit``
recipe gated by the operator) call ``dispatch_plan(...)`` and then iterate
over the returned list.

Design notes:
- Stdlib only.
- Default-off contract is a HARD invariant. ``--print-plan`` always renders
  the static plan; ``--execute`` requires the env flag to be set AND a
  ``--workspace`` to be passed AND the runner to be available.
- Runner map covers the 4 of 5 language buckets present in the Phase-1
  roster that already have a detector-runner. Circom (1 entry,
  ``w22_circom_under_constrained``) and Vyper (3 entries) have no runner
  in the current tree; they are marked ``runner_status="not_yet_supported"``
  so the dispatch plan documents the gap without blocking the rest.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


_HERE = Path(__file__).resolve().parent
_ROSTER_PATH = _HERE / "detector_previews" / "wave2_w22_phase1_roster.json"
_PHASE2_ROSTER_PATH = _HERE / "detector_previews" / "wave2_w22_phase2_roster.json"
_TOOLS_DIR = _HERE.parent

# Env-flag is OFF by default. The orchestrator (or operator) flips this to
# "1" to opt in. Empty / unset / "0" / "false" / "no" -> disabled.
ENV_FLAG_NAME = "AUDITOOOR_W22_PHASE1_ENABLED"
_TRUE_VALUES = {"1", "true", "yes", "on"}

# ---------------------------------------------------------------------------
# Phase-2 active-roster API (W3.7)
# ---------------------------------------------------------------------------
#
# The Phase-1 dispatch API above (dispatch_plan / build_spec) is preserved
# unchanged for backward compatibility. The functions below add the
# Phase-2-aware "active roster" API consumed by the smoke driver
# (tools/audit/wave2_w22_phase2_smoke.py) and its test sibling.
#
# Default-OFF contract (HARD invariant):
#   - PHASE1_ENV_FLAG unset/falsey  -> no active detectors at all.
#   - PHASE2_ENV_FLAG without PHASE1 -> no-op (Phase-2 IMPLIES Phase-1).
#   - Both flags truthy             -> Phase-1 (20) + Phase-2 (20) = 40.
#
# Phase-2 stays opt-in until a human reviews real-source detector output;
# see docs/WAVE3_W37_PHASE2_REVIEW_GATE.md. This loader never flips a
# default.

PHASE1_ENV_FLAG = "AUDITOOOR_W22_PHASE1_ENABLED"
PHASE2_ENV_FLAG = "AUDITOOOR_W22_PHASE2_ENABLED"


def _flag_truthy(env: dict[str, str] | None, name: str) -> bool:
    """Return True iff env var ``name`` is a recognised truthy value."""
    e = os.environ if env is None else env
    return (e.get(name) or "").strip().lower() in _TRUE_VALUES


def phase1_enabled(env: dict[str, str] | None = None) -> bool:
    """True iff AUDITOOOR_W22_PHASE1_ENABLED is truthy. Default OFF."""
    return _flag_truthy(env, PHASE1_ENV_FLAG)


def phase2_enabled(env: dict[str, str] | None = None) -> bool:
    """True iff AUDITOOOR_W22_PHASE2_ENABLED is truthy. Default OFF.

    Note: Phase-2 IMPLIES Phase-1. ``phase2_enabled`` only reports the raw
    flag state; ``load_active_detectors`` enforces the implication (Phase-2
    detectors are only loaded when Phase-1 is ALSO on).
    """
    return _flag_truthy(env, PHASE2_ENV_FLAG)


def _load_roster_detectors(path: Path, expected_phase: str) -> list[dict[str, Any]]:
    """Load and lightly validate one roster JSON, returning its detector list."""
    if not path.exists():
        raise FileNotFoundError(f"roster not found: {path}")
    raw = json.loads(path.read_text(encoding="utf-8"))
    phase = raw.get("phase", "")
    if phase != expected_phase:
        raise ValueError(
            f"roster phase mismatch: expected {expected_phase!r}, got {phase!r}"
        )
    detectors = raw.get("detectors", [])
    if not isinstance(detectors, list):
        raise ValueError(f"roster {path} has non-list 'detectors'")
    return detectors


def load_phase1_roster() -> list[dict[str, Any]]:
    """Return the 20 hand-curated Phase-1 detector entries (unconditional read)."""
    return _load_roster_detectors(_ROSTER_PATH, "wave2_w22_phase_1")


def load_phase2_roster() -> list[dict[str, Any]]:
    """Return the 20 auto-generated Phase-2 detector entries (unconditional read).

    Reading the roster is always allowed; whether the entries become ACTIVE
    is gated by ``load_active_detectors`` + the two env flags.
    """
    return _load_roster_detectors(_PHASE2_ROSTER_PATH, "wave2_w22_phase_2")


def load_active_detectors(env: dict[str, str] | None = None) -> list[dict[str, Any]]:
    """Return the detectors that are ACTIVE given the current env flags.

    - Phase-1 OFF                 -> [] (default-off contract).
    - Phase-1 ON,  Phase-2 OFF    -> 20 Phase-1 entries.
    - Phase-1 ON,  Phase-2 ON     -> 40 entries (Phase-1 + Phase-2).
    - Phase-1 OFF, Phase-2 ON     -> [] (Phase-2 implies Phase-1; no-op).
    """
    if not phase1_enabled(env):
        return []
    active = list(load_phase1_roster())
    if phase2_enabled(env):
        active.extend(load_phase2_roster())
    return active


def loader_status(env: dict[str, str] | None = None) -> dict[str, Any]:
    """Emit a stable status envelope describing flag state + active counts."""
    p1_on = phase1_enabled(env)
    p2_on = phase2_enabled(env)
    p1 = load_phase1_roster()
    p2 = load_phase2_roster()
    p1_count = len(p1) if p1_on else 0
    p2_count = len(p2) if (p1_on and p2_on) else 0
    return {
        "schema": "auditooor.wave2_w22_loader_status.v1",
        "phase1_env_flag": PHASE1_ENV_FLAG,
        "phase1_enabled": p1_on,
        "phase2_env_flag": PHASE2_ENV_FLAG,
        "phase2_enabled": p2_on,
        "phase1_roster_path": str(_ROSTER_PATH),
        "phase2_roster_path": str(_PHASE2_ROSTER_PATH),
        "phase1_detector_count": p1_count,
        "phase2_detector_count": p2_count,
        "active_detector_count": p1_count + p2_count,
    }


# ---------------------------------------------------------------------------
# Per-language runner registry
# ---------------------------------------------------------------------------
#
# Maps the roster's ``language`` field to the existing per-language detector
# runner. ``None`` means "no runner yet"; the loader will mark such entries
# ``runner_status="not_yet_supported"`` in the dispatch plan so the gap is
# documented (not silently dropped).
#
# Solidity / Vyper / Circom currently have no dedicated runner in this tree;
# Phase-2 may add them. Go / Rust use the existing SPARK-GAP-001 / Wave-1
# runners respectively. Cosmos / reth / anchor live alongside go/rust and
# are not used by Phase-1 (none of the 20 entries are cosmos/reth/anchor-
# class).

_RUNNER_MAP: dict[str, str | None] = {
    "go": "tools/go-detector-runner.py",
    "rust": "tools/rust-detector-runner.py",
    "solidity": None,
    "vyper": None,
    "circom": None,
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class DetectorSpec:
    """One dispatch entry. See module docstring for schema notes."""

    detector_id: str
    language: str
    attack_class: str
    severity_floor: str
    cluster_group: str
    fixture_path: str | None
    runner: str | None
    runner_status: str
    args: list[str] = field(default_factory=list)
    enabled: bool = False
    phase: str = "wave2_w22_phase_1"
    rationale: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def env_flag_enabled(env: dict[str, str] | None = None) -> bool:
    """Return True iff ``AUDITOOOR_W22_PHASE1_ENABLED`` is a truthy value.

    Default-off contract: anything other than the small set in
    ``_TRUE_VALUES`` (case-insensitive) -> False.
    """

    e = os.environ if env is None else env
    raw = (e.get(ENV_FLAG_NAME) or "").strip().lower()
    return raw in _TRUE_VALUES


def load_roster(path: Path | None = None) -> dict[str, Any]:
    """Load the W2.2 Phase-1 roster JSON.

    Raises FileNotFoundError if the file is missing, ValueError if the
    schema header does not match the Wave-1 roster shape.
    """

    p = path if path is not None else _ROSTER_PATH
    if not p.exists():
        raise FileNotFoundError(f"roster not found: {p}")
    raw = json.loads(p.read_text(encoding="utf-8"))
    schema = raw.get("schema", "")
    if not schema.startswith("auditooor.wave2_w22_phase1_roster"):
        raise ValueError(
            f"roster schema mismatch: expected wave2_w22_phase1_roster, got {schema!r}"
        )
    if raw.get("phase") != "wave2_w22_phase_1":
        raise ValueError(
            f"roster phase mismatch: expected wave2_w22_phase_1, got {raw.get('phase')!r}"
        )
    return raw


def build_spec(
    entry: dict[str, Any],
    workspace: Path | None = None,
    env: dict[str, str] | None = None,
) -> DetectorSpec:
    """Build a single dispatch spec from one roster entry.

    ``workspace`` is optional. When provided, it becomes the ``--workspace``
    arg in the runner CLI invocation. When omitted, ``args`` is empty (the
    spec is structural-only).

    ``enabled`` mirrors ``env_flag_enabled()`` AND ``runner_status ==
    "available"`` AND ``workspace is not None``. All three must hold for
    the entry to be dispatched.
    """

    lang = entry.get("language", "")
    runner = _RUNNER_MAP.get(lang)
    if runner is None:
        runner_status = "not_yet_supported"
    else:
        runner_status = "available"

    args: list[str] = []
    if runner_status == "available" and workspace is not None:
        args = ["--workspace", str(workspace)]

    env_on = env_flag_enabled(env=env)
    enabled = (
        env_on
        and runner_status == "available"
        and workspace is not None
    )

    return DetectorSpec(
        detector_id=entry["detector_id"],
        language=lang,
        attack_class=entry.get("attack_class", ""),
        severity_floor=entry.get("severity_floor", ""),
        cluster_group=entry.get("cluster_group", ""),
        fixture_path=entry.get("fixture_path"),
        runner=runner,
        runner_status=runner_status,
        args=args,
        enabled=enabled,
        phase="wave2_w22_phase_1",
        rationale=entry.get("rationale", ""),
    )


def dispatch_plan(
    workspace: Path | None = None,
    roster_path: Path | None = None,
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Build the full dispatch plan for all 20 W2.2 Phase-1 detectors.

    Returns a dict shaped::

        {
            "schema": "auditooor.wave2_w22_phase1_dispatch_plan.v1",
            "env_flag": "AUDITOOOR_W22_PHASE1_ENABLED",
            "env_flag_value": str,
            "enabled_globally": bool,
            "workspace": str | None,
            "detector_count": int,
            "dispatchable_count": int,
            "not_yet_supported_count": int,
            "phase": "wave2_w22_phase_1",
            "specs": [DetectorSpec.to_dict(), ...],
        }
    """

    roster = load_roster(roster_path)
    detectors = roster.get("detectors", [])
    specs = [build_spec(d, workspace=workspace, env=env) for d in detectors]

    e = os.environ if env is None else env
    raw_flag = e.get(ENV_FLAG_NAME, "")

    return {
        "schema": "auditooor.wave2_w22_phase1_dispatch_plan.v1",
        "env_flag": ENV_FLAG_NAME,
        "env_flag_value": raw_flag,
        "enabled_globally": env_flag_enabled(env=env),
        "workspace": str(workspace) if workspace else None,
        "detector_count": len(specs),
        "dispatchable_count": sum(1 for s in specs if s.enabled),
        "not_yet_supported_count": sum(
            1 for s in specs if s.runner_status == "not_yet_supported"
        ),
        "phase": "wave2_w22_phase_1",
        "specs": [s.to_dict() for s in specs],
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description=(
            "PREVIEW-ONLY loader for the W2.2 Phase-1 detector roster. "
            "Default OFF: AUDITOOOR_W22_PHASE1_ENABLED=1 is required to "
            "actually dispatch (and the runner must exist; Phase-2 wires "
            "this into `make audit`)."
        ),
    )
    p.add_argument(
        "--workspace",
        type=Path,
        default=None,
        help=(
            "Workspace root (optional; populates the per-detector CLI args). "
            "Without --workspace the plan is structural-only."
        ),
    )
    p.add_argument(
        "--roster",
        type=Path,
        default=None,
        help="Override roster JSON path (default: tools/audit/detector_previews/wave2_w22_phase1_roster.json).",
    )
    p.add_argument(
        "--print-plan",
        action="store_true",
        help="Print the JSON dispatch plan to stdout and exit.",
    )
    p.add_argument(
        "--require-enabled",
        action="store_true",
        help=(
            "Exit 3 if AUDITOOOR_W22_PHASE1_ENABLED is not truthy. Used by "
            "future operator-gated wrapper scripts; default behavior just "
            "prints the plan with `enabled_globally=false` and exits 0."
        ),
    )
    p.add_argument(
        "--phase2",
        action="store_true",
        help=(
            "Opt in to the Phase-2 auto-generated detector roster (20 extra "
            "tier-2 detectors). Equivalent to exporting "
            "AUDITOOOR_W22_PHASE2_ENABLED=1 for this invocation. Default OFF; "
            "Phase-2 IMPLIES Phase-1 (it is a no-op without Phase-1). Stays "
            "opt-in until a human reviews real-source output - see "
            "docs/WAVE3_W37_PHASE2_REVIEW_GATE.md. This flag NEVER flips a "
            "persisted default."
        ),
    )
    args = p.parse_args(argv)

    # --phase2 is a per-invocation opt-in: it sets the env flag for this
    # process only. The default-OFF contract for any other process is
    # untouched (no persisted state is written).
    if args.phase2:
        os.environ[PHASE2_ENV_FLAG] = "1"

    # When --phase2 is requested, surface the active-roster status so the
    # operator sees how many detectors the Phase-2 opt-in activates.
    if args.phase2:
        status = loader_status()
        print(json.dumps(status, indent=2, sort_keys=True))
        if not status["phase1_enabled"]:
            print(
                f"[wave2_w22_detector_loader] NOTE: --phase2 is a no-op "
                f"because {PHASE1_ENV_FLAG} is not set. Phase-2 implies "
                f"Phase-1; export {PHASE1_ENV_FLAG}=1 to activate.",
                file=sys.stderr,
            )
        return 0

    plan = dispatch_plan(
        workspace=args.workspace,
        roster_path=args.roster,
    )

    if args.require_enabled and not plan["enabled_globally"]:
        print(
            f"[wave2_w22_detector_loader] {ENV_FLAG_NAME} is not set; "
            "default-OFF preview path. Set the flag to 1 to opt in.",
            file=sys.stderr,
        )
        return 3

    if args.print_plan or not args.workspace:
        print(json.dumps(plan, indent=2, sort_keys=True))
        return 0

    # Structural mode: print a one-line summary when a workspace is given
    # but --print-plan is not. Even when enabled, this loader does NOT
    # execute the runners; that is Phase-2 wiring's job.
    print(
        f"[wave2_w22_detector_loader] phase={plan['phase']} "
        f"detectors={plan['detector_count']} "
        f"dispatchable={plan['dispatchable_count']} "
        f"not_yet_supported={plan['not_yet_supported_count']} "
        f"env_flag={ENV_FLAG_NAME}={'on' if plan['enabled_globally'] else 'off'}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
