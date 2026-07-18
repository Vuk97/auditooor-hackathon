#!/usr/bin/env python3
"""Wave-1 hackerman capability lift (PR #726) - composite pre-merge runner.

Runs every pre-merge check in sequence, capturing each step's exit code
under ``|| true`` semantics (every step runs even if a prior one failed),
and emits a final aggregate verdict.

Steps (stable order):

    1. ``hackerman-all``                  - full hackerman gate suite
    2. ``docs-check``                     - cross-link + ontology checks
    3. ``hackerman-docs-cross-link-audit``- HACKERMAN/WAVE/PR_726 docs links
    4. ``hackerman-pr726-merge-checklist``- pre-merge GO/YELLOW/NO-GO checklist
    5. ``hackerman-mcp-smoke-test``       - live MCP callable surface check
    6. ``hackerman-unit-tests``           - test_hackerman_*.py discovery

Aggregate verdicts:

    * ``PASS``          - every step exited 0.
    * ``NEEDS-CHANGES`` - one or more non-critical steps failed
      (currently ``docs-check`` and ``hackerman-docs-cross-link-audit``)
      but every critical step (``hackerman-all``,
      ``hackerman-pr726-merge-checklist``, ``hackerman-mcp-smoke-test``,
      ``hackerman-unit-tests``) passed.
    * ``FAIL``          - one or more critical steps failed.

Exit code:

    * Default: 0 on PASS or NEEDS-CHANGES, 1 on FAIL.
    * ``--strict``: 0 on PASS only, 1 on NEEDS-CHANGES or FAIL.

Determinism:

    * Step order is fixed (``STEPS``).
    * Verdict derivation is a pure function of returncodes.
    * ``--generated-at`` (or env ``AUDITOOOR_HACKERMAN_PRE_MERGE_GENERATED_AT``)
      pins the envelope timestamp for reproducible JSON output.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


REPO_ROOT = Path(__file__).resolve().parents[1]

PASS = "PASS"
FAIL = "FAIL"
SKIPPED = "SKIPPED"

OVERALL_PASS = "PASS"
OVERALL_NEEDS_CHANGES = "NEEDS-CHANGES"
OVERALL_FAIL = "FAIL"

# Wave-2 PR-A: per-step subprocess ceiling raised from 1800s to 3600s
# (corpus-amplified `make hackerman-all` runs to ~30-50 min on the
# wave-2-corpus-migration branch; the previous 1800s ceiling timed out
# the orchestrator before any sub-check could complete). Configurable
# via env var ``AUDITOOOR_PRE_MERGE_STEP_TIMEOUT_S`` so operators can
# raise (or lower) the ceiling without code edits.
DEFAULT_STEP_TIMEOUT_S = 3600
STEP_TIMEOUT_ENV_VAR = "AUDITOOOR_PRE_MERGE_STEP_TIMEOUT_S"

# Wave-2 PR-A: env vars the orchestrator forwards into every sub-make
# subprocess so the underlying tools see operator-provided context
# (PR number, branch). The `make ... PR_NUMBER=N BRANCH=name`
# Make-variable form is ALSO appended to argv for the checklist step
# (Make-vars are NOT inherited from env). See `_step_argv_with_env`.
FORWARDED_ENV_VARS = (
    "PR_NUMBER",
    "BRANCH",
    "AUDITOOOR_TARGET_PR",
    "AUDITOOOR_TARGET_BRANCH",
)

# Step ids that accept `PR_NUMBER=...` / `BRANCH=...` as Make variable
# overrides on the argv (the Makefile target reads `$(PR_NUMBER)` /
# `$(BRANCH)` and short-circuits the tool's discovery cascade).
MAKE_VAR_FORWARD_STEP_IDS = frozenset({"hackerman-pr726-merge-checklist"})


# Each step: step_id, label, argv (list[str]), critical (bool).
# argv is executed verbatim from REPO_ROOT.
STEPS: List[Dict[str, Any]] = [
    {
        "step_id": "hackerman-all",
        "label": "make hackerman-all",
        "argv": ["make", "hackerman-all"],
        "critical": True,
    },
    {
        "step_id": "docs-check",
        "label": "make docs-check",
        "argv": ["make", "docs-check"],
        "critical": False,
    },
    {
        "step_id": "hackerman-docs-cross-link-audit",
        "label": "make hackerman-docs-cross-link-audit",
        "argv": ["make", "hackerman-docs-cross-link-audit"],
        "critical": False,
    },
    {
        # Wave-2 rename: the Makefile target moved from
        # `hackerman-pr726-merge-checklist` to the generic
        # `hackerman-pr-merge-checklist` which auto-discovers the target
        # PR + branch via `discover_target_pr_and_branch` in the
        # underlying tool (CLI > env > `gh pr status` > git current-
        # branch). step_id retained as-is for back-compat with
        # `tools/tests/test_hackerman_pre_merge.py::StepsShapeTests`.
        "step_id": "hackerman-pr726-merge-checklist",
        "label": "make hackerman-pr-merge-checklist",
        "argv": ["make", "hackerman-pr-merge-checklist"],
        "critical": True,
    },
    {
        "step_id": "hackerman-mcp-smoke-test",
        "label": "make hackerman-mcp-smoke-test",
        "argv": ["make", "hackerman-mcp-smoke-test"],
        "critical": True,
    },
    {
        "step_id": "hackerman-unit-tests",
        "label": "python3 -m unittest discover tools/tests/ -p test_hackerman_*",
        "argv": [
            sys.executable,
            "-m",
            "unittest",
            "discover",
            "-s",
            "tools/tests",
            "-p",
            "test_hackerman_*.py",
        ],
        "critical": True,
    },
]


def compute_overall(steps: List[Dict[str, Any]]) -> str:
    """Pure verdict aggregation.

    PASS if every step is PASS or SKIPPED.
    FAIL if any critical step is FAIL.
    NEEDS-CHANGES otherwise (a non-critical step failed but criticals passed).
    """
    any_critical_fail = False
    any_non_critical_fail = False
    for step in steps:
        verdict = step.get("verdict", FAIL)
        if verdict == FAIL:
            if step.get("critical", True):
                any_critical_fail = True
            else:
                any_non_critical_fail = True
    if any_critical_fail:
        return OVERALL_FAIL
    if any_non_critical_fail:
        return OVERALL_NEEDS_CHANGES
    return OVERALL_PASS


def _now_iso(pin: Optional[str]) -> str:
    if pin:
        return pin
    env_pin = os.environ.get("AUDITOOOR_HACKERMAN_PRE_MERGE_GENERATED_AT")
    if env_pin:
        return env_pin
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _step_argv_with_env(
    step: Dict[str, Any], env: Dict[str, str]
) -> List[str]:
    """Return the argv for ``step``, appending Make-var overrides
    (``PR_NUMBER=N`` / ``BRANCH=name``) parsed from ``env`` if the
    step opts in via ``MAKE_VAR_FORWARD_STEP_IDS``.

    Make variables are NOT inherited from the environment - they must
    be on the argv. Env-var forwarding (for tools that consult env
    directly) is handled separately by the subprocess ``env=`` param.
    """
    argv = list(step["argv"])
    if step.get("step_id") not in MAKE_VAR_FORWARD_STEP_IDS:
        return argv
    # Append Make-var overrides only when set in env (and non-empty).
    for var in ("PR_NUMBER", "BRANCH"):
        value = (env.get(var) or "").strip()
        if value:
            argv.append(f"{var}={value}")
    return argv


def _resolve_step_timeout(timeout: Optional[int]) -> int:
    """Resolve the per-step subprocess ceiling.

    Precedence: explicit ``timeout`` arg > env var
    ``AUDITOOOR_PRE_MERGE_STEP_TIMEOUT_S`` > ``DEFAULT_STEP_TIMEOUT_S``.
    Negative / zero / non-int env values fall back to the default.
    """
    if timeout is not None and timeout > 0:
        return timeout
    raw = os.environ.get(STEP_TIMEOUT_ENV_VAR)
    if raw:
        try:
            value = int(raw)
        except (TypeError, ValueError):
            value = 0
        if value > 0:
            return value
    return DEFAULT_STEP_TIMEOUT_S


def _run_step(
    step: Dict[str, Any],
    *,
    cwd: Path,
    timeout: int,
    dry_run: bool = False,
    env: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Run one step under ``|| true`` semantics; never raises."""
    if dry_run:
        return {
            **step,
            "verdict": SKIPPED,
            "returncode": None,
            "duration_s": 0.0,
            "stdout_tail": "",
            "stderr_tail": "",
            "reason": "dry-run",
        }
    if env is None:
        env = dict(os.environ)
    # Ensure each forwarded env var is present (even if only inherited)
    # so the sub-process sees the orchestrator's context. We do NOT
    # clear other env vars - the orchestrator runs make, which expects
    # PATH / HOME / etc.
    sub_env = dict(env)
    for var in FORWARDED_ENV_VARS:
        if var in os.environ and var not in sub_env:
            sub_env[var] = os.environ[var]
    argv = _step_argv_with_env(step, sub_env)
    start = time.monotonic()
    try:
        proc = subprocess.run(
            argv,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=sub_env,
        )
        duration = time.monotonic() - start
        verdict = PASS if proc.returncode == 0 else FAIL
        return {
            **step,
            "verdict": verdict,
            "returncode": proc.returncode,
            "duration_s": round(duration, 2),
            "stdout_tail": _tail(proc.stdout, 40),
            "stderr_tail": _tail(proc.stderr, 40),
            "reason": "",
        }
    except subprocess.TimeoutExpired:
        duration = time.monotonic() - start
        return {
            **step,
            "verdict": FAIL,
            "returncode": None,
            "duration_s": round(duration, 2),
            "stdout_tail": "",
            "stderr_tail": "",
            "reason": f"timeout after {timeout}s",
        }
    except (FileNotFoundError, OSError) as exc:
        duration = time.monotonic() - start
        return {
            **step,
            "verdict": FAIL,
            "returncode": None,
            "duration_s": round(duration, 2),
            "stdout_tail": "",
            "stderr_tail": "",
            "reason": f"exec error: {exc.__class__.__name__}: {exc}",
        }


def _tail(s: str, n_lines: int) -> str:
    if not s:
        return ""
    lines = s.splitlines()
    return "\n".join(lines[-n_lines:])


def _format_text(
    steps: List[Dict[str, Any]],
    overall: str,
    generated_at: str,
) -> str:
    lines: List[str] = []
    lines.append("=" * 78)
    lines.append("hackerman-pre-merge composite report")
    lines.append(f"generated_at: {generated_at}")
    lines.append("=" * 78)
    lines.append("")
    lines.append(f"{'STEP':<42}  {'CRIT':<5}  {'VERDICT':<8}  {'RC':<4}  {'DUR(s)':<7}")
    lines.append("-" * 78)
    for step in steps:
        crit = "yes" if step.get("critical", True) else "no"
        rc = step.get("returncode")
        rc_s = "-" if rc is None else str(rc)
        dur = step.get("duration_s", 0.0)
        lines.append(
            f"{step['step_id']:<42}  {crit:<5}  {step['verdict']:<8}  {rc_s:<4}  {dur:<7}"
        )
    lines.append("-" * 78)
    lines.append("")
    lines.append(f"OVERALL VERDICT: {overall}")
    # Per-step reasons for any FAIL.
    fail_lines: List[str] = []
    for step in steps:
        if step["verdict"] == FAIL:
            reason = step.get("reason") or f"exit={step.get('returncode')}"
            fail_lines.append(f"  - {step['step_id']}: {reason}")
    if fail_lines:
        lines.append("")
        lines.append("Failing steps:")
        lines.extend(fail_lines)
    lines.append("=" * 78)
    return "\n".join(lines) + "\n"


def _envelope(
    steps: List[Dict[str, Any]],
    overall: str,
    generated_at: str,
    *,
    exit_code: Optional[int] = None,
    runtime_seconds: Optional[float] = None,
) -> Dict[str, Any]:
    """Build the JSON envelope persisted by ``--out-json``.

    Adds three fields above the historical v1 schema so the
    ``tools/wave2-a-close-readiness.py`` cache reader can consume the
    file without re-running ``make hackerman-pre-merge`` (PR #728 Wave-2
    PR-A close-readiness cache contract):

      * ``overall_status``      mirror of ``overall`` (cache-reader-
                                friendly key name).
      * ``timestamp``           mirror of ``generated_at``.
      * ``exit_code``           the integer rc returned by ``main`` /
                                ``hackerman-pre-merge-cached``.
      * ``runtime_seconds``     wall-clock duration of the composite
                                run; falls back to the sum of per-step
                                ``duration_s`` when not provided.
      * ``sub_check_breakdown`` mirror of ``steps`` (cache-reader-
                                friendly key name).

    All new keys are additive; ``overall`` / ``steps`` / ``schema`` /
    ``generated_at`` remain present verbatim so callers pinned to the
    v1 schema keep working.
    """
    sub_check_breakdown = [
        {
            "step_id": s["step_id"],
            "label": s["label"],
            "critical": s.get("critical", True),
            "verdict": s["verdict"],
            "returncode": s.get("returncode"),
            "duration_s": s.get("duration_s", 0.0),
            "reason": s.get("reason", ""),
        }
        for s in steps
    ]
    if runtime_seconds is None:
        runtime_seconds = round(
            sum(float(s.get("duration_s") or 0.0) for s in steps), 2
        )
    return {
        "schema": "auditooor.hackerman_pre_merge.v1",
        "generated_at": generated_at,
        "timestamp": generated_at,
        "overall": overall,
        "overall_status": overall,
        "exit_code": exit_code,
        "runtime_seconds": runtime_seconds,
        "steps": sub_check_breakdown,
        "sub_check_breakdown": sub_check_breakdown,
    }


def run_pre_merge(
    *,
    cwd: Optional[Path] = None,
    timeout: Optional[int] = None,
    dry_run: bool = False,
    skip_steps: Optional[List[str]] = None,
    env: Optional[Dict[str, str]] = None,
) -> Tuple[List[Dict[str, Any]], str]:
    """Public entry point used by both CLI and tests.

    ``timeout`` resolution: explicit arg > env
    ``AUDITOOOR_PRE_MERGE_STEP_TIMEOUT_S`` > ``DEFAULT_STEP_TIMEOUT_S``
    (3600s). Wave-2 PR-A raised the default from 1800s to 3600s to
    accommodate the corpus-amplified ``make hackerman-all`` runtime.
    """
    cwd = cwd or REPO_ROOT
    skip_set = set(skip_steps or [])
    resolved_timeout = _resolve_step_timeout(timeout)
    results: List[Dict[str, Any]] = []
    for step in STEPS:
        if step["step_id"] in skip_set:
            results.append(
                {
                    **step,
                    "verdict": SKIPPED,
                    "returncode": None,
                    "duration_s": 0.0,
                    "stdout_tail": "",
                    "stderr_tail": "",
                    "reason": "skipped via --skip-step",
                }
            )
            continue
        results.append(
            _run_step(
                step,
                cwd=cwd,
                timeout=resolved_timeout,
                dry_run=dry_run,
                env=env,
            )
        )
    overall = compute_overall(results)
    return results, overall


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="hackerman-pre-merge composite runner (PR #726)"
    )
    parser.add_argument("--json", action="store_true", help="emit JSON envelope")
    parser.add_argument(
        "--out-json",
        type=str,
        default=None,
        help="write JSON envelope to this path (in addition to stdout)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="exit non-zero on NEEDS-CHANGES as well as FAIL",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=None,
        help=(
            "per-step subprocess timeout in seconds. Default: env "
            "AUDITOOOR_PRE_MERGE_STEP_TIMEOUT_S if set, otherwise 3600 "
            "(Wave-2 PR-A raised from 1800 for corpus-amplified runs)."
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="skip subprocess execution; mark every step SKIPPED (for tests)",
    )
    parser.add_argument(
        "--skip-step",
        action="append",
        default=[],
        help="skip a step (repeatable; uses step_id)",
    )
    parser.add_argument(
        "--generated-at",
        type=str,
        default=None,
        help="pin envelope timestamp (reproducible builds)",
    )
    args = parser.parse_args(argv)

    main_start = time.monotonic()
    results, overall = run_pre_merge(
        timeout=args.timeout,
        dry_run=args.dry_run,
        skip_steps=args.skip_step,
    )
    runtime_seconds = round(time.monotonic() - main_start, 2)
    generated_at = _now_iso(args.generated_at)

    if overall == OVERALL_FAIL:
        exit_code = 1
    elif args.strict and overall == OVERALL_NEEDS_CHANGES:
        exit_code = 1
    else:
        exit_code = 0

    envelope = _envelope(
        results,
        overall,
        generated_at,
        exit_code=exit_code,
        runtime_seconds=runtime_seconds,
    )

    if args.json:
        print(json.dumps(envelope, indent=2, sort_keys=True))
    else:
        sys.stdout.write(_format_text(results, overall, generated_at))

    if args.out_json:
        out_path = Path(args.out_json)
        if out_path.parent and str(out_path.parent) != ".":
            out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            json.dumps(envelope, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
