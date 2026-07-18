#!/usr/bin/env python3
"""wave3-e2e-pipeline.py - end-to-end orchestrator for the Wave-3 finding lifecycle.

PR #729 / Wave-3 item #5. The pipeline takes a workspace + cluster name and
walks through the five Wave-3 capability lifts in order:

  Step 1: cluster -> Hacker Brief         (tools/wave3-cluster-to-hacker-brief.py)
  Step 2: brief   -> Rule-30 PoC scaffold (tools/wave3-poc-scaffold-generator.py)
  Step 3: operator builds PoC against the scaffold      (manual wait gate)
  Step 4: draft   -> originality scan      (tools/wave3-published-source-originality-scanner.py)
  Step 5: draft   -> platform paste-ready  (tools/wave3-paste-ready-packager.py)

The pipeline is COORDINATING, not RE-IMPLEMENTING; each step shells out to
the sibling tool. If a sibling tool has not landed yet (Wave-3 items #1-#4
are being built in parallel), the step is recorded as SKIPPED with a
diagnostic and the pipeline keeps going (unless --strict is set).

Pipeline state lives in `<out-dir>/pipeline_state.json` and conforms to the
JSON schema `auditooor.wave3_e2e_pipeline.v1`.

Exit codes:
  0   pipeline completed cleanly, paused for operator PoC, or finished with
      non-strict warnings/skips
  1   blocking step failed, originality BLOCK, sibling tool returned !=0
      under --strict, unrecoverable I/O error, or any WARNING / SKIPPED
      step under --strict (strict treats degraded as failure)

Exit-code table (overall_status -> exit):
  COMPLETE                  -> 0
  WAITING_FOR_OPERATOR      -> 0 (clean operator-build pause)
  DEGRADED-WITH-WARNINGS    -> 0 normally, 1 under --strict
  BLOCKED                   -> 1
  FAILED                    -> 1

CLI:
  wave3-e2e-pipeline.py --workspace <ws> --cluster <name> \
      --target-platform {cantina|immunefi|sherlock|code4rena} \
      --target-protocol <name> \
      [--out-dir <path>] [--strict] [--steps 1,2,3,4,5] [--resume]

Stdlib-only. No em-dashes anywhere in this file.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


SCHEMA_ID = "auditooor.wave3_e2e_pipeline.v1"

# Sibling tool registry. Each entry: (step_number, tool_path_relative_to_tools_dir,
# step_name, requires_input, produces_output_glob).
SIBLING_TOOLS: Dict[int, Dict[str, Any]] = {
    1: {
        "name": "cluster-to-hacker-brief",
        "tool": "wave3-cluster-to-hacker-brief.py",
        "description": "Convert engage cluster into a Hacker Brief",
    },
    2: {
        "name": "poc-scaffold-generator",
        "tool": "wave3-poc-scaffold-generator.py",
        "description": "Emit Rule-30-compliant PoC scaffold from the Hacker Brief",
    },
    3: {
        "name": "operator-builds-poc",
        "tool": None,
        "description": "Operator builds the PoC against the scaffold",
    },
    4: {
        "name": "published-source-originality-scanner",
        "tool": "wave3-published-source-originality-scanner.py",
        "description": "Dupe-check across 4 platforms + NVD/GHSA + prior audits",
    },
    5: {
        "name": "paste-ready-packager",
        "tool": "wave3-paste-ready-packager.py",
        "description": "Emit platform-shaped paste-ready submission",
    },
}

# Status constants. UPPER_SNAKE for JSON values; lower-case helpers in code.
STATUS_PENDING = "PENDING"
STATUS_RUNNING = "RUNNING"
STATUS_OK = "OK"
STATUS_WARNING = "WARNING"
STATUS_BLOCKED = "BLOCKED"
STATUS_FAILED = "FAILED"
STATUS_SKIPPED = "SKIPPED"
STATUS_WAITING_FOR_OPERATOR = "WAITING_FOR_OPERATOR"

OVERALL_COMPLETE = "COMPLETE"
OVERALL_WAITING = "WAITING_FOR_OPERATOR"
OVERALL_BLOCKED = "BLOCKED"
OVERALL_DEGRADED = "DEGRADED-WITH-WARNINGS"
OVERALL_FAILED = "FAILED"


# ---------------------------------------------------------------------------
# Slug helpers
# ---------------------------------------------------------------------------


def slugify(name: str) -> str:
    """Lowercase, hyphen-separated, alnum-only cluster slug. No em-dashes.

    Used for the orchestrator's own out-dir naming only.
    """
    s = name.lower().strip()
    s = re.sub(r"[^a-z0-9]+", "-", s)
    s = s.strip("-")
    return s or "cluster"


def sibling_brief_slug(name: str) -> str:
    """Reproduce `safe_slug` from wave3-cluster-to-hacker-brief.py exactly.

    The brief sibling writes `hacker-brief-<safe_slug>.md`, where safe_slug
    is case-preserving and keeps `.`, `_`, `-`. The orchestrator must compute
    the brief filename with the SAME rule, otherwise step 4's draft-path
    fallback (and step 2's brief input) point at a file that does not exist
    whenever the cluster name has uppercase letters or dots/underscores.
    """
    s = re.sub(r"[^a-zA-Z0-9._-]+", "-", name).strip("-")
    return s or "cluster"


# ---------------------------------------------------------------------------
# State persistence
# ---------------------------------------------------------------------------


@dataclass
class StepResult:
    step: int
    name: str
    status: str = STATUS_PENDING
    exit_code: Optional[int] = None
    output_path: Optional[str] = None
    duration_seconds: Optional[float] = None
    diagnostic: Optional[str] = None
    stdout_tail: Optional[str] = None
    stderr_tail: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step": self.step,
            "name": self.name,
            "status": self.status,
            "exit_code": self.exit_code,
            "output_path": self.output_path,
            "duration_seconds": self.duration_seconds,
            "diagnostic": self.diagnostic,
            "stdout_tail": self.stdout_tail,
            "stderr_tail": self.stderr_tail,
        }


@dataclass
class PipelineState:
    workspace: str
    cluster: str
    target_platform: str
    target_protocol: str
    out_dir: str
    steps_requested: List[int]
    step_results: Dict[int, StepResult] = field(default_factory=dict)
    overall_status: str = STATUS_PENDING
    recommended_next_action: str = ""
    schema: str = SCHEMA_ID
    synthetic_fixture: bool = False

    def to_dict(self) -> Dict[str, Any]:
        executed = [
            s for s, r in self.step_results.items()
            if r.status in (STATUS_OK, STATUS_WARNING)
        ]
        pending = [
            s for s, r in self.step_results.items()
            if r.status in (STATUS_PENDING, STATUS_WAITING_FOR_OPERATOR)
        ]
        blocked = [
            s for s, r in self.step_results.items()
            if r.status in (STATUS_BLOCKED, STATUS_FAILED)
        ]
        return {
            "schema": self.schema,
            "workspace": self.workspace,
            "cluster": self.cluster,
            "target_platform": self.target_platform,
            "target_protocol": self.target_protocol,
            "out_dir": self.out_dir,
            "steps_requested": self.steps_requested,
            "steps_executed": executed,
            "steps_pending": pending,
            "steps_blocked": blocked,
            "step_results": {
                str(k): v.to_dict() for k, v in sorted(self.step_results.items())
            },
            "overall_status": self.overall_status,
            "recommended_next_action": self.recommended_next_action,
            "synthetic_fixture": self.synthetic_fixture,
        }


def state_path(out_dir: Path) -> Path:
    return out_dir / "pipeline_state.json"


def write_state(state: PipelineState) -> None:
    out_dir = Path(state.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = state_path(out_dir)
    payload = json.dumps(state.to_dict(), indent=2, sort_keys=False)
    path.write_text(payload + "\n", encoding="utf-8")


def load_state(out_dir: Path) -> Optional[PipelineState]:
    path = state_path(out_dir)
    if not path.exists():
        return None
    raw = json.loads(path.read_text(encoding="utf-8"))
    st = PipelineState(
        workspace=raw["workspace"],
        cluster=raw["cluster"],
        target_platform=raw["target_platform"],
        target_protocol=raw["target_protocol"],
        out_dir=raw["out_dir"],
        steps_requested=list(raw.get("steps_requested", [1, 2, 3, 4, 5])),
        synthetic_fixture=bool(raw.get("synthetic_fixture", False)),
    )
    for k, v in raw.get("step_results", {}).items():
        st.step_results[int(k)] = StepResult(
            step=int(k),
            name=v["name"],
            status=v.get("status", STATUS_PENDING),
            exit_code=v.get("exit_code"),
            output_path=v.get("output_path"),
            duration_seconds=v.get("duration_seconds"),
            diagnostic=v.get("diagnostic"),
            stdout_tail=v.get("stdout_tail"),
            stderr_tail=v.get("stderr_tail"),
        )
    st.overall_status = raw.get("overall_status", STATUS_PENDING)
    st.recommended_next_action = raw.get("recommended_next_action", "")
    return st


# ---------------------------------------------------------------------------
# Sibling tool resolution + execution
# ---------------------------------------------------------------------------


def resolve_tools_dir() -> Path:
    """Return the tools/ directory this script lives in.

    Tests override via AUDITOOOR_WAVE3_TOOLS_DIR env var (used to point the
    pipeline at a fixture directory of mock sibling tools).
    """
    override = os.environ.get("AUDITOOOR_WAVE3_TOOLS_DIR")
    if override:
        return Path(override)
    return Path(__file__).resolve().parent


def sibling_exists(step: int) -> Tuple[bool, Optional[Path]]:
    meta = SIBLING_TOOLS[step]
    tool_name = meta.get("tool")
    if not tool_name:
        return False, None
    tools_dir = resolve_tools_dir()
    path = tools_dir / tool_name
    return path.exists(), path


def _tail(stream: str, n: int = 40) -> str:
    if not stream:
        return ""
    lines = stream.splitlines()
    if len(lines) <= n:
        return stream
    return "\n".join(lines[-n:])


def run_sibling(
    step: int,
    cli_args: List[str],
    timeout: int = 300,
    expected_output: Optional[Path] = None,
) -> StepResult:
    """Run the sibling tool for `step`.

    `expected_output`, when supplied, is the artifact path the orchestrator
    expects the sibling to have produced (step 1 brief) or consumed (step 4
    scanned draft). On an OK / WARNING outcome the path is recorded onto
    `result.output_path` so downstream steps and the operator have a concrete
    pointer. Without this the W5.1 acceptance gate (both steps reach a
    non-null output_path) cannot be satisfied.
    """
    meta = SIBLING_TOOLS[step]
    name = meta["name"]
    result = StepResult(step=step, name=name)

    exists, path = sibling_exists(step)
    if not exists:
        result.status = STATUS_SKIPPED
        result.diagnostic = (
            "await sibling tool landing: "
            f"{meta['tool']} not yet present in tools/"
        )
        return result

    cmd = [sys.executable, str(path)] + cli_args
    started = time.monotonic()
    result.status = STATUS_RUNNING
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        result.status = STATUS_FAILED
        result.duration_seconds = time.monotonic() - started
        result.diagnostic = f"timeout after {timeout}s"
        result.stderr_tail = str(exc)[:2000]
        return result
    except (OSError, ValueError) as exc:
        result.status = STATUS_FAILED
        result.duration_seconds = time.monotonic() - started
        result.diagnostic = f"subprocess error: {exc}"
        return result

    result.duration_seconds = round(time.monotonic() - started, 3)
    result.exit_code = proc.returncode
    result.stdout_tail = _tail(proc.stdout)
    result.stderr_tail = _tail(proc.stderr)

    # Map sibling exit codes onto pipeline statuses.
    # Convention (negotiated with the parallel item #1-#4 builders):
    #   0  OK
    #   2  WARNING (non-blocking; pipeline degrades)
    #   3  BLOCK (originality dupe found, etc; pipeline halts unless override)
    #   other  FAILED
    if proc.returncode == 0:
        result.status = STATUS_OK
    elif proc.returncode == 2:
        result.status = STATUS_WARNING
        result.diagnostic = "sibling tool emitted WARNING (non-blocking)"
    elif proc.returncode == 3:
        result.status = STATUS_BLOCKED
        result.diagnostic = "sibling tool emitted BLOCK (originality dupe or hard refusal)"
    else:
        result.status = STATUS_FAILED
        result.diagnostic = f"sibling tool failed with exit_code={proc.returncode}"

    # Record the artifact path on any non-failing outcome so downstream
    # steps and the operator have a concrete pointer.
    if (
        expected_output is not None
        and result.status in (STATUS_OK, STATUS_WARNING)
    ):
        result.output_path = str(expected_output)
        if not expected_output.exists():
            note = (
                f"expected artifact not found at {expected_output} "
                "despite non-failing sibling exit"
            )
            result.diagnostic = (
                f"{result.diagnostic}; {note}" if result.diagnostic else note
            )
    return result


# ---------------------------------------------------------------------------
# Step argument builders. Kept separate so tests can introspect what we
# would pass to each sibling.
# ---------------------------------------------------------------------------


def step1_brief_path(state: PipelineState) -> Path:
    """Path the sibling writes the hacker brief to.

    The sibling tool (wave3-cluster-to-hacker-brief.py) writes
    `hacker-brief-<slug>.md` inside the supplied --out-dir; the orchestrator
    must follow that convention rather than re-using its own filename.
    """
    out_dir = Path(state.out_dir) / "hacker_briefs"
    return out_dir / f"hacker-brief-{sibling_brief_slug(state.cluster)}.md"


def step1_args(state: PipelineState) -> List[str]:
    # The sibling does NOT accept --target-protocol (verified against
    # tools/wave3-cluster-to-hacker-brief.py --help at commit 83d5c5ac4c).
    # Cluster + workspace fully specify the input. The sibling owns the
    # filename inside --out-dir; we resolve it via step1_brief_path().
    out_dir = step1_brief_path(state).parent
    return [
        "--workspace", state.workspace,
        "--cluster", state.cluster,
        "--out-dir", str(out_dir),
        "--format", "markdown",
    ]


def step2_args(state: PipelineState) -> List[str]:
    # The brief consumed by step 2 is the file step 1's sibling actually
    # wrote (step1_brief_path), NOT a fixed `01_hacker_brief.md` slot the
    # orchestrator never produces. Re-using the wrong filename here was a
    # silent inter-step path-contract break.
    in_brief = step1_brief_path(state)
    out_scaffold = Path(state.out_dir) / "poc"
    return [
        "--brief", str(in_brief),
        "--out-dir", str(out_scaffold),
        "--target-protocol", state.target_protocol,
    ]


def step4_draft_path(state: PipelineState) -> Path:
    """Resolve the draft to scan for originality.

    Preference order:
      1. <out>/04_finding_draft.md (operator-built finding draft; the standard
         shape after step 3 completes)
      2. The hacker brief produced by step 1 (acceptable fallback when only
         steps 1 + 4 are run, e.g. capability smoke-test)
    """
    explicit = Path(state.out_dir) / "04_finding_draft.md"
    if explicit.exists():
        return explicit
    brief = step1_brief_path(state)
    if brief.exists():
        return brief
    return explicit


def step4_args(state: PipelineState) -> List[str]:
    # The sibling (wave3-published-source-originality-scanner.py) takes
    # --finding-draft, --target-protocol, --workspace (verified --help at
    # commit 7d131254ac). It does NOT take --target-platform; the cross-
    # platform aspect is internal (it scans all 4 platforms unconditionally).
    draft = step4_draft_path(state)
    return [
        "--finding-draft", str(draft),
        "--target-protocol", state.target_protocol,
        "--workspace", state.workspace,
    ]


def step5_args(state: PipelineState) -> List[str]:
    draft = Path(state.out_dir) / "04_finding_draft.md"
    out_paste = Path(state.out_dir) / "05_paste_ready.md"
    return [
        "--input", str(draft),
        "--platform", state.target_platform,
        "--output", str(out_paste),
    ]


# ---------------------------------------------------------------------------
# Step 3: operator-pause gate.
# ---------------------------------------------------------------------------


def step3_check_for_poc(state: PipelineState) -> StepResult:
    """Step 3 is the operator-build step. We never run it; we only check
    whether the operator has produced PoC artifacts at <out>/poc/."""
    result = StepResult(step=3, name=SIBLING_TOOLS[3]["name"])
    poc_dir = Path(state.out_dir) / "poc"

    # If step 2 was SKIPPED (sibling not landed) AND no scaffold dir exists,
    # we cascade the skip rather than parking on an operator that has nothing
    # to build against.
    prev_step2 = state.step_results.get(2)
    if (
        prev_step2 is not None
        and prev_step2.status == STATUS_SKIPPED
        and not poc_dir.exists()
    ):
        result.status = STATUS_SKIPPED
        result.diagnostic = (
            "step 2 sibling skipped and no scaffold dir present; "
            "operator-build gate cannot evaluate"
        )
        return result

    if not poc_dir.exists():
        result.status = STATUS_WAITING_FOR_OPERATOR
        result.diagnostic = (
            "scaffold not present; waiting on step 2 sibling tool"
        )
        return result

    # Look for at least one PoC test artifact in the standard shapes.
    patterns = ["*.t.sol", "*_test.go", "*_test.rs", "*.test.ts", "*.test.js"]
    found: List[Path] = []
    for pat in patterns:
        found.extend(poc_dir.rglob(pat))

    instructions = poc_dir / "RUN_INSTRUCTIONS.md"
    if found and instructions.exists():
        result.status = STATUS_OK
        result.output_path = str(poc_dir)
        result.diagnostic = (
            f"found {len(found)} PoC test file(s) + RUN_INSTRUCTIONS.md"
        )
    else:
        result.status = STATUS_WAITING_FOR_OPERATOR
        if not found:
            result.diagnostic = (
                "scaffold present but no PoC test artifact found; "
                "operator must build PoC against the scaffold"
            )
        else:
            result.diagnostic = (
                f"found {len(found)} PoC file(s) but RUN_INSTRUCTIONS.md is missing"
            )
    return result


# ---------------------------------------------------------------------------
# Overall-status reducer + next-action recommender.
# ---------------------------------------------------------------------------


def compute_overall(state: PipelineState) -> Tuple[str, str]:
    """Return (overall_status, recommended_next_action)."""
    results = state.step_results

    # Any blocked or failed step short-circuits.
    blocked = [r for r in results.values() if r.status in (STATUS_BLOCKED, STATUS_FAILED)]
    if blocked:
        first = blocked[0]
        if first.status == STATUS_BLOCKED:
            return (
                OVERALL_BLOCKED,
                f"Address BLOCK from step {first.step} ({first.name}): "
                f"{first.diagnostic or 'see stderr_tail'}",
            )
        return (
            OVERALL_FAILED,
            f"Investigate step {first.step} failure ({first.name}); "
            f"see stderr_tail. exit_code={first.exit_code}",
        )

    # Any step still waiting for operator PoC.
    waiting = [r for r in results.values() if r.status == STATUS_WAITING_FOR_OPERATOR]
    if waiting:
        first = waiting[0]
        poc_dir = Path(state.out_dir) / "poc"
        return (
            OVERALL_WAITING,
            f"Build PoC at {poc_dir} (then add RUN_INSTRUCTIONS.md and re-run pipeline)",
        )

    # Warnings degrade. SKIPPED counts as a warning for overall-status purposes
    # (sibling tool not yet landed = degraded coverage).
    warnings = [r for r in results.values() if r.status in (STATUS_WARNING, STATUS_SKIPPED)]
    if warnings:
        # Recommended action depends on the last step that ran cleanly.
        last_ok = None
        for s in sorted(results.keys()):
            r = results[s]
            if r.status in (STATUS_OK, STATUS_WARNING):
                last_ok = r
        if any(r.step == 5 and r.status == STATUS_OK for r in results.values()):
            paste = Path(state.out_dir) / "05_paste_ready.md"
            return (
                OVERALL_DEGRADED,
                f"Review warnings, then paste from {paste}",
            )
        return (
            OVERALL_DEGRADED,
            "Review warnings / skipped steps; pipeline ran but with degraded coverage",
        )

    # All steps OK.
    if results and all(r.status == STATUS_OK for r in results.values()):
        paste = Path(state.out_dir) / "05_paste_ready.md"
        if any(r.step == 5 for r in results.values()):
            return (OVERALL_COMPLETE, f"Paste from {paste}")
        return (OVERALL_COMPLETE, "Subset complete; re-run without --steps to finish")

    return (STATUS_PENDING, "Pipeline not yet started")


# ---------------------------------------------------------------------------
# Pipeline runner.
# ---------------------------------------------------------------------------


def parse_steps(raw: str) -> List[int]:
    if not raw:
        return [1, 2, 3, 4, 5]
    out: List[int] = []
    for tok in raw.split(","):
        tok = tok.strip()
        if not tok:
            continue
        try:
            n = int(tok)
        except ValueError as exc:
            raise SystemExit(f"invalid step token: {tok!r}") from exc
        if n not in SIBLING_TOOLS:
            raise SystemExit(f"unknown step number: {n}")
        if n not in out:
            out.append(n)
    return sorted(out)


def run_pipeline(state: PipelineState, strict: bool = False) -> int:
    """Execute the requested steps in order. Returns exit code."""
    halt = False

    for step in state.steps_requested:
        # Initialize result row if not already present from a resume.
        if step not in state.step_results:
            state.step_results[step] = StepResult(
                step=step, name=SIBLING_TOOLS[step]["name"]
            )
        row = state.step_results[step]

        # Skip already-completed rows on resume.
        if row.status in (STATUS_OK, STATUS_BLOCKED, STATUS_FAILED):
            continue

        if step == 1:
            result = run_sibling(
                1, step1_args(state), expected_output=step1_brief_path(state)
            )
        elif step == 2:
            # Step 2 needs the brief from step 1; if step 1 was skipped/failed
            # we mark step 2 skipped too. The brief lives at the sibling-owned
            # path (step1_brief_path), not a fixed `01_hacker_brief.md` slot.
            prev = state.step_results.get(1)
            brief_path = step1_brief_path(state)
            if prev and prev.status == STATUS_SKIPPED and not brief_path.exists():
                result = StepResult(
                    step=2,
                    name=SIBLING_TOOLS[2]["name"],
                    status=STATUS_SKIPPED,
                    diagnostic="step 1 sibling skipped and no hacker brief present",
                )
            else:
                result = run_sibling(2, step2_args(state))
        elif step == 3:
            result = step3_check_for_poc(state)
        elif step == 4:
            result = run_sibling(
                4, step4_args(state), expected_output=step4_draft_path(state)
            )
        elif step == 5:
            result = run_sibling(5, step5_args(state))
        else:
            result = StepResult(
                step=step,
                name=f"unknown-step-{step}",
                status=STATUS_FAILED,
                diagnostic=f"step {step} is not implemented",
            )

        state.step_results[step] = result
        write_state(state)

        # Halt conditions. Under --strict, WARNING / SKIPPED / FAILED all
        # short-circuit the pipeline so the operator sees the first
        # degradation immediately rather than cascading downstream skips.
        if result.status == STATUS_BLOCKED:
            halt = True
            break
        if result.status == STATUS_FAILED and strict:
            halt = True
            break
        if result.status == STATUS_WAITING_FOR_OPERATOR:
            halt = True
            break
        if result.status == STATUS_SKIPPED and strict:
            halt = True
            break
        if result.status == STATUS_WARNING and strict:
            halt = True
            break

    overall, action = compute_overall(state)
    state.overall_status = overall
    state.recommended_next_action = action
    write_state(state)

    if overall in (OVERALL_BLOCKED, OVERALL_FAILED):
        return 1
    if strict and overall == OVERALL_DEGRADED:
        return 1
    # WAITING_FOR_OPERATOR is a clean pause: exit 0.
    return 0


# ---------------------------------------------------------------------------
# Argparse + main.
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="wave3-e2e-pipeline",
        description="Wave-3 end-to-end finding-lifecycle orchestrator (PR #729).",
    )
    p.add_argument("--workspace", required=True, help="audit workspace path")
    p.add_argument("--cluster", required=True, help="engage cluster name")
    p.add_argument(
        "--target-platform",
        required=True,
        choices=["cantina", "immunefi", "sherlock", "code4rena"],
        help="bounty platform shape for the paste-ready",
    )
    p.add_argument("--target-protocol", required=True, help="target protocol name")
    p.add_argument("--out-dir", default=None, help="pipeline output directory")
    p.add_argument(
        "--strict",
        action="store_true",
        help="exit 1 on any non-OK step (warnings, skipped, failures all hard)",
    )
    p.add_argument(
        "--steps",
        default="1,2,3,4,5",
        help="comma-separated subset of step numbers to execute",
    )
    p.add_argument(
        "--resume",
        action="store_true",
        help="resume from existing pipeline_state.json at out-dir",
    )
    p.add_argument(
        "--print-state",
        action="store_true",
        help="print final pipeline_state.json to stdout on exit",
    )
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    out_dir = (
        Path(args.out_dir)
        if args.out_dir
        else Path(args.workspace) / "paste_ready_pipeline" / slugify(args.cluster)
    )
    out_dir.mkdir(parents=True, exist_ok=True)

    steps = parse_steps(args.steps)

    state: Optional[PipelineState] = None
    if args.resume:
        state = load_state(out_dir)
        if state is None:
            print(
                f"[wave3-e2e] --resume requested but no state file at "
                f"{state_path(out_dir)}; starting fresh",
                file=sys.stderr,
            )

    if state is None:
        state = PipelineState(
            workspace=str(Path(args.workspace).resolve()),
            cluster=args.cluster,
            target_platform=args.target_platform,
            target_protocol=args.target_protocol,
            out_dir=str(out_dir.resolve()),
            steps_requested=steps,
        )
        write_state(state)
    else:
        # If we are resuming, override requested-steps with the new request.
        state.steps_requested = steps

    rc = run_pipeline(state, strict=args.strict)

    if args.print_state:
        print(json.dumps(state.to_dict(), indent=2))
    else:
        print(
            f"[wave3-e2e] overall_status={state.overall_status} "
            f"next_action={state.recommended_next_action!r} "
            f"state_file={state_path(out_dir)}"
        )
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
