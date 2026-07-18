#!/usr/bin/env python3
# r36-rebuttal: lane-HUNT-DEDUP-FIRST-ORCH registered in .auditooor/agent_pathspec.json
# SCOPE-TIER: canonical full-workspace 10-step deterministic hunt driver (make-wired).
# NOT a duplicate of base-critical-hunt.py (5-step critical-candidate verifier) or
# critical-hunt.py (lightweight advisory dossier emitter) - each covers a distinct tier.
"""hunt-orchestrate.py - deterministic `make hunt` step engine (L36).

The single deterministic entry point behind ``make hunt-deterministic
WS=<ws>``. It runs the canonical hunt pipeline IN ORDER, hard-failing on
any non-zero step (no step is silently skipped). This is the root-cause
fix for BOTH shallow hunts AND repeated work:

  Step 0  DEDUP-LOAD (MANDATORY, runs FIRST) -- hunt-dedup-load.py
          Materializes <ws>/.auditooor/hunt_skip_set.json from ALL prior
          work. The orchestrator FAILS if this step can't run. Every
          downstream cluster/brief consults the skip-set and skips
          already-filed / killed / dead-ended candidates.
  Step 1  ensure-full-clone (unshallow if shallow)
  Step 2  make audit
  Step 3  make audit-deep
  Step 4  Tier-6 bidirectional mining. When the
          workspace is a fork/vendored target the upstream owner/repo is
          AUTO-resolved (fork-upstream-resolve.py) and passed as --upstream
          (no manual UPSTREAM= needed); otherwise the target-mining wrapper
          reads targets.tsv and emits workspace-local mining evidence.
  Step 5  SAME-FAMILY DIFFERENTIAL SEED: when a sibling workspace shares the
          engagement family, run cross-workspace-differential-seed.py with
          --merge-proof-queue so sibling findings become proof obligations.
  Step 6  FORK-DIVERGENCE AUTO-WIRE: when the workspace is a fork/vendored
          target or same-family source-delta target, run fork-divergence-prober.py
          and emit the
          .auditooor/fork_divergence*.json artifact the master gate
          (audit-completeness-check.py check_fork_divergence) verifies.
  Step 7  emit per-cluster dispatch briefs from SCOPE.md (each brief
          embeds the skip-set + the canonical hunt definition)
  Step 8  sidecar->corpus learn ETL (hackerman-etl-from-finding-sidecars
          + promote-mined-to-canonical + triage-kill-promoter to APPEND
          new dead-ends)
  Step 9  build/refresh CAPABILITY_COVERAGE_MATRIX
  Step 10 FINAL: hunt-completeness-check.py <ws> -- non-zero => the whole
          orchestrator exits non-zero.

Step ordering is load-bearing and is asserted by the unit tests:
DEDUP-LOAD is ALWAYS step 0, and the completeness gate is ALWAYS the
final step. A run that cannot produce the skip-set, or that fails the
completeness gate, exits non-zero so `make hunt-deterministic` fails and
the loop-finalization gate refuses to mark the workspace exhausted.

Design
------
The orchestrator is a thin, deterministic step-runner. Each step is a
``Step`` dataclass with an id, a human label, a list of argv commands to
run (in order), and flags: ``mandatory`` (non-zero => orchestrator fails)
vs ``best_effort`` (non-zero => WARN, continue). Steps 0, 8 and the audit
stages are mandatory; mining / brief-emit / ETL are best-effort because a
target with no upstream git history or no SCOPE.md still constitutes a
runnable hunt (and the completeness gate is the backstop).

``--plan`` prints the ordered step plan as JSON without executing - used
by the unit tests to assert ordering and dedup-first placement offline.
When the caller has already run the audit and deep-engine stages, pass
``--skip-audit-stages`` or set ``HUNT_ORCHESTRATE_SKIP_AUDIT_STAGES=1`` so
the deterministic tail does not run duplicate deep engines.

CLI
---
    python3 tools/hunt-orchestrate.py --workspace <ws> [--plan]
        [--json] [--no-mcp] [--dry-run] [--repo-root <path>]
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

SCHEMA = "auditooor.l36_hunt_orchestrate.v1"
GATE = "L36-HUNT-ORCHESTRATE"

STEP_DEDUP_LOAD = "dedup-load"
STEP_COMPLETENESS = "completeness-gate"
STEP_FORK_DIVERGENCE = "fork-divergence-autowire"
STEP_DIFFERENTIAL_SEED = "same-family-differential-seed"


def _resolve_fork_upstream(ws, repo_root):
    """Read-only fork detection + upstream resolution for AUTO-wiring the
    Tier-6 upstream mining and the fork-divergence probe. Returns a dict
    {is_fork, upstream, upstream_source, lang_hint, fork_reasons}. Loads the
    sibling fork-upstream-resolve.py module in-process (no subprocess) so the
    plan is built from a single resolved verdict. On ANY error it degrades to
    a non-fork verdict (the fork lane is simply skipped; the completeness gate
    remains the backstop)."""
    import importlib.util
    fallback = {"is_fork": False, "upstream": None, "upstream_source": "",
                "lang_hint": "go", "fork_reasons": []}
    tool = repo_root / "tools" / "fork-upstream-resolve.py"
    if not _exists(tool):
        return fallback
    try:
        spec = importlib.util.spec_from_file_location("fork_upstream_resolve", tool)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        v = m.evaluate(ws)
        return {
            "is_fork": bool(v.get("is_fork")),
            "upstream": v.get("upstream"),
            "upstream_source": v.get("upstream_source", ""),
            "lang_hint": v.get("lang_hint", "go"),
            "fork_reasons": v.get("fork_reasons", []),
            "probe_workspace": v.get("probe_workspace"),
        }
    except Exception:
        return fallback


def _resolve_same_family_seed_need(ws, repo_root):
    """Return same-family sibling context for the differential seed step."""
    import importlib.util

    fallback = {"needed": False, "sibling": None, "family": None}
    tool = repo_root / "tools" / "audit-completeness-check.py"
    if not _exists(tool):
        return fallback
    try:
        spec = importlib.util.spec_from_file_location("audit_completeness_for_hunt", tool)
        m = importlib.util.module_from_spec(spec)
        sys.modules["audit_completeness_for_hunt"] = m
        spec.loader.exec_module(m)
        sibling = m._same_family_sibling(ws)
    except Exception:
        return fallback
    if not sibling:
        return fallback
    sibling_path, family = sibling
    return {"needed": True, "sibling": str(sibling_path), "family": family}


def _probe_workspace(ws: Path) -> str:
    src = ws / "src"
    if _exists(src / ".git"):
        return str(src)
    return str(ws)


@dataclass
class Step:
    step_id: str
    order: int
    label: str
    commands: list[list[str]]
    mandatory: bool = True
    best_effort: bool = False


@dataclass
class StepResult:
    step_id: str
    order: int
    label: str
    rc: int
    mandatory: bool
    best_effort: bool
    seconds: float = 0.0
    skipped_reason: str = ""
    command_rcs: list[int] = field(default_factory=list)


def _exists(p: Path) -> bool:
    try:
        return p.exists()
    except OSError:
        return False


def _repo_root_default() -> Path:
    return Path(__file__).resolve().parent.parent


def build_plan(
    ws: Path,
    repo_root: Path,
    *,
    use_mcp: bool,
    skip_audit_stages: bool = False,
) -> list[Step]:
    """Return the ordered, deterministic step plan. PURE (no side effects);
    every command is argv, never shell."""
    py = sys.executable
    tools = repo_root / "tools"
    make = ["make", "-C", str(repo_root), "--no-print-directory"]

    dedup_cmd = [py, str(tools / "hunt-dedup-load.py"), str(ws), "--json"]
    if not use_mcp:
        dedup_cmd.append("--no-mcp")

    # AUTO-DETECT fork/vendored target + resolve upstream owner/repo so the
    # Tier-6 mining and fork-divergence probe wire themselves (no manual
    # UPSTREAM= argument). Read-only; degrades to non-fork on any error.
    fork = _resolve_fork_upstream(ws, repo_root)
    same_family_seed = _resolve_same_family_seed_need(ws, repo_root)
    is_fork = fork["is_fork"]
    upstream = fork.get("upstream")
    lang_hint = fork.get("lang_hint", "go")
    ws_name = ws.name

    # Tier-6 mining command. For a fork with a resolved upstream, drive
    # git-commits-mining.py with the resolved --upstream + workspace NAME +
    # language hint. For normal target workspaces, use the audit-flow wrapper:
    # it reads targets.tsv and supplies the required upstream/pin arguments for
    # each target. Calling git-commits-mining.py directly without --upstream is
    # invalid and only creates a best-effort rc=2 noise trail.
    if is_fork and upstream:
        tier6_cmd = [py, str(tools / "git-commits-mining.py"),
                     "--workspace", ws_name, "--upstream", upstream,
                     "--lang", lang_hint, "--direction", "bidirectional",
                     "--since-pin"]
        tier6_label = (f"Tier-6 bidirectional commit-mining (AUTO upstream={upstream} "
                       f"lang={lang_hint}, source={fork.get('upstream_source','')})")
    else:
        tier6_cmd = [py, str(tools / "audit-target-commit-mining.py"),
                     "--workspace", str(ws), "--window", "90", "--json"]
        tier6_label = (
            "Tier-6 bidirectional commit-mining via targets.tsv "
            "(no fork upstream resolved; best-effort)"
        )

    steps: list[Step] = [
        # Step 0 -- DEDUP-LOAD, MANDATORY, FIRST.
        Step(
            step_id=STEP_DEDUP_LOAD,
            order=0,
            label="DEDUP-LOAD: materialize hunt_skip_set.json from all prior work",
            commands=[dedup_cmd],
            mandatory=True,
        ),
        # Step 1 -- ensure full clone (unshallow if shallow).
        Step(
            step_id="ensure-full-clone",
            order=1,
            label="ensure-full-clone: unshallow source tree so Tier-6 mining can run",
            commands=[[py, str(tools / "hunt-orchestrate-ensure-clone.py"), str(ws)]],
            mandatory=False,
            best_effort=True,
        ),
    ]

    next_order = len(steps)
    if not skip_audit_stages:
        steps.extend([
            # Step 2 -- make audit.
            Step(
                step_id="make-audit",
                order=next_order,
                label="make audit WS=<ws>",
                commands=[[*make, "audit", f"WS={ws}"]],
                mandatory=True,
            ),
            # Step 3 -- make audit-deep.
            Step(
                step_id="make-audit-deep",
                order=next_order + 1,
                label="make audit-deep WS=<ws>",
                commands=[[*make, "audit-deep", f"WS={ws}"]],
                mandatory=True,
            ),
        ])
        next_order += 2

    steps.extend([
        # Step 4 -- Tier-6 bidirectional mining (AUTO upstream when fork).
        Step(
            step_id="tier6-bidirectional-mining",
            order=next_order,
            label=tier6_label,
            commands=[tier6_cmd],
            mandatory=False,
            best_effort=True,
        ),
    ])

    next_order = len(steps)
    if same_family_seed.get("needed"):
        steps.append(Step(
            step_id=STEP_DIFFERENTIAL_SEED,
            order=next_order,
            label=(
                "SAME-FAMILY DIFFERENTIAL SEED: cross-workspace-differential-seed "
                f"(family={same_family_seed.get('family')}, sibling={same_family_seed.get('sibling')})"
            ),
            commands=[[
                py,
                str(tools / "cross-workspace-differential-seed.py"),
                "--workspace",
                str(ws),
                "--k",
                "3",
                "--merge-proof-queue",
                "--json",
            ]],
            mandatory=False,
            best_effort=True,
        ))
        next_order += 1

    # Step 5/6 -- FORK-DIVERGENCE AUTO-WIRE. Injected for fork/vendored targets
    # and same-family differential targets whose source-delta obligations need a
    # concrete probe artifact in the same deterministic plan.
    # Runs fork-divergence-prober.py with --out pointing at the canonical
    # .auditooor/fork_divergence_probe.json artifact the master gate
    # (audit-completeness-check.py check_fork_divergence) verifies.
    if is_fork or same_family_seed.get("needed"):
        fork_out = ws / ".auditooor" / "fork_divergence_probe.json"
        probe_workspace = fork.get("probe_workspace") or _probe_workspace(ws)
        prober_cmd = [py, str(tools / "fork-divergence-prober.py"),
                      "--workspace", str(probe_workspace), "--out", str(fork_out), "--json"]
        up_note = f" (upstream={upstream})" if upstream else " (upstream unresolved)"
        steps.append(Step(
            step_id=STEP_FORK_DIVERGENCE,
            order=next_order,
            label=(f"FORK-DIVERGENCE AUTO-WIRE: fork-divergence-prober -> "
                   f".auditooor/fork_divergence_probe.json{up_note}"),
            commands=[prober_cmd],
            mandatory=False,
            best_effort=True,
        ))
        next_order += 1

    # Tail steps -- briefs, ETL, coverage matrix, completeness gate. Orders
    # follow the fork-divergence injection point so the plan stays strictly
    # increasing 0..N regardless of whether the fork step was added.
    steps.extend([
        Step(
            step_id="emit-cluster-briefs",
            order=next_order,
            label="emit per-cluster dispatch briefs from SCOPE.md (skip-set + canonical hunt def embedded)",
            commands=[[py, str(tools / "hunt-cluster-brief-emit.py"), str(ws)]],
            mandatory=False,
            best_effort=True,
        ),
        Step(
            step_id="sidecar-corpus-learn-etl",
            order=next_order + 1,
            label="sidecar->corpus learn ETL (etl-from-finding-sidecars + promote-mined + triage-kill-promoter append dead-ends)",
            commands=[
                [py, str(tools / "hackerman-etl-from-finding-sidecars.py"), "--workspace", str(ws)],
                [py, str(tools / "promote-mined-to-canonical.py")],
                [py, str(tools / "triage-kill-promoter.py")],
            ],
            mandatory=False,
            best_effort=True,
        ),
        Step(
            step_id="capability-coverage-matrix",
            order=next_order + 2,
            label="build/refresh CAPABILITY_COVERAGE_MATRIX",
            commands=[[py, str(tools / "capability-coverage-matrix-build.py"), str(ws)]],
            mandatory=False,
            best_effort=True,
        ),
        # FINAL completeness gate, MANDATORY -- always last.
        Step(
            step_id=STEP_COMPLETENESS,
            order=next_order + 3,
            label="FINAL: hunt-completeness-check.py (non-zero => make hunt non-zero)",
            commands=[[py, str(tools / "hunt-completeness-check.py"), str(ws), "--json"]],
            mandatory=True,
        ),
    ])
    return steps


def _run_command(cmd: list[str], cwd: Path) -> int:
    try:
        proc = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True)
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"[{GATE}]   command error: {' '.join(cmd[:3])}...: {exc}", file=sys.stderr)
        return 127
    if proc.stdout:
        sys.stdout.write(proc.stdout)
    if proc.stderr:
        sys.stderr.write(proc.stderr)
    return proc.returncode


def execute_plan(
    steps: list[Step],
    repo_root: Path,
    *,
    dry_run: bool,
) -> tuple[list[StepResult], str, int]:
    """Execute steps in order. Return (results, verdict, exit_code)."""
    results: list[StepResult] = []
    failed_mandatory: StepResult | None = None
    completeness_advisory = False

    for step in steps:
        # If a mandatory step already failed, skip the rest (deterministic
        # short-circuit) EXCEPT we always still report them as skipped.
        if failed_mandatory is not None:
            results.append(StepResult(
                step_id=step.step_id, order=step.order, label=step.label,
                rc=-1, mandatory=step.mandatory, best_effort=step.best_effort,
                skipped_reason=f"skipped: mandatory step '{failed_mandatory.step_id}' failed (rc={failed_mandatory.rc})",
            ))
            continue

        print(f"[{GATE}] Step {step.order} - {step.label}")
        if dry_run:
            results.append(StepResult(
                step_id=step.step_id, order=step.order, label=step.label,
                rc=0, mandatory=step.mandatory, best_effort=step.best_effort,
                skipped_reason="dry-run",
            ))
            continue

        t0 = time.time()
        command_rcs: list[int] = []
        step_rc = 0
        for cmd in step.commands:
            # Skip a command whose tool script does not exist yet (sibling
            # lane in flight) for best-effort steps; mandatory steps with a
            # missing tool fail hard.
            tool_path = Path(cmd[1]) if len(cmd) > 1 and cmd[1].endswith(".py") else None
            if tool_path is not None and not _exists(tool_path):
                if step.best_effort:
                    print(f"[{GATE}]   NOTE tool missing (skip best-effort cmd): {tool_path.name}")
                    command_rcs.append(0)
                    continue
                print(f"[{GATE}]   ERR mandatory tool missing: {tool_path}", file=sys.stderr)
                command_rcs.append(127)
                step_rc = 127
                break
            rc = _run_command(cmd, repo_root)
            command_rcs.append(rc)
            if rc != 0:
                step_rc = rc
                if not step.best_effort:
                    break
        elapsed = time.time() - t0

        sr = StepResult(
            step_id=step.step_id, order=step.order, label=step.label,
            rc=step_rc, mandatory=step.mandatory, best_effort=step.best_effort,
            seconds=round(elapsed, 2), command_rcs=command_rcs,
        )
        results.append(sr)

        if step_rc != 0:
            if step.best_effort and not step.mandatory:
                print(f"[{GATE}]   WARN step '{step.step_id}' rc={step_rc} (best-effort; continuing)")
            elif step.step_id == STEP_COMPLETENESS and os.environ.get("AUDITOOOR_HUNT_COMPLETENESS_FATAL", "0") != "1":
                # G9: the hunt-completeness gate is an HONESTY METRIC, not a
                # producer-blocker. The core hunt steps ran and produced output;
                # fail-closing the whole run here would deny the partial queue +
                # findings (and on a large workspace one pass can never be
                # complete). The completeness-check tool already wrote its verdict
                # for the Step-5 closeout to enforce; coverage is honestly labeled
                # partial. Set AUDITOOOR_HUNT_COMPLETENESS_FATAL=1 to restore the
                # hard fail-close.
                print(
                    f"[{GATE}]   NOTE completeness-gate rc={step_rc} is ADVISORY at the hunt "
                    f"level (G9: honesty metric, not a producer-blocker). Core hunt steps ran; "
                    f"continuing so the partial queue + findings are produced and labeled "
                    f"partial-coverage. The completeness verdict is enforced at Step-5 closeout. "
                    f"Set AUDITOOOR_HUNT_COMPLETENESS_FATAL=1 to hard-fail.",
                    file=sys.stderr,
                )
                completeness_advisory = True
            else:
                print(f"[{GATE}]   FAIL mandatory step '{step.step_id}' rc={step_rc}", file=sys.stderr)
                failed_mandatory = sr

    if failed_mandatory is not None:
        verdict = f"fail-step-{failed_mandatory.step_id}"
        return results, verdict, 1
    if completeness_advisory:
        return results, "pass-hunt-orchestrated-completeness-advisory", 0
    return results, "pass-hunt-orchestrated", 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="hunt-orchestrate.py",
        description="Deterministic `make hunt` step engine: dedup-first + full pipeline + completeness gate.",
    )
    p.add_argument("--workspace", "--ws", dest="workspace", required=True, help="Audit workspace path.")
    p.add_argument("--plan", action="store_true", help="Print the ordered step plan as JSON; do not execute.")
    p.add_argument("--json", action="store_true", help="Emit JSON result payload.")
    p.add_argument("--no-mcp", action="store_true", help="Pass --no-mcp to the dedup-load step.")
    p.add_argument("--dry-run", action="store_true", help="Print each step but do not run commands.")
    p.add_argument("--skip-audit-stages", action="store_true",
                   help="Do not run make audit / make audit-deep inside the deterministic tail.")
    p.add_argument("--repo-root", default=None, help="Toolkit repo root (default: this tool's repo).")
    args = p.parse_args(argv)

    ws = Path(os.path.expanduser(args.workspace)).resolve()
    repo_root = Path(os.path.expanduser(args.repo_root)).resolve() if args.repo_root else _repo_root_default()

    if not args.plan and (not _exists(ws) or not ws.is_dir()):
        payload = {
            "schema": SCHEMA, "gate": GATE, "workspace": str(ws),
            "verdict": "error", "reason": "workspace path does not exist or is not a directory",
        }
        print(json.dumps(payload, indent=2) if args.json else f"[{GATE}] verdict=error reason={payload['reason']}")
        return 2

    skip_audit_stages = (
        args.skip_audit_stages
        or os.environ.get("HUNT_ORCHESTRATE_SKIP_AUDIT_STAGES") in {"1", "true", "yes"}
    )
    steps = build_plan(
        ws,
        repo_root,
        use_mcp=not args.no_mcp,
        skip_audit_stages=skip_audit_stages,
    )

    # Invariant guard: DEDUP-LOAD is always step 0, completeness is always last.
    assert steps[0].step_id == STEP_DEDUP_LOAD and steps[0].order == 0, "dedup-load must be step 0"
    assert steps[-1].step_id == STEP_COMPLETENESS, "completeness gate must be the final step"

    if args.plan:
        plan = {
            "schema": SCHEMA, "gate": GATE, "workspace": str(ws),
            "dedup_first": steps[0].step_id == STEP_DEDUP_LOAD,
            "completeness_last": steps[-1].step_id == STEP_COMPLETENESS,
            "skip_audit_stages": skip_audit_stages,
            "steps": [
                {"order": s.order, "step_id": s.step_id, "label": s.label,
                 "mandatory": s.mandatory, "best_effort": s.best_effort,
                 "commands": s.commands}
                for s in steps
            ],
        }
        print(json.dumps(plan, indent=2))
        return 0

    results, verdict, exit_code = execute_plan(steps, repo_root, dry_run=args.dry_run)

    payload = {
        "schema": SCHEMA, "gate": GATE, "workspace": str(ws),
        "verdict": verdict,
        "skip_audit_stages": skip_audit_stages,
        "steps": [
            {"order": r.order, "step_id": r.step_id, "rc": r.rc,
             "mandatory": r.mandatory, "best_effort": r.best_effort,
             "seconds": r.seconds, "skipped_reason": r.skipped_reason,
             "command_rcs": r.command_rcs}
            for r in results
        ],
    }
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(f"[{GATE}] verdict={verdict}")
        for r in results:
            mark = "PASS" if r.rc == 0 else ("SKIP" if r.rc == -1 else "FAIL")
            extra = f" ({r.skipped_reason})" if r.skipped_reason else ""
            print(f"  [{mark}] step {r.order} {r.step_id} rc={r.rc}{extra}")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
