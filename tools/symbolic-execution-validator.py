#!/usr/bin/env python3
"""tools/symbolic-execution-validator.py — Kimi 20/10 Step 4 validator.

Purpose
-------
Cross-engagement validation harness for the existing symbolic-runner. It
locks the Step-4 status vocabulary
    {no-counterexample, counterexample, timeout, skipped, error}
and produces per-engagement + aggregate JSON manifests so the supervisor
can decide whether `Check #23` (a hard-fail blocking gate in
`tools/pre-submit-check.sh` for High+ A-AUTH drafts lacking symbolic
artifacts) is eligible for promotion.

Promotion gate (Kimi spec):
    fp_rate_estimate <= 0.3  AND  total_runs >= 3
            AND  >=3 distinct engagements with at least 1 run each

Gate eligibility is **advisory** — this tool never edits
`pre-submit-check.sh`. The PR body documents the gate decision.

Status vocabulary mapping (the underlying `tools/symbolic-runner.sh` emits
one extra historical token, `pass`, which we collapse to `no-counterexample`
to match the Step-4 lock).

Inputs
------
    --workspace <path>          path to engagement workspace (contains src/, etc.)
    --draft <path>              path to draft .md file under that workspace
    --angle  A-AUTH|A-ORACLE|A-REENT
    --engagement <name>         engagement label written into the JSON
    --out <path>                output manifest path
    --runner <path>             override path to symbolic-runner.sh (rare)
    --timeout <sec>             pass-through to symbolic-runner.sh (default 60)
    --dry-run                   render plan only, do not invoke runner

Output JSON shape (single-run manifest):
    {
        "schema_version": 1,
        "engagement": "polymarket",
        "draft": "<basename>",
        "angle": "A-AUTH",
        "verdict": "no-counterexample",
        "runtime_ms": 1234,
        "counterexample": null,
        "backend": "halmos",
        "backend_version": "0.3.3",
        "runner_manifest": "<path or null>",
        "skipped_reason": null
    }

Aggregate command (`--aggregate <dir>`) walks per-run manifests and emits
`aggregate.json` with `by_verdict`, `fp_rate_estimate`, and the
`blocking_eligible` boolean.

Stdlib only. Never raises on missing artifacts — the whole point of Step 4
is to surface gaps gracefully (skipped/error verdicts).
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Optional

# Locked status vocabulary (Kimi 20/10 Step 4).
STATUS_VOCAB: tuple[str, ...] = (
    "no-counterexample",
    "counterexample",
    "timeout",
    "skipped",
    "error",
)

# The existing tools/symbolic-runner.sh emits {pass, counterexample,
# no-counterexample, timeout, error, skipped}. `pass` is a legacy alias
# that this validator collapses to `no-counterexample` to enforce the
# Step-4 5-state lock.
RUNNER_STATUS_ALIASES: dict[str, str] = {
    "pass": "no-counterexample",
    "no-counterexample": "no-counterexample",
    "counterexample": "counterexample",
    "timeout": "timeout",
    "skipped": "skipped",
    "error": "error",
}

# Promotion thresholds (Kimi spec):
FP_RATE_THRESHOLD: float = 0.3
MIN_RUNS: int = 3
MIN_ENGAGEMENTS: int = 3


# ---------------------------------------------------------------------------
# Vocabulary helpers
# ---------------------------------------------------------------------------

def normalize_verdict(raw: str | None) -> str:
    """Map any runner status (or a missing one) to the Step-4 vocabulary.

    Unknown / falsy inputs collapse to ``error`` so the JSON schema stays
    closed. Never raises.
    """
    if not raw:
        return "error"
    canonical = RUNNER_STATUS_ALIASES.get(raw.strip().lower())
    if canonical is None:
        return "error"
    return canonical


def is_locked_vocab(verdict: str) -> bool:
    return verdict in STATUS_VOCAB


# ---------------------------------------------------------------------------
# Backend discovery (advisory only)
# ---------------------------------------------------------------------------

def discover_backend() -> tuple[str, str]:
    """Return (backend_name, backend_version) for the first symbolic engine
    found on PATH. Falls back to ("none", "") if nothing is installed.
    """
    for name in ("halmos", "kontrol"):
        bin_path = shutil.which(name)
        if not bin_path:
            continue
        try:
            proc = subprocess.run(
                [bin_path, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            ver = (proc.stdout.strip().splitlines()[:1] or [""])[0] or proc.stderr.strip()
            return name, ver
        except (OSError, subprocess.SubprocessError):
            return name, ""
    return ("none", "")


# ---------------------------------------------------------------------------
# Single-run validation
# ---------------------------------------------------------------------------

def run_validation(
    workspace: Path,
    draft: Path,
    angle: str,
    engagement: str,
    out_path: Path,
    runner: Path,
    timeout_sec: int,
    dry_run: bool = False,
    contract: str | None = None,
) -> dict[str, Any]:
    """Run the symbolic-runner once and emit a Step-4 manifest at ``out_path``.

    Skipped/error states are emitted as JSON; the function never raises on
    runner failures.
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)
    backend, backend_version = discover_backend()

    base: dict[str, Any] = {
        "schema_version": 1,
        "engagement": engagement,
        "draft": draft.name,
        "draft_path": str(draft),
        "workspace": str(workspace),
        "angle": angle,
        "verdict": "skipped",
        "runtime_ms": 0,
        "counterexample": None,
        "backend": backend,
        "backend_version": backend_version,
        "runner_manifest": None,
        "skipped_reason": None,
    }

    # Workspace must exist + look like an engagement workspace (has at
    # least one of: src, foundry.toml, package.json, scope*.md).
    if not workspace.is_dir():
        base["verdict"] = "skipped"
        base["skipped_reason"] = f"workspace not found: {workspace}"
        out_path.write_text(json.dumps(base, indent=2) + "\n")
        return base

    if not draft.is_file():
        base["verdict"] = "skipped"
        base["skipped_reason"] = f"draft not found: {draft}"
        out_path.write_text(json.dumps(base, indent=2) + "\n")
        return base

    if backend == "none":
        base["verdict"] = "skipped"
        base["skipped_reason"] = "no symbolic-execution backend installed (halmos/kontrol)"
        out_path.write_text(json.dumps(base, indent=2) + "\n")
        return base

    if not runner.is_file():
        base["verdict"] = "error"
        base["skipped_reason"] = f"symbolic-runner.sh not found at {runner}"
        out_path.write_text(json.dumps(base, indent=2) + "\n")
        return base

    if dry_run:
        base["verdict"] = "skipped"
        base["skipped_reason"] = "dry-run: no invocation"
        out_path.write_text(json.dumps(base, indent=2) + "\n")
        return base

    # Always run in a sandboxed --out-dir. We DO NOT pass --contract; the
    # underlying runner auto-picks from mining_priorities.json when present.
    # If auto-pick fails for A-AUTH the runner exits non-zero — we capture
    # that as `error`.
    with tempfile.TemporaryDirectory(prefix="symval-") as tmp:
        run_dir = Path(tmp) / "run"
        cmd = [
            str(runner),
            str(workspace),
            "--angle",
            angle,
            "--timeout",
            str(timeout_sec),
            "--out-dir",
            str(run_dir),
        ]
        if contract:
            cmd.extend(["--contract", contract])
        env = os.environ.copy()
        env.setdefault("SYMBOLIC_DRY_RUN", "1")
        t0 = time.monotonic()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=max(timeout_sec + 30, 60),
                env=env,
            )
        except subprocess.TimeoutExpired:
            base["verdict"] = "timeout"
            base["runtime_ms"] = int((time.monotonic() - t0) * 1000)
            base["skipped_reason"] = "validator wall-clock exceeded runner timeout"
            out_path.write_text(json.dumps(base, indent=2) + "\n")
            return base
        except OSError as exc:
            base["verdict"] = "error"
            base["runtime_ms"] = int((time.monotonic() - t0) * 1000)
            base["skipped_reason"] = f"runner invocation failed: {exc}"
            out_path.write_text(json.dumps(base, indent=2) + "\n")
            return base

        runtime_ms = int((time.monotonic() - t0) * 1000)
        manifest_path = run_dir / "manifest.json"
        if not manifest_path.is_file():
            base["verdict"] = "error"
            base["runtime_ms"] = runtime_ms
            base["skipped_reason"] = (
                f"runner exited rc={proc.returncode} but produced no manifest.json"
            )
            out_path.write_text(json.dumps(base, indent=2) + "\n")
            return base

        try:
            runner_manifest = json.loads(manifest_path.read_text())
        except (OSError, ValueError) as exc:
            base["verdict"] = "error"
            base["runtime_ms"] = runtime_ms
            base["skipped_reason"] = f"runner manifest unreadable: {exc}"
            out_path.write_text(json.dumps(base, indent=2) + "\n")
            return base

        verdict = normalize_verdict(runner_manifest.get("status"))
        ce_path_rel = runner_manifest.get("counterexample_path")
        ce_text: str | None = None
        if ce_path_rel:
            ce_full = run_dir / ce_path_rel
            try:
                ce_text = ce_full.read_text()
            except OSError:
                ce_text = None

        base.update(
            {
                "verdict": verdict,
                "runtime_ms": runtime_ms,
                "counterexample": ce_text,
                "runner_manifest": runner_manifest,  # inline the dict (tmp dir vanishes)
                "runner_status_raw": runner_manifest.get("status"),
                "runner_notes": runner_manifest.get("notes"),
                "runner_returncode": proc.returncode,
                "skipped_reason": runner_manifest.get("reason"),
            }
        )
        out_path.write_text(json.dumps(base, indent=2) + "\n")
        return base


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------

def load_manifests(directory: Path) -> list[dict[str, Any]]:
    """Load every per-run manifest in ``directory`` (excluding aggregate.json)."""
    manifests: list[dict[str, Any]] = []
    if not directory.is_dir():
        return manifests
    for path in sorted(directory.glob("*.json")):
        if path.name == "aggregate.json":
            continue
        try:
            manifests.append(json.loads(path.read_text()))
        except (OSError, ValueError):
            continue
    return manifests


def compute_fp_rate(manifests: list[dict[str, Any]]) -> float:
    """Estimate false-positive rate.

    A symbolic-execution validator's FP rate is the fraction of advisory
    `counterexample` runs that disagree with the engagement's ground-truth
    submission outcome (i.e., the draft was rejected as not-a-bug). Without
    a Step-1 outcome ledger join we conservatively use the simpler
    structural proxy:

        fp_rate ~= counterexample / max(total - skipped - error, 1)

    where the denominator is "decisive runs" (counterexample +
    no-counterexample + timeout). This is intentionally conservative:
    counterexamples on advisory runs that the supervisor has not yet
    triaged are *potential* FPs until proven otherwise.
    """
    if not manifests:
        return 1.0
    total = len(manifests)
    by_verdict: dict[str, int] = {}
    for m in manifests:
        v = normalize_verdict(m.get("verdict"))
        by_verdict[v] = by_verdict.get(v, 0) + 1
    decisive = total - by_verdict.get("skipped", 0) - by_verdict.get("error", 0)
    if decisive <= 0:
        # No decisive evidence either way. FP rate is undefined; return 1.0
        # so the gate stays closed.
        return 1.0
    ce = by_verdict.get("counterexample", 0)
    return ce / decisive


def is_blocking_eligible(
    total_runs: int,
    fp_rate: float,
    engagements: list[str],
) -> bool:
    distinct = len(set(engagements))
    return (
        total_runs >= MIN_RUNS
        and distinct >= MIN_ENGAGEMENTS
        and fp_rate <= FP_RATE_THRESHOLD
    )


def aggregate(directory: Path, out_path: Path) -> dict[str, Any]:
    manifests = load_manifests(directory)
    by_verdict: dict[str, int] = {v: 0 for v in STATUS_VOCAB}
    engagements: list[str] = []
    for m in manifests:
        v = normalize_verdict(m.get("verdict"))
        by_verdict[v] = by_verdict.get(v, 0) + 1
        eng = m.get("engagement")
        if isinstance(eng, str) and eng:
            engagements.append(eng)
    fp_rate = compute_fp_rate(manifests)
    eligible = is_blocking_eligible(len(manifests), fp_rate, engagements)
    agg = {
        "schema_version": 1,
        "total_runs": len(manifests),
        "by_verdict": by_verdict,
        "fp_rate_estimate": round(fp_rate, 4),
        "fp_rate_threshold": FP_RATE_THRESHOLD,
        "min_runs_required": MIN_RUNS,
        "min_engagements_required": MIN_ENGAGEMENTS,
        "blocking_eligible": eligible,
        "engagements": sorted(set(engagements)),
        "status_vocab_locked": list(STATUS_VOCAB),
        "notes": (
            "FP rate is a structural proxy: counterexample / decisive_runs "
            "(decisive = total - skipped - error). Promotion of Check #23 "
            "into tools/pre-submit-check.sh requires blocking_eligible=true "
            "AND supervisor sign-off."
        ),
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(agg, indent=2) + "\n")
    return agg


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="symbolic-execution-validator",
        description="Kimi 20/10 Step 4 cross-engagement symbolic-execution validator.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    rp = sub.add_parser("run", help="Run validation for a single (workspace, draft, angle).")
    rp.add_argument("--workspace", required=True, type=Path)
    rp.add_argument("--draft", required=True, type=Path)
    rp.add_argument(
        "--angle",
        required=True,
        choices=["A-AUTH", "A-ORACLE", "A-REENT"],
    )
    rp.add_argument("--engagement", required=True)
    rp.add_argument("--out", required=True, type=Path)
    rp.add_argument(
        "--runner",
        type=Path,
        default=Path(__file__).resolve().parent / "symbolic-runner.sh",
    )
    rp.add_argument("--timeout", type=int, default=60)
    rp.add_argument("--dry-run", action="store_true")
    rp.add_argument(
        "--contract",
        default=None,
        help="Explicit contract name passed to symbolic-runner.sh.",
    )
    rp.add_argument(
        "--emit-candidate",
        action="store_true",
        help=(
            "Opt-in V5 deep-lane emission. Writes a deep_candidate.v1 JSON "
            "to <workspace>/deep_candidates/ summarising the run verdict. "
            "Acceptance test 3: counterexamples without a runnable replay "
            "are emitted with confidence='low' + blocking_questions=['needs replay']."
        ),
    )

    ap = sub.add_parser("aggregate", help="Aggregate per-run manifests in a directory.")
    ap.add_argument("--dir", required=True, type=Path)
    ap.add_argument(
        "--out",
        type=Path,
        default=None,
        help="aggregate.json output path (default: <dir>/aggregate.json)",
    )

    vp = sub.add_parser("vocab", help="Print the locked status vocabulary as JSON.")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.cmd == "run":
        manifest = run_validation(
            workspace=args.workspace,
            draft=args.draft,
            angle=args.angle,
            engagement=args.engagement,
            out_path=args.out,
            runner=args.runner,
            timeout_sec=args.timeout,
            dry_run=args.dry_run,
            contract=args.contract,
        )
        if getattr(args, "emit_candidate", False):
            try:
                emit_path = _emit_symbolic_candidate(args.workspace, manifest, args.draft)
                if emit_path is not None:
                    sys.stderr.write(f"[symbolic-validator] EMIT {emit_path}\n")
            except Exception as exc:  # pragma: no cover — emission is opt-in
                sys.stderr.write(
                    f"[symbolic-validator] WARN deep-candidate emission failed: {exc}\n"
                )
        json.dump(manifest, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0
    if args.cmd == "aggregate":
        out = args.out or (args.dir / "aggregate.json")
        agg = aggregate(args.dir, out)
        json.dump(agg, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0
    if args.cmd == "vocab":
        json.dump({"status_vocab": list(STATUS_VOCAB)}, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0
    return 2


# ---------------------------------------------------------------------------
# V5 deep-candidate emission (opt-in, lane=symbolic)
# ---------------------------------------------------------------------------


def _load_deep_candidate_lib() -> Optional[Any]:
    spec_path = Path(__file__).resolve().parent / "lib" / "deep_candidate.py"
    if not spec_path.is_file():
        return None
    spec = importlib.util.spec_from_file_location("_deep_candidate_lib_sym", spec_path)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("_deep_candidate_lib_sym", module)
    spec.loader.exec_module(module)
    return module


def _emit_symbolic_candidate(
    workspace: Path, manifest: dict[str, Any], draft: Path
) -> Optional[Path]:
    """Convert a per-run symbolic manifest into a deep_candidate.v1 doc.

    Acceptance test 3: a `counterexample` verdict WITHOUT an executable
    replay is emitted at confidence='low' with `blocking_questions` containing
    the literal "needs replay" entry. The validator enforces that
    blocking_questions is non-empty when confidence='low' + active promotion.
    """
    lib = _load_deep_candidate_lib()
    if lib is None:
        return None
    verdict = manifest.get("verdict", "skipped")
    angle = manifest.get("angle", "?")
    engagement = manifest.get("engagement", "?")
    ce = manifest.get("counterexample")
    runner_manifest = manifest.get("runner_manifest")
    has_replay = bool(ce) and isinstance(ce, dict) and bool(ce.get("call_sequence"))

    # Short-circuit: skipped / error / no-counterexample => emit a `hold`
    # candidate so the operator sees the lane was exercised.
    if verdict in ("skipped", "error"):
        promotion = "hold"
    elif verdict == "no-counterexample":
        promotion = "hold"
    elif verdict == "timeout":
        promotion = "investigate"
    elif verdict == "counterexample":
        promotion = "investigate"
    else:
        promotion = "hold"

    if verdict == "counterexample" and not has_replay:
        blocking = [
            "needs replay",
            "Symbolic counterexample lacks an executable call_sequence; replay required before promotion.",
        ]
        repro = (
            "advisory: counterexample present but no replay path is wired; "
            "feed the CE into tools/symbolic-ce-to-forge.py and confirm the "
            "scaffold compiles before claiming reproducibility"
        )
    elif verdict == "counterexample" and has_replay:
        blocking = [
            "Has the counterexample been replayed under Forge as a passing test?",
            "Does the replay touch a production code path (not lib/test/mock)?",
        ]
        repro = (
            "tools/symbolic-ce-to-forge.py --input "
            f"{runner_manifest or '<runner_manifest>'} && "
            "forge test --match-contract SymbolicReplay -vv"
        )
    else:
        blocking = [
            f"Symbolic verdict was `{verdict}`; what would change the outcome?",
            "Is the harness/contract actually reachable from the symbolic engine?",
        ]
        repro = (
            "tools/symbolic-runner.sh "
            f"(workspace={workspace}, angle={angle}); "
            "rerun with extended timeout or alternative backend"
        )

    doc = lib.build_candidate(
        lane="symbolic",
        candidate_id=f"symbolic.{engagement}.{angle}.{verdict}",
        files=[str(draft)],
        claim=(
            f"Symbolic-execution lane verdict for {engagement}/{angle}: {verdict}. "
            "Tier-B advisory."
        ),
        trigger=(
            f"halmos / kontrol harness for angle {angle}; see runner manifest "
            f"{runner_manifest or '<none>'} for the exact entry function."
        ),
        impact=(
            "Counterexample without replay does NOT prove exploitability; "
            "no-counterexample does NOT prove safety beyond the harness bound."
        ),
        reproduction=repro,
        confidence="low",
        promotion_status=promotion,
        blocking_questions=blocking,
        tool="symbolic-execution-validator.py",
        workspace=workspace,
        lane_payload={
            "verdict": verdict,
            "angle": angle,
            "engagement": engagement,
            "runner_manifest": runner_manifest,
            "has_replay": has_replay,
        },
    )
    return lib.write_candidate(doc, workspace=workspace)


if __name__ == "__main__":
    raise SystemExit(main())
