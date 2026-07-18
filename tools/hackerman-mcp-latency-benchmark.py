#!/usr/bin/env python3
"""Wave-1 hackerman MCP callable wall-clock latency benchmark.

Invokes every ``vault_*`` callable exposed by ``tools/vault-mcp-server.py``
against the live corpus, three times per callable, and aggregates a
per-callable latency table (mean / median / p99 wall-clock seconds, plus
min / max / sample-count and an outcome flag).

The output is operator-facing input for the Wave-2 performance roadmap:
callables that dominate the tail get prioritised for caching / index work.

Usage
-----

.. code:: bash

    # default: benchmark every callable in the baked-in registry, print a
    # human-readable table, exit 0 on success
    python3 tools/hackerman-mcp-latency-benchmark.py

    # JSON envelope (operator-friendly machine output)
    python3 tools/hackerman-mcp-latency-benchmark.py --json

    # restrict to a subset of callables
    python3 tools/hackerman-mcp-latency-benchmark.py \
        --only vault_corpus_search,vault_dupe_advisory_check

    # override the per-callable invocation count (default 3)
    python3 tools/hackerman-mcp-latency-benchmark.py --runs 5

    # custom registry, same JSON shape as the smoke-test runner
    python3 tools/hackerman-mcp-latency-benchmark.py --registry path.json

Design notes
------------

The benchmark intentionally re-uses the smoke-test registry of representative
arguments (``tools/hackerman-mcp-smoke-test.py:WAVE1_REGISTRY``) and extends
it to cover every ``vault_*`` callable enumerated by ``vault-mcp-server.py``
so we have one wall-clock data-point per callable end-to-end. Each callable
is invoked ``--runs`` times back-to-back; ``time.perf_counter()`` brackets
the ``subprocess.run`` call so the measurement includes Python startup,
argument parsing, vault load, and the callable body itself (i.e. what a
real operator session sees).

The tool is read-only: callables that mutate the vault (none currently) would
need an opt-in flag. ``--runs 3`` is the minimum that produces a meaningful
median; higher values reduce variance at the cost of wall-clock time.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import statistics
import subprocess
import sys
import time
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.hackerman_mcp_latency_benchmark.v1"
REPO_ROOT = Path(__file__).resolve().parents[1]
VAULT_MCP_SERVER = REPO_ROOT / "tools" / "vault-mcp-server.py"
DEFAULT_TIMEOUT_SECONDS = 180
DEFAULT_RUNS = 3
# Minimum runs we can report a median + p99 for. p99 of <3 samples is just
# the max, but we still emit a row so the operator sees coverage; we flag
# low-sample rows in the verdict.
MIN_RUNS = 1

# Representative argument fixtures per callable. The Wave-1 smoke-test
# registry (tools/hackerman-mcp-smoke-test.py) is the canonical source for
# the deeper Wave-1 surface; this dict extends coverage to every callable
# enumerated by tools/vault-mcp-server.py --help.
#
# Conventions:
#   - empty dict {} = invoke with no arguments (callable should accept defaults)
#   - limit=2..3 keeps wall-time bounded for live runs
#   - workspace_path uses the repo root so workspace-scoped lookups succeed
#
# When a new vault_* callable is added to vault-mcp-server.py, add a row
# here. If a callable name is missing from this map at benchmark time, the
# tool falls back to {} (no args) and records a verdict of
# "no_registered_args" so the operator notices.
DEFAULT_ARGS: dict[str, dict[str, Any]] = {
    # Wave-1 smoke-test parity
    "vault_attack_class_taxonomy": {"limit": 3},
    "vault_attack_class_orphan_report": {"limit": 3},
    "vault_corpus_search": {"attack_class": "reentrancy", "limit": 2},
    "vault_corpus_subtree_summary": {"limit": 3},
    "vault_dupe_advisory_check": {"query": "reentrancy", "limit": 2},
    "vault_severity_calibration": {"attack_class": "reentrancy", "limit": 3},
    "vault_attack_class_evidence_v2": {"attack_class": "reentrancy", "limit": 2},
    "vault_attack_class_evidence_v3": {"attack_class": "reentrancy", "limit": 2},
    "vault_hacker_brief_for_lane_v2": {"lane_id": "solidity-deep-audit", "limit": 2},
    "vault_hacker_brief_for_lane_v3": {"lane_id": "solidity-deep-audit", "limit": 2},
    # Core context callables
    "vault_search": {"query": "reentrancy", "limit": 2},
    "vault_get": {"path": "README.md"},
    "vault_next_loop": {"limit": 3},
    "vault_goal_state": {},
    "vault_outcome_context": {"limit": 3},
    "vault_dispatch_context": {"limit": 3},
    "vault_resume_context": {"limit": 3},
    "vault_finalization_context": {"limit": 3},
    "vault_exploit_context": {"limit": 3},
    "vault_harness_context": {"limit": 3},
    "vault_knowledge_gap_context": {"limit": 3},
    "vault_engagement_status": {},
    "vault_route": {"query": "reentrancy"},
    "vault_spark_engagement_context": {"limit": 3},
    "vault_engage_report_context": {"limit": 3},
    "vault_corpus_mining_state": {"limit": 3},
    "vault_hacker_brief_for_lane": {"lane_id": "solidity-deep-audit", "limit": 2},
    "vault_lane_cooldown_check": {"lane_id": "solidity-deep-audit"},
    "vault_kill_rubric_context": {"limit": 3},
    "vault_bug_family_heatmap": {"limit": 3},
    "vault_language_patterns": {"limit": 3},
    "vault_dupe_rejection_context": {"limit": 3},
    "vault_intent_resolve": {"query": "reentrancy"},
    "vault_remember": {},
    "vault_originality_context": {"limit": 3},
    "vault_function_mindset": {"limit": 3},
    "vault_function_signature_shape": {"limit": 3},
    "vault_attack_class_evidence": {"attack_class": "reentrancy", "limit": 2},
    # Detector / provenance
    "vault_detector_provenance": {"limit": 3},
    "vault_detector_provenance_v2": {"limit": 3},
    "vault_detector_action_graph_context": {"limit": 3},
    "vault_solidity_detector_proof_context": {"limit": 3},
    "vault_solidity_changelog_drift_context": {"limit": 3},
    "vault_chained_attack_plan_context": {"limit": 3},
    "vault_high_impact_execution_bridge_context": {"limit": 3},
    "vault_poc_execution_record_context": {"limit": 3},
    # Lineage / mining
    "vault_finding_lineage": {"limit": 3},
    "vault_corpus_lineage": {"limit": 3},
    "vault_commit_mining_state": {"limit": 3},
    "vault_external_corpus_search": {"query": "reentrancy", "limit": 2},
    "vault_llm_calibration": {},
    # Sessions / capacity
    "vault_issue_session_token": {},
    "vault_verify_session_token": {},
    "vault_provider_capacity": {},
    # Triage / harness
    "vault_harness_failure_context": {"limit": 3},
    "vault_triager_pattern_context": {"limit": 3},
    # Hackerman v1 surface
    "vault_hackerman_chain_candidates": {"limit": 3},
    "vault_hackerman_detector_relationships": {"limit": 3},
    "vault_hackerman_exploit_predicates": {"limit": 3},
    "vault_hackerman_go_cosmos_inventory": {"limit": 3},
    # Loop / toolsite
    "vault_loop_finalization_check": {},
    "vault_toolsite_context": {"limit": 3},
    "vault_zk_template_lookup": {"limit": 3},
    # Function shape / cross-language
    "vault_function_shape_attack_evidence": {"limit": 3},
    "vault_cross_language_pattern_lift": {"limit": 3},
}


@dataclass
class CallableLatencyRow:
    """Aggregated wall-clock latency for one callable across N runs."""

    name: str
    args: dict[str, Any]
    runs: int
    samples_seconds: list[float] = field(default_factory=list)
    mean_seconds: float = 0.0
    median_seconds: float = 0.0
    p99_seconds: float = 0.0
    min_seconds: float = 0.0
    max_seconds: float = 0.0
    error_runs: int = 0
    last_error: str = ""
    verdict: str = "ok"  # ok | partial_errors | all_errors | no_registered_args | low_sample

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _percentile(values: list[float], pct: float) -> float:
    """Linear-interpolation percentile over a 0..100 scale.

    Matches the convention used by numpy.percentile and statistics.quantiles
    with method='inclusive' so the output is reproducible without numpy. For
    n=1 returns the only value; for n=2 returns a linear interpolation.
    """
    if not values:
        return 0.0
    if len(values) == 1:
        return values[0]
    ordered = sorted(values)
    if pct <= 0:
        return ordered[0]
    if pct >= 100:
        return ordered[-1]
    rank = (pct / 100.0) * (len(ordered) - 1)
    low_idx = int(rank)
    high_idx = min(low_idx + 1, len(ordered) - 1)
    frac = rank - low_idx
    return ordered[low_idx] + frac * (ordered[high_idx] - ordered[low_idx])


def _summarise_samples(name: str, args: dict[str, Any], runs: int, samples: list[float], errors: list[str]) -> CallableLatencyRow:
    """Build the aggregate row from raw sample data."""
    error_runs = len(errors)
    last_error = errors[-1] if errors else ""
    if samples:
        mean_s = round(statistics.fmean(samples), 4)
        median_s = round(statistics.median(samples), 4)
        p99_s = round(_percentile(samples, 99.0), 4)
        min_s = round(min(samples), 4)
        max_s = round(max(samples), 4)
    else:
        mean_s = median_s = p99_s = min_s = max_s = 0.0

    if error_runs == 0 and samples:
        verdict = "ok"
    elif error_runs > 0 and samples:
        verdict = "partial_errors"
    else:
        verdict = "all_errors"

    if name not in DEFAULT_ARGS and not args:
        verdict = "no_registered_args"

    if samples and len(samples) < 2 and verdict == "ok":
        # p99 of one sample isn't meaningful; flag it.
        verdict = "low_sample"

    return CallableLatencyRow(
        name=name,
        args=args,
        runs=runs,
        samples_seconds=[round(s, 4) for s in samples],
        mean_seconds=mean_s,
        median_seconds=median_s,
        p99_seconds=p99_s,
        min_seconds=min_s,
        max_seconds=max_s,
        error_runs=error_runs,
        last_error=last_error,
        verdict=verdict,
    )


def discover_callables(server_path: Path = VAULT_MCP_SERVER) -> list[str]:
    """Parse the ``--call`` choices from ``vault-mcp-server.py --help``."""
    proc = subprocess.run(
        [sys.executable or "python3", str(server_path), "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0 and not proc.stdout:
        raise RuntimeError(
            f"vault-mcp-server.py --help failed rc={proc.returncode}: "
            f"{proc.stderr.strip()[:200]}"
        )
    match = re.search(r"--call \{([^}]+)\}", proc.stdout)
    if not match:
        raise RuntimeError(
            "could not locate --call {...} choice list in vault-mcp-server.py --help"
        )
    names = [n.strip() for n in match.group(1).split(",") if n.strip().startswith("vault_")]
    # Deterministic order: alphabetical so the benchmark output is stable.
    return sorted(dict.fromkeys(names))


def args_for_callable(name: str) -> dict[str, Any]:
    """Return the representative fixture for a callable, or {} if unregistered."""
    return dict(DEFAULT_ARGS.get(name, {}))


def _invoke_once(
    name: str,
    args: dict[str, Any],
    *,
    server_path: Path,
    repo_root: Path,
    timeout: int,
    python_executable: str | None,
) -> tuple[float, str]:
    """Single ``subprocess.run`` invocation. Returns (elapsed_seconds, error)."""
    python_bin = python_executable or sys.executable or "python3"
    cmd = [
        python_bin,
        str(server_path),
        "--call",
        name,
        "--args",
        json.dumps(args, sort_keys=True),
    ]
    env = dict(os.environ)
    env.setdefault("PYTHONUNBUFFERED", "1")
    started = time.perf_counter()
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return (float(timeout), f"timeout_after_{timeout}s")
    except FileNotFoundError as exc:
        return (round(time.perf_counter() - started, 4), f"command_not_found: {exc}")
    elapsed = round(time.perf_counter() - started, 4)
    if proc.returncode != 0:
        return (
            elapsed,
            f"nonzero_exit: rc={proc.returncode} stderr={proc.stderr.strip()[:200]}",
        )
    return (elapsed, "")


def benchmark_callable(
    name: str,
    args: dict[str, Any] | None = None,
    *,
    runs: int = DEFAULT_RUNS,
    server_path: Path = VAULT_MCP_SERVER,
    repo_root: Path = REPO_ROOT,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    python_executable: str | None = None,
) -> CallableLatencyRow:
    """Benchmark one callable across ``runs`` invocations."""
    if runs < MIN_RUNS:
        raise ValueError(f"runs must be >= {MIN_RUNS}, got {runs}")
    call_args = args if args is not None else args_for_callable(name)
    samples: list[float] = []
    errors: list[str] = []
    for _ in range(runs):
        elapsed, err = _invoke_once(
            name,
            call_args,
            server_path=server_path,
            repo_root=repo_root,
            timeout=timeout,
            python_executable=python_executable,
        )
        if err:
            errors.append(err)
        else:
            samples.append(elapsed)
    return _summarise_samples(name, call_args, runs, samples, errors)


def load_registry(path: Path | None) -> list[tuple[str, dict[str, Any]]]:
    """Load a callable registry from a JSON file (same shape as smoke test).

    If ``path`` is None, the registry is auto-discovered from
    ``vault-mcp-server.py --help`` and merged with ``DEFAULT_ARGS``.
    """
    if path is None:
        names = discover_callables()
        return [(n, args_for_callable(n)) for n in names]
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError(f"registry must be a JSON list, got {type(raw).__name__}")
    out: list[tuple[str, dict[str, Any]]] = []
    for row in raw:
        if not isinstance(row, dict):
            raise ValueError(f"registry row must be an object, got {type(row).__name__}")
        name = row.get("name")
        args = row.get("args", {})
        if not isinstance(name, str) or not name:
            raise ValueError(f"registry row missing string 'name': {row!r}")
        if not isinstance(args, dict):
            raise ValueError(f"registry row 'args' must be an object: {row!r}")
        out.append((name, args))
    return out


def aggregate(rows: list[CallableLatencyRow], runs: int) -> dict[str, Any]:
    """Build the operator-facing envelope from per-callable rows."""
    ok = sum(1 for r in rows if r.verdict in ("ok", "low_sample"))
    partial = sum(1 for r in rows if r.verdict == "partial_errors")
    fail = sum(1 for r in rows if r.verdict == "all_errors")
    no_args = sum(1 for r in rows if r.verdict == "no_registered_args")
    # Rank top-10 by p99 for operator triage.
    ranked = sorted(rows, key=lambda r: r.p99_seconds, reverse=True)
    return {
        "schema": SCHEMA,
        "wave": "wave-1-hackerman-capability-lift",
        "runs_per_callable": runs,
        "callables_total": len(rows),
        "callables_ok": ok,
        "callables_partial_errors": partial,
        "callables_all_errors": fail,
        "callables_no_registered_args": no_args,
        "top10_p99_seconds": [
            {"name": r.name, "p99_seconds": r.p99_seconds, "median_seconds": r.median_seconds}
            for r in ranked[:10]
        ],
        "results": [r.to_dict() for r in rows],
    }


def format_table(envelope: dict[str, Any]) -> str:
    """Render the envelope as a human-readable table sorted by p99 desc."""
    lines: list[str] = []
    lines.append("=" * 88)
    lines.append("Wave-1 Hackerman MCP callable wall-clock latency benchmark")
    lines.append("=" * 88)
    rows = sorted(envelope["results"], key=lambda r: r["p99_seconds"], reverse=True)
    width = max((len(r["name"]) for r in rows), default=20) + 2
    header = (
        f"{'callable':<{width}} {'mean':>8} {'med':>8} {'p99':>8} "
        f"{'min':>8} {'max':>8}  {'verdict':<18} err"
    )
    lines.append(header)
    lines.append("-" * len(header))
    for row in rows:
        lines.append(
            f"{row['name']:<{width}} "
            f"{row['mean_seconds']:>8.3f} "
            f"{row['median_seconds']:>8.3f} "
            f"{row['p99_seconds']:>8.3f} "
            f"{row['min_seconds']:>8.3f} "
            f"{row['max_seconds']:>8.3f}  "
            f"{row['verdict']:<18} "
            f"{row['error_runs']}"
        )
    lines.append("-" * len(header))
    lines.append(
        f"total={envelope['callables_total']} "
        f"ok={envelope['callables_ok']} "
        f"partial={envelope['callables_partial_errors']} "
        f"all_errors={envelope['callables_all_errors']} "
        f"no_args={envelope['callables_no_registered_args']} "
        f"runs={envelope['runs_per_callable']}"
    )
    if envelope["top10_p99_seconds"]:
        lines.append("")
        lines.append("Top-10 by p99 (operator triage list for Wave-2 perf work):")
        for i, hot in enumerate(envelope["top10_p99_seconds"], start=1):
            lines.append(
                f"  {i:>2}. {hot['name']:<{width}} p99={hot['p99_seconds']:.3f}s "
                f"median={hot['median_seconds']:.3f}s"
            )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--only",
        default="",
        help="Comma-separated subset of callable names to benchmark (default: all).",
    )
    parser.add_argument(
        "--registry",
        default="",
        help="Optional path to a JSON file with a custom callable registry.",
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=DEFAULT_RUNS,
        help=f"Invocations per callable (default: {DEFAULT_RUNS}).",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT_SECONDS,
        help=f"Per-invocation timeout seconds (default: {DEFAULT_TIMEOUT_SECONDS}).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON instead of the human-readable table.",
    )
    args = parser.parse_args(argv)

    if args.runs < MIN_RUNS:
        print(
            f"[hackerman-mcp-latency-benchmark] --runs must be >= {MIN_RUNS}",
            file=sys.stderr,
        )
        return 2

    registry_path = Path(args.registry).expanduser() if args.registry else None
    try:
        registry = load_registry(registry_path)
    except (RuntimeError, ValueError) as exc:
        print(
            f"[hackerman-mcp-latency-benchmark] registry load failed: {exc}",
            file=sys.stderr,
        )
        return 2

    if args.only:
        wanted = {name.strip() for name in args.only.split(",") if name.strip()}
        registry = [(n, a) for (n, a) in registry if n in wanted]
        if not registry:
            print(
                f"[hackerman-mcp-latency-benchmark] no callable matched --only={args.only!r}",
                file=sys.stderr,
            )
            return 2

    rows: list[CallableLatencyRow] = []
    for name, call_args in registry:
        rows.append(
            benchmark_callable(
                name,
                call_args,
                runs=args.runs,
                timeout=args.timeout,
            )
        )

    envelope = aggregate(rows, args.runs)
    if args.json:
        print(json.dumps(envelope, indent=2, sort_keys=True))
    else:
        print(format_table(envelope))
    # Exit 0 unless every callable errored: this is an operator-review tool,
    # not a CI gate. Partial errors and no-args rows are surfaced via the
    # verdict column, not via exit code.
    if rows and envelope["callables_all_errors"] == len(rows):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
