#!/usr/bin/env python3
"""Wave-1 hackerman MCP callable smoke-test runner.

Invokes every Wave-1 hackerman MCP callable exposed by
``tools/vault-mcp-server.py`` against the live corpus and validates that the
JSON envelope returned by each callable contains the canonical
``schema`` / ``context_pack_id`` / ``context_pack_hash`` triple plus a
``source_refs`` list.

The runner is intentionally side-effect-free (read-only invocations) and
aggregates a per-callable PASS / FAIL verdict suitable for CI gating.

Usage
-----

.. code:: bash

    # default: run all Wave-1 callables, print a summary table, exit 0 on
    # all-pass and 1 on any failure
    python3 tools/hackerman-mcp-smoke-test.py

    # restrict to a comma-separated subset (useful for debugging)
    python3 tools/hackerman-mcp-smoke-test.py --only vault_corpus_search,vault_dupe_advisory_check

    # emit JSON instead of the human-readable table
    python3 tools/hackerman-mcp-smoke-test.py --json

    # use a custom Wave-1 callable registry (advanced; default is the
    # registry baked into this file)
    python3 tools/hackerman-mcp-smoke-test.py --registry path/to/registry.json

The script exits with status 0 only when every invoked callable returned a
JSON envelope with all four required keys. Any decode error / missing key /
non-zero subprocess exit code is recorded as a FAIL with diagnostic detail.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.hackerman_mcp_smoke_test.v1"
REPO_ROOT = Path(__file__).resolve().parents[1]
VAULT_MCP_SERVER = REPO_ROOT / "tools" / "vault-mcp-server.py"
DEFAULT_TIMEOUT_SECONDS = 120
REQUIRED_KEYS: tuple[str, ...] = (
    "schema",
    "context_pack_id",
    "context_pack_hash",
    "source_refs",
)

# Wave-1 hackerman MCP callable registry. Each entry is (callable_name,
# representative_args_dict). The args are deliberately minimal to keep
# smoke-test wall-time low; deeper integration coverage lives in
# tools/tests/test_vault_hackerman_integration.py.
WAVE1_REGISTRY: list[tuple[str, dict[str, Any]]] = [
    ("vault_attack_class_taxonomy", {"limit": 3}),
    ("vault_attack_class_orphan_report", {"limit": 3}),
    ("vault_corpus_search", {"attack_class": "reentrancy", "limit": 2}),
    ("vault_corpus_subtree_summary", {"limit": 3}),
    ("vault_dupe_advisory_check", {"query": "reentrancy", "limit": 2}),
    ("vault_severity_calibration", {"attack_class": "reentrancy", "limit": 3}),
    ("vault_attack_class_evidence_v2", {"attack_class": "reentrancy", "limit": 2}),
    ("vault_attack_class_evidence_v3", {"attack_class": "reentrancy", "limit": 2}),
    ("vault_hacker_brief_for_lane_v2", {"lane_id": "solidity-deep-audit", "limit": 2}),
    ("vault_hacker_brief_for_lane_v3", {"lane_id": "solidity-deep-audit", "limit": 2}),
    # 2026-05-16 hackermind-wiring audit: the four corpus-query hackerman
    # callables were absent from the smoke-test registry, so the CI gate
    # never exercised them. That blind spot let a schema_version v1->v1.1
    # regression in hackerman-exploit-predicates / -detector-relationships
    # ship undetected (6/36475 records emitted). Registered here so the
    # envelope contract is enforced for the whole hackerman-mindset surface.
    ("vault_hackerman_chain_candidates", {"limit": 2}),
    ("vault_hackerman_detector_relationships", {"limit": 2}),
    ("vault_hackerman_exploit_predicates", {"limit": 2}),
    ("vault_hackerman_go_cosmos_inventory", {"limit": 2}),
    # 2026-05-16 Wave-5 W5-M3 callable coverage expansion batch 2. Six
    # Wave-4/5 knowledge surfaces that had no MCP recall path. Registered so
    # the CI envelope contract is enforced for the whole batch. Each callable
    # returns a schema-valid envelope (degraded when its artifact is absent),
    # so the smoke test exercises the envelope shape, not artifact presence.
    ("vault_fanout_pattern_library", {"limit": 2}),
    ("vault_detector_backtest", {"limit": 2}),
    ("vault_rollup_digest", {"cadence": "daily", "limit": 2}),
    ("vault_anti_pattern_corpus", {"limit": 2}),
    ("vault_bug_class_priority", {"limit": 2}),
    ("vault_exploit_chain_unifier", {"limit": 2}),
]


@dataclass
class CallableResult:
    """Outcome of invoking a single MCP callable."""

    name: str
    args: dict[str, Any]
    passed: bool
    elapsed_seconds: float
    missing_keys: list[str] = field(default_factory=list)
    error: str = ""
    schema_value: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _decode_envelope(stdout: str) -> tuple[dict[str, Any] | None, str]:
    """Decode the JSON stdout of a callable.

    Returns ``(envelope, "")`` on success or ``(None, reason)`` on decode
    failure. The error string is suitable for inclusion in a CallableResult.
    """
    stripped = stdout.strip()
    if not stripped:
        return None, "empty stdout"
    try:
        envelope = json.loads(stripped)
    except json.JSONDecodeError as exc:
        return None, f"json_decode_error: {exc}"
    if not isinstance(envelope, dict):
        return None, f"envelope_not_object: type={type(envelope).__name__}"
    return envelope, ""


def _missing_required_keys(envelope: dict[str, Any]) -> list[str]:
    """Return the subset of REQUIRED_KEYS missing from the envelope."""
    return [k for k in REQUIRED_KEYS if k not in envelope]


def run_callable(
    name: str,
    args: dict[str, Any],
    *,
    server_path: Path = VAULT_MCP_SERVER,
    repo_root: Path = REPO_ROOT,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    python_executable: str | None = None,
) -> CallableResult:
    """Invoke one Wave-1 MCP callable and validate its envelope."""
    started = time.monotonic()
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
    except FileNotFoundError as exc:
        return CallableResult(
            name=name,
            args=args,
            passed=False,
            elapsed_seconds=round(time.monotonic() - started, 3),
            error=f"command_not_found: {exc}",
        )
    except subprocess.TimeoutExpired:
        return CallableResult(
            name=name,
            args=args,
            passed=False,
            elapsed_seconds=round(time.monotonic() - started, 3),
            error=f"timeout_after_{timeout}s",
        )
    elapsed = round(time.monotonic() - started, 3)

    if proc.returncode == 2:
        # vault-mcp-server.py returns 2 when --call references an unknown
        # callable name. Surface that gracefully so the runner can keep
        # going (matches the "callable-not-found graceful" test case).
        return CallableResult(
            name=name,
            args=args,
            passed=False,
            elapsed_seconds=elapsed,
            error=f"callable_not_found: rc=2 stderr={proc.stderr.strip()[:200]}",
        )
    if proc.returncode != 0:
        return CallableResult(
            name=name,
            args=args,
            passed=False,
            elapsed_seconds=elapsed,
            error=f"nonzero_exit: rc={proc.returncode} stderr={proc.stderr.strip()[:200]}",
        )

    envelope, decode_error = _decode_envelope(proc.stdout)
    if envelope is None:
        return CallableResult(
            name=name,
            args=args,
            passed=False,
            elapsed_seconds=elapsed,
            error=decode_error,
        )

    missing = _missing_required_keys(envelope)
    schema_value = str(envelope.get("schema", ""))
    return CallableResult(
        name=name,
        args=args,
        passed=not missing,
        elapsed_seconds=elapsed,
        missing_keys=missing,
        error="" if not missing else f"missing_required_keys: {','.join(missing)}",
        schema_value=schema_value,
    )


def load_registry(path: Path | None) -> list[tuple[str, dict[str, Any]]]:
    """Load a callable registry from a JSON file or return the baked-in default."""
    if path is None:
        return list(WAVE1_REGISTRY)
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


def aggregate(results: list[CallableResult]) -> dict[str, Any]:
    """Aggregate per-callable results into the smoke-test envelope."""
    pass_count = sum(1 for r in results if r.passed)
    fail_count = len(results) - pass_count
    return {
        "schema": SCHEMA,
        "wave": "wave-1-hackerman-capability-lift",
        "callables_total": len(results),
        "callables_passed": pass_count,
        "callables_failed": fail_count,
        "all_passed": fail_count == 0 and len(results) > 0,
        "results": [r.to_dict() for r in results],
    }


def format_table(envelope: dict[str, Any]) -> str:
    """Render the aggregated envelope as a human-readable table."""
    lines: list[str] = []
    lines.append("=" * 78)
    lines.append("Wave-1 Hackerman MCP callable smoke test")
    lines.append("=" * 78)
    width = max((len(r["name"]) for r in envelope["results"]), default=20) + 2
    header = f"{'callable':<{width}} {'verdict':<8} {'secs':>7}  detail"
    lines.append(header)
    lines.append("-" * len(header))
    for row in envelope["results"]:
        verdict = "PASS" if row["passed"] else "FAIL"
        detail = row["error"] or row.get("schema_value", "")
        lines.append(
            f"{row['name']:<{width}} {verdict:<8} {row['elapsed_seconds']:>7.2f}  {detail}"
        )
    lines.append("-" * len(header))
    lines.append(
        f"total={envelope['callables_total']} "
        f"passed={envelope['callables_passed']} "
        f"failed={envelope['callables_failed']} "
        f"all_passed={envelope['all_passed']}"
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--only",
        default="",
        help="Comma-separated subset of callable names to invoke (default: all).",
    )
    parser.add_argument(
        "--registry",
        default="",
        help="Optional path to a JSON file with a custom callable registry.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT_SECONDS,
        help=f"Per-callable timeout in seconds (default: {DEFAULT_TIMEOUT_SECONDS}).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON instead of the human-readable table.",
    )
    args = parser.parse_args(argv)

    registry_path = Path(args.registry).expanduser() if args.registry else None
    registry = load_registry(registry_path)
    if args.only:
        wanted = {name.strip() for name in args.only.split(",") if name.strip()}
        registry = [(n, a) for (n, a) in registry if n in wanted]
        if not registry:
            print(
                f"[hackerman-mcp-smoke-test] no callable matched --only={args.only!r}",
                file=sys.stderr,
            )
            return 2

    results: list[CallableResult] = []
    for name, call_args in registry:
        results.append(
            run_callable(name, call_args, timeout=args.timeout)
        )

    envelope = aggregate(results)
    if args.json:
        print(json.dumps(envelope, indent=2, sort_keys=True))
    else:
        print(format_table(envelope))
    return 0 if envelope["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
