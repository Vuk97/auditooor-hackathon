#!/usr/bin/env python3
"""Execute generated per-function Halmos harness invocations.

RELATED TOOLS:
- tools/per-function-invariant-gen.py writes the invocation manifest consumed here.
- tools/halmos-runner.sh writes per-invocation deep-engine artifacts.
- tools/solidity-deep-all-harnesses-manifest.py folds this result into the full
  invariant denominator.

The generated per-function harnesses are advisory scaffolds, not submission
proof. This runner only proves that every generated harness invocation was
actually attempted and either produced a successful Halmos artifact or left a
typed failure row.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.solidity_per_function_halmos.v1"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def load_json(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def safe_slug(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())
    return cleaned.strip("._-") or "per-function-harness"


def invocation_rows(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    functions = manifest.get("functions")
    if not isinstance(functions, list):
        return []
    rows: list[dict[str, Any]] = []
    for idx, row in enumerate(functions):
        if not isinstance(row, dict):
            continue
        invocation = row.get("halmos_invocation")
        args = None
        if isinstance(invocation, dict) and isinstance(invocation.get("args"), list):
            args = [str(arg) for arg in invocation["args"]]
        elif isinstance(row.get("halmos_args"), list):
            args = [str(arg) for arg in row["halmos_args"]]
        if args is None:
            args = []
        harness_contract = str(row.get("harness_contract") or "").strip()
        selector = str(row.get("selector") or f"row-{idx}").strip()
        # Per-contract scaffold root for block-explorer-fetched verified source.
        # When present, halmos runs with --root = this dir (its foundry.toml +
        # populated lib/ resolves the imports). Read from the row directly, or
        # fall back to the embedded halmos_invocation.workspace_arg.
        halmos_root = row.get("halmos_root")
        if not halmos_root and isinstance(invocation, dict):
            wa = invocation.get("workspace_arg")
            # Only treat workspace_arg as a scaffold root if it differs from the
            # manifest workspace (a per-contract root, not the workspace root).
            if isinstance(wa, str) and wa.strip():
                halmos_root = wa.strip()
        rows.append(
            {
                "index": idx,
                "selector": selector,
                "harness_contract": harness_contract,
                "harness_path": row.get("harness_path"),
                "halmos_root": halmos_root or None,
                "args": args,
            }
        )
    return rows


def run_invocation(
    *,
    repo_root: Path,
    workspace: Path,
    out_root: Path,
    row: dict[str, Any],
    timeout_seconds: int | None,
) -> dict[str, Any]:
    selector = str(row.get("selector") or f"row-{row.get('index')}").strip()
    harness_contract = str(row.get("harness_contract") or "").strip()
    slug = safe_slug(harness_contract or selector)
    artifact_root = out_root / slug
    artifact_root.mkdir(parents=True, exist_ok=True)
    args = [str(arg) for arg in (row.get("args") or [])]
    # Build root: a per-contract scaffold root (block-explorer verified source)
    # when present, else the workspace. halmos-runner.sh keys off $PWD/foundry.toml
    # and auto-adds --root $PWD, so cwd must be the build root.
    halmos_root_raw = row.get("halmos_root")
    build_root = workspace
    if isinstance(halmos_root_raw, str) and halmos_root_raw.strip():
        candidate = Path(halmos_root_raw).expanduser()
        if not candidate.is_absolute():
            candidate = workspace / candidate
        if (candidate / "foundry.toml").is_file():
            build_root = candidate
    command = ["bash", str(repo_root / "tools" / "halmos-runner.sh"), str(build_root), *args]
    env = os.environ.copy()
    env["AUDITOOOR_DEEP_ARTIFACT_ROOT"] = str(artifact_root)
    foundry_test = foundry_test_dir(build_root, row.get("harness_path"))
    if foundry_test:
        env["FOUNDRY_TEST"] = foundry_test
    status = "blocked"
    reason = "artifact_missing"
    rc: int | None = None
    timed_out = False
    try:
        proc = subprocess.Popen(
            command,
            cwd=build_root,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        try:
            proc.communicate(timeout=timeout_seconds)
            rc = proc.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(proc.pid, signal.SIGTERM)
                proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.communicate()
            rc = 124
    except subprocess.TimeoutExpired:
        timed_out = True
        rc = 124

    artifact_path = artifact_root / "halmos" / "artifact.json"
    artifact = load_json(artifact_path)
    if timed_out:
        status = "timeout"
        reason = "halmos invocation timed out"
    elif artifact is not None:
        status = str(artifact.get("status") or "unknown")
        reason = str(artifact.get("reason") or "")
    elif rc not in (None, 0):
        status = "blocked"
        reason = f"halmos-runner exited {rc}"

    return {
        "index": row.get("index"),
        "selector": selector,
        "harness_contract": harness_contract or None,
        "harness_path": row.get("harness_path"),
        "build_root": str(build_root),
        "foundry_test": foundry_test,
        "args": args,
        "command": command,
        "artifact_root": str(artifact_root),
        "artifact": str(artifact_path),
        "returncode": rc,
        "status": status,
        "reason": reason,
    }


def foundry_test_dir(workspace: Path, harness_path: Any) -> str | None:
    if not isinstance(harness_path, str) or not harness_path.strip():
        return None
    path = Path(harness_path).expanduser()
    if not path.is_absolute():
        path = workspace / path
    try:
        parent = path.resolve().parent
    except OSError:
        parent = path.parent
    try:
        return parent.relative_to(workspace).as_posix()
    except ValueError:
        return str(parent)


def build_manifest(
    *,
    repo_root: Path,
    workspace: Path,
    generated_manifest_path: Path,
    out_path: Path,
    run_id: str | None,
    timeout_seconds: int | None,
    total_budget_seconds: float | None = None,
) -> dict[str, Any]:
    generated_manifest = load_json(generated_manifest_path)
    if generated_manifest is None:
        return {
            "schema": SCHEMA,
            "workspace": str(workspace),
            "run_id": run_id,
            "generated_at_utc": utc_now(),
            "generated_manifest": str(generated_manifest_path),
            "status": "blocked",
            "reason": "generated per-function manifest missing or invalid",
            "expected_invocation_count": None,
            "executed_invocation_count": 0,
            "ok_invocation_count": 0,
            "invocations": [],
        }

    rows = invocation_rows(generated_manifest)
    expected = len(rows)
    out_root = workspace / ".auditooor" / "deep-engine-runs" / "per-function-halmos"
    # Total wall-clock budget for the whole sweep. Each invocation already has a
    # per-invocation timeout; without a TOTAL budget a workspace with a huge
    # generated-harness denominator (e.g. 1187 functions x ~1-2 min compile each)
    # runs for many hours. The deep-engine completion cert tolerates partial
    # coverage (build-class), so a budget-truncated partial sweep still lets the
    # pipeline complete. budget None/<=0 = no budget (unchanged behavior).
    results: list[dict[str, Any]] = []
    truncated_by_budget = False
    start = time.monotonic()
    for row in rows:
        if (
            total_budget_seconds is not None
            and total_budget_seconds > 0
            and (time.monotonic() - start) >= total_budget_seconds
        ):
            truncated_by_budget = True
            break
        results.append(
            run_invocation(
                repo_root=repo_root,
                workspace=workspace,
                out_root=out_root,
                row=row,
                timeout_seconds=timeout_seconds,
            )
        )
    skipped_count = expected - len(results)
    ok_count = sum(1 for row in results if row.get("status") == "ok")
    status = "ok" if ok_count == expected else "blocked"
    if expected == 0:
        status = "ok"
    return {
        "schema": SCHEMA,
        "workspace": str(workspace),
        "run_id": run_id,
        "generated_at_utc": utc_now(),
        "generated_manifest": str(generated_manifest_path),
        "artifact_root": str(out_root),
        "status": status,
        "expected_invocation_count": expected,
        "executed_invocation_count": len(results),
        "ok_invocation_count": ok_count,
        "skipped_invocation_count": skipped_count,
        "truncated_by_total_budget": truncated_by_budget,
        "total_budget_seconds": total_budget_seconds,
        "invocations": results,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True)
    parser.add_argument(
        "--manifest",
        help="Default: <workspace>/poc-tests/per_function_invariants/manifest.json",
    )
    parser.add_argument(
        "--out",
        help="Default: <workspace>/.audit_logs/solidity_per_function_halmos_manifest.json",
    )
    parser.add_argument("--run-id", default=os.environ.get("AUDITOOOR_AUDIT_RUN_FULL_ID"))
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=int(os.environ.get("HALMOS_TIMEOUT", "0") or "0"),
    )
    parser.add_argument(
        "--total-budget-seconds",
        type=float,
        default=float(
            os.environ.get("AUDITOOOR_PER_FUNCTION_HALMOS_TOTAL_BUDGET", "1800") or "1800"
        ),
        help=(
            "Total wall-clock budget (s) for the whole per-function sweep; once "
            "exceeded, remaining invocations are skipped and the manifest is marked "
            "truncated_by_total_budget (the deep-engine cert tolerates the partial). "
            "0 = no budget. Default 1800 (30 min)."
        ),
    )
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--json", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = Path(__file__).resolve().parents[1]
    workspace = Path(args.workspace).expanduser().resolve()
    generated_manifest_path = (
        Path(args.manifest).expanduser().resolve()
        if args.manifest
        else next((_p for _p in (workspace / ".auditooor" / "per_function_invariants" / "manifest.json", workspace / "poc-tests" / "per_function_invariants" / "manifest.json") if _p.is_file()), workspace / ".auditooor" / "per_function_invariants" / "manifest.json")
    )
    out_path = (
        Path(args.out).expanduser().resolve()
        if args.out
        else workspace / ".audit_logs" / "solidity_per_function_halmos_manifest.json"
    )
    timeout = args.timeout_seconds if args.timeout_seconds and args.timeout_seconds > 0 else None
    total_budget = (
        args.total_budget_seconds
        if args.total_budget_seconds and args.total_budget_seconds > 0
        else None
    )
    payload = build_manifest(
        repo_root=repo_root,
        workspace=workspace,
        generated_manifest_path=generated_manifest_path,
        out_path=out_path,
        run_id=args.run_id,
        timeout_seconds=timeout,
        total_budget_seconds=total_budget,
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    if args.strict and payload.get("status") != "ok":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
