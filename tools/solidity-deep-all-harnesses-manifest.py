#!/usr/bin/env python3
"""Build an aggregate manifest for Solidity engine harness deep-audit runs.

RELATED TOOLS:
- tools/deep-engine-output-parse.py parses individual engine outputs.
- tools/engine-harness-proof-check.py checks proof evidence for harnesses.
- tools/tests/test_audit_deep_solidity_makefile.py exercises Makefile routing.

This tool fills the narrow gap between those pieces: it aggregates repeated
`audit-deep-solidity PROJECT_ROOT=<harness>` runs into one per-workspace
manifest without re-running any engine.
"""

from __future__ import annotations

import argparse
import json
import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ENGINES = ("halmos", "echidna", "medusa")
HARNESS_RECORDED_STATES = frozenset({"ok", "blocked", "skipped"})


def _optional_int(payload: dict[str, Any] | None, key: str) -> int | None:
    if not isinstance(payload, dict):
        return None
    value = payload.get(key)
    if isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _load_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _read_roots(path: Path) -> list[Path]:
    if not path.is_file():
        return []
    return [Path(line.strip()) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _per_function_manifest_path(workspace: Path) -> Path:
    return next((_p for _p in (workspace / ".auditooor" / "per_function_invariants" / "manifest.json", workspace / "poc-tests" / "per_function_invariants" / "manifest.json") if _p.is_file()), workspace / ".auditooor" / "per_function_invariants" / "manifest.json")


def _per_function_execution_manifest_path(workspace: Path) -> Path:
    return workspace / ".audit_logs" / "solidity_per_function_halmos_manifest.json"


def _per_function_generated_count(workspace: Path) -> int | None:
    payload = _load_json(_per_function_manifest_path(workspace))
    if payload is None:
        return None
    count = _optional_int(payload, "function_count")
    if count is not None:
        return count
    functions = payload.get("functions")
    if isinstance(functions, list):
        return len(functions)
    invocations = payload.get("halmos_invocations")
    if isinstance(invocations, list):
        return len(invocations)
    return None


def _per_function_executed_count(workspace: Path, run_id: str | None) -> int | None:
    payload = _load_json(_per_function_execution_manifest_path(workspace))
    if payload is None:
        generated = _per_function_generated_count(workspace)
        return 0 if generated is not None else None
    if run_id and str(payload.get("run_id") or "") != str(run_id):
        return 0
    count = _optional_int(payload, "executed_invocation_count")
    if count is not None:
        return count
    count = _optional_int(payload, "ok_invocation_count")
    if count is not None:
        return count
    rows = payload.get("invocations")
    if isinstance(rows, list):
        return len([row for row in rows if isinstance(row, dict)])
    return None


def _invariant_denominator_status(
    generated_per_function_harness_count: int | None,
    executed_generated_harness_count: int | None,
    available_engine_harness_count: int,
    executed_engine_harness_count: int,
) -> str:
    if generated_per_function_harness_count is None:
        return "partial-generated-per-function-manifest-missing"
    if (
        generated_per_function_harness_count > (executed_generated_harness_count or 0)
        or available_engine_harness_count > executed_engine_harness_count
    ):
        return "partial-invariant-denominator"
    return "complete-full-invariant-denominator"


def _sync_primary_solidity_manifest(workspace: Path, aggregate: dict[str, Any]) -> None:
    primary_path = workspace / ".auditooor" / "solidity-deep-audit" / "manifest.json"
    primary = _load_json(primary_path)
    if primary is None:
        return
    fields = (
        "generated_per_function_manifest",
        "generated_per_function_harness_count",
        "per_function_halmos_manifest",
        "executed_generated_harness_count",
        "enumerated_harness_count",
        "available_engine_harness_roots",
        "available_engine_harness_count",
        "all_harnesses_manifest",
        "executed_engine_harness_count",
        "invariant_denominator_status",
        "full_in_scope_invariant_denominator",
        "ok_harness_count",
        "blocked_harness_count",
        "skipped_harness_count",
        "missing_harness_count",
        "ok_harness_slugs",
        "blocked_harness_slugs",
        "skipped_harness_slugs",
        "missing_harness_slugs",
    )
    for field in fields:
        if field in aggregate:
            primary[field] = aggregate[field]
    primary_path.write_text(json.dumps(primary, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def build_manifest(workspace: Path, roots_file: Path, out_path: Path, run_id: str | None) -> dict[str, Any]:
    roots = _read_roots(roots_file)
    rows: list[dict[str, Any]] = []
    status_counts: Counter[str] = Counter()

    for root in roots:
        slug = root.name
        manifest_path = workspace / ".auditooor" / "solidity-deep-audit" / "by-harness" / slug / "manifest.json"
        runner_root = workspace / ".auditooor" / "deep-engine-runs" / "by-harness" / slug
        manifest = _load_json(manifest_path)
        step_counts = manifest.get("status_counts", {}) if manifest else {}
        engine_rows: list[dict[str, Any]] = []

        missing_engine = False
        blocked_engine = False
        skipped_engine = False
        successful_engine = False
        current_run_mismatch = False
        for engine in ENGINES:
            artifact_path = runner_root / engine / "artifact.json"
            artifact = _load_json(artifact_path)
            status = artifact.get("status", "missing") if artifact else "missing"
            if status == "missing":
                missing_engine = True
            elif status == "ok":
                successful_engine = True
            elif status in {"skipped", "tool-unavailable"}:
                skipped_engine = True
            else:
                blocked_engine = True
            artifact_run_id = artifact.get("run_id") if artifact else None
            if run_id and artifact_run_id != run_id:
                current_run_mismatch = True
            engine_rows.append(
                {
                    "engine": engine,
                    "artifact": str(artifact_path),
                    "status": status,
                    "engine_rc": artifact.get("engine_rc") if artifact else None,
                    "run_id": artifact_run_id,
                    "command": artifact.get("command") if artifact else None,
                }
            )

        if manifest is None:
            status = "missing"
        elif missing_engine or blocked_engine or current_run_mismatch:
            status = "ok" if successful_engine and not missing_engine and not current_run_mismatch else "blocked"
        elif skipped_engine:
            status = "ok" if successful_engine else "skipped"
        else:
            status = "ok" if successful_engine else "blocked"

        status_counts[status] += 1
        rows.append(
            {
                "slug": slug,
                "root": str(root),
                "status": status,
                "manifest_path": str(manifest_path),
                "runner_artifact_root": str(runner_root),
                "status_counts": step_counts,
                "engines": engine_rows,
            }
        )

    overall = "ok"
    if not roots:
        overall = "skipped"
    elif status_counts.get("missing", 0) or status_counts.get("blocked", 0):
        overall = "blocked"
    elif status_counts.get("skipped", 0):
        overall = "skipped"

    available_engine_harness_roots = [str(root) for root in roots]
    available_engine_harness_count = len(available_engine_harness_roots)
    generated_per_function_harness_count = _per_function_generated_count(workspace)
    executed_generated_harness_count = _per_function_executed_count(workspace, run_id)
    executed_engine_harness_count = sum(
        1 for row in rows if str(row.get("status") or "") in HARNESS_RECORDED_STATES
    )
    invariant_denominator_status = _invariant_denominator_status(
        generated_per_function_harness_count,
        executed_generated_harness_count,
        available_engine_harness_count,
        executed_engine_harness_count,
    )
    ok_harness_slugs = sorted(
        str(row.get("slug") or "") for row in rows if str(row.get("status") or "") == "ok"
    )
    blocked_harness_slugs = sorted(
        str(row.get("slug") or "") for row in rows if str(row.get("status") or "") == "blocked"
    )
    skipped_harness_slugs = sorted(
        str(row.get("slug") or "") for row in rows if str(row.get("status") or "") == "skipped"
    )
    missing_harness_slugs = sorted(
        str(row.get("slug") or "") for row in rows if str(row.get("status") or "") == "missing"
    )

    return {
        "schema": "auditooor.solidity_deep_all_harnesses.v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "workspace": str(workspace),
        "run_id": run_id,
        "status": overall,
        "expected_harness_count": len(roots),
        "enumerated_harness_count": len(rows),
        "executed_harness_count": len(rows),
        "generated_per_function_manifest": str(_per_function_manifest_path(workspace)),
        "available_engine_harness_roots": available_engine_harness_roots,
        "available_engine_harness_count": available_engine_harness_count,
        "generated_per_function_harness_count": generated_per_function_harness_count,
        "per_function_halmos_manifest": str(_per_function_execution_manifest_path(workspace)),
        "executed_generated_harness_count": executed_generated_harness_count,
        "all_harnesses_manifest": str(out_path),
        "executed_engine_harness_count": executed_engine_harness_count,
        "invariant_denominator_status": invariant_denominator_status,
        "full_in_scope_invariant_denominator": (
            invariant_denominator_status == "complete-full-invariant-denominator"
        ),
        "ok_harness_count": len(ok_harness_slugs),
        "blocked_harness_count": len(blocked_harness_slugs),
        "skipped_harness_count": len(skipped_harness_slugs),
        "missing_harness_count": len(missing_harness_slugs),
        "ok_harness_slugs": ok_harness_slugs,
        "blocked_harness_slugs": blocked_harness_slugs,
        "skipped_harness_slugs": skipped_harness_slugs,
        "missing_harness_slugs": missing_harness_slugs,
        "status_counts": dict(sorted(status_counts.items())),
        "harnesses": rows,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--roots-file", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--run-id", default=os.environ.get("AUDITOOOR_AUDIT_RUN_FULL_ID"))
    parser.add_argument("--sync-primary", action="store_true")
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args()

    workspace = Path(args.workspace).resolve()
    roots_file = Path(args.roots_file).resolve()
    out_path = Path(args.out).resolve()
    payload = build_manifest(workspace, roots_file, out_path, args.run_id)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.sync_primary:
        _sync_primary_solidity_manifest(workspace, payload)

    if args.strict:
        missing_count = int(payload.get("missing_harness_count") or 0)
        denominator_ok = payload.get("invariant_denominator_status") == "complete-full-invariant-denominator"
        if missing_count or not denominator_ok:
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
