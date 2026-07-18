#!/usr/bin/env python3
"""Reconcile a scoped hunt plan with canonical provider sidecars.

The dispatch ledger proves that batches were routed through the worker path;
this tool proves that every task has one current, joinable provider result.
It writes the provider receipt only from the validated reconciliation result.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

RECEIPT_SCHEMA = "auditooor.provider_fanout_receipt.v1"
TASK_RE = re.compile(r"^### Task \d+: ([A-Za-z0-9_.-]+)$", re.MULTILINE)


def _utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _tasks(plan_dir: Path) -> list[str]:
    found: list[str] = []
    for path in sorted(plan_dir.glob("agent_batch_*.md")):
        found.extend(TASK_RE.findall(path.read_text(encoding="utf-8", errors="replace")))
    if len(found) != len(set(found)):
        raise ValueError("plan contains duplicate task_id values")
    return found


def _validate_sidecar(path: Path, task_id: str, workspace: Path, provider: str) -> str | None:
    try:
        data: Any = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return f"{task_id}: invalid outer JSON ({exc})"
    if not isinstance(data, dict):
        return f"{task_id}: outer JSON is not an object"
    expected = {
        "task_id": task_id,
        "workspace": workspace.name,
        "workspace_path": str(workspace),
        "provider": provider,
        "status": "ok",
    }
    for key, value in expected.items():
        if data.get(key) != value:
            return f"{task_id}: {key} does not match expected value"
    if not isinstance(data.get("result"), str):
        return f"{task_id}: result is not a JSON-encoded string"
    try:
        nested = json.loads(data["result"])
    except (TypeError, ValueError) as exc:
        return f"{task_id}: result is invalid JSON ({exc})"
    if not isinstance(nested, dict):
        return f"{task_id}: result JSON is not an object"
    return None


def reconcile(workspace: Path, plan_dir: Path, sidecar_dir: Path, provider: str) -> dict[str, Any]:
    started = _utc()
    errors: list[str] = []
    try:
        task_ids = _tasks(plan_dir)
    except (OSError, ValueError) as exc:
        task_ids = []
        errors.append(f"plan: {exc}")
    for task_id in task_ids:
        path = sidecar_dir / f"{task_id}.json"
        if not path.is_file():
            errors.append(f"{task_id}: canonical sidecar is missing")
            continue
        error = _validate_sidecar(path, task_id, workspace, provider)
        if error:
            errors.append(error)
    ok_count = len(task_ids) - len(errors)
    if ok_count < 0:
        ok_count = 0
    receipt: dict[str, Any] = {
        "schema": RECEIPT_SCHEMA,
        "workspace": str(workspace),
        "output_dir": str(plan_dir.parent),
        "plan_token": plan_dir.parent.name,
        "provider": provider,
        "task_count": len(task_ids),
        "terminal_counts": {"ok": ok_count, "failed": len(errors)},
        "started_at_utc": started,
        "ended_at_utc": _utc(),
        "reconciliation": {
            "plan_dir": str(plan_dir),
            "sidecar_dir": str(sidecar_dir),
            "error_count": len(errors),
            "errors": errors,
        },
    }
    return receipt


def _write_atomic(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--plan-dir", type=Path, required=True)
    parser.add_argument("--sidecar-dir", type=Path, required=True)
    parser.add_argument("--provider", required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args(argv)
    receipt = reconcile(args.workspace, args.plan_dir, args.sidecar_dir, args.provider)
    _write_atomic(args.receipt, receipt)
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0 if receipt["terminal_counts"].get("failed", 0) == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
