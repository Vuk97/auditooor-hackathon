#!/usr/bin/env python3
"""Bulk agent-artifact mining across audit workspaces.

K1 in the HACKERMAN V3 roadmap requires every workspace with agent-produced
artifact inputs to have a fresh inventory or a typed skip reason.  This wrapper
keeps the single-workspace miner as the source of truth and adds durable
per-workspace state under ``.auditooor/agent_artifacts/state.json``.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import sys
import traceback
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "auditooor.agent_artifact_mine_all.v1"
STATE_SCHEMA = "auditooor.agent_artifact_mining_state.v1"
MINER_PATH = ROOT / "tools" / "agent-artifact-miner.py"


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_miner():
    spec = importlib.util.spec_from_file_location("agent_artifact_miner", MINER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load miner at {MINER_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules["agent_artifact_miner"] = module
    spec.loader.exec_module(module)
    return module


def artifact_input_summary(workspace: Path, miner: Any | None = None) -> dict[str, Any]:
    if miner is None or not hasattr(miner, "artifact_input_summary"):
        miner = _load_miner()
    return miner.artifact_input_summary(workspace)


def artifact_input_evidence(workspace: Path) -> list[str]:
    return list(artifact_input_summary(workspace)["evidence_roots"])


def discover_workspaces(audits_root: Path, explicit: Iterable[Path] = ()) -> list[Path]:
    if explicit:
        return sorted({path.expanduser().resolve() for path in explicit})
    return sorted(
        path.resolve()
        for path in audits_root.expanduser().resolve().iterdir()
        if path.is_dir() and not path.name.startswith(".") and not path.name.startswith("-")
    )


def _state_path(workspace: Path) -> Path:
    return workspace / ".auditooor" / "agent_artifacts" / "state.json"


def _write_state(workspace: Path, payload: dict[str, Any]) -> None:
    path = _state_path(workspace)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _state_base(workspace: Path, audits_root: Path, generated_at: str, input_summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": STATE_SCHEMA,
        "schema_version": STATE_SCHEMA,
        "generated_at_utc": generated_at,
        "workspace": str(workspace),
        "workspace_name": workspace.name,
        "audits_root": str(audits_root),
        "artifact_input_evidence": input_summary.get("evidence_roots", []),
        "input_summary": input_summary,
    }


def mine_one(workspace: Path, audits_root: Path, miner: Any, *, generated_at: str, dry_run: bool = False) -> dict[str, Any]:
    input_summary = artifact_input_summary(workspace, miner)
    state = _state_base(workspace, audits_root, generated_at, input_summary)
    if not input_summary["has_artifact_inputs"]:
        state.update(
            {
                "status": "skipped",
                "skip_reason": "NO_ARTIFACT_INPUTS",
                "fresh_inventory": False,
                "fresh": False,
                "report_path": "",
                "report_sha256": "",
                "total_artifacts": 0,
            }
        )
        if not dry_run:
            _write_state(workspace, state)
        return state

    report_path = workspace / "agent_artifact_mining_report.json"
    try:
        report = miner.mine_workspace(workspace)
        report_text = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
        if not dry_run:
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(report_text, encoding="utf-8")
        report_hash = hashlib.sha256(report_text.encode("utf-8")).hexdigest() if dry_run else _sha256(report_path)
        state.update(
            {
                "status": "mined",
                "skip_reason": "",
                "fresh_inventory": True,
                "fresh": True,
                "report_path": str(report_path),
                "report_sha256": report_hash,
                "report_schema": report.get("schema_version"),
                "total_artifacts": int(report.get("total_artifacts", 0) or 0),
                "artifact_type_counts": report.get("artifact_type_counts") if isinstance(report.get("artifact_type_counts"), dict) else {},
                "no_learning_reason": report.get("no_learning_reason"),
            }
        )
    except Exception as exc:  # noqa: BLE001 - state must capture workspace-specific failure.
        state.update(
            {
                "status": "error",
                "skip_reason": "MINER_EXCEPTION",
                "fresh_inventory": False,
                "fresh": False,
                "report_path": str(report_path),
                "report_sha256": _sha256(report_path) if report_path.is_file() else "",
                "total_artifacts": 0,
                "error": str(exc),
                "traceback": traceback.format_exc(limit=8),
            }
        )
    if not dry_run:
        _write_state(workspace, state)
    return state


def build_payload(audits_root: Path, rows: list[dict[str, Any]], generated_at: str) -> dict[str, Any]:
    by_status: dict[str, int] = {}
    for row in rows:
        status = str(row.get("status") or "unknown")
        by_status[status] = by_status.get(status, 0) + 1
    return {
        "schema": SCHEMA,
        "generated_at_utc": generated_at,
        "audits_root": str(audits_root),
        "workspace_count": len(rows),
        "mined_count": by_status.get("mined", 0),
        "skipped_count": by_status.get("skipped", 0),
        "error_count": by_status.get("error", 0),
        "by_status": dict(sorted(by_status.items())),
        "rows": rows,
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audits-root", type=Path, default=Path.home() / "audits")
    parser.add_argument("--workspace", type=Path, action="append", default=[], help="Explicit workspace; repeatable.")
    parser.add_argument("--out", type=Path, help="Optional aggregate JSON output path.")
    parser.add_argument("--json", action="store_true", help="Print aggregate JSON.")
    parser.add_argument("--dry-run", action="store_true", help="Do not write reports or state files.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    audits_root = args.audits_root.expanduser().resolve()
    if not args.workspace and not audits_root.is_dir():
        print(f"ERROR: audits root not found: {audits_root}", file=sys.stderr)
        return 2

    generated_at = _utc_now()
    miner = _load_miner()
    workspaces = discover_workspaces(audits_root, args.workspace)
    rows = [mine_one(workspace, audits_root, miner, generated_at=generated_at, dry_run=args.dry_run) for workspace in workspaces]
    payload = build_payload(audits_root, rows, generated_at)
    text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if args.out:
        out = args.out.expanduser().resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
    if args.json or not args.out:
        print(text, end="")
    if payload["error_count"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
