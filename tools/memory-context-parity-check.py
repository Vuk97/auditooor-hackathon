#!/usr/bin/env python3
"""Compare open knowledge-gap ledger state against vault MCP context output."""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any, Callable


REPO_ROOT = Path(__file__).resolve().parents[1]
REPORT_SCHEMA = "auditooor.memory_context_parity_check.v1"


def _load_module(module_name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load module {module_name} from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _repo_relative(path: Path, repo_root: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return str(path.resolve())


def _knowledge_gap_module(repo_root: Path) -> Any:
    return _load_module("knowledge_gap_log", repo_root / "tools" / "knowledge-gap-log.py")


def _vault_module(repo_root: Path) -> Any:
    return _load_module("vault_mcp_server", repo_root / "tools" / "vault-mcp-server.py")


def load_latest_open_rows(repo_root: Path, ledger_path: Path | None = None) -> tuple[Path, list[dict[str, Any]]]:
    repo_root = repo_root.resolve()
    ledger = (ledger_path or (repo_root / "reports" / "knowledge_gaps.jsonl")).resolve()
    module = _knowledge_gap_module(repo_root)
    states = module.latest_states(ledger, repo=repo_root)
    open_rows = [row for row in states.values() if str(row.get("status", "")).lower() == "open"]
    open_rows.sort(key=lambda row: str(row.get("gap_id", "")))
    return ledger, open_rows


def fetch_open_context(repo_root: Path, expected_open_count: int) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    module = _vault_module(repo_root)
    vault = module.VaultQuery(repo_root / "obsidian-vault", repo_root=repo_root)
    limit = max(1, expected_open_count)
    return vault.vault_knowledge_gap_context(status="open", limit=limit)


def build_report(
    repo_root: Path,
    ledger_path: Path | None = None,
    *,
    fetcher: Callable[[Path, int], dict[str, Any]] = fetch_open_context,
) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    ledger, open_rows = load_latest_open_rows(repo_root, ledger_path=ledger_path)
    expected_ids = sorted(str(row.get("gap_id", "")) for row in open_rows if row.get("gap_id"))
    pack = fetcher(repo_root, len(expected_ids))

    returned_ids = sorted(
        str(gap.get("gap_id", ""))
        for gap in pack.get("gaps", [])
        if isinstance(gap, dict) and gap.get("gap_id")
    )
    expected_set = set(expected_ids)
    returned_set = set(returned_ids)
    missing_ids = sorted(expected_set - returned_set)
    unexpected_ids = sorted(returned_set - expected_set)
    pack_error = str(pack.get("error", "")) if isinstance(pack, dict) and pack.get("error") else ""
    pack_message = str(pack.get("message", "")) if isinstance(pack, dict) and pack.get("message") else ""

    command_args = {"status": "open", "limit": max(1, len(expected_ids))}
    report = {
        "schema": REPORT_SCHEMA,
        "repo_root": str(repo_root),
        "ledger_path": _repo_relative(ledger, repo_root),
        "tool": "vault_knowledge_gap_context",
        "tool_call": {
            "command": "python3 tools/vault-mcp-server.py --call vault_knowledge_gap_context --args "
            + json.dumps(json.dumps(command_args, separators=(",", ":"))),
            "args": command_args,
            "mode": "direct_function",
        },
        "comparison": {
            "expected_open_gap_ids": expected_ids,
            "returned_open_gap_ids": returned_ids,
            "missing_gap_ids": missing_ids,
            "unexpected_gap_ids": unexpected_ids,
        },
        "summary": {
            "expected_open_count": len(expected_ids),
            "returned_open_count": len(returned_ids),
            "missing_count": len(missing_ids),
            "unexpected_count": len(unexpected_ids),
            "parity_ok": not missing_ids and not unexpected_ids and not pack_error,
            "strict_ready": not missing_ids,
        },
        "advisory": {
            "default_exit_code": 0,
            "strict_exit_code": 1 if missing_ids else 0,
        },
        "pack_status": {
            "error": pack_error,
            "message": pack_message,
            "context_pack_id": pack.get("context_pack_id", "") if isinstance(pack, dict) else "",
            "context_pack_hash": pack.get("context_pack_hash", "") if isinstance(pack, dict) else "",
            "returned_count": pack.get("summary", {}).get("returned_count") if isinstance(pack.get("summary"), dict) else None,
            "open_count": pack.get("summary", {}).get("open_count") if isinstance(pack.get("summary"), dict) else None,
        },
    }
    return report


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    parser.add_argument("--ledger-path", type=Path, default=None)
    parser.add_argument("--strict", action="store_true", help="fail when known open gaps are missing from MCP context")
    return parser.parse_args(argv)


def main(
    argv: list[str] | None = None,
    *,
    fetcher: Callable[[Path, int], dict[str, Any]] = fetch_open_context,
    stdout: Any = None,
) -> int:
    args = parse_args(argv)
    out = stdout or sys.stdout
    try:
        report = build_report(args.repo_root, args.ledger_path, fetcher=fetcher)
    except Exception as exc:  # noqa: BLE001 - CLI should emit JSON on failure.
        print(
            json.dumps(
                {
                    "schema": REPORT_SCHEMA,
                    "repo_root": str(args.repo_root.resolve()),
                    "ledger_path": str(args.ledger_path) if args.ledger_path else "reports/knowledge_gaps.jsonl",
                    "error": "parity_check_failed",
                    "message": str(exc),
                },
                sort_keys=True,
            ),
            file=out,
        )
        return 2
    print(json.dumps(report, sort_keys=True), file=out)
    if args.strict and report["summary"]["missing_count"] > 0:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
