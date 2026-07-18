#!/usr/bin/env python3
"""Plan per-contract audit-deep commands for Solidity workspaces."""

from __future__ import annotations

import argparse
import json
import os
import re  # r36-rebuttal: bugfix-inventory-claude-20260610
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = "auditooor.audit_deep_per_contract_plan.v1"
DEFAULT_OUT = ".auditooor/per_contract_audit_deep_plan.json"
# Directories that should never be treated as protocol source.
# Kept consistent with gen-composition-fixtures.py; extend both together.
EXCLUDED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "lib",
    "out",
    "artifacts",
    "cache",
    "poc-tests",
    "poc_execution",
    # test / mock / harness / spec directories - not protocol contracts
    "test",
    "tests",
    "certora",
    "mock",
    "mocks",
    "interface",
    "interfaces",
    "helpers",
    "spec",
    "specs",
    "halmos",
    "kontrol",
    "script",
    "scripts",
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _is_live_enabled(args: argparse.Namespace) -> bool:
    if args.live:
        return True
    for name in ("AUDIT_DEEP_LIVE", "LIVE"):
        if os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}:
            return True
    return False


def _contract_name(path: Path) -> str:
    # Parse the first `contract Foo` declaration so the CONTRACT= make argument
    # matches the actual Solidity identifier rather than the filename stem.
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
        m = re.search(r"\bcontract\s+([A-Za-z_]\w*)\b", text)
        if m:
            return m.group(1)
    except OSError:
        pass
    return path.stem


def _discover_contracts(workspace: Path) -> list[Path]:
    contracts: list[Path] = []
    for root, dirs, files in os.walk(workspace):
        dirs[:] = sorted(d for d in dirs if d not in EXCLUDED_DIRS and not d.startswith("."))
        for file_name in sorted(files):
            if file_name.endswith(".sol"):
                contracts.append(Path(root) / file_name)
    return sorted(contracts, key=lambda p: p.as_posix())


def _build_commands(workspace: Path, contracts: list[Path], live: bool) -> list[dict[str, str | bool]]:
    ws = str(workspace)
    rows: list[dict[str, str | bool]] = []
    for contract in contracts:
        rel = contract.relative_to(workspace).as_posix()
        name = _contract_name(contract)
        cmd = (
            f"CONTRACT={name} CONTRACT_FILE={rel} make --no-print-directory audit-deep-solidity "
            f"WS={ws} PROJECT_ROOT={ws} {'LIVE=1' if live else ''}".strip()
        )
        rows.append(
            {
                "contract": name,
                "contract_file": rel,
                "command": cmd,
                "live": live,
                "dry_run": not live,
            }
        )
    return rows


def build_payload(workspace: Path, *, live: bool) -> dict[str, object]:
    contracts = _discover_contracts(workspace)
    return {
        "schema": SCHEMA,
        "generated_at": _utc_now(),
        "workspace": str(workspace),
        "dry_run_default": True,
        "live_enabled": live,
        "contracts_discovered": len(contracts),
        "contracts": [c.relative_to(workspace).as_posix() for c in contracts],
        "commands": _build_commands(workspace, contracts, live=live),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--out", default=DEFAULT_OUT)
    parser.add_argument("--json", action="store_true", help="Print JSON payload to stdout")
    parser.add_argument("--live", action="store_true", help="Opt in to live mode planning")
    args = parser.parse_args()

    workspace = Path(args.workspace).expanduser().resolve()
    if not workspace.is_dir():
        raise SystemExit(f"[audit-deep-per-contract] workspace not found: {workspace}")

    live = _is_live_enabled(args)
    payload = build_payload(workspace, live=live)
    out_path = Path(args.out)
    if not out_path.is_absolute():
        out_path = workspace / out_path
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"[audit-deep-per-contract] wrote plan: {out_path}")
        print(
            "[audit-deep-per-contract] contracts: "
            f"{payload['contracts_discovered']} (live_enabled={str(live).lower()})"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
