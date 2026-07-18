#!/usr/bin/env python3
"""Live verifier-config check spec emitter (PR #546 Wave 10 Lane B).

Reads a workspace's ``deployment_topology.json`` (and optional
``addresses.json``) and emits live-check specs that pin the verifier /
dispute-game-implementation / proxy-admin / registry slots at a known block.

Per POLY-14 forensic lessons (cross-RPC validation), every emitted spec
includes a primary RPC and at least one cross-validate RPC so a single
malicious or stale endpoint cannot silently confirm a stale slot value.

This tool DOES NOT call any RPC. It only emits a deterministic spec
payload for a downstream live-check runner (cast / ethers script) to
execute against pinned blocks. The output is appended to
``<ws>/live_topology_checks.json`` so the artifact is durable.

Inputs (best-effort, all optional):
  <ws>/deployment_topology.json   built by tools/deployment-topology-builder.py
  <ws>/addresses.json             flat name->address map (project-supplied)
  <ws>/critical_hunt/verifier_upgrade_surface.json
                                  built by tools/verifier-upgrade-surface.py

Output:
  <ws>/live_topology_checks.json  appended (existing rows preserved)

Exit codes:
  0 = spec emitted (or no targets and --strict not set)
  1 = --strict and no eligible targets in workspace
  2 = workspace not found / unreadable
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Iterable


SCHEMA_VERSION = "auditooor.live_verifier_config_check.v1"

# EIP-1967 storage slots.
EIP1967_IMPLEMENTATION_SLOT = (
    "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
)
EIP1967_ADMIN_SLOT = (
    "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
)
EIP1967_BEACON_SLOT = (
    "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"
)

DEFAULT_PRIMARY_RPC_ENV = "ETH_RPC_URL"
DEFAULT_CROSS_RPC_ENVS = ("ETH_RPC_URL_BACKUP", "ETH_RPC_URL_QUICKNODE")

# Heuristics: which contract names are verifier / dispute-game targets.
VERIFIER_HINT_TOKENS = (
    "verifier",
    "disputegame",
    "anchorstate",
    "fault",
    "outputs",
    "proofsystem",
    "respectedgame",
    "factory",
)


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _looks_like_verifier(name: str) -> bool:
    low = name.lower()
    return any(tok in low for tok in VERIFIER_HINT_TOKENS)


def _resolved_address(entry: dict[str, Any]) -> str | None:
    addr = entry.get("resolved_address")
    if isinstance(addr, str) and addr.startswith("0x"):
        return addr
    candidates = entry.get("candidate_addresses") or []
    if isinstance(candidates, list) and len(candidates) == 1:
        if isinstance(candidates[0], str) and candidates[0].startswith("0x"):
            return candidates[0]
    return None


def collect_targets(workspace: Path) -> list[dict[str, Any]]:
    """Return a list of target {name,address,source} dicts."""
    targets: list[dict[str, Any]] = []
    seen_keys: set[tuple[str, str]] = set()

    topo_path = workspace / "deployment_topology.json"
    topo = _load_json(topo_path)
    if isinstance(topo, dict):
        entries = topo.get("contracts") or topo.get("entries") or []
        if isinstance(entries, list):
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                name = entry.get("contract") or entry.get("name") or ""
                if not isinstance(name, str) or not name:
                    continue
                if not _looks_like_verifier(name):
                    continue
                addr = _resolved_address(entry)
                if not addr:
                    continue
                key = (name, addr.lower())
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                targets.append(
                    {
                        "name": name,
                        "address": addr,
                        "source": "deployment_topology.json",
                    }
                )

    addresses_path = workspace / "addresses.json"
    addresses = _load_json(addresses_path)
    if isinstance(addresses, dict):
        for name, addr in addresses.items():
            if not isinstance(name, str) or not isinstance(addr, str):
                continue
            if not addr.startswith("0x"):
                continue
            if not _looks_like_verifier(name):
                continue
            key = (name, addr.lower())
            if key in seen_keys:
                continue
            seen_keys.add(key)
            targets.append({"name": name, "address": addr, "source": "addresses.json"})

    return targets


def build_spec(
    target: dict[str, Any],
    pinned_block: str,
    primary_rpc_env: str,
    cross_rpc_envs: tuple[str, ...],
) -> dict[str, Any]:
    name = target["name"]
    addr = target["address"]
    source = target["source"]
    checks = [
        {
            "name": "implementation_slot",
            "method": "eth_getStorageAt",
            "address": addr,
            "slot": EIP1967_IMPLEMENTATION_SLOT,
            "block": pinned_block,
            "expectation": "non_zero",
            "rationale": "EIP-1967 implementation slot must be non-zero on a UUPS proxy",
        },
        {
            "name": "admin_slot",
            "method": "eth_getStorageAt",
            "address": addr,
            "slot": EIP1967_ADMIN_SLOT,
            "block": pinned_block,
            "expectation": "matches_governance",
            "rationale": "EIP-1967 admin slot must match the documented governance owner",
        },
        {
            "name": "beacon_slot",
            "method": "eth_getStorageAt",
            "address": addr,
            "slot": EIP1967_BEACON_SLOT,
            "block": pinned_block,
            "expectation": "any",
            "rationale": "Beacon slot — non-zero indicates beacon-proxy pattern",
        },
        {
            "name": "owner_call",
            "method": "cast_call",
            "address": addr,
            "signature": "owner()(address)",
            "block": pinned_block,
            "expectation": "matches_governance",
            "rationale": "owner() returns the documented governance owner",
        },
    ]
    return {
        "schema": SCHEMA_VERSION,
        "target_name": name,
        "target_address": addr,
        "address_source": source,
        "pinned_block": pinned_block,
        "primary_rpc_env": primary_rpc_env,
        "cross_validate_rpc_envs": list(cross_rpc_envs),
        "cross_validation_required": True,
        "checks": checks,
        "notes": [
            "POLY-14 lesson: cross-validate every result against >=1 secondary RPC",
            "default-to-kill: spec is advisory until owner confirms expected_value",
        ],
    }


def merge_into_existing(
    existing: list[dict[str, Any]] | None,
    new_specs: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    if isinstance(existing, list):
        for row in existing:
            if not isinstance(row, dict):
                continue
            key = (
                str(row.get("schema", "")),
                str(row.get("target_address", "")).lower(),
                str(row.get("pinned_block", "")),
            )
            seen.add(key)
            out.append(row)
    for spec in new_specs:
        key = (
            spec["schema"],
            spec["target_address"].lower(),
            spec["pinned_block"],
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(spec)
    return out


def write_specs(workspace: Path, specs: list[dict[str, Any]]) -> Path:
    out_path = workspace / "live_topology_checks.json"
    existing = _load_json(out_path)
    existing_rows: list[dict[str, Any]] | None = None
    if isinstance(existing, dict):
        rows = existing.get("rows") or existing.get("checks")
        if isinstance(rows, list):
            existing_rows = rows
    elif isinstance(existing, list):
        existing_rows = existing

    merged = merge_into_existing(existing_rows, specs)
    payload = {
        "schema": SCHEMA_VERSION,
        "tool": "tools/live-verifier-config-check.py",
        "row_count": len(merged),
        "rows": merged,
    }
    out_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return out_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Emit live-config check specs for verifier/dispute-game targets."
    )
    parser.add_argument("--workspace", required=True, help="Workspace root.")
    parser.add_argument(
        "--pinned-block",
        default="latest",
        help="Block tag to pin (default: latest). For forensic, prefer a hex block.",
    )
    parser.add_argument(
        "--primary-rpc-env",
        default=DEFAULT_PRIMARY_RPC_ENV,
        help="Env var name to read for the primary RPC URL.",
    )
    parser.add_argument(
        "--cross-rpc-envs",
        nargs="*",
        default=list(DEFAULT_CROSS_RPC_ENVS),
        help="Env var names for >=1 cross-validation RPC URL(s).",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit 1 if no verifier-shaped targets are found.",
    )
    parser.add_argument(
        "--print-json",
        action="store_true",
        help="Print emitted spec JSON to stdout in addition to writing the file.",
    )
    args = parser.parse_args(argv)

    workspace = Path(args.workspace).expanduser().resolve()
    if not workspace.is_dir():
        print(
            f"[live-verifier-config-check] ERR workspace not a dir: {workspace}",
            file=sys.stderr,
        )
        return 2

    targets = collect_targets(workspace)
    specs = [
        build_spec(
            t,
            pinned_block=args.pinned_block,
            primary_rpc_env=args.primary_rpc_env,
            cross_rpc_envs=tuple(args.cross_rpc_envs),
        )
        for t in targets
    ]

    out_path = write_specs(workspace, specs)
    print(f"[live-verifier-config-check] wrote {out_path}")
    print(f"[live-verifier-config-check] new_specs={len(specs)} targets={len(targets)}")

    if args.print_json:
        json.dump({"schema": SCHEMA_VERSION, "specs": specs}, sys.stdout, indent=2)
        sys.stdout.write("\n")

    if args.strict and not targets:
        print(
            "[live-verifier-config-check] STRICT: no verifier-shaped targets",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
