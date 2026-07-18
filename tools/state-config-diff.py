#!/usr/bin/env python3
"""
state-config-diff.py -- G1 live state/config diff runner.

Schema: auditooor.state_config_diff.v1

For every in-scope deployed contract, produce a per-asset read plan enumerating:
  - proxy implementation / EIP-1967 admin slots
  - role members (AccessControl / Ownable)
  - owner / admin config
  - critical config getters (caps, fees, limits, thresholds)
  - balances and reserve levels
  - pause / freeze / emergency flags
  - bridge / router / registry endpoints
  - oracle / price-feed addresses
  - constructor / deploy-time assumptions

Each read item carries the EXACT pinned cast/RPC command a human (or follow-up
step) runs -- block-pinned so reads are reproducible.

OFFLINE-SAFE: the tool never makes a network call.
- Mode A (read-plan emit): no probe outputs present -> emit <ws>/.auditooor/state_config_diff.json
  with the pinned read plan.
- Mode B (probe-diff): if <ws>/live_state_probes/ contains probe JSON files that match
  addresses in the read plan, ingest them and surface divergences from the audited assumption.

Divergences become:
  - type "exploit_queue_seed": actionable candidate for exploit queue ingestion
  - type "benign_control":     documented as expected / non-exploitable

Usage:
    state-config-diff.py --workspace <ws>
    state-config-diff.py --workspace <ws> --chain-id 137 --block 50000000
    state-config-diff.py --workspace <ws> --rpc-url https://polygon-rpc.com
    state-config-diff.py --workspace <ws> --out <path>
    state-config-diff.py --workspace <ws> --json          # emit JSON to stdout
    state-config-diff.py --workspace <ws> --diff-only     # only report divergences

Do NOT call live-state-checker.py or deployment-topology-builder.py; this tool
ingests their already-produced artifacts (live_topology_checks.json,
deployment_topology.json, live_state_probes/) and produces a new, purpose-built
artifact suited for exploit-queue ingestion.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Schema version
# ---------------------------------------------------------------------------
SCHEMA = "auditooor.state_config_diff.v1"
SCHEMA_VERSION = "1"

# ---------------------------------------------------------------------------
# EIP-1967 standard storage slots
# ---------------------------------------------------------------------------
EIP1967_SLOTS = {
    "implementation": "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
    "admin": "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103",
    "beacon": "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50",
}

# OpenZeppelin legacy proxy slot (Transparent Proxy pre-1967)
LEGACY_OZ_IMPL_SLOT = "0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3"

# ---------------------------------------------------------------------------
# Category definitions: what to read for each contract type
# ---------------------------------------------------------------------------
CATEGORY_CHECKS: dict[str, list[dict[str, Any]]] = {
    "proxy": [
        {
            "id": "proxy_impl",
            "label": "EIP-1967 implementation slot",
            "slot": EIP1967_SLOTS["implementation"],
            "cmd_template": "cast storage {address} {slot} --rpc-url {rpc_url} --block {block}",
            "expect_key": "implementation_address",
            "description": "Actual on-chain implementation; must match audited assumption.",
            "divergence_class": "implementation_mismatch",
        },
        {
            "id": "proxy_admin",
            "label": "EIP-1967 admin slot",
            "slot": EIP1967_SLOTS["admin"],
            "cmd_template": "cast storage {address} {slot} --rpc-url {rpc_url} --block {block}",
            "expect_key": "admin_address",
            "description": "Proxy admin; should match documented multisig / timelock.",
            "divergence_class": "admin_mismatch",
        },
        {
            "id": "proxy_beacon",
            "label": "EIP-1967 beacon slot",
            "slot": EIP1967_SLOTS["beacon"],
            "cmd_template": "cast storage {address} {slot} --rpc-url {rpc_url} --block {block}",
            "expect_key": "beacon_address",
            "description": "Beacon proxy pointer; non-zero only for beacon-pattern contracts.",
            "divergence_class": "beacon_unexpected",
        },
    ],
    "access_control": [
        {
            "id": "owner",
            "label": "owner()",
            "call": "owner()(address)",
            "cmd_template": "cast call {address} 'owner()(address)' --rpc-url {rpc_url} --block {block}",
            "expect_key": "owner_address",
            "description": "Ownable owner; must match documented owner / multisig.",
            "divergence_class": "owner_mismatch",
        },
        {
            "id": "pending_owner",
            "label": "pendingOwner()",
            "call": "pendingOwner()(address)",
            "cmd_template": "cast call {address} 'pendingOwner()(address)' --rpc-url {rpc_url} --block {block}",
            "expect_key": "pending_owner_address",
            "description": "Pending two-step ownership transfer; non-zero is significant.",
            "divergence_class": "pending_owner_unexpected",
        },
        {
            "id": "default_admin_role",
            "label": "getRoleMember(DEFAULT_ADMIN_ROLE, 0)",
            "call": "getRoleMember(bytes32,uint256)(address)",
            "call_args": ["0x0000000000000000000000000000000000000000000000000000000000000000", "0"],
            "cmd_template": "cast call {address} 'getRoleMember(bytes32,uint256)(address)' 0x0000000000000000000000000000000000000000000000000000000000000000 0 --rpc-url {rpc_url} --block {block}",
            "expect_key": "default_admin_address",
            "description": "DEFAULT_ADMIN_ROLE member[0]; must match documented admin.",
            "divergence_class": "admin_role_mismatch",
        },
    ],
    "pause": [
        {
            "id": "paused",
            "label": "paused()",
            "call": "paused()(bool)",
            "cmd_template": "cast call {address} 'paused()(bool)' --rpc-url {rpc_url} --block {block}",
            "expect_key": "paused",
            "expect_value": False,
            "description": "Pausable flag; true at audit time is a significant finding signal.",
            "divergence_class": "unexpected_paused_state",
        },
        {
            "id": "frozen",
            "label": "frozen() / isFrozen()",
            "call": "frozen()(bool)",
            "cmd_template": "cast call {address} 'frozen()(bool)' --rpc-url {rpc_url} --block {block}",
            "expect_key": "frozen",
            "expect_value": False,
            "description": "Frozen flag; true signals emergency state.",
            "divergence_class": "unexpected_frozen_state",
        },
    ],
    "config_getters": [
        {
            "id": "fee_rate",
            "label": "feeRate() / fee()",
            "call": "feeRate()(uint256)",
            "cmd_template": "cast call {address} 'feeRate()(uint256)' --rpc-url {rpc_url} --block {block}",
            "expect_key": "fee_rate",
            "description": "Protocol fee rate; compare to audited assumption / docs.",
            "divergence_class": "fee_config_divergence",
        },
        {
            "id": "max_leverage",
            "label": "maxLeverage() / maxBorrowFactor()",
            "call": "maxLeverage()(uint256)",
            "cmd_template": "cast call {address} 'maxLeverage()(uint256)' --rpc-url {rpc_url} --block {block}",
            "expect_key": "max_leverage",
            "description": "Max leverage cap; higher than audited signals risk expansion.",
            "divergence_class": "leverage_cap_divergence",
        },
        {
            "id": "borrow_cap",
            "label": "borrowCap() / supplyCap()",
            "call": "borrowCap()(uint256)",
            "cmd_template": "cast call {address} 'borrowCap()(uint256)' --rpc-url {rpc_url} --block {block}",
            "expect_key": "borrow_cap",
            "description": "Borrow / supply cap; 0 or very high may signal missing guardrail.",
            "divergence_class": "cap_divergence",
        },
    ],
    "oracle": [
        {
            "id": "price_oracle",
            "label": "priceOracle() / oracle() / feed()",
            "call": "priceOracle()(address)",
            "cmd_template": "cast call {address} 'priceOracle()(address)' --rpc-url {rpc_url} --block {block}",
            "expect_key": "oracle_address",
            "description": "Price oracle / feed address; mismatch signals oracle swap.",
            "divergence_class": "oracle_mismatch",
        },
        {
            "id": "sequencer_uptime_feed",
            "label": "sequencerUptimeFeed()",
            "call": "sequencerUptimeFeed()(address)",
            "cmd_template": "cast call {address} 'sequencerUptimeFeed()(address)' --rpc-url {rpc_url} --block {block}",
            "expect_key": "sequencer_feed_address",
            "description": "L2 sequencer uptime feed; zero address signals missing L2 guard.",
            "divergence_class": "missing_sequencer_feed",
        },
    ],
    "bridge_router": [
        {
            "id": "router",
            "label": "router() / bridge()",
            "call": "router()(address)",
            "cmd_template": "cast call {address} 'router()(address)' --rpc-url {rpc_url} --block {block}",
            "expect_key": "router_address",
            "description": "Router / bridge endpoint; mismatch could indicate routing attack surface.",
            "divergence_class": "router_mismatch",
        },
        {
            "id": "bridge",
            "label": "bridge() / messagePasser()",
            "call": "bridge()(address)",
            "cmd_template": "cast call {address} 'bridge()(address)' --rpc-url {rpc_url} --block {block}",
            "expect_key": "bridge_address",
            "description": "Bridge contract pointer.",
            "divergence_class": "bridge_mismatch",
        },
    ],
    "balance": [
        {
            "id": "eth_balance",
            "label": "ETH balance",
            "cmd_template": "cast balance {address} --rpc-url {rpc_url} --block {block}",
            "expect_key": "eth_balance_wei",
            "description": "Native ETH held by contract; unexpected holdings signal accounting issue.",
            "divergence_class": "unexpected_eth_balance",
        },
        {
            "id": "token_balance",
            "label": "ERC20 balanceOf(address)",
            "call": "balanceOf(address)(uint256)",
            "call_args": ["{address}"],
            "cmd_template": "cast call {token_address} 'balanceOf(address)(uint256)' {address} --rpc-url {rpc_url} --block {block}",
            "expect_key": "token_balance",
            "description": "ERC20 token balance; compare to documented reserve.",
            "divergence_class": "token_balance_divergence",
        },
    ],
}

# Default categories to include when contract type is unknown
DEFAULT_CATEGORIES = ["proxy", "access_control", "pause", "config_getters", "oracle", "bridge_router", "balance"]


# ---------------------------------------------------------------------------
# Helpers: address / scope loading
# ---------------------------------------------------------------------------

def _is_address(val: str) -> bool:
    return bool(re.match(r"^0x[0-9a-fA-F]{40}$", val.strip()))


def _extract_assets_from_scope(scope_path: Path) -> list[dict[str, Any]]:
    """Parse scope.json for deployed contract addresses.

    Handles:
      - Immunefi / HackenProof format (assets[].reference = blockexplorer URL)
      - Simple format: targets[].address or deployed_addresses[]
      - Flat list: [{name, address, chain_id, ...}]
    """
    if not scope_path.exists():
        return []
    try:
        data = json.loads(scope_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []

    assets: list[dict[str, Any]] = []

    # Handle list-of-scope-items (Immunefi multi-asset format)
    scope_items = data if isinstance(data, list) else [data]
    for item in scope_items:
        if not isinstance(item, dict):
            continue

        # Nested assets[] with .reference URLs
        for asset in item.get("assets", []):
            if not isinstance(asset, dict):
                continue
            ref = asset.get("reference", "")
            # Extract address from explorer URL: /address/0x...
            m = re.search(r"/address/(0x[0-9a-fA-F]{40})", ref)
            if m:
                assets.append({
                    "name": asset.get("name", "unknown"),
                    "address": m.group(1),
                    "chain_id": _infer_chain_id_from_url(ref),
                    "categories": DEFAULT_CATEGORIES,
                    "audited_assumptions": {},
                    "source": "scope.json:assets[].reference",
                })

        # Flat targets[] with .address field
        for tgt in item.get("targets", []):
            if isinstance(tgt, dict) and _is_address(str(tgt.get("address", ""))):
                assets.append({
                    "name": tgt.get("name", tgt.get("contract", "unknown")),
                    "address": tgt["address"],
                    "chain_id": tgt.get("chain_id", None),
                    "categories": DEFAULT_CATEGORIES,
                    "audited_assumptions": {},
                    "source": "scope.json:targets[].address",
                })

        # Flat deployed_addresses[] list
        for da in item.get("deployed_addresses", []):
            if isinstance(da, dict) and _is_address(str(da.get("address", ""))):
                assets.append({
                    "name": da.get("name", "unknown"),
                    "address": da["address"],
                    "chain_id": da.get("chain_id", None),
                    "categories": DEFAULT_CATEGORIES,
                    "audited_assumptions": {},
                    "source": "scope.json:deployed_addresses[]",
                })

        # Top-level address field in scope item itself
        if _is_address(str(item.get("address", ""))):
            assets.append({
                "name": item.get("name", "unknown"),
                "address": item["address"],
                "chain_id": item.get("chain_id", None),
                "categories": DEFAULT_CATEGORIES,
                "audited_assumptions": {},
                "source": "scope.json:top-level",
            })

    return assets


def _infer_chain_id_from_url(url: str) -> int | None:
    mapping = {
        "polygonscan.com": 137,
        "etherscan.io": 1,
        "arbiscan.io": 42161,
        "optimistic.etherscan.io": 10,
        "bscscan.com": 56,
        "basescan.org": 8453,
        "gnosisscan.io": 100,
        "snowtrace.io": 43114,
        "ftmscan.com": 250,
    }
    for host, cid in mapping.items():
        if host in url:
            return cid
    return None


def _load_state_config_assets(workspace: Path) -> list[dict[str, Any]]:
    """Load the operator-provided state_config_assets.json if present."""
    path = workspace / ".auditooor" / "state_config_assets.json"
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return data
    except (json.JSONDecodeError, OSError):
        pass
    return []


def _load_deployment_topology(workspace: Path) -> list[dict[str, Any]]:
    """Extract resolved addresses from deployment_topology.json if present."""
    path = workspace / "deployment_topology.json"
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []

    assets = []
    for entry in data.get("entries", []):
        if not isinstance(entry, dict):
            continue
        addr = entry.get("resolved_address")
        if addr and _is_address(str(addr)):
            assets.append({
                "name": entry.get("contract", "unknown"),
                "address": addr,
                "chain_id": None,
                "categories": DEFAULT_CATEGORIES,
                "audited_assumptions": {},
                "source": "deployment_topology.json",
            })
    return assets


# ---------------------------------------------------------------------------
# Read plan generation
# ---------------------------------------------------------------------------

def _default_rpc(chain_id: int | None) -> str:
    defaults: dict[int, str] = {
        1: "https://ethereum-rpc.publicnode.com",
        137: "https://polygon-bor-rpc.publicnode.com",
        42161: "https://arbitrum-one-rpc.publicnode.com",
        10: "https://optimism-rpc.publicnode.com",
        56: "https://bsc-rpc.publicnode.com",
        8453: "https://base-rpc.publicnode.com",
        100: "https://gnosis-rpc.publicnode.com",
        43114: "https://avalanche-c-chain-rpc.publicnode.com",
    }
    return defaults.get(chain_id, "${RPC_URL}")


def _build_read_plan_for_asset(
    asset: dict[str, Any],
    rpc_url: str,
    block: int | str,
) -> list[dict[str, Any]]:
    """Generate the list of pinned read items for a single asset."""
    address = asset["address"]
    categories = asset.get("categories", DEFAULT_CATEGORIES)
    items: list[dict[str, Any]] = []

    for cat in categories:
        checks = CATEGORY_CHECKS.get(cat, [])
        for check in checks:
            # Render command template
            cmd = check["cmd_template"].format(
                address=address,
                rpc_url=rpc_url,
                block=block,
                slot=check.get("slot", ""),
                token_address=asset.get("token_address", "${TOKEN_ADDRESS}"),
            )
            item: dict[str, Any] = {
                "id": f"{cat}__{check['id']}",
                "category": cat,
                "label": check["label"],
                "description": check["description"],
                "pinned_cmd": cmd,
                "rpc_url": rpc_url,
                "block": block,
                "address": address,
                "expect_key": check.get("expect_key"),
                "expect_value": check.get("expect_value"),
                "divergence_class": check.get("divergence_class"),
            }
            if "slot" in check:
                item["slot"] = check["slot"]
            if "call" in check:
                item["call"] = check["call"]
                item["call_args"] = [
                    a.format(address=address) for a in check.get("call_args", [])
                ]
            items.append(item)

    return items


# ---------------------------------------------------------------------------
# Probe ingestion and diff
# ---------------------------------------------------------------------------

def _load_probes(workspace: Path) -> list[dict[str, Any]]:
    """Load all JSON probe files from live_state_probes/ directory."""
    probe_dir = workspace / "live_state_probes"
    if not probe_dir.is_dir():
        return []
    probes: list[dict[str, Any]] = []
    for f in sorted(probe_dir.glob("*.json")):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                data["_probe_file"] = f.name
                probes.append(data)
        except (json.JSONDecodeError, OSError):
            pass
    return probes


def _extract_probe_values(probes: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Build address -> {key -> value} index from probe files."""
    index: dict[str, dict[str, Any]] = {}
    for probe in probes:
        # Try results[] array first (live_topology_checks format)
        for result in probe.get("results", []):
            if not isinstance(result, dict):
                continue
            addr = result.get("address") or result.get("host") or result.get("contract_address")
            if not addr:
                continue
            addr = addr.strip().lower()
            if addr not in index:
                index[addr] = {"_probe_file": probe.get("_probe_file", "")}
            index[addr].update({k: v for k, v in result.items() if k != "address"})

        # Try top-level host / contract_address fields (hyperbridge probe format)
        for result in probe.get("results", []):
            if not isinstance(result, dict):
                continue
            for addr_key in ("host", "contract_address", "bandwidth_manager"):
                addr = result.get(addr_key, "")
                if addr and _is_address(str(addr)):
                    addr_l = addr.strip().lower()
                    if addr_l not in index:
                        index[addr_l] = {"_probe_file": probe.get("_probe_file", "")}
                    index[addr_l][addr_key] = addr

    return index


def _diff_asset(
    asset: dict[str, Any],
    read_plan_items: list[dict[str, Any]],
    probe_index: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Compare probe values against audited assumptions for one asset."""
    address = asset["address"].strip().lower()
    probe_vals = probe_index.get(address, {})
    assumptions = asset.get("audited_assumptions", {})
    divergences: list[dict[str, Any]] = []

    if not probe_vals:
        return divergences  # no probe data -- nothing to diff

    for item in read_plan_items:
        expect_key = item.get("expect_key")
        if not expect_key:
            continue
        # Check if probe has this key
        actual = probe_vals.get(expect_key)
        if actual is None:
            continue

        expected = assumptions.get(expect_key) or item.get("expect_value")
        if expected is None:
            continue

        # Compare (string-normalize for addresses)
        def norm(v: Any) -> str:
            s = str(v).strip().lower()
            # Strip leading zeros from hex values for comparison
            return s

        if norm(actual) != norm(expected):
            divergences.append({
                "item_id": item["id"],
                "category": item["category"],
                "label": item["label"],
                "address": asset["address"],
                "expect_key": expect_key,
                "expected_value": expected,
                "actual_value": actual,
                "divergence_class": item.get("divergence_class", "unknown"),
                "pinned_cmd": item["pinned_cmd"],
                "probe_file": probe_vals.get("_probe_file", ""),
            })

    return divergences


def _classify_divergence(divergence: dict[str, Any]) -> dict[str, Any]:
    """Assign exploit_queue_seed vs benign_control type to a divergence."""
    # Classes that are always exploit-queue seeds
    exploit_classes = {
        "implementation_mismatch",
        "owner_mismatch",
        "admin_mismatch",
        "admin_role_mismatch",
        "oracle_mismatch",
        "router_mismatch",
        "bridge_mismatch",
        "pending_owner_unexpected",
        "missing_sequencer_feed",
        "fee_config_divergence",
        "leverage_cap_divergence",
        "cap_divergence",
    }
    # Classes that may be benign but warrant documentation
    benign_classes = {
        "beacon_unexpected",
        "unexpected_paused_state",
        "unexpected_frozen_state",
        "unexpected_eth_balance",
        "token_balance_divergence",
    }

    dc = divergence.get("divergence_class", "unknown")
    if dc in exploit_classes:
        dtype = "exploit_queue_seed"
        severity_hint = "high"
    elif dc in benign_classes:
        dtype = "benign_control"
        severity_hint = "info"
    else:
        dtype = "exploit_queue_seed"
        severity_hint = "medium"

    return {
        **divergence,
        "divergence_type": dtype,
        "severity_hint": severity_hint,
        "exploit_queue_row": _make_exploit_queue_row(divergence, dtype, severity_hint),
    }


def _make_exploit_queue_row(
    divergence: dict[str, Any],
    dtype: str,
    severity_hint: str,
) -> dict[str, Any] | None:
    """Produce an exploit-queue compatible row for exploit_queue_seed divergences."""
    if dtype != "exploit_queue_seed":
        return None
    return {
        "id": f"scd_{divergence['divergence_class']}__{divergence['address'][:10]}",
        "schema": "auditooor.exploit_queue_seed.v1",
        "source": "state_config_diff",
        "title": f"Deployed-state divergence: {divergence['label']} mismatch on {divergence['address'][:10]}...",
        "category": divergence["category"],
        "divergence_class": divergence["divergence_class"],
        "address": divergence["address"],
        "expected_value": divergence["expected_value"],
        "actual_value": divergence["actual_value"],
        "evidence_cmd": divergence["pinned_cmd"],
        "severity_hint": severity_hint,
        "requires_manual_verification": True,
        "notes": (
            f"Live state differs from audited assumption for key '{divergence['expect_key']}'. "
            f"Verify via: {divergence['pinned_cmd']}"
        ),
    }


# ---------------------------------------------------------------------------
# Main output builder
# ---------------------------------------------------------------------------

def build_state_config_diff(
    workspace: Path,
    rpc_url: str | None = None,
    chain_id: int | None = None,
    block: int | str = "latest",
    categories_override: list[str] | None = None,
) -> dict[str, Any]:
    """Build the full state_config_diff artifact for a workspace."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # --- Load asset list (priority: state_config_assets.json > scope.json > deployment_topology) ---
    assets = _load_state_config_assets(workspace)
    if not assets:
        assets = _extract_assets_from_scope(workspace / "scope.json")
    if not assets:
        assets = _load_deployment_topology(workspace)

    if categories_override:
        for asset in assets:
            asset["categories"] = categories_override

    # --- Resolve RPC and block per asset ---
    probes = _load_probes(workspace)
    probe_index = _extract_probe_values(probes)
    has_probes = bool(probes)

    # --- Build per-asset entries ---
    asset_entries: list[dict[str, Any]] = []
    all_divergences: list[dict[str, Any]] = []
    all_benign: list[dict[str, Any]] = []

    for asset in assets:
        asset_chain_id = chain_id or asset.get("chain_id")
        asset_rpc = rpc_url or asset.get("rpc_url") or _default_rpc(asset_chain_id)
        asset_block = asset.get("pinned_block", block)

        read_plan = _build_read_plan_for_asset(asset, asset_rpc, asset_block)

        # Diff against probes if available
        raw_divs: list[dict[str, Any]] = []
        if has_probes:
            raw_divs = _diff_asset(asset, read_plan, probe_index)

        classified: list[dict[str, Any]] = [_classify_divergence(d) for d in raw_divs]
        seeds = [c for c in classified if c["divergence_type"] == "exploit_queue_seed"]
        benign = [c for c in classified if c["divergence_type"] == "benign_control"]
        all_divergences.extend(seeds)
        all_benign.extend(benign)

        entry: dict[str, Any] = {
            "name": asset.get("name", "unknown"),
            "address": asset["address"],
            "chain_id": asset_chain_id,
            "rpc_url": asset_rpc,
            "pinned_block": asset_block,
            "categories": asset.get("categories", DEFAULT_CATEGORIES),
            "source": asset.get("source", "unknown"),
            "read_plan": read_plan,
            "audited_assumptions": asset.get("audited_assumptions", {}),
            "probe_coverage": bool(probe_index.get(asset["address"].strip().lower())),
            "divergences": classified,
            "divergence_count": len(classified),
            "exploit_queue_seeds": len(seeds),
            "benign_controls": len(benign),
        }
        asset_entries.append(entry)

    mode = "probe_diff" if has_probes else "read_plan"

    output: dict[str, Any] = {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "workspace": str(workspace),
        "generated_at": now,
        "mode": mode,
        "assets_total": len(asset_entries),
        "assets_with_probes": sum(1 for e in asset_entries if e["probe_coverage"]),
        "total_divergences": len(all_divergences) + len(all_benign),
        "exploit_queue_seeds": len(all_divergences),
        "benign_controls": len(all_benign),
        "offline_safe": True,
        "note": (
            "Mode 'read_plan': run each entry.read_plan[].pinned_cmd to capture probe data, "
            "then store in <ws>/live_state_probes/<name>.json and re-run to diff."
            if mode == "read_plan" else
            "Mode 'probe_diff': divergences reflect differences between probe outputs and "
            "audited_assumptions. exploit_queue_seeds are actionable candidates."
        ),
        "assets": asset_entries,
        "exploit_queue_seeds": [
            d["exploit_queue_row"]
            for d in all_divergences
            if d.get("exploit_queue_row")
        ],
        "benign_controls_summary": [
            {
                "address": d["address"],
                "category": d["category"],
                "label": d["label"],
                "divergence_class": d["divergence_class"],
                "actual_value": d["actual_value"],
                "expected_value": d["expected_value"],
            }
            for d in all_benign
        ],
    }

    return output


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--workspace", required=True, type=Path,
                        help="Workspace directory (must exist)")
    parser.add_argument("--rpc-url", default=None,
                        help="Override RPC URL for all assets")
    parser.add_argument("--chain-id", type=int, default=None,
                        help="Override chain ID for default RPC selection")
    parser.add_argument("--block", default="latest",
                        help="Block number or 'latest' (default: latest)")
    parser.add_argument("--categories", nargs="+", default=None,
                        choices=list(CATEGORY_CHECKS.keys()),
                        help="Restrict to these check categories")
    parser.add_argument("--out", type=Path, default=None,
                        help="Output path (default: <ws>/.auditooor/state_config_diff.json)")
    parser.add_argument("--json", action="store_true", dest="json_stdout",
                        help="Emit JSON to stdout (also writes file unless --no-file)")
    parser.add_argument("--no-file", action="store_true",
                        help="Do not write output file (stdout only)")
    parser.add_argument("--diff-only", action="store_true",
                        help="Only print divergences, not full output")
    args = parser.parse_args(argv)

    workspace = args.workspace.expanduser().resolve()
    if not workspace.is_dir():
        print(f"[state-config-diff] ERR workspace not found: {workspace}", file=sys.stderr)
        return 2

    result = build_state_config_diff(
        workspace=workspace,
        rpc_url=args.rpc_url,
        chain_id=args.chain_id,
        block=args.block,
        categories_override=args.categories,
    )

    if args.diff_only:
        seeds = result.get("exploit_queue_seeds", [])
        benign = result.get("benign_controls_summary", [])
        out_obj = {
            "schema": SCHEMA,
            "mode": result["mode"],
            "exploit_queue_seeds": seeds,
            "benign_controls_summary": benign,
        }
        print(json.dumps(out_obj, indent=2))
        return 0

    json_text = json.dumps(result, indent=2)

    if args.json_stdout:
        print(json_text)

    if not args.no_file:
        out_path = args.out or (workspace / ".auditooor" / "state_config_diff.json")
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json_text, encoding="utf-8")
        if not args.json_stdout:
            print(f"[state-config-diff] written to {out_path}")
            print(f"[state-config-diff] mode={result['mode']} assets={result['assets_total']} "
                  f"exploit_queue_seeds={result['exploit_queue_seeds_count'] if 'exploit_queue_seeds_count' in result else len(result.get('exploit_queue_seeds', []))} "
                  f"benign_controls={result['benign_controls']}")
    elif not args.json_stdout:
        print(json_text)

    return 0


if __name__ == "__main__":
    sys.exit(main())
