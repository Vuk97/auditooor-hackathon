#!/usr/bin/env python3
"""HACKERMAN_V3 Lane D5 - Cross-protocol dependency graph for chains.

Build a static dependency graph over deployed addresses, external calls,
oracles, routers, bridges, governance executors, keepers, tokens, packages,
and adapters so workers can find prerequisite-state chains.

Each node is typed and confidence-labelled. Each edge captures a directional
dependency (caller -> callee, user -> oracle, etc.). The ``prerequisite_state_paths``
section enumerates candidate chains where component A's external dependency
creates the exploitable prerequisite state component B's exploit needs.

All prerequisite_state_path entries are labelled ``candidate_unvalidated``.
This tool does NOT promote chain rows; that is chain-composition-harness.py's job.

Usage
-----
    python3 tools/cross-protocol-dependency-graph.py --workspace ~/audits/myproject

    # JSON output (machine-readable)
    python3 tools/cross-protocol-dependency-graph.py --workspace ~/audits/myproject --json

    # Limit scan to 200 files (for tests / fast feedback)
    python3 tools/cross-protocol-dependency-graph.py --workspace ~/audits/myproject --limit 200

Exit code is always 0 (advisory tool). Use --strict to exit 1 when 0 nodes found.

Schema
------
    auditooor.cross_protocol_dependency_graph.v1
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "auditooor.cross_protocol_dependency_graph.v1"

# ---------------------------------------------------------------------------
# Node types (matches D5 spec verbatim)
# ---------------------------------------------------------------------------
NODE_TYPES = {
    "deployed_address",
    "external_call",
    "oracle",
    "router",
    "bridge",
    "governance_executor",
    "keeper",
    "token",
    "package",
    "adapter",
}

# ---------------------------------------------------------------------------
# Directories to skip (vendored / test / generated)
# ---------------------------------------------------------------------------
SKIP_DIR_PARTS: frozenset[str] = frozenset({
    "node_modules", "out", "cache", "build", "broadcast", ".git",
    ".auditooor", "forge-artifacts", "artifacts", "typechain",
    "typechain-types", "dist", "coverage", "external-prior-audits",
    "_archive", "_archived", "deps", "vendored", "lib",
    "test", "tests", "spec", "specs", "mocks", "mock",
    "fixtures", "fixture", "test_fixtures", "test-fixtures",
    "harness", "harnesses", "chimera_harnesses", "recon", "scanners",
    "_slither-tmp", "poc-tests", "poc_tests", "poc", "scanner-out",
    "spells", "spell",
})

# ---------------------------------------------------------------------------
# Source file extensions by language
# ---------------------------------------------------------------------------
SOLIDITY_EXT = {".sol"}
RUST_EXT = {".rs"}
GO_EXT = {".go"}
COSMOS_EXT = {".go"}  # Cosmos uses Go; handled together
ALL_EXT = SOLIDITY_EXT | RUST_EXT | GO_EXT

# ---------------------------------------------------------------------------
# Extraction regexes - Solidity
# ---------------------------------------------------------------------------

# address public/private oracleName; address immutable router;
SOL_NAMED_ADDR_RE = re.compile(
    r"address\s+(?:public\s+|private\s+|internal\s+|immutable\s+|constant\s+)*"
    r"(\w+)\s*(?:=|;)",
    re.IGNORECASE,
)

# IOracle(addr) or IOracleV2(addr) interface casts
SOL_IFACE_CAST_RE = re.compile(
    r"\b(I[A-Z][A-Za-z0-9]*)\s*\(",
)

# Low-level calls: addr.call(, addr.delegatecall(, addr.staticcall(
SOL_LOW_LEVEL_CALL_RE = re.compile(
    r"(\w+)\.(call|delegatecall|staticcall)\s*[({]",
    re.IGNORECASE,
)

# Import statements - OpenZeppelin, Uniswap, etc.
SOL_IMPORT_RE = re.compile(
    r'import\s+(?:\{[^}]+\}\s+from\s+)?["\']([^"\']+)["\']',
)

# Hardcoded addresses (0x...)
SOL_ADDR_LITERAL_RE = re.compile(
    r"address\s*\(\s*(0x[0-9a-fA-F]{40})\s*\)",
)

# Named role patterns for governance / keeper detection
SOL_GOVERNANCE_RE = re.compile(
    r"\b(governor|executor|timelock|multisig|gnosis|safe|guardian|proposer|"
    r"councilmember|votingescrow|votingpower|governance)\b",
    re.IGNORECASE,
)
SOL_KEEPER_RE = re.compile(
    r"\b(keeper|harvester|rebalancer|liquidator|bot|upkeep|chainlinkkeeper|"
    r"automationcompatible)\b",
    re.IGNORECASE,
)
SOL_ORACLE_RE = re.compile(
    r"\b(oracle|pricefeed|aggregator|twap|chainlink|pyth|band|flux|uniswapv3twap|"
    r"ioracle|iaggregatorv3|ipricefeed|priceprovider|spotprice|getcurrentprice)\b",
    re.IGNORECASE,
)
SOL_ROUTER_RE = re.compile(
    r"\b(router|swaprouter|uniswaprouter|curverouter|balancerrouter|"
    r"irouter|iswaprouter|iuniswapv[23]router|routerv[23])\b",
    re.IGNORECASE,
)
SOL_BRIDGE_RE = re.compile(
    r"\b(bridge|messenger|portal|gateway|l1bridge|l2bridge|hop|stargate|"
    r"layerzero|wormhole|axelar|ibridge|imessenger)\b",
    re.IGNORECASE,
)
SOL_TOKEN_RE = re.compile(
    r"\b(ierc20|erc20|token|usdc|usdt|dai|weth|wbtc|atoken|ctoken|steth|"
    r"stablecoin|collateral)\b",
    re.IGNORECASE,
)
SOL_ADAPTER_RE = re.compile(
    r"\b(adapter|wrapper|plugin|connector|strategy|vault|iadapter|"
    r"basestrategy|astrategy)\b",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Extraction regexes - Rust
# ---------------------------------------------------------------------------

RUST_EXTERN_CALL_RE = re.compile(
    r"(?:extern\s+crate|use\s+)([a-z_][a-z0-9_]*)::",
)
RUST_TRAIT_IMPL_RE = re.compile(
    r"impl\s+(?:<[^>]*>\s+)?([A-Z][A-Za-z0-9]*(?:Oracle|Router|Bridge|Keeper|Token|Adapter))\b",
)
RUST_ADDR_RE = re.compile(
    r"""(?:address|pubkey|addr)\s*[:=]\s*["']?([\w:]{32,})""",
    re.IGNORECASE,
)
RUST_DEP_RE = re.compile(
    r"([a-z_][a-z0-9_-]*)\s*=\s*\{[^}]*version\s*=",
)

# ---------------------------------------------------------------------------
# Extraction regexes - Go / Cosmos
# ---------------------------------------------------------------------------

GO_IMPORT_RE = re.compile(
    r'(?:^|\n)\s+"([^"]+)"',
)
GO_IFACE_FIELD_RE = re.compile(
    r"(\w+)\s+([\w.]+(?:Oracle|Router|Bridge|Keeper|Token|Adapter|Executor))\b",
    re.IGNORECASE,
)
GO_COSMOS_KEEPER_RE = re.compile(
    r"(\w+Keeper)\b",
)
GO_GRPC_CALL_RE = re.compile(
    r"(\w+Client)\s*\.\s*(\w+)\s*\(",
)

# ---------------------------------------------------------------------------
# Name -> node_type classifier
# ---------------------------------------------------------------------------

def _classify_name(name: str) -> str:
    """Heuristically classify a name into one of the NODE_TYPES."""
    lower = name.lower()
    if SOL_ORACLE_RE.search(lower):
        return "oracle"
    if SOL_ROUTER_RE.search(lower):
        return "router"
    if SOL_BRIDGE_RE.search(lower):
        return "bridge"
    if SOL_GOVERNANCE_RE.search(lower):
        return "governance_executor"
    if SOL_KEEPER_RE.search(lower):
        return "keeper"
    if SOL_TOKEN_RE.search(lower):
        return "token"
    if SOL_ADAPTER_RE.search(lower):
        return "adapter"
    if re.search(r"^0x[0-9a-fA-F]{40}$", name):
        return "deployed_address"
    return "external_call"


def _node_id(node_type: str, name: str, source_file: str) -> str:
    raw = f"{node_type}:{name}:{source_file}"
    digest = hashlib.sha256(raw.encode()).hexdigest()[:10]
    slug = re.sub(r"[^a-z0-9]+", "_", name.lower())[:32].strip("_")
    return f"{node_type[:6]}_{slug}_{digest}"


def _conf(level: str) -> str:
    return level  # "high" | "medium" | "low"


# ---------------------------------------------------------------------------
# Per-language extractors
# ---------------------------------------------------------------------------

class _Extractor:
    """Accumulates nodes and edges from a single source file."""

    def __init__(self, rel_path: str) -> None:
        self.rel_path = rel_path
        self.nodes: dict[str, dict[str, Any]] = {}  # id -> node
        self.edges: list[dict[str, Any]] = []

    def _add_node(
        self,
        name: str,
        node_type: str,
        confidence: str = "medium",
        extra: dict[str, Any] | None = None,
    ) -> str:
        nid = _node_id(node_type, name, self.rel_path)
        if nid not in self.nodes:
            row: dict[str, Any] = {
                "id": nid,
                "type": node_type,
                "name": name,
                "confidence": confidence,
                "source_file": self.rel_path,
            }
            if extra:
                row.update(extra)
            self.nodes[nid] = row
        return nid

    def _add_edge(
        self,
        from_id: str,
        to_id: str,
        relation: str,
        confidence: str = "medium",
    ) -> None:
        self.edges.append({
            "from": from_id,
            "to": to_id,
            "relation": relation,
            "confidence": confidence,
            "source_file": self.rel_path,
        })

    def extract_solidity(self, text: str) -> None:
        # Named address declarations -> typed nodes
        for m in SOL_NAMED_ADDR_RE.finditer(text):
            name = m.group(1)
            if name.lower() in {"this", "msg", "tx", "block", "address", "_"}:
                continue
            ntype = _classify_name(name)
            self._add_node(name, ntype, confidence="medium")

        # Interface casts (IOracle(...), IRouter(...))
        for m in SOL_IFACE_CAST_RE.finditer(text):
            iface = m.group(1)
            ntype = _classify_name(iface)
            self._add_node(iface, ntype, confidence="medium")

        # Low-level calls: variable.call(
        for m in SOL_LOW_LEVEL_CALL_RE.finditer(text):
            caller_name = m.group(1)
            if caller_name.lower() in {"this", "msg", "tx", "super", "address"}:
                continue
            self._add_node(caller_name, "external_call", confidence="low")

        # Hardcoded deployed addresses
        for m in SOL_ADDR_LITERAL_RE.finditer(text):
            addr = m.group(1)
            self._add_node(addr, "deployed_address", confidence="high",
                           extra={"literal": True})

        # Import paths -> package nodes
        for m in SOL_IMPORT_RE.finditer(text):
            pkg = m.group(1)
            # Normalize to package root (first 2 path segments)
            parts = [p for p in pkg.split("/") if p and p not in {".", ".."}]
            pkg_name = "/".join(parts[:2]) if len(parts) >= 2 else pkg
            if pkg_name:
                self._add_node(pkg_name, "package", confidence="high")

    def extract_rust(self, text: str) -> None:
        for m in RUST_EXTERN_CALL_RE.finditer(text):
            crate_name = m.group(1)
            if crate_name in {"std", "core", "alloc", "super", "crate", "self"}:
                continue
            ntype = _classify_name(crate_name)
            self._add_node(crate_name, ntype, confidence="medium")

        for m in RUST_TRAIT_IMPL_RE.finditer(text):
            trait_name = m.group(1)
            ntype = _classify_name(trait_name)
            self._add_node(trait_name, ntype, confidence="medium")

        for m in RUST_ADDR_RE.finditer(text):
            addr = m.group(1)
            self._add_node(addr, "deployed_address", confidence="medium")

        # Cargo.toml-style dep: name = { version = ... }
        for m in RUST_DEP_RE.finditer(text):
            dep = m.group(1)
            ntype = _classify_name(dep)
            self._add_node(dep, ntype, confidence="high")

    def extract_go(self, text: str) -> None:
        for m in GO_IMPORT_RE.finditer(text):
            imp = m.group(1)
            if imp.startswith("//") or not imp:
                continue
            parts = [p for p in imp.split("/") if p]
            pkg_name = "/".join(parts[:3]) if len(parts) >= 3 else imp
            ntype = _classify_name(pkg_name.split("/")[-1])
            self._add_node(pkg_name, ntype, confidence="medium")

        for m in GO_COSMOS_KEEPER_RE.finditer(text):
            keeper = m.group(1)
            if keeper.lower() in {"keeper", "storekey"}:
                continue
            self._add_node(keeper, "keeper", confidence="medium")

        for m in GO_GRPC_CALL_RE.finditer(text):
            client = m.group(1)
            method = m.group(2)
            cid = self._add_node(client, "external_call", confidence="medium")
            # Also mint a node for the method as an external_call edge target
            mid = self._add_node(f"{client}.{method}", "external_call", confidence="low")
            self._add_edge(cid, mid, "grpc_call", confidence="low")

    def extract_edges_from_nodes(self) -> None:
        """Second pass: infer cross-node edges from name proximity."""
        node_ids = list(self.nodes.keys())
        # For Solidity: if we have both a named address and an interface cast
        # with the same root word, link them.
        named: dict[str, str] = {}  # lower_name -> node_id
        ifaces: dict[str, str] = {}

        for nid, node in self.nodes.items():
            name_lower = node["name"].lower()
            if node["type"] == "deployed_address":
                named[name_lower] = nid
            elif node["type"] in {"oracle", "router", "bridge", "governance_executor",
                                   "keeper", "token", "adapter", "external_call"}:
                # Strip leading "I" for interface names
                stripped = re.sub(r"^i([a-z])", r"\1", name_lower)
                ifaces[stripped] = nid
                ifaces[name_lower] = nid

        # Link named addresses to interface nodes when names overlap
        for name_lower, nid_addr in named.items():
            for iface_key, nid_iface in ifaces.items():
                if nid_addr == nid_iface:
                    continue
                if name_lower in iface_key or iface_key in name_lower:
                    # Only add edge once per pair
                    pair_edge = {
                        "from": nid_addr,
                        "to": nid_iface,
                        "relation": "uses",
                        "confidence": "low",
                        "source_file": self.rel_path,
                    }
                    if pair_edge not in self.edges:
                        self.edges.append(pair_edge)


def _extract_file(path: Path, repo_root: Path) -> _Extractor:
    rel_path = str(path.relative_to(repo_root)) if path.is_relative_to(repo_root) else str(path)
    extractor = _Extractor(rel_path)
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return extractor

    suffix = path.suffix.lower()
    if suffix in SOLIDITY_EXT:
        extractor.extract_solidity(text)
    elif suffix in RUST_EXT:
        extractor.extract_rust(text)
    elif suffix in GO_EXT:
        extractor.extract_go(text)

    extractor.extract_edges_from_nodes()
    return extractor


# ---------------------------------------------------------------------------
# Prerequisite-state path analysis
# ---------------------------------------------------------------------------

# These mappings capture: if a component of type A depends on type B, what
# is the potential exploitable prerequisite-state relationship?
PREREQ_RELATION_MAP: list[tuple[str, str, str]] = [
    # (dependency_node_type, dependent_node_type, chain_description)
    ("oracle",             "external_call",   "oracle_price_feeds_external_call"),
    ("oracle",             "adapter",         "oracle_price_used_by_adapter"),
    ("oracle",             "token",           "oracle_price_controls_token_valuation"),
    ("router",             "token",           "router_swap_path_controls_token_flow"),
    ("router",             "adapter",         "router_routes_through_adapter"),
    ("bridge",             "token",           "bridge_lock_creates_token_prerequisite"),
    ("bridge",             "deployed_address","bridge_calls_deployed_contract"),
    ("governance_executor","adapter",         "governance_sets_adapter_param"),
    ("governance_executor","token",           "governance_controls_token_behavior"),
    ("governance_executor","oracle",          "governance_updates_oracle_config"),
    ("keeper",             "external_call",   "keeper_triggers_external_call"),
    ("keeper",             "token",           "keeper_harvests_token"),
    ("token",              "deployed_address","token_transfers_to_deployed_address"),
    ("adapter",            "external_call",   "adapter_delegates_to_external_call"),
    ("package",            "external_call",   "imported_package_introduces_external_call"),
]


def _build_prereq_paths(
    all_nodes: dict[str, dict[str, Any]],
    all_edges: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Find pairs of nodes that match PREREQ_RELATION_MAP and emit candidate paths."""
    paths: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    # Index nodes by type
    by_type: dict[str, list[dict[str, Any]]] = {}
    for node in all_nodes.values():
        by_type.setdefault(node["type"], []).append(node)

    # Check direct edges first
    from_ids: dict[str, dict[str, Any]] = {n["id"]: n for n in all_nodes.values()}
    edge_pairs: set[tuple[str, str]] = {(e["from"], e["to"]) for e in all_edges}

    for dep_type, dependent_type, chain_desc in PREREQ_RELATION_MAP:
        dep_nodes = by_type.get(dep_type, [])
        dependent_nodes = by_type.get(dependent_type, [])
        if not dep_nodes or not dependent_nodes:
            continue

        for dep_node in dep_nodes:
            for dependent_node in dependent_nodes:
                if dep_node["id"] == dependent_node["id"]:
                    continue
                pair_key = (dep_node["id"], dependent_node["id"], chain_desc)
                if pair_key in seen:
                    continue
                seen.add(pair_key)

                # Check if there is a direct edge or infer from same-file co-occurrence
                has_direct_edge = (dep_node["id"], dependent_node["id"]) in edge_pairs
                same_file = dep_node.get("source_file") == dependent_node.get("source_file")

                if has_direct_edge or same_file:
                    confidence = "medium" if has_direct_edge else "low"
                    path_id_raw = f"{dep_node['id']}:{dependent_node['id']}:{chain_desc}"
                    path_id = "path_" + hashlib.sha256(path_id_raw.encode()).hexdigest()[:10]
                    paths.append({
                        "path_id": path_id,
                        "status": "candidate_unvalidated",
                        "chain_description": chain_desc,
                        "prerequisite_node": {
                            "id": dep_node["id"],
                            "type": dep_node["type"],
                            "name": dep_node["name"],
                            "source_file": dep_node.get("source_file"),
                        },
                        "dependent_node": {
                            "id": dependent_node["id"],
                            "type": dependent_node["type"],
                            "name": dependent_node["name"],
                            "source_file": dependent_node.get("source_file"),
                        },
                        "has_direct_edge": has_direct_edge,
                        "same_file_cooccurrence": same_file,
                        "confidence": confidence,
                        "advisory": (
                            "External dependency creates prerequisite state: "
                            f"{dep_node['name']} ({dep_type}) -> "
                            f"{dependent_node['name']} ({dependent_type}). "
                            "Build PoC evidence before promoting."
                        ),
                    })

    # Sort by confidence (medium first) then path_id for determinism
    paths.sort(key=lambda p: (0 if p["confidence"] == "medium" else 1, p["path_id"]))
    return paths


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

def _should_skip(path: Path) -> bool:
    for part in path.parts:
        if part.lower() in SKIP_DIR_PARTS:
            return True
    return False


def _find_source_files(workspace: Path, limit: int) -> list[Path]:
    src_roots: list[Path] = []

    # Prefer src/ sub-directory if it exists
    for candidate in (workspace / "src", workspace / "contracts", workspace):
        if candidate.is_dir():
            src_roots.append(candidate)
            break

    found: list[Path] = []
    for root in src_roots:
        for path in sorted(root.rglob("*")):
            if len(found) >= limit:
                break
            if not path.is_file():
                continue
            if path.suffix.lower() not in ALL_EXT:
                continue
            if _should_skip(path):
                continue
            found.append(path)
        if len(found) >= limit:
            break

    return found[:limit]


# ---------------------------------------------------------------------------
# Main graph builder
# ---------------------------------------------------------------------------

def build_graph(args: argparse.Namespace) -> dict[str, Any]:
    workspace = Path(args.workspace).expanduser().resolve()
    limit: int = args.limit

    scanned_files: list[str] = []
    missing: list[str] = []
    all_nodes: dict[str, dict[str, Any]] = {}
    all_edges: list[dict[str, Any]] = []

    if not workspace.is_dir():
        missing.append(f"workspace not found: {workspace}")
    else:
        source_files = _find_source_files(workspace, limit)
        if not source_files:
            missing.append(
                f"no source files (.sol/.rs/.go) found under {workspace} "
                "(vendored/test dirs excluded)"
            )
        for fpath in source_files:
            rel = (
                str(fpath.relative_to(workspace))
                if fpath.is_relative_to(workspace)
                else str(fpath)
            )
            scanned_files.append(rel)
            extractor = _extract_file(fpath, workspace)
            all_nodes.update(extractor.nodes)
            all_edges.extend(extractor.edges)

    # Deduplicate edges (same from/to/relation)
    seen_edges: set[tuple[str, str, str]] = set()
    deduped_edges: list[dict[str, Any]] = []
    for edge in all_edges:
        key = (edge["from"], edge["to"], edge["relation"])
        if key not in seen_edges:
            seen_edges.add(key)
            deduped_edges.append(edge)

    prereq_paths = _build_prereq_paths(all_nodes, deduped_edges)

    # Node-type summary
    type_counts: dict[str, int] = {}
    for node in all_nodes.values():
        type_counts[node["type"]] = type_counts.get(node["type"], 0) + 1

    return {
        "schema_version": SCHEMA_VERSION,
        "workspace": str(workspace),
        "scan_summary": {
            "files_scanned": len(scanned_files),
            "files_limit": limit,
            "node_count": len(all_nodes),
            "edge_count": len(deduped_edges),
            "prereq_path_count": len(prereq_paths),
            "node_type_counts": type_counts,
        },
        "scanned_files": scanned_files,
        "missing": missing,
        "nodes": list(all_nodes.values()),
        "edges": deduped_edges,
        "prerequisite_state_paths": prereq_paths,
    }


# ---------------------------------------------------------------------------
# Human-readable output
# ---------------------------------------------------------------------------

def _human_output(graph: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append(f"Cross-Protocol Dependency Graph  [{SCHEMA_VERSION}]")
    lines.append(f"Workspace : {graph['workspace']}")
    ss = graph["scan_summary"]
    lines.append(
        f"Scanned   : {ss['files_scanned']} files | "
        f"{ss['node_count']} nodes | "
        f"{ss['edge_count']} edges | "
        f"{ss['prereq_path_count']} prerequisite_state_paths"
    )
    if graph["missing"]:
        for m in graph["missing"]:
            lines.append(f"[MISSING] {m}")

    if ss["node_type_counts"]:
        lines.append("\nNode type breakdown:")
        for ntype, count in sorted(ss["node_type_counts"].items()):
            lines.append(f"  {ntype:<25} {count}")

    if graph["prerequisite_state_paths"]:
        lines.append(
            f"\nPrerequisite-state chain candidates ({len(graph['prerequisite_state_paths'])} total, all candidate_unvalidated):"
        )
        for path in graph["prerequisite_state_paths"][:20]:  # cap display
            lines.append(
                f"  [{path['confidence']:6}] {path['prerequisite_node']['name']} "
                f"({path['prerequisite_node']['type']}) -> "
                f"{path['dependent_node']['name']} "
                f"({path['dependent_node']['type']})  //  {path['chain_description']}"
            )
        if len(graph["prerequisite_state_paths"]) > 20:
            lines.append(f"  ... and {len(graph['prerequisite_state_paths']) - 20} more (use --json for full list)")
    else:
        lines.append("\nNo prerequisite-state chain candidates found (insufficient cross-type co-occurrence).")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--workspace", required=True, help="Workspace root directory")
    p.add_argument("--json", dest="json_mode", action="store_true",
                   help="Emit JSON output (default: human-readable)")
    p.add_argument("--limit", type=int, default=2000,
                   help="Max source files to scan (default: 2000)")
    p.add_argument("--strict", action="store_true",
                   help="Exit 1 when 0 nodes are found")
    p.add_argument("--out", default=None,
                   help="Write output to file instead of stdout")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    graph = build_graph(args)

    if args.json_mode:
        output = json.dumps(graph, indent=2)
    else:
        output = _human_output(graph)

    if args.out:
        Path(args.out).write_text(output + "\n", encoding="utf-8")
    else:
        print(output)

    if args.strict and graph["scan_summary"]["node_count"] == 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
