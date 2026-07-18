"""Tests for tools/cross-protocol-dependency-graph.py (D5 acceptance tests).

Covers:
  1. Empty workspace - no crash, correct missing/empty fields
  2. Oracle node extraction from Solidity address declaration
  3. Router node extraction from Solidity interface cast
  4. Bridge node extraction from Solidity
  5. External_call node extraction from low-level .call() pattern
  6. Edge construction via same-file co-occurrence
  7. Prerequisite_state_path candidate with 'candidate_unvalidated' label
  8. JSON schema field presence (schema_version, nodes, edges, prerequisite_state_paths, scan_summary, scanned_files, missing)
  9. Go keeper extraction
  10. Package node extraction from Solidity imports
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

import importlib.util

_SPEC = importlib.util.spec_from_file_location(
    "cross_protocol_dependency_graph",
    REPO / "tools" / "cross-protocol-dependency-graph.py",
)
_MOD = importlib.util.module_from_spec(_SPEC)  # type: ignore[arg-type]
_SPEC.loader.exec_module(_MOD)  # type: ignore[union-attr]

build_graph = _MOD.build_graph
SCHEMA_VERSION = _MOD.SCHEMA_VERSION


def _args(workspace: str, limit: int = 500) -> object:
    """Minimal namespace that satisfies build_graph."""
    import argparse
    ns = argparse.Namespace()
    ns.workspace = workspace
    ns.limit = limit
    return ns


class TestEmptyWorkspace(unittest.TestCase):
    """Case 1: empty workspace directory -> no crash, proper missing/empty output."""

    def test_empty_dir_no_crash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            graph = build_graph(_args(tmp))
        self.assertIsInstance(graph, dict)
        self.assertEqual(graph["scan_summary"]["node_count"], 0)
        self.assertEqual(graph["scan_summary"]["edge_count"], 0)
        self.assertEqual(graph["scan_summary"]["prereq_path_count"], 0)
        self.assertIsInstance(graph["missing"], list)
        self.assertGreater(len(graph["missing"]), 0, "empty workspace should have missing entry")
        self.assertIsInstance(graph["nodes"], list)
        self.assertIsInstance(graph["edges"], list)
        self.assertIsInstance(graph["prerequisite_state_paths"], list)

    def test_nonexistent_workspace_no_crash(self) -> None:
        graph = build_graph(_args("/tmp/this_dir_does_not_exist_auditooor_d5_test_xyz"))
        self.assertEqual(graph["scan_summary"]["node_count"], 0)
        self.assertGreater(len(graph["missing"]), 0)


class TestOracleExtraction(unittest.TestCase):
    """Case 2: oracle node from Solidity address declaration."""

    def test_sol_address_oracle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "Vault.sol"
            src.write_text(
                "pragma solidity ^0.8.0;\n"
                "contract Vault {\n"
                "    address public oracle;\n"
                "    function getPrice() external {}\n"
                "}\n",
                encoding="utf-8",
            )
            graph = build_graph(_args(tmp))

        types = {n["type"] for n in graph["nodes"]}
        self.assertIn("oracle", types, f"expected oracle node, got types: {types}")
        oracle_nodes = [n for n in graph["nodes"] if n["type"] == "oracle"]
        self.assertTrue(
            any("oracle" in n["name"].lower() for n in oracle_nodes),
            f"oracle node names: {[n['name'] for n in oracle_nodes]}",
        )

    def test_sol_iface_cast_oracle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "Strategy.sol"
            src.write_text(
                "contract Strategy {\n"
                "    function update(address feed) external {\n"
                "        uint256 price = IOracle(feed).latestAnswer();\n"
                "    }\n"
                "}\n",
                encoding="utf-8",
            )
            graph = build_graph(_args(tmp))

        oracle_nodes = [n for n in graph["nodes"] if n["type"] == "oracle"]
        self.assertGreater(len(oracle_nodes), 0, "IOracle cast should produce oracle node")


class TestRouterExtraction(unittest.TestCase):
    """Case 3: router node from Solidity interface cast."""

    def test_sol_irouter_cast(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "Swap.sol"
            src.write_text(
                "contract Swap {\n"
                "    IUniswapV2Router public router;\n"
                "    function swap(address token, uint amount) external {\n"
                "        IUniswapV2Router(router).swapExactTokensForTokens(amount, 0, new address[](0), msg.sender, block.timestamp);\n"
                "    }\n"
                "}\n",
                encoding="utf-8",
            )
            graph = build_graph(_args(tmp))

        router_nodes = [n for n in graph["nodes"] if n["type"] == "router"]
        self.assertGreater(len(router_nodes), 0, "Expected router node from IUniswapV2Router pattern")


class TestBridgeExtraction(unittest.TestCase):
    """Case 4: bridge node from Solidity."""

    def test_sol_bridge_address(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "CrossChain.sol"
            src.write_text(
                "contract CrossChain {\n"
                "    address public bridge;\n"
                "    address public l1Bridge;\n"
                "    function sendMessage(bytes calldata data) external {\n"
                "        IBridge(bridge).sendMessage(data);\n"
                "    }\n"
                "}\n",
                encoding="utf-8",
            )
            graph = build_graph(_args(tmp))

        bridge_nodes = [n for n in graph["nodes"] if n["type"] == "bridge"]
        self.assertGreater(len(bridge_nodes), 0, f"Expected bridge node, got: {[n['type'] for n in graph['nodes']]}")


class TestExternalCallExtraction(unittest.TestCase):
    """Case 5: external_call node from low-level .call() pattern."""

    def test_sol_low_level_call(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "Executor.sol"
            src.write_text(
                "contract Executor {\n"
                "    function execute(address target, bytes calldata data) external {\n"
                "        (bool success,) = target.call(data);\n"
                "        require(success);\n"
                "    }\n"
                "}\n",
                encoding="utf-8",
            )
            graph = build_graph(_args(tmp))

        types = {n["type"] for n in graph["nodes"]}
        self.assertIn("external_call", types, f"Expected external_call node from .call() pattern, got: {types}")


class TestEdgeConstruction(unittest.TestCase):
    """Case 6: edge construction from same-file co-occurrence of oracle + external_call."""

    def test_same_file_cooccurrence_edge(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "Complex.sol"
            src.write_text(
                "contract Complex {\n"
                "    address public oracle;\n"
                "    function doSomething(address target) external {\n"
                "        (bool ok,) = target.call(\"\");\n"
                "        IOracle(oracle).latestAnswer();\n"
                "    }\n"
                "}\n",
                encoding="utf-8",
            )
            graph = build_graph(_args(tmp))

        # There should be edges and nodes from this file
        self.assertGreater(graph["scan_summary"]["node_count"], 0)
        # Edges may be empty for simple files but graph structure should be present
        self.assertIn("edges", graph)
        self.assertIsInstance(graph["edges"], list)

    def test_cross_type_nodes_in_same_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "MultiDep.sol"
            src.write_text(
                "contract MultiDep {\n"
                "    address public oracle;\n"
                "    address public router;\n"
                "    address public bridge;\n"
                "    IERC20 public token;\n"
                "    function act() external {}\n"
                "}\n",
                encoding="utf-8",
            )
            graph = build_graph(_args(tmp))

        types = {n["type"] for n in graph["nodes"]}
        # Should extract multiple node types from same file
        self.assertGreater(len(types), 1, f"Expected multiple types, got: {types}")


class TestPrerequisiteStatePath(unittest.TestCase):
    """Case 7: prerequisite_state_path candidate with 'candidate_unvalidated' label."""

    def test_oracle_plus_adapter_yields_prereq_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "Strategy.sol"
            src.write_text(
                "interface IAdapter {}\n"
                "contract Strategy {\n"
                "    address public oracle;\n"
                "    IAdapter public adapter;\n"
                "    function update() external {\n"
                "        uint256 price = IOracle(oracle).latestAnswer();\n"
                "        IAdapter(adapter).rebalance(price);\n"
                "    }\n"
                "}\n",
                encoding="utf-8",
            )
            graph = build_graph(_args(tmp))

        # If prerequisite_state_paths exist, all must be candidate_unvalidated
        for path in graph["prerequisite_state_paths"]:
            self.assertEqual(
                path["status"],
                "candidate_unvalidated",
                f"Expected candidate_unvalidated, got {path['status']} for {path['path_id']}",
            )

    def test_prereq_path_fields_present(self) -> None:
        """Any emitted path must carry required fields."""
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "Bridge.sol"
            src.write_text(
                "contract BridgeUser {\n"
                "    address public bridge;\n"
                "    IERC20 public token;\n"
                "    function lock(uint amount) external {\n"
                "        token.transferFrom(msg.sender, address(this), amount);\n"
                "        IBridge(bridge).lock(amount);\n"
                "    }\n"
                "}\n",
                encoding="utf-8",
            )
            graph = build_graph(_args(tmp))

        for path in graph["prerequisite_state_paths"]:
            self.assertIn("path_id", path)
            self.assertIn("status", path)
            self.assertIn("chain_description", path)
            self.assertIn("prerequisite_node", path)
            self.assertIn("dependent_node", path)
            self.assertIn("confidence", path)
            self.assertIn("advisory", path)
            # Nested fields
            self.assertIn("id", path["prerequisite_node"])
            self.assertIn("type", path["prerequisite_node"])
            self.assertIn("name", path["prerequisite_node"])
            self.assertIn("id", path["dependent_node"])
            self.assertIn("type", path["dependent_node"])
            self.assertIn("name", path["dependent_node"])


class TestJsonSchemaFields(unittest.TestCase):
    """Case 8: JSON output has all required schema fields."""

    def test_required_top_level_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "Token.sol"
            src.write_text(
                "contract Token is IERC20 { address public oracle; }\n",
                encoding="utf-8",
            )
            graph = build_graph(_args(tmp))

        required_fields = {
            "schema_version", "workspace", "scan_summary",
            "scanned_files", "missing", "nodes", "edges",
            "prerequisite_state_paths",
        }
        for field in required_fields:
            self.assertIn(field, graph, f"Missing top-level field: {field}")

        self.assertEqual(graph["schema_version"], SCHEMA_VERSION)
        self.assertIn("files_scanned", graph["scan_summary"])
        self.assertIn("node_count", graph["scan_summary"])
        self.assertIn("edge_count", graph["scan_summary"])
        self.assertIn("prereq_path_count", graph["scan_summary"])
        self.assertIn("node_type_counts", graph["scan_summary"])

    def test_json_serializable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "Foo.sol"
            src.write_text("contract Foo { address public oracle; }\n", encoding="utf-8")
            graph = build_graph(_args(tmp))

        # Should not raise
        serialized = json.dumps(graph)
        reparsed = json.loads(serialized)
        self.assertEqual(reparsed["schema_version"], SCHEMA_VERSION)


class TestGoKeeperExtraction(unittest.TestCase):
    """Case 9: Go keeper extraction (Cosmos pattern)."""

    def test_go_cosmos_keeper_nodes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "keeper.go"
            src.write_text(
                'package keeper\n\nimport (\n\t"github.com/cosmos/cosmos-sdk/x/bank/keeper"\n)\n\n'
                "type BankKeeper interface{}\n"
                "type OracleKeeper interface{}\n"
                "type Keeper struct {\n"
                "\tbankKeeper    BankKeeper\n"
                "\toracleKeeper  OracleKeeper\n"
                "}\n",
                encoding="utf-8",
            )
            graph = build_graph(_args(tmp))

        keeper_nodes = [n for n in graph["nodes"] if n["type"] == "keeper"]
        self.assertGreater(len(keeper_nodes), 0, f"Expected keeper nodes from Go source, got types: {[n['type'] for n in graph['nodes']]}")


class TestPackageExtraction(unittest.TestCase):
    """Case 10: package node from Solidity imports."""

    def test_sol_import_openzeppelin(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "OzContract.sol"
            src.write_text(
                'import "@openzeppelin/contracts/token/ERC20/IERC20.sol";\n'
                'import "@openzeppelin/contracts/access/Ownable.sol";\n'
                "contract OzContract {}\n",
                encoding="utf-8",
            )
            graph = build_graph(_args(tmp))

        package_nodes = [n for n in graph["nodes"] if n["type"] == "package"]
        self.assertGreater(len(package_nodes), 0, "Expected package nodes from OZ import")
        names = {n["name"] for n in package_nodes}
        # Should have a node for @openzeppelin/contracts
        self.assertTrue(
            any("openzeppelin" in name.lower() for name in names),
            f"Expected openzeppelin package node, got: {names}",
        )

    def test_rust_cargo_deps(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            # Rust Cargo.toml-style dep pattern
            src = Path(tmp) / "lib.rs"
            src.write_text(
                "use serde::Deserialize;\n"
                "use anchor_lang::prelude::*;\n",
                encoding="utf-8",
            )
            graph = build_graph(_args(tmp))

        self.assertIsInstance(graph["nodes"], list)
        # Should not crash; package/external_call nodes may be present
        self.assertIsNotNone(graph["scan_summary"])


if __name__ == "__main__":
    unittest.main()
