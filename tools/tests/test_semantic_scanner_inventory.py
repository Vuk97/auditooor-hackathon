from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SEMANTIC = ROOT / "tools" / "semantic-graph.py"
WORKLIST = ROOT / "tools" / "semantic-detector-worklist.py"
QUERY = ROOT / "tools" / "semantic-graph-query.py"
ADJUDICATION = ROOT / "tools" / "semantic-detector-adjudication.py"
INVENTORY = ROOT / "tools" / "semantic-scanner-inventory.py"


def _write_workspace(ws: Path) -> None:
    (ws / "src").mkdir()
    (ws / "src" / "Portal.sol").write_text(
        textwrap.dedent(
            """
            pragma solidity ^0.8.20;

            contract Portal {
                mapping(bytes32 => bool) public finalized;
                OutputOracle public outputOracle;
                ProofVerifier public verifier;
                Bridge public bridge;
                Registry public registry;

                function finalizeWithdrawal(bytes calldata proof, bytes calldata data) external {
                    bytes32 outputRoot = outputOracle.getOutputRoot(abi.decode(data, (uint256)));
                    require(verifier.verifyProof(proof, outputRoot), "bad proof");
                    finalized[outputRoot] = true;
                    bridge.finalizeWithdrawal(data);
                }

                function registerRoute(address impl) external {
                    Clones.clone(impl);
                    new TransparentUpgradeableProxy(impl);
                    registry.register(impl);
                }

                function routeOnly(bytes calldata data) external {
                    bridge.finalizeWithdrawal(data);
                }
            }

            contract OutputOracle { function getOutputRoot(uint256) external returns (bytes32) {} }
            contract ProofVerifier { function verifyProof(bytes calldata, bytes32) external returns (bool) {} }
            contract Bridge { function finalizeWithdrawal(bytes calldata) external {} }
            contract Registry { function register(address) external {} }
            contract TransparentUpgradeableProxy { constructor(address) {} }
            library Clones { function clone(address) internal returns (address) {} }
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )


def _run(*args: Path | str) -> None:
    proc = subprocess.run(
        [str(arg) for arg in args],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        raise AssertionError(proc.stderr or proc.stdout)


class SemanticScannerInventoryTest(unittest.TestCase):
    def test_inventory_bridges_worklist_query_and_adjudication_into_scanner_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_workspace(ws)
            _run(sys.executable, SEMANTIC, "--workspace", ws)
            _run(sys.executable, WORKLIST, "--workspace", ws)
            _run(sys.executable, QUERY, "--workspace", ws)
            _run(sys.executable, ADJUDICATION, "--workspace", ws)
            _run(sys.executable, INVENTORY, "--workspace", ws, "--limit", "50")

            payload = json.loads((ws / ".auditooor" / "semantic_scanner_inventory.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["schema"], "auditooor.semantic_scanner_inventory.v1")
            self.assertEqual(payload["limit"], 50)
            self.assertLessEqual(payload["item_count"], 50)
            self.assertEqual(payload["task_queue_count"], payload["item_count"])
            self.assertGreaterEqual(payload["item_count"], 5)
            self.assertEqual(payload["coverage_claim"], "none_source_shape_only")
            self.assertEqual(payload["severity"], "none")
            self.assertEqual(payload["selected_impact"], "")
            self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")
            self.assertFalse(payload["promotion_allowed"])
            self.assertTrue(payload["impact_contract_required"])
            self.assertTrue(payload["source_shape_limitations"])
            self.assertIn("semantic_detector_worklist", payload["source_artifacts"])
            self.assertIn("semantic_detector_adjudication", payload["source_artifacts"])

            statuses = payload["scanner_inventory_status_counts"]
            self.assertIn("detector_task_routed", statuses)
            self.assertIn("detector_rewrite_with_fixture_pair", payload["task_queue_type_counts"])
            kinds = {item["item_kind"] for item in payload["items"]}
            self.assertIn("semantic_detector_route", kinds)
            self.assertTrue(all(item["severity"] == "none" for item in payload["items"]))
            self.assertTrue(all(item["submission_posture"] == "NOT_SUBMIT_READY" for item in payload["items"]))
            self.assertTrue(all(item["promotion_allowed"] is False for item in payload["items"]))
            self.assertTrue(all(row["submission_posture"] == "NOT_SUBMIT_READY" for row in payload["detector_fixture_task_queue"]))
            self.assertTrue(all(row["promotion_allowed"] is False for row in payload["detector_fixture_task_queue"]))
            self.assertTrue(any(
                row["task_type"] == "detector_rewrite_with_fixture_pair"
                and row["fixture_task"]["positive_fixture_path"].endswith("_positive.sol")
                and row["fixture_task"]["clean_fixture_path"].endswith("_clean.sol")
                for row in payload["detector_fixture_task_queue"]
            ))
            self.assertTrue(any(
                item["source_component"] == "Portal.finalizeWithdrawal"
                and item["query_match_count"] >= 1
                and item["scanner_inventory_status"] == "detector_task_routed"
                for item in payload["items"]
            ))
            self.assertGreaterEqual(
                payload["function_coverage_summary"]["function_with_detector_task_count"],
                2,
            )
            md = (ws / ".auditooor" / "semantic_scanner_inventory.md").read_text(encoding="utf-8")
            self.assertIn("Rows are planning/coverage input only", md)
            self.assertIn("Detector/Fixture Task Queue", md)

    def test_inventory_can_emit_raw_coverage_rows_before_worklist_exists(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_workspace(ws)
            _run(sys.executable, SEMANTIC, "--workspace", ws)
            _run(sys.executable, INVENTORY, "--workspace", ws, "--limit", "3")

            payload = json.loads((ws / ".auditooor" / "semantic_scanner_inventory.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["item_count"], 3)
            self.assertLessEqual(payload["item_count"], payload["limit"])
            statuses = set(payload["scanner_inventory_status_counts"])
            self.assertTrue(any(status.startswith("coverage_only") for status in statuses))
            self.assertTrue(any(
                item.get("recommended_next_command") == "make semantic-detector-worklist WS=<workspace>"
                for item in payload["items"]
            ))
            self.assertTrue(any(
                row.get("task_type") == "coverage_to_detector_worklist"
                and row.get("next_command", "").startswith("make semantic-detector-worklist")
                for row in payload["detector_fixture_task_queue"]
            ))

    def test_inventory_defaults_to_fifty_concrete_queue_items(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            audit_dir = ws / ".auditooor"
            audit_dir.mkdir()
            entrypoints = []
            relation_edges = []
            for idx in range(60):
                contract = f"Portal{idx}"
                function = "finalizeWithdrawal"
                entrypoints.append(
                    {
                        "contract": contract,
                        "function": function,
                        "file": f"src/{contract}.sol",
                        "line": idx + 1,
                        "visibility": "external",
                        "role": "external",
                    }
                )
                relation_edges.append(
                    {
                        "source_contract": contract,
                        "source_function": function,
                        "kind": "verifier-adapter-call",
                        "target": "ProofVerifier",
                        "target_type": "ProofVerifier",
                        "receiver": "verifier",
                        "receiver_source": "storage",
                        "method": "verifyProof",
                        "file": f"src/{contract}.sol",
                        "line": idx + 10,
                    }
                )
            (audit_dir / "semantic_graph.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.semantic_graph.v1",
                        "entrypoints": entrypoints,
                        "relation_edges": relation_edges,
                        "multi_hop_paths": [],
                    }
                ),
                encoding="utf-8",
            )
            _run(sys.executable, INVENTORY, "--workspace", ws)

            payload = json.loads((audit_dir / "semantic_scanner_inventory.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["limit"], 50)
            self.assertEqual(payload["item_count"], 50)
            self.assertEqual(payload["task_queue_count"], 50)
            self.assertTrue(payload["truncated"])
            self.assertTrue(all(row["submission_posture"] == "NOT_SUBMIT_READY" for row in payload["detector_fixture_task_queue"]))
            self.assertEqual(
                set(payload["task_queue_type_counts"]),
                {"coverage_to_detector_worklist"},
            )


if __name__ == "__main__":
    unittest.main()
