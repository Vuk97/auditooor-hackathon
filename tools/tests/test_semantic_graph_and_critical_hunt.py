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
CRITICAL = ROOT / "tools" / "critical-hunt.py"
BASE_CRITICAL_HUNT = ROOT / "tools" / "base-critical-hunt.py"


def _write_workspace(ws: Path) -> None:
    (ws / "src").mkdir()
    (ws / "src" / "Vault.sol").write_text(
        textwrap.dedent(
            """
            // SPDX-License-Identifier: MIT
            pragma solidity ^0.8.20;

            contract Vault {
                address public owner;
                mapping(address => uint256) public balanceOf;

                modifier onlyOwner() {
                    require(msg.sender == owner, "owner");
                    _;
                }

                function deposit() external payable {
                    balanceOf[msg.sender] += msg.value;
                    emit Deposited(msg.sender, msg.value);
                }

                function withdraw(uint256 amount) external {
                    balanceOf[msg.sender] -= amount;
                    payable(msg.sender).transfer(amount);
                }

                function sweep(address to) external onlyOwner {
                    payable(to).transfer(address(this).balance);
                }

                event Deposited(address indexed user, uint256 amount);
            }
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    (ws / "src" / "VaultFactory.sol").write_text(
        textwrap.dedent(
            """
            // SPDX-License-Identifier: MIT
            pragma solidity ^0.8.20;

            library Clones {
                function clone(address implementation) internal returns (address) {}
            }

            contract ERC1967Proxy {
                constructor(address implementation, bytes memory data) {}
            }

            contract ProofVerifier {
                function verifyProof(bytes calldata proof) external returns (bool) {}
            }

            contract VaultFactory {
                address public implementation;
                Registry public registry;
                ProofVerifier public verifier;

                function deployClone(bytes calldata proof) external {
                    require(verifier.verifyProof(proof), "proof");
                    address clone = Clones.clone(implementation);
                    registry.registerVault(clone);
                }

                function deployProxy(bytes calldata data) external {
                    new ERC1967Proxy(implementation, data);
                }
            }

            contract Registry {
                function registerVault(address vault) external {}
            }

            contract VaultRouter {
                Vault public vault;

                function routeWithdraw(uint256 amount) external {
                    vault.withdraw(amount);
                }

                function routeLocal(address vaultAddress, uint256 amount) external {
                    Vault localVault = Vault(vaultAddress);
                    localVault.withdraw(amount);
                }

                function routeCast(address vaultAddress, uint256 amount) external {
                    Vault(vaultAddress).withdraw(amount);
                }
            }
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    (ws / "SCOPE.md").write_text(
        "Assets in scope: src/Vault.sol\nOut of scope: owner compromise\n",
        encoding="utf-8",
    )


class SemanticGraphTest(unittest.TestCase):
    def test_graph_extracts_entrypoints_roles_writes_and_scope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_workspace(ws)
            proc = subprocess.run(
                [sys.executable, str(SEMANTIC), "--workspace", str(ws), "--print-json"],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            graph = json.loads(proc.stdout[proc.stdout.index("{"):])
            self.assertEqual(graph["schema_version"], "auditooor.semantic_graph.v1")
            self.assertEqual(graph["contract_count"], 7)
            by_fn = {e["function"]: e for e in graph["entrypoints"]}
            self.assertEqual(by_fn["withdraw"]["role"], "permissionless")
            self.assertIn("balanceOf", by_fn["withdraw"]["state_writes"])
            self.assertTrue(by_fn["withdraw"]["value_movement"])
            self.assertTrue(by_fn["sweep"]["privileged"])
            self.assertTrue(graph["scope_annotations"])
            self.assertGreaterEqual(graph["relation_edge_count"], 4)
            edge_kinds = {edge["kind"] for edge in graph["relation_edges"]}
            self.assertIn("clone-deploy", edge_kinds)
            self.assertIn("proxy-deploy", edge_kinds)
            self.assertIn("registry-write", edge_kinds)
            self.assertIn("verifier-adapter-call", edge_kinds)
            self.assertIn("high-level-call", edge_kinds)
            self.assertIn("typed-cast-call", edge_kinds)
            high_level = [
                edge for edge in graph["relation_edges"]
                if edge["kind"] == "high-level-call" and edge["method"] == "withdraw"
            ]
            self.assertTrue(high_level)
            withdraw_edges = [
                edge for edge in graph["relation_edges"]
                if edge["method"] == "withdraw"
            ]
            by_receiver = {edge["receiver"]: edge for edge in withdraw_edges}
            self.assertEqual(by_receiver["vault"]["target"], "Vault")
            self.assertEqual(by_receiver["vault"]["target_type"], "Vault")
            self.assertEqual(by_receiver["vault"]["receiver_source"], "state")
            self.assertEqual(by_receiver["localVault"]["target"], "Vault")
            self.assertEqual(by_receiver["localVault"]["target_type"], "Vault")
            self.assertEqual(by_receiver["localVault"]["receiver_source"], "local")
            typed_cast = next(edge for edge in withdraw_edges if edge["kind"] == "typed-cast-call")
            self.assertEqual(typed_cast["target_type"], "Vault")
            self.assertEqual(typed_cast["receiver_source"], "typed-cast")
            verifier_edge = next(
                edge for edge in graph["relation_edges"]
                if edge["kind"] == "verifier-adapter-call"
            )
            self.assertEqual(verifier_edge["target_type"], "ProofVerifier")
            self.assertEqual(verifier_edge["receiver_source"], "state")
            self.assertGreaterEqual(graph["evidence_edge_count"], 1)
            self.assertGreaterEqual(graph["multi_hop_path_count"], 1)
            self.assertGreaterEqual(graph["causal_composition_edge_count"], 1)
            stages = {
                stage
                for path in graph["multi_hop_paths"]
                for stage in path["mapped_stages"]
            }
            self.assertIn("caller", stages)
            self.assertIn("validation", stages)
            causal_edges = [
                edge for edge in graph["causal_composition_edges"]
                if edge["source_component"] == "VaultFactory.deployClone"
            ]
            self.assertTrue(causal_edges)
            self.assertTrue(all(edge["submission_posture"] == "NOT_SUBMIT_READY" for edge in causal_edges))
            self.assertTrue(all(edge["hypothesis_strength"] == "weak_same_entrypoint_source_shape" for edge in causal_edges))
            sinks = {edge["relation_sink_component"] for edge in causal_edges}
            self.assertIn("ProofVerifier.verifyProof", sinks)
            self.assertIn("Clones.clone", sinks)

    def test_relation_edge_lines_preserve_source_positions_after_comments(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "src").mkdir()
            source = textwrap.dedent(
                """
                pragma solidity ^0.8.20;

                /*
                 * Large NatSpec-style block that used to be deleted before
                 * relation line numbers were calculated.
                 *
                 * Every newline here must still count.
                 */
                contract CrossChainManager {
                    Token public token;
                    Token public shareToken;

                    /**
                     * @notice Deposits with an off-chain permit.
                     * @param amount Amount to deposit.
                     */
                    function depositWithPermit(uint256 amount) external {
                        // Inline comments should not shift call positions either.
                        token.permit(
                            msg.sender,
                            address(this),
                            amount
                        );

                        if (token.allowance(msg.sender, address(this)) < amount) {
                            revert();
                        }
                    }
                }

                contract Token {
                    function permit(address, address, uint256) external {}
                    function allowance(address, address) external returns (uint256) {}
                }
                """
            ).strip() + "\n"
            (ws / "src" / "CrossChainManager.sol").write_text(source, encoding="utf-8")

            graph = _run_semantic(ws)
            expected_lines = {
                "permit": source.splitlines().index("        token.permit(") + 1,
                "allowance": source.splitlines().index(
                    "        if (token.allowance(msg.sender, address(this)) < amount) {"
                ) + 1,
            }
            by_method = {
                edge["method"]: edge
                for edge in graph["relation_edges"]
                if edge["file"] == "src/CrossChainManager.sol"
            }

            self.assertEqual(by_method["permit"]["line"], expected_lines["permit"])
            self.assertEqual(by_method["allowance"]["line"], expected_lines["allowance"])

    def test_scoped_graph_selects_bounded_semantic_live_depth_items_from_sidecar(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            aud = ws / ".auditooor"
            aud.mkdir()
            relation_edges = []
            multi_hop_paths = []
            for idx in range(360):
                relation_edges.append(
                    {
                        "source_contract": f"Portal{idx}",
                        "source_function": "finalizeWithdrawal",
                        "kind": "bridge-finalizer-call",
                        "target": f"Bridge{idx}",
                        "target_type": f"Bridge{idx}",
                        "method": "finalizeWithdrawal",
                        "file": f"src/Portal{idx}.sol",
                        "line": idx + 10,
                    }
                )
            for idx in range(120):
                multi_hop_paths.append(
                    {
                        "path_id": f"SG-MH-{idx:03d}",
                        "impact_family": "bridge_finalization",
                        "source_component": f"Portal{idx}.finalizeWithdrawal",
                        "sink_component": f"Bridge{idx}.finalizeWithdrawal",
                        "mapped_stages": ["caller", "validation", "proof_dispute_bridge_finalization"],
                        "evidence_edges": [],
                    }
                )
            sidecar = aud / "callgraph_de_semantic_graph_fixtures.json"
            sidecar.write_text(
                json.dumps(
                    {
                        "schema_version": "auditooor.semantic_graph.v1",
                        "workspace": str(ws),
                        "contracts": [],
                        "entrypoints": [],
                        "relation_edges": relation_edges,
                        "multi_hop_paths": multi_hop_paths,
                    }
                ),
                encoding="utf-8",
            )

            proc = subprocess.run(
                [
                    sys.executable,
                    str(SEMANTIC),
                    "--workspace",
                    str(ws),
                    "--scoped",
                    "--print-json",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            graph = json.loads(proc.stdout[proc.stdout.index("{"):])
            self.assertEqual(graph["selection_mode"], "scoped_semantic_live_depth")
            self.assertEqual(graph["selection_metadata"]["target_range"], "300-500")
            self.assertGreaterEqual(graph["selection_metadata"]["selected_semantic_item_count"], 300)
            self.assertLessEqual(graph["selection_metadata"]["selected_semantic_item_count"], 500)
            self.assertEqual(graph["selection_metadata"]["selected_semantic_item_count"], 480)

    def test_critical_hunt_outputs_conservative_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_workspace(ws)
            proc = subprocess.run(
                [sys.executable, str(CRITICAL), "--workspace", str(ws), "--print-json"],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout[proc.stdout.index("{"):])
            self.assertEqual(payload["schema_version"], "auditooor.critical_candidates.v1")
            inventory = payload["semantic_path_inventory"]
            self.assertEqual(inventory["coverage_claim"], "none_source_shape_only")
            self.assertGreaterEqual(inventory["relation_edge_count"], 1)
            self.assertGreaterEqual(inventory["multi_hop_path_count"], 1)
            self.assertTrue(inventory["relation_edge_worklist"])
            self.assertGreaterEqual(payload["candidate_count"], 2)
            self.assertTrue(
                all(c["status"] == "needs_production_path" for c in payload["candidates"])
            )
            self.assertTrue(
                all(c["severity_claim"] == "none" for c in payload["candidates"])
            )
            self.assertTrue(
                all(c["severity_ceiling"] == "none" for c in payload["candidates"])
            )
            self.assertTrue(
                all(c["submission_posture"] == "not_submit_ready" for c in payload["candidates"])
            )
            self.assertTrue(
                all(c["submit_verdict"] == "not_submission_ready" for c in payload["candidates"])
            )
            self.assertTrue(
                all(c["advisory_only"] is True for c in payload["candidates"])
            )
            self.assertTrue(
                all(c["impact_contract_linked"] is False for c in payload["candidates"])
            )
            self.assertTrue(
                all(c["impact_contract_status"] == "missing_exact_impact_contract" for c in payload["candidates"])
            )

    def test_critical_hunt_links_only_exact_impact_contracts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_workspace(ws)
            graph = _run_semantic(ws)
            withdraw = next(
                entry for entry in graph["entrypoints"]
                if entry["contract"] == "Vault" and entry["function"] == "withdraw"
            )
            candidate_id = f"{withdraw['contract']}:{withdraw['function']}:{withdraw['line']}"
            (ws / ".auditooor" / "impact_contracts.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.pr560.impact_contracts.v1",
                        "contracts": [
                            {
                                "candidate_id": candidate_id,
                                "impact_contract_id": "impact-contract-withdraw",
                                "exact_impact_row": True,
                                "selected_impact": "Direct theft of user deposits",
                                "severity": "Critical",
                                "posture": "in_scope_direct_submit",
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            proc = subprocess.run(
                [sys.executable, str(CRITICAL), "--workspace", str(ws), "--print-json"],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout[proc.stdout.index("{"):])
            by_id = {c["candidate_id"]: c for c in payload["candidates"]}
            linked = by_id[candidate_id]
            self.assertFalse(linked["advisory_only"])
            self.assertTrue(linked["impact_contract_linked"])
            self.assertEqual(linked["impact_contract_id"], "impact-contract-withdraw")
            self.assertEqual(linked["impact_contract_status"], "exact_impact_contract_linked")
            self.assertEqual(linked["reportable_status"], "impact_contract_linked_proof_required")
            self.assertEqual(linked["severity_claim"], "none")
            self.assertEqual(linked["submission_posture"], "not_submit_ready")

            unlinked = [c for c in payload["candidates"] if c["candidate_id"] != candidate_id]
            self.assertTrue(unlinked)
            self.assertTrue(
                all(c["advisory_only"] is True for c in unlinked)
            )
            self.assertTrue(
                all(c["impact_contract_status"] == "missing_exact_impact_contract" for c in unlinked)
            )


def _run_semantic(ws: Path) -> dict:
    proc = subprocess.run(
        [sys.executable, str(SEMANTIC), "--workspace", str(ws), "--print-json"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        raise AssertionError(proc.stderr)
    return json.loads(proc.stdout[proc.stdout.index("{"):])


def _run_base_critical_hunt(ws: Path) -> dict:
    proc = subprocess.run(
        [sys.executable, str(BASE_CRITICAL_HUNT), "--workspace", str(ws)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=60,
    )
    if proc.returncode != 0:
        raise AssertionError(proc.stderr + proc.stdout)
    return json.loads((ws / ".auditooor" / "coverage_inventory.json").read_text())


class MultiHopCoverageInventoryTest(unittest.TestCase):
    def test_base_like_bridge_finalization_path_flows_to_coverage_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "src").mkdir()
            (ws / "SEVERITY.md").write_text(
                "# Severity\n\n## Critical\n\n- Bridge finalization can be bypassed\n",
                encoding="utf-8",
            )
            (ws / "src" / "Portal.sol").write_text(
                textwrap.dedent(
                    """
                    pragma solidity ^0.8.20;

                    contract Portal {
                        mapping(bytes32 => bool) public finalized;
                        OutputOracle public outputOracle;
                        ProofVerifier public verifier;
                        Bridge public bridge;

                        function finalizeWithdrawal(bytes calldata proof, bytes calldata data) external {
                            bytes32 outputRoot = outputOracle.getOutputRoot(abi.decode(data, (uint256)));
                            require(verifier.verifyProof(proof, outputRoot), "bad proof");
                            finalized[outputRoot] = true;
                            bridge.finalizeWithdrawal(data);
                        }
                    }

                    contract OutputOracle { function getOutputRoot(uint256) external returns (bytes32) {} }
                    contract ProofVerifier { function verifyProof(bytes calldata, bytes32) external returns (bool) {} }
                    contract Bridge { function finalizeWithdrawal(bytes calldata) external {} }
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )

            graph = _run_semantic(ws)
            path = graph["multi_hop_paths"][0]
            self.assertEqual(path["impact_family"], "bridge_finalization")
            self.assertIn("parser", path["mapped_stages"])
            self.assertIn("cache_provider", path["mapped_stages"])
            self.assertIn("validation", path["mapped_stages"])
            self.assertIn("state_root", path["mapped_stages"])
            self.assertIn("proof_dispute_bridge_finalization", path["mapped_stages"])

            inventory = _run_base_critical_hunt(ws)
            self.assertTrue(inventory["multi_hop_paths"])
            worklist = inventory["impact_family_worklists"][0]
            self.assertEqual(worklist["impact_family"], "bridge_finalization")
            self.assertEqual(worklist["status"], "WARN")
            self.assertTrue(worklist["multi_hop_path_ids"])
            self.assertIn("next_action", worklist)

    def test_non_base_oracle_state_root_path_flows_to_coverage_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "contracts").mkdir()
            (ws / "SEVERITY.md").write_text(
                "# Severity\n\n## Critical\n\n- Oracle provider validation can corrupt state root\n",
                encoding="utf-8",
            )
            (ws / "contracts" / "PriceBook.sol").write_text(
                textwrap.dedent(
                    """
                    pragma solidity ^0.8.20;

                    contract PriceBook {
                        bytes32 public stateRootCache;
                        OracleProvider public oracleProvider;

                        function updatePrice(bytes calldata payload) external {
                            uint256 price = parsePrice(payload);
                            bytes32 providerRoot = oracleProvider.latestStateRoot();
                            require(validatePrice(price, providerRoot), "invalid");
                            stateRootCache = providerRoot;
                        }

                        function parsePrice(bytes calldata payload) internal pure returns (uint256) {
                            return abi.decode(payload, (uint256));
                        }

                        function validatePrice(uint256, bytes32) internal pure returns (bool) {
                            return true;
                        }
                    }

                    contract OracleProvider { function latestStateRoot() external returns (bytes32) {} }
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )

            graph = _run_semantic(ws)
            paths = graph["multi_hop_paths"]
            self.assertEqual(len(paths), 1)
            self.assertEqual(paths[0]["impact_family"], "state_root_validation")
            self.assertNotIn("proof_dispute_bridge_finalization", paths[0]["mapped_stages"])

            inventory = _run_base_critical_hunt(ws)
            worklist = inventory["impact_family_worklists"][0]
            self.assertEqual(worklist["impact_family"], "state_root_validation")
            self.assertEqual(worklist["status"], "WARN")
            self.assertTrue(inventory["multi_hop_paths"][0]["evidence_edges"])


if __name__ == "__main__":
    unittest.main()
