from __future__ import annotations

# r36-rebuttal: bugfix-inventory-claude-20260610
import importlib.util
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


def _load_relation_family():
    """Import _relation_family directly from semantic-detector-worklist.py."""
    spec = importlib.util.spec_from_file_location(
        "semantic_detector_worklist_impl", str(WORKLIST)
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules["semantic_detector_worklist_impl"] = mod
    spec.loader.exec_module(mod)
    return mod._relation_family


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


# r36-rebuttal: bugfix-inventory-claude-20260610 -- test file for confirmed bug in _relation_family
class RelationFamilyWordBoundaryTest(unittest.TestCase):
    """
    Guards against the substring word-boundary false-positive in _relation_family.

    Bug (line 66): plain `"verif" in haystack` matches "reverif..." and "overif..."
    (interior substrings), wrongly classifying those edges as verifier_relation.

    Fix: re.search(r'\\b(verif|proof)\\w*', haystack) anchors to word boundaries.
    """

    def setUp(self) -> None:
        self._relation_family = _load_relation_family()

    def test_reverification_not_verifier_relation(self) -> None:
        # "reverificationBridge" has 'verif' as an interior substring (preceded by 're').
        # Must NOT classify as verifier_relation.
        edge = {"kind": "call", "method": "reverificationBridge", "target": ""}
        result = self._relation_family(edge)
        self.assertNotEqual(
            result,
            "verifier_relation",
            "interior 'verif' in 'reverificationBridge' must not trigger verifier_relation; "
            f"got: {result!r}",
        )

    def test_overification_target_not_verifier_relation(self) -> None:
        # "overificationCheck" has 'verif' after 'o' (non-word-boundary).
        edge = {"kind": "call", "method": "", "target": "overificationCheck"}
        result = self._relation_family(edge)
        self.assertNotEqual(
            result,
            "verifier_relation",
            f"'overificationCheck' must not trigger verifier_relation; got: {result!r}",
        )

    def test_verifier_still_matches(self) -> None:
        # Positive control: real verifier call must still classify correctly.
        edge = {"kind": "call", "method": "verifyProof", "target": ""}
        result = self._relation_family(edge)
        self.assertEqual(
            result,
            "verifier_relation",
            f"'verifyProof' must still produce verifier_relation; got: {result!r}",
        )

    def test_proof_target_still_matches(self) -> None:
        # Positive control: "proofValidator" starts with "proof" at a word boundary.
        edge = {"kind": "call", "method": "", "target": "proofValidator"}
        result = self._relation_family(edge)
        self.assertEqual(
            result,
            "verifier_relation",
            f"'proofValidator' must still produce verifier_relation; got: {result!r}",
        )

    def test_verification_kind_still_matches(self) -> None:
        # Positive control: "verification" as a standalone word in kind field.
        edge = {"kind": "verification", "method": "", "target": ""}
        result = self._relation_family(edge)
        self.assertEqual(
            result,
            "verifier_relation",
            f"kind='verification' must still produce verifier_relation; got: {result!r}",
        )

    def test_disproof_not_verifier_relation(self) -> None:
        # "disproveClaim" contains "proof" after "dis" (interior, non-word-boundary).
        edge = {"kind": "call", "method": "disproveClaim", "target": ""}
        result = self._relation_family(edge)
        self.assertNotEqual(
            result,
            "verifier_relation",
            f"'disproveClaim' (interior 'proof') must not trigger verifier_relation; got: {result!r}",
        )


class SemanticDetectorWorklistTest(unittest.TestCase):
    def test_worklist_turns_semantic_paths_into_advisory_detector_tasks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_workspace(ws)
            graph_proc = subprocess.run(
                [sys.executable, str(SEMANTIC), "--workspace", str(ws)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(graph_proc.returncode, 0, graph_proc.stderr)

            out_json = ws / ".auditooor" / "semantic_detector_worklist.json"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(WORKLIST),
                    "--workspace",
                    str(ws),
                    "--out-json",
                    str(out_json),
                    "--print-json",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(out_json.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema"], "auditooor.semantic_detector_worklist.v1")
            self.assertEqual(payload["coverage_claim"], "none_source_shape_only")
            self.assertFalse(payload["promotion_allowed"])
            self.assertTrue(payload["advisory_only"])
            self.assertGreaterEqual(payload["relation_edge_task_count"], 2)
            self.assertGreaterEqual(payload["multi_hop_task_count"], 1)
            self.assertGreaterEqual(payload["proof_task_count"], 1)
            self.assertEqual(payload["task_count"], len(payload["tasks"]))

            postures = {task["submission_posture"] for task in payload["tasks"]}
            severities = {task["severity"] for task in payload["tasks"]}
            self.assertEqual(postures, {"NOT_SUBMIT_READY"})
            self.assertEqual(severities, {"none"})
            self.assertTrue(all(task["submission_posture"] == "NOT_SUBMIT_READY" for task in payload["proof_tasks"]))
            self.assertTrue(all(task["severity"] == "none" for task in payload["proof_tasks"]))
            self.assertTrue(all(task["impact_contract_required"] for task in payload["tasks"]))
            self.assertTrue(all(task["promotion_allowed"] is False for task in payload["tasks"]))
            self.assertIn("source_shape_limitations", payload)
            self.assertIn("detector_rewrite_candidate", payload["action_lane_counts"])
            self.assertIn("fixture_first_source_invariant", payload["action_lane_counts"])
            self.assertIn("proof_first_causal_composition", payload["proof_action_lane_counts"])
            self.assertIn("needs_local_source_proof_or_kill", payload["proof_readiness_counts"])
            self.assertIn(
                "candidate_static_predicate_needs_fixtures",
                payload["detectorization_readiness_counts"],
            )
            self.assertIn(
                "not_ready_fixture_or_invariant_first",
                payload["detectorization_readiness_counts"],
            )

            kinds = {task["detector_task_kind"] for task in payload["tasks"]}
            self.assertIn("semantic_relation_detector_rewrite", kinds)
            self.assertIn("semantic_multihop_detector_rewrite", kinds)
            families = payload["candidate_detector_family_counts"]
            self.assertIn("bridge_finalization", families)
            query_shapes = payload["detector_query_bridge_counts"]
            self.assertIn("bridge_or_proof_finalization_path", query_shapes)
            self.assertIn("factory_proxy_or_clone_relation", query_shapes)
            self.assertIn("oracle_or_root_relation", query_shapes)
            self.assertIn("registry_write_relation", query_shapes)
            self.assertIn("verifier_adapter_relation", query_shapes)
            self.assertTrue(all(
                task["detector_query_bridge"]["backend"] == "semantic_graph_query"
                for task in payload["tasks"]
            ))
            self.assertTrue(all(
                task["detector_query_bridge"]["coverage_claim"] == "none_source_shape_only"
                for task in payload["tasks"]
            ))
            self.assertTrue(all(
                task["detector_query_bridge"]["advisory_only"] is True
                for task in payload["tasks"]
            ))
            self.assertTrue(all(task.get("required_next_artifacts") for task in payload["tasks"]))
            self.assertTrue(any(
                task.get("impact_family") == "bridge_finalization"
                and "proof_dispute_bridge_finalization" in task.get("mapped_stages", [])
                and task["detector_query_bridge"]["query_shape"] == "bridge_or_proof_finalization_path"
                and task["action_lane"] == "fixture_first_source_invariant"
                for task in payload["tasks"]
            ))
            self.assertTrue(any(
                task.get("proof_task_kind") == "semantic_causal_composition_proof"
                and task.get("source_component") == "Portal.finalizeWithdrawal"
                and task.get("relation_sink_component") == "ProofVerifier.verifyProof"
                and task.get("proof_obligation", {}).get("claim_shape") == "same_entrypoint_path_to_relation_sink"
                for task in payload["proof_tasks"]
            ))
            md = (ws / ".auditooor" / "semantic_detector_worklist.md").read_text(encoding="utf-8")
            self.assertIn("## Proof Tasks", md)

    def test_missing_graph_fails_with_actionable_message(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            proc = subprocess.run(
                [sys.executable, str(WORKLIST), "--workspace", str(ws)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("semantic graph missing", proc.stderr)

    def test_worklist_dedupes_external_and_src_mirror_relation_edges(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            aud = ws / ".auditooor"
            aud.mkdir()
            graph = {
                "schema_version": "auditooor.semantic_graph.v1",
                "relation_edges": [
                    {
                        "file": "external/nuva-evm-contracts/contracts/Router.sol",
                        "line": 12,
                        "source_contract": "Router",
                        "source_function": "deposit",
                        "kind": "high-level-call",
                        "receiver": "token",
                        "target": "Token",
                        "target_type": "Token",
                        "method": "transferFrom",
                        "evidence": "token.transferFrom(msg.sender, address(this), amount)",
                    },
                    {
                        "file": "src/nuva-evm-contracts/contracts/Router.sol",
                        "line": 12,
                        "source_contract": "Router",
                        "source_function": "deposit",
                        "kind": "high-level-call",
                        "receiver": "token",
                        "target": "Token",
                        "target_type": "Token",
                        "method": "transferFrom",
                        "evidence": "token.transferFrom(msg.sender, address(this), amount)",
                    },
                ],
                "multi_hop_paths": [],
                "causal_composition_edges": [],
            }
            (aud / "semantic_graph.json").write_text(json.dumps(graph), encoding="utf-8")
            out_json = aud / "semantic_detector_worklist.json"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(WORKLIST),
                    "--workspace",
                    str(ws),
                    "--out-json",
                    str(out_json),
                    "--print-json",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(out_json.read_text(encoding="utf-8"))
            self.assertEqual(payload["raw_relation_edge_count"], 2)
            self.assertEqual(payload["mirror_duplicate_relation_edge_count"], 1)
            self.assertEqual(payload["relation_edge_task_count"], 1)
            self.assertEqual([task["file"] for task in payload["tasks"]], ["external/nuva-evm-contracts/contracts/Router.sol"])


if __name__ == "__main__":
    unittest.main()
