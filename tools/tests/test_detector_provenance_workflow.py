from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
VAULT_MODULE_PATH = ROOT / "tools" / "vault-mcp-server.py"
RANKER_MODULE_PATH = ROOT / "tools" / "attack-class-ranker.py"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load module from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


vault_mcp_server = _load_module("vault_mcp_server_workflow_test", VAULT_MODULE_PATH)
attack_class_ranker = _load_module("attack_class_ranker_workflow_test", RANKER_MODULE_PATH)


class DetectorProvenanceWorkflowSmokeTest(unittest.TestCase):
    def test_engage_report_detector_context_flows_into_provenance_v2_and_ranker(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditooor-prov-workflow-") as tmp:
            root = Path(tmp)
            repo_root = root / "repo"
            workspace = root / "workspace"

            (repo_root / "obsidian-vault").mkdir(parents=True)
            (repo_root / "detectors" / "wave12").mkdir(parents=True)
            (repo_root / "reference" / "patterns.dsl").mkdir(parents=True)
            (repo_root / "tools" / "tests").mkdir(parents=True)
            (workspace / "src").mkdir(parents=True)

            detector_id = "zero-amountoutmin-in-router"
            detector_path = repo_root / "detectors" / "wave12" / "zero_amountoutmin_router.py"
            detector_path.write_text(
                textwrap.dedent(
                    '''
                    from slither.detectors.abstract_detector import AbstractDetector


                    class ZeroAmountOutMinInRouter(AbstractDetector):
                        ARGUMENT = "zero-amountoutmin-in-router"


                    """zero-amountoutmin-in-router - generated from reference/patterns.dsl/zero-amountoutmin-in-router.yaml"""
                    '''
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            (repo_root / "reference" / "patterns.dsl" / "zero-amountoutmin-in-router.yaml").write_text(
                textwrap.dedent(
                    """
                    pattern: zero-amountoutmin-in-router
                    source: local-workflow-test
                    severity: HIGH
                    confidence: HIGH
                    match:
                      - function.name_matches: '(?i)swap|route'
                      - function.body_contains_regex: '(?i)amountOutMin\\s*[:=]\\s*0'
                      - function.body_not_contains_regex: '(?i)deadline'
                    help: "Router swap accepts zero amountOutMin and no deadline slippage protection."
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            (repo_root / "reference" / "patterns.dsl" / "manager-write-no-auth.yaml").write_text(
                textwrap.dedent(
                    """
                    pattern: manager-write-no-auth
                    source: local-workflow-test
                    severity: MEDIUM
                    confidence: MEDIUM
                    match:
                      - function.name_matches: '(?i)addManager|removeManager'
                      - function.body_not_contains_regex: '(?i)onlyOwner|hasRole|admin'
                    help: "Manager mapping mutation has no visible caller authorization guard."
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            (repo_root / "tools" / "tests" / "test_zero_amountoutmin_detector.py").write_text(
                "ARG = 'zero-amountoutmin-in-router'\n",
                encoding="utf-8",
            )
            (workspace / "src" / "Router.sol").write_text(
                textwrap.dedent(
                    """
                    contract Router {
                        function swapExactTokensForTokens(uint256 amountOutMin) external {}
                    }
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            (workspace / "engage_report.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.engage_report.sidecar.v1",
                        "kind": "engage_report_sidecar",
                        "total_hits": 1,
                        "distinct_detectors": 1,
                        "analogical_clusters": 1,
                        "severity_summary": {"HIGH": 1, "MEDIUM": 0, "LOW": 0},
                        "actionable_next_steps": {"triage": 1, "dupe_check": 0, "mine": 0},
                        "clusters": [
                            {
                                "detector_slug": detector_id,
                                "hit_count": 1,
                                "hits": [
                                    {
                                        "severity": "HIGH",
                                        "file_path": f"{workspace / 'src' / 'Router.sol'}:42",
                                        "snippet": "swap sets amountOutMin to 0 and omits deadline slippage protection",
                                    }
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            vault = vault_mcp_server.VaultQuery(repo_root / "obsidian-vault", repo_root)
            engage = vault.vault_engage_report_context(workspace_path=str(workspace))

            self.assertTrue(engage["report_found"])
            self.assertEqual(engage["report_path"], "workspace:engage_report.json")
            self.assertEqual(engage["clusters_returned"], 1)

            cluster = engage["clusters"][0]
            hit = cluster["hits"][0]
            self.assertEqual(cluster["detector_slug"], detector_id)
            self.assertEqual(hit["file_path"], "src/Router.sol:42")

            provenance = vault.vault_detector_provenance_v2(detector_id=cluster["detector_slug"])
            self.assertEqual(
                provenance["schema"], vault_mcp_server.DETECTOR_PROVENANCE_V2_SCHEMA
            )
            self.assertEqual(provenance["kind"], "detector_provenance_v2")
            self.assertEqual(
                provenance["resolver_schema"], "auditooor.detector_provenance_v2.solidity.v1"
            )
            self.assertEqual(provenance["backend"], "solidity")
            self.assertEqual(
                provenance["detector_path"], "detectors/wave12/zero_amountoutmin_router.py"
            )
            self.assertEqual(provenance["argument"], detector_id)
            self.assertTrue(
                provenance["generated_from_dsl_path"].endswith(
                    "zero-amountoutmin-in-router.yaml"
                )
            )
            self.assertEqual(
                provenance["advisory_boundary"],
                "advisory_only_local_metadata_no_impact_claim",
            )
            self.assertTrue(provenance["privacy_guards"]["repo_relative_refs_only"])
            self.assertTrue(
                all(
                    ref
                    and not ref.startswith("/")
                    and "://" not in ref
                    for ref in provenance["source_refs"]
                )
            )

            provenance_blob = json.dumps(provenance)
            self.assertNotIn(str(repo_root), provenance_blob)
            self.assertNotIn(str(workspace), provenance_blob)

            ranked = attack_class_ranker.run(
                [
                    "--repo-root",
                    str(repo_root),
                    "--detector-slug",
                    cluster["detector_slug"],
                    "--file-path",
                    hit["file_path"],
                    "--context",
                    hit["snippet"],
                    "--top-n",
                    "2",
                ]
            )

            self.assertTrue(ranked["advisory_only"])
            self.assertEqual(ranked["inputs"]["detector_slug"], detector_id)
            self.assertEqual(ranked["inputs"]["file_path"], "src/Router.sol:42")
            self.assertTrue(ranked["inputs"]["context_present"])
            self.assertGreaterEqual(ranked["summary"]["ranked_count"], 1)

            top = ranked["ranked_attack_classes"][0]
            self.assertEqual(top["attack_class"], "slippage-mev")
            self.assertTrue(top["advisory_only"])
            self.assertEqual(top["claim_scope"], "hypothesis_prioritization_only")
            self.assertIn(detector_id, top["pattern_ids"])
            self.assertIn("amountoutmin", top["matched_terms"])
            self.assertEqual(top["evidence_refs"][0]["source_kind"], "patterns.dsl")


if __name__ == "__main__":
    unittest.main()
