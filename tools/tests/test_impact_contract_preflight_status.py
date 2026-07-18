from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "impact-contract-preflight-status.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("impact_contract_preflight_status", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MOD = _load_tool()


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _seed_complete_fixture(root: Path) -> None:
    _write(
        root / "tools" / "impact-contract-preflight.py",
        "\n".join(
            [
                'SCHEMA_VERSION = "auditooor.impact_contract_preflight.v1"',
                "impact-contract-missing",
                "planning-artifact-advisory-bypass",
                "impact-contract-explicit",
            ]
        ),
    )
    _write(
        root / "tools" / "tests" / "test_impact_contract_preflight.py",
        "\n".join(
            [
                "def test_proof_grade_draft_without_explicit_contract_is_blocked(): pass",
                "def test_explicit_markdown_contract_allows_filing(): pass",
                "def test_planning_json_gets_advisory_bypass(): pass",
                "def test_explicit_json_contract_allows_promotion(): pass",
            ]
        ),
    )
    _write(
        root / "tools" / "source-proof-record.py",
        "impact_contract_preflight\nbuild_source_proof_preflight\nroute=\"source-proof\"\nblocked_missing_impact_contract\n",
    )
    _write(
        root / "tools" / "tests" / "test_source_proof_record.py",
        "impact_contract_preflight\nsource-proof\ndef test_missing_impact_contract_blocks_even_if_proof_requested(): pass\n",
    )
    _write(
        root / "tools" / "harness-scaffold-emitter.py",
        "impact_contract_preflight\nharness_impact_preflight\nroute=\"harness-scaffold\"\nblocked_missing_impact_contract\n",
    )
    _write(
        root / "tools" / "tests" / "test_harness_scaffold_emitter.py",
        "\n".join(
            [
                "impact_contract_preflight",
                "harness-scaffold",
                "def test_missing_impact_contract_writes_only_blocked_manifest(): pass",
                "def test_workspace_impact_contract_unlocks_scaffold_and_manifest_metadata(): pass",
            ]
        ),
    )
    _write(
        root / "tools" / "exploit-memory-brief.py",
        "impact_contract_preflight\n_exploit_memory_preflight\nroute=\"exploit-memory\"\nplanning-artifact-advisory-bypass\n",
    )
    _write(
        root / "tools" / "tests" / "test_exploit_memory_brief.py",
        "impact_contract_preflight\nexploit-memory\nplanning-artifact-advisory-bypass\n",
    )
    _write(
        root / "tools" / "pre-submit-check.sh",
        "impact-contract-preflight\n--route filing\nimpact-contract-missing\n",
    )
    _write(
        root / "tools" / "tests" / "test_pre_submit_impact_contract_check.py",
        "def test_missing_explicit_contract_is_reported(): pass\ndef test_explicit_contract_marks_check_green(): pass\nimpact-contract-missing\n",
    )
    _write(
        root / "tools" / "agent-output-synthesizer.py",
        "impact_contract_preflight\nroute=\"promotion\"\ncandidate_finding\n",
    )
    _write(
        root / "tools" / "tests" / "test_agent_output_synthesizer_impact_contract.py",
        "def test_missing_contract_demotes_candidate_to_poc_plan(): pass\ndef test_explicit_contract_promotes_candidate_finding(): pass\nimpact-contract-missing\n",
    )


class ImpactContractPreflightStatusTests(unittest.TestCase):
    def test_complete_route_evidence_closes_klbq_010_locally(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _seed_complete_fixture(root)

            report = MOD.build_report(root)

        self.assertEqual(report["limitation_id"], "KLBQ-010")
        self.assertEqual(report["implementation_status"], "implemented_verified_local_evidence")
        self.assertFalse(report["open"])
        self.assertFalse(report["dispatch_ready"])
        self.assertEqual(report["expected_loop_cost"], 0)
        self.assertEqual(report["summary"]["blocked_route_count"], 0)
        self.assertEqual(report["summary"]["passed_route_count"], 6)
        self.assertEqual(report["blockers"], [])
        self.assertIn("advisory-only bypass", report["closed_benefit"])
        self.assertIn("tools/impact-contract-preflight.py", report["evidence_paths"])
        self.assertIn("tools/tests/test_impact_contract_preflight.py", report["evidence_paths"])

    def test_missing_route_regression_test_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _seed_complete_fixture(root)
            (root / "tools" / "tests" / "test_harness_scaffold_emitter.py").unlink()

            report = MOD.build_report(root)

        self.assertEqual(report["implementation_status"], "blocked_missing_route_evidence")
        self.assertTrue(report["open"])
        self.assertTrue(report["dispatch_ready"])
        self.assertEqual(report["expected_loop_cost"], 1)
        blocked = {route["route"]: route for route in report["routes"] if route["status"] != "pass"}
        self.assertEqual(set(blocked), {"harness-scaffold"})
        self.assertIn("missing file: tools/tests/test_harness_scaffold_emitter.py", blocked["harness-scaffold"]["issues"])
        self.assertTrue(any("harness-scaffold" in blocker for blocker in report["blockers"]))

    def test_markdown_lists_routes_and_caveats(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _seed_complete_fixture(root)

            markdown = MOD.render_markdown(MOD.build_report(root))

        self.assertIn("| source-proof |", markdown)
        self.assertIn("| exploit-memory |", markdown)
        self.assertIn("advisory-only", markdown)
        self.assertIn("not exploit proof", markdown)


if __name__ == "__main__":
    unittest.main(verbosity=2)
