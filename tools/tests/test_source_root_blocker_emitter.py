#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "source-root-blocker-emitter.py"
KG_TOOL = ROOT / "tools" / "knowledge-gap-log.py"
REAL_LOCATOR = ROOT / "reports" / "g1_source_root_locator_2026-05-05.json"


def _load_module(path: Path, name: str) -> types.ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MOD = _load_module(TOOL, "source_root_blocker_emitter")
KG = _load_module(KG_TOOL, "knowledge_gap_log_for_source_root_blocker_tests")


def fixture_report() -> dict:
    return {
        "generated_at": "2026-05-05",
        "packet_id": "G1-NWP-001",
        "mode": "local_files_caches_workspaces_only",
        "findings": [
            {
                "finding_id": "38333",
                "title": "Cluster row",
                "project": "The Standard Smart Vault",
                "source_root_status": "cluster_inferred_candidate_no_local_root",
                "confirmation_level": "cluster_inferred_only",
                "local_source_checkout_found": False,
                "local_source_root": None,
                "candidate_repo": "https://github.com/the-standard/smart-vault",
                "candidate_commit": "c6837d4a296fe8a6e4bb5e0280a66d6eb8a40361",
                "candidate_tag": None,
                "candidate_source_root": "contracts",
                "confidence": "low",
                "blockers": [
                    "Exact #38333 row has no local GitHub URL or commit.",
                    "No local checkout contains SmartVaultV4.sol or SmartVaultYieldManager.sol.",
                    "Candidate commit and contracts/ source root are cluster-inferred only and must be confirmed against the exact #38333 source report before replay.",
                ],
            },
            {
                "finding_id": "36418",
                "title": "[C-01] Decreasing position size via leverage update can be abused",
                "project": "GainsNetwork May",
                "source_root_status": "unresolved_local_absent",
                "confirmation_level": "unresolved_no_candidate",
                "local_source_checkout_found": False,
                "local_source_root": None,
                "candidate_repo": None,
                "candidate_commit": None,
                "candidate_tag": None,
                "candidate_source_root": None,
                "confidence": "low",
                "blockers": [
                    "No local GitHub URL, commit, tag, or checkout found for the Pashov GainsNetwork May row.",
                    "Exact repo and reviewed commit/tag remain required before source replay.",
                ],
            },
            {
                "finding_id": "99999",
                "title": "Already exact",
                "project": "Ready Project",
                "source_root_status": "exact_local_root_found",
                "confirmation_level": "exact_row_confirmed",
                "local_source_checkout_found": True,
                "local_source_root": "projects/ready",
                "blockers": [],
            },
        ],
    }


class SourceRootBlockerEmitterTest(unittest.TestCase):
    def test_cluster_candidate_is_preserved_but_not_replay_ready(self) -> None:
        payload = MOD.build_payload(
            fixture_report(),
            input_path=REAL_LOCATOR,
            repo_root=ROOT,
            occurred_at="2026-05-05T00:00:00+00:00",
        )

        by_id = {row["finding_id"]: row for row in payload["rows"]}
        row = by_id["38333"]
        self.assertEqual(row["blocker_status"], MOD.STATUS_BLOCKED_CLUSTER)
        self.assertEqual(row["candidate"]["repo"], "https://github.com/the-standard/smart-vault")
        self.assertEqual(row["candidate"]["commit"], "c6837d4a296fe8a6e4bb5e0280a66d6eb8a40361")
        self.assertEqual(row["candidate"]["source_root"], "contracts")
        self.assertEqual(row["candidate"]["status"], "cluster_inferred_non_replay_ready")
        self.assertFalse(row["candidate"]["replay_ready"])
        self.assertFalse(row["source_replay_ready"])
        self.assertEqual(row["source_root_acquisition_plan"]["schema"], MOD.PLAN_SCHEMA)
        self.assertTrue(row["source_root_acquisition_plan"]["candidate_confirmation_required"])
        self.assertIn("SmartVaultV4.sol", row["source_root_acquisition_plan"]["anchor_hints"])
        self.assertEqual(
            row["kg_row"]["verification"]["commands"],
            row["source_root_acquisition_plan"]["local_verification_commands"],
        )
        self.assertIn("candidate_replay_ready=false", row["kg_row"]["evidence"])
        plan = row["source_root_acquisition_plan"]
        self.assertEqual(plan["schema"], MOD.ACTIONABILITY_SCHEMA)
        self.assertEqual(plan["state"], "blocked_pending_exact_source_acquisition")
        self.assertTrue(plan["candidate_confirmation_required"])
        self.assertFalse(plan["candidate_is_replay_ready"])
        self.assertEqual(plan["next_commands"], plan["local_verification_commands"])
        self.assertIn("exact-row confirmation that the candidate tuple is the reviewed source", plan["missing_criteria"])
        self.assertEqual(plan["candidate_hints"]["candidate"]["commit"], "c6837d4a296fe8a6e4bb5e0280a66d6eb8a40361")
        self.assertIn("SmartVaultV4.sol", plan["anchor_hints"])
        self.assertIn("SmartVaultYieldManager.sol", plan["anchor_hints"])
        self.assertIn(
            "exact_reviewed_source_report_or_metadata_for_this_solodit_row",
            plan["missing_inputs"],
        )
        self.assertTrue(
            any("cluster-inferred candidate is confirmed" in item for item in plan["confirmation_criteria"])
        )
        self.assertTrue(
            any("make project-source-root-readiness WS=<workspace> JSON=1" == command for command in plan["local_verification_commands"])
        )
        self.assertEqual(row["kg_row"]["verification"]["commands"], plan["local_verification_commands"])
        self.assertFalse(row["kg_row"]["verification"]["passed"])

    def test_unresolved_row_preserves_exact_blockers(self) -> None:
        payload = MOD.build_payload(
            fixture_report(),
            input_path=REAL_LOCATOR,
            repo_root=ROOT,
            occurred_at="2026-05-05T00:00:00+00:00",
        )

        row = {row["finding_id"]: row for row in payload["rows"]}["36418"]
        self.assertEqual(row["blocker_status"], MOD.STATUS_BLOCKED_UNRESOLVED)
        self.assertEqual(
            row["exact_blockers"],
            [
                "No local GitHub URL, commit, tag, or checkout found for the Pashov GainsNetwork May row.",
                "Exact repo and reviewed commit/tag remain required before source replay.",
            ],
        )
        self.assertEqual(row["candidate"]["status"], "no_candidate")
        self.assertFalse(row["source_root_acquisition_plan"]["candidate_confirmation_required"])
        self.assertIn("DecreasePositionSize", row["source_root_acquisition_plan"]["anchor_hints"])
        self.assertIn("No candidate repo, commit/tag, or source root", row["kg_row"]["evidence"])
        plan = row["source_root_acquisition_plan"]
        self.assertFalse(plan["candidate_confirmation_required"])
        self.assertEqual(plan["state"], "blocked_pending_exact_source_acquisition")
        self.assertIn("exact_repo_url_from_the_reviewed_row", plan["missing_inputs"])
        self.assertIn("local_checkout_path_containing_the_vulnerable_source_tree", plan["missing_inputs"])
        self.assertIn("exact reviewed repo URL", plan["missing_criteria"])
        self.assertEqual(plan["candidate_hints"]["candidate"]["status"], "no_candidate")
        self.assertTrue(any("PositionSize" in hint for hint in plan["anchor_hints"]))
        self.assertTrue(
            any(command.startswith("rg -n ") and "<exact-source-report-or-local-metadata>" in command for command in plan["local_verification_commands"])
        )

    def test_payload_is_offline_and_never_claims_replay_readiness(self) -> None:
        payload = MOD.build_payload(
            fixture_report(),
            input_path=REAL_LOCATOR,
            repo_root=ROOT,
            occurred_at="2026-05-05T00:00:00+00:00",
            extra_searched_paths=["/Users/wolf/Downloads"],
            extra_commands_run=["rg --files /Users/wolf/Downloads | rg '/SmartVaultV4\\.sol$'"],
        )

        self.assertTrue(payload["offline"])
        self.assertFalse(payload["network_used"])
        self.assertFalse(payload["llm_dispatch_ran"])
        self.assertFalse(payload["source_replay_performed"])
        self.assertEqual(payload["source_replay_ready_count"], 0)
        self.assertFalse(payload["promotion_claim_allowed"])
        self.assertEqual(payload["row_count"], 2)
        self.assertEqual(payload["skipped_exact_source_root_count"], 1)
        self.assertTrue(all(row["source_replay_ready"] is False for row in payload["rows"]))
        self.assertTrue(all(row["candidate"]["replay_ready"] is False for row in payload["rows"]))
        self.assertTrue(all(row["source_root_acquisition_plan"]["candidate_is_replay_ready"] is False for row in payload["rows"]))
        self.assertTrue(all("searched_paths" in row["source_root_acquisition_plan"] for row in payload["rows"]))
        self.assertTrue(all("next_commands" in row["source_root_acquisition_plan"] for row in payload["rows"]))
        self.assertIn("/Users/wolf/Downloads", payload["searched_paths"])
        self.assertTrue(any("/Users/wolf/Downloads" in command for command in payload["commands_already_run"]))
        self.assertNotIn("immutable_ready", json.dumps(payload["rows"]).lower())

    def test_emitted_kg_rows_validate_against_knowledge_gap_log_rules(self) -> None:
        payload = MOD.build_payload(
            fixture_report(),
            input_path=REAL_LOCATOR,
            repo_root=ROOT,
            occurred_at="2026-05-05T00:00:00+00:00",
        )

        for row in payload["kg_rows"]:
            self.assertEqual(KG.validate_row(KG.normalize_row(row), repo=ROOT, ledger=ROOT / "reports" / "knowledge_gaps.jsonl"), [])

    def test_real_locator_emits_three_blocked_rows(self) -> None:
        report = json.loads(REAL_LOCATOR.read_text(encoding="utf-8"))
        payload = MOD.build_payload(
            report,
            input_path=REAL_LOCATOR,
            repo_root=ROOT,
            occurred_at="2026-05-05T00:00:00+00:00",
        )

        self.assertEqual(payload["row_count"], 3)
        self.assertEqual(payload["source_replay_ready_count"], 0)
        self.assertEqual(payload["summary"]["cluster_inferred_candidate_count"], 2)
        self.assertEqual(payload["summary"]["unresolved_no_candidate_count"], 1)
        self.assertEqual(
            sorted(row["finding_id"] for row in payload["rows"]),
            ["33463", "36418", "38333"],
        )
        self.assertTrue(
            all("source_root_acquisition_plan" in row for row in payload["rows"])
        )
        for row in payload["rows"]:
            plan = row["source_root_acquisition_plan"]
            self.assertEqual(plan["searched_paths"], report["searched_roots"])
            self.assertTrue(plan["commands_already_run"])
            self.assertTrue(plan["searched_artifact_paths"])
            self.assertEqual(plan["next_commands"], plan["local_verification_commands"])

    def test_cli_can_write_canonical_kg_jsonl(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "source_root_blockers.jsonl"
            result = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--input",
                    str(REAL_LOCATOR),
                    "--out",
                    str(out),
                    "--jsonl",
                    "--repo-root",
                    str(ROOT),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            rows = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(rows), 3)
            self.assertTrue(all(row["schema"] == MOD.KG_SCHEMA for row in rows))
            self.assertIn("replay_ready=0", result.stdout)


if __name__ == "__main__":
    unittest.main()
