from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "outcome-lesson-gate.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("outcome_lesson_gate_test", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def inventory_for(*predicates: tuple[str, str]) -> dict:
    return {
        "schema": "auditooor.lesson_enforcement_inventory.v1",
        "schema_version": "1.0",
        "offline_only": True,
        "network_access": False,
        "enforcement_rows": [
            {
                "predicate": predicate,
                "enforcement_level": level,
                "gate_phase": "test",
                "lesson_count": 1,
                "examples": [],
            }
            for predicate, level in predicates
        ],
        "lessons": [],
    }


class OutcomeLessonGateTests(unittest.TestCase):
    def test_hard_predicate_fails_with_blocker_and_proof_obligation(self) -> None:
        tool = load_tool()
        active = {
            "economic_viability_missing": "hard_pre_poc",
            "protocol_bug_amplified_by_mev": "advisory_worker_context",
        }
        records = [{"source_ref": "draft.md", "text": "This lacks attacker profit; gas cost exceeds value."}]

        payload = tool.evaluate_records(records, active_levels=active, max_matches=10)

        self.assertEqual(payload["status"], "fail")
        self.assertEqual(len(payload["blockers"]), 1)
        self.assertEqual(payload["blockers"][0]["predicate"], "economic_viability_missing")
        self.assertTrue(payload["blockers"][0]["suggested_proof_obligations"])

    def test_advisory_mev_amplification_warns_without_blocking(self) -> None:
        tool = load_tool()
        active = {
            "protocol_bug_amplified_by_mev": "advisory_worker_context",
            "ambient_mev_not_protocol_bug": "hard_pre_poc",
        }
        records = [
            {
                "source_ref": "draft.md",
                "text": "MEV amplifies a protocol bug: not merely MEV; the contract root cause allows stale settlement.",
            }
        ]

        payload = tool.evaluate_records(records, active_levels=active, max_matches=10)

        self.assertEqual(payload["status"], "warn")
        self.assertEqual(payload["blockers"], [])
        self.assertEqual(payload["warnings"][0]["predicate"], "protocol_bug_amplified_by_mev")

    def test_positive_payout_claim_is_not_surfaced(self) -> None:
        tool = load_tool()
        active = {"low_severity_cap_triggered": "hard_pre_submit"}
        records = [
            {
                "source_ref": "draft.md",
                "text": "Paid $9000 bounty.\nSeverity is capped to Low because no material loss.",
            }
        ]

        payload = tool.evaluate_records(records, active_levels=active, max_matches=10)
        serialized = json.dumps(payload).lower()

        self.assertEqual(payload["status"], "fail")
        self.assertEqual(payload["summary"]["positive_reward_claim_lines_suppressed"], 1)
        self.assertNotIn("paid $9000", serialized)
        self.assertNotIn("9000 bounty", serialized)

    def test_output_is_bounded(self) -> None:
        tool = load_tool()
        active = {
            "economic_viability_missing": "hard_pre_poc",
            "generic_dos_scope_risk": "hard_pre_submit",
            "low_severity_cap_triggered": "hard_pre_submit",
        }
        records = [
            {"source_ref": "a.md", "text": "lacks attacker profit and gas cost exceeds value"},
            {"source_ref": "b.md", "text": "generic DoS scope risk; temporary DoS is out of scope"},
            {"source_ref": "c.md", "text": "severity is capped to Low because bounded impact"},
        ]

        payload = tool.evaluate_records(records, active_levels=active, max_matches=2)

        self.assertEqual(payload["status"], "fail")
        self.assertEqual(len(payload["matched_predicates"]), 2)
        self.assertTrue(payload["summary"]["truncated"])

    def test_build_gate_consumes_inventory_and_workspace_text(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inv = root / "inventory.json"
            inv.write_text(
                json.dumps(
                    inventory_for(
                        ("admin_or_team_action_prerequisite", "hard_pre_poc"),
                        ("protocol_bug_amplified_by_mev", "advisory_worker_context"),
                    )
                ),
                encoding="utf-8",
            )
            draft = root / "draft.md"
            draft.write_text("Requires admin action; onlyOwner team action is a prerequisite.", encoding="utf-8")

            payload = tool.build_gate(draft_paths=[draft], inventory_path=inv)

        self.assertEqual(payload["schema"], tool.SCHEMA)
        self.assertTrue(payload["offline_only"])
        self.assertFalse(payload["network_access"])
        self.assertFalse(payload["submit_ready"])
        self.assertEqual(payload["status"], "fail")
        self.assertEqual(payload["blockers"][0]["predicate"], "admin_or_team_action_prerequisite")

    def test_build_gate_surfaces_source_inventory_coverage_warnings(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_inventory = root / "lesson_source_inventory.json"
            source_inventory.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.lesson_source_inventory.v1",
                        "schema_version": "1.0",
                        "status": "partial",
                        "summary": {
                            "sources_seen": 3,
                            "default_enforcement_sources": 2,
                            "promotion_candidate_sources": 1,
                        },
                        "coverage_blockers": [
                            {
                                "source_kind": "case_study",
                                "path": "case_study",
                                "lesson_candidates": 17,
                                "admissibility": "candidate_hard_requires_review",
                                "gate_role": "candidate_lesson_promotion_queue",
                                "reason": "case studies require promotion before hard blocking reports",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            draft = root / "draft.md"
            draft.write_text("Clean draft text without known lesson trigger.", encoding="utf-8")

            payload = tool.build_gate(draft_paths=[draft], source_inventory_path=source_inventory)

        self.assertEqual(payload["status"], "pass")
        self.assertEqual(payload["summary"]["inventory_coverage_warning_count"], 1)
        self.assertEqual(payload["inventory_coverage_warnings"][0]["source_kind"], "case_study")
        self.assertEqual(payload["source_inventory"]["coverage_blocker_count"], 1)

    def test_explicit_inventory_bounds_active_predicates(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inv = root / "inventory.json"
            inv.write_text(
                json.dumps(inventory_for(("protocol_bug_amplified_by_mev", "advisory_worker_context"))),
                encoding="utf-8",
            )
            draft = root / "draft.md"
            draft.write_text("This lacks attacker profit; gas cost exceeds value.", encoding="utf-8")

            payload = tool.build_gate(draft_paths=[draft], inventory_path=inv)

        self.assertEqual(payload["status"], "pass")
        self.assertEqual(payload["matched_predicates"], [])

    def test_missing_explicit_inventory_does_not_broaden_to_catalog(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            missing = root / "missing-inventory.json"
            draft = root / "draft.md"
            draft.write_text("This lacks attacker profit; gas cost exceeds value.", encoding="utf-8")

            payload = tool.build_gate(draft_paths=[draft], inventory_path=missing)

        self.assertEqual(payload["status"], "fail")
        self.assertEqual(payload["matched_predicates"], [])
        self.assertEqual(payload["blockers"][0]["code"], "lesson_inventory_unavailable")
        self.assertEqual(payload["inventory"]["source"], "inventory_load_failed")
        self.assertIn("inventory load failed", payload["inventory"]["warnings"][0])

    def test_malformed_explicit_inventory_fails_structurally_without_traceback(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            malformed = root / "inventory.json"
            malformed.write_text("[]", encoding="utf-8")
            draft = root / "draft.md"
            draft.write_text("No known lesson trigger.", encoding="utf-8")

            payload = tool.build_gate(draft_paths=[draft], inventory_path=malformed)

        self.assertEqual(payload["status"], "fail")
        self.assertEqual(payload["matched_predicates"], [])
        self.assertEqual(payload["blockers"][0]["code"], "lesson_inventory_unavailable")
        self.assertEqual(payload["inventory"]["source"], "inventory_invalid_shape")

    def test_empty_explicit_inventory_fails_closed(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            empty = root / "inventory.json"
            empty.write_text(json.dumps(inventory_for()), encoding="utf-8")
            draft = root / "draft.md"
            draft.write_text("No known lesson trigger.", encoding="utf-8")

            payload = tool.build_gate(draft_paths=[draft], inventory_path=empty)

        self.assertEqual(payload["status"], "fail")
        self.assertEqual(payload["matched_predicates"], [])
        self.assertEqual(payload["blockers"][0]["code"], "lesson_inventory_empty")

    def test_candidate_json_triggers_admin_and_economic_blockers(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            candidate = root / "candidate.json"
            candidate.write_text(
                json.dumps(
                    {
                        "candidate_id": "lead-1",
                        "attacker_role": "external user after team setup",
                        "prerequisites": ["owner must enable the market", "multisig must seed liquidity"],
                        "impact_claim": "Attacker drains user funds for profit.",
                        "evidence_class": "candidate",
                        "production_path": "production contracts",
                        "economics": {},
                        "oos_flags": [],
                    }
                ),
                encoding="utf-8",
            )

            payload = tool.build_gate(candidate_json_path=candidate)

        self.assertEqual(payload["status"], "fail")
        self.assertEqual(payload["summary"]["candidate_record_count"], 1)
        predicates = {row["predicate"] for row in payload["blockers"]}
        self.assertIn("admin_or_team_action_prerequisite", predicates)
        self.assertIn("economic_viability_missing", predicates)
        self.assertTrue(all(row["input_kind"] == "candidate_json" for row in payload["blockers"]))
        self.assertIn("candidate_admin_or_team_prerequisite", json.dumps(payload["blockers"]))

    def test_candidate_json_respects_active_inventory_bounds(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inv = root / "inventory.json"
            inv.write_text(
                json.dumps(inventory_for(("documented_mechanics_no_stronger_intent", "hard_pre_submit"))),
                encoding="utf-8",
            )
            candidate = root / "candidate.json"
            candidate.write_text(
                json.dumps(
                    {
                        "candidate_id": "lead-docs",
                        "prerequisites": ["owner action required"],
                        "impact_claim": "This follows documented mechanics.",
                        "evidence_class": "docs-only documented behavior",
                        "intent_delta": False,
                    }
                ),
                encoding="utf-8",
            )

            payload = tool.build_gate(candidate_json_path=candidate, inventory_path=inv)

        self.assertEqual(payload["status"], "fail")
        self.assertEqual([row["predicate"] for row in payload["blockers"]], ["documented_mechanics_no_stronger_intent"])
        self.assertEqual(payload["blockers"][0]["candidate_fields"][0], "evidence_class")

    def test_candidate_json_can_warn_for_advisory_frontrun_only_predicate(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inv = root / "inventory.json"
            inv.write_text(
                json.dumps(inventory_for(("ambient_mev_not_protocol_bug", "advisory_worker_context"))),
                encoding="utf-8",
            )
            candidate = root / "candidate.json"
            candidate.write_text(
                json.dumps(
                    {
                        "candidate_id": "lead-mev",
                        "attacker_role": "searcher",
                        "production_path": "sandwich only through mempool ordering",
                        "evidence_class": "ambient MEV",
                        "oos_flags": {"sandwich_only": True},
                    }
                ),
                encoding="utf-8",
            )

            payload = tool.build_gate(candidate_json_path=candidate, inventory_path=inv)

        self.assertEqual(payload["status"], "warn")
        self.assertEqual(payload["blockers"], [])
        self.assertEqual(payload["warnings"][0]["predicate"], "ambient_mev_not_protocol_bug")
        self.assertEqual(payload["warnings"][0]["input_kind"], "candidate_json")

    def test_candidate_json_triggers_low_severity_cap(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inv = root / "inventory.json"
            inv.write_text(
                json.dumps(inventory_for(("low_severity_cap_triggered", "hard_pre_submit"))),
                encoding="utf-8",
            )
            candidate = root / "candidate.json"
            candidate.write_text(
                json.dumps(
                    {
                        "lead_id": "lead-low",
                        "impact_claim": "No material loss; dust only bounded impact.",
                        "evidence_class": "severity cap",
                        "oos_flags": {"low_severity_cap": True},
                        "severity": "High",
                    }
                ),
                encoding="utf-8",
            )

            payload = tool.build_gate(candidate_json_path=candidate, inventory_path=inv)

        self.assertEqual(payload["status"], "fail")
        self.assertEqual(payload["blockers"][0]["predicate"], "low_severity_cap_triggered")
        self.assertIn("candidate_low_severity_cap", payload["blockers"][0]["matched_signals"])

    def test_proof_relevant_candidate_with_current_refs_lesson_and_repro_passes(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            aud = ws / ".auditooor"
            (ws / "src").mkdir(parents=True)
            (ws / "test").mkdir()
            aud.mkdir()
            (ws / "src" / "Vault.sol").write_text("contract Vault {}\n", encoding="utf-8")
            (ws / "test" / "Vault.t.sol").write_text("contract VaultTest {}\n", encoding="utf-8")
            queue = aud / "exploit_queue.source_mined.json"
            queue.write_text(
                json.dumps(
                    {
                        "queue": [
                            {
                                "lead_id": "OK",
                                "proof_relevant": True,
                                "source_refs": ["src/Vault.sol:1"],
                                "lesson_pack_refs": ["case_study/R82_detector_gap_audit.md:1"],
                                "proof_path": "test/Vault.t.sol",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            payload = tool.build_gate(candidate_json_path=queue)

        self.assertEqual(payload["status"], "pass")
        self.assertEqual(payload["blockers"], [])
        proof_row = payload["proof_relevance"]["rows"][0]
        self.assertEqual(proof_row["decision"], "proof_relevant_pass")
        self.assertTrue(proof_row["has_current_source_refs"])
        self.assertTrue(proof_row["has_source_backed_lesson_linkage"])
        self.assertTrue(proof_row["has_concrete_reproduction_evidence"])

    def test_proof_relevant_missing_source_ref_blocks(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            aud = ws / ".auditooor"
            (ws / "test").mkdir(parents=True)
            aud.mkdir()
            (ws / "test" / "Vault.t.sol").write_text("contract VaultTest {}\n", encoding="utf-8")
            queue = aud / "exploit_queue.source_mined.json"
            queue.write_text(
                json.dumps(
                    {
                        "queue": [
                            {
                                "lead_id": "MISSING",
                                "proof_relevant": True,
                                "lesson_pack_refs": ["case_study/R82_detector_gap_audit.md:1"],
                                "proof_path": "test/Vault.t.sol",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            payload = tool.build_gate(candidate_json_path=queue)

        self.assertEqual(payload["status"], "fail")
        codes = {row["code"] for row in payload["blockers"]}
        self.assertIn("proof_relevance_missing_source_refs", codes)
        proof_row = payload["proof_relevance"]["rows"][0]
        self.assertIn("missing_source_refs", proof_row["rejection_reasons"])

    def test_explicit_non_proof_exploit_queue_row_is_not_a_blocker(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            aud = ws / ".auditooor"
            aud.mkdir(parents=True)
            queue = aud / "exploit_queue.source_mined.json"
            queue.write_text(
                json.dumps(
                    {
                        "queue": [
                            {
                                "lead_id": "ADVISORY-NON-PROOF",
                                "proof_relevant": False,
                                "proof_status": "needs_source",
                                "source_refs": ["<workspace>/.auditooor/hacker_brief.md"],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            payload = tool.build_gate(candidate_json_path=queue)

        self.assertEqual(payload["status"], "pass")
        self.assertEqual(payload["blockers"], [])
        self.assertEqual(payload["proof_relevance"]["rows"], [])

    def test_unproved_skipped_non_proof_row_is_not_misread_as_proved(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            aud = ws / ".auditooor"
            aud.mkdir(parents=True)
            queue = aud / "exploit_queue.source_mined.json"
            queue.write_text(
                json.dumps(
                    {
                        "queue": [
                            {
                                "lead_id": "UNPROVED-NON-PROOF",
                                "proof_relevance": False,
                                "proof_relevance_status": "skipped_non_proof",
                                "proof_status": "unproved",
                                "source_refs": ["src/Vault.sol:1"],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            payload = tool.build_gate(candidate_json_path=queue)

        self.assertEqual(payload["status"], "pass")
        self.assertEqual(payload["blockers"], [])
        self.assertEqual(payload["proof_relevance"]["rows"], [])

    def test_not_candidate_exploit_queue_row_is_not_proof_relevant(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            aud = ws / ".auditooor"
            aud.mkdir(parents=True)
            queue = aud / "exploit_queue.source_mined.json"
            queue.write_text(
                json.dumps(
                    {
                        "queue": [
                            {
                                "lead_id": "ADVISORY-NOT-CANDIDATE",
                                "proof_status": "not_candidate",
                                "status": "advisory_not_candidate",
                                "source_refs": ["src/Vault.sol:1"],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            payload = tool.build_gate(candidate_json_path=queue)

        self.assertEqual(payload["status"], "pass")
        self.assertEqual(payload["blockers"], [])
        self.assertEqual(payload["proof_relevance"]["rows"], [])

    def test_terminal_killed_exploit_queue_row_is_not_proof_relevant(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            aud = ws / ".auditooor"
            aud.mkdir(parents=True)
            queue = aud / "exploit_queue.source_mined.json"
            queue.write_text(
                json.dumps(
                    {
                        "queue": [
                            {
                                "lead_id": "KILLED-ROW",
                                "proof_status": "killed",
                                "source_mined_proof_status": "killed",
                                "quality_gate_status": "closed_negative_operator_review",
                                "learning_route": "drop",
                                "source_refs": ["src/Vault.sol:1"],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            payload = tool.build_gate(candidate_json_path=queue)

        self.assertEqual(payload["status"], "pass")
        self.assertEqual(payload["blockers"], [])
        self.assertEqual(payload["proof_relevance"]["rows"], [])

    def test_proof_relevant_stale_workspace_ref_blocks(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            aud = ws / ".auditooor"
            (ws / "test").mkdir(parents=True)
            aud.mkdir()
            (ws / "test" / "Vault.t.sol").write_text("contract VaultTest {}\n", encoding="utf-8")
            queue = aud / "exploit_queue.source_mined.json"
            queue.write_text(
                json.dumps(
                    {
                        "queue": [
                            {
                                "lead_id": "STALE",
                                "proof_relevant": True,
                                "source_refs": ["src/Missing.sol:1"],
                                "lesson_pack_refs": ["case_study/R82_detector_gap_audit.md:1"],
                                "proof_path": "test/Vault.t.sol",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            payload = tool.build_gate(candidate_json_path=queue)

        self.assertEqual(payload["status"], "fail")
        codes = {row["code"] for row in payload["blockers"]}
        self.assertIn("proof_relevance_stale_workspace_source_refs", codes)
        proof_row = payload["proof_relevance"]["rows"][0]
        self.assertIn("stale_workspace_source_refs", proof_row["rejection_reasons"])
        self.assertEqual(proof_row["stale_source_refs"][0]["reason"], "source_file_missing")

    def test_proof_relevant_missing_reproduction_evidence_blocks(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            aud = ws / ".auditooor"
            (ws / "src").mkdir(parents=True)
            aud.mkdir()
            (ws / "src" / "Vault.sol").write_text("contract Vault {}\n", encoding="utf-8")
            queue = aud / "exploit_queue.source_mined.json"
            queue.write_text(
                json.dumps(
                    {
                        "queue": [
                            {
                                "lead_id": "NO-REPRO",
                                "proof_relevant": True,
                                "source_refs": ["src/Vault.sol:1"],
                                "lesson_pack_refs": ["case_study/R82_detector_gap_audit.md:1"],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            payload = tool.build_gate(candidate_json_path=queue)

        self.assertEqual(payload["status"], "fail")
        codes = {row["code"] for row in payload["blockers"]}
        self.assertIn("proof_relevance_proof_without_runnable_harness_evidence", codes)
        self.assertIn(
            "proof_without_runnable_harness_evidence",
            payload["proof_relevance"]["rows"][0]["rejection_reasons"],
        )

    def test_advisory_only_candidate_marks_lesson_blocker_as_warning(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            aud = ws / ".auditooor"
            (ws / "src").mkdir(parents=True)
            (ws / "test").mkdir()
            aud.mkdir()
            (ws / "src" / "Vault.sol").write_text("contract Vault {}\n", encoding="utf-8")
            (ws / "test" / "Vault.t.sol").write_text("contract VaultTest {}\n", encoding="utf-8")
            queue = aud / "exploit_queue.source_mined.json"
            queue.write_text(
                json.dumps(
                    {
                        "queue": [
                            {
                                "lead_id": "ADVISORY",
                                "advisory_only": True,
                                "proof_relevant": True,
                                "source_refs": ["src/Vault.sol:1"],
                                "proof_path": "test/Vault.t.sol",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            payload = tool.build_gate(candidate_json_path=queue)

        self.assertEqual(payload["status"], "warn")
        self.assertEqual(payload["blockers"], [])
        codes = {row["code"] for row in payload["warnings"]}
        self.assertIn("proof_relevance_missing_source_backed_lesson_linkage", codes)
        proof_row = payload["proof_relevance"]["rows"][0]
        self.assertEqual(proof_row["decision"], "advisory_only")
        self.assertIn("advisory_only_row", proof_row["advisory_reasons"])
        self.assertIn("missing_source_backed_lesson_linkage", proof_row["advisory_reasons"])

    def test_cli_strict_fails_on_proof_relevance_blocker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            aud = ws / ".auditooor"
            (ws / "test").mkdir(parents=True)
            aud.mkdir()
            (ws / "test" / "Vault.t.sol").write_text("contract VaultTest {}\n", encoding="utf-8")
            queue = aud / "exploit_queue.source_mined.json"
            queue.write_text(
                json.dumps(
                    {
                        "queue": [
                            {
                                "lead_id": "STRICT-BAD",
                                "proof_relevant": True,
                                "lesson_pack_refs": ["case_study/R82_detector_gap_audit.md:1"],
                                "proof_path": "test/Vault.t.sol",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            proc = subprocess.run(
                [sys.executable, str(TOOL), "--candidate-json", str(queue), "--format", "json", "--strict"],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

        self.assertEqual(proc.returncode, 1, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["status"], "fail")
        self.assertIn("missing_source_refs", payload["proof_relevance"]["rows"][0]["rejection_reasons"])

    def test_reward_stream_future_emissions_only_blocks(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inv = root / "inventory.json"
            inv.write_text(
                json.dumps(
                    inventory_for(("future_reward_eligibility_not_accrued_reward_loss", "hard_pre_poc"))
                ),
                encoding="utf-8",
            )
            draft = root / "draft.md"
            draft.write_text(
                "The PoC demonstrates late entrants only participate in future "
                "reward-stream emissions, but it does not prove accrued reward dilution.",
                encoding="utf-8",
            )

            payload = tool.build_gate(draft_paths=[draft], inventory_path=inv)

        self.assertEqual(payload["status"], "fail")
        self.assertEqual(
            payload["blockers"][0]["predicate"],
            "future_reward_eligibility_not_accrued_reward_loss",
        )
        self.assertIn("reward funding time", payload["blockers"][0]["suggested_proof_obligations"][0])

    def test_reward_stream_accrued_dilution_proof_does_not_block(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inv = root / "inventory.json"
            inv.write_text(
                json.dumps(
                    inventory_for(("future_reward_eligibility_not_accrued_reward_loss", "hard_pre_poc"))
                ),
                encoding="utf-8",
            )
            draft = root / "draft.md"
            draft.write_text(
                "The reward-token finding identifies funding time T0 and attacker entry T1. "
                "A before/after accounting delta proves rewards accrued before entry are "
                "redistributed to the attacker.",
                encoding="utf-8",
            )

            payload = tool.build_gate(draft_paths=[draft], inventory_path=inv)

        self.assertEqual(payload["status"], "pass")
        self.assertEqual(payload["blockers"], [])

    def test_wave16_promoted_generic_dos_scope_risk_blocks_hard_pre_submit(self) -> None:
        """Wave-16 promotion: generic_dos_scope_risk in enforcement inventory blocks paste-ready promotion."""
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inv = root / "inventory.json"
            inv.write_text(
                json.dumps(inventory_for(("generic_dos_scope_risk", "hard_pre_submit"))),
                encoding="utf-8",
            )
            draft = root / "draft.md"
            draft.write_text(
                "Impact: generic DoS via gas griefing; temporary denial of service; scope risk.",
                encoding="utf-8",
            )
            payload = tool.build_gate(draft_paths=[draft], inventory_path=inv)

        self.assertEqual(payload["status"], "fail")
        blocker_predicates = [b["predicate"] for b in payload["blockers"]]
        self.assertIn("generic_dos_scope_risk", blocker_predicates)
        self.assertIn(
            "Prove specific in-scope protocol impact beyond generic DoS",
            payload["blockers"][0]["suggested_proof_obligations"][0],
        )

    def test_wave16_promoted_ambient_mev_blocks_hard_pre_poc_via_text(self) -> None:
        """Wave-16 promotion: ambient_mev_not_protocol_bug in enforcement inventory blocks pre-PoC."""
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inv = root / "inventory.json"
            inv.write_text(
                json.dumps(inventory_for(("ambient_mev_not_protocol_bug", "hard_pre_poc"))),
                encoding="utf-8",
            )
            draft = root / "draft.md"
            draft.write_text(
                "This is not a protocol bug; it is ambient MEV from ordinary mempool ordering only.",
                encoding="utf-8",
            )
            payload = tool.build_gate(draft_paths=[draft], inventory_path=inv)

        self.assertEqual(payload["status"], "fail")
        self.assertEqual(payload["blockers"][0]["predicate"], "ambient_mev_not_protocol_bug")
        self.assertIn(
            "Prove a protocol invariant violation",
            payload["blockers"][0]["suggested_proof_obligations"][0],
        )

    def test_wave16_enforcement_inventory_loads_promoted_predicates(self) -> None:
        """Wave-16+ promotion: the live inventory covers the hard lesson predicates."""
        tool = load_tool()
        compiler = tool._load_compiler()
        from pathlib import Path as _P
        inv_path = _P(__file__).resolve().parents[2] / ".auditooor" / "lesson_enforcement_inventory.json"
        active, meta, warns = tool.load_inventory(inv_path, compiler)
        self.assertIn("generic_dos_scope_risk", active)
        self.assertIn("ambient_mev_not_protocol_bug", active)
        self.assertIn("economic_viability_missing", active)
        self.assertIn("future_reward_eligibility_not_accrued_reward_loss", active)
        self.assertEqual(len(warns), 0)
        # economic_viability_missing now has 3 examples (was 1 before wave-16)
        import json as _json
        inv = _json.loads(inv_path.read_text())
        ev_row = next(r for r in inv["enforcement_rows"] if r["predicate"] == "economic_viability_missing")
        self.assertGreaterEqual(ev_row["lesson_count"], 3)

    def test_cli_prints_json_and_strict_fails_only_on_hard_blocker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            draft = root / "draft.md"
            draft.write_text("Ambient MEV only: normal arbitrage is not a protocol bug.", encoding="utf-8")

            proc = subprocess.run(
                [sys.executable, str(TOOL), "--draft", str(draft), "--format", "json", "--strict"],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

        self.assertEqual(proc.returncode, 1, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["status"], "fail")
        self.assertEqual(payload["blockers"][0]["predicate"], "ambient_mev_not_protocol_bug")


if __name__ == "__main__":
    unittest.main()
