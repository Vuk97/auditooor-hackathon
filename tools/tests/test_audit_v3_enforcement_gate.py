from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "audit-v3-enforcement-gate.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("audit_v3_enforcement_gate", TOOL)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load audit-v3-enforcement-gate.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _future_date(days: int = 90) -> str:
    return (date.today() + timedelta(days=days)).isoformat()


def _past_date(days: int = 1) -> str:
    return (date.today() - timedelta(days=days)).isoformat()


class AuditV3EnforcementGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="audit-v3-gate-")
        self.root = Path(self.tmp.name)
        (self.root / "reports").mkdir()
        (self.root / ".auditooor").mkdir()
        self.tool = _load_tool()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def write_json(self, rel: str, payload: dict) -> None:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload), encoding="utf-8")

    def write_clean_artifacts(self) -> None:
        self.write_json(
            "reports/v3_roadmap_progress_report.json",
            {
                "categories": {
                    category: {"status": "met"}
                    for category in self.tool.DEFAULT_BLOCKING_CATEGORIES
                },
                "blocking_unmet_categories": [],
            },
        )
        self.write_json(
            ".auditooor/hackerman_sidecar_coverage_report.json",
            {"status": "ok", "blockers": [], "sidecars": []},
        )
        self.write_json(
            ".auditooor/audit_workflow_coverage_map.json",
            {
                "schema": "auditooor.audit_workflow_coverage_map.v1",
                "concept_summary": {
                    concept_id: {"label": concept_id, "present": 1, "unknown": 0, "missing": 0}
                    for concept_id in self.tool.REQUIRED_WORKFLOW_CONCEPTS
                },
            },
        )
        self.write_json(".auditooor/lesson_source_inventory.json", {"coverage_blockers": []})
        self.write_json(".auditooor/v3_provider_campaign_completeness_gate.json", {"status": "pass"})
        anti_pattern_dir = self.root / "obsidian-vault" / "anti-patterns"
        anti_pattern_dir.mkdir(parents=True, exist_ok=True)
        (anti_pattern_dir / "sample.md").write_text(
            "---\nrecommendation: sample\nsample_size: 1\nconfidence: medium\ncounter_examples: 0\n---\n",
            encoding="utf-8",
        )

    def write_partial_progress(self, category_id: str) -> None:
        """Make one roadmap category partial while leaving others met."""
        progress = json.loads((self.root / "reports/v3_roadmap_progress_report.json").read_text())
        progress["categories"][category_id] = {"status": "partial"}
        progress["blocking_unmet_categories"] = [
            {"category_id": category_id, "reason": f"{category_id} partially met"}
        ]
        self.write_json("reports/v3_roadmap_progress_report.json", progress)

    def write_documented_blockers(self, rel: str, entries: list[dict]) -> Path:
        path = self.root / rel
        path.write_text(
            json.dumps({"schema": "auditooor.v3_documented_blockers.v1", "entries": entries}),
            encoding="utf-8",
        )
        return path

    # ------------------------------------------------------------------ #
    # Existing behavior preserved                                          #
    # ------------------------------------------------------------------ #

    def test_passes_when_all_required_artifacts_are_clean(self) -> None:
        self.write_clean_artifacts()
        gate = self.tool.build_gate(self.root)
        self.assertEqual(gate["verdict"], "pass")
        self.assertEqual(gate["blockers"], [])

    def test_fails_on_partial_roadmap_category(self) -> None:
        self.write_clean_artifacts()
        progress = json.loads((self.root / "reports/v3_roadmap_progress_report.json").read_text())
        progress["categories"]["lesson_gates"] = {"status": "partial"}
        progress["blocking_unmet_categories"] = [
            {"category_id": "lesson_gates", "reason": "source coverage blockers=2"}
        ]
        self.write_json("reports/v3_roadmap_progress_report.json", progress)

        gate = self.tool.build_gate(self.root)
        self.assertEqual(gate["verdict"], "fail")
        self.assertTrue(any(row["category_id"] == "lesson_gates" for row in gate["blockers"]))

    def test_fails_on_lesson_source_inventory_blockers(self) -> None:
        self.write_clean_artifacts()
        self.write_json(
            ".auditooor/lesson_source_inventory.json",
            {"coverage_blockers": [{"source_type": "agent_artifacts", "candidate_count": 50}]},
        )
        gate = self.tool.build_gate(self.root)
        self.assertEqual(gate["verdict"], "fail")
        self.assertTrue(any(row["code"] == "lesson_source_coverage_blockers" for row in gate["blockers"]))

    def test_fails_on_provider_campaign_failure(self) -> None:
        self.write_clean_artifacts()
        self.write_json(
            ".auditooor/v3_provider_campaign_completeness_gate.json",
            {"status": "fail", "blockers": [{"code": "pending"}]},
        )
        gate = self.tool.build_gate(self.root)
        self.assertEqual(gate["verdict"], "fail")
        self.assertTrue(any(row["code"] == "provider_campaign_incomplete" for row in gate["blockers"]))

    def test_fails_when_workflow_coverage_map_missing(self) -> None:
        self.write_clean_artifacts()
        (self.root / ".auditooor" / "audit_workflow_coverage_map.json").unlink()
        gate = self.tool.build_gate(self.root)
        self.assertEqual(gate["verdict"], "fail")
        self.assertTrue(any(row["code"] == "workflow_coverage_map_missing_or_unreadable" for row in gate["blockers"]))

    def test_fails_when_required_workflow_concept_is_absent(self) -> None:
        self.write_clean_artifacts()
        payload = json.loads((self.root / ".auditooor" / "audit_workflow_coverage_map.json").read_text())
        payload["concept_summary"].pop("candidate_judgment")
        self.write_json(".auditooor/audit_workflow_coverage_map.json", payload)
        gate = self.tool.build_gate(self.root)
        self.assertEqual(gate["verdict"], "fail")
        self.assertTrue(
            any(
                row["code"] == "workflow_required_concept_missing"
                and row["concept_id"] == "candidate_judgment"
                for row in gate["blockers"]
            )
        )

    def test_fails_when_severity_calibration_workflow_concept_is_absent(self) -> None:
        self.write_clean_artifacts()
        payload = json.loads((self.root / ".auditooor" / "audit_workflow_coverage_map.json").read_text())
        payload["concept_summary"].pop("severity_calibration")
        self.write_json(".auditooor/audit_workflow_coverage_map.json", payload)
        gate = self.tool.build_gate(self.root)
        self.assertEqual(gate["verdict"], "fail")
        self.assertTrue(
            any(
                row["code"] == "workflow_required_concept_missing"
                and row["concept_id"] == "severity_calibration"
                for row in gate["blockers"]
            )
        )

    def test_fails_when_required_workflow_concept_has_no_present_wiring(self) -> None:
        self.write_clean_artifacts()
        payload = json.loads((self.root / ".auditooor" / "audit_workflow_coverage_map.json").read_text())
        payload["concept_summary"]["dupe_risk"]["present"] = 0
        payload["concept_summary"]["dupe_risk"]["unknown"] = 1
        self.write_json(".auditooor/audit_workflow_coverage_map.json", payload)
        gate = self.tool.build_gate(self.root)
        self.assertEqual(gate["verdict"], "fail")
        self.assertTrue(
            any(
                row["code"] == "workflow_required_concept_not_present"
                and row["concept_id"] == "dupe_risk"
                for row in gate["blockers"]
            )
        )

    def test_fails_when_anti_pattern_corpus_empty(self) -> None:
        self.write_clean_artifacts()
        for path in (self.root / "obsidian-vault" / "anti-patterns").glob("*.md"):
            path.unlink()
        gate = self.tool.build_gate(self.root)
        self.assertEqual(gate["verdict"], "fail")
        self.assertTrue(any(row["code"] == "anti_pattern_corpus_empty" for row in gate["blockers"]))

    def test_required_category_can_be_narrowed(self) -> None:
        self.write_clean_artifacts()
        progress = json.loads((self.root / "reports/v3_roadmap_progress_report.json").read_text())
        progress["categories"]["provider_keep_verification"] = {"status": "partial"}
        self.write_json("reports/v3_roadmap_progress_report.json", progress)

        gate = self.tool.build_gate(self.root, required_categories={"sidecar_coverage"})
        self.assertEqual(gate["verdict"], "pass")

    # ------------------------------------------------------------------ #
    # New: documented-blocker mechanism                                   #
    # ------------------------------------------------------------------ #

    def test_no_documented_blockers_arg_preserves_existing_fail_behavior(self) -> None:
        """Without --documented-blockers, a partial provider category still hard-fails."""
        self.write_clean_artifacts()
        self.write_json(
            ".auditooor/v3_provider_campaign_completeness_gate.json",
            {"status": "fail", "blockers": [{"code": "no_subscription"}]},
        )
        gate = self.tool.build_gate(self.root)  # no documented_blockers_path
        self.assertEqual(gate["verdict"], "fail")
        # documented_blockers key exists but is empty (no file was passed)
        self.assertEqual(gate.get("documented_blockers", []), [])

    def test_valid_provider_documented_blocker_reclassifies_and_yields_pass_with_documented_blockers(self) -> None:
        """A valid documented-blocker entry for provider_campaign_completeness
        reclassifies the hard blocker; verdict becomes pass_with_documented_blockers."""
        self.write_clean_artifacts()
        self.write_partial_progress("provider_campaign_completeness")

        db_path = self.write_documented_blockers(
            ".auditooor/v3_documented_blockers.json",
            [
                {
                    "category_id": "provider_campaign_completeness",
                    "reason_code": "no_provider_subscription",
                    "evidence": "Kimi/MiniMax subscription cancelled 2026-05-01; no provider campaign can run",
                    "expires_at": _future_date(60),
                }
            ],
        )
        gate = self.tool.build_gate(self.root, documented_blockers_path=db_path)
        self.assertEqual(gate["verdict"], "pass_with_documented_blockers")
        self.assertEqual(gate["blockers"], [])
        self.assertTrue(len(gate["documented_blockers"]) >= 1)

    def test_claim_guard_present_on_pass_with_documented_blockers(self) -> None:
        """pass_with_documented_blockers verdict must carry a claim_guard string."""
        self.write_clean_artifacts()
        self.write_partial_progress("provider_campaign_completeness")

        db_path = self.write_documented_blockers(
            ".auditooor/v3_documented_blockers.json",
            [
                {
                    "category_id": "provider_campaign_completeness",
                    "reason_code": "no_provider_subscription",
                    "evidence": "No subscription active",
                    "expires_at": _future_date(30),
                }
            ],
        )
        gate = self.tool.build_gate(self.root, documented_blockers_path=db_path)
        self.assertEqual(gate["verdict"], "pass_with_documented_blockers")
        self.assertIn("claim_guard", gate)
        self.assertIn("NOT empirically complete", gate["claim_guard"])

    def test_expired_entry_is_ignored_still_fails(self) -> None:
        """An entry with expires_at in the past is silently skipped; hard blocker resurfaces."""
        self.write_clean_artifacts()
        self.write_partial_progress("provider_campaign_completeness")

        db_path = self.write_documented_blockers(
            ".auditooor/v3_documented_blockers.json",
            [
                {
                    "category_id": "provider_campaign_completeness",
                    "reason_code": "no_provider_subscription",
                    "evidence": "Old expired entry",
                    "expires_at": _past_date(1),  # yesterday - expired
                }
            ],
        )
        gate = self.tool.build_gate(self.root, documented_blockers_path=db_path)
        self.assertEqual(gate["verdict"], "fail")
        # Should be a warning about expired entry
        expired_warnings = [w for w in gate["warnings"] if w.get("code") == "documented_blockers_expired_entries_ignored"]
        self.assertTrue(len(expired_warnings) >= 1)

    def test_entry_missing_evidence_is_ignored_still_fails(self) -> None:
        """An entry with missing/empty evidence is rejected; hard blocker resurfaces."""
        self.write_clean_artifacts()
        self.write_partial_progress("provider_campaign_completeness")

        db_path = self.write_documented_blockers(
            ".auditooor/v3_documented_blockers.json",
            [
                {
                    "category_id": "provider_campaign_completeness",
                    "reason_code": "no_provider_subscription",
                    "evidence": "",  # empty - must be rejected
                    "expires_at": _future_date(30),
                }
            ],
        )
        gate = self.tool.build_gate(self.root, documented_blockers_path=db_path)
        self.assertEqual(gate["verdict"], "fail")
        parse_error_warnings = [w for w in gate["warnings"] if w.get("code") == "documented_blockers_parse_errors"]
        self.assertTrue(len(parse_error_warnings) >= 1)
        errors = parse_error_warnings[0]["errors"]
        self.assertTrue(any(e.get("code") == "documented_blockers_missing_evidence" for e in errors))

    def test_tooling_category_document_block_attempt_yields_fail_with_illegitimate_code(self) -> None:
        """Attempting to document-block a tooling-only category is itself a hard fail."""
        self.write_clean_artifacts()
        # Make sidecar_coverage fail (a tooling category)
        self.write_json(
            ".auditooor/hackerman_sidecar_coverage_report.json",
            {"status": "fail", "blockers": [{"code": "missing_sidecar"}]},
        )

        db_path = self.write_documented_blockers(
            ".auditooor/v3_documented_blockers.json",
            [
                {
                    "category_id": "sidecar_coverage",  # tooling-only - cannot be waived
                    "reason_code": "source_data_unavailable",
                    "evidence": "Trying to waive a tooling gap",
                    "expires_at": _future_date(30),
                }
            ],
        )
        gate = self.tool.build_gate(self.root, documented_blockers_path=db_path)
        self.assertEqual(gate["verdict"], "fail")
        self.assertTrue(
            any(b.get("code") == "illegitimate_documented_blocker" and b.get("category_id") == "sidecar_coverage"
                for b in gate["blockers"])
        )

    def test_lesson_gates_tooling_category_cannot_be_document_blocked(self) -> None:
        """lesson_gates is also a tooling-only category - cannot be waived."""
        self.write_clean_artifacts()
        self.write_partial_progress("lesson_gates")

        db_path = self.write_documented_blockers(
            ".auditooor/v3_documented_blockers.json",
            [
                {
                    "category_id": "lesson_gates",
                    "reason_code": "source_data_unavailable",
                    "evidence": "Trying to waive lesson_gates",
                    "expires_at": _future_date(30),
                }
            ],
        )
        gate = self.tool.build_gate(self.root, documented_blockers_path=db_path)
        self.assertEqual(gate["verdict"], "fail")
        self.assertTrue(
            any(b.get("code") == "illegitimate_documented_blocker" for b in gate["blockers"])
        )

    def test_fully_clean_repo_with_no_documented_blockers_yields_pass(self) -> None:
        """A clean repo with an empty documented-blockers file still yields pass (not pass_with_documented_blockers)."""
        self.write_clean_artifacts()
        db_path = self.write_documented_blockers(".auditooor/v3_documented_blockers.json", [])
        gate = self.tool.build_gate(self.root, documented_blockers_path=db_path)
        self.assertEqual(gate["verdict"], "pass")
        self.assertEqual(gate["blockers"], [])
        self.assertEqual(gate["documented_blockers"], [])
        self.assertNotIn("claim_guard", gate)

    def test_multiple_documented_blockers_all_reclassified(self) -> None:
        """Multiple valid documented-blocker entries all get reclassified."""
        self.write_clean_artifacts()
        self.write_partial_progress("provider_campaign_completeness")
        # Also make field_validation partial
        progress = json.loads((self.root / "reports/v3_roadmap_progress_report.json").read_text())
        progress["categories"]["field_validation"] = {"status": "partial"}
        progress["blocking_unmet_categories"].append(
            {"category_id": "field_validation", "reason": "no live-audit outcome yet"}
        )
        self.write_json("reports/v3_roadmap_progress_report.json", progress)

        db_path = self.write_documented_blockers(
            ".auditooor/v3_documented_blockers.json",
            [
                {
                    "category_id": "provider_campaign_completeness",
                    "reason_code": "no_provider_subscription",
                    "evidence": "No subscription active",
                    "expires_at": _future_date(60),
                },
                {
                    "category_id": "field_validation",
                    "reason_code": "empirical_pending_live_outcome",
                    "evidence": "Hyperbridge 2026-05-22 field hunt produced 0 fileable findings",
                    "expires_at": _future_date(30),
                },
            ],
        )
        gate = self.tool.build_gate(self.root, documented_blockers_path=db_path)
        self.assertEqual(gate["verdict"], "pass_with_documented_blockers")
        self.assertEqual(gate["blockers"], [])
        self.assertEqual(len(gate["documented_blockers"]), 2)

    def test_documented_blocker_for_met_category_is_warned(self) -> None:
        """A documented-blocker entry for an already-met category triggers a warning."""
        self.write_clean_artifacts()
        db_path = self.write_documented_blockers(
            ".auditooor/v3_documented_blockers.json",
            [
                {
                    "category_id": "provider_campaign_completeness",
                    "reason_code": "no_provider_subscription",
                    "evidence": "Spurious entry for met category",
                    "expires_at": _future_date(30),
                }
            ],
        )
        gate = self.tool.build_gate(self.root, documented_blockers_path=db_path)
        self.assertEqual(gate["verdict"], "pass")
        spurious_warnings = [w for w in gate["warnings"] if w.get("code") == "documented_blocker_for_already_met_category"]
        self.assertTrue(len(spurious_warnings) >= 1)

    def test_hard_blocker_alongside_documented_blocker_still_fails(self) -> None:
        """If a valid documented-blocker entry reclassifies one blocker but another
        hard blocker remains, the verdict is still fail."""
        self.write_clean_artifacts()
        # Make provider_campaign_completeness partial - will be documented
        self.write_partial_progress("provider_campaign_completeness")
        # Also delete the sidecar file - hard tooling failure, cannot be waived
        (self.root / ".auditooor" / "hackerman_sidecar_coverage_report.json").unlink()

        db_path = self.write_documented_blockers(
            ".auditooor/v3_documented_blockers.json",
            [
                {
                    "category_id": "provider_campaign_completeness",
                    "reason_code": "no_provider_subscription",
                    "evidence": "No subscription",
                    "expires_at": _future_date(30),
                }
            ],
        )
        gate = self.tool.build_gate(self.root, documented_blockers_path=db_path)
        self.assertEqual(gate["verdict"], "fail")
        # documented_blockers list should have the reclassified one
        self.assertTrue(len(gate["documented_blockers"]) >= 1)
        # hard blockers should have the sidecar failure
        self.assertTrue(any(b.get("code") == "sidecar_coverage_missing" for b in gate["blockers"]))

    def test_invalid_reason_code_entry_is_rejected(self) -> None:
        """An entry with an invalid reason_code is rejected; hard blocker resurfaces."""
        self.write_clean_artifacts()
        self.write_partial_progress("provider_campaign_completeness")

        db_path = self.write_documented_blockers(
            ".auditooor/v3_documented_blockers.json",
            [
                {
                    "category_id": "provider_campaign_completeness",
                    "reason_code": "made_up_reason",  # invalid
                    "evidence": "Some evidence",
                    "expires_at": _future_date(30),
                }
            ],
        )
        gate = self.tool.build_gate(self.root, documented_blockers_path=db_path)
        self.assertEqual(gate["verdict"], "fail")
        parse_error_warnings = [w for w in gate["warnings"] if w.get("code") == "documented_blockers_parse_errors"]
        self.assertTrue(len(parse_error_warnings) >= 1)

    def test_real_hunt_validation_can_be_documented_blocked(self) -> None:
        """real_hunt_validation is in DOCUMENTABLE_CATEGORIES and can be blocked."""
        self.write_clean_artifacts()
        self.write_partial_progress("real_hunt_validation")

        db_path = self.write_documented_blockers(
            ".auditooor/v3_documented_blockers.json",
            [
                {
                    "category_id": "real_hunt_validation",
                    "reason_code": "empirical_pending_live_outcome",
                    "evidence": "Hyperbridge 2026-05-22: 0 fileable findings; no submission or PoC outcome yet",
                    "expires_at": _future_date(45),
                }
            ],
        )
        gate = self.tool.build_gate(self.root, documented_blockers_path=db_path)
        self.assertEqual(gate["verdict"], "pass_with_documented_blockers")
        self.assertIn("claim_guard", gate)

    def test_local_actionable_blocker_ledger_row_is_hard_failure(self) -> None:
        """Open blocker-ledger rows without external_state_required cannot be waived by clean roadmap status."""
        self.write_clean_artifacts()
        self.write_json(
            "reports/v3_blocker_ledger/blocker_ledger.json",
            {
                "schema": "auditooor.v3_blocker_ledger.v1",
                "blockers": [
                    {
                        "blocker_id": "BLK-LOCAL-FIX-ME",
                        "status": "blocked_local_patch_available",
                        "external_state_required": False,
                    }
                ],
            },
        )

        gate = self.tool.build_gate(self.root)

        self.assertEqual(gate["verdict"], "fail")
        self.assertTrue(
            any(
                row.get("code") == "blocker_ledger_local_actionable_open"
                and row.get("local_actionable_open_ids") == ["BLK-LOCAL-FIX-ME"]
                for row in gate["blockers"]
            )
        )

    def test_documented_blocker_does_not_mask_local_actionable_blocker_ledger_row(self) -> None:
        """Empirical documented-blockers may reclassify external waits, not local ledger work."""
        self.write_clean_artifacts()
        self.write_partial_progress("field_validation")
        self.write_json(
            "reports/v3_blocker_ledger/blocker_ledger.json",
            {
                "schema": "auditooor.v3_blocker_ledger.v1",
                "blockers": [
                    {
                        "blocker_id": "BLK-LOCAL-FIX-ME",
                        "status": "blocked_local_patch_available",
                        "external_state_required": False,
                    }
                ],
            },
        )
        db_path = self.write_documented_blockers(
            ".auditooor/v3_documented_blockers.json",
            [
                {
                    "category_id": "field_validation",
                    "reason_code": "empirical_pending_live_outcome",
                    "evidence": "Platform outcome not yet available",
                    "expires_at": _future_date(30),
                }
            ],
        )

        gate = self.tool.build_gate(self.root, documented_blockers_path=db_path)

        self.assertEqual(gate["verdict"], "fail")
        self.assertTrue(gate["documented_blockers"])
        self.assertTrue(
            any(row.get("code") == "blocker_ledger_local_actionable_open" for row in gate["blockers"])
        )

    def test_declared_local_actionable_count_without_rows_is_hard_failure(self) -> None:
        """A stale aggregate count must be reconciled before enforcement can pass."""
        self.write_clean_artifacts()
        self.write_json(
            "reports/v3_blocker_ledger/blocker_ledger.json",
            {
                "schema": "auditooor.v3_blocker_ledger.v1",
                "local_actionable_open_count": 1,
                "blockers": [
                    {
                        "blocker_id": "BLK-EXTERNAL",
                        "status": "blocked_external",
                        "external_state_required": True,
                    }
                ],
            },
        )

        gate = self.tool.build_gate(self.root)

        self.assertEqual(gate["verdict"], "fail")
        self.assertTrue(
            any(row.get("code") == "blocker_ledger_declares_local_actionable_open" for row in gate["blockers"])
        )


if __name__ == "__main__":
    unittest.main()
