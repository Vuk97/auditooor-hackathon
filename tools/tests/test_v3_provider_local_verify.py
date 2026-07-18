from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "v3-provider-local-verify.py"


def _import_tool():
    spec = importlib.util.spec_from_file_location("v3_provider_local_verify_test", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _queue_row(
    *,
    queue_id: str = "V3-LV-001",
    route: str = "local_source_review",
    terminal_options: list[str] | None = None,
    source_refs: list[dict] | None = None,
    grep_patterns: list[str] | None = None,
    blockers: list[dict] | None = None,
) -> dict:
    return {
        "queue_id": queue_id,
        "row_id": f"{queue_id}-row",
        "task_id": "task-1",
        "provider": "kimi",
        "model": "kimi-for-coding",
        "route": route,
        "claim": {"kind": "workflow_gap", "summary": "claim"},
        "source_provider_row": {"task_id": "task-1", "provider": "kimi"},
        "source_refs": source_refs or [],
        "grep_patterns": grep_patterns or [],
        "blockers": blockers or [{"code": "needs_source_inspection", "blocking": True}],
        "verification": {"commands": ["rg -n target tools/example.py"], "evidence_refs": []},
        "terminal_outcome_options": terminal_options or ["verified_actionable", "needs_more_source"],
        "advisory_only": True,
        "promotion_authority": False,
        "submit_ready": False,
    }


class V3ProviderLocalVerifyTests(unittest.TestCase):
    def test_blocked_row_maps_to_allowed_blocked_terminal(self) -> None:
        mod = _import_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            row = _queue_row(
                route="blocked_provider_output",
                terminal_options=["blocked_missing_model"],
                blockers=[{"code": "blocked_missing_model", "blocking": True}],
            )
            result = mod._verify_row(row, root)

        self.assertEqual(result["verification_status"], "blocked")
        self.assertEqual(result["terminal_outcome"], "blocked_missing_model")
        self.assertTrue(result["terminal_safe"])
        self.assertFalse(result["submit_ready"])
        self.assertFalse(result["promotion_authority"])
        self.assertEqual(result["severity"], "none")

    def test_external_source_row_stays_needs_more_source(self) -> None:
        mod = _import_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            row = _queue_row(
                route="external_source_needed",
                terminal_options=["needs_more_source", "verified_no_action"],
                blockers=[{"code": "needs_primary_source", "blocking": True}],
                source_refs=[{"kind": "provider_suggested_ref", "path": "https://example.invalid/report", "verified": False}],
            )
            result = mod._verify_row(row, root)

        self.assertEqual(result["verification_status"], "needs_more_source")
        self.assertEqual(result["terminal_outcome"], "needs_more_source")
        self.assertTrue(result["terminal_safe"])
        self.assertEqual(result["external_source_ref_count"], 1)

    def test_annotated_local_ref_is_normalized_before_source_check(self) -> None:
        mod = _import_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "reference" / "external_intel_sources.yaml"
            source.parent.mkdir()
            source.write_text("source_id: darknavy_web3_pages\n", encoding="utf-8")
            row = _queue_row(
                route="local_source_review",
                terminal_options=["verified_actionable", "needs_more_source"],
                source_refs=[
                    {
                        "kind": "provider_suggested_ref",
                        "path": "reference/external_intel_sources.yaml: status=missing",
                        "verified": False,
                    }
                ],
                grep_patterns=["darknavy_web3_pages"],
            )
            result = mod._verify_row(row, root)

        self.assertEqual(result["verification_status"], "verified")
        self.assertEqual(result["missing_source_ref_count"], 0)
        self.assertEqual(result["exact_source_ref_count"], 1)
        self.assertEqual(result["grep_hit_count"], 1)
        self.assertEqual(result["source_ref_checks"][0]["normalized_path"], "reference/external_intel_sources.yaml")

    def test_source_review_with_file_and_grep_hit_finds_evidence_without_terminal_promotion(self) -> None:
        mod = _import_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "tools" / "example.py"
            source.parent.mkdir()
            source.write_text("def target_symbol():\n    return True\n", encoding="utf-8")
            row = _queue_row(
                route="local_source_review",
                terminal_options=["verified_actionable", "needs_more_source"],
                source_refs=[{"kind": "provider_suggested_ref", "path": "tools/example.py:1", "verified": False}],
                grep_patterns=["target_symbol"],
            )
            result = mod._verify_row(row, root)

        self.assertEqual(result["verification_status"], "verified")
        self.assertIsNone(result["terminal_outcome"])
        self.assertFalse(result["terminal_safe"])
        self.assertEqual(result["existing_source_ref_count"], 1)
        self.assertEqual(result["exact_source_ref_count"], 1)
        self.assertEqual(result["grep_hit_count"], 1)
        self.assertTrue(result["verification"]["evidence_refs"])
        self.assertFalse(result["local_verification_required"])
        self.assertFalse(result["source_collection_required"])
        self.assertTrue(result["terminal_judgment_required"])

    def test_local_terminal_judgment_closes_verified_row(self) -> None:
        mod = _import_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "tools" / "example.py"
            source.parent.mkdir()
            source.write_text("def target_symbol():\n    return True\n", encoding="utf-8")
            row = _queue_row(
                route="local_source_review",
                terminal_options=["verified_actionable", "verified_no_action", "needs_more_source"],
                source_refs=[{"kind": "provider_suggested_ref", "path": "tools/example.py:1", "verified": False}],
                grep_patterns=["target_symbol"],
            )
            result = mod._verify_row(
                row,
                root,
                terminal_judgments={
                    "V3-LV-001": {
                        "queue_id": "V3-LV-001",
                        "reviewer": "local",
                        "terminal_outcome": "verified_no_action",
                        "exact_citation": "tools/example.py:1",
                        "command": "rg -n target_symbol tools/example.py",
                    }
                },
            )

        self.assertEqual(result["verification_status"], "no_action")
        self.assertEqual(result["terminal_outcome"], "verified_no_action")
        self.assertFalse(result["terminal_judgment_required"])
        self.assertTrue(result["terminal_safe"])
        self.assertEqual(result["terminal_judgment"]["reviewer"], "local")
        self.assertTrue(result["terminal_judgment"]["valid"])
        self.assertTrue(any(ref["kind"] == "terminal_judgment" for ref in result["verification"]["evidence_refs"]))

    def test_invalid_terminal_judgment_does_not_close_row(self) -> None:
        mod = _import_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "tools" / "example.py"
            source.parent.mkdir()
            source.write_text("def target_symbol():\n    return True\n", encoding="utf-8")
            row = _queue_row(
                route="local_source_review",
                terminal_options=["verified_actionable", "verified_no_action", "needs_more_source"],
                source_refs=[{"kind": "provider_suggested_ref", "path": "tools/example.py:1", "verified": False}],
                grep_patterns=["target_symbol"],
            )
            result = mod._verify_row(
                row,
                root,
                terminal_judgments={
                    "V3-LV-001": {
                        "queue_id": "V3-LV-001",
                        "reviewer": "provider",
                        "terminal_outcome": "verified_no_action",
                        "exact_citation": "tools/example.py",
                        "command": "",
                    }
                },
            )

        self.assertEqual(result["verification_status"], "verified")
        self.assertIsNone(result["terminal_outcome"])
        self.assertTrue(result["terminal_judgment_required"])
        self.assertFalse(result["terminal_judgment"]["valid"])
        self.assertIn("reviewer_must_be_local", result["terminal_judgment"]["errors"])
        self.assertIn("exact_local_line_citation_required", result["terminal_judgment"]["errors"])

    def test_source_review_with_only_existing_ref_needs_more_source(self) -> None:
        mod = _import_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "tools" / "example.py"
            source.parent.mkdir()
            source.write_text("def target_symbol():\n    return True\n", encoding="utf-8")
            row = _queue_row(
                route="local_source_review",
                terminal_options=["verified_actionable", "verified_no_action", "needs_more_source"],
                source_refs=[{"kind": "provider_suggested_ref", "path": "tools/example.py:1", "verified": False}],
                grep_patterns=[],
            )
            result = mod._verify_row(row, root)

        self.assertEqual(result["verification_status"], "needs_more_source")
        self.assertEqual(result["terminal_outcome"], "needs_more_source")
        self.assertTrue(result["terminal_safe"])
        self.assertFalse(result["local_verification_required"])
        self.assertTrue(result["source_collection_required"])
        self.assertFalse(result["terminal_judgment_required"])

    def test_source_review_derives_concrete_local_patterns_from_claim_text(self) -> None:
        mod = _import_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "tools" / "example.py"
            source.parent.mkdir()
            source.write_text("SCHEMA = 'mcp_evidence_receipt.v1'\n", encoding="utf-8")
            row = _queue_row(
                route="local_source_review",
                terminal_options=["verified_actionable", "verified_no_action", "needs_more_source"],
                source_refs=[{"kind": "provider_suggested_ref", "path": "tools/example.py:1", "verified": False}],
                grep_patterns=[],
            )
            row["claim"] = {
                "kind": "workflow_gap",
                "summary": "Verify `mcp_evidence_receipt.v1` is checked before strict closeout can pass.",
            }
            result = mod._verify_row(row, root)

        self.assertEqual(result["verification_status"], "verified")
        self.assertIn("mcp_evidence_receipt.v1", result["derived_grep_patterns"])
        self.assertEqual(result["grep_hit_count"], 1)
        self.assertFalse(result["source_collection_required"])
        self.assertTrue(result["terminal_judgment_required"])

    def test_keep_backfill_extracted_ref_can_be_locally_verified(self) -> None:
        mod = _import_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "tools" / "example.py"
            source.parent.mkdir()
            source.write_text("def dangerousWithdraw():\n    return True\n", encoding="utf-8")
            row = _queue_row(
                route="local_source_review",
                terminal_options=["verified_actionable", "verified_no_action", "needs_more_source"],
                source_refs=[
                    {"kind": "provider_output", "path": ".auditooor/provider.out.txt", "verified": False},
                    {"kind": "provider_suggested_ref", "path": "tools/example.py:1", "verified": False},
                ],
                grep_patterns=["dangerousWithdraw"],
            )
            row["claim"] = {
                "kind": "provider_keep_backfill",
                "summary": "KEEP-BACKFILL-001: provider KEEP requires local verification",
            }
            result = mod._verify_row(row, root)

        self.assertEqual(result["verification_status"], "verified")
        self.assertEqual(result["grep_hit_count"], 1)
        self.assertEqual(result["exact_source_ref_count"], 1)
        self.assertIsNone(result["terminal_outcome"])
        self.assertTrue(result["terminal_judgment_required"])
        self.assertFalse(result["submit_ready"])
        self.assertFalse(result["promotion_authority"])

    def test_kill_review_with_missing_ref_closes_to_needs_more_source_when_allowed(self) -> None:
        mod = _import_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "tools" / "example.py"
            source.parent.mkdir()
            source.write_text("def target_symbol():\n    return True\n", encoding="utf-8")
            row = _queue_row(
                route="kill_review",
                terminal_options=[
                    "verified_no_action",
                    "rejected_oos",
                    "rejected_duplicate",
                    "rejected_false_positive",
                    "verified_actionable",
                    "needs_more_source",
                ],
                source_refs=[
                    {"kind": "provider_suggested_ref", "path": "tools/example.py:1", "verified": False},
                    {"kind": "provider_suggested_ref", "path": "tools/missing.py:1", "verified": False},
                ],
            )
            result = mod._verify_row(row, root)

        self.assertEqual(result["verification_status"], "needs_more_source")
        self.assertEqual(result["terminal_outcome"], "needs_more_source")
        self.assertTrue(result["source_collection_required"])
        self.assertFalse(result["terminal_judgment_required"])

    def test_kill_review_reject_verdict_maps_to_no_action_terminal_without_verifying_claim(self) -> None:
        mod = _import_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "tools" / "example.py"
            source.parent.mkdir()
            source.write_text("def target_symbol():\n    return True\n", encoding="utf-8")
            row = _queue_row(
                route="kill_review",
                terminal_options=[
                    "verified_no_action",
                    "rejected_oos",
                    "rejected_duplicate",
                    "rejected_false_positive",
                    "verified_actionable",
                    "needs_more_source",
                ],
                source_refs=[{"kind": "provider_suggested_ref", "path": "tools/example.py:1", "verified": False}],
            )
            row["claim"]["provider_verdict"] = "REJECT_MISSING_PRODUCTION_PATH"
            result = mod._verify_row(row, root)

        self.assertEqual(result["verification_status"], "no_action")
        self.assertEqual(result["terminal_outcome"], "verified_no_action")
        self.assertTrue(result["terminal_safe"])
        self.assertFalse(result["terminal_judgment_required"])
        self.assertFalse(result["promotion_authority"])

    def test_terminal_not_assigned_when_not_allowed_by_row_options(self) -> None:
        mod = _import_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "tools" / "example.py"
            source.parent.mkdir()
            source.write_text("def target_symbol():\n    return True\n", encoding="utf-8")
            row = _queue_row(
                route="local_source_review",
                terminal_options=["needs_more_source"],
                source_refs=[{"kind": "provider_suggested_ref", "path": "tools/example.py", "verified": False}],
                grep_patterns=["target_symbol"],
            )
            result = mod._verify_row(row, root)

        self.assertEqual(result["verification_status"], "verified")
        self.assertIsNone(result["terminal_outcome"])
        self.assertFalse(result["terminal_safe"])
        self.assertFalse(result["local_verification_required"])
        self.assertFalse(result["source_collection_required"])
        self.assertTrue(result["terminal_judgment_required"])

    def test_out_of_workspace_and_invalid_line_refs_do_not_become_evidence(self) -> None:
        mod = _import_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "ws"
            root.mkdir()
            outside = Path(tmp) / "secret.txt"
            outside.write_text("target_symbol\n", encoding="utf-8")
            source = root / "tools" / "example.py"
            source.parent.mkdir()
            source.write_text("target_symbol\n", encoding="utf-8")
            row = _queue_row(
                route="local_source_review",
                terminal_options=["verified_actionable", "needs_more_source"],
                source_refs=[
                    {"kind": "provider_suggested_ref", "path": str(outside), "verified": False},
                    {"kind": "provider_suggested_ref", "path": "tools/example.py:9999", "verified": False},
                ],
                grep_patterns=["target_symbol"],
            )
            result = mod._verify_row(row, root)

        self.assertEqual(result["verification_status"], "needs_more_source")
        self.assertEqual(result["terminal_outcome"], "needs_more_source")
        self.assertFalse(result["local_verification_required"])
        self.assertTrue(result["source_collection_required"])
        self.assertFalse(result["terminal_judgment_required"])
        self.assertEqual(result["existing_source_ref_count"], 1)
        self.assertEqual(result["exact_source_ref_count"], 0)
        self.assertEqual(result["grep_hit_count"], 0)
        self.assertEqual(result["verification"]["evidence_refs"], [])
        self.assertTrue(any(check.get("out_of_workspace") for check in result["source_ref_checks"]))

    def test_build_verification_preserves_non_promotional_posture(self) -> None:
        mod = _import_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "tools" / "example.py"
            source.parent.mkdir()
            source.write_text("target\n", encoding="utf-8")
            queue = root / "queue.json"
            queue.write_text(
                json.dumps(
                    {
                        "campaign_id": "hackerman-v3-8kimi-8minimax",
                        "run_id": "unit",
                        "run_dir": str(root),
                        "rows": [
                            _queue_row(
                                terminal_options=["verified_actionable", "verified_no_action", "needs_more_source"],
                                source_refs=[{"kind": "provider_suggested_ref", "path": "tools/example.py"}],
                                grep_patterns=["target"],
                            )
                        ],
                    }
                ),
                encoding="utf-8",
            )
            judgments = {
                "V3-LV-001": {
                    "queue_id": "V3-LV-001",
                    "reviewer": "local",
                    "terminal_outcome": "verified_no_action",
                    "exact_citation": "tools/example.py:1",
                    "command": "rg -n target tools/example.py",
                }
            }
            payload = mod.build_verification(queue, root, terminal_judgments=judgments)

        self.assertFalse(payload["promotion_authority"])
        self.assertFalse(payload["submit_ready"])
        self.assertEqual(payload["summary"]["rows"], 1)
        self.assertEqual(payload["summary"]["grep_hit_rows"], 1)
        self.assertEqual(payload["summary"]["local_verification_required_rows"], 0)
        self.assertEqual(payload["summary"]["terminal_judgment_required_rows"], 0)
        self.assertEqual(payload["summary"]["terminal_judgment_input_rows"], 1)
        self.assertEqual(payload["summary"]["invalid_terminal_judgment_rows"], 0)


if __name__ == "__main__":
    unittest.main()
