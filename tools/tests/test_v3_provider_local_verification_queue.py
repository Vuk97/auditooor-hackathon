from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "v3-provider-local-verification-queue.py"


def _import_tool():
    spec = importlib.util.spec_from_file_location("v3_provider_local_verification_queue_test", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class V3ProviderLocalVerificationQueueTests(unittest.TestCase):
    def test_builds_claim_level_queue_without_promoting_provider_output(self) -> None:
        mod = _import_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "kimi.out.txt"
            output.write_text(
                json.dumps(
                    {
                        "advisory_candidates": [
                            {
                                "candidate_id": "DARKNAVY-MINER-001",
                                "source_surface": "DarkNavy Web3 pages",
                                "status": "KEEP_FOR_LOCAL_VERIFICATION",
                                "next_action_required": "collect primary source URL and txhash",
                                "exact_local_files_to_inspect_next": [
                                    {"path": "tools/hackerman-etl-refresh.py", "lines": "1-20"}
                                ],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            closeout = root / "fanout_closeout.json"
            closeout.write_text(
                json.dumps(
                    {
                        "campaign_id": "hackerman-v3-8kimi-8minimax",
                        "run_id": "unit",
                        "run_dir": str(root),
                        "summary": {"tokens_by_provider": {"kimi": 100}, "total_tokens": 100},
                        "rows": [
                            {
                                "task_id": "kimi-01",
                                "provider": "kimi",
                                "model": "kimi-for-coding",
                                "template": "source-extract",
                                "status": "needs_local_verification",
                                "output_shape": "json",
                                "provider_output_path": str(output),
                                "provider_output_bytes": output.stat().st_size,
                                "tokens_used": 100,
                                "mcp_receipt": {"path": "last_mcp_recall.json", "sha256_16": "abc"},
                                "campaign_dispatch_audit_path": "llm_dispatch.json",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            payload = mod.build_queue(closeout)

        self.assertEqual(payload["summary"]["total_queue_items"], 1)
        row = payload["rows"][0]
        self.assertEqual(row["claim"]["provider_claim_id"], "DARKNAVY-MINER-001")
        self.assertIn("DarkNavy Web3 pages", row["claim"]["summary"])
        self.assertEqual(row["verification"]["status"], "pending")
        self.assertIsNone(row["terminal_outcome"])
        self.assertFalse(row["submit_ready"])
        self.assertFalse(row["promotion_authority"])
        self.assertTrue(row["local_verification_required"])
        self.assertIn("needs_source_inspection", {blocker["code"] for blocker in row["blockers"]})
        self.assertIn("provider_suggested_ref", {ref["kind"] for ref in row["source_refs"]})
        self.assertTrue(set(row["terminal_outcome_options"]).issubset(set(payload["terminal_outcomes"])))

    def test_compound_and_annotated_path_hints_are_normalized(self) -> None:
        mod = _import_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "kimi.out.txt"
            output.write_text(
                json.dumps(
                    {
                        "claims": [
                            {
                                "id": "compound-ref",
                                "summary": "needs local source review",
                                "source_refs": [
                                    {
                                        "path": (
                                            "Cross-reference: docs/HACKERMAN_V3_CAPABILITY_PLAN_2026-05-19.md:935-949 "
                                            "with tools/hackerman-etl-refresh.py:22-43, 128-147"
                                        )
                                    },
                                    {"path": "reference/external_intel_sources.yaml: status=missing"},
                                ],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            closeout = root / "fanout_closeout.json"
            closeout.write_text(
                json.dumps(
                    {
                        "campaign_id": "hackerman-v3-8kimi-8minimax",
                        "run_id": "unit",
                        "run_dir": str(root),
                        "summary": {},
                        "rows": [
                            {
                                "task_id": "kimi-paths",
                                "provider": "kimi",
                                "model": "kimi-for-coding",
                                "template": "source-extract",
                                "status": "needs_local_verification",
                                "output_shape": "json",
                                "provider_output_path": str(output),
                                "provider_output_bytes": output.stat().st_size,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            payload = mod.build_queue(closeout, root)

        row = payload["rows"][0]
        self.assertIn("docs/HACKERMAN_V3_CAPABILITY_PLAN_2026-05-19.md:935-949", row["file_hints"])
        self.assertIn("tools/hackerman-etl-refresh.py:22-43", row["file_hints"])
        self.assertIn("reference/external_intel_sources.yaml", row["file_hints"])
        self.assertTrue(all(not hint.startswith("Cross-reference") for hint in row["file_hints"]))
        self.assertTrue(all("status=missing" not in hint for hint in row["file_hints"]))

    def test_explicit_needs_more_source_prose_is_preserved_as_provider_verdict(self) -> None:
        mod = _import_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "kimi.out.txt"
            output.write_text(
                "Verdict: NEEDS_MORE_SOURCE\n"
                + json.dumps({"claims": [{"id": "source-gap", "summary": "needs primary tx"}]}),
                encoding="utf-8",
            )
            closeout = root / "fanout_closeout.json"
            closeout.write_text(
                json.dumps(
                    {
                        "campaign_id": "hackerman-v3-8kimi-8minimax",
                        "run_id": "unit",
                        "run_dir": str(root),
                        "summary": {},
                        "rows": [
                            {
                                "task_id": "kimi-source",
                                "provider": "kimi",
                                "model": "kimi-for-coding",
                                "template": "source-extract",
                                "status": "needs_local_verification",
                                "output_shape": "markdown",
                                "provider_output_path": str(output),
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            payload = mod.build_queue(closeout, root)

        row = payload["rows"][0]
        self.assertEqual(row["claim"]["provider_verdict"], "NEEDS_MORE_SOURCE")
        self.assertEqual(row["route"], "external_source_needed")
        self.assertIn("needs_more_source", row["terminal_outcome_options"])

    def test_reject_prose_is_not_promoted_to_provider_verdict(self) -> None:
        mod = _import_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "minimax.out.txt"
            output.write_text(
                "Verdict: REJECT_OOS\n"
                + json.dumps({"claims": [{"id": "oos", "summary": "needs local source review"}]}),
                encoding="utf-8",
            )
            closeout = root / "fanout_closeout.json"
            closeout.write_text(
                json.dumps(
                    {
                        "campaign_id": "hackerman-v3-8kimi-8minimax",
                        "run_id": "unit",
                        "run_dir": str(root),
                        "summary": {},
                        "rows": [
                            {
                                "task_id": "minimax-kill",
                                "provider": "minimax",
                                "model": "MiniMax-M2.7",
                                "template": "adversarial-kill",
                                "status": "needs_local_verification",
                                "output_shape": "markdown",
                                "provider_output_path": str(output),
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            payload = mod.build_queue(closeout, root)

        row = payload["rows"][0]
        self.assertEqual(row["claim"]["provider_verdict"], "")
        self.assertIsNone(row["terminal_outcome"])
        self.assertFalse(row["submit_ready"])

    def test_blocked_provider_closeout_row_becomes_blocked_verification_row(self) -> None:
        mod = _import_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            closeout = root / "fanout_closeout.json"
            closeout.write_text(
                json.dumps(
                    {
                        "campaign_id": "hackerman-v3-8kimi-8minimax",
                        "run_id": "unit",
                        "run_dir": str(root),
                        "summary": {},
                        "rows": [
                            {
                                "task_id": "kimi-blocked",
                                "provider": "kimi",
                                "template": "source-extract",
                                "status": "blocked_missing_model",
                                "output_shape": "empty",
                                "provider_output_path": str(root / "missing.out.txt"),
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            payload = mod.build_queue(closeout)

        self.assertEqual(payload["summary"]["total_queue_items"], 1)
        row = payload["rows"][0]
        self.assertEqual(row["route"], "blocked_provider_output")
        self.assertEqual(row["verification"]["status"], "blocked")
        self.assertIn("blocked_missing_model", {blocker["code"] for blocker in row["blockers"]})
        self.assertIn("blocked_missing_model", row["terminal_outcome_options"])

    def test_backfill_packet_becomes_verifier_owned_queue_row(self) -> None:
        mod = _import_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            local_source = root / "tools" / "example.py"
            local_source.parent.mkdir()
            local_source.write_text("def dangerousWithdraw():\n    return True\n", encoding="utf-8")
            output = root / "provider.out.txt"
            output.write_text("MUST_KEEP_LOCAL_REVIEW: inspect `dangerousWithdraw` in tools/example.py:1\n", encoding="utf-8")
            backfill = root / "provider_keep_verification_backfill.json"
            backfill.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.provider_keep_verification_backfill.v1",
                        "packets": [
                            {
                                "packet_id": "KEEP-BACKFILL-001",
                                "source_file": str(output),
                                "provider": "minimax",
                                "task_type": "adversarial-kill",
                                "missing_verification_reason": "keep_without_local_verification_signal",
                                "suggested_local_commands": [
                                    {"kind": "rg", "command": "rg -n dangerousWithdraw tools/example.py"}
                                ],
                                "packet_status": "pending_local_verification_backfill",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            payload = mod.build_queue(None, root, backfill_path=backfill)

        self.assertEqual(payload["summary"]["total_queue_items"], 1)
        self.assertEqual(payload["summary"]["backfill_packet_rows"], 1)
        row = payload["rows"][0]
        self.assertEqual(row["route"], "local_source_review")
        self.assertEqual(row["claim"]["provider_claim_id"], "KEEP-BACKFILL-001")
        self.assertEqual(row["grep_patterns"], ["dangerousWithdraw"])
        self.assertEqual(row["file_hints"], ["tools/example.py:1"])
        self.assertIn("provider_suggested_ref", {ref["kind"] for ref in row["source_refs"]})
        self.assertNotEqual(row["source_refs"][-1]["path"], str(output))
        self.assertIn("dangerousWithdraw", row["verification"]["commands"][0])
        self.assertIn("tools/example.py", row["verification"]["commands"][0])
        self.assertNotIn("tools/example.py:1", row["verification"]["commands"][0])
        self.assertFalse(row["submit_ready"])
        self.assertFalse(row["promotion_authority"])

    def test_backfill_command_paths_cannot_escape_workspace(self) -> None:
        mod = _import_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "ws"
            root.mkdir()
            outside = Path(tmp) / "secret.py"
            outside.write_text("dangerousWithdraw\n", encoding="utf-8")
            provider_output = root / "provider.out.txt"
            provider_output.write_text("KEEP: inspect dangerousWithdraw\n", encoding="utf-8")
            safe_source = root / "tools" / "safe.py"
            safe_source.parent.mkdir()
            safe_source.write_text("dangerousWithdraw\n", encoding="utf-8")
            backfill = root / "provider_keep_verification_backfill.json"
            backfill.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.provider_keep_verification_backfill.v1",
                        "packets": [
                            {
                                "packet_id": "KEEP-BACKFILL-ESCAPE",
                                "source_file": str(provider_output),
                                "provider": "kimi",
                                "task_type": "source-extract",
                                "missing_verification_reason": "keep_without_local_verification_signal",
                                "suggested_local_commands": [
                                    {"kind": "rg", "command": f"rg -n dangerousWithdraw {outside} ../secret.py tools/safe.py {provider_output}"}
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            payload = mod.build_queue(None, root, backfill_path=backfill)

        row = payload["rows"][0]
        self.assertEqual(row["file_hints"], ["tools/safe.py"])
        self.assertTrue(all("secret" not in str(ref.get("path")) for ref in row["source_refs"]))
        self.assertTrue(all(str(provider_output) != str(ref.get("path")) for ref in row["source_refs"] if ref["kind"] != "provider_output"))

    def test_missing_backfill_source_routes_to_blocked_provider_output(self) -> None:
        mod = _import_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            backfill = root / "provider_keep_verification_backfill.json"
            backfill.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.provider_keep_verification_backfill.v1",
                        "packets": [
                            {
                                "packet_id": "KEEP-BACKFILL-404",
                                "source_file": str(root / "missing.out.txt"),
                                "provider": "kimi",
                                "task_type": "source-extract",
                                "missing_verification_reason": "provider_output_file_missing_or_unreadable",
                                "suggested_local_commands": [],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            payload = mod.build_queue(None, root, backfill_path=backfill)

        row = payload["rows"][0]
        self.assertEqual(row["route"], "blocked_provider_output")
        self.assertEqual(row["verification"]["status"], "blocked")
        self.assertIn("blocked_no_output", {blocker["code"] for blocker in row["blockers"]})

    def test_provider_path_hints_cannot_escape_workspace(self) -> None:
        mod = _import_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "ws"
            root.mkdir()
            outside = Path(tmp) / "secret.txt"
            output = root / "minimax.out.txt"
            output.write_text(
                json.dumps(
                    {
                        "advisory_candidates": [
                            {
                                "candidate_id": "escape-attempt",
                                "verdict": "REJECT_OOS",
                                "summary": "try to force external read",
                                "exact_local_files_to_inspect_next": [
                                    {"path": "../../../secret.txt", "lines": "1-2"},
                                    {"path": str(outside), "lines": "1"},
                                    {"path": "tools/safe.py", "lines": "1"},
                                ],
                                "local_verification_grep_patterns": ["safe_symbol"],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            closeout = root / "fanout_closeout.json"
            closeout.write_text(
                json.dumps(
                    {
                        "campaign_id": "hackerman-v3-8kimi-8minimax",
                        "run_id": "unit",
                        "run_dir": str(root),
                        "summary": {},
                        "rows": [
                            {
                                "task_id": "minimax-01",
                                "provider": "minimax",
                                "model": "MiniMax-M2.7",
                                "template": "adversarial-kill",
                                "status": "needs_local_verification",
                                "output_shape": "json",
                                "provider_output_path": str(output),
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            payload = mod.build_queue(closeout, root)

        row = payload["rows"][0]
        self.assertEqual(row["file_hints"], ["tools/safe.py"])
        self.assertEqual(row["route"], "kill_review")
        self.assertIn("needs_more_source", row["terminal_outcome_options"])
        self.assertNotIn("..", row["next_command"])
        self.assertNotIn(str(outside), row["next_command"])
        self.assertTrue(all("secret" not in str(ref.get("path")) for ref in row["source_refs"]))


if __name__ == "__main__":
    unittest.main()
