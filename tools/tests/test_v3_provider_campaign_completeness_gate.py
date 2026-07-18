from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "v3-provider-campaign-completeness-gate.py"
SPEC = importlib.util.spec_from_file_location("v3_provider_campaign_completeness_gate", TOOL)
assert SPEC is not None and SPEC.loader is not None
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


class V3ProviderCampaignCompletenessGateTests(unittest.TestCase):
    def test_latest_run_dir_uses_rerun_verification_mtime(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = root / "ws"
            old_run = ws / ".auditooor" / "provider_fanout" / "cam" / "runs" / "old"
            current_run = ws / ".auditooor" / "provider_fanout" / "cam" / "runs" / "current"
            write_json(old_run / "v3_provider_fanout_run.json", {"rows": []})
            write_json(current_run / "v3_provider_fanout_run.json", {"rows": []})
            write_json(current_run / "v3_provider_local_verification_result.json", {"rows": []})
            os.utime(old_run / "v3_provider_fanout_run.json", (200, 200))
            os.utime(current_run / "v3_provider_fanout_run.json", (100, 100))
            os.utime(current_run / "v3_provider_local_verification_result.json", (300, 300))

            self.assertEqual(gate._latest_run_dir(ws, "cam"), current_run)

    def test_gate_reports_selection_and_excluded_broad_results(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = root / "ws"
            selected = ws / ".auditooor" / "provider_fanout" / "cam" / "runs" / "20260520T0702Z"
            newer_named = ws / ".auditooor" / "provider_fanout" / "cam" / "runs" / "20260520T112836Z"
            broad = ws / ".auditooor" / "provider_fanout" / "followup" / "runs" / "run" / "v3_provider_local_verification_result.json"
            queue = ws / ".auditooor" / "provider_fanout" / "cam" / "v3_provider_fanout_queue.json"
            write_json(queue, {"campaign_id": "cam", "provider_counts": {}, "total_tasks": 0, "rows": []})
            write_json(selected / "v3_provider_fanout_run.json", {"campaign_id": "cam", "rows": []})
            write_json(selected / "fanout_closeout.json", {"campaign_id": "cam", "rows": []})
            write_json(
                selected / "v3_provider_local_verification_result.json",
                {"campaign_id": "cam", "generated_at_utc": "2026-05-20T18:47:43Z", "summary": {}, "rows": []},
            )
            write_json(newer_named / "v3_provider_fanout_run.json", {"campaign_id": "cam", "rows": []})
            write_json(newer_named / "fanout_closeout.json", {"campaign_id": "cam", "rows": []})
            write_json(
                newer_named / "v3_provider_local_verification_result.json",
                {"campaign_id": "cam", "generated_at_utc": "2026-05-20T14:40:00Z", "summary": {}, "rows": []},
            )
            write_json(broad, {"campaign_id": "followup", "summary": {}, "rows": []})
            for artifact in selected.iterdir():
                os.utime(artifact, (300, 300))
            for artifact in newer_named.iterdir():
                os.utime(artifact, (200, 200))

            payload = gate.build_gate(ws, campaign_id="cam")

        self.assertEqual(payload["selection"]["strategy"], "latest_artifact_mtime")
        self.assertEqual(payload["selection"]["selected_run_dir"], str(selected.resolve()))
        self.assertEqual(payload["selection"]["excluded_verification_result_count"], 2)
        warning_codes = {row["code"] for row in payload["warnings"]}
        self.assertIn("selected_older_named_run_by_mtime", warning_codes)
        self.assertIn("broader_verification_results_excluded", warning_codes)

    def test_passes_when_campaign_is_accounted_and_verified(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = root / "ws"
            run_dir = ws / ".auditooor" / "provider_fanout" / "cam" / "runs" / "run-1"
            out_a = run_dir / "provider_outputs" / "kimi.txt"
            out_b = run_dir / "provider_outputs" / "minimax.txt"
            out_a.parent.mkdir(parents=True)
            out_a.write_text("classification: KEEP_FOR_LOCAL_VERIFICATION\n", encoding="utf-8")
            out_b.write_text("classification: REJECT_FALSE_POSITIVE\n", encoding="utf-8")
            queue = ws / ".auditooor" / "provider_fanout" / "cam" / "v3_provider_fanout_queue.json"
            run = run_dir / "v3_provider_fanout_run.json"
            closeout = run_dir / "fanout_closeout.json"
            verify = run_dir / "v3_provider_local_verification_result.json"
            write_json(
                queue,
                {
                    "campaign_id": "cam",
                    "provider_counts": {"kimi": 1, "minimax": 1},
                    "total_tasks": 2,
                    "rows": [{"provider": "kimi"}, {"provider": "minimax"}],
                },
            )
            write_json(
                run,
                {
                    "campaign_id": "cam",
                    "run_id": "run-1",
                    "run_dir": str(run_dir),
                    "rows": [{"provider": "kimi"}, {"provider": "minimax"}],
                },
            )
            closeout_rows = [
                {
                    "task_id": "k1",
                    "provider": "kimi",
                    "status": "needs_local_verification",
                    "model": "kimi-k2.6",
                    "provider_output_path": str(out_a),
                    "provider_output_bytes": out_a.stat().st_size,
                    "mcp_receipt": {"path": "receipt.json", "sha256_16": "abcd"},
                    "local_verification_required": True,
                    "tokens_used": 120,
                },
                {
                    "task_id": "m1",
                    "provider": "minimax",
                    "status": "killed_by_minimax",
                    "model": "minimax-m2.7",
                    "provider_output_path": str(out_b),
                    "provider_output_bytes": out_b.stat().st_size,
                    "mcp_receipt": {"path": "receipt.json", "context_pack_id": "ctx"},
                    "local_verification_required": True,
                    "tokens_used": 85,
                },
            ]
            write_json(closeout, {"campaign_id": "cam", "run_id": "run-1", "rows": closeout_rows})
            write_json(
                verify,
                {
                    "campaign_id": "cam",
                    "run_id": "run-1",
                    "summary": {
                        "source_collection_required_rows": 0,
                        "terminal_judgment_required_rows": 0,
                    },
                    "rows": [
                        {"queue_id": "k1", "verification_status": "verified", "terminal_outcome": "verified_no_action"},
                        {"queue_id": "m1", "verification_status": "verified", "terminal_outcome": "killed_by_minimax"},
                    ],
                },
            )

            payload = gate.build_gate(ws, campaign_id="cam")

        self.assertEqual(payload["status"], "pass")
        self.assertEqual(payload["blockers"], [])
        self.assertEqual(payload["observed_counts"]["local_verification_rows"], 2)

    def test_fails_on_missing_minimax_and_pending_verification(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = root / "ws"
            run_dir = ws / ".auditooor" / "provider_fanout" / "cam" / "runs" / "run-1"
            out_a = run_dir / "provider_outputs" / "kimi.txt"
            out_a.parent.mkdir(parents=True)
            out_a.write_text("classification: KEEP_FOR_LOCAL_VERIFICATION\n", encoding="utf-8")
            write_json(
                ws / ".auditooor" / "provider_fanout" / "cam" / "v3_provider_fanout_queue.json",
                {
                    "campaign_id": "cam",
                    "provider_counts": {"kimi": 1, "minimax": 1},
                    "total_tasks": 2,
                    "rows": [{"provider": "kimi"}, {"provider": "minimax"}],
                },
            )
            write_json(
                run_dir / "v3_provider_fanout_run.json",
                {"campaign_id": "cam", "run_id": "run-1", "run_dir": str(run_dir), "rows": [{"provider": "kimi"}]},
            )
            write_json(
                run_dir / "fanout_closeout.json",
                {
                    "campaign_id": "cam",
                    "run_id": "run-1",
                    "rows": [
                        {
                            "task_id": "k1",
                            "provider": "kimi",
                            "status": "needs_local_verification",
                            "model": "kimi-k2.6",
                            "provider_output_path": str(out_a),
                            "provider_output_bytes": out_a.stat().st_size,
                            "mcp_receipt": {"path": "receipt.json", "sha256_16": "abcd"},
                            "local_verification_required": True,
                        }
                    ],
                },
            )
            write_json(
                run_dir / "v3_provider_local_verification_result.json",
                {
                    "campaign_id": "cam",
                    "run_id": "run-1",
                    "summary": {"source_collection_required_rows": 1, "terminal_judgment_required_rows": 0},
                    "rows": [{"queue_id": "k1", "verification_status": "pending"}],
                },
            )

            payload = gate.build_gate(ws, campaign_id="cam")

        codes = {row["code"] for row in payload["blockers"]}
        self.assertEqual(payload["status"], "fail")
        self.assertIn("run_row_count_mismatch", codes)
        self.assertIn("provider_run_count_mismatch", codes)
        self.assertIn("blocking_local_verification_status", codes)
        self.assertIn("source_collection_required_rows", codes)

    def test_closure_queue_is_remediation_evidence_not_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = root / "ws"
            run_dir = ws / ".auditooor" / "provider_fanout" / "cam" / "runs" / "run-1"
            out_a = run_dir / "provider_outputs" / "kimi.txt"
            out_a.parent.mkdir(parents=True)
            out_a.write_text("classification: KEEP_FOR_LOCAL_VERIFICATION\n", encoding="utf-8")
            queue = ws / ".auditooor" / "provider_fanout" / "cam" / "v3_provider_fanout_queue.json"
            run = run_dir / "v3_provider_fanout_run.json"
            closeout = run_dir / "fanout_closeout.json"
            verify = run_dir / "v3_provider_local_verification_result.json"
            closure_queue = ws / ".auditooor" / "provider_closure_packet_queue.json"
            write_json(
                queue,
                {
                    "campaign_id": "cam",
                    "provider_counts": {"kimi": 1, "minimax": 0},
                    "total_tasks": 1,
                    "rows": [{"provider": "kimi"}],
                },
            )
            write_json(run, {"campaign_id": "cam", "rows": [{"provider": "kimi"}]})
            write_json(
                closeout,
                {
                    "campaign_id": "cam",
                    "rows": [
                        {
                            "task_id": "k1",
                            "provider": "kimi",
                            "status": "needs_local_verification",
                            "model": "kimi-k2.6",
                            "provider_output_path": str(out_a),
                            "provider_output_bytes": out_a.stat().st_size,
                            "mcp_receipt": {"path": "receipt.json", "sha256_16": "abcd"},
                            "local_verification_required": True,
                        }
                    ],
                },
            )
            write_json(
                verify,
                {
                    "campaign_id": "cam",
                    "summary": {"source_collection_required_rows": 1, "terminal_judgment_required_rows": 0},
                    "rows": [
                        {
                            "queue_id": "k1",
                            "verification_status": "needs_more_source",
                            "terminal_outcome": "needs_more_source",
                            "source_collection_required": True,
                        }
                    ],
                },
            )
            write_json(
                closure_queue,
                {
                    "schema": "auditooor.v3_provider_source_collection_queue.v1",
                    "summary": {
                        "source_rows": 1,
                        "deduped_items": 1,
                        "terminal_judgment_rows": 0,
                        "terminal_judgment_items": 0,
                        "by_source_reviewer": {"kimi": 1, "local": 1},
                    },
                    "items": [{"source_collection_id": "V3-SC-001"}],
                },
            )

            payload = gate.build_gate(ws, campaign_id="cam")

        codes = {row["code"] for row in payload["blockers"]}
        closure = payload["remediation_evidence"]["closure_packet_queue"]
        self.assertEqual(payload["status"], "fail")
        self.assertIn("blocking_local_verification_status", codes)
        self.assertIn("source_collection_required_rows", codes)
        self.assertTrue(closure["present"])
        self.assertEqual(closure["deduped_items"], 1)
        self.assertEqual(closure["by_source_reviewer"], {"kimi": 1, "local": 1})
        self.assertIn("do not resolve blockers", payload["remediation_evidence"]["claim_guard"])

    # ------------------------------------------------------------------
    # Gap-closure tests (accounting enforcement)
    # ------------------------------------------------------------------

    def _make_pass_fixture(self, tmp: str, *, tokens_used: int = 50) -> tuple[Path, Path]:
        """Build a minimal passing campaign fixture. Returns (ws, run_dir)."""
        ws = Path(tmp) / "ws"
        run_dir = ws / ".auditooor" / "provider_fanout" / "cam" / "runs" / "run-1"
        out = run_dir / "provider_outputs" / "kimi.txt"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text("classification: KEEP_FOR_LOCAL_VERIFICATION\n", encoding="utf-8")
        write_json(
            ws / ".auditooor" / "provider_fanout" / "cam" / "v3_provider_fanout_queue.json",
            {"campaign_id": "cam", "provider_counts": {"kimi": 1}, "total_tasks": 1, "rows": [{"provider": "kimi"}]},
        )
        write_json(
            run_dir / "v3_provider_fanout_run.json",
            {"campaign_id": "cam", "run_id": "run-1", "run_dir": str(run_dir), "rows": [{"provider": "kimi"}]},
        )
        write_json(
            run_dir / "fanout_closeout.json",
            {
                "campaign_id": "cam",
                "run_id": "run-1",
                "rows": [
                    {
                        "task_id": "k1",
                        "provider": "kimi",
                        "status": "needs_local_verification",
                        "model": "kimi-k2.6",
                        "provider_output_path": str(out),
                        "provider_output_bytes": out.stat().st_size,
                        "mcp_receipt": {"path": "receipt.json", "sha256_16": "abcd"},
                        "local_verification_required": True,
                        "tokens_used": tokens_used,
                    }
                ],
            },
        )
        write_json(
            run_dir / "v3_provider_local_verification_result.json",
            {
                "schema": "auditooor.v3_provider_local_verification_result.v1",
                "campaign_id": "cam",
                "run_id": "run-1",
                "summary": {"source_collection_required_rows": 0, "terminal_judgment_required_rows": 0},
                "rows": [
                    {
                        "queue_id": "k1",
                        "verification_status": "no_action",
                        "terminal_outcome": "verified_no_action",
                        "advisory_only": True,
                        "promotion_authority": False,
                        "submit_ready": False,
                        "severity": "none",
                    }
                ],
            },
        )
        return ws, run_dir

    def test_zero_token_burn_is_blocked(self) -> None:
        """Gap 1: closeout row with tokens_used=0 must block the gate."""
        with tempfile.TemporaryDirectory() as tmp:
            ws, _ = self._make_pass_fixture(tmp, tokens_used=0)
            payload = gate.build_gate(ws, campaign_id="cam")

        codes = {row["code"] for row in payload["blockers"]}
        self.assertEqual(payload["status"], "fail")
        self.assertIn("zero_token_burn", codes)

    def test_nonzero_token_burn_does_not_block(self) -> None:
        """Gap 1 (inverse): tokens_used > 0 must not raise zero_token_burn."""
        with tempfile.TemporaryDirectory() as tmp:
            ws, _ = self._make_pass_fixture(tmp, tokens_used=42)
            payload = gate.build_gate(ws, campaign_id="cam")

        codes = {row["code"] for row in payload["blockers"]}
        self.assertNotIn("zero_token_burn", codes)

    def test_blocked_status_row_with_zero_tokens_is_not_flagged(self) -> None:
        """Gap 1 (edge): rows in a blocking closeout status must not also get zero_token_burn."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            run_dir = ws / ".auditooor" / "provider_fanout" / "cam" / "runs" / "run-1"
            out = run_dir / "out.txt"
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text("classification: KEEP\n", encoding="utf-8")
            write_json(
                ws / ".auditooor" / "provider_fanout" / "cam" / "v3_provider_fanout_queue.json",
                {"campaign_id": "cam", "provider_counts": {"kimi": 1}, "total_tasks": 1, "rows": [{"provider": "kimi"}]},
            )
            write_json(
                run_dir / "v3_provider_fanout_run.json",
                {"campaign_id": "cam", "run_id": "run-1", "run_dir": str(run_dir), "rows": [{"provider": "kimi"}]},
            )
            # Row with blocked_no_mcp_receipt status and zero tokens
            write_json(
                run_dir / "fanout_closeout.json",
                {
                    "campaign_id": "cam",
                    "run_id": "run-1",
                    "rows": [
                        {
                            "task_id": "k1",
                            "provider": "kimi",
                            "status": "blocked_no_mcp_receipt",
                            "model": "kimi-k2.6",
                            "provider_output_path": str(out),
                            "provider_output_bytes": out.stat().st_size,
                            "mcp_receipt": {},
                            "local_verification_required": True,
                            "tokens_used": 0,
                        }
                    ],
                },
            )
            write_json(
                run_dir / "v3_provider_local_verification_result.json",
                {"campaign_id": "cam", "run_id": "run-1", "summary": {}, "rows": []},
            )
            payload = gate.build_gate(ws, campaign_id="cam")

        codes = {row["code"] for row in payload["blockers"]}
        # Should be blocked for missing_mcp_receipt (via blocking_closeout_status) but NOT zero_token_burn
        self.assertNotIn("zero_token_burn", codes)
        self.assertEqual(payload["status"], "fail")

    def test_provider_only_promotion_escape_count_is_zero_on_clean_run(self) -> None:
        """Gap 2+3: clean run must report provider_only_promotion_escape_count=0."""
        with tempfile.TemporaryDirectory() as tmp:
            ws, _ = self._make_pass_fixture(tmp, tokens_used=50)
            payload = gate.build_gate(ws, campaign_id="cam")

        self.assertEqual(payload["status"], "pass")
        self.assertIn("provider_only_promotion_escape_count", payload)
        self.assertEqual(payload["provider_only_promotion_escape_count"], 0)

    def test_promotion_authority_true_in_verification_row_blocks_gate(self) -> None:
        """Gap 2: verification row with promotion_authority=True must block."""
        with tempfile.TemporaryDirectory() as tmp:
            ws, run_dir = self._make_pass_fixture(tmp, tokens_used=50)
            # Overwrite verification result with a promotion-escaped row
            write_json(
                run_dir / "v3_provider_local_verification_result.json",
                {
                    "schema": "auditooor.v3_provider_local_verification_result.v1",
                    "campaign_id": "cam",
                    "run_id": "run-1",
                    "summary": {"source_collection_required_rows": 0, "terminal_judgment_required_rows": 0},
                    "rows": [
                        {
                            "queue_id": "k1",
                            "verification_status": "verified",
                            "terminal_outcome": "verified_no_action",
                            "advisory_only": True,
                            "promotion_authority": True,
                            "submit_ready": False,
                            "severity": "none",
                        }
                    ],
                },
            )
            payload = gate.build_gate(ws, campaign_id="cam")

        codes = {row["code"] for row in payload["blockers"]}
        self.assertEqual(payload["status"], "fail")
        self.assertIn("provider_only_promotion_escape", codes)
        self.assertEqual(payload["provider_only_promotion_escape_count"], 1)

    def test_submit_ready_true_in_verification_row_blocks_gate(self) -> None:
        """Gap 2: verification row with submit_ready=True must block."""
        with tempfile.TemporaryDirectory() as tmp:
            ws, run_dir = self._make_pass_fixture(tmp, tokens_used=50)
            write_json(
                run_dir / "v3_provider_local_verification_result.json",
                {
                    "schema": "auditooor.v3_provider_local_verification_result.v1",
                    "campaign_id": "cam",
                    "run_id": "run-1",
                    "summary": {"source_collection_required_rows": 0, "terminal_judgment_required_rows": 0},
                    "rows": [
                        {
                            "queue_id": "k1",
                            "verification_status": "no_action",
                            "terminal_outcome": "verified_no_action",
                            "advisory_only": True,
                            "promotion_authority": False,
                            "submit_ready": True,
                            "severity": "none",
                        }
                    ],
                },
            )
            payload = gate.build_gate(ws, campaign_id="cam")

        codes = {row["code"] for row in payload["blockers"]}
        self.assertEqual(payload["status"], "fail")
        self.assertIn("provider_only_promotion_escape", codes)
        self.assertEqual(payload["provider_only_promotion_escape_count"], 1)

    def test_nonnone_severity_in_verification_row_blocks_gate(self) -> None:
        """Gap 2: verification row with severity != 'none' must block."""
        with tempfile.TemporaryDirectory() as tmp:
            ws, run_dir = self._make_pass_fixture(tmp, tokens_used=50)
            write_json(
                run_dir / "v3_provider_local_verification_result.json",
                {
                    "schema": "auditooor.v3_provider_local_verification_result.v1",
                    "campaign_id": "cam",
                    "run_id": "run-1",
                    "summary": {"source_collection_required_rows": 0, "terminal_judgment_required_rows": 0},
                    "rows": [
                        {
                            "queue_id": "k1",
                            "verification_status": "verified",
                            "terminal_outcome": "verified_no_action",
                            "advisory_only": True,
                            "promotion_authority": False,
                            "submit_ready": False,
                            "severity": "HIGH",
                        }
                    ],
                },
            )
            payload = gate.build_gate(ws, campaign_id="cam")

        codes = {row["code"] for row in payload["blockers"]}
        self.assertEqual(payload["status"], "fail")
        self.assertIn("provider_only_promotion_escape", codes)
        self.assertGreater(payload["provider_only_promotion_escape_count"], 0)

    def test_advisory_only_false_in_verification_row_blocks_gate(self) -> None:
        """Gap 2: verification row with advisory_only=False must block."""
        with tempfile.TemporaryDirectory() as tmp:
            ws, run_dir = self._make_pass_fixture(tmp, tokens_used=50)
            write_json(
                run_dir / "v3_provider_local_verification_result.json",
                {
                    "schema": "auditooor.v3_provider_local_verification_result.v1",
                    "campaign_id": "cam",
                    "run_id": "run-1",
                    "summary": {"source_collection_required_rows": 0, "terminal_judgment_required_rows": 0},
                    "rows": [
                        {
                            "queue_id": "k1",
                            "verification_status": "verified",
                            "terminal_outcome": "verified_no_action",
                            "advisory_only": False,
                            "promotion_authority": False,
                            "submit_ready": False,
                            "severity": "none",
                        }
                    ],
                },
            )
            payload = gate.build_gate(ws, campaign_id="cam")

        codes = {row["code"] for row in payload["blockers"]}
        self.assertEqual(payload["status"], "fail")
        self.assertIn("provider_only_promotion_escape", codes)
        self.assertEqual(payload["provider_only_promotion_escape_count"], 1)

    def test_multiple_escape_violations_counted_correctly(self) -> None:
        """Gap 3: escape count must reflect all offending rows, not just the first."""
        with tempfile.TemporaryDirectory() as tmp:
            ws, run_dir = self._make_pass_fixture(tmp, tokens_used=50)
            write_json(
                ws / ".auditooor" / "provider_fanout" / "cam" / "v3_provider_fanout_queue.json",
                {"campaign_id": "cam", "provider_counts": {"kimi": 2}, "total_tasks": 2, "rows": [{"provider": "kimi"}, {"provider": "kimi"}]},
            )
            out = run_dir / "provider_outputs" / "kimi.txt"
            out2 = run_dir / "provider_outputs" / "kimi2.txt"
            out2.write_text("classification: KEEP\n", encoding="utf-8")
            write_json(
                run_dir / "v3_provider_fanout_run.json",
                {"campaign_id": "cam", "run_id": "run-1", "run_dir": str(run_dir), "rows": [{"provider": "kimi"}, {"provider": "kimi"}]},
            )
            write_json(
                run_dir / "fanout_closeout.json",
                {
                    "campaign_id": "cam",
                    "run_id": "run-1",
                    "rows": [
                        {
                            "task_id": "k1", "provider": "kimi", "status": "needs_local_verification",
                            "model": "kimi-k2.6", "provider_output_path": str(out),
                            "provider_output_bytes": out.stat().st_size,
                            "mcp_receipt": {"path": "r.json", "sha256_16": "ab"}, "local_verification_required": True, "tokens_used": 10,
                        },
                        {
                            "task_id": "k2", "provider": "kimi", "status": "needs_local_verification",
                            "model": "kimi-k2.6", "provider_output_path": str(out2),
                            "provider_output_bytes": out2.stat().st_size,
                            "mcp_receipt": {"path": "r.json", "sha256_16": "cd"}, "local_verification_required": True, "tokens_used": 10,
                        },
                    ],
                },
            )
            write_json(
                run_dir / "v3_provider_local_verification_result.json",
                {
                    "schema": "auditooor.v3_provider_local_verification_result.v1",
                    "campaign_id": "cam",
                    "run_id": "run-1",
                    "summary": {"source_collection_required_rows": 0, "terminal_judgment_required_rows": 0},
                    "rows": [
                        {"queue_id": "k1", "verification_status": "verified", "terminal_outcome": "verified_no_action",
                         "advisory_only": True, "promotion_authority": True, "submit_ready": False, "severity": "none"},
                        {"queue_id": "k2", "verification_status": "verified", "terminal_outcome": "verified_no_action",
                         "advisory_only": True, "promotion_authority": False, "submit_ready": True, "severity": "HIGH"},
                    ],
                },
            )
            payload = gate.build_gate(ws, campaign_id="cam")

        self.assertEqual(payload["status"], "fail")
        self.assertEqual(payload["provider_only_promotion_escape_count"], 2)


if __name__ == "__main__":
    unittest.main()
