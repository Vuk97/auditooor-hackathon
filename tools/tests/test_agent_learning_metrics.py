"""Tests for agent-learning-metrics.py (Lane K K8)."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "agent-learning-metrics.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("agent_learning_metrics", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["agent_learning_metrics"] = module
    spec.loader.exec_module(module)
    return module


def _write_report(path: Path, artifacts: list[dict]) -> None:
    path.write_text(
        json.dumps({"schema": "test", "artifacts": artifacts}, sort_keys=True),
        encoding="utf-8",
    )


def _write_ledger(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(json.dumps(r, sort_keys=True) for r in rows) + "\n",
        encoding="utf-8",
    )


class AgentLearningMetricsTests(unittest.TestCase):
    def test_emits_k8_metric_set_for_healthy_ledger(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            report = ws / "agent_artifact_mining_report.json"
            ledger = ws / ".auditooor" / "agent_artifacts" / "learning_ledger.jsonl"
            _write_report(
                report,
                [
                    {"artifact_id": "a1", "artifact_type": "rejection_pattern"},
                    {"artifact_id": "a2", "artifact_type": "triager_pattern"},
                ],
            )
            _write_ledger(
                ledger,
                [
                    {
                        "artifact_id": "a1",
                        "terminal_kind": "kill_reason",
                        "proposition": "OOS oracle path",
                        "evidence_polarity": "contradicts",
                        "primary_for": "OOS",
                        "reuse_action": "add_kill_rubric",
                    },
                    {
                        "artifact_id": "a2",
                        "terminal_kind": "triager_objection",
                        "proposition": "Triager objection on severity",
                        "evidence_polarity": "limits",
                        "primary_for": "team_position",
                        "reuse_action": "add_pre_submit_gate",
                    },
                ],
            )
            payload = tool.compute_metrics(ws, report, ledger)

        m = payload["metrics"]
        # Full K8 metric set is present.
        for key in (
            "artifact_accounting_coverage",
            "unclassified_high_critical_artifacts",
            "provider_only_promotion_escape_count",
            "learning_promotion_rate",
            "kill_reason_reuse_rate",
            "triager_objection_pre_submit_caught_count",
            "proof_artifact_binding_rate",
            "closeout_block_count",
            "time_to_learning_hours",
        ):
            self.assertIn(key, m)
        self.assertEqual(m["artifact_accounting_coverage"], 1.0)
        self.assertEqual(m["learning_promotion_rate"], 1.0)
        self.assertEqual(m["kill_reason_reuse_rate"], 1.0)
        self.assertEqual(m["triager_objection_pre_submit_caught_count"], 1)
        self.assertEqual(m["provider_only_promotion_escape_count"], 0)
        self.assertTrue(payload["k8_healthy"])

    def test_flags_unclassified_high_critical_artifact(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            report = ws / "agent_artifact_mining_report.json"
            ledger = ws / ".auditooor" / "agent_artifacts" / "learning_ledger.jsonl"
            _write_report(
                report,
                [
                    {"artifact_id": "hc1", "artifact_type": "x", "severity": "critical"},
                ],
            )
            _write_ledger(ledger, [])  # no terminal row for hc1
            payload = tool.compute_metrics(ws, report, ledger)

        self.assertEqual(payload["metrics"]["unclassified_high_critical_artifacts"], 1)
        self.assertIn("hc1", payload["metrics"]["unclassified_high_critical_ids"])
        self.assertFalse(payload["k8_healthy"])

    def test_provider_only_proof_escape_breaks_health_gate(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            report = ws / "agent_artifact_mining_report.json"
            ledger = ws / ".auditooor" / "agent_artifacts" / "learning_ledger.jsonl"
            _write_report(report, [{"artifact_id": "p1", "artifact_type": "x"}])
            _write_ledger(
                ledger,
                [
                    {
                        "artifact_id": "p1",
                        "terminal_kind": "proof_artifact",
                        "provider_only": True,
                        "proposition": "provider claimed proof",
                        "evidence_polarity": "supports",
                        "primary_for": "proof",
                        "reuse_action": "add_detector",
                    }
                ],
            )
            payload = tool.compute_metrics(ws, report, ledger)

        self.assertEqual(payload["metrics"]["provider_only_promotion_escape_count"], 1)
        self.assertFalse(payload["k8_healthy"])


    def test_closeout_block_count_increments_for_missing_proposition(self) -> None:
        """K8: closeout_block_count must rise when a terminal row is missing its proposition."""
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            report = ws / "agent_artifact_mining_report.json"
            ledger = ws / ".auditooor" / "agent_artifacts" / "learning_ledger.jsonl"
            _write_report(report, [{"artifact_id": "b1", "artifact_type": "x"}])
            # Row has terminal_kind but is missing proposition (K3a required field).
            _write_ledger(ledger, [
                {
                    "artifact_id": "b1",
                    "terminal_kind": "typed_lesson",
                    # No proposition field.
                    "evidence_polarity": "context_only",
                    "primary_for": "methodology",
                    "reuse_action": "none",
                }
            ])
            payload = tool.compute_metrics(ws, report, ledger)

        self.assertGreater(
            payload["metrics"]["closeout_block_count"],
            0,
            "K8: missing proposition must increment closeout_block_count",
        )
        self.assertFalse(payload["k8_healthy"])

    def test_closeout_block_count_increments_for_missing_reuse_action(self) -> None:
        """K8/K4: closeout_block_count must rise when reuse_action is absent on a terminal row."""
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            report = ws / "agent_artifact_mining_report.json"
            ledger = ws / ".auditooor" / "agent_artifacts" / "learning_ledger.jsonl"
            _write_report(report, [{"artifact_id": "r1", "artifact_type": "x"}])
            _write_ledger(ledger, [
                {
                    "artifact_id": "r1",
                    "terminal_kind": "kill_reason",
                    "proposition": "Attacker has no economic incentive",
                    "evidence_polarity": "contradicts",
                    "primary_for": "economics",
                    # Deliberately omit reuse_action.
                }
            ])
            payload = tool.compute_metrics(ws, report, ledger)

        self.assertGreater(
            payload["metrics"]["closeout_block_count"],
            0,
            "K8/K4: missing reuse_action must increment closeout_block_count",
        )
        self.assertFalse(payload["k8_healthy"])

    def test_proof_artifact_binding_rate_with_primary_signal(self) -> None:
        """K8: proof_artifact_binding_rate should be 1.0 when proof row has is_primary_signal=True."""
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            report = ws / "agent_artifact_mining_report.json"
            ledger = ws / ".auditooor" / "agent_artifacts" / "learning_ledger.jsonl"
            _write_report(report, [{"artifact_id": "p1", "artifact_type": "proof_artifact_mapping_candidate"}])
            _write_ledger(ledger, [
                {
                    "artifact_id": "p1",
                    "terminal_kind": "proof_artifact",
                    "is_primary_signal": True,
                    "can_promote_to_proof": True,
                    "proposition": "Local PoC proves the fund loss path",
                    "evidence_polarity": "supports",
                    "primary_for": "proof",
                    "reuse_action": "add_detector",
                }
            ])
            payload = tool.compute_metrics(ws, report, ledger)

        m = payload["metrics"]
        self.assertEqual(m["proof_artifact_count"], 1)
        self.assertEqual(m["proof_artifact_binding_rate"], 1.0)
        self.assertTrue(payload["k8_healthy"])

    def test_k8_healthy_only_when_all_gates_pass(self) -> None:
        """K8: k8_healthy must be False when provider escape count > 0, even if coverage is 100%."""
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            report = ws / "agent_artifact_mining_report.json"
            ledger = ws / ".auditooor" / "agent_artifacts" / "learning_ledger.jsonl"
            _write_report(report, [{"artifact_id": "e1", "artifact_type": "x"}])
            # 100% covered BUT has a provider_only proof_artifact escape.
            _write_ledger(ledger, [
                {
                    "artifact_id": "e1",
                    "terminal_kind": "proof_artifact",
                    "provider_only": True,
                    "proposition": "provider proof escape",
                    "evidence_polarity": "supports",
                    "primary_for": "proof",
                    "reuse_action": "add_detector",
                }
            ])
            payload = tool.compute_metrics(ws, report, ledger)

        m = payload["metrics"]
        self.assertEqual(m["artifact_accounting_coverage"], 1.0, "Coverage should be 100%")
        self.assertEqual(m["provider_only_promotion_escape_count"], 1)
        self.assertFalse(payload["k8_healthy"], "K8: escape count > 0 must make k8_healthy False")


if __name__ == "__main__":
    unittest.main()
