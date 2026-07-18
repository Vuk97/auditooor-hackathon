from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "v3-provider-learning-compiler.py"


def _import_tool():
    spec = importlib.util.spec_from_file_location("v3_provider_learning_compiler_test", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class V3ProviderLearningCompilerTests(unittest.TestCase):
    def test_compiles_only_terminal_rows_into_quarantined_ledger_entries(self) -> None:
        mod = _import_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = root / "result.json"
            ledger = root / ".auditooor" / "agent_artifacts" / "learning_ledger.jsonl"
            result.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.v3_provider_local_verification_result.v1",
                        "campaign_id": "hackerman-v3-8kimi-8minimax",
                        "run_id": "unit",
                        "summary": {"by_terminal_outcome": {"needs_more_source": 1}},
                        "rows": [
                            {
                                "queue_id": "V3-LV-001",
                                "task_id": "task-1",
                                "provider": "kimi",
                                "model": "kimi-for-coding",
                                "route": "external_source_needed",
                                "terminal_safe": True,
                                "terminal_outcome": "needs_more_source",
                                "terminal_outcome_options": ["needs_more_source", "verified_no_action"],
                                "learning_ledger_ready": True,
                                "local_verification_required": False,
                                "advisory_only": True,
                                "promotion_authority": False,
                                "submit_ready": False,
                                "severity": "none",
                                "claim": {
                                    "kind": "proof_obligation",
                                    "summary": "Need primary source before use",
                                    "provider_claim_id": "c1",
                                    "provider_verdict": "KEEP_FOR_LOCAL_VERIFICATION",
                                },
                                "source_provider_row": {
                                    "provider_output_path": "provider.out.txt",
                                    "advisory_only": True,
                                },
                                "verification": {"status": "needs_more_source", "evidence_refs": []},
                            },
                            {
                                "queue_id": "V3-LV-002",
                                "task_id": "task-2",
                                "provider": "minimax",
                                "route": "local_source_review",
                                "terminal_outcome": None,
                                "claim": {"summary": "pending row"},
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )
            payload = mod.compile_learning(result, ledger)
            again = mod.compile_learning(result, ledger)
            rows = [json.loads(line) for line in ledger.read_text(encoding="utf-8").splitlines()]

        self.assertEqual(payload["terminal_rows_seen"], 1)
        self.assertEqual(payload["rows_appended"], 1)
        self.assertEqual(again["rows_appended"], 0)
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["source"], "v3-provider-local-verification")
        self.assertEqual(row["terminal_kind"], "NO_ACTION")
        self.assertEqual(row["terminal_outcome"], "needs_more_source")
        self.assertEqual(row["primary_for"], "source_reachability")
        self.assertEqual(row["evidence_polarity"], "limits")
        self.assertTrue(row["quarantine"])
        self.assertFalse(row["promotion_authority"])
        self.assertFalse(row["submit_ready"])
        self.assertEqual(row["severity"], "none")
        self.assertEqual(row["provider_lineage"]["provider_claim_id"], "c1")

    def test_unsafe_terminal_rows_are_not_compiled_and_actionable_stays_quarantined(self) -> None:
        mod = _import_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = root / "result.json"
            ledger = root / ".auditooor" / "agent_artifacts" / "learning_ledger.jsonl"
            base = {
                "task_id": "task",
                "provider": "kimi",
                "model": "kimi-for-coding",
                "route": "local_source_review",
                "terminal_outcome": "verified_actionable",
                "terminal_outcome_options": ["verified_actionable", "needs_more_source"],
                "claim": {"kind": "proof_obligation", "summary": "candidate lesson"},
                "source_provider_row": {"advisory_only": True},
                "verification": {"status": "verified", "evidence_refs": []},
                "local_verification_required": False,
                "advisory_only": True,
                "promotion_authority": False,
                "submit_ready": False,
                "severity": "none",
            }
            safe = dict(base, queue_id="V3-LV-010", terminal_safe=True, learning_ledger_ready=True)
            forged = dict(base, queue_id="V3-LV-011", terminal_safe=False, learning_ledger_ready=True)
            result.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.v3_provider_local_verification_result.v1",
                        "campaign_id": "hackerman-v3-8kimi-8minimax",
                        "run_id": "unit",
                        "summary": {"by_terminal_outcome": {"verified_actionable": 2}},
                        "rows": [safe, forged],
                    }
                ),
                encoding="utf-8",
            )

            payload = mod.compile_learning(result, ledger)
            rows = [json.loads(line) for line in ledger.read_text(encoding="utf-8").splitlines()]

        self.assertEqual(payload["terminal_rows_seen"], 2)
        self.assertEqual(payload["unsafe_terminal_rows_skipped"], 1)
        self.assertEqual(payload["rows_appended"], 1)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["queue_id"], "V3-LV-010")
        self.assertTrue(rows[0]["quarantine"])
        self.assertFalse(rows[0]["promotion_authority"])
        self.assertFalse(rows[0]["submit_ready"])


if __name__ == "__main__":
    unittest.main()
