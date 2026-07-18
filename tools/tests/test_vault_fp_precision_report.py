"""Tests for the ``vault_fp_precision_report`` MCP callable.

Wave-4 capability lift (W4.9). Surfaces the FP/TP feedback-loop
precision-tuning report (schema ``auditooor.fp_tp_feedback_loop.v1``)
emitted by ``tools/audit/fp_tp_feedback_loop.py``.

Exercises:

- envelope shape (schema / context_pack_id / context_pack_hash);
- degraded envelopes (report_path_required, report_not_found,
  report_unreadable, workspace_not_found);
- classification filter (keep-promote / refine / ...);
- totals / classification_buckets / thresholds passthrough;
- limit clamping of fp_shapes;
- explicit report_path vs workspace-resolved default path;
- dispatch routing via ``_dispatch``.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"


def _load_module() -> Any:
    spec = importlib.util.spec_from_file_location(
        "vault_mcp_server_fp_precision_report_test", MODULE_PATH
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


vault_mcp_server = _load_module()


def _report() -> dict[str, Any]:
    return {
        "schema": "auditooor.fp_tp_feedback_loop.v1",
        "ledger": "/audits/demo/.auditooor/fp_verdict_ledger.jsonl",
        "ledger_schema": "auditooor.fp_verdict_ledger.v1",
        "runner_outputs": ["/audits/demo/.auditooor/universal-fp-runner.output.json"],
        "thresholds": {"promote": 0.8, "refine": 0.4, "min_verdicts": 5},
        "totals": {
            "fp_shapes": 3,
            "runner_hits": 30,
            "tp": 18,
            "fp": 9,
            "negative": 3,
            "overall_precision": 0.6667,
        },
        "classification_buckets": {
            "keep-promote": ["FP-01"],
            "refine": ["FP-03"],
            "insufficient-data": ["FP-05"],
        },
        "fp_shapes": [
            {
                "fp_id": "FP-01",
                "runner_hits": 12,
                "tp": 11,
                "fp": 1,
                "negative": 0,
                "scored_verdicts": 12,
                "precision": 0.9167,
                "verdict_coverage": 1.0,
                "workspaces": ["/audits/demo"],
                "classification": "keep-promote",
                "rationale": "precision 0.92 >= promote threshold 0.80",
            },
            {
                "fp_id": "FP-03",
                "runner_hits": 10,
                "tp": 2,
                "fp": 8,
                "negative": 0,
                "scored_verdicts": 10,
                "precision": 0.2,
                "verdict_coverage": 1.0,
                "workspaces": ["/audits/demo"],
                "classification": "refine",
                "rationale": "precision 0.20 < refine threshold 0.40 - needs a tighter shape",
            },
            {
                "fp_id": "FP-05",
                "runner_hits": 8,
                "tp": 5,
                "fp": 0,
                "negative": 3,
                "scored_verdicts": 5,
                "precision": 1.0,
                "verdict_coverage": 0.625,
                "workspaces": ["/audits/demo"],
                "classification": "insufficient-data",
                "rationale": "scored verdicts below min threshold",
            },
        ],
    }


class FpPrecisionReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="fp-precision-mcp-test-")
        self.root = Path(self.tmp.name)
        self.ws = self.root / "ws"
        (self.ws / ".auditooor").mkdir(parents=True)
        self.rep_path = self.ws / ".auditooor" / "fp_tp_feedback_loop.output.json"
        self.rep_path.write_text(json.dumps(_report()), encoding="utf-8")
        self.vault_dir = self.root / "obsidian-vault"
        self.vault_dir.mkdir()
        self.vault = vault_mcp_server.VaultQuery(self.vault_dir, self.root)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    # 1.
    def test_envelope_shape(self):
        r = self.vault.vault_fp_precision_report(workspace_path=str(self.ws))
        self.assertEqual(r["schema"], vault_mcp_server.FP_PRECISION_REPORT_SCHEMA)
        self.assertTrue(
            r["context_pack_id"].startswith(
                vault_mcp_server.FP_PRECISION_REPORT_SCHEMA + ":"
            )
        )
        self.assertEqual(len(r["context_pack_hash"]), 64)
        self.assertFalse(r["degraded"])
        self.assertEqual(r["fp_shapes_returned"], 3)

    # 2.
    def test_totals_and_thresholds_passthrough(self):
        r = self.vault.vault_fp_precision_report(workspace_path=str(self.ws))
        self.assertEqual(r["totals"]["tp"], 18)
        self.assertEqual(r["totals"]["overall_precision"], 0.6667)
        self.assertEqual(r["thresholds"]["promote"], 0.8)

    # 3.
    def test_classification_buckets_passthrough(self):
        r = self.vault.vault_fp_precision_report(workspace_path=str(self.ws))
        self.assertEqual(r["classification_buckets"]["keep-promote"], ["FP-01"])
        self.assertEqual(r["classification_buckets"]["refine"], ["FP-03"])

    # 4.
    def test_classification_filter(self):
        r = self.vault.vault_fp_precision_report(
            workspace_path=str(self.ws), classification="refine"
        )
        self.assertEqual(r["fp_shapes_returned"], 1)
        self.assertEqual(r["fp_shapes"][0]["fp_id"], "FP-03")
        self.assertEqual(r["classification_filter"], "refine")

    # 5.
    def test_classification_filter_case_insensitive(self):
        r = self.vault.vault_fp_precision_report(
            workspace_path=str(self.ws), classification="KEEP-PROMOTE"
        )
        self.assertEqual(r["fp_shapes_returned"], 1)
        self.assertEqual(r["fp_shapes"][0]["fp_id"], "FP-01")

    # 6.
    def test_limit_clamps_rows(self):
        r = self.vault.vault_fp_precision_report(
            workspace_path=str(self.ws), limit=1
        )
        self.assertEqual(r["fp_shapes_returned"], 1)

    # 7.
    def test_explicit_report_path(self):
        r = self.vault.vault_fp_precision_report(report_path=str(self.rep_path))
        self.assertFalse(r["degraded"])
        self.assertEqual(r["fp_shapes_returned"], 3)

    # 8.
    def test_report_path_required_degraded(self):
        r = self.vault.vault_fp_precision_report()
        self.assertTrue(r["degraded"])
        self.assertEqual(r["reason"], "report_path_required")

    # 9.
    def test_report_not_found_degraded(self):
        empty_ws = self.root / "empty-ws"
        empty_ws.mkdir()
        r = self.vault.vault_fp_precision_report(workspace_path=str(empty_ws))
        self.assertTrue(r["degraded"])
        self.assertEqual(r["reason"], "fp_precision_report_not_found")

    # 10.
    def test_report_unreadable_degraded(self):
        self.rep_path.write_text("{bad json", encoding="utf-8")
        r = self.vault.vault_fp_precision_report(workspace_path=str(self.ws))
        self.assertTrue(r["degraded"])
        self.assertEqual(r["reason"], "fp_precision_report_unreadable")

    # 11.
    def test_dispatch_via_call(self):
        r = self.vault._dispatch(
            "vault_fp_precision_report", {"workspace_path": str(self.ws)}
        )
        self.assertEqual(r["schema"], vault_mcp_server.FP_PRECISION_REPORT_SCHEMA)
        self.assertEqual(r["fp_shapes_returned"], 3)


if __name__ == "__main__":
    unittest.main()
