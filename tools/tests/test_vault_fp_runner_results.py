"""Tests for the ``vault_fp_runner_results`` MCP callable.

Wave-4 capability lift (W4.9). Surfaces the universal_fp_runner output
JSON (schema ``auditooor.universal_fp_runner.v1``) that ``make audit-deep``
writes to
``<workspace>/.auditooor/solidity-deep-audit/universal-fp-runner.output.json``.

Exercises:

- envelope shape (schema / context_pack_id / context_pack_hash);
- degraded envelopes (workspace_not_found, output_not_found,
  output_unreadable);
- production_only filter (default true) vs include-all;
- explicit output_path override;
- limit clamping of the hit sample;
- hits_per_fp / hits_per_classification passthrough;
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
        "vault_mcp_server_fp_runner_results_test", MODULE_PATH
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


vault_mcp_server = _load_module()


def _runner_output() -> dict[str, Any]:
    return {
        "schema": "auditooor.universal_fp_runner.v1",
        "target_workspace": "/audits/demo",
        "fp_dir": "/audits/demo/fp",
        "target_languages": ["solidity", "go"],
        "total_hits": 4,
        "production_hit_count": 3,
        "hits_per_fp": {"FP-01": 3, "FP-03": 1},
        "hits_per_classification": {
            "production": 3,
            "test": 1,
            "mock": 0,
            "lib": 0,
            "script": 0,
            "unknown": 0,
        },
        "hits_per_fp_by_classification": {},
        "fps_evaluated": [
            {"fp_id": "FP-01", "record_id": "r1"},
            {"fp_id": "FP-03", "record_id": "r3"},
        ],
        "hits": [
            {
                "fp_id": "FP-01",
                "file": "/audits/demo/src/Vault.sol",
                "line": 42,
                "function": "withdraw",
                "confidence": "high",
                "path_classification": "production",
                "evidence": "state write without preceding require",
            },
            {
                "fp_id": "FP-01",
                "file": "/audits/demo/src/Pool.sol",
                "line": 88,
                "function": "deposit",
                "confidence": "medium",
                "path_classification": "production",
                "evidence": "state write without preceding require",
            },
            {
                "fp_id": "FP-03",
                "file": "/audits/demo/src/Admin.sol",
                "line": 12,
                "function": "setConfig",
                "confidence": "high",
                "path_classification": "production",
                "evidence": "admin setter writes config without refresh",
            },
            {
                "fp_id": "FP-01",
                "file": "/audits/demo/test/Vault.t.sol",
                "line": 5,
                "function": "testWithdraw",
                "confidence": "low",
                "path_classification": "test",
                "evidence": "test-path hit",
            },
        ],
    }


class FpRunnerResultsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="fp-runner-mcp-test-")
        self.root = Path(self.tmp.name)
        self.ws = self.root / "ws"
        self.deep_dir = self.ws / ".auditooor" / "solidity-deep-audit"
        self.deep_dir.mkdir(parents=True)
        self.out_path = self.deep_dir / "universal-fp-runner.output.json"
        self.out_path.write_text(json.dumps(_runner_output()), encoding="utf-8")
        self.vault_dir = self.root / "obsidian-vault"
        self.vault_dir.mkdir()
        self.vault = vault_mcp_server.VaultQuery(self.vault_dir, self.root)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    # 1.
    def test_envelope_shape(self):
        r = self.vault.vault_fp_runner_results(workspace_path=str(self.ws))
        self.assertEqual(r["schema"], vault_mcp_server.FP_RUNNER_RESULTS_SCHEMA)
        self.assertTrue(
            r["context_pack_id"].startswith(
                vault_mcp_server.FP_RUNNER_RESULTS_SCHEMA + ":"
            )
        )
        self.assertEqual(len(r["context_pack_hash"]), 64)
        self.assertFalse(r["degraded"])
        self.assertEqual(r["total_hits"], 4)
        self.assertEqual(r["production_hit_count"], 3)
        self.assertEqual(r["fps_evaluated"], 2)

    # 2.
    def test_production_only_default(self):
        r = self.vault.vault_fp_runner_results(workspace_path=str(self.ws))
        self.assertTrue(r["production_only"])
        # 3 production hits, none test.
        self.assertEqual(r["hits_returned"], 3)
        for h in r["hits"]:
            self.assertEqual(h["path_classification"], "production")

    # 3.
    def test_include_all_classifications(self):
        r = self.vault.vault_fp_runner_results(
            workspace_path=str(self.ws), production_only=False
        )
        self.assertFalse(r["production_only"])
        self.assertEqual(r["hits_returned"], 4)

    # 4.
    def test_limit_clamps_hit_sample(self):
        r = self.vault.vault_fp_runner_results(
            workspace_path=str(self.ws), production_only=False, limit=2
        )
        self.assertEqual(r["hits_returned"], 2)

    # 5.
    def test_hits_per_fp_passthrough(self):
        r = self.vault.vault_fp_runner_results(workspace_path=str(self.ws))
        self.assertEqual(r["hits_per_fp"], {"FP-01": 3, "FP-03": 1})
        self.assertEqual(r["hits_per_classification"]["production"], 3)

    # 6.
    def test_workspace_not_found_degraded(self):
        r = self.vault.vault_fp_runner_results(
            workspace_path=str(self.root / "nonexistent")
        )
        self.assertTrue(r["degraded"])
        self.assertEqual(r["reason"], "workspace_not_found")
        self.assertEqual(r["total_hits"], 0)

    # 7.
    def test_output_not_found_degraded(self):
        empty_ws = self.root / "empty-ws"
        empty_ws.mkdir()
        r = self.vault.vault_fp_runner_results(workspace_path=str(empty_ws))
        self.assertTrue(r["degraded"])
        self.assertEqual(r["reason"], "fp_runner_output_not_found")

    # 8.
    def test_output_unreadable_degraded(self):
        self.out_path.write_text("{not valid json", encoding="utf-8")
        r = self.vault.vault_fp_runner_results(workspace_path=str(self.ws))
        self.assertTrue(r["degraded"])
        self.assertEqual(r["reason"], "fp_runner_output_unreadable")

    # 9.
    def test_explicit_output_path(self):
        r = self.vault.vault_fp_runner_results(output_path=str(self.out_path))
        self.assertFalse(r["degraded"])
        self.assertEqual(r["total_hits"], 4)

    # 10.
    def test_missing_workspace_path_degraded(self):
        r = self.vault.vault_fp_runner_results()
        self.assertTrue(r["degraded"])
        self.assertEqual(r["reason"], "workspace_path_required")

    # 11.
    def test_dispatch_via_call(self):
        r = self.vault._dispatch(
            "vault_fp_runner_results", {"workspace_path": str(self.ws)}
        )
        self.assertEqual(r["schema"], vault_mcp_server.FP_RUNNER_RESULTS_SCHEMA)
        self.assertEqual(r["production_hit_count"], 3)


if __name__ == "__main__":
    unittest.main()
