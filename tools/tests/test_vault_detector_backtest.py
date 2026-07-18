"""Tests for VaultQuery.vault_detector_backtest callable (W5-M3).

synthetic_fixture: true

Verifies:
  1. Degraded envelope when the backtest JSON is absent.
  2. Happy path on a synthetic catch-rate JSON returns overall + classes.
  3. weakest_only filters to recall<1.0 rows.
  4. Envelope carries schema + context_pack_id + context_pack_hash.
  5. CLI dispatch exits 0 and returns valid JSON.
  6. Callable appears in TOOL_SCHEMAS list.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("vault_mcp_server", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _make_minimal_vault(vault_dir: Path) -> None:
    # synthetic_fixture: true
    vault_dir.mkdir(parents=True, exist_ok=True)
    (vault_dir / "INDEX.md").write_text("# INDEX\n\n- entry\n", encoding="utf-8")
    (vault_dir / "INDEX_active.md").write_text("# active\n- item\n", encoding="utf-8")
    (vault_dir / "NEXT_LOOP.md").write_text("# NEXT_LOOP\n\n## Section\n- item\n", encoding="utf-8")
    goals = vault_dir / "goals"
    goals.mkdir(exist_ok=True)
    (goals / "current.md").write_text("---\nobjective: synth\n---\n# goal\n", encoding="utf-8")


vault_mcp_server = _load_module()

_SYNTH_BACKTEST = {
    "schema": "auditooor.detector_catch_rate.v1",
    "overall": {"recall_catch_rate": 0.62, "precision": 0.88, "false_positive_rate": 0.05},
    "attack_classes": [
        {"attack_class": "reentrancy", "patterns": 4, "true_positives": 4,
         "false_negatives": 0, "false_positives": 0, "recall": 1.0},
        {"attack_class": "access-control", "patterns": 3, "true_positives": 1,
         "false_negatives": 2, "false_positives": 0, "recall": 0.33},
    ],
}


class TestVaultDetectorBacktest(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="w5m3-backtest-")
        self.root = Path(self.tmp.name)
        self.vault = self.root / "obsidian-vault"
        _make_minimal_vault(self.vault)
        self.query = vault_mcp_server.VaultQuery(self.vault, self.root)
        # synthetic_fixture: true
        self.bt_path = self.root / "synth_detector_catch_rate.json"
        self.bt_path.write_text(json.dumps(_SYNTH_BACKTEST), encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def test_degraded_when_absent(self):
        # synthetic_fixture: true
        result = self.query.vault_detector_backtest(
            backtest_path=str(self.root / "missing.json")
        )
        self.assertTrue(result.get("degraded"))
        self.assertEqual(result.get("reason"), "detector_backtest_not_found")

    def test_happy_path_returns_overall_and_classes(self):
        # synthetic_fixture: true
        result = self.query.vault_detector_backtest(backtest_path=str(self.bt_path))
        self.assertFalse(result.get("degraded"))
        self.assertEqual(result["overall"]["recall_catch_rate"], 0.62)
        self.assertEqual(result["attack_classes_returned"], 2)

    def test_weakest_only_filters(self):
        # synthetic_fixture: true
        result = self.query.vault_detector_backtest(
            backtest_path=str(self.bt_path), weakest_only=True
        )
        self.assertEqual(result["attack_classes_returned"], 1)
        self.assertEqual(result["attack_classes"][0]["attack_class"], "access-control")

    def test_schema_envelope_present(self):
        # synthetic_fixture: true
        result = self.query.vault_detector_backtest(backtest_path=str(self.bt_path))
        self.assertEqual(result.get("schema"), vault_mcp_server.DETECTOR_BACKTEST_SCHEMA)
        self.assertIn("context_pack_id", result)
        self.assertIn("context_pack_hash", result)

    def test_cli_dispatch_exits_zero(self):
        # synthetic_fixture: true
        args_json = json.dumps({"backtest_path": str(self.bt_path)})
        proc = subprocess.run(
            [sys.executable, str(MODULE_PATH), "--repo-root", str(self.root),
             "--vault-dir", str(self.vault), "--call", "vault_detector_backtest",
             "--args", args_json],
            capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr[:300])
        parsed = json.loads(proc.stdout[proc.stdout.index("{"):])
        self.assertEqual(parsed["attack_classes_returned"], 2)

    def test_callable_in_tool_schemas(self):
        # synthetic_fixture: true
        names = [t["name"] for t in vault_mcp_server.TOOL_SCHEMAS]
        self.assertIn("vault_detector_backtest", names)


if __name__ == "__main__":
    unittest.main()
