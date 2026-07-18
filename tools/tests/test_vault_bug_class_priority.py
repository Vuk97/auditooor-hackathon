"""Tests for VaultQuery.vault_bug_class_priority callable (W5-M3).

synthetic_fixture: true

Verifies:
  1. Degraded envelope when no report_path / workspace is given.
  2. Degraded envelope when the report JSON is absent.
  3. Happy path on a synthetic bug_class_priority JSON returns ranked rows.
  4. limit is honored.
  5. Envelope carries schema + context_pack_id + context_pack_hash.
  6. CLI dispatch exits 0; callable appears in TOOL_SCHEMAS.
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

_SYNTH_PRIORITY = {
    "schema": "auditooor.bug_class_priority.v1",
    "workspace": "synth-ws",
    "protocol_category": "lending",
    "score_weights": {"w_sev": 0.4, "w_dens": 0.3, "w_conc": 0.2, "w_prec": 0.1},
    "classes_scored": 3,
    "ranked_attack_classes": [
        {"attack_class": "reentrancy", "priority": 0.91, "rationale": "high payout history"},
        {"attack_class": "access-control", "priority": 0.74, "rationale": "dense corpus"},
        {"attack_class": "rounding", "priority": 0.41, "rationale": "low concentration"},
    ],
}


class TestVaultBugClassPriority(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="w5m3-bugclass-")
        self.root = Path(self.tmp.name)
        self.vault = self.root / "obsidian-vault"
        _make_minimal_vault(self.vault)
        self.query = vault_mcp_server.VaultQuery(self.vault, self.root)
        # synthetic_fixture: true
        self.rep_path = self.root / "synth_bug_class_priority.json"
        self.rep_path.write_text(json.dumps(_SYNTH_PRIORITY), encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def test_degraded_when_no_path(self):
        # synthetic_fixture: true
        result = self.query.vault_bug_class_priority()
        self.assertTrue(result.get("degraded"))
        self.assertEqual(result.get("reason"), "report_path_required")

    def test_degraded_when_absent(self):
        # synthetic_fixture: true
        result = self.query.vault_bug_class_priority(
            report_path=str(self.root / "missing.json")
        )
        self.assertTrue(result.get("degraded"))
        self.assertEqual(result.get("reason"), "bug_class_priority_not_found")

    def test_happy_path_returns_ranked(self):
        # synthetic_fixture: true
        result = self.query.vault_bug_class_priority(report_path=str(self.rep_path))
        self.assertFalse(result.get("degraded"))
        self.assertEqual(result["classes_scored"], 3)
        self.assertEqual(result["ranked_attack_classes"][0]["attack_class"], "reentrancy")

    def test_limit_honored(self):
        # synthetic_fixture: true
        result = self.query.vault_bug_class_priority(
            report_path=str(self.rep_path), limit=2
        )
        self.assertEqual(result["ranked_returned"], 2)

    def test_schema_envelope_present(self):
        # synthetic_fixture: true
        result = self.query.vault_bug_class_priority(report_path=str(self.rep_path))
        self.assertEqual(result.get("schema"), vault_mcp_server.BUG_CLASS_PRIORITY_SCHEMA)
        self.assertIn("context_pack_id", result)
        self.assertIn("context_pack_hash", result)

    def test_cli_dispatch_exits_zero(self):
        # synthetic_fixture: true
        args_json = json.dumps({"report_path": str(self.rep_path)})
        proc = subprocess.run(
            [sys.executable, str(MODULE_PATH), "--repo-root", str(self.root),
             "--vault-dir", str(self.vault), "--call", "vault_bug_class_priority",
             "--args", args_json],
            capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr[:300])
        parsed = json.loads(proc.stdout[proc.stdout.index("{"):])
        self.assertEqual(parsed["classes_scored"], 3)

    def test_callable_in_tool_schemas(self):
        # synthetic_fixture: true
        names = [t["name"] for t in vault_mcp_server.TOOL_SCHEMAS]
        self.assertIn("vault_bug_class_priority", names)


if __name__ == "__main__":
    unittest.main()
