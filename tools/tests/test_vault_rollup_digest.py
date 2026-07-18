"""Tests for VaultQuery.vault_rollup_digest callable (W5-M3).

synthetic_fixture: true

Verifies:
  1. Degraded envelope when the rollup dir is absent.
  2. Happy path on a synthetic daily rollup returns the note body.
  3. Newest-first ordering and limit are honored.
  4. body_chars truncation is applied.
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


class TestVaultRollupDigest(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="w5m3-rollup-")
        self.root = Path(self.tmp.name)
        self.vault = self.root / "obsidian-vault"
        _make_minimal_vault(self.vault)
        self.query = vault_mcp_server.VaultQuery(self.vault, self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def _seed_daily(self):
        # synthetic_fixture: true
        daily = self.vault / "rollups" / "daily"
        daily.mkdir(parents=True, exist_ok=True)
        (daily / "2026-05-14.md").write_text("# 2026-05-14\n\nolder rollup\n", encoding="utf-8")
        (daily / "2026-05-15.md").write_text("# 2026-05-15\n\n" + "x" * 5000, encoding="utf-8")

    def test_degraded_when_dir_absent(self):
        # synthetic_fixture: true
        result = self.query.vault_rollup_digest(cadence="daily")
        self.assertTrue(result.get("degraded"))
        self.assertEqual(result.get("reason"), "rollup_dir_not_found")

    def test_happy_path_returns_body(self):
        # synthetic_fixture: true
        self._seed_daily()
        result = self.query.vault_rollup_digest(cadence="daily")
        self.assertFalse(result.get("degraded"))
        self.assertEqual(result["rollups_count"], 2)
        # newest first
        self.assertEqual(result["rollups"][0]["rollup"], "2026-05-15")

    def test_limit_honored(self):
        # synthetic_fixture: true
        self._seed_daily()
        result = self.query.vault_rollup_digest(cadence="daily", limit=1)
        self.assertEqual(result["rollups_returned"], 1)
        self.assertEqual(result["rollups"][0]["rollup"], "2026-05-15")

    def test_body_chars_truncation(self):
        # synthetic_fixture: true
        self._seed_daily()
        result = self.query.vault_rollup_digest(cadence="daily", body_chars=500)
        newest = result["rollups"][0]
        self.assertTrue(newest["body_truncated"])
        self.assertLessEqual(len(newest["body"]), 500)

    def test_schema_envelope_present(self):
        # synthetic_fixture: true
        self._seed_daily()
        result = self.query.vault_rollup_digest(cadence="daily")
        self.assertEqual(result.get("schema"), vault_mcp_server.ROLLUP_DIGEST_SCHEMA)
        self.assertIn("context_pack_id", result)
        self.assertIn("context_pack_hash", result)

    def test_cli_dispatch_exits_zero(self):
        # synthetic_fixture: true
        self._seed_daily()
        args_json = json.dumps({"cadence": "daily"})
        proc = subprocess.run(
            [sys.executable, str(MODULE_PATH), "--repo-root", str(self.root),
             "--vault-dir", str(self.vault), "--call", "vault_rollup_digest",
             "--args", args_json],
            capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr[:300])
        parsed = json.loads(proc.stdout[proc.stdout.index("{"):])
        self.assertEqual(parsed["rollups_count"], 2)

    def test_callable_in_tool_schemas(self):
        # synthetic_fixture: true
        names = [t["name"] for t in vault_mcp_server.TOOL_SCHEMAS]
        self.assertIn("vault_rollup_digest", names)


if __name__ == "__main__":
    unittest.main()
