#!/usr/bin/env python3
"""Tests for the Wave-4 Track B vault_attack_class_evidence callable."""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SERVER_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"


def _load_server_module():
    spec = importlib.util.spec_from_file_location("vault_mcp_server_for_test_evidence", SERVER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {SERVER_PATH}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["vault_mcp_server_for_test_evidence"] = mod
    spec.loader.exec_module(mod)
    return mod


SERVER = _load_server_module()


class TestVaultAttackClassEvidence(unittest.TestCase):

    def _vault(self):
        return SERVER.VaultQuery(SERVER.Path(REPO_ROOT))

    def test_missing_attack_class_degraded(self):
        v = self._vault()
        out = v.vault_attack_class_evidence(attack_class="")
        self.assertTrue(out.get("degraded"))
        self.assertEqual(out["schema"], SERVER.ATTACK_CLASS_EVIDENCE_SCHEMA)

    def test_admin_bypass_has_matches(self):
        v = self._vault()
        out = v.vault_attack_class_evidence(attack_class="admin-bypass")
        self.assertFalse(out.get("degraded"))
        # admin-bypass is in the seed (cantina-192 + spark-btkn-freeze-flip + reserve-governor)
        self.assertGreaterEqual(out["total_verdicts_matched"], 1)
        self.assertIsInstance(out["exemplar_verdicts"], list)
        self.assertLessEqual(len(out["exemplar_verdicts"]), 10)

    def test_target_repo_filter_excludes_siblings(self):
        v = self._vault()
        all_out = v.vault_attack_class_evidence(
            attack_class="admin-bypass", sibling_repos_ok=True,
        )
        filt_out = v.vault_attack_class_evidence(
            attack_class="admin-bypass",
            target_repo="dydxprotocol/v4-chain",
            sibling_repos_ok=False,
        )
        self.assertGreaterEqual(
            all_out["total_verdicts_matched"], filt_out["total_verdicts_matched"]
        )

    def test_unknown_attack_class_returns_zero(self):
        v = self._vault()
        out = v.vault_attack_class_evidence(attack_class="nonexistent-attack-class-xyz")
        self.assertFalse(out.get("degraded"))
        self.assertEqual(out["total_verdicts_matched"], 0)

    def test_envelope_has_pack_id(self):
        v = self._vault()
        out = v.vault_attack_class_evidence(attack_class="admin-bypass")
        self.assertIn("context_pack_id", out)
        self.assertTrue(out["context_pack_id"].startswith(SERVER.ATTACK_CLASS_EVIDENCE_SCHEMA))


if __name__ == "__main__":
    unittest.main()
