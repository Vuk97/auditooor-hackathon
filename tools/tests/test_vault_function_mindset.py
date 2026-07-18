#!/usr/bin/env python3
"""Tests for the Wave-4 Track B vault_function_mindset callable."""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SERVER_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"


def _load_server_module():
    spec = importlib.util.spec_from_file_location("vault_mcp_server_for_test_mindset", SERVER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {SERVER_PATH}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["vault_mcp_server_for_test_mindset"] = mod
    spec.loader.exec_module(mod)
    return mod


SERVER = _load_server_module()


class TestVaultFunctionMindset(unittest.TestCase):

    def _vault(self):
        return SERVER.VaultQuery(SERVER.Path(REPO_ROOT))

    def test_missing_target_repo_degraded(self):
        v = self._vault()
        out = v.vault_function_mindset(file_path="x/y.go")
        self.assertTrue(out.get("degraded"))
        self.assertEqual(out["schema"], SERVER.FUNCTION_MINDSET_SCHEMA)

    def test_missing_file_path_degraded(self):
        v = self._vault()
        out = v.vault_function_mindset(target_repo="dydxprotocol/v4-chain")
        self.assertTrue(out.get("degraded"))

    def test_register_affiliate_sanity_top_5_includes_admin_bypass(self):
        v = self._vault()
        out = v.vault_function_mindset(
            target_repo="dydxprotocol/v4-chain",
            file_path="protocol/x/affiliates/keeper/msg_server.go",
            function_signature=(
                "func (k msgServer) RegisterAffiliate(ctx context.Context, "
                "msg *types.MsgRegisterAffiliate) "
                "(*types.MsgRegisterAffiliateResponse, error)"
            ),
            top_n=5,
        )
        self.assertEqual(out["schema"], SERVER.FUNCTION_MINDSET_SCHEMA)
        self.assertFalse(out.get("degraded"))
        top = [r["attack_class"] for r in out["ranked_attack_classes"]]
        # cantina-192 sanity: at least one of the four expected attack classes
        expected = {"admin-bypass", "blocked-addr-bypass", "fee-redirect", "module-account-permafreeze"}
        self.assertTrue(expected & set(top), f"expected at least one of {expected} in {top}")

    def test_envelope_includes_context_pack_id_and_hash(self):
        v = self._vault()
        out = v.vault_function_mindset(
            target_repo="dydxprotocol/v4-chain",
            file_path="protocol/x/affiliates/keeper/msg_server.go",
        )
        self.assertIn("context_pack_id", out)
        self.assertIn("context_pack_hash", out)
        self.assertTrue(out["context_pack_id"].startswith(SERVER.FUNCTION_MINDSET_SCHEMA))

    def test_source_refs_populated(self):
        v = self._vault()
        out = v.vault_function_mindset(
            target_repo="dydxprotocol/v4-chain",
            file_path="protocol/x/affiliates/keeper/msg_server.go",
        )
        self.assertIn("tools/ranker.py", out["source_refs"])
        self.assertIn("tools/hacker_question_renderer.py", out["source_refs"])

    def test_envelope_includes_rendered_hacker_questions(self):
        v = self._vault()
        out = v.vault_function_mindset(
            target_repo="dydxprotocol/v4-chain",
            file_path="protocol/x/affiliates/keeper/msg_server.go",
            function_signature=(
                "func (k msgServer) RegisterAffiliate(ctx context.Context, "
                "msg *types.MsgRegisterAffiliate) "
                "(*types.MsgRegisterAffiliateResponse, error)"
            ),
            top_n=5,
        )

        self.assertEqual(out["hacker_question_schema"], "auditooor.hacker_question.v1")
        self.assertTrue(out["hacker_questions"])
        first = out["hacker_questions"][0]
        self.assertEqual(first["schema"], "auditooor.hacker_question.v1")
        self.assertEqual(first["target_file"], "protocol/x/affiliates/keeper/msg_server.go")
        self.assertTrue(first["question"])
        self.assertIn("proof_obligation", first)
        self.assertIn("kill_condition", first)
        self.assertEqual(first["function_shape_fine"], out["target"]["shape_hash_fine"])
        self.assertEqual(first["mcp_context_pack_id"], out["context_pack_id"])

    def test_function_mindset_does_not_append_ranker_prediction_log_by_default(self):
        log_path = REPO_ROOT / "audit" / "ranker_predictions_log.jsonl"
        before = log_path.read_text(encoding="utf-8") if log_path.is_file() else ""

        v = self._vault()
        v.vault_function_mindset(
            target_repo="dydxprotocol/v4-chain",
            file_path="protocol/x/affiliates/keeper/msg_server.go",
            function_signature=(
                "func (k msgServer) RegisterAffiliate(ctx context.Context, "
                "msg *types.MsgRegisterAffiliate) "
                "(*types.MsgRegisterAffiliateResponse, error)"
            ),
            top_n=2,
        )

        after = log_path.read_text(encoding="utf-8") if log_path.is_file() else ""
        self.assertEqual(after, before)

    def test_merge_prefers_canonical_hackerman_evidence_for_duplicate_class(self):
        merged = SERVER.VaultQuery._merge_ranked_attack_classes(
            legacy_rows=[
                {
                    "attack_class": "admin-bypass",
                    "score": 0.4,
                    "confidence": 0.5,
                    "evidence": [{"record_id": "legacy-admin"}],
                },
                {
                    "attack_class": "fee-redirect",
                    "score": 0.3,
                    "confidence": 0.45,
                    "evidence": [{"record_id": "legacy-fee"}],
                },
            ],
            helper_rows=[
                {
                    "attack_class": "admin-bypass",
                    "score": 9.0,
                    "confidence": 0.97,
                    "evidence": [
                        {
                            "record_id": "canonical-admin",
                            "match_kind": "fine_exact",
                        }
                    ],
                },
                {
                    "attack_class": "module-account-permafreeze",
                    "score": 7.0,
                    "confidence": 0.88,
                    "evidence": [{"record_id": "canonical-freeze"}],
                },
            ],
            limit=3,
        )

        self.assertEqual(
            [row["attack_class"] for row in merged],
            ["admin-bypass", "fee-redirect", "module-account-permafreeze"],
        )
        self.assertEqual(merged[0]["score"], 9.0)
        self.assertEqual(merged[0]["evidence"][0]["record_id"], "canonical-admin")
        self.assertEqual(merged[0]["evidence"][0]["match_kind"], "fine_exact")


if __name__ == "__main__":
    unittest.main()
