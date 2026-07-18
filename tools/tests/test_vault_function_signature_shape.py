#!/usr/bin/env python3
"""Tests for the Wave-4 Track B vault_function_signature_shape callable."""
from __future__ import annotations

import importlib.util
import re
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SERVER_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"


def _load_server_module():
    spec = importlib.util.spec_from_file_location("vault_mcp_server_for_test_shape", SERVER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {SERVER_PATH}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["vault_mcp_server_for_test_shape"] = mod
    spec.loader.exec_module(mod)
    return mod


SERVER = _load_server_module()


class TestVaultFunctionSignatureShape(unittest.TestCase):

    def _vault(self):
        return SERVER.VaultQuery(SERVER.Path(REPO_ROOT))

    def test_missing_signature_degraded(self):
        v = self._vault()
        out = v.vault_function_signature_shape(language="go", function_signature="")
        self.assertTrue(out.get("degraded"))
        self.assertEqual(out["schema"], SERVER.FUNCTION_SIGNATURE_SHAPE_SCHEMA)

    def test_go_msg_server_register_affiliate_shape(self):
        v = self._vault()
        out = v.vault_function_signature_shape(
            language="go",
            function_signature=(
                "func (k msgServer) RegisterAffiliate(ctx context.Context, "
                "msg *types.MsgRegisterAffiliate) "
                "(*types.MsgRegisterAffiliateResponse, error)"
            ),
            receiver_type="msgServer",
            guards_detected=["error-return"],
        )
        self.assertFalse(out.get("degraded"))
        self.assertRegex(out["shape_hash"], r"^[0-9a-f]{16}$")
        self.assertRegex(out["shape_hash_fine"], r"^[0-9a-f]{16}$")
        self.assertNotEqual(out["shape_hash"], out["shape_hash_fine"])
        self.assertEqual(out["shape_components"]["receiver_family"], "msg-server-family")

    def test_coarse_collapses_msg_payload_fine_distinguishes(self):
        v = self._vault()
        out_a = v.vault_function_signature_shape(
            language="go",
            function_signature=(
                "func (k msgServer) Foo(ctx context.Context, "
                "msg *types.MsgFoo) (*types.MsgFooResponse, error)"
            ),
            receiver_type="msgServer",
        )
        out_b = v.vault_function_signature_shape(
            language="go",
            function_signature=(
                "func (k msgServer) Bar(ctx context.Context, "
                "msg *types.MsgBar) (*types.MsgBarResponse, error)"
            ),
            receiver_type="msgServer",
        )
        self.assertEqual(out_a["shape_hash"], out_b["shape_hash"])
        self.assertNotEqual(out_a["shape_hash_fine"], out_b["shape_hash_fine"])

    def test_collisions_in_corpus_is_int(self):
        v = self._vault()
        out = v.vault_function_signature_shape(
            language="go",
            function_signature="func (k msgServer) X(ctx context.Context, msg *types.MsgX) (*types.MsgXResponse, error)",
            receiver_type="msgServer",
        )
        self.assertIsInstance(out["collisions_in_corpus"], int)
        self.assertGreaterEqual(out["collisions_in_corpus"], 0)

    def test_envelope_has_pack_id(self):
        v = self._vault()
        out = v.vault_function_signature_shape(
            language="go",
            function_signature="func Foo() error",
        )
        self.assertIn("context_pack_id", out)
        self.assertTrue(out["context_pack_id"].startswith(SERVER.FUNCTION_SIGNATURE_SHAPE_SCHEMA))

    def test_rust_signature_parses_params_and_return_type(self):
        v = self._vault()
        out = v.vault_function_signature_shape(
            language="rust",
            function_signature=(
                "pub async fn process_message<'a, T: AccountStore>"
                "(ctx: &mut Context<'a>, msg: MsgExecute, signer: AccountId) "
                "-> Result<(), ProgramError>"
            ),
        )
        self.assertFalse(out.get("degraded"))
        comps = out["shape_components"]
        self.assertEqual(
            comps["param_type_sequence"],
            ["Context<'a>", "MsgExecute", "@address"],
        )
        self.assertEqual(comps["return_type_sequence"], ["Result<(), ProgramError>"])
        self.assertNotIn("->", comps["return_type_sequence"])

    def test_rust_visibility_tracks_pub_vs_private(self):
        v = self._vault()
        pub_out = v.vault_function_signature_shape(
            language="rust",
            function_signature="pub fn public_handler(msg: MsgX) -> Result<(), ProgramError>",
        )
        priv_out = v.vault_function_signature_shape(
            language="rust",
            function_signature="fn private_helper(msg: MsgX) -> Result<(), ProgramError>",
        )
        self.assertEqual(pub_out["shape_components"]["flag_vector"]["exported"], 1)
        self.assertEqual(priv_out["shape_components"]["flag_vector"]["exported"], 0)


if __name__ == "__main__":
    unittest.main()
