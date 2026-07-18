#!/usr/bin/env python3
"""Tests for tools/shape-hash.py — canonical adversarial-equivalence hash.

Covers the six canonicalization steps from BIG_PLAN_2026-05-11 sub-report 06.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MOD_PATH = REPO_ROOT / "tools" / "shape-hash.py"


def _load() -> object:
    spec = importlib.util.spec_from_file_location("shape_hash_for_test", MOD_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {MOD_PATH}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["shape_hash_for_test"] = mod
    spec.loader.exec_module(mod)
    return mod


SH = _load()


class TestShapeHash(unittest.TestCase):

    def test_type_alias_go_address_collapse(self):
        """AccAddress / sdk.AccAddress / common.Address all map to @address."""
        for raw in ("AccAddress", "sdk.AccAddress", "common.Address"):
            self.assertEqual(SH.normalize_type(raw, "go"), "@address")
        # Non-address Go type stays
        self.assertEqual(SH.normalize_type("uint64", "go"), "uint64")

    def test_type_alias_go_ctx_collapse(self):
        for raw in ("context.Context", "sdk.Context", "Context"):
            self.assertEqual(SH.normalize_type(raw, "go"), "@ctx")

    def test_rust_reference_mut_normalization(self):
        self.assertEqual(SH.normalize_type("&mut AccountId", "rust"), "@address")
        self.assertEqual(SH.normalize_type("& Context<'a>", "rust"), "Context<'a>")

    def test_msg_payload_coarse_vs_fine(self):
        """*types.MsgRegisterAffiliate → @msg (coarse) or @msg<RegisterAffiliate> (fine)."""
        self.assertEqual(SH.normalize_type("*types.MsgRegisterAffiliate", "go"), "@msg")
        self.assertEqual(
            SH.normalize_type("*types.MsgRegisterAffiliate", "go", fine=True),
            "@msg<RegisterAffiliate>",
        )

    def test_receiver_family_classification(self):
        self.assertEqual(SH.receiver_family("msgServer"), "msg-server-family")
        self.assertEqual(SH.receiver_family("*Keeper"), "msg-server-family")
        self.assertEqual(SH.receiver_family("k.Keeper"), "msg-server-family")
        self.assertEqual(SH.receiver_family("IBCModule"), "ibc-module")
        self.assertEqual(SH.receiver_family("FooHook"), "hook-family")
        self.assertEqual(SH.receiver_family("BankKeeper"), "msg-server-family")
        self.assertEqual(SH.receiver_family(None), "free-function")
        self.assertEqual(SH.receiver_family("RandomThing"), "misc-family")

    def test_flag_vector_authority_guard_distinguishes(self):
        """The cantina-192 signal: same param/return shape on two msgServer
        methods; one has authority-check guard, the other does not. Coarse
        hashes MUST differ."""
        params = [
            {"name": "ctx", "type": "context.Context"},
            {"name": "msg", "type": "*types.MsgX"},
        ]
        returns = ["*types.MsgXResponse", "error"]
        h_no_guard = SH.compute_shape_hash(
            language="go", params=params, return_types=returns,
            visibility="exported", guards_detected=["error-return", "write-store"],
            receiver_type="msgServer",
        )
        h_with_guard = SH.compute_shape_hash(
            language="go", params=params, return_types=returns,
            visibility="exported",
            guards_detected=["authority-check", "error-return", "write-store"],
            receiver_type="msgServer",
        )
        self.assertNotEqual(h_no_guard, h_with_guard)

    def test_coarse_collapses_fine_distinguishes(self):
        """Two msgServer methods with different Msg payload names but same
        guard surface → coarse hash equal, fine hash differs."""
        params_a = [
            {"name": "ctx", "type": "context.Context"},
            {"name": "msg", "type": "*types.MsgRegisterAffiliate"},
        ]
        params_b = [
            {"name": "ctx", "type": "context.Context"},
            {"name": "msg", "type": "*types.MsgUpdateAffiliateTiers"},
        ]
        returns_a = ["*types.MsgRegisterAffiliateResponse", "error"]
        returns_b = ["*types.MsgUpdateAffiliateTiersResponse", "error"]
        guards = ["error-return", "write-store"]
        kwargs = dict(language="go", visibility="exported",
                      guards_detected=guards, receiver_type="msgServer")
        h_a_coarse = SH.compute_shape_hash(params=params_a, return_types=returns_a, fine=False, **kwargs)
        h_b_coarse = SH.compute_shape_hash(params=params_b, return_types=returns_b, fine=False, **kwargs)
        h_a_fine = SH.compute_shape_hash(params=params_a, return_types=returns_a, fine=True, **kwargs)
        h_b_fine = SH.compute_shape_hash(params=params_b, return_types=returns_b, fine=True, **kwargs)
        self.assertEqual(h_a_coarse, h_b_coarse, "coarse must collapse Msg names")
        self.assertNotEqual(h_a_fine, h_b_fine, "fine must distinguish Msg names")

    def test_hash_is_16_hex(self):
        h = SH.compute_shape_hash(language="go", params=[], return_types=["error"])
        self.assertRegex(h, r"^[0-9a-f]{16}$")

    def test_shape_components_introspection(self):
        comps = SH.shape_components(
            language="go",
            params=[{"name": "ctx", "type": "context.Context"}],
            return_types=["error"],
            visibility="exported",
            guards_detected=["authority-check", "write-store"],
            receiver_type="msgServer",
        )
        self.assertEqual(comps["receiver_family"], "msg-server-family")
        self.assertEqual(comps["param_type_sequence"], ["@ctx"])
        # Order: exported, authority, pause, reentr, blocked, mutates
        # exported=1, authority=1, mutates_state=1; rest=0 → 110001
        self.assertEqual(comps["flag_vector_string"], "110001")

    def test_process_jsonl_roundtrip(self):
        sample = [
            {
                "file_path": "x/affiliates/keeper/msg_server.go",
                "language": "go",
                "function_name": "RegisterAffiliate",
                "function_signature": "func (k msgServer) RegisterAffiliate(...)",
                "receiver_type": "msgServer",
                "visibility": "exported",
                "params": [{"name": "ctx", "type": "context.Context"}],
                "return_types": ["error"],
                "guards_detected": ["error-return"],
            }
        ]
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            inp = tdp / "in.jsonl"
            out = tdp / "out.jsonl"
            with inp.open("w", encoding="utf-8") as fh:
                fh.write(json.dumps(sample[0]) + "\n")
            n, _ = SH.process_jsonl(inp, out)
            self.assertEqual(n, 1)
            rec = json.loads(out.read_text(encoding="utf-8").strip())
            self.assertIn("shape_hash", rec)
            self.assertIn("shape_hash_fine", rec)
            self.assertRegex(rec["shape_hash"], r"^[0-9a-f]{16}$")


if __name__ == "__main__":
    unittest.main()
