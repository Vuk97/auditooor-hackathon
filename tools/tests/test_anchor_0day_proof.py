#!/usr/bin/env python3
"""Tests for tools/anchor-0day-proof.py - the Solana/Anchor 0-day proof driver.

Two test tiers:
  * shape/authoring tests (always run): assert the Anchor-shape detectors fire on
    the right context, the authored crate + harness carry the REAL-constraint-
    driving shape (no tautology), the honesty guards block correctly (guard
    already present, non-Anchor file, runtime tier), and the runtime scaffold
    carries the documented Anchor discriminator.
  * live-run tests (gated on `cargo` availability): drive the authored harness
    with real `cargo test` and assert the adjudication is `proof-backed` with
    exploit-FAIL-on-bug + control-PASS-on-fixed. Skipped (not failed) when cargo
    is absent - mirroring the tool's own honesty posture.
"""
import importlib.util
import json
import shutil
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "anchor-0day-proof.py"
FIXT = REPO / "tools" / "exploit-anchor-fixtures"

_spec = importlib.util.spec_from_file_location("a0d", TOOL)
a0d = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(a0d)

HAVE_CARGO = shutil.which("cargo") is not None

FIXTURES = {
    "access-control": (FIXT / "anchor_missing_has_one_vault.rs", "set_admin_fee",
                       "missing-has-one"),
    "account-validation": (FIXT / "anchor_unchecked_account_oracle.rs", "consume_feed",
                           "unchecked-account"),
    "freshness": (FIXT / "anchor_stale_price_read.rs", "read_price",
                  "stale-price-on-read"),
}


def _convert(target, fn, vc, out_dir, run=True, force_runtime=False):
    return a0d.convert(Path(target), fn, vc, repo_root=REPO, out_dir=out_dir,
                       run=run, force_runtime_tier=force_runtime)


class TestVulnClassMap(unittest.TestCase):
    def test_three_families_present(self):
        cats = {v[0] for v in a0d.VULN_CLASS_MAP.values()}
        self.assertEqual(cats, {"access-control", "account-validation", "freshness"})

    def test_synonym_normalization(self):
        self.assertEqual(a0d.map_vuln_class("missing_has_one")[0], "access-control")
        self.assertEqual(a0d.map_vuln_class("Missing Owner Check")[0], "access-control")
        self.assertEqual(a0d.map_vuln_class("unchecked-account")[0], "account-validation")
        self.assertEqual(a0d.map_vuln_class("stale-price-on-read")[0], "freshness")

    def test_unknown_class_blocks(self):
        r = _convert(FIXTURES["access-control"][0], "set_admin_fee",
                     "reentrancy", None, run=False)
        self.assertEqual(r["verdict"], a0d.BLOCKED)
        self.assertIn("not in the Anchor auto-convertible map", r["reason"])


class TestAnchorMarkerDetection(unittest.TestCase):
    def test_anchor_file_recognized(self):
        for _, (path, _, _) in FIXTURES.items():
            self.assertTrue(a0d.is_anchor_file(path.read_text()), path.name)

    def test_plain_rust_not_anchor(self):
        self.assertFalse(a0d.is_anchor_file(
            "pub fn foo(a: &mut Bar) -> Result<(), String> { Ok(()) }"))

    def test_non_anchor_file_blocks(self):
        import tempfile
        p = Path(tempfile.mktemp(suffix=".rs"))
        p.write_text("pub struct Bar { pub x: u64 }\n"
                     "pub fn foo(a: &mut Bar) -> Result<(),String> { Ok(()) }")
        r = _convert(p, "foo", "missing-has-one", None, run=False)
        self.assertEqual(r["verdict"], a0d.BLOCKED)
        self.assertIn("no Anchor markers", r["reason"])


class TestShapeDetection(unittest.TestCase):
    def test_access_control_shape(self):
        src = FIXTURES["access-control"][0].read_text()
        fn_src = a0d.extract_rust_fn(src, "set_admin_fee")
        shape = a0d.detect_access_control(src, fn_src)
        self.assertIsNotNone(shape)
        self.assertEqual(shape["owner_field"], "admin")
        self.assertEqual(shape["state_data_ty"], "VaultState")
        self.assertEqual(shape["signer_field"], "signer")

    def test_account_validation_shape(self):
        src = FIXTURES["account-validation"][0].read_text()
        fn_src = a0d.extract_rust_fn(src, "consume_feed")
        shape = a0d.detect_account_validation(src, fn_src)
        self.assertIsNotNone(shape)
        self.assertEqual(shape["account_field"], "price_feed")

    def test_staleness_shape(self):
        src = FIXTURES["freshness"][0].read_text()
        fn_src = a0d.extract_rust_fn(src, "read_price")
        shape = a0d.detect_staleness(src, fn_src)
        self.assertIsNotNone(shape)
        self.assertEqual(shape["ts_field"], "last_update_slot")
        self.assertEqual(shape["value_field"], "price")

    def test_generic_field_names_no_hardcode(self):
        """A never-seen program with different names converts via the same path."""
        src = (
            "use anchor_lang::prelude::*;\n"
            "#[program] pub mod m { use super::*;\n"
            "  pub fn rotate(ctx: Context<Rot>, v: u64) -> Result<()> "
            "{ ctx.accounts.pool.cfg = v; Ok(()) } }\n"
            "#[account] pub struct PoolCfg { pub governor: Pubkey, pub cfg: u64 }\n"
            "#[derive(Accounts)] pub struct Rot<'info> {\n"
            "  #[account(mut)] pub pool: Account<'info, PoolCfg>,\n"
            "  pub actor: Signer<'info> }\n")
        fn_src = a0d.extract_rust_fn(src, "rotate")
        shape = a0d.detect_access_control(src, fn_src)
        self.assertIsNotNone(shape)
        # owner field is `governor` (not a hardcoded `admin`/`owner` literal).
        self.assertEqual(shape["owner_field"], "governor")
        self.assertEqual(shape["signer_field"], "actor")


class TestHonestyGuards(unittest.TestCase):
    def test_has_one_present_blocks_no_fabrication(self):
        """A handler that ALREADY has the has_one guard must NOT be flagged."""
        src = (
            "use anchor_lang::prelude::*;\n"
            "#[program] pub mod m { use super::*;\n"
            "  pub fn set_fee(ctx: Context<SetFee>, f: u64) -> Result<()> "
            "{ ctx.accounts.vault.fee = f; Ok(()) } }\n"
            "#[account] pub struct VaultState { pub admin: Pubkey, pub fee: u64 }\n"
            "#[derive(Accounts)] pub struct SetFee<'info> {\n"
            "  #[account(mut, has_one = admin)] pub vault: Account<'info, VaultState>,\n"
            "  pub admin: Signer<'info> }\n")
        import tempfile
        p = Path(tempfile.mktemp(suffix=".rs"))
        p.write_text(src)
        r = _convert(p, "set_fee", "missing-has-one", None, run=False)
        self.assertEqual(r["verdict"], a0d.BLOCKED)
        self.assertIn("MISSING has_one", r["reason"])

    def test_require_keys_eq_in_body_blocks(self):
        src = (
            "use anchor_lang::prelude::*;\n"
            "#[program] pub mod m { use super::*;\n"
            "  pub fn set_fee(ctx: Context<SetFee>, f: u64) -> Result<()> {\n"
            "    require_keys_eq!(ctx.accounts.signer.key(), ctx.accounts.vault.admin);\n"
            "    ctx.accounts.vault.fee = f; Ok(()) } }\n"
            "#[account] pub struct VaultState { pub admin: Pubkey, pub fee: u64 }\n"
            "#[derive(Accounts)] pub struct SetFee<'info> {\n"
            "  #[account(mut)] pub vault: Account<'info, VaultState>,\n"
            "  pub signer: Signer<'info> }\n")
        import tempfile
        p = Path(tempfile.mktemp(suffix=".rs"))
        p.write_text(src)
        r = _convert(p, "set_fee", "missing-has-one", None, run=False)
        self.assertEqual(r["verdict"], a0d.BLOCKED)

    def test_fn_not_found_blocks(self):
        r = _convert(FIXTURES["access-control"][0], "nonexistent_fn",
                     "missing-has-one", None, run=False)
        self.assertEqual(r["verdict"], a0d.BLOCKED)
        self.assertIn("not found", r["reason"])

    def test_no_run_is_scaffold_only_not_proof(self):
        r = _convert(FIXTURES["access-control"][0], "set_admin_fee",
                     "missing-has-one", None, run=False)
        self.assertEqual(r["verdict"], a0d.BLOCKED)
        self.assertTrue(r.get("scaffold_only"))
        self.assertNotEqual(r["verdict"], a0d.PROOF_BACKED)


class TestRuntimeTier(unittest.TestCase):
    def test_force_runtime_tier_blocks_with_obligation(self):
        r = _convert(FIXTURES["access-control"][0], "set_admin_fee",
                     "missing-has-one", None, run=True, force_runtime=True)
        self.assertEqual(r["verdict"], a0d.BLOCKED)
        self.assertEqual(r["runtime_tier"], "solana-program-test")
        self.assertTrue(r.get("scaffold_only"))
        self.assertIn("obligation", r)
        # SBF toolchain is absent in this env -> honesty posture must name it.
        self.assertFalse(r.get("sbf_toolchain_present"))
        self.assertIn("SBF toolchain", r["reason"])

    def test_runtime_scaffold_carries_real_discriminator(self):
        import hashlib
        scaffold = a0d.render_runtime_scaffold(
            "set_admin_fee", "access-control",
            {"invariant_id": "X", "category": "access-control", "statement": "s"})
        expect = hashlib.sha256(b"global:set_admin_fee").digest()[:8]
        expect_str = "[" + ", ".join(str(b) for b in expect) + "]"
        self.assertIn(expect_str, scaffold)
        self.assertIn("build_account_fixture", scaffold)
        self.assertIn("discriminator", scaffold)

    def test_non_self_contained_data_struct_routes_to_runtime(self):
        """A data struct referencing a non-primitive nested type cannot be lifted
        plain-cargo -> the access-control path routes to the runtime scaffold."""
        src = (
            "use anchor_lang::prelude::*;\n"
            "#[program] pub mod m { use super::*;\n"
            "  pub fn op(ctx: Context<Op>, v: u64) -> Result<()> "
            "{ ctx.accounts.s.x = v; Ok(()) } }\n"
            "#[account] pub struct State { pub admin: Pubkey, pub nested: SomeOther, pub x: u64 }\n"
            "#[derive(Accounts)] pub struct Op<'info> {\n"
            "  #[account(mut)] pub s: Account<'info, State>,\n"
            "  pub caller: Signer<'info> }\n")
        import tempfile
        p = Path(tempfile.mktemp(suffix=".rs"))
        p.write_text(src)
        r = _convert(p, "op", "missing-has-one", None, run=True)
        self.assertEqual(r["verdict"], a0d.BLOCKED)
        self.assertEqual(r.get("runtime_tier"), "solana-program-test")
        self.assertIn("not plain-cargo-liftable", r["reason"])


class TestHarnessShape(unittest.TestCase):
    """The authored harness must DRIVE the real lifted constraint with a real
    accept-vs-reject differential (not a tautology)."""

    def test_access_control_harness_drives_owner_vs_attacker(self):
        inv = {"invariant_id": "X", "category": "access-control", "statement": "s"}
        body = "\n    pub admin: Pubkey,\n    pub fee: u64,\n"
        crate = a0d.render_access_control_crate("VaultState", body, "admin", inv)
        harness = a0d.render_access_control_harness("VaultState", body, "admin",
                                                    "set_fee", inv, "c")
        # buggy handler has NO equality guard; fixed handler DOES.
        self.assertIn("signer_key != state.admin", crate)
        self.assertIn("handler_buggy", crate)
        self.assertIn("handler_fixed", crate)
        # harness drives both an owner (accept) and an attacker (reject).
        self.assertIn("attacker", harness)
        self.assertIn("test_exploit_access_control_AUTO", harness)
        self.assertIn("test_negative_control_access_control_AUTO", harness)
        # NOT a tautology: the exploit assertion is on a real drive(), not assert(true).
        self.assertNotIn("assert!(true", harness)

    def test_staleness_harness_drives_fresh_vs_stale(self):
        inv = {"invariant_id": "X", "category": "freshness", "statement": "s"}
        body = "\n    pub authority: Pubkey,\n    pub price: u64,\n    pub last_update_slot: u64,\n"
        crate = a0d.render_staleness_crate("PriceData", body, "last_update_slot",
                                           "price", inv)
        self.assertIn("saturating_sub", crate)
        self.assertIn("read_buggy", crate)
        self.assertIn("read_fixed", crate)

    def test_account_validation_harness_drives_good_vs_spoofed(self):
        inv = {"invariant_id": "X", "category": "account-validation", "statement": "s"}
        crate = a0d.render_account_validation_crate(inv)
        harness = a0d.render_account_validation_harness("consume", inv, "c")
        self.assertIn("owner_program != expected_program", crate)
        self.assertIn("spoofed", harness)


class TestAdjudication(unittest.TestCase):
    def test_proof_backed_shape(self):
        v, _ = a0d.adjudicate(
            {"exploit_fail": True, "control_pass": True,
             "exploit_pass": False, "control_fail": False}, True)
        self.assertEqual(v, a0d.PROOF_BACKED)

    def test_refuted_shape(self):
        v, _ = a0d.adjudicate(
            {"exploit_fail": False, "control_pass": True,
             "exploit_pass": True, "control_fail": False}, True)
        self.assertEqual(v, a0d.REFUTED)

    def test_no_compile_blocks(self):
        v, _ = a0d.adjudicate(
            {"exploit_fail": True, "control_pass": True,
             "exploit_pass": False, "control_fail": False}, False)
        self.assertEqual(v, a0d.BLOCKED)


@unittest.skipUnless(HAVE_CARGO, "cargo unavailable; live-run proof tier skipped")
class TestLiveRunProof(unittest.TestCase):
    """Drive the authored harness with REAL cargo and assert proof-backed for
    each of the three Anchor convert families."""

    def _run_family(self, key):
        import tempfile
        out = Path(tempfile.mkdtemp(prefix="a0d_test_"))
        path, fn, vc = FIXTURES[key]
        r = _convert(path, fn, vc, out, run=True)
        self.assertEqual(r["verdict"], a0d.PROOF_BACKED,
                         f"{key}: {r.get('reason')}\n{r.get('transcript_tail','')}")
        self.assertTrue(r["parsed"]["exploit_fail"])
        self.assertTrue(r["parsed"]["control_pass"])
        self.assertTrue(r["parsed"]["compiled"])
        shutil.rmtree(out, ignore_errors=True)

    def test_access_control_proof_backed(self):
        self._run_family("access-control")

    def test_account_validation_proof_backed(self):
        self._run_family("account-validation")

    def test_freshness_proof_backed(self):
        self._run_family("freshness")


class TestSchema(unittest.TestCase):
    def test_schema_version(self):
        self.assertEqual(a0d.SCHEMA_VERSION, "auditooor.anchor_0day_proof.v1")

    def test_base_result_has_required_keys(self):
        r = a0d._base_result(Path("x.rs"), "f", "vc",
                             {"invariant_id": "I", "category": "c", "grounded": False})
        for k in ("schema_version", "target_file", "fn", "vuln_class", "language",
                  "grounded_invariant", "invariant_category"):
            self.assertIn(k, r)
        self.assertEqual(r["language"], "anchor")


if __name__ == "__main__":
    unittest.main(verbosity=2)
