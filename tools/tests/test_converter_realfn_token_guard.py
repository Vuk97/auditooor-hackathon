#!/usr/bin/env python3
"""Regression tests for the shared real-fn-token verification guard.

Anchor: GRSWEEP-2 (Securitize RWA). anchor-0day-proof.py emitted a `proof-backed`
verdict with a real `cargo run` (rc 101) on a NAMED REAL TARGET, while the lifted
src/lib.rs contained ZERO tokens from the real `create.rs` handler - it had
authored a SYNTHETIC GENERIC template (handler_buggy(acct, exp) { Ok(()) }) and
proved THAT, not the real function. The shared guard
`tools/lib/realfn_token_guard.verify_realfn_tokens_or_downgrade` catches this:
on a cited-real-source run about to emit proof-backed, it requires the authored
harness/lifted source to embed the real fn NAME + >= 3 distinct real-fn-body
tokens, else it downgrades to blocked-with-obligation.

These tests drive the guard directly (no cargo / no toolchain needed) so they are
deterministic. Required cases:
  (a) synthetic-stub: authored harness has 0 real-fn tokens -> downgraded.
  (b) real-fn-embedded: authored harness embeds the real fn body -> proof-backed
      preserved.
  (c) fixture-exemption: a registered self-contained fixture is NOT downgraded.
Plus edge cases: 1-2 body tokens (below threshold) downgrade; no-external-source
runs are exempt; non-proof verdicts are never touched; INDEX.json fixture role.
"""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
GUARD = REPO / "tools" / "lib" / "realfn_token_guard.py"

_spec = importlib.util.spec_from_file_location("realfn_token_guard", GUARD)
G = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(G)


# A realistic "real" Anchor-ish handler the converter cites.
REAL_FN = "process_create"
REAL_FN_SRC = '''pub fn process_create(ctx: Context<CreateAsset>, params: CreateParams)
    -> Result<()> {
    let registry = &mut ctx.accounts.asset_registry;
    let issuer_authority = ctx.accounts.issuer.key();
    require_keys_eq!(issuer_authority, registry.compliance_officer);
    registry.outstanding_supply = params.initial_supply;
    registry.lockup_expiry = params.lockup_slots;
    emit_compliance_event(&registry, issuer_authority);
    Ok(())
}'''

# The synthetic generic template the fabrication authored (NO real-fn tokens).
SYNTH_TEMPLATE_LIB = '''#![allow(unused)]
#[derive(Clone)]
pub struct AcctMeta { pub key: [u8; 32], pub owner_program: [u8; 32] }
pub fn handler_buggy(acct: &AcctMeta, expected_program: [u8; 32]) -> Result<(), String> {
    Ok(())
}
pub fn handler_fixed(acct: &AcctMeta, expected_program: [u8; 32]) -> Result<(), String> {
    if acct.owner_program != expected_program { return Err("nope".into()); }
    Ok(())
}'''

# A real-fn-embedded lift: the authored lib embeds the real fn source verbatim
# (this is what engine-auto-convert's _rust_lib does - it embeds the full src).
REAL_EMBED_LIB = "#![allow(unused)]\n" + REAL_FN_SRC + "\n"


def _mk_workdir_with(files: dict) -> Path:
    d = Path(tempfile.mkdtemp(prefix="realfn_guard_test_"))
    for rel, content in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return d


class TestRealFnTokenGuard(unittest.TestCase):

    # --- (a) synthetic-stub: 0 real-fn tokens -> downgraded ------------------
    def test_a_synthetic_stub_downgraded(self):
        work = _mk_workdir_with({
            "src/lib.rs": SYNTH_TEMPLATE_LIB,
            "tests/auditooor_anchor_convert.rs":
                "use crate::*;\n#[test] fn t() { assert!(true); }\n",
        })
        result = {"verdict": "proof-backed",
                  "reason": "exploit FAILED-on-bug + control PASSED",
                  "target_file": "/tmp/cloned-repo/securitize/programs/asset/src/create.rs",
                  "fn": REAL_FN, "workdir": str(work)}
        out = G.verify_realfn_tokens_or_downgrade(
            result, target_file=Path(result["target_file"]), fn=REAL_FN,
            fn_src=REAL_FN_SRC, workdir=work)
        self.assertEqual(out["verdict"], "blocked-with-obligation")
        self.assertIn("template-proof", out["reason"])
        # overlap count is recorded + auditable
        self.assertIn("realfn_token_guard", out)
        self.assertTrue(out["realfn_token_guard"]["applied"])
        # synthetic generic template: < 3 real-fn-body tokens (incidental token
        # collisions such as the ubiquitous `key` may push the count to 1-2, which
        # is still a downgrade) AND the real fn name is absent.
        self.assertLess(out["realfn_token_guard"]["body_token_hits"], 3)
        self.assertFalse(out["realfn_token_guard"]["fn_name_present"])
        self.assertEqual(out["pre_guard_verdict"], "proof-backed")

    # --- (b) real-fn-embedded -> proof-backed preserved ----------------------
    def test_b_real_fn_embedded_preserved(self):
        work = _mk_workdir_with({
            "src/lib.rs": REAL_EMBED_LIB,
            "tests/auditooor_convert.rs":
                f"use crate::*;\n#[test] fn t() {{ {REAL_FN}; }}\n",
        })
        result = {"verdict": "proof-backed",
                  "reason": "exploit FAILED-on-bug + control PASSED",
                  "target_file": "/tmp/cloned-repo/securitize/programs/asset/src/create.rs",
                  "fn": REAL_FN, "workdir": str(work)}
        out = G.verify_realfn_tokens_or_downgrade(
            result, target_file=Path(result["target_file"]), fn=REAL_FN,
            fn_src=REAL_FN_SRC, workdir=work)
        self.assertEqual(out["verdict"], "proof-backed")
        self.assertTrue(out["realfn_token_guard"]["applied"])
        self.assertTrue(out["realfn_token_guard"]["fn_name_present"])
        self.assertGreaterEqual(out["realfn_token_guard"]["body_token_hits"], 3)
        self.assertNotIn("pre_guard_verdict", out)

    # --- (c) fixture-exemption: registered self-contained fixture not touched -
    def test_c_fixture_path_exemption(self):
        # target lives under tools/tests/fixtures/** -> exempt even though the
        # authored lib is a generic template with no "real fn" tokens.
        work = _mk_workdir_with({"src/lib.rs": SYNTH_TEMPLATE_LIB})
        fixture_target = (REPO / "tools" / "tests" / "fixtures" /
                          "some_kit" / "vuln" / "src" / "lib.rs")
        result = {"verdict": "proof-backed", "reason": "ok",
                  "target_file": str(fixture_target), "fn": "handler_buggy",
                  "workdir": str(work)}
        out = G.verify_realfn_tokens_or_downgrade(
            result, target_file=fixture_target, fn="handler_buggy",
            fn_src="pub fn handler_buggy() {}", workdir=work)
        self.assertEqual(out["verdict"], "proof-backed")
        self.assertFalse(out["realfn_token_guard"]["applied"])
        self.assertTrue(out["realfn_token_guard"]["exempt"])

    def test_c3_bundled_exploit_fixtures_path_exemption(self):
        # The converters' OWN in-repo bundled fixtures (tools/exploit-*-fixtures/)
        # are registered self-contained fixtures: the anchor plain-cargo tier
        # synthesizes a constraint-reimplementation harness (not a real-fn embed),
        # so it must stay proof-backed only on these bundled fixtures, never on an
        # external cloned-repo target.
        work = _mk_workdir_with({"src/lib.rs": SYNTH_TEMPLATE_LIB})
        bundled = (REPO / "tools" / "exploit-anchor-fixtures" /
                   "anchor_missing_has_one_vault.rs")
        result = {"verdict": "proof-backed", "reason": "ok",
                  "target_file": str(bundled), "fn": "set_admin_fee",
                  "workdir": str(work)}
        out = G.verify_realfn_tokens_or_downgrade(
            result, target_file=bundled, fn="set_admin_fee",
            fn_src="pub fn set_admin_fee(ctx: Context<X>) {}", workdir=work)
        self.assertEqual(out["verdict"], "proof-backed")
        self.assertTrue(out["realfn_token_guard"]["exempt"])

    def test_c2_index_json_fixture_role_exemption(self):
        # An INDEX.json declaring a fixture kit at/above the target dir = exempt.
        d = Path(tempfile.mkdtemp(prefix="realfn_guard_idx_"))
        (d / "INDEX.json").write_text(
            json.dumps({"schema": "auditooor.some_fixtures.v1",
                        "fixture_role": "vuln"}), encoding="utf-8")
        (d / "kit" / "src").mkdir(parents=True, exist_ok=True)
        tgt = d / "kit" / "src" / "create.rs"
        tgt.write_text("pub fn process_create() {}", encoding="utf-8")
        work = _mk_workdir_with({"src/lib.rs": SYNTH_TEMPLATE_LIB})
        result = {"verdict": "proof-backed", "reason": "ok",
                  "target_file": str(tgt), "fn": REAL_FN, "workdir": str(work)}
        out = G.verify_realfn_tokens_or_downgrade(
            result, target_file=tgt, fn=REAL_FN, fn_src=REAL_FN_SRC, workdir=work)
        self.assertEqual(out["verdict"], "proof-backed")
        self.assertTrue(out["realfn_token_guard"]["exempt"])

    # --- edge: below-threshold (1-2 tokens) downgrades -----------------------
    def test_below_threshold_two_tokens_downgraded(self):
        # authored lib mentions the fn name + only 2 distinct body tokens.
        partial = ("#![allow(unused)]\n"
                   "pub fn process_create() {\n"
                   "    let registry = 0; let lockup_expiry = 1;\n"
                   "}\n")
        work = _mk_workdir_with({"src/lib.rs": partial})
        result = {"verdict": "proof-backed", "reason": "ok",
                  "target_file": "/tmp/repo/src/create.rs", "fn": REAL_FN,
                  "workdir": str(work)}
        out = G.verify_realfn_tokens_or_downgrade(
            result, target_file=Path(result["target_file"]), fn=REAL_FN,
            fn_src=REAL_FN_SRC, workdir=work)
        self.assertEqual(out["verdict"], "blocked-with-obligation")
        self.assertTrue(out["realfn_token_guard"]["fn_name_present"])
        self.assertLess(out["realfn_token_guard"]["body_token_hits"], 3)

    # --- edge: no external cited source -> exempt ----------------------------
    def test_no_external_source_exempt(self):
        work = _mk_workdir_with({"src/lib.rs": SYNTH_TEMPLATE_LIB})
        result = {"verdict": "proof-backed", "reason": "ok",
                  "target_file": None, "fn": "", "workdir": str(work)}
        out = G.verify_realfn_tokens_or_downgrade(
            result, target_file=None, fn="", fn_src=None, workdir=work)
        self.assertEqual(out["verdict"], "proof-backed")
        self.assertTrue(out["realfn_token_guard"]["exempt"])

    # --- edge: non-proof verdicts are never touched --------------------------
    def test_non_proof_verdict_untouched(self):
        for v in ("blocked-with-obligation", "refuted", "error"):
            result = {"verdict": v, "reason": "x",
                      "target_file": "/tmp/repo/src/create.rs", "fn": REAL_FN}
            out = G.verify_realfn_tokens_or_downgrade(
                result, target_file=Path("/tmp/repo/src/create.rs"), fn=REAL_FN,
                fn_src=REAL_FN_SRC, workdir=None)
            self.assertEqual(out["verdict"], v)
            self.assertNotIn("realfn_token_guard", out)

    # --- edge: cited real source but tool failed to hand us fn_src -> fail closed
    def test_missing_fn_src_fails_closed(self):
        work = _mk_workdir_with({"src/lib.rs": SYNTH_TEMPLATE_LIB})
        result = {"verdict": "proof-backed", "reason": "ok",
                  "target_file": "/tmp/repo/src/create.rs", "fn": REAL_FN,
                  "workdir": str(work)}
        out = G.verify_realfn_tokens_or_downgrade(
            result, target_file=Path(result["target_file"]), fn=REAL_FN,
            fn_src=None, workdir=work)
        # No real tokens derivable + synthetic lib lacks the fn name -> downgrade.
        self.assertEqual(out["verdict"], "blocked-with-obligation")

    # --- "converted" / "real-fn-convert" verdict synonyms also guarded -------
    def test_verdict_synonyms_guarded(self):
        work = _mk_workdir_with({"src/lib.rs": SYNTH_TEMPLATE_LIB})
        for v in ("proven", "converted", "real-fn-convert"):
            result = {"verdict": v, "reason": "ok",
                      "target_file": "/tmp/repo/src/create.rs", "fn": REAL_FN,
                      "workdir": str(work)}
            out = G.verify_realfn_tokens_or_downgrade(
                result, target_file=Path(result["target_file"]), fn=REAL_FN,
                fn_src=REAL_FN_SRC, workdir=work)
            self.assertEqual(out["verdict"], "blocked-with-obligation", v)


if __name__ == "__main__":
    unittest.main()
