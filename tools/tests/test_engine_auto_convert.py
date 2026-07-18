#!/usr/bin/env python3
"""Tests for tools/engine-auto-convert.py.

Two layers:
  * hermetic unit tests (no toolchain): vuln-class mapping, fn extraction,
    self-containment detection, fixed-variant derivation, adjudication, and the
    honesty-contract block verdicts.
  * real-run end-to-end tests (skipped when cargo / go is absent): drive the
    REAL lifted fn, run `cargo test` / `go test`, and assert `proof-backed`
    requires exploit-FAIL-on-bug + control-PASS-on-fixed.
"""
import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parents[1] / "engine-auto-convert.py"
_spec = importlib.util.spec_from_file_location("engine_auto_convert", _TOOL)
M = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(M)

REPO_ROOT = Path(__file__).resolve().parents[2]
TRAIN = REPO_ROOT / "tools" / "exploit-anchor-fixtures" / "engine_auto_convert_train"

RUST_BUGGY = '''pub struct SigningNonces { pub hiding: u64, pub binding: u64 }
pub struct SigningPackage { pub message: Vec<u8> }
pub struct SignatureShare { pub value: u64 }
pub type Error = String;
pub fn sign(p: &SigningPackage, n: &mut SigningNonces) -> Result<SignatureShare, Error> {
    Ok(SignatureShare { value: n.hiding ^ n.binding ^ p.message.len() as u64 })
}
'''

GO_BUGGY = '''package target
type Nonce struct { Value uint64 }
func Sign(n *Nonce, msg uint64) (uint64, bool) { return n.Value ^ msg, true }
'''

# Generic Go method-receiver shape (iter12 BS top blind spot): a method defined
# on a receiver `(s *Signer)` - the dominant Cosmos-SDK shape `func (k msgServer)
# Name(...)`. Pre-fix the free-function-only regex never matched this. This
# fixture is intentionally self-contained (receiver type + body reference only
# in-file types/primitives) so extraction is exercised without needing a
# package-wide cosmos toolchain. It is GENERAL: no Quicksilver/Synthetify symbol
# names, just a canonical receiver-method.
GO_RECEIVER_METHOD = '''package target
type Signer struct { Key uint64 }
func (s *Signer) Compute(msg uint64) uint64 { return s.Key ^ msg }
'''

# A Cosmos-SDK-idiomatic receiver method that extracts but is NOT self-contained
# (its body references a package-qualified keeper call). Pre-fix it never even
# extracted; post-fix it extracts and then honestly blocks-with-obligation,
# naming the dep wall ("drive the real fn inside its own package's _test.go").
GO_COSMOS_MSGSERVER = '''package keeper
type msgServer struct { Keeper Keeper }
type Keeper struct{}
func (k msgServer) Deposit(ctx Context, amt uint64) (uint64, error) {
	bal := sdk.NewCoin(amt)
	return bal, nil
}
'''

# bounds / dos-resource-exhaustion family: a caller-controlled `proof_len`
# drives an unbounded allocation with no cap-check against the configured
# `cfg.max_depth`. Self-contained.
RUST_BOUNDS_BUGGY = '''pub struct MerkleVerifier { pub max_depth: u32 }
pub struct VerifyResult { pub root: u64 }
pub type Error = String;
pub fn verify(cfg: &MerkleVerifier, leaf: u64, proof_len: u32) -> Result<VerifyResult, Error> {
    let mut acc: u64 = leaf;
    let mut siblings: Vec<u64> = Vec::with_capacity(proof_len as usize);
    let mut i: u32 = 0;
    while i < proof_len { siblings.push(acc); acc = acc.wrapping_mul(31).wrapping_add(i as u64); i += 1; }
    Ok(VerifyResult { root: acc })
}
'''

# bounds shape where the cap is a module-level const instead of a struct field.
RUST_BOUNDS_CONST_BUGGY = '''pub const MAX_ITEMS: u32 = 64;
pub type Error = String;
pub fn build(count: u32) -> Result<u64, Error> {
    let mut v: Vec<u64> = Vec::with_capacity(count as usize);
    let mut i: u32 = 0;
    while i < count { v.push(i as u64); i += 1; }
    Ok(v.len() as u64)
}
'''


class TestVulnClassMap(unittest.TestCase):
    def test_known_classes_map(self):
        for vc in ("nonce-reuse", "replay", "double-spend", "missing-freshness-guard"):
            self.assertIsNotNone(M.map_vuln_class(vc), vc)

    def test_normalize(self):
        self.assertEqual(M.normalize_vuln_class("Nonce_Reuse Risk"), "nonce-reuse-risk")

    def test_unknown_class_none(self):
        # A genuinely-unmapped class returns None. `reentrancy` USED to be the
        # canary here but is now a first-class convertible family (cei-order-check),
        # so use a class that is not in any convert family.
        self.assertIsNone(M.map_vuln_class("totally-unknown-class-xyz"))

    def test_missing_input_validation_maps_to_bounds_capcheck(self):
        # iter12 BS-3: missing-input-validation joins the bounds/cap-check
        # family (an unchecked caller-controlled length must be rejected when it
        # exceeds the configured bound). GENERAL mapping, not target-tuned.
        for vc in ("missing-input-validation", "missing-validation",
                   "unchecked-input", "missing-length-check"):
            m = M.map_vuln_class(vc)
            self.assertIsNotNone(m, vc)
            self.assertEqual(m, ("bounds", "cap-check"), vc)

    def test_missing_input_validation_normalizes(self):
        self.assertEqual(
            M.normalize_vuln_class("Missing Input_Validation"),
            "missing-input-validation")
        self.assertIsNotNone(M.map_vuln_class("Missing Input_Validation"))


class TestFnExtraction(unittest.TestCase):
    def test_rust_extract_brace_match(self):
        body = M.extract_rust_fn(RUST_BUGGY, "sign")
        self.assertIsNotNone(body)
        self.assertTrue(body.strip().startswith("pub fn sign"))
        self.assertTrue(body.rstrip().endswith("}"))

    def test_rust_extract_missing(self):
        self.assertIsNone(M.extract_rust_fn(RUST_BUGGY, "nope"))

    def test_go_extract(self):
        body = M.extract_go_fn(GO_BUGGY, "Sign")
        self.assertIsNotNone(body)
        self.assertIn("n.Value ^ msg", body)

    def test_go_extract_receiver_method(self):
        # iter12 top blind spot: a method with a `(s *Signer)` receiver
        # (the dominant Cosmos-SDK `func (k msgServer) Name(...)` shape) must
        # now extract. Pre-fix the free-function-only regex returned None.
        body = M.extract_go_fn(GO_RECEIVER_METHOD, "Compute")
        self.assertIsNotNone(body, "receiver-method must extract post-fix")
        self.assertTrue(body.lstrip().startswith("func (s *Signer) Compute"))
        self.assertIn("s.Key ^ msg", body)
        self.assertTrue(body.rstrip().endswith("}"))

    def test_go_extract_cosmos_msgserver_method(self):
        # Cosmos-SDK msgServer method extracts (the receiver group is matched);
        # downstream self-containment honestly blocks because the body calls a
        # package-qualified helper. This asserts EXTRACTION, not conversion.
        body = M.extract_go_fn(GO_COSMOS_MSGSERVER, "Deposit")
        self.assertIsNotNone(body, "cosmos msgServer method must extract post-fix")
        self.assertTrue(body.lstrip().startswith("func (k msgServer) Deposit"))

    def test_go_extract_receiver_does_not_break_free_fn(self):
        # Regression: the receiver-optional regex must still match free funcs.
        body = M.extract_go_fn(GO_BUGGY, "Sign")
        self.assertIsNotNone(body)
        self.assertTrue(body.lstrip().startswith("func Sign("))


class TestSelfContainment(unittest.TestCase):
    def test_rust_self_contained(self):
        fn = M.extract_rust_fn(RUST_BUGGY, "sign")
        ok, unresolved = M.is_rust_self_contained(RUST_BUGGY, fn)
        self.assertTrue(ok, unresolved)
        self.assertEqual(unresolved, [])

    def test_rust_external_ref_blocks(self):
        src = "pub fn sign(n: &mut Foreign) -> Result<u64, String> { Ok(n.x) }"
        fn = M.extract_rust_fn(src, "sign")
        ok, unresolved = M.is_rust_self_contained(src, fn)
        self.assertFalse(ok)
        self.assertIn("Foreign", unresolved)

    def test_go_self_contained_excludes_fn_name(self):
        fn = M.extract_go_fn(GO_BUGGY, "Sign")
        ok, unresolved = M.is_go_self_contained(GO_BUGGY, fn)
        self.assertTrue(ok, unresolved)

    def test_go_receiver_method_self_contained(self):
        # The extraction fix alone is hollow without go_sig_types skipping the
        # receiver group: a self-contained receiver method must NOT spuriously
        # block. sig_types must yield only the receiver type (a real in-file
        # dep), never the fn name.
        fn = M.extract_go_fn(GO_RECEIVER_METHOD, "Compute")
        ok, unresolved = M.is_go_self_contained(GO_RECEIVER_METHOD, fn)
        self.assertTrue(ok, unresolved)
        self.assertEqual(unresolved, [])
        self.assertEqual(M.go_sig_types(fn), {"Signer"})


class TestFixedDerivation(unittest.TestCase):
    def test_rust_fixed_injects_guard(self):
        fn = M.extract_rust_fn(RUST_BUGGY, "sign")
        fixed = M.derive_rust_fixed(fn, "sign", "sign_fixed_AUTO", "freshness-flag")
        self.assertIsNotNone(fixed)
        self.assertIn("fn sign_fixed_AUTO", fixed)
        self.assertIn(".used", fixed)
        self.assertIn("return Err", fixed)

    def test_rust_fixed_none_for_immutable_resource(self):
        src = "pub fn sign(n: &SigningNonces) -> Result<u64, String> { Ok(0) }"
        fn = M.extract_rust_fn(src, "sign")
        self.assertIsNone(M.derive_rust_fixed(fn, "sign", "x", "freshness-flag"))

    def test_go_fixed_injects_guard(self):
        fn = M.extract_go_fn(GO_BUGGY, "Sign")
        fixed = M.derive_go_fixed(fn, "Sign", "SignFixedAUTO", "freshness-flag")
        self.assertIsNotNone(fixed)
        self.assertIn("func SignFixedAUTO", fixed)
        self.assertIn(".Used", fixed)
        self.assertIn("return", fixed)


class TestBoundsFamily(unittest.TestCase):
    """dos-resource-exhaustion / bounds family: cap-check derivation, length-
    param + cap detection, and the honesty-contract blocks for non-fixable
    shapes (no length param, no configured cap)."""

    def test_bounds_classes_map_to_capcheck(self):
        for vc in ("dos-resource-exhaustion", "resource-exhaustion",
                   "allocation-amplification", "unbounded-allocation",
                   "missing-bounds-check", "unbounded-loop"):
            m = M.map_vuln_class(vc)
            self.assertIsNotNone(m, vc)
            self.assertEqual(m, ("bounds", "cap-check"), vc)

    def test_detect_length_param_via_with_capacity(self):
        fn = M.extract_rust_fn(RUST_BOUNDS_BUGGY, "verify")
        self.assertEqual(M.detect_rust_length_param(fn), "proof_len")

    def test_detect_length_param_via_loop_bound(self):
        fn = M.extract_rust_fn(RUST_BOUNDS_CONST_BUGGY, "build")
        self.assertEqual(M.detect_rust_length_param(fn), "count")

    def test_detect_cap_struct_field(self):
        fn = M.extract_rust_fn(RUST_BOUNDS_BUGGY, "verify")
        cap = M.detect_rust_cap_expr(RUST_BOUNDS_BUGGY, fn, "proof_len")
        self.assertEqual(cap, "cfg.max_depth")

    def test_detect_cap_const(self):
        fn = M.extract_rust_fn(RUST_BOUNDS_CONST_BUGGY, "build")
        cap = M.detect_rust_cap_expr(RUST_BOUNDS_CONST_BUGGY, fn, "count")
        self.assertEqual(cap, "MAX_ITEMS")

    def test_derive_capcheck_injects_guard(self):
        fn = M.extract_rust_fn(RUST_BOUNDS_BUGGY, "verify")
        fixed = M.derive_rust_fixed_capcheck(fn, "verify", "verify_fixed_AUTO",
                                             "proof_len", "cfg.max_depth")
        self.assertIn("fn verify_fixed_AUTO", fixed)
        self.assertIn("proof_len > cfg.max_depth", fixed)
        self.assertIn("return Err", fixed)

    def test_no_length_param_blocked(self):
        src = "pub fn f(cfg: &Cfg) -> Result<u64, String> { Ok(0) }\npub struct Cfg { pub max_depth: u32 }"
        tmp = Path(tempfile.mkdtemp())
        try:
            tf = tmp / "t.rs"
            tf.write_text(src)
            r = M.convert(tf, "f", "dos-resource-exhaustion", "rust",
                          repo_root=REPO_ROOT, out_dir=None, run=False)
            self.assertEqual(r["verdict"], M.BLOCKED)
            self.assertIn("length param", r["reason"])
            self.assertNotEqual(r["verdict"], M.PROOF_BACKED)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_no_cap_blocked(self):
        # length param present (drives with_capacity) but no configured cap.
        src = ("pub fn f(n: u32) -> Result<u64, String> "
               "{ let v: Vec<u64> = Vec::with_capacity(n as usize); Ok(v.len() as u64) }")
        tmp = Path(tempfile.mkdtemp())
        try:
            tf = tmp / "t.rs"
            tf.write_text(src)
            r = M.convert(tf, "f", "dos-resource-exhaustion", "rust",
                          repo_root=REPO_ROOT, out_dir=None, run=False)
            self.assertEqual(r["verdict"], M.BLOCKED)
            self.assertIn("cap", r["reason"])
            self.assertNotEqual(r["verdict"], M.PROOF_BACKED)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestUsedFieldInjection(unittest.TestCase):
    def test_rust_adds_used_field(self):
        fn = M.extract_rust_fn(RUST_BUGGY, "sign")
        amended = M.ensure_rust_used_field(RUST_BUGGY, fn)
        self.assertIn("pub used: bool", amended)

    def test_go_adds_used_field(self):
        fn = M.extract_go_fn(GO_BUGGY, "Sign")
        amended = M.ensure_go_used_field(GO_BUGGY, fn)
        self.assertIn("Used bool", amended)


class TestAdjudication(unittest.TestCase):
    def test_proof_backed(self):
        v, _ = M.adjudicate(
            {"exploit_fail": True, "exploit_pass": False,
             "control_pass": True, "control_fail": False}, True)
        self.assertEqual(v, M.PROOF_BACKED)

    def test_refuted_when_invariant_does_not_catch(self):
        v, _ = M.adjudicate(
            {"exploit_fail": False, "exploit_pass": True,
             "control_pass": True, "control_fail": False}, True)
        self.assertEqual(v, M.REFUTED)

    def test_blocked_on_no_compile(self):
        v, _ = M.adjudicate(
            {"exploit_fail": True, "exploit_pass": False,
             "control_pass": True, "control_fail": False}, False)
        self.assertEqual(v, M.BLOCKED)

    def test_blocked_on_ambiguous(self):
        v, _ = M.adjudicate(
            {"exploit_fail": False, "exploit_pass": False,
             "control_pass": False, "control_fail": False}, True)
        self.assertEqual(v, M.BLOCKED)


class TestHonestyContractBlocks(unittest.TestCase):
    """The single worst failure is a fabricated proof. These assert that
    non-convertible inputs return blocked-with-obligation, never proof-backed."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_unmapped_vuln_class_blocked(self):
        tf = self.tmp / "t.rs"
        tf.write_text(RUST_BUGGY)
        r = M.convert(tf, "sign", "reentrancy", "rust",
                      repo_root=REPO_ROOT, out_dir=None, run=False)
        self.assertEqual(r["verdict"], M.BLOCKED)
        self.assertNotEqual(r["verdict"], M.PROOF_BACKED)

    def test_external_ref_blocked(self):
        tf = self.tmp / "t.rs"
        tf.write_text("pub fn sign(n: &mut Foreign) -> Result<u64, String> { Ok(n.x) }")
        r = M.convert(tf, "sign", "nonce-reuse", "rust",
                      repo_root=REPO_ROOT, out_dir=None, run=False)
        self.assertEqual(r["verdict"], M.BLOCKED)
        self.assertIn("self-contained", r["reason"])

    def test_missing_fn_blocked(self):
        tf = self.tmp / "t.rs"
        tf.write_text(RUST_BUGGY)
        r = M.convert(tf, "does_not_exist", "nonce-reuse", "rust",
                      repo_root=REPO_ROOT, out_dir=None, run=False)
        self.assertEqual(r["verdict"], M.BLOCKED)

    def test_scaffold_only_never_proof_backed(self):
        tf = self.tmp / "t.rs"
        tf.write_text(RUST_BUGGY)
        r = M.convert(tf, "sign", "nonce-reuse", "rust",
                      repo_root=REPO_ROOT, out_dir=None, run=False)
        # --no-run path: scaffolded but NOT adjudicated -> never proof-backed.
        self.assertNotEqual(r["verdict"], M.PROOF_BACKED)
        self.assertTrue(r.get("scaffold_only"))

    def test_cosmos_msgserver_extracts_then_blocks_with_obligation(self):
        # The receiver-method fix makes extraction succeed; the conversion then
        # honestly reports blocked-with-obligation because the method body is
        # not self-contained (package-qualified call). This is the conversion
        # wall: extraction is a real lift, but autonomous conversion still
        # blocks on the dep-graph and must be reported as blocked, not faked.
        tf = self.tmp / "msgserver.go"
        tf.write_text(GO_COSMOS_MSGSERVER)
        r = M.convert(tf, "Deposit", "missing-input-validation", "go",
                      repo_root=REPO_ROOT, out_dir=None, run=False)
        self.assertNotEqual(r["verdict"], M.PROOF_BACKED)
        self.assertEqual(r["verdict"], M.BLOCKED)
        # Obligation must be named (self-containment / dep wall).
        self.assertIn("self-contained", r["reason"])


@unittest.skipIf(shutil.which("cargo") is None, "cargo not installed")
class TestRustRealRun(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_proof_backed_end_to_end(self):
        tf = self.tmp / "frost_buggy.rs"
        tf.write_text(RUST_BUGGY)
        r = M.convert(tf, "sign", "nonce-reuse", "rust",
                      repo_root=REPO_ROOT, out_dir=self.tmp / "out", run=True)
        self.assertEqual(r["verdict"], M.PROOF_BACKED, r.get("transcript_tail", ""))
        self.assertTrue(r["parsed"]["exploit_fail"])
        self.assertTrue(r["parsed"]["control_pass"])
        self.assertTrue(r["parsed"]["compiled"])

    def test_bounds_proof_backed_end_to_end(self):
        # dos-resource-exhaustion / bounds family: over-cap allocation accepted on
        # the buggy fn (exploit FAILs) + rejected on the cap-check fixed fn
        # (control PASSES).
        tf = self.tmp / "merkle_buggy.rs"
        tf.write_text(RUST_BOUNDS_BUGGY)
        r = M.convert(tf, "verify", "dos-resource-exhaustion", "rust",
                      repo_root=REPO_ROOT, out_dir=self.tmp / "out_bounds", run=True)
        self.assertEqual(r["verdict"], M.PROOF_BACKED, r.get("transcript_tail", ""))
        self.assertTrue(r["parsed"]["exploit_fail"])
        self.assertTrue(r["parsed"]["control_pass"])
        self.assertTrue(r["parsed"]["compiled"])
        self.assertEqual(r["invariant_category"], "bounds")
        self.assertEqual(r["length_param"], "proof_len")
        self.assertEqual(r["cap_expr"], "cfg.max_depth")
        self.assertTrue(r["invariant_grounded_in_corpus"])

    def test_bounds_const_cap_proof_backed_end_to_end(self):
        tf = self.tmp / "build_buggy.rs"
        tf.write_text(RUST_BOUNDS_CONST_BUGGY)
        r = M.convert(tf, "build", "unbounded-allocation", "rust",
                      repo_root=REPO_ROOT, out_dir=self.tmp / "out_const", run=True)
        self.assertEqual(r["verdict"], M.PROOF_BACKED, r.get("transcript_tail", ""))
        self.assertEqual(r["cap_expr"], "MAX_ITEMS")


@unittest.skipIf(shutil.which("go") is None, "go not installed")
class TestGoRealRun(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_proof_backed_end_to_end(self):
        tf = self.tmp / "nonce_buggy.go"
        tf.write_text(GO_BUGGY)
        r = M.convert(tf, "Sign", "nonce-reuse", "go",
                      repo_root=REPO_ROOT, out_dir=self.tmp / "out", run=True)
        self.assertEqual(r["verdict"], M.PROOF_BACKED, r.get("transcript_tail", ""))
        self.assertTrue(r["parsed"]["exploit_fail"])
        self.assertTrue(r["parsed"]["control_pass"])


# Conservation / normalization family (iter15-B). GENERIC signature-driven
# synthesis - the synthesizer detects a `[]*T` / `[]T` slice param whose element
# struct carries a numeric weight-like field, builds conserving + non-conserving
# collections, derives the sum-check fixed variant. No target symbol names.
#
# QUICKSILVER-SHAPE: faithful to x/interchainstaking validateIntents (slice of
# weight-bearing intents consumed with no sum/positivity check). The REAL fn is
# protocol-coupled and blocks; this lifts the SAME bug shape standalone.
GO_CONSERVATION_QUICKSILVER = '''package target
type ValidatorIntent struct {
	ValoperAddress string
	Weight         int64
}
func validateIntents(intents []*ValidatorIntent) error {
	for _, intent := range intents {
		if intent.ValoperAddress == "" {
			return errIntent
		}
	}
	return nil
}
var errIntent = makeErr("invalid intent")
type strErr struct{ s string }
func (e *strErr) Error() string { return e.s }
func makeErr(s string) error    { return &strErr{s} }
'''

# UNBIASED never-seen conservation target: DIFFERENT symbol names (distribute /
# Payout / Bps) - no quicksilver vocabulary. Proves the synthesis is re-derived
# from the signature, not a memorized body.
GO_CONSERVATION_UNBIASED = '''package payouts
type Payout struct {
	Recipient string
	Bps       int32
}
func distribute(payouts []Payout, totalAmount uint64) error {
	for _, p := range payouts {
		if p.Recipient == "" {
			return errBadRecipient
		}
	}
	return nil
}
var errBadRecipient = mkErr("empty recipient")
type pErr struct{ m string }
func (e *pErr) Error() string { return e.m }
func mkErr(m string) error    { return &pErr{m} }
'''

# Conservation with NO weight field -> honesty block (no fabricated fix).
GO_CONSERVATION_NOWEIGHT = '''package t
type Item struct { Name string }
func process(items []Item) error { return nil }
'''

# Staleness sub-shape of the freshness family (iter15-B). SYNTHETIFY-SHAPE:
# faithful to programs/exchange/src/math.rs:26 calculate_debt asset.last_update
# staleness gate. The REAL fn is protocol-coupled (RefMut<AssetsList>) and
# blocks; this lifts the SAME staleness bug standalone.
RUST_STALENESS_SYNTHETIFY = '''pub struct Asset {
    pub last_update: u64,
    pub price: u64,
}
pub type Error = String;
pub fn calculate_debt(asset: &Asset, slot: u64, max_delay: u32) -> Result<u64, Error> {
    Ok(asset.price)
}
'''

# UNBIASED never-seen staleness target: DIFFERENT symbol names (read_value /
# PriceFeed / published_at / now / ttl). Proves signature-driven re-derivation.
RUST_STALENESS_UNBIASED = '''pub struct PriceFeed {
    pub published_at: u64,
    pub value: u128,
}
pub type Err = String;
pub fn read_value(feed: &PriceFeed, now: u64, ttl: u32) -> Result<u128, Err> {
    Ok(feed.value)
}
'''


class TestConservationFamily(unittest.TestCase):
    """GENERIC conservation/normalization convert family - the Quicksilver
    economic-validation-omission shape. Hermetic detection tests + real go-test
    proof tests."""

    def test_conservation_classes_map(self):
        for vc in ("missing-conservation-check", "missing-weight-validation",
                   "unchecked-weight-sum", "missing-normalization-check",
                   "unnormalized-weights"):
            m = M.map_vuln_class(vc)
            self.assertIsNotNone(m, vc)
            self.assertEqual(m, ("conservation", "sum-check"), vc)

    def test_detect_slice_param(self):
        fn = M.extract_go_fn(GO_CONSERVATION_QUICKSILVER, "validateIntents")
        sp = M._go_slice_param(fn)
        self.assertEqual(sp, ("intents", "ValidatorIntent", True))

    def test_detect_weight_field(self):
        wf = M._go_struct_weight_field(GO_CONSERVATION_QUICKSILVER, "ValidatorIntent")
        self.assertEqual(wf, ("Weight", "int64"))

    def test_detect_weight_field_unbiased_bps(self):
        # The unbiased target uses `Bps` not `Weight` - the canonical
        # distribution-field-name regex matches it.
        wf = M._go_struct_weight_field(GO_CONSERVATION_UNBIASED, "Payout")
        self.assertEqual(wf, ("Bps", "int32"))

    def test_no_weight_field_blocked(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            tf = tmp / "t.go"
            tf.write_text(GO_CONSERVATION_NOWEIGHT)
            r = M.convert(tf, "process", "missing-conservation-check", "go",
                          repo_root=REPO_ROOT, out_dir=None, run=False)
            self.assertEqual(r["verdict"], M.BLOCKED)
            self.assertNotEqual(r["verdict"], M.PROOF_BACKED)
            self.assertIn("weight", r["reason"].lower())
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


@unittest.skipIf(shutil.which("go") is None, "go not installed")
class TestConservationRealRun(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_quicksilver_shape_proof_backed(self):
        # GENERIC: drives the Quicksilver validateIntents shape via signature-
        # driven synthesis (no hand-spec). exploit FAILs on bug + control PASSes.
        tf = self.tmp / "qs.go"
        tf.write_text(GO_CONSERVATION_QUICKSILVER)
        r = M.convert(tf, "validateIntents", "missing-weight-validation", "go",
                      repo_root=REPO_ROOT, out_dir=self.tmp / "out", run=True)
        self.assertEqual(r["verdict"], M.PROOF_BACKED, r.get("transcript_tail", ""))
        self.assertTrue(r["parsed"]["exploit_fail"])
        self.assertTrue(r["parsed"]["control_pass"])
        self.assertEqual(r["invariant_category"], "conservation")
        self.assertEqual(r["slice_param"], "intents")
        self.assertEqual(r["weight_field"], "ValidatorIntent.Weight")

    def test_unbiased_shape_proof_backed(self):
        # The REAL genericity proof: a never-seen target (distribute/Payout/Bps)
        # with NO quicksilver vocabulary converts via the same synthesizer.
        tf = self.tmp / "payout.go"
        tf.write_text(GO_CONSERVATION_UNBIASED)
        r = M.convert(tf, "distribute", "missing-conservation-check", "go",
                      repo_root=REPO_ROOT, out_dir=self.tmp / "out", run=True)
        self.assertEqual(r["verdict"], M.PROOF_BACKED, r.get("transcript_tail", ""))
        self.assertTrue(r["parsed"]["exploit_fail"])
        self.assertTrue(r["parsed"]["control_pass"])
        self.assertEqual(r["slice_param"], "payouts")
        self.assertEqual(r["weight_field"], "Payout.Bps")


class TestStalenessFamily(unittest.TestCase):
    """GENERIC staleness sub-shape of the freshness family - the Synthetify
    oracle-pricing shape. Hermetic detection + real cargo proof tests."""

    def test_detect_staleness_synthetify(self):
        fn = M.extract_rust_fn(RUST_STALENESS_SYNTHETIFY, "calculate_debt")
        stale = M._detect_rust_staleness(RUST_STALENESS_SYNTHETIFY, fn)
        self.assertIsNotNone(stale)
        ref_param, ref_ty, ts_field, now_param, delay_param = stale
        self.assertEqual((ref_ty, ts_field, now_param, delay_param),
                         ("Asset", "last_update", "slot", "max_delay"))

    def test_detect_staleness_unbiased(self):
        # Never-seen names: PriceFeed/published_at/now/ttl.
        fn = M.extract_rust_fn(RUST_STALENESS_UNBIASED, "read_value")
        stale = M._detect_rust_staleness(RUST_STALENESS_UNBIASED, fn)
        self.assertIsNotNone(stale)
        _, ref_ty, ts_field, now_param, delay_param = stale
        self.assertEqual((ref_ty, ts_field, now_param, delay_param),
                         ("PriceFeed", "published_at", "now", "ttl"))

    def test_staleness_falls_back_and_blocks_when_no_ts(self):
        # No timestamp field + no consume-once resource -> honesty block.
        src = ("pub struct Cfg { pub price: u64 }\n"
               "pub fn f(c: &Cfg, slot: u64, max_delay: u32) "
               "-> Result<u64, String> { Ok(c.price) }")
        tmp = Path(tempfile.mkdtemp())
        try:
            tf = tmp / "t.rs"
            tf.write_text(src)
            r = M.convert(tf, "f", "missing-freshness-guard", "rust",
                          repo_root=REPO_ROOT, out_dir=None, run=False)
            self.assertEqual(r["verdict"], M.BLOCKED)
            self.assertNotEqual(r["verdict"], M.PROOF_BACKED)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


@unittest.skipIf(shutil.which("cargo") is None, "cargo not installed")
class TestStalenessRealRun(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_synthetify_shape_proof_backed(self):
        tf = self.tmp / "synth.rs"
        tf.write_text(RUST_STALENESS_SYNTHETIFY)
        r = M.convert(tf, "calculate_debt", "missing-freshness-guard", "rust",
                      repo_root=REPO_ROOT, out_dir=self.tmp / "out", run=True)
        self.assertEqual(r["verdict"], M.PROOF_BACKED, r.get("transcript_tail", ""))
        self.assertTrue(r["parsed"]["exploit_fail"])
        self.assertTrue(r["parsed"]["control_pass"])
        self.assertEqual(r["freshness_shape"], "staleness-gate")
        self.assertEqual(r["timestamp_field"], "Asset.last_update")

    def test_unbiased_staleness_proof_backed(self):
        tf = self.tmp / "feed.rs"
        tf.write_text(RUST_STALENESS_UNBIASED)
        r = M.convert(tf, "read_value", "missing-freshness-guard", "rust",
                      repo_root=REPO_ROOT, out_dir=self.tmp / "out", run=True)
        self.assertEqual(r["verdict"], M.PROOF_BACKED, r.get("transcript_tail", ""))
        self.assertEqual(r["timestamp_field"], "PriceFeed.published_at")
        self.assertEqual(r["now_param"], "now")
        self.assertEqual(r["delay_param"], "ttl")


class TestRealProtocolCoupledFnsBlock(unittest.TestCase):
    """The REAL Quicksilver/Synthetify fns are protocol-coupled and MUST honestly
    block-with-obligation (never a fabricated proof). These tests are skipped
    when the iter12 workspaces are absent."""

    QS = Path("/Users/wolf/audits/quicksilver-iter12/x/interchainstaking/"
              "keeper/msg_server.go")

    def test_real_quicksilver_blocks(self):
        if not self.QS.is_file():
            self.skipTest("quicksilver-iter12 workspace absent")
        r = M.convert(self.QS, "validateIntents", "missing-weight-validation",
                      "go", repo_root=REPO_ROOT, out_dir=None, run=False)
        self.assertEqual(r["verdict"], M.BLOCKED)
        self.assertIn("self-contained", r["reason"])


# ===========================================================================
# iter17 PARALLEL-B: int-truncation + access-control families (Go + Rust).
# Two MORE target-agnostic generic shape families, signature/shape-driven with
# NO hardcoded target fn names. Each family proves on an ANCHOR fixture AND an
# UNBIASED never-seen fixture (different symbol names, zero vocab overlap) to
# show the synthesis is re-derived from the signature, not memorized.
# ===========================================================================

# --- int-truncation family (guard = cast-bound-check) -----------------------

# Rust ANCHOR: wide `amount: u64` narrowed by `as u32` with no bound check.
RUST_TRUNC_ANCHOR = '''pub type Error = String;
pub fn pack_amount(amount: u64) -> Result<u32, Error> {
    let packed: u32 = amount as u32;
    Ok(packed)
}
'''

# Rust UNBIASED: never-seen names (fold_index / slot / stride) + u128->u64. No
# vocabulary overlap with the anchor. Proves signature-driven re-derivation.
RUST_TRUNC_UNBIASED = '''pub type Fault = String;
pub fn fold_index(slot: u128, stride: u16) -> Result<u64, Fault> {
    let folded: u64 = slot as u64;
    Ok(folded.wrapping_mul(stride as u64))
}
'''

# Go ANCHOR: wide `amount: uint64` narrowed by `uint32(...)`, returns error.
GO_TRUNC_ANCHOR = '''package target
func packAmount(amount uint64) (uint32, error) {
	packed := uint32(amount)
	return packed, nil
}
'''

# Go UNBIASED: never-seen names (clampReward / reward / Outcome) + uint64->uint16
# + a MULTI-VALUE (Outcome, error) return (exercises the arity-aware reject /
# capture path). Zero vocab overlap with the anchor.
GO_TRUNC_UNBIASED = '''package settlement
type Outcome struct { Total uint64 }
func clampReward(reward uint64, factor uint8) (Outcome, error) {
	scaled := uint16(reward)
	return Outcome{Total: uint64(scaled) * uint64(factor)}, nil
}
'''

# Go widening conversion (uint16 -> uint64): NOT a narrowing cast -> honesty
# block (no fabricated fix).
GO_TRUNC_WIDENING = '''package t
func widen(x uint16) (uint64, error) { return uint64(x), nil }
'''

# Rust truncation with NO Result/error channel -> honesty block.
RUST_TRUNC_NOERR = '''pub fn shrink(x: u64) -> u32 { x as u32 }
'''

# --- access-control family (guard = owner-guard) ----------------------------

# Rust ANCHOR: `&mut Vault` with an `owner` identity field + a `caller` of the
# same type, mutated with NO `caller == vault.owner` guard.
RUST_AC_ANCHOR = '''pub struct Vault { pub owner: u64, pub fee_bps: u64 }
pub type Error = String;
pub fn set_fee(vault: &mut Vault, caller: u64, new_fee: u64) -> Result<u64, Error> {
    vault.fee_bps = new_fee;
    Ok(vault.fee_bps)
}
'''

# Rust UNBIASED: never-seen names (withdraw_reserve / Treasury / governor /
# requester) + u128 reserve. Zero vocab overlap with the anchor.
RUST_AC_UNBIASED = '''pub struct Treasury { pub governor: u64, pub reserve: u128 }
pub type Fault = String;
pub fn withdraw_reserve(book: &mut Treasury, requester: u64, amt: u128) -> Result<u128, Fault> {
    book.reserve = book.reserve.saturating_sub(amt);
    Ok(book.reserve)
}
'''

# Rust ALREADY-GUARDED: the fn already compares caller against the owner ->
# honesty block (the bug is NOT present; never falsely proof-backed).
RUST_AC_GUARDED = '''pub struct Vault { pub owner: u64, pub fee: u64 }
pub type Error = String;
pub fn set_fee(v: &mut Vault, caller: u64, fee: u64) -> Result<u64, Error> {
    if caller != v.owner { return Err("not owner".into()); }
    v.fee = fee;
    Ok(v.fee)
}
'''

# Rust NO-IDENTITY-FIELD: state struct has no identity field -> honesty block.
RUST_AC_NOIDENT = '''pub struct State { pub balance: u64 }
pub type Error = String;
pub fn poke(s: &mut State, caller: u64) -> Result<u64, Error> { s.balance += 1; Ok(s.balance) }
'''

# Go ANCHOR: `*Vault` with `Owner` identity + `caller` of same type, no guard.
GO_AC_ANCHOR = '''package target
type Vault struct {
	Owner  uint64
	FeeBps uint64
}
func SetFee(vault *Vault, caller uint64, newFee uint64) error {
	vault.FeeBps = newFee
	return nil
}
'''

# Go UNBIASED: never-seen names (adjustRate / Pool / Controller / origin) +
# STRING identity type + MULTI-VALUE (uint64, error) return. Zero vocab overlap.
GO_AC_UNBIASED = '''package registry
type Pool struct {
	Controller string
	Rate       uint64
}
func adjustRate(book *Pool, origin string, newRate uint64) (uint64, error) {
	book.Rate = newRate
	return book.Rate, nil
}
'''


class TestIntTruncationFamily(unittest.TestCase):
    """GENERIC int-truncation/narrowing-cast convert family. Hermetic detection
    + map + honesty-block tests; real-run proofs gated on toolchain below."""

    def test_truncation_classes_map(self):
        for vc in ("integer-overflow", "integer-truncation", "narrowing-cast",
                   "downcast-truncation", "silent-truncation", "unchecked-cast",
                   "unsafe-cast", "missing-overflow-check"):
            m = M.map_vuln_class(vc)
            self.assertIsNotNone(m, vc)
            self.assertEqual(m, ("int-truncation", "cast-bound-check"), vc)

    def test_detect_rust_narrowing_cast(self):
        fn = M.extract_rust_fn(RUST_TRUNC_ANCHOR, "pack_amount")
        self.assertEqual(M._detect_rust_truncation(fn), ("amount", "u64", "u32"))

    def test_detect_rust_narrowing_cast_unbiased(self):
        fn = M.extract_rust_fn(RUST_TRUNC_UNBIASED, "fold_index")
        # u128 -> u64 is the narrowing cast; `stride as u64` is a WIDENING cast
        # (u16 -> u64) and must NOT be selected.
        self.assertEqual(M._detect_rust_truncation(fn), ("slot", "u128", "u64"))

    def test_rust_widening_cast_not_detected(self):
        src = "pub fn widen(x: u32) -> Result<u64, String> { let y: u64 = x as u64; Ok(y) }"
        fn = M.extract_rust_fn(src, "widen")
        self.assertIsNone(M._detect_rust_truncation(fn))

    def test_detect_go_narrowing_cast(self):
        fn = M.extract_go_fn(GO_TRUNC_ANCHOR, "packAmount")
        self.assertEqual(M._detect_go_truncation(fn), ("amount", "uint64", "uint32"))

    def test_detect_go_narrowing_cast_unbiased(self):
        fn = M.extract_go_fn(GO_TRUNC_UNBIASED, "clampReward")
        self.assertEqual(M._detect_go_truncation(fn), ("reward", "uint64", "uint16"))

    def test_go_widening_not_detected(self):
        fn = M.extract_go_fn(GO_TRUNC_WIDENING, "widen")
        self.assertIsNone(M._detect_go_truncation(fn))

    def test_derive_rust_castcheck_injects_guard(self):
        fn = M.extract_rust_fn(RUST_TRUNC_ANCHOR, "pack_amount")
        fixed = M.derive_rust_fixed_castcheck(fn, "pack_amount", "pa_AUTO",
                                              "amount", "u32")
        self.assertIn("fn pa_AUTO", fixed)
        self.assertIn("4294967295", fixed)
        self.assertIn("return Err", fixed)

    def test_go_widening_blocked(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            tf = tmp / "t.go"
            tf.write_text(GO_TRUNC_WIDENING)
            r = M.convert(tf, "widen", "narrowing-cast", "go",
                          repo_root=REPO_ROOT, out_dir=None, run=False)
            self.assertEqual(r["verdict"], M.BLOCKED)
            self.assertNotEqual(r["verdict"], M.PROOF_BACKED)
            self.assertIn("narrowing", r["reason"].lower())
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_rust_no_error_channel_blocked(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            tf = tmp / "t.rs"
            tf.write_text(RUST_TRUNC_NOERR)
            r = M.convert(tf, "shrink", "truncation", "rust",
                          repo_root=REPO_ROOT, out_dir=None, run=False)
            self.assertEqual(r["verdict"], M.BLOCKED)
            self.assertNotEqual(r["verdict"], M.PROOF_BACKED)
            self.assertIn("Result", r["reason"])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


@unittest.skipIf(shutil.which("cargo") is None, "cargo not installed")
class TestIntTruncationRustRealRun(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_anchor_proof_backed(self):
        tf = self.tmp / "anchor.rs"
        tf.write_text(RUST_TRUNC_ANCHOR)
        r = M.convert(tf, "pack_amount", "integer-truncation", "rust",
                      repo_root=REPO_ROOT, out_dir=self.tmp / "out", run=True)
        self.assertEqual(r["verdict"], M.PROOF_BACKED, r.get("transcript_tail", ""))
        self.assertTrue(r["parsed"]["exploit_fail"])
        self.assertTrue(r["parsed"]["control_pass"])
        self.assertEqual(r["narrowing_cast"], "u64 -> u32")

    def test_unbiased_proof_backed(self):
        # The genericity proof: never-seen target (fold_index/slot/stride, u128
        # -> u64) with no anchor vocabulary converts via the same synthesizer.
        tf = self.tmp / "unbiased.rs"
        tf.write_text(RUST_TRUNC_UNBIASED)
        r = M.convert(tf, "fold_index", "downcast-truncation", "rust",
                      repo_root=REPO_ROOT, out_dir=self.tmp / "out", run=True)
        self.assertEqual(r["verdict"], M.PROOF_BACKED, r.get("transcript_tail", ""))
        self.assertEqual(r["truncation_param"], "slot")
        self.assertEqual(r["narrowing_cast"], "u128 -> u64")


@unittest.skipIf(shutil.which("go") is None, "go not installed")
class TestIntTruncationGoRealRun(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_anchor_proof_backed(self):
        tf = self.tmp / "anchor.go"
        tf.write_text(GO_TRUNC_ANCHOR)
        r = M.convert(tf, "packAmount", "integer-truncation", "go",
                      repo_root=REPO_ROOT, out_dir=self.tmp / "out", run=True)
        self.assertEqual(r["verdict"], M.PROOF_BACKED, r.get("transcript_tail", ""))
        self.assertTrue(r["parsed"]["exploit_fail"])
        self.assertTrue(r["parsed"]["control_pass"])

    def test_unbiased_multivalue_proof_backed(self):
        # never-seen (clampReward/reward/Outcome) + a MULTI-VALUE (Outcome,error)
        # return exercises the arity-aware reject + capture path.
        tf = self.tmp / "unbiased.go"
        tf.write_text(GO_TRUNC_UNBIASED)
        r = M.convert(tf, "clampReward", "silent-truncation", "go",
                      repo_root=REPO_ROOT, out_dir=self.tmp / "out", run=True)
        self.assertEqual(r["verdict"], M.PROOF_BACKED, r.get("transcript_tail", ""))
        self.assertEqual(r["truncation_param"], "reward")
        self.assertEqual(r["narrowing_cast"], "uint64 -> uint16")


class TestAccessControlFamily(unittest.TestCase):
    """GENERIC access-control / owner-guard convert family. Hermetic detection +
    map + honesty-block tests; real-run proofs gated on toolchain below."""

    def test_access_control_classes_map(self):
        for vc in ("access-control-bypass", "missing-access-control",
                   "missing-owner-check", "missing-authorization",
                   "unauthorized-state-mutation", "privilege-escalation",
                   "broken-access-control"):
            m = M.map_vuln_class(vc)
            self.assertIsNotNone(m, vc)
            self.assertEqual(m, ("access-control", "owner-guard"), vc)

    def test_detect_rust_access_control(self):
        fn = M.extract_rust_fn(RUST_AC_ANCHOR, "set_fee")
        ac = M._detect_rust_access_control(RUST_AC_ANCHOR, fn)
        self.assertIsNotNone(ac)
        state_param, state_ty, identity_field, identity_fty, caller_param = ac
        self.assertEqual((state_ty, identity_field, caller_param),
                         ("Vault", "owner", "caller"))

    def test_detect_rust_access_control_unbiased(self):
        fn = M.extract_rust_fn(RUST_AC_UNBIASED, "withdraw_reserve")
        ac = M._detect_rust_access_control(RUST_AC_UNBIASED, fn)
        self.assertIsNotNone(ac)
        _, state_ty, identity_field, _, caller_param = ac
        self.assertEqual((state_ty, identity_field, caller_param),
                         ("Treasury", "governor", "requester"))

    def test_rust_already_guarded_not_detected(self):
        # The bug is NOT present (caller is already compared to owner) -> the
        # detector must return None so the converter blocks, never proof-backs.
        fn = M.extract_rust_fn(RUST_AC_GUARDED, "set_fee")
        self.assertIsNone(M._detect_rust_access_control(RUST_AC_GUARDED, fn))

    def test_rust_no_identity_field_not_detected(self):
        fn = M.extract_rust_fn(RUST_AC_NOIDENT, "poke")
        self.assertIsNone(M._detect_rust_access_control(RUST_AC_NOIDENT, fn))

    def test_detect_go_access_control(self):
        fn = M.extract_go_fn(GO_AC_ANCHOR, "SetFee")
        ac = M._detect_go_access_control(GO_AC_ANCHOR, fn)
        self.assertIsNotNone(ac)
        _, state_ty, identity_field, _, caller_param = ac
        self.assertEqual((state_ty, identity_field, caller_param),
                         ("Vault", "Owner", "caller"))

    def test_detect_go_access_control_unbiased(self):
        fn = M.extract_go_fn(GO_AC_UNBIASED, "adjustRate")
        ac = M._detect_go_access_control(GO_AC_UNBIASED, fn)
        self.assertIsNotNone(ac)
        _, state_ty, identity_field, identity_fty, caller_param = ac
        self.assertEqual((state_ty, identity_field, identity_fty, caller_param),
                         ("Pool", "Controller", "string", "origin"))

    def test_derive_rust_ownerguard_injects_guard(self):
        fn = M.extract_rust_fn(RUST_AC_ANCHOR, "set_fee")
        fixed = M.derive_rust_fixed_ownerguard(fn, "set_fee", "sf_AUTO",
                                               "vault", "owner", "caller")
        self.assertIn("fn sf_AUTO", fixed)
        self.assertIn("caller != vault.owner", fixed)
        self.assertIn("return Err", fixed)

    def test_rust_already_guarded_blocked(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            tf = tmp / "t.rs"
            tf.write_text(RUST_AC_GUARDED)
            r = M.convert(tf, "set_fee", "missing-owner-check", "rust",
                          repo_root=REPO_ROOT, out_dir=None, run=False)
            self.assertEqual(r["verdict"], M.BLOCKED)
            self.assertNotEqual(r["verdict"], M.PROOF_BACKED)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


@unittest.skipIf(shutil.which("cargo") is None, "cargo not installed")
class TestAccessControlRustRealRun(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_anchor_proof_backed(self):
        tf = self.tmp / "anchor.rs"
        tf.write_text(RUST_AC_ANCHOR)
        r = M.convert(tf, "set_fee", "access-control-bypass", "rust",
                      repo_root=REPO_ROOT, out_dir=self.tmp / "out", run=True)
        self.assertEqual(r["verdict"], M.PROOF_BACKED, r.get("transcript_tail", ""))
        self.assertTrue(r["parsed"]["exploit_fail"])
        self.assertTrue(r["parsed"]["control_pass"])
        self.assertEqual(r["identity_field"], "Vault.owner")

    def test_unbiased_proof_backed(self):
        tf = self.tmp / "unbiased.rs"
        tf.write_text(RUST_AC_UNBIASED)
        r = M.convert(tf, "withdraw_reserve", "missing-owner-check", "rust",
                      repo_root=REPO_ROOT, out_dir=self.tmp / "out", run=True)
        self.assertEqual(r["verdict"], M.PROOF_BACKED, r.get("transcript_tail", ""))
        self.assertEqual(r["identity_field"], "Treasury.governor")
        self.assertEqual(r["caller_param"], "requester")


@unittest.skipIf(shutil.which("go") is None, "go not installed")
class TestAccessControlGoRealRun(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_anchor_proof_backed(self):
        tf = self.tmp / "anchor.go"
        tf.write_text(GO_AC_ANCHOR)
        r = M.convert(tf, "SetFee", "access-control-bypass", "go",
                      repo_root=REPO_ROOT, out_dir=self.tmp / "out", run=True)
        self.assertEqual(r["verdict"], M.PROOF_BACKED, r.get("transcript_tail", ""))
        self.assertTrue(r["parsed"]["exploit_fail"])
        self.assertTrue(r["parsed"]["control_pass"])

    def test_unbiased_string_identity_multivalue_proof_backed(self):
        # never-seen (adjustRate/Pool/Controller/origin) + STRING identity +
        # MULTI-VALUE (uint64, error) return.
        tf = self.tmp / "unbiased.go"
        tf.write_text(GO_AC_UNBIASED)
        r = M.convert(tf, "adjustRate", "missing-access-control", "go",
                      repo_root=REPO_ROOT, out_dir=self.tmp / "out", run=True)
        self.assertEqual(r["verdict"], M.PROOF_BACKED, r.get("transcript_tail", ""))
        self.assertEqual(r["identity_field"], "Pool.Controller")
        self.assertEqual(r["caller_param"], "origin")


# Go reentrancy / CEI, valid-flag staleness, double-credit families (the Go
# twins of the Rust cei-order-check / valid-flag-check / processed-flag-check
# families). Self-contained, never-seen symbol names (zero anchor overlap).
GO_REENTRANCY_UNBIASED = '''package vaultcore
type LiquidityPool struct { Reserve uint64; Steward uint64 }
func disburse(pool *LiquidityPool, drain uint64, notify func(uint64)) error {
\tnotify(pool.Reserve)
\tpool.Reserve -= drain
\treturn nil
}
'''
GO_REENTRANCY_CEI_CORRECT = '''package x
type Pool struct { Reserve uint64; Steward uint64 }
func disburse(pool *Pool, drain uint64, notify func(uint64)) error {
\tpool.Reserve -= drain
\tnotify(pool.Reserve)
\treturn nil
}
'''
GO_VALIDFLAG_UNBIASED_POS = '''package feedcore
type TickerSnapshot struct { Rate uint64; Live bool }
func quoteRate(snap *TickerSnapshot) (uint64, error) { return snap.Rate, nil }
'''
GO_VALIDFLAG_UNBIASED_NEG = '''package feedcore
type Quote struct { Value uint64; Stale bool }
func quoteRate(q *Quote) (uint64, error) { return q.Value, nil }
'''
GO_VALIDFLAG_ALREADY_CONSULTED = '''package x
type Snap struct { Rate uint64; Live bool }
func quoteRate(snap *Snap) (uint64, error) {
\tif !snap.Live { return 0, nil }
\treturn snap.Rate, nil
}
'''
GO_DOUBLE_CREDIT_UNBIASED = '''package ledgercore
type MemberAccount struct { MemberId uint64; Bonus uint64; Accrued uint64 }
func applyRebate(acct *MemberAccount) error { acct.Accrued += acct.Bonus; return nil }
'''
GO_DOUBLE_CREDIT_NO_FIELD = '''package x
type Acct struct { MemberId uint64 }
func applyRebate(acct *Acct) error { return nil }
'''


class TestGoReentrancyValidFlagDoubleCreditDetect(unittest.TestCase):
    """Detector-level (no engine) discipline for the 3 new Go families."""

    def test_detect_go_reentrancy_unbiased(self):
        fn = M.extract_go_fn(GO_REENTRANCY_UNBIASED, "disburse")
        ree = M._detect_go_reentrancy(GO_REENTRANCY_UNBIASED, fn)
        self.assertIsNotNone(ree)
        sp, sty, bf, hp = ree
        self.assertEqual((sty, bf, hp), ("LiquidityPool", "Reserve", "notify"))

    def test_detect_go_reentrancy_cei_correct_blocks(self):
        # write BEFORE the call -> already CEI-correct -> NOT flagged.
        fn = M.extract_go_fn(GO_REENTRANCY_CEI_CORRECT, "disburse")
        self.assertIsNone(M._detect_go_reentrancy(GO_REENTRANCY_CEI_CORRECT, fn))

    def test_detect_go_valid_flag_positive(self):
        fn = M.extract_go_fn(GO_VALIDFLAG_UNBIASED_POS, "quoteRate")
        vf = M._detect_go_valid_flag(GO_VALIDFLAG_UNBIASED_POS, fn)
        self.assertIsNotNone(vf)
        self.assertEqual((vf[1], vf[3], vf[4]), ("TickerSnapshot", "Live", "positive"))

    def test_detect_go_valid_flag_negative(self):
        fn = M.extract_go_fn(GO_VALIDFLAG_UNBIASED_NEG, "quoteRate")
        vf = M._detect_go_valid_flag(GO_VALIDFLAG_UNBIASED_NEG, fn)
        self.assertIsNotNone(vf)
        self.assertEqual((vf[3], vf[4]), ("Stale", "negative"))

    def test_detect_go_valid_flag_already_consulted_blocks(self):
        fn = M.extract_go_fn(GO_VALIDFLAG_ALREADY_CONSULTED, "quoteRate")
        self.assertIsNone(M._detect_go_valid_flag(GO_VALIDFLAG_ALREADY_CONSULTED, fn))

    def test_detect_go_double_credit_unbiased(self):
        fn = M.extract_go_fn(GO_DOUBLE_CREDIT_UNBIASED, "applyRebate")
        dc = M._detect_go_double_credit(GO_DOUBLE_CREDIT_UNBIASED, fn)
        self.assertIsNotNone(dc)
        self.assertEqual((dc[1], dc[2]), ("MemberAccount", "Accrued"))

    def test_detect_go_double_credit_no_field_blocks(self):
        fn = M.extract_go_fn(GO_DOUBLE_CREDIT_NO_FIELD, "applyRebate")
        self.assertIsNone(M._detect_go_double_credit(GO_DOUBLE_CREDIT_NO_FIELD, fn))


@unittest.skipIf(shutil.which("go") is None, "go not installed")
class TestGoReentrancyValidFlagDoubleCreditRealRun(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self, src, fn, vc, name):
        tf = self.tmp / name
        tf.write_text(src)
        return M.convert(tf, fn, vc, "go", repo_root=REPO_ROOT,
                         out_dir=self.tmp / "out", run=True)

    def test_reentrancy_unbiased_proof_backed(self):
        r = self._run(GO_REENTRANCY_UNBIASED, "disburse", "reentrancy", "r.go")
        self.assertEqual(r["verdict"], M.PROOF_BACKED, r.get("transcript_tail", ""))
        self.assertTrue(r["parsed"]["exploit_fail"])
        self.assertTrue(r["parsed"]["control_pass"])
        self.assertEqual(r["balance_field"], "LiquidityPool.Reserve")

    def test_valid_flag_positive_proof_backed(self):
        r = self._run(GO_VALIDFLAG_UNBIASED_POS, "quoteRate",
                      "stale-price-on-read", "v.go")
        self.assertEqual(r["verdict"], M.PROOF_BACKED, r.get("transcript_tail", ""))
        self.assertEqual(r["flag_polarity"], "positive")
        self.assertEqual(r["validity_flag"], "TickerSnapshot.Live")

    def test_valid_flag_negative_proof_backed(self):
        r = self._run(GO_VALIDFLAG_UNBIASED_NEG, "quoteRate",
                      "stale-price-on-read", "vn.go")
        self.assertEqual(r["verdict"], M.PROOF_BACKED, r.get("transcript_tail", ""))
        self.assertEqual(r["flag_polarity"], "negative")

    def test_double_credit_unbiased_proof_backed(self):
        r = self._run(GO_DOUBLE_CREDIT_UNBIASED, "applyRebate",
                      "double-credit", "d.go")
        self.assertEqual(r["verdict"], M.PROOF_BACKED, r.get("transcript_tail", ""))
        self.assertTrue(r["parsed"]["exploit_fail"])
        self.assertTrue(r["parsed"]["control_pass"])
        self.assertEqual(r["credit_field"], "MemberAccount.Accrued")

    def test_anchor_double_credit_proof_backed(self):
        # the in-tree TRAIN anchor must also convert (regression lock).
        src = (TRAIN / "double_credit_claim_buggy.go").read_text()
        r = self._run(src, "processClaim", "double-credit", "anchor.go")
        self.assertEqual(r["verdict"], M.PROOF_BACKED, r.get("transcript_tail", ""))


# ---------------------------------------------------------------------------
# 3 new GENERIC families (codex95 single-owner wave): signature-replay /
# missing-nonce (used-nonce-check), unchecked-external-call-return
# (call-return-check), missing-deadline / slippage-bound (deadline-bound-check).
# All signature/shape-driven; NO target fn-name dispatch. UNBIASED never-seen
# symbol names prove the synthesis is re-derived from the signature.
# ---------------------------------------------------------------------------

# UNBIASED signature-replay: a "voucher claim" domain. The fn authorizes a claim
# against a signed digest but never marks the ticket `seen`, so the same signed
# digest replays. DIFFERENT vocabulary from the TRAIN anchor.
GO_SIGREPLAY_UNBIASED = '''package claimdesk
type ClaimTicket struct {
	Beneficiary uint64
	Granted     uint64
	Seen        bool
}
func grantClaim(ticket *ClaimTicket, digest uint64, units uint64) error {
	if units == 0 {
		return errNoUnits
	}
	ticket.Granted += units
	return nil
}
type _nu struct{}
func (_nu) Error() string { return "no units" }
var errNoUnits error = _nu{}
'''

# UNBIASED signature-replay with a COUNTER nonce (no bool flag) - the converter
# injects an auxiliary UsedAUTO flag.
GO_SIGREPLAY_COUNTER_UNBIASED = '''package vault
type SignerSlot struct {
	Account uint64
	Balance uint64
	Nonce   uint64
}
func applyApproval(slot *SignerSlot, approval uint64, amt uint64) error {
	if amt == 0 {
		return errZ
	}
	slot.Balance += amt
	return nil
}
type _z struct{}
func (_z) Error() string { return "zero" }
var errZ error = _z{}
'''

# UNBIASED unchecked-external-call-return with an `error`-returning call.
GO_UNCHECKEDCALL_UNBIASED = '''package treasury
type Voucher struct {
	Holder uint64
	Debt   uint64
}
func clearVoucher(v *Voucher, amount uint64, push func(uint64) error) error {
	if amount == 0 {
		return errZeroV
	}
	push(amount)
	v.Debt = 0
	return nil
}
type _zv struct{}
func (_zv) Error() string { return "zero" }
var errZeroV error = _zv{}
'''

# UNBIASED missing-deadline / slippage-bound with a DEADLINE (max-polarity) bound.
GO_DEADLINE_MAX_UNBIASED = '''package router
type SwapState struct {
	Trader uint64
	Done   uint64
}
func routeSwap(st *SwapState, now uint64, deadline uint64) error {
	if now == 0 {
		return errZeroT
	}
	st.Done += 1
	return nil
}
type _zt struct{}
func (_zt) Error() string { return "zero" }
var errZeroT error = _zt{}
'''


class TestNewGenericFamiliesMap(unittest.TestCase):
    def test_sig_replay_classes_map(self):
        for vc in ["signature-replay", "missing-nonce", "replayable-signature",
                   "permit-replay", "missing-sig-replay-protection"]:
            self.assertEqual(M.map_vuln_class(vc), ("uniqueness", "used-nonce-check"), vc)

    def test_unchecked_call_classes_map(self):
        for vc in ["unchecked-external-call-return", "unchecked-call-return",
                   "ignored-return-value", "swallowed-error", "unchecked-send"]:
            self.assertEqual(M.map_vuln_class(vc), ("external-call", "call-return-check"), vc)

    def test_missing_deadline_classes_map(self):
        for vc in ["missing-deadline", "missing-slippage-check", "missing-min-out",
                   "unbounded-slippage", "missing-price-bound"]:
            self.assertEqual(M.map_vuln_class(vc), ("slippage-bound", "deadline-bound-check"), vc)


class TestNewGenericFamiliesGoRealRun(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self, src, fn, vc, name):
        tf = self.tmp / name
        tf.write_text(src)
        return M.convert(tf, fn, vc, "go", repo_root=REPO_ROOT,
                         out_dir=self.tmp / "out", run=True)

    def test_sig_replay_flag_proof_backed(self):
        r = self._run(GO_SIGREPLAY_UNBIASED, "grantClaim", "signature-replay", "s.go")
        self.assertEqual(r["verdict"], M.PROOF_BACKED, r.get("transcript_tail", ""))
        self.assertTrue(r["parsed"]["exploit_fail"])
        self.assertTrue(r["parsed"]["control_pass"])
        self.assertEqual(r["nonce_field"], "ClaimTicket.Seen")
        self.assertEqual(r["nonce_kind"], "flag")

    def test_sig_replay_counter_proof_backed(self):
        r = self._run(GO_SIGREPLAY_COUNTER_UNBIASED, "applyApproval",
                      "missing-nonce", "sc.go")
        self.assertEqual(r["verdict"], M.PROOF_BACKED, r.get("transcript_tail", ""))
        self.assertEqual(r["nonce_kind"], "counter")

    def test_unchecked_call_proof_backed(self):
        r = self._run(GO_UNCHECKEDCALL_UNBIASED, "clearVoucher",
                      "unchecked-external-call-return", "u.go")
        self.assertEqual(r["verdict"], M.PROOF_BACKED, r.get("transcript_tail", ""))
        self.assertTrue(r["parsed"]["exploit_fail"])
        self.assertTrue(r["parsed"]["control_pass"])
        self.assertEqual(r["result_kind"], "error")
        self.assertEqual(r["call_param"], "push")

    def test_missing_deadline_max_proof_backed(self):
        r = self._run(GO_DEADLINE_MAX_UNBIASED, "routeSwap", "missing-deadline", "d.go")
        self.assertEqual(r["verdict"], M.PROOF_BACKED, r.get("transcript_tail", ""))
        self.assertEqual(r["bound_polarity"], "max")
        self.assertEqual(r["bound_param"], "deadline")

    def test_anchor_sig_replay_proof_backed(self):
        src = (TRAIN / "permit_authorize_sig_replay_unbiased.go").read_text()
        r = self._run(src, "AuthorizeRedeem", "signature-replay", "asr.go")
        self.assertEqual(r["verdict"], M.PROOF_BACKED, r.get("transcript_tail", ""))

    def test_anchor_unchecked_call_proof_backed(self):
        src = (TRAIN / "settle_remit_unchecked_return_unbiased.go").read_text()
        r = self._run(src, "SettleDisbursement",
                      "unchecked-external-call-return", "auc.go")
        self.assertEqual(r["verdict"], M.PROOF_BACKED, r.get("transcript_tail", ""))

    def test_anchor_missing_deadline_proof_backed(self):
        src = (TRAIN / "fill_order_missing_minout_unbiased.go").read_text()
        r = self._run(src, "ExecuteFill", "missing-deadline", "amd.go")
        self.assertEqual(r["verdict"], M.PROOF_BACKED, r.get("transcript_tail", ""))


class TestNewGenericFamiliesRustDetect(unittest.TestCase):
    """Hermetic (no toolchain) detector tests for the three newly-Rust-supported
    guards: used-nonce-check, call-return-check, deadline-bound-check. Detection is
    shape-driven (signature + struct-field name regex), NOT fn-name-driven."""

    def test_detect_rust_signature_replay_flag(self):
        rust = ('pub struct L { pub payout: u64, pub consumed: bool }\n'
                'pub fn auth(l: &mut L, signature: u64, amt: u64) -> Result<(), String> {\n'
                '    l.payout += amt; Ok(())\n}\n')
        fn = M.extract_rust_fn(rust, "auth")
        sr = M._detect_rust_signature_replay(rust, fn)
        self.assertIsNotNone(sr)
        self.assertEqual(sr[2], "signature")   # sig_param
        self.assertEqual(sr[3], "consumed")    # nonce_field
        self.assertEqual(sr[4], "flag")        # nonce_kind

    def test_detect_rust_signature_replay_counter(self):
        rust = ('pub struct A { pub bal: u64, pub seq: u64 }\n'
                'pub fn ap(a: &mut A, approval: u64, amt: u64) -> Result<(), String> {\n'
                '    a.bal += amt; Ok(())\n}\n')
        fn = M.extract_rust_fn(rust, "ap")
        sr = M._detect_rust_signature_replay(rust, fn)
        self.assertIsNotNone(sr)
        self.assertEqual(sr[4], "counter")

    def test_detect_rust_signature_replay_already_consulted_blocks(self):
        rust = ('pub struct L { pub payout: u64, pub consumed: bool }\n'
                'pub fn auth(l: &mut L, signature: u64, amt: u64) -> Result<(), String> {\n'
                '    if l.consumed { return Err("x".into()); }\n'
                '    l.consumed = true; l.payout += amt; Ok(())\n}\n')
        fn = M.extract_rust_fn(rust, "auth")
        self.assertIsNone(M._detect_rust_signature_replay(rust, fn))

    def test_detect_rust_signature_replay_no_sig_param_blocks(self):
        # a state ref whose name matches sig-vocab must NOT be taken for the sig.
        rust = ('pub struct L { pub payout: u64, pub used: bool }\n'
                'pub fn auth(proof: &mut L, amt: u64) -> Result<(), String> {\n'
                '    proof.payout += amt; Ok(())\n}\n')
        fn = M.extract_rust_fn(rust, "auth")
        self.assertIsNone(M._detect_rust_signature_replay(rust, fn))

    def test_detect_rust_unchecked_call_bool(self):
        rust = ('pub struct D { pub owed: u64 }\n'
                'pub fn s(d: &mut D, amt: u64, remit: impl Fn(u64) -> bool) -> Result<(), String> {\n'
                '    remit(amt); d.owed = 0; Ok(())\n}\n')
        fn = M.extract_rust_fn(rust, "s")
        uc = M._detect_rust_unchecked_call(fn)
        self.assertEqual(uc, ("remit", "bool"))

    def test_detect_rust_unchecked_call_result(self):
        rust = ('pub struct D { pub owed: u64 }\n'
                'pub fn s(d: &mut D, amt: u64, payout: impl Fn(u64) -> Result<(), String>) -> Result<(), String> {\n'
                '    payout(amt); d.owed = 0; Ok(())\n}\n')
        fn = M.extract_rust_fn(rust, "s")
        uc = M._detect_rust_unchecked_call(fn)
        self.assertEqual(uc, ("payout", "result"))

    def test_detect_rust_unchecked_call_already_checked_blocks(self):
        rust = ('pub struct D { pub owed: u64 }\n'
                'pub fn s(d: &mut D, amt: u64, remit: impl Fn(u64) -> bool) -> Result<(), String> {\n'
                '    if !remit(amt) { return Err("x".into()); }\n'
                '    d.owed = 0; Ok(())\n}\n')
        fn = M.extract_rust_fn(rust, "s")
        self.assertIsNone(M._detect_rust_unchecked_call(fn))

    def test_detect_rust_missing_deadline_min(self):
        rust = ('pub struct B { pub filled: u64 }\n'
                'pub fn fl(b: &mut B, received: u64, min_received: u64) -> Result<(), String> {\n'
                '    b.filled += received; Ok(())\n}\n')
        fn = M.extract_rust_fn(rust, "fl")
        md = M._detect_rust_missing_deadline(fn)
        self.assertEqual(md, ("received", "min_received", "min"))

    def test_detect_rust_missing_deadline_max(self):
        rust = ('pub struct E { pub rel: u64 }\n'
                'pub fn rl(e: &mut E, now: u64, valid_until: u64) -> Result<(), String> {\n'
                '    e.rel += 1; Ok(())\n}\n')
        fn = M.extract_rust_fn(rust, "rl")
        md = M._detect_rust_missing_deadline(fn)
        self.assertEqual(md, ("now", "valid_until", "max"))

    def test_detect_rust_missing_deadline_already_compared_blocks(self):
        rust = ('pub struct S { pub done: u64 }\n'
                'pub fn fl(s: &mut S, received: u64, min_out: u64) -> Result<(), String> {\n'
                '    if received < min_out { return Err("x".into()); }\n'
                '    s.done += received; Ok(())\n}\n')
        fn = M.extract_rust_fn(rust, "fl")
        self.assertIsNone(M._detect_rust_missing_deadline(fn))

    def test_rust_param_list_robust_to_unit_result_return(self):
        # regression: a fn returning `Result<(), String>` must not break the param
        # slice (the inner `()` paren previously fooled `rfind(')')`).
        rust = ('pub fn f(a: &mut u64, b: u64) -> Result<(), String> { Ok(()) }')
        fn = M.extract_rust_fn(rust, "f")
        params = M._rust_named_params(fn)
        self.assertEqual([(n, t) for (n, t, _) in params],
                         [("a", "&mut u64"), ("b", "u64")])


@unittest.skipIf(shutil.which("cargo") is None, "cargo not installed")
class TestRustParityRealRun(unittest.TestCase):
    """Rust parity for the three formerly-Go-only guards: each proves on >=1 UNSEEN
    self-contained Rust fixture (distinct symbol names, zero anchor-vocab overlap)
    with a real `cargo test` exploit-FAIL-on-bug + control-PASS-on-fixed transcript."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self, src, fn, vc, name):
        tf = self.tmp / name
        tf.write_text(src)
        return M.convert(tf, fn, vc, "rust", repo_root=REPO_ROOT,
                         out_dir=self.tmp / "out", run=True)

    # --- inline UNSEEN-shape proofs (distinct symbols) ---
    def test_sig_replay_flag_proof_backed(self):
        rust = ('pub struct Ledger { pub holder: u64, pub minted: u64, pub consumed: bool }\n'
                'pub fn mint_against(ledger: &mut Ledger, voucher: u64, qty: u64) -> Result<(), String> {\n'
                '    if qty == 0 { return Err("zero".into()); }\n'
                '    ledger.minted += qty; Ok(())\n}\n')
        r = self._run(rust, "mint_against", "signature-replay", "srf.rs")
        self.assertEqual(r["verdict"], M.PROOF_BACKED, r.get("transcript_tail", ""))
        self.assertTrue(r["parsed"]["exploit_fail"])
        self.assertTrue(r["parsed"]["control_pass"])
        self.assertEqual(r["nonce_field"], "Ledger.consumed")
        self.assertEqual(r["nonce_kind"], "flag")

    def test_sig_replay_counter_proof_backed(self):
        rust = ('pub struct Vault { pub owner: u64, pub paid: u64, pub nonce: u64 }\n'
                'pub fn release_to(vault: &mut Vault, witness: u64, sum: u64) -> Result<(), String> {\n'
                '    if sum == 0 { return Err("zero".into()); }\n'
                '    vault.paid += sum; Ok(())\n}\n')
        r = self._run(rust, "release_to", "missing-nonce", "src.rs")
        self.assertEqual(r["verdict"], M.PROOF_BACKED, r.get("transcript_tail", ""))
        self.assertEqual(r["nonce_kind"], "counter")

    def test_unchecked_call_bool_proof_backed(self):
        rust = ('pub struct Tab { pub debt: u64 }\n'
                'pub fn discharge(tab: &mut Tab, sum: u64, forward: impl Fn(u64) -> bool) -> Result<(), String> {\n'
                '    if sum == 0 { return Err("zero".into()); }\n'
                '    forward(sum); tab.debt = 0; Ok(())\n}\n')
        r = self._run(rust, "discharge", "unchecked-external-call-return", "ucb.rs")
        self.assertEqual(r["verdict"], M.PROOF_BACKED, r.get("transcript_tail", ""))
        self.assertTrue(r["parsed"]["exploit_fail"])
        self.assertTrue(r["parsed"]["control_pass"])
        self.assertEqual(r["result_kind"], "bool")
        self.assertEqual(r["call_param"], "forward")

    def test_unchecked_call_result_proof_backed(self):
        rust = ('pub struct Tab { pub debt: u64 }\n'
                'pub fn discharge(tab: &mut Tab, sum: u64, dispatch: impl Fn(u64) -> Result<(), String>) -> Result<(), String> {\n'
                '    if sum == 0 { return Err("zero".into()); }\n'
                '    dispatch(sum); tab.debt = 0; Ok(())\n}\n')
        r = self._run(rust, "discharge", "unchecked-external-call-return", "ucr.rs")
        self.assertEqual(r["verdict"], M.PROOF_BACKED, r.get("transcript_tail", ""))
        self.assertEqual(r["result_kind"], "result")

    def test_missing_deadline_min_proof_backed(self):
        rust = ('pub struct Trade { pub party: u64, pub done: u64 }\n'
                'pub fn execute(trade: &mut Trade, got: u64, floor: u64) -> Result<(), String> {\n'
                '    if got == 0 { return Err("zero".into()); }\n'
                '    trade.done += got; Ok(())\n}\n')
        r = self._run(rust, "execute", "missing-min-out", "dmn.rs")
        self.assertEqual(r["verdict"], M.PROOF_BACKED, r.get("transcript_tail", ""))
        self.assertEqual(r["bound_polarity"], "min")

    def test_missing_deadline_max_proof_backed(self):
        rust = ('pub struct Lock { pub owner: u64, pub spent: u64 }\n'
                'pub fn unlock(lock: &mut Lock, current_time: u64, expiry: u64) -> Result<(), String> {\n'
                '    if current_time == 0 { return Err("zero".into()); }\n'
                '    lock.spent += 1; Ok(())\n}\n')
        r = self._run(rust, "unlock", "missing-deadline", "dmx.rs")
        self.assertEqual(r["verdict"], M.PROOF_BACKED, r.get("transcript_tail", ""))
        self.assertEqual(r["bound_polarity"], "max")

    # --- on-disk UNSEEN train-fixture proofs (zero anchor-vocab overlap) ---
    def test_train_fixture_sig_replay_flag_proof_backed(self):
        src = (TRAIN / "coupon_settle_sig_replay_unbiased.rs").read_text()
        r = self._run(src, "settle_coupon", "signature-replay", "fsr.rs")
        self.assertEqual(r["verdict"], M.PROOF_BACKED, r.get("transcript_tail", ""))
        self.assertEqual(r["nonce_kind"], "flag")

    def test_train_fixture_sig_replay_counter_proof_backed(self):
        src = (TRAIN / "voucher_grant_counter_nonce_unbiased.rs").read_text()
        r = self._run(src, "disburse_grant", "missing-nonce", "fsc.rs")
        self.assertEqual(r["verdict"], M.PROOF_BACKED, r.get("transcript_tail", ""))
        self.assertEqual(r["nonce_kind"], "counter")

    def test_train_fixture_unchecked_call_proof_backed(self):
        src = (TRAIN / "payroll_remit_unchecked_return_unbiased.rs").read_text()
        r = self._run(src, "pay_wage", "unchecked-external-call-return", "fuc.rs")
        self.assertEqual(r["verdict"], M.PROOF_BACKED, r.get("transcript_tail", ""))

    def test_train_fixture_missing_deadline_min_proof_backed(self):
        src = (TRAIN / "auction_clear_missing_minout_unbiased.rs").read_text()
        r = self._run(src, "clear_lot", "missing-slippage-check", "fdmn.rs")
        self.assertEqual(r["verdict"], M.PROOF_BACKED, r.get("transcript_tail", ""))
        self.assertEqual(r["bound_polarity"], "min")

    def test_train_fixture_missing_deadline_max_proof_backed(self):
        src = (TRAIN / "escrow_release_deadline_max_unbiased.rs").read_text()
        r = self._run(src, "release_escrow", "missing-deadline", "fdmx.rs")
        self.assertEqual(r["verdict"], M.PROOF_BACKED, r.get("transcript_tail", ""))
        self.assertEqual(r["bound_polarity"], "max")


class TestNewGenericFamiliesHonesty(unittest.TestCase):
    """Non-matching / non-self-contained inputs MUST block-with-obligation, never
    fabricate a proof. Rust MUST honestly block (these families are Go-proven)."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self, src, fn, vc, name, lang="go"):
        tf = self.tmp / name
        tf.write_text(src)
        return M.convert(tf, fn, vc, lang, repo_root=REPO_ROOT,
                         out_dir=self.tmp / "out", run=True)

    def test_sig_replay_no_sig_param_blocks(self):
        # double-credit fixture has no signature param -> blocks.
        src = (TRAIN / "double_credit_rebate_unbiased.go").read_text()
        r = self._run(src, "applyRebate", "signature-replay", "ns.go")
        self.assertEqual(r["verdict"], M.BLOCKED)
        self.assertIn("obligation", r["reason"])

    def test_sig_replay_already_guarded_blocks(self):
        guarded = '''package g
type L struct { Payout uint64; Consumed bool }
func authG(l *L, signature uint64, amt uint64) error {
	if l.Consumed { return errC }
	l.Consumed = true
	l.Payout += amt
	return nil
}
type _c struct{}
func (_c) Error() string { return "x" }
var errC error = _c{}
'''
        r = self._run(guarded, "authG", "signature-replay", "ag.go")
        self.assertEqual(r["verdict"], M.BLOCKED)

    def test_unchecked_call_result_already_checked_blocks(self):
        checked = '''package c
type V struct { Debt uint64 }
func clr(v *V, amt uint64, push func(uint64) bool) error {
	if !push(amt) { return errF }
	v.Debt = 0
	return nil
}
type _f struct{}
func (_f) Error() string { return "x" }
var errF error = _f{}
'''
        r = self._run(checked, "clr", "unchecked-external-call-return", "ck.go")
        self.assertEqual(r["verdict"], M.BLOCKED)

    def test_missing_deadline_already_compared_blocks(self):
        compared = '''package m
type S struct { Done uint64 }
func fill(s *S, received uint64, min_out uint64) error {
	if received < min_out { return errB }
	s.Done += received
	return nil
}
type _b struct{}
func (_b) Error() string { return "x" }
var errB error = _b{}
'''
        r = self._run(compared, "fill", "missing-deadline", "cmp.go")
        self.assertEqual(r["verdict"], M.BLOCKED)

    def test_sig_replay_rust_no_nonce_field_blocks_honestly(self):
        # A Rust authorization fn whose state struct carries NO nonce/used field has
        # no mechanical guard to inject -> must block-with-obligation, never fabricate.
        rust = '''pub struct L { pub payout: u64 }
pub fn auth(l: &mut L, signature: u64, amt: u64) -> Result<(), String> {
    l.payout += amt;
    Ok(())
}
'''
        r = self._run(rust, "auth", "signature-replay", "rnn.rs", lang="rust")
        self.assertEqual(r["verdict"], M.BLOCKED)
        self.assertIn("obligation", r["reason"])

    def test_unchecked_call_rust_already_checked_blocks_honestly(self):
        rust = '''pub struct C { pub debt: u64 }
pub fn clr(c: &mut C, amt: u64, push: impl Fn(u64) -> bool) -> Result<(), String> {
    if !push(amt) { return Err("x".into()); }
    c.debt = 0;
    Ok(())
}
'''
        r = self._run(rust, "clr", "unchecked-external-call-return", "ruc.rs", lang="rust")
        self.assertEqual(r["verdict"], M.BLOCKED)
        self.assertIn("obligation", r["reason"])

    def test_missing_deadline_rust_already_compared_blocks_honestly(self):
        rust = '''pub struct S { pub done: u64 }
pub fn fill(s: &mut S, received: u64, min_out: u64) -> Result<(), String> {
    if received < min_out { return Err("x".into()); }
    s.done += received;
    Ok(())
}
'''
        r = self._run(rust, "fill", "missing-deadline", "rdc.rs", lang="rust")
        self.assertEqual(r["verdict"], M.BLOCKED)
        self.assertIn("obligation", r["reason"])


class TestNewGenericFamiliesNoTargetLiteral(unittest.TestCase):
    """No-target-literal discipline: the new family code must NOT hardcode the
    unbiased-fixture symbol names (dispatch is shape-driven, not name-driven)."""

    def test_no_fixture_symbols_in_tool_source(self):
        src = _TOOL.read_text()
        forbidden = ["AuthorizeRedeem", "SettleDisbursement", "ExecuteFill",
                     "grantClaim", "clearVoucher", "routeSwap", "RedeemLedger",
                     "Disbursement", "FillBook", "ClaimTicket",
                     # new Rust-parity fixture symbols (must also stay shape-driven).
                     # (canonical field/param-name vocab like `min_return` /
                     # `valid_until` lives in the recognizer regexes by design and
                     # is NOT a target symbol, so it is intentionally NOT listed.)
                     "settle_coupon", "LoyaltyAccount", "pay_wage", "WageSlip",
                     "clear_lot", "AuctionLot", "disburse_grant", "GrantBook",
                     "release_escrow"]
        for sym in forbidden:
            self.assertNotIn(sym, src,
                             f"tool source hardcodes fixture symbol {sym!r} "
                             "(must be shape-driven, not name-driven)")


class TestTrainFixturesExist(unittest.TestCase):
    def test_go_reentrancy_train_fixture_present(self):
        self.assertTrue(
            (TRAIN / "reentrancy_cei_disburse_unbiased.go").is_file())

    def test_go_valid_flag_train_fixture_present(self):
        self.assertTrue((TRAIN / "valid_flag_quote_unbiased.go").is_file())

    def test_go_double_credit_train_fixture_present(self):
        self.assertTrue((TRAIN / "double_credit_rebate_unbiased.go").is_file())
        self.assertTrue((TRAIN / "double_credit_claim_buggy.go").is_file())

    def test_rust_train_fixture_present(self):
        self.assertTrue((TRAIN / "frost_nonce_reuse_buggy.rs").is_file())

    def test_truncation_train_fixture_present(self):
        self.assertTrue((TRAIN / "amount_downcast_truncation_buggy.rs").is_file())

    def test_access_control_train_fixture_present(self):
        self.assertTrue(
            (TRAIN / "setconfig_missing_owner_guard_buggy.go").is_file())

    def test_go_train_fixture_present(self):
        self.assertTrue((TRAIN / "nonce_reuse_buggy.go").is_file())

    def test_bounds_train_fixture_present(self):
        self.assertTrue((TRAIN / "merkle_unbounded_alloc_buggy.rs").is_file())

    def test_conservation_train_fixture_present(self):
        self.assertTrue(
            (TRAIN / "quicksilver_validate_intents_conservation_buggy.go").is_file())

    def test_staleness_train_fixture_present(self):
        self.assertTrue(
            (TRAIN / "synthetify_calculate_debt_staleness_buggy.rs").is_file())

    def test_sig_replay_train_fixture_present(self):
        self.assertTrue(
            (TRAIN / "permit_authorize_sig_replay_unbiased.go").is_file())

    def test_unchecked_call_train_fixture_present(self):
        self.assertTrue(
            (TRAIN / "settle_remit_unchecked_return_unbiased.go").is_file())

    def test_missing_deadline_train_fixture_present(self):
        self.assertTrue(
            (TRAIN / "fill_order_missing_minout_unbiased.go").is_file())

    def test_rust_parity_train_fixtures_present(self):
        # the 5 UNSEEN Rust fixtures backing the Go->Rust parity for used-nonce-
        # check / call-return-check / deadline-bound-check.
        for f in ("coupon_settle_sig_replay_unbiased.rs",
                  "voucher_grant_counter_nonce_unbiased.rs",
                  "payroll_remit_unchecked_return_unbiased.rs",
                  "auction_clear_missing_minout_unbiased.rs",
                  "escrow_release_deadline_max_unbiased.rs"):
            self.assertTrue((TRAIN / f).is_file(), f)


if __name__ == "__main__":
    unittest.main()
