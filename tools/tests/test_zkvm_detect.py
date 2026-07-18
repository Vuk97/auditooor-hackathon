"""Tests for the zkvm_wave1 generic proof-system detector family + runner."""
import importlib.util
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
FAM = REPO / "detectors" / "zkvm_wave1"


def _load(stem):
    py = FAM / f"{stem}.py"
    spec = importlib.util.spec_from_file_location(f"zkvm_wave1.{stem}", py)
    mod = importlib.util.module_from_spec(spec)
    import sys
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class TestFiatShamir(unittest.TestCase):
    def test_sample_without_observe_fires(self):
        m = _load("zkvm_fiat_shamir_challenge_before_observe")
        src = """
        struct C; impl C {
            fn get_challenge(&mut self) -> F { self.sponge.squeeze() }
        }"""
        self.assertTrue(m.run_text(src, "challenger.rs"))

    def test_observe_then_sample_clean(self):
        m = _load("zkvm_fiat_shamir_challenge_before_observe")
        src = """
        struct C; impl C {
            fn round(&mut self, msg: &[F]) -> F { self.transcript.observe(msg); self.transcript.sample() }
        }"""
        self.assertFalse(m.run_text(src, "challenger.rs"))

    def test_non_fs_file_skipped(self):
        m = _load("zkvm_fiat_shamir_challenge_before_observe")
        self.assertFalse(m.run_text("fn add(a:u32,b:u32)->u32{a+b}", "math.rs"))


class TestFieldCanonical(unittest.TestCase):
    def test_unchecked_no_reduction_fires(self):
        m = _load("zkvm_field_from_raw_no_canonical_reduction")
        src = "use field; fn f(x:u64)->Fp{ Fp::from_canonical_unchecked(x) }"
        self.assertTrue(m.run_text(src, "field.rs"))

    def test_unchecked_with_assert_clean(self):
        m = _load("zkvm_field_from_raw_no_canonical_reduction")
        src = "use field; fn f(x:u64)->Fp{ assert!(x < ORDER_U64); Fp::from_canonical_unchecked(x) }"
        self.assertFalse(m.run_text(src, "field.rs"))


class TestSumcheck(unittest.TestCase):
    def test_verify_without_rejection_fires(self):
        m = _load("zkvm_sumcheck_round_missing_sum_binding")
        src = "// sumcheck\nfn verify_round(&self, claim: F) -> F { let r = self.eval(claim); r }"
        self.assertTrue(m.run_text(src, "sumcheck.rs"))

    def test_verify_with_assert_clean(self):
        m = _load("zkvm_sumcheck_round_missing_sum_binding")
        src = "// sumcheck\nfn verify_round(&self, claim: F) { assert_eq!(self.eval0()+self.eval1(), claim); }"
        self.assertFalse(m.run_text(src, "sumcheck.rs"))


class TestTweakUnused(unittest.TestCase):
    def test_tweak_param_unused_fires(self):
        m = _load("zkvm_tweakable_hash_tweak_unused")
        src = "// tweak\nfn apply(param: &P, tweak: T, msg: &[F]) -> H { hash(param, msg) }"
        self.assertTrue(m.run_text(src, "tweak_hash.rs"))

    def test_tweak_param_used_clean(self):
        m = _load("zkvm_tweakable_hash_tweak_unused")
        src = "// tweak\nfn apply(param: &P, tweak: T, msg: &[F]) -> H { hash(param, tweak, msg) }"
        self.assertFalse(m.run_text(src, "tweak_hash.rs"))


class TestMerkleDomainSep(unittest.TestCase):
    def test_no_domain_sep_fires(self):
        m = _load("zkvm_merkle_leaf_node_no_domain_separation")
        src = "// merkle\nfn hash_leaf(x:&[F])->H{poseidon(x)}\nfn hash_combine(a:&H,b:&H)->H{poseidon2(a,b)}"
        self.assertTrue(m.run_text(src, "tree.rs"))

    def test_with_tweak_clean(self):
        m = _load("zkvm_merkle_leaf_node_no_domain_separation")
        src = "// merkle\nfn hash_leaf(x:&[F])->H{poseidon(LEAF_TWEAK,x)}\nfn hash_combine(a:&H,b:&H)->H{poseidon2(NODE_TWEAK,a,b)}"
        self.assertFalse(m.run_text(src, "tree.rs"))


class TestUnsafeTransmute(unittest.TestCase):
    def test_unsafe_transmute_in_packing_fires(self):
        m = _load("zkvm_unsafe_transmute_in_field_packing")
        src = "fn pack(x:&[F])->P{ unsafe { core::mem::transmute::<_,P>(x) } }"
        self.assertTrue(m.run_text(src, "packing.rs"))

    def test_safe_code_clean(self):
        m = _load("zkvm_unsafe_transmute_in_field_packing")
        self.assertFalse(m.run_text("fn pack(x:&[F])->P{ P::from_slice(x) }", "packing.rs"))


class TestRunner(unittest.TestCase):
    def test_runner_loads_six_detectors(self):
        spec = importlib.util.spec_from_file_location("zkvm_detect", REPO / "tools" / "zkvm-detect.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        dets = mod.load_detectors("zkvm_wave1")
        self.assertEqual(len(dets), 6, f"expected 6 detectors, got {len(dets)}")


if __name__ == "__main__":
    unittest.main()
