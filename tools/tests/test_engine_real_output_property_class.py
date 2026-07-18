#!/usr/bin/env python3
"""Guard tests for the wave-4 engine-real-output-property-class uplift.

Root cause fixed: the generic engine-harness authors asserted determinism /
soundness / bounds over a hand-authored MODEL (`// MODEL ->` transform, mutate*
seam) instead of over the REAL fn return value. Only EVM's hard-coded TickLib
special case asserted over real output. This uplift generalises a language-
agnostic REAL-OUTPUT property class (determinism f(x)==f(x)) over the actual fn
output and adds a `real_output_bound` honesty flag so audit-honesty-check and
mutation-verify-coverage credit ONLY real-output-bound harnesses as genuine.

Per arm the load-bearing guard is: the authored determinism harness binds the
REAL call, and a MUTATION of the real fn FLIPS the assert (proving the property
is bound to the real output, not a model). Rust exercises this end-to-end with
the real cargo toolchain (skip if cargo is missing). Go/EVM assert the rendered
body references the real call twice + the manifest real_output_bound flag, and
the cross-cutting honesty flag wiring is exercised against synthetic manifests.

R80/R76: every "real_output_bound" claim here is proven by either a real
toolchain mutation-flip (rust) or by the assert text referencing the real call.
"""
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parents[1]


def _load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, _TOOLS / filename)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod  # py3.14 dataclass string-annotation needs this
    spec.loader.exec_module(mod)
    return mod


RHA = _load("rha_w4", "rust-engine-harness-author.py")
GHA = _load("gha_w4", "go-engine-harness-author.py")
EHA = _load("eha_w4", "evm-engine-harness-author.py")
HC = _load("hc_w4", "audit-honesty-check.py")
MV = _load("mv_w4", "mutation-verify-coverage.py")


# ---------------------------------------------------------------------------
# RUST arm
# ---------------------------------------------------------------------------
class TestRustRealOutputBound(unittest.TestCase):
    def test_coercible_determinism_asserts_over_real_call_no_model(self):
        fn = {"function_name": "decode", "params": [{"type": "&[u8]"}],
              "file_path": "src/lib.rs", "line_start": 1}
        inv = {"invariant_id": "INV-BND-1", "category": "bounds", "statement": "x"}
        self.assertTrue(RHA.predicate_is_real_output_bound(inv, fn))
        body = "\n".join(RHA._predicate_lines("decode", inv, fn))
        # Real call bound twice; synthetic MODEL transform deleted.
        self.assertIn("let out_a = decode(", body)
        self.assertIn("let out_b = decode(", body)
        self.assertNotIn("fn transform(", body)
        self.assertIn("assert_eq!(out_a, out_b", body)

    def test_struct_param_falls_back_to_model_seam(self):
        fn = {"function_name": "process", "params": [{"type": "MyStruct"}],
              "file_path": "src/lib.rs", "line_start": 2}
        inv = {"invariant_id": "INV-DET-1", "category": "determinism", "statement": "x"}
        self.assertFalse(RHA.predicate_is_real_output_bound(inv, fn))
        body = "\n".join(RHA._predicate_lines("process", inv, fn))
        # Non-coercible struct param keeps the MODEL+seam scaffold (needs-binding).
        self.assertIn("fn transform(", body)

    def test_protocol_semantic_category_stays_model_seam(self):
        fn = {"function_name": "transfer", "params": [{"type": "u64"}],
              "file_path": "src/lib.rs", "line_start": 3}
        inv = {"invariant_id": "INV-CONS-1", "category": "conservation", "statement": "x"}
        self.assertFalse(RHA.predicate_is_real_output_bound(inv, fn))

    @unittest.skipUnless(shutil.which("cargo"), "cargo not on PATH")
    def test_real_fn_mutation_flips_the_determinism_assert(self):
        """End-to-end: the authored determinism proptest PASSES against a real
        deterministic fn, and FAILS once the real fn is mutated to be
        non-deterministic. This proves the assert is bound to the REAL output."""
        with tempfile.TemporaryDirectory() as d:
            crate = Path(d) / "demo"
            (crate / "src").mkdir(parents=True)
            (crate / "Cargo.toml").write_text(
                '[package]\nname="demo"\nversion="0.1.0"\nedition="2021"\n'
                '[dev-dependencies]\nproptest="1"\n')
            real_src = "pub fn decode(input: u64) -> u64 { input.rotate_left(7) ^ 0x9E37 }\n"
            (crate / "src" / "lib.rs").write_text(real_src)

            fn = {"function_name": "decode", "params": [{"type": "u64"}],
                  "file_path": "src/lib.rs", "line_start": 1}
            inv = {"invariant_id": "INV-DET-1", "category": "determinism", "statement": "x"}
            self.assertTrue(RHA.predicate_is_real_output_bound(inv, fn))
            harness = RHA.render_proptest_target(fn, inv)
            # Wrap so the harness can see the crate's `decode`.
            test_file = crate / "tests" / "realout.rs"
            test_file.parent.mkdir(parents=True)
            test_file.write_text(
                "#![allow(unused, clippy::all)]\n"
                "use demo::decode;\n"
                "#[cfg(test)]\n"
                "mod m {\n"
                "    use super::*;\n"
                "    use proptest::prelude::*;\n"
                f"{harness}"
                "}\n"
            )
            env = {"PROPTEST_CASES": "16"}
            import os
            run_env = {**os.environ, **env}
            ok = subprocess.run(["cargo", "test", "--test", "realout"],
                                cwd=crate, capture_output=True, text=True, env=run_env)
            self.assertEqual(ok.returncode, 0,
                             f"real fn should PASS determinism:\n{ok.stdout}\n{ok.stderr}")

            # Mutate the REAL fn to be non-deterministic (state counter) -> assert flips.
            (crate / "src" / "lib.rs").write_text(
                "use std::sync::atomic::{AtomicU64, Ordering};\n"
                "static C: AtomicU64 = AtomicU64::new(0);\n"
                "pub fn decode(input: u64) -> u64 { input.wrapping_add(C.fetch_add(1, Ordering::SeqCst)) }\n"
            )
            bad = subprocess.run(["cargo", "test", "--test", "realout"],
                                 cwd=crate, capture_output=True, text=True, env=run_env)
            self.assertNotEqual(bad.returncode, 0,
                                "mutated non-deterministic fn must FLIP the assert "
                                f"(real-output bound):\n{bad.stdout}\n{bad.stderr}")


# ---------------------------------------------------------------------------
# GO arm
# ---------------------------------------------------------------------------
class TestGoRealOutputBound(unittest.TestCase):
    def test_value_returning_fn_admitted_for_determinism(self):
        fn = {"function_name": "Parse", "params": [{"type": "[]byte"}],
              "return_types": ["uint64", "error"], "receiver_type": "",
              "file_path": "a.go", "line_start": 1}
        self.assertTrue(GHA.is_pure_shaped(fn))
        nm, body = GHA.render_determinism(
            fn, {"invariant_id": "INV-DET-1", "category": "determinism", "statement": "x"})
        # Asserts DeepEqual over the REAL fn's captured returns, calling it twice.
        self.assertIn("reflect.DeepEqual(rA0, rB0)", body)
        self.assertGreaterEqual(body.count("Parse("), 2)

    def test_error_only_return_not_admitted(self):
        fn = {"function_name": "Validate", "params": [{"type": "[]byte"}],
              "return_types": ["error"], "receiver_type": "", "file_path": "a.go",
              "line_start": 2}
        self.assertFalse(GHA.is_pure_shaped(fn),
                         "error-only fn has no value to compare -> not real-output")

    def test_method_stays_nopanic_only(self):
        fn = {"function_name": "Do", "params": [{"type": "[]byte"}],
              "return_types": ["uint64"], "receiver_type": "*T", "file_path": "a.go",
              "line_start": 3}
        self.assertFalse(GHA.is_pure_shaped(fn))

    @unittest.skipUnless(shutil.which("go"), "go not on PATH")
    def test_real_fn_mutation_flips_the_determinism_assert(self):
        """The authored Go determinism fuzz target PASSES against a deterministic
        real fn and FAILS once the real fn is mutated non-deterministic."""
        with tempfile.TemporaryDirectory() as d:
            pkg = Path(d)
            (pkg / "go.mod").write_text("module demo\n\ngo 1.21\n")
            (pkg / "lib.go").write_text(
                "package demo\n\n"
                "func Parse(in []byte) uint64 {\n"
                "    var s uint64\n"
                "    for _, b := range in { s = s*31 + uint64(b) }\n"
                "    return s\n"
                "}\n")
            fn = {"function_name": "Parse", "params": [{"type": "[]byte"}],
                  "return_types": ["uint64"], "receiver_type": "",
                  "file_path": "lib.go", "line_start": 1}
            nm, body = GHA.render_determinism(
                fn, {"invariant_id": "INV-DET-1", "category": "determinism", "statement": "x"})
            (pkg / "realout_test.go").write_text(
                "package demo\n\nimport (\n\t\"reflect\"\n\t\"testing\"\n)\n\n"
                "var _ = reflect.DeepEqual\n\n" + body)
            ok = subprocess.run(
                ["go", "test", "-run", nm, "-fuzz", nm, "-fuzztime", "2s", "."],
                cwd=pkg, capture_output=True, text=True)
            self.assertEqual(ok.returncode, 0,
                             f"deterministic fn should PASS:\n{ok.stdout}\n{ok.stderr}")
            # Mutate the real fn to be non-deterministic.
            (pkg / "lib.go").write_text(
                "package demo\n\n"
                "import \"sync/atomic\"\n\n"
                "var c uint64\n\n"
                "func Parse(in []byte) uint64 {\n"
                "    return uint64(len(in)) + atomic.AddUint64(&c, 1)\n"
                "}\n")
            bad = subprocess.run(
                ["go", "test", "-run", nm, "-fuzz", nm, "-fuzztime", "2s", "."],
                cwd=pkg, capture_output=True, text=True)
            self.assertNotEqual(bad.returncode, 0,
                                "non-deterministic fn must FLIP the real-output assert:\n"
                                f"{bad.stdout}\n{bad.stderr}")


# ---------------------------------------------------------------------------
# EVM arm
# ---------------------------------------------------------------------------
class TestEvmRealOutputBound(unittest.TestCase):
    def _surf(self, src: str):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "C.sol"
            p.write_text(src)
            return EHA.parse_contract(p, None)

    def test_zero_arg_comparable_view_fns_picked(self):
        surf = self._surf(
            "pragma solidity ^0.8.0;\n"
            "contract Vault {\n"
            "  function previewRedeem() external view returns (uint256) { return 0; }\n"
            "  function owner() public view returns (address) { return address(0); }\n"
            "  function balances(address a) external view returns (uint256) { return 0; }\n"
            "  function name() external pure returns (string memory) { return \"x\"; }\n"
            "  function deposit(uint256 a) external {}\n"
            "}\n")
        names = [f.name for f in EHA.realout_view_fns(surf)]
        self.assertIn("previewRedeem", names)
        self.assertIn("owner", names)
        self.assertNotIn("balances", names, "param'd view fn excluded (arg synthesis risk)")
        self.assertNotIn("name", names, "string return excluded (not comparable)")
        self.assertNotIn("deposit", names, "mutating fn excluded")

    def test_determinism_property_asserts_over_real_target_call(self):
        surf = self._surf(
            "pragma solidity ^0.8.0;\n"
            "contract Vault {\n"
            "  function previewRedeem() external view returns (uint256) { return 0; }\n"
            "}\n")
        block = EHA._realout_determinism_props(surf, style="assert")
        self.assertIn("target.previewRedeem() == target.previewRedeem()", block)
        # The interface must declare the real getter so the call compiles.
        iface = EHA._render_target_interface(surf)
        self.assertIn("function previewRedeem() external view returns (uint256);", iface)

    def test_no_view_fns_means_no_real_output_block(self):
        surf = self._surf(
            "pragma solidity ^0.8.0;\n"
            "contract Vault { function deposit(uint256 a) external {} }\n")
        self.assertEqual(EHA._realout_determinism_props(surf, style="assert"), "")
        self.assertEqual(EHA.realout_view_fns(surf), [])


# ---------------------------------------------------------------------------
# CROSS-CUTTING: real_output_bound honesty flag wiring
# ---------------------------------------------------------------------------
class TestRealOutputBoundWiring(unittest.TestCase):
    def _ws_with_manifests(self, d: Path):
        rm = d / "poc-tests" / "crate" / "tests" / "auditooor_harnesses"
        rm.mkdir(parents=True)
        (rm / "harness_manifest.json").write_text(json.dumps({"authored": [
            {"harness_file": "tests/auditooor_decode__lib.rs", "real_output_bound": True},
            {"harness_file": "tests/auditooor_process__lib.rs", "real_output_bound": False},
        ]}))
        em = d / "poc-tests" / "Vault-engine-harness"
        em.mkdir(parents=True)
        (em / "attempt_manifest.json").write_text(json.dumps({"real_output_bound": True}))

    def test_honesty_split_counts_only_real_output_as_genuine(self):
        with tempfile.TemporaryDirectory() as dd:
            d = Path(dd)
            self._ws_with_manifests(d)
            split = HC._authored_real_output_bound_split(d)
            self.assertEqual(split["genuine"], 2)       # 1 rust + 1 evm
            self.assertEqual(split["needs_binding"], 1)  # the model+seam rust entry
            self.assertEqual(split["manifests"], 2)

    def test_mutation_verify_lookup_classifies_each_harness(self):
        with tempfile.TemporaryDirectory() as dd:
            d = Path(dd)
            self._ws_with_manifests(d)
            real = d / "poc-tests" / "crate" / "tests" / "auditooor_decode__lib.rs"
            model = d / "poc-tests" / "crate" / "tests" / "auditooor_process__lib.rs"
            evm = d / "poc-tests" / "Vault-engine-harness" / "test" / "Vault_FuzzProps.sol"
            unknown = d / "somewhere" / "hand_written.sol"
            self.assertIs(MV._harness_real_output_bound(real), True)
            self.assertIs(MV._harness_real_output_bound(model), False)
            self.assertIs(MV._harness_real_output_bound(evm), True)
            self.assertIsNone(MV._harness_real_output_bound(unknown))


if __name__ == "__main__":
    unittest.main()
