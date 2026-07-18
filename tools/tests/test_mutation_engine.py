#!/usr/bin/env python3
"""Tests for tools/mutation-engine.py (generic mutation engine, R80/R81).

Zero workspace hardcoding: all behavioral assertions run on inline fixtures.
The one morpho-midnight reference is a SMOKE anchor that is skipped when the
anchor file is absent (so the suite is portable).
"""
import importlib.util
import os
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_TOOL = _HERE.parent / "mutation-engine.py"
_spec = importlib.util.spec_from_file_location("mutation_engine", str(_TOOL))
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)


SOL_FIXTURE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

library Math {
    function mulDivUp(uint256 x, uint256 y, uint256 d) internal pure returns (uint256) {
        return (x * y + (d - 1)) / d;
    }

    function safeAdd(uint256 a, uint256 b) internal pure returns (uint256) {
        require(a + b >= a, "overflow");
        uint256 c = a + b;
        if (c < a) revert("bad");
        return c;
    }
}
"""

RUST_FIXTURE = """pub fn checked_add(a: u128, b: u128) -> u128 {
    assert!(a <= u128::MAX - b);
    let c = a + b;
    if c < a {
        panic!("overflow");
    }
    c
}
"""


class TestSolidityMutations(unittest.TestCase):
    def _gen(self, name, classes):
        mutants, fn, span = mod.generate_mutants(
            SOL_FIXTURE, "solidity", name=name, line_hint=None,
            classes=classes, max_mutants=None)
        return mutants, fn, span

    def test_function_found_by_name(self):
        mutants, fn, span = self._gen("mulDivUp", ["arithmetic"])
        self.assertEqual(fn, "mulDivUp")
        self.assertTrue(span[0] <= span[1])
        self.assertTrue(all(m["operator_class"] == "arithmetic" for m in mutants))

    def test_arithmetic_plus_to_minus(self):
        mutants, _, _ = self._gen("mulDivUp", ["arithmetic"])
        labels = " ".join(m["operator"] for m in mutants)
        self.assertIn("+ -> -", labels)
        self.assertIn("* -> /", labels)
        # Each mutant differs from original on exactly its one line.
        for m in mutants:
            self.assertNotEqual(m["original_line"], m["mutated_line"])

    def test_rounding_muldivup_to_down(self):
        mutants, _, _ = self._gen("mulDivUp", ["rounding"])
        labels = " ".join(m["operator"] for m in mutants)
        self.assertIn("mulDivUp -> mulDivDown", labels)
        # The "+(d-1)" round-up bias drop should also appear.
        self.assertTrue(any("round-up bias" in m["operator"] for m in mutants))

    def test_guard_removal_comments_require(self):
        mutants, _, _ = self._gen("safeAdd", ["guard_removal"])
        self.assertTrue(mutants, "guard removal should produce >=1 mutant")
        joined = "\n".join(m["mutated_line"] for m in mutants)
        self.assertIn("MUTANT-GUARD-REMOVED", joined)
        # The require line is removed in at least one mutant.
        self.assertTrue(any("require" in m["original_line"] for m in mutants))

    def test_relational_flips(self):
        mutants, _, _ = self._gen("safeAdd", ["relational"])
        labels = " ".join(m["operator"] for m in mutants)
        self.assertIn(">=", labels)

    def test_single_mutation_per_mutant(self):
        # Each mutant changes exactly one source line vs the original.
        mutants, _, _ = self._gen("safeAdd", mod.ALL_CLASSES)
        orig_lines = SOL_FIXTURE.splitlines()
        for m in mutants:
            mutated = m["_mutated_source"].splitlines()
            diff = [i for i in range(min(len(orig_lines), len(mutated)))
                    if orig_lines[i] != mutated[i]]
            self.assertEqual(len(diff), 1,
                             f"mutant {m['mutant_id']} changed {len(diff)} lines")

    def test_max_cap(self):
        mutants, _, _ = self._gen("safeAdd", mod.ALL_CLASSES)
        capped, _, _ = mod.generate_mutants(
            SOL_FIXTURE, "solidity", name="safeAdd", line_hint=None,
            classes=mod.ALL_CLASSES, max_mutants=2)
        self.assertLessEqual(len(capped), 2)
        self.assertTrue(len(mutants) >= len(capped))

    def test_function_not_found_raises(self):
        with self.assertRaises(LookupError):
            mod.generate_mutants(SOL_FIXTURE, "solidity", name="nope",
                                 line_hint=None, classes=["arithmetic"],
                                 max_mutants=None)

    def test_line_hint_resolves_to_function(self):
        # Line 6 is inside mulDivUp body.
        mutants, fn, _ = mod.generate_mutants(
            SOL_FIXTURE, "solidity", name=None, line_hint=6,
            classes=["arithmetic"], max_mutants=None)
        self.assertEqual(fn, "mulDivUp")


class TestRustMutations(unittest.TestCase):
    def test_rust_guard_and_arithmetic(self):
        mutants, fn, _ = mod.generate_mutants(
            RUST_FIXTURE, "rust", name="checked_add", line_hint=None,
            classes=["guard_removal", "arithmetic"], max_mutants=None)
        self.assertEqual(fn, "checked_add")
        joined = "\n".join(m["mutated_line"] for m in mutants)
        self.assertIn("MUTANT-GUARD-REMOVED", joined)  # assert! removed
        self.assertTrue(any(m["operator_class"] == "arithmetic" for m in mutants))


class TestEnvExtension(unittest.TestCase):
    def test_env_adds_operator(self):
        os.environ["AUDITOOOR_MUTATION_OPS_SOLIDITY"] = (
            "rounding|\\bWAD\\b|WAD_MINUS_ONE|rounding: WAD scale tweak")
        try:
            mutants, _, _ = mod.generate_mutants(
                "function f() public { uint256 z = WAD; }",
                "solidity", name="f", line_hint=None,
                classes=["rounding"], max_mutants=None)
            self.assertTrue(any("WAD scale tweak" in m["operator"] for m in mutants))
        finally:
            del os.environ["AUDITOOOR_MUTATION_OPS_SOLIDITY"]


class TestMorphoSmokeAnchor(unittest.TestCase):
    """Smoke anchor on the real morpho-midnight UtilsLib (skipped if absent)."""
    ANCHOR = Path("/Users/wolf/audits/morpho-midnight/poc-tests/"
                  "UtilsLib-engine-harness/src/UtilsLib.sol")

    def test_muldivup_mutants_on_real_contract(self):
        if not self.ANCHOR.is_file():
            self.skipTest("morpho-midnight anchor not present")
        source = self.ANCHOR.read_text(encoding="utf-8")
        mutants, fn, _ = mod.generate_mutants(
            source, "solidity", name="mulDivUp", line_hint=None,
            classes=mod.ALL_CLASSES, max_mutants=None)
        self.assertEqual(fn, "mulDivUp")
        self.assertTrue(mutants, "real UtilsLib.mulDivUp should be mutatable")
        labels = " ".join(m["operator"] for m in mutants)
        # The round-up function should yield a rounding mutant flipping the bias.
        self.assertIn("mulDivUp -> mulDivDown", labels)


_VALUE_FIXTURE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Hook {
    uint256 public fee;
    address public beneficiary;
    function collect() external {
        payable(beneficiary).sendValue(address(this).balance);
    }
    function quote() external view returns (uint256) {
        return fee;
    }
    function owner() external view returns (address) {
        return beneficiary;
    }
}
"""


class TestValueMutationOperator(unittest.TestCase):
    """value_mutation: single-statement economic functions (balance sweeps, fee
    getters) get a behaviour-changing mutant the relational/arithmetic operators
    miss. Numeric-return zeroing is GUARDED to numeric returns so a mutant always
    compiles (no false compile-fail kill)."""

    def _gen(self, name):
        mutants, fn, _ = mod.generate_mutants(
            _VALUE_FIXTURE, "solidity", name=name, line_hint=None,
            classes=["value_mutation"], max_mutants=None)
        return mutants

    def test_value_send_halved(self):
        muts = self._gen("collect")
        labels = " ".join(m["operator"] for m in muts)
        self.assertIn("halve value-send amount", labels)
        self.assertTrue(any("/ 2)" in m["mutated_line"] for m in muts))

    def test_numeric_return_zeroed(self):
        muts = self._gen("quote")
        self.assertTrue(any(m["mutated_line"].strip() == "return 0;" for m in muts),
                        [m["mutated_line"] for m in muts])

    def test_non_numeric_return_not_zeroed(self):
        # `owner()` returns address - must NOT be zeroed (would compile-fail =>
        # false kill). The guard restricts return-zeroing to numeric returns.
        muts = self._gen("owner")
        self.assertFalse(any(m["mutated_line"].strip() == "return 0;" for m in muts),
                         "non-numeric return must not be zeroed")


if __name__ == "__main__":
    unittest.main()
