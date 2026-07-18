"""F5: Cairo/zk (cairo/circom/noir) source is enumerable and language-resolved;
circuit test files + codegen artifacts are OOS; a real Nargo/Scarb package source
file is NOT dropped by a build-looking parent.
"""
import sys
import unittest
from pathlib import Path

_LIB = Path(__file__).resolve().parent.parent / "lib"
if str(_LIB) not in sys.path:
    sys.path.insert(0, str(_LIB))
import scope_exclusion as se  # noqa: E402


class TestZkNargoGuard(unittest.TestCase):
    def test_circuit_production_source_kept(self):
        for p in ("circuits/poseidon.circom", "src/lib.cairo", "src/main.nr",
                  "crates/my_circuit/src/main.nr"):
            self.assertFalse(se.is_oos(p), f"in-scope circuit source dropped: {p}")

    def test_circuit_ext_lang_resolved(self):
        # mapping .cairo/.circom/.nr stops the unknown-language ambiguity WARN path.
        self.assertEqual(se._lang_of("/circuits/poseidon.circom"), "circom")
        self.assertEqual(se._lang_of("/src/lib.cairo"), "cairo")
        self.assertEqual(se._lang_of("/src/main.nr"), "noir")

    def test_circuit_test_files_oos(self):
        for p in ("circuits/poseidon.test.circom", "tests/poseidon_test.cairo",
                  "circuits/test/foo.circom"):
            self.assertTrue(se.is_oos(p), f"circuit test file should be OOS: {p}")

    def test_codegen_artifacts_excluded(self):
        # snarkjs *_js/ + build artifacts are not auditable source
        self.assertTrue(se.is_oos("build/circuit_js/witness_calculator.js"))
        self.assertTrue(se.is_oos("target/debug/circuit.json"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
