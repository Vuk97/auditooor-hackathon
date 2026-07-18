"""F5: Move test code is annotation-based (#[test]/#[test_only]) INSIDE otherwise
production .move files. move_test_line_ranges marks those spans so a coverage/depth
pass skips test oracles without dropping the file's real entry functions.
"""
import sys
import unittest
from pathlib import Path

_LIB = Path(__file__).resolve().parent.parent / "lib"
if str(_LIB) not in sys.path:
    sys.path.insert(0, str(_LIB))
import scope_exclusion as se  # noqa: E402


class TestMoveAnnotation(unittest.TestCase):
    def test_move_test_basenames_oos(self):
        self.assertTrue(se.is_test("sources/escrow_tests.move"))   # plural (new)
        self.assertTrue(se.is_test("sources/escrow_test.move"))    # singular (_test. marker)
        self.assertTrue(se.is_test("sources/escrow.spec.move"))    # .spec. marker

    def test_move_production_kept(self):
        self.assertFalse(se.is_oos("sources/escrow.move"))
        self.assertFalse(se.is_oos("sources/coin/managed_coin.move"))

    def test_move_test_line_ranges(self):
        src = (
            "module a::escrow {\n"
            "    public fun deposit(x: u64): u64 {\n"
            "        x + 1\n"
            "    }\n"
            "\n"
            "    #[test]\n"
            "    fun test_deposit() {\n"
            "        assert!(deposit(1) == 2, 0);\n"
            "    }\n"
            "\n"
            "    #[test_only]\n"
            "    fun helper() {\n"
            "        let _y = 1;\n"
            "    }\n"
            "}\n"
        )
        lines = src.split("\n")
        rng = se.move_test_line_ranges(lines)
        depo = next(i for i, l in enumerate(lines) if "public fun deposit" in l)
        self.assertNotIn(depo, rng, "production deposit() must NOT be in a test span")
        tline = next(i for i, l in enumerate(lines) if "fun test_deposit" in l)
        self.assertIn(tline, rng)
        self.assertIn(tline + 1, rng)  # the assert! body line
        attr = next(i for i, l in enumerate(lines) if l.strip() == "#[test]")
        self.assertIn(attr, rng, "the #[test] attribute line itself is marked")
        helper = next(i for i, l in enumerate(lines) if "fun helper" in l)
        self.assertIn(helper, rng, "#[test_only] helper span is marked too")

    def test_non_move_input_empty(self):
        self.assertEqual(se.move_test_line_ranges(["pragma solidity;", "contract C {}"]), set())


if __name__ == "__main__":
    unittest.main(verbosity=2)
