#!/usr/bin/env python3
"""Non-vacuous tests for GEN-A3 ephemeral-store reset-conservation screen.

Every positive case has a paired negative (the SAME code WITH the dominating
reset / matching tier) that must NOT fire - proving the reset-dominance and
tier-fidelity predicates are load-bearing, not a shape match. Includes the
real-fleet mutation witness on lido CircuitBreaker.nonReentrant (bounded original
silent, reset-removed / early-return-inserted copy fires).
"""
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent
TOOL = TOOLS / "ephemeral-reset-conservation-screen.py"

_spec = importlib.util.spec_from_file_location("rc_screen", TOOL)
rc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rc)


def _scan(text, name):
    return rc.scan_file(Path(name), name, file_text=text)


def _kinds(rows):
    return {r["pattern_id"] for r in rows}


class ReentrancyResetMissingTests(unittest.TestCase):
    def test_guard_never_reset_fires(self):
        src = """
        contract C {
            bool locked;
            function pull() external {
                require(!locked, "reent");
                locked = true;
                _payout();
            }
        }
        """
        rows = _scan(src, "C.sol")
        self.assertIn("S_GUARD_RESET_MISSING", _kinds(rows))
        r = [x for x in rows if x["pattern_id"] == "S_GUARD_RESET_MISSING"][0]
        self.assertEqual(r["defect"], "reset-not-dominating-exit")
        self.assertEqual(r["store_kind"], "reentrancy-flag")
        self.assertEqual(r["store_var"], "locked")

    def test_guard_reset_present_silent(self):
        # SAME guard WITH the reset - must NOT fire.
        src = """
        contract C {
            bool locked;
            function pull() external {
                require(!locked, "reent");
                locked = true;
                _payout();
                locked = false;
            }
        }
        """
        rows = _scan(src, "C.sol")
        self.assertNotIn("S_GUARD_RESET_MISSING", _kinds(rows))

    def test_oz_split_helper_silent(self):
        # OZ-style: set in _before(), reset in _after() - reset exists in file.
        src = """
        contract C {
            uint256 private _status;
            uint256 private constant _NOT_ENTERED = 1;
            uint256 private constant _ENTERED = 2;
            function _nonReentrantBefore() private {
                _status = _ENTERED;
            }
            function _nonReentrantAfter() private {
                _status = _NOT_ENTERED;
            }
        }
        """
        rows = _scan(src, "C.sol")
        self.assertNotIn("S_GUARD_RESET_MISSING", _kinds(rows))

    def test_non_guard_bool_silent(self):
        # a non-guard bool set once and never reset (initialized/paused) is not
        # this class - name heuristic must exclude it.
        src = """
        contract C {
            bool initialized;
            bool paused;
            function init() external { initialized = true; }
            function pause() external { paused = true; }
        }
        """
        rows = _scan(src, "C.sol")
        self.assertEqual(rows, [])

    def test_delete_counts_as_reset_silent(self):
        src = """
        contract C {
            bool locked;
            function f() external {
                locked = true;
                _work();
                delete locked;
            }
        }
        """
        rows = _scan(src, "C.sol")
        self.assertNotIn("S_GUARD_RESET_MISSING", _kinds(rows))


class ReentrancyEarlyReturnTests(unittest.TestCase):
    def test_early_return_between_set_and_reset_fires(self):
        src = """
        contract C {
            bool locked;
            function pull(bool skip) external {
                locked = true;
                if (skip) return;
                _payout();
                locked = false;
            }
        }
        """
        rows = _scan(src, "C.sol")
        self.assertIn("S_GUARD_EARLY_RETURN", _kinds(rows))
        r = [x for x in rows if x["pattern_id"] == "S_GUARD_EARLY_RETURN"][0]
        self.assertEqual(r["defect"], "reset-not-dominating-exit")

    def test_early_return_after_reset_silent(self):
        # SAME early-return but the reset dominates it - must NOT fire.
        src = """
        contract C {
            bool locked;
            function pull(bool skip) external {
                locked = true;
                if (skip) { locked = false; return; }
                _payout();
                locked = false;
            }
        }
        """
        rows = _scan(src, "C.sol")
        self.assertNotIn("S_GUARD_EARLY_RETURN", _kinds(rows))


class TransientTierTests(unittest.TestCase):
    def test_tstore_no_reset_fires(self):
        src = """
        contract C {
            function enter() external {
                assembly { tstore(0, 1) }
                _work();
            }
        }
        """
        rows = _scan(src, "C.sol")
        self.assertIn("S_TSTORE_RESET_MISSING", _kinds(rows))
        r = [x for x in rows if x["pattern_id"] == "S_TSTORE_RESET_MISSING"][0]
        self.assertEqual(r["store_kind"], "transient")

    def test_tstore_with_reset_silent(self):
        src = """
        contract C {
            function enter() external {
                assembly { tstore(0, 1) }
                _work();
                assembly { tstore(0, 0) }
            }
        }
        """
        rows = _scan(src, "C.sol")
        self.assertNotIn("S_TSTORE_RESET_MISSING", _kinds(rows))

    def test_tier_mismatch_fires(self):
        # set transient, reset persistent on the SAME slot -> poison.
        src = """
        contract C {
            function enter() external {
                assembly { tstore(0x1, 1) }
                _work();
                assembly { sstore(0x1, 0) }
            }
        }
        """
        rows = _scan(src, "C.sol")
        self.assertIn("S_TIER_MISMATCH", _kinds(rows))
        r = [x for x in rows if x["pattern_id"] == "S_TIER_MISMATCH"][0]
        self.assertEqual(r["defect"], "tier-mismatch-set-vs-reset")

    def test_same_tier_reset_silent(self):
        # both writes are tstore (matched tier) -> not a mismatch.
        src = """
        contract C {
            function enter() external {
                assembly { tstore(0x1, 1) }
                assembly { tstore(0x1, 0) }
            }
        }
        """
        rows = _scan(src, "C.sol")
        self.assertNotIn("S_TIER_MISMATCH", _kinds(rows))


class GoCacheTests(unittest.TestCase):
    def test_go_cache_early_return_fires(self):
        src = """
        package p
        func (s *S) handle(x int) error {
            s.cache = x
            if x < 0 {
                return errors.New("bad")
            }
            s.cache = 0
            return nil
        }
        """
        rows = _scan(src, "h.go")
        self.assertIn("G_CACHE_EARLY_RETURN", _kinds(rows))

    def test_go_defer_reset_silent(self):
        # a defered reset dominates every exit -> must NOT fire.
        src = """
        package p
        func (s *S) handle(x int) error {
            s.cache = x
            defer func() { s.cache = 0 }()
            if x < 0 {
                return errors.New("bad")
            }
            return nil
        }
        """
        rows = _scan(src, "h.go")
        self.assertNotIn("G_CACHE_EARLY_RETURN", _kinds(rows))


class ExclusionTests(unittest.TestCase):
    def test_codegen_marker_excluded(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "src"
            root.mkdir()
            gen = root / "x.pb.go"
            gen.write_text(
                "// Code generated by protoc. DO NOT EDIT.\n"
                "package p\n"
                "func (s *S) h(x int) error {\n"
                "  s.cache = x\n"
                "  if x<0 { return nil }\n"
                "  s.cache = 0\n"
                "  return nil\n}\n")
            rows = rc.scan_tree(root, workspace=Path(td))
            self.assertEqual(rows, [])


class MutationWitnessTests(unittest.TestCase):
    """Real-fleet non-vacuity witness on lido CircuitBreaker.nonReentrant.

    Original inline modifier resets `lock = false` after `_` (reset dominates the
    single exit) -> silent. Two weakenings (remove the reset; insert an early
    return between set and reset) must newly fire. Restored byte-identical.
    """

    CB = Path("/Users/wolf/audits/lido/src/circuit-breaker/src/CircuitBreaker.sol")

    def test_real_bounded_original_silent(self):
        if not self.CB.exists():
            self.skipTest("lido CircuitBreaker.sol not present")
        orig = self.CB.read_text()
        rows0 = rc.scan_file(self.CB, self.CB.name, file_text=orig)
        self.assertNotIn("S_GUARD_RESET_MISSING", _kinds(rows0))
        self.assertNotIn("S_GUARD_EARLY_RETURN", _kinds(rows0))

    def test_reset_removed_weakening_fires(self):
        if not self.CB.exists():
            self.skipTest("lido CircuitBreaker.sol not present")
        orig = self.CB.read_text()
        weak_lines = [l for l in orig.split("\n")
                      if l.strip() != "lock = false;"]
        weak = "\n".join(weak_lines)
        self.assertNotEqual(weak, orig, "mutation did not change source")
        rows1 = rc.scan_file(self.CB, self.CB.name, file_text=weak)
        self.assertIn("S_GUARD_RESET_MISSING", _kinds(rows1))
        # restore invariant: original file untouched on disk
        self.assertEqual(self.CB.read_text(), orig)

    def test_early_return_weakening_fires(self):
        if not self.CB.exists():
            self.skipTest("lido CircuitBreaker.sol not present")
        orig = self.CB.read_text()
        # insert an early return between `lock = true;` and the trailing reset
        weak = orig.replace("lock = true;\n", "lock = true;\n        return;\n", 1)
        self.assertNotEqual(weak, orig, "mutation did not change source")
        rows1 = rc.scan_file(self.CB, self.CB.name, file_text=weak)
        self.assertIn("S_GUARD_EARLY_RETURN", _kinds(rows1))
        self.assertEqual(self.CB.read_text(), orig)


class CliTests(unittest.TestCase):
    def test_cli_source_mode_and_exit0(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "src"
            src.mkdir()
            (src / "a.sol").write_text(
                "contract C {\n"
                "    bool locked;\n"
                "    function pull() external {\n"
                "        require(!locked);\n"
                "        locked = true;\n"
                "        _pay();\n"
                "    }\n"
                "}\n")
            r = subprocess.run(
                [sys.executable, str(TOOL), "--workspace", td],
                capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            summ = json.loads(r.stdout)
            self.assertEqual(summ["schema"], rc.HYP_SCHEMA)
            self.assertGreaterEqual(summ["fired"], 1)
            side = (Path(td) / ".auditooor" /
                    "reset_conservation_hypotheses.jsonl")
            self.assertTrue(side.exists())

    def test_cli_strict_exit1_on_fire(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "src"
            src.mkdir()
            (src / "a.sol").write_text(
                "contract C {\n"
                "    bool locked;\n"
                "    function pull() external {\n"
                "        locked = true;\n"
                "        _pay();\n"
                "    }\n"
                "}\n")
            r = subprocess.run(
                [sys.executable, str(TOOL), "--workspace", td, "--strict"],
                capture_output=True, text=True)
            self.assertEqual(r.returncode, 1)


if __name__ == "__main__":
    unittest.main()
