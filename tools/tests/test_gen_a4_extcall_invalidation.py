#!/usr/bin/env python3
"""Non-vacuous tests for GEN-A4 external-call boundary state-invalidation screen.

Every positive case has a paired negative (the SAME code that RE-READS state after
the boundary, or a deliberate before-snapshot) that must NOT fire - proving the
temporal cache-then-stale predicate is load-bearing, not a shape match. Includes
the real-fleet mutation witness on etherfi Liquifier.depositWithERC20 (the benign
re-read of balanceOf AFTER safeTransferFrom stays silent; a variant that caches the
post-balance BEFORE the transfer and trusts the stale local newly fires). The
witness is the DISTINCTNESS proof vs the reentrancy/CEI lane: depositWithERC20 is
`nonReentrant`, so CRC / CMSR / interproc-CEI are silent by construction, yet the
stale-local variant is a real defect (the token mutates its own balance during
transfer - a non-reentrant, different-actor mutation).
"""
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent
TOOL = TOOLS / "extcall-boundary-invalidation-screen.py"

_spec = importlib.util.spec_from_file_location("a4_screen", TOOL)
a4 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(a4)


def _scan(text, name):
    return a4.scan_file(Path(name), name, file_text=text)


def _kinds(rows):
    return {r["pattern_id"] for r in rows}


class SolidityStaleLocalTests(unittest.TestCase):
    def test_cached_balance_used_after_transfer_fires(self):
        src = """
        contract C {
            function f(address t) external {
                uint256 bal = IERC20(t).balanceOf(address(this));
                IERC20(t).transferFrom(msg.sender, address(this), 1);
                doSomething(bal);
            }
        }
        """
        rows = _scan(src, "C.sol")
        self.assertIn("S_STALE_LOCAL_AFTER_EXTCALL", _kinds(rows))
        r = [x for x in rows if x["pattern_id"] == "S_STALE_LOCAL_AFTER_EXTCALL"][0]
        self.assertEqual(r["defect"], "stale-local-after-extcall")
        self.assertEqual(r["cached_value"], "bal")

    def test_reread_after_transfer_silent(self):
        # SAME shape but the local is RE-READ after the boundary -> benign.
        src = """
        contract C {
            function f(address t) external {
                uint256 bal = IERC20(t).balanceOf(address(this));
                IERC20(t).transferFrom(msg.sender, address(this), 1);
                bal = IERC20(t).balanceOf(address(this));
                doSomething(bal);
            }
        }
        """
        rows = _scan(src, "C.sol")
        self.assertNotIn("S_STALE_LOCAL_AFTER_EXTCALL", _kinds(rows))

    def test_inline_reread_no_cache_silent(self):
        # the balance is read INLINE after the call (no cached-before local) -
        # the fee-on-transfer delta idiom. Only `balanceBefore` is cached, and it
        # is a deliberate snapshot (name-excluded).
        src = """
        contract C {
            function f(address t) external returns (uint256) {
                uint256 balanceBefore = IERC20(t).balanceOf(address(this));
                IERC20(t).safeTransferFrom(msg.sender, address(this), 1);
                return IERC20(t).balanceOf(address(this)) - balanceBefore;
            }
        }
        """
        rows = _scan(src, "C.sol")
        self.assertNotIn("S_STALE_LOCAL_AFTER_EXTCALL", _kinds(rows))

    def test_snapshot_name_excluded(self):
        # a cached read used after the call but named as a deliberate snapshot.
        src = """
        contract C {
            function f(address t) external {
                uint256 balBefore = IERC20(t).balanceOf(address(this));
                IERC20(t).transferFrom(msg.sender, address(this), 1);
                emit E(balBefore);
            }
        }
        """
        rows = _scan(src, "C.sol")
        self.assertNotIn("S_STALE_LOCAL_AFTER_EXTCALL", _kinds(rows))

    def test_no_boundary_silent(self):
        # cached read, no external boundary between cache and use -> not this class.
        src = """
        contract C {
            function f(address t) external {
                uint256 bal = IERC20(t).balanceOf(address(this));
                uint256 y = bal + 1;
                emit E(y);
            }
        }
        """
        rows = _scan(src, "C.sol")
        self.assertEqual(rows, [])

    def test_length_cached_across_lowlevel_call_fires(self):
        src = """
        contract C {
            address[] arr;
            function f(address cb) external {
                uint256 n = arr.length;
                cb.call("");
                for (uint256 i; i < n; i++) { use(arr[i]); }
            }
        }
        """
        rows = _scan(src, "C.sol")
        self.assertIn("S_STALE_LOCAL_AFTER_EXTCALL", _kinds(rows))
        self.assertEqual(
            [x for x in rows if x["pattern_id"] == "S_STALE_LOCAL_AFTER_EXTCALL"
             ][0]["cached_value"], "n")

    def test_use_before_boundary_only_silent(self):
        # the cached value is used BEFORE the boundary only -> no stale read.
        src = """
        contract C {
            function f(address t) external {
                uint256 bal = IERC20(t).balanceOf(address(this));
                require(bal > 0);
                IERC20(t).transfer(msg.sender, bal > 0 ? 1 : 0);
            }
        }
        """
        rows = _scan(src, "C.sol")
        # `bal` is used only in the transfer arg (part of the boundary line) and
        # in require BEFORE the call; no read strictly after the boundary.
        self.assertNotIn("S_STALE_LOCAL_AFTER_EXTCALL", _kinds(rows))


class RustBorrowAcrossAwaitTests(unittest.TestCase):
    def test_ref_held_across_await_with_mutation_fires(self):
        src = """
        impl S {
            async fn run(&mut self) {
                let head = self.queue.first();
                self.remote.send().await;
                self.queue.push(9);
                log(head);
            }
        }
        """
        rows = _scan(src, "s.rs")
        self.assertIn("R_BORROW_ACROSS_AWAIT", _kinds(rows))
        r = [x for x in rows if x["pattern_id"] == "R_BORROW_ACROSS_AWAIT"][0]
        self.assertEqual(r["defect"], "borrow-across-await")

    def test_reref_after_await_silent(self):
        # backing not mutated after the borrow -> benign hold.
        src = """
        impl S {
            async fn run(&mut self) {
                let head = self.queue.first();
                self.remote.send().await;
                log(head);
            }
        }
        """
        rows = _scan(src, "s.rs")
        self.assertNotIn("R_BORROW_ACROSS_AWAIT", _kinds(rows))

    def test_no_await_silent(self):
        src = """
        impl S {
            fn run(&mut self) {
                let head = self.queue.first();
                self.queue.push(9);
                log(head);
            }
        }
        """
        rows = _scan(src, "s.rs")
        self.assertEqual(rows, [])


class GoStaleValueTests(unittest.TestCase):
    def test_cached_len_across_callback_fires(self):
        src = """
        package p
        func (s *S) run(cb Callback) {
            n := len(s.items)
            cb.Invoke()
            for i := 0; i < n; i++ { use(s.items[i]) }
        }
        """
        rows = _scan(src, "s.go")
        self.assertIn("G_STALE_VALUE_AFTER_CALL", _kinds(rows))
        r = [x for x in rows if x["pattern_id"] == "G_STALE_VALUE_AFTER_CALL"][0]
        self.assertEqual(r["defect"], "slice-backing-mutated")

    def test_reread_after_callback_silent(self):
        src = """
        package p
        func (s *S) run(cb Callback) {
            n := len(s.items)
            cb.Invoke()
            n = len(s.items)
            for i := 0; i < n; i++ { use(s.items[i]) }
        }
        """
        rows = _scan(src, "s.go")
        self.assertNotIn("G_STALE_VALUE_AFTER_CALL", _kinds(rows))

    def test_no_boundary_silent(self):
        src = """
        package p
        func (s *S) run() {
            n := len(s.items)
            for i := 0; i < n; i++ { use(s.items[i]) }
        }
        """
        rows = _scan(src, "s.go")
        self.assertEqual(rows, [])


class ExclusionTests(unittest.TestCase):
    def test_codegen_marker_excluded(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "src"
            root.mkdir()
            gen = root / "x.pb.go"
            gen.write_text(
                "// Code generated by protoc. DO NOT EDIT.\n"
                "package p\n"
                "func (s *S) run(cb Callback) {\n"
                "  n := len(s.items)\n"
                "  cb.Invoke()\n"
                "  for i := 0; i < n; i++ { use(s.items[i]) }\n"
                "}\n")
            rows = a4.scan_tree(root, workspace=Path(td))
            self.assertEqual(rows, [])


class MutationWitnessTests(unittest.TestCase):
    """Real-fleet non-vacuity + reentrancy-distinctness witness on etherfi
    Liquifier.depositWithERC20. The function is `nonReentrant` and CORRECTLY
    re-reads balanceOf(this) AFTER safeTransferFrom to measure the amount received
    (stETH rounding / rebase - a NON-reentrant, token-side mutation the reentrancy
    lane cannot see). Original -> silent. A variant caching the post-balance BEFORE
    the transfer and trusting the stale local -> fires. Restored byte-identical."""

    LIQ = Path("/Users/wolf/audits/etherfi/src/smart-contracts/src/Liquifier.sol")
    _BENIGN = (
        "            uint256 balanceBefore = IERC20(_token).balanceOf(address(this));\n"
        "            IERC20(_token).safeTransferFrom(msg.sender, address(this), _amount);\n"
        "            amountReceived = IERC20(_token).balanceOf(address(this)) - balanceBefore;")
    _WEAK = (
        "            uint256 balanceBefore = IERC20(_token).balanceOf(address(this));\n"
        "            uint256 balNow = IERC20(_token).balanceOf(address(this));\n"
        "            IERC20(_token).safeTransferFrom(msg.sender, address(this), _amount);\n"
        "            amountReceived = balNow - balanceBefore;")

    def test_real_benign_reread_silent(self):
        if not self.LIQ.exists():
            self.skipTest("etherfi Liquifier.sol not present")
        orig = self.LIQ.read_text()
        self.assertIn(self._BENIGN, orig, "fixture drifted from source")
        rows0 = a4.scan_file(self.LIQ, self.LIQ.name, file_text=orig)
        dep = [r for r in rows0 if r["function"] == "depositWithERC20"]
        self.assertEqual(dep, [], "benign re-read must not fire")

    def test_hoisted_stale_local_fires(self):
        if not self.LIQ.exists():
            self.skipTest("etherfi Liquifier.sol not present")
        orig = self.LIQ.read_text()
        weak = orig.replace(self._BENIGN, self._WEAK, 1)
        self.assertNotEqual(weak, orig, "mutation did not change source")
        rows1 = a4.scan_file(self.LIQ, self.LIQ.name, file_text=weak)
        dep = [r for r in rows1 if r["function"] == "depositWithERC20"
               and r["cached_value"] == "balNow"]
        self.assertTrue(dep, "hoisted stale-local variant must newly fire")
        self.assertEqual(dep[0]["defect"], "stale-local-after-extcall")
        # restore invariant: original file untouched on disk
        self.assertEqual(self.LIQ.read_text(), orig)


class CliTests(unittest.TestCase):
    def test_cli_source_mode_and_exit0(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "src"
            src.mkdir()
            (src / "a.sol").write_text(
                "contract C {\n"
                "    function f(address t) external {\n"
                "        uint256 bal = IERC20(t).balanceOf(address(this));\n"
                "        IERC20(t).transferFrom(msg.sender, address(this), 1);\n"
                "        use(bal);\n"
                "    }\n"
                "}\n")
            r = subprocess.run(
                [sys.executable, str(TOOL), "--workspace", td],
                capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            summ = json.loads(r.stdout)
            self.assertEqual(summ["schema"], a4.HYP_SCHEMA)
            self.assertGreaterEqual(summ["fired"], 1)
            side = (Path(td) / ".auditooor" /
                    "extcall_boundary_invalidation_hypotheses.jsonl")
            self.assertTrue(side.exists())

    def test_cli_strict_exit1_on_fire(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "src"
            src.mkdir()
            (src / "a.sol").write_text(
                "contract C {\n"
                "    function f(address t) external {\n"
                "        uint256 bal = IERC20(t).balanceOf(address(this));\n"
                "        IERC20(t).transferFrom(msg.sender, address(this), 1);\n"
                "        use(bal);\n"
                "    }\n"
                "}\n")
            r = subprocess.run(
                [sys.executable, str(TOOL), "--workspace", td, "--strict"],
                capture_output=True, text=True)
            self.assertEqual(r.returncode, 1)


if __name__ == "__main__":
    unittest.main()
