#!/usr/bin/env python3
# <!-- r36-rebuttal: lane FIX-XFI-TEST-PATH registered via agent-pathspec-register.py -->
"""Guard: cross-function-invariant-coverage._is_test_path excludes test files even
when the path is relative to a src/ root (no leading slash).

Regression for the morpho-midnight cross-function false-red: with src_root=src/,
a top-level test dir arrives as "test/Foo.sol" (no leading slash), so the "/test/"
substring hint missed it and all 60 src/test/*Test.sol files counted as in-scope
cross-function requirements (60/120 uncovered, all test). After the fix the gate
sees only the 8 genuine in-scope requirements.
"""
import importlib.util
import sys
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("xfi", str(_TOOLS / "cross-function-invariant-coverage.py"))
m = importlib.util.module_from_spec(spec)
sys.modules["xfi"] = m
spec.loader.exec_module(m)


class TestIsTestPath(unittest.TestCase):
    def test_root_relative_test_dir_detected(self):
        # rel relative to src/ root => no leading slash; must still be classified test
        self.assertTrue(m._is_test_path("test/EcrecoverRatifierTest.sol"))
        self.assertTrue(m._is_test_path("test/erc20s/ERC20.sol"))
        self.assertTrue(m._is_test_path("test/TakeTest.sol"))

    def test_prefixed_test_dir_still_detected(self):
        self.assertTrue(m._is_test_path("src/test/Foo.sol"))

    def test_foundry_and_underscore_basenames(self):
        self.assertTrue(m._is_test_path("invariants/Foo.t.sol"))
        self.assertTrue(m._is_test_path("pkg/foo_test.go"))

    def test_real_src_not_flagged(self):
        for p in ("Midnight.sol", "src/Midnight.sol", "libraries/TickLib.sol",
                  "contest/Proposal.sol", "latestThing.sol"):
            self.assertFalse(m._is_test_path(p), f"{p} wrongly flagged as test")


if __name__ == "__main__":
    unittest.main(verbosity=2)
