#!/usr/bin/env python3
"""Regression: sibling-path-guard-diff excludes Solidity view/pure functions from
guard-asymmetry pairing (they move no funds; any asymmetry is spurious) but keeps
state-mutating functions."""
import importlib.util, sys, tempfile, unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_MOD = _HERE.parent / "sibling-path-guard-diff.py"
_spec = importlib.util.spec_from_file_location("spgd_view_skip_test", _MOD)
_m = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = _m
_spec.loader.exec_module(_m)


class TestViewSkip(unittest.TestCase):
    def _arms(self, body: str):
        d = Path(tempfile.mkdtemp())
        p = d / "C.sol"
        p.write_text(body)
        return {a.name for a in _m._extract_arms(p, "sol", "C.sol")}

    def test_view_and_pure_excluded_mutator_kept(self):
        names = self._arms(
            "contract C {\n"
            "  function maxWithdraw(address o) external view returns (uint256) { return 1; }\n"
            "  function previewX() public pure returns (uint256) { return 2; }\n"
            "  function withdraw(uint256 a) external nonReentrant { doStuff(); }\n"
            "}\n")
        self.assertNotIn("maxWithdraw", names)
        self.assertNotIn("previewX", names)
        self.assertIn("withdraw", names)

    def test_param_named_view_not_tripped(self):
        # a mutator whose body/params mention 'view' must NOT be excluded
        names = self._arms(
            "contract C {\n"
            "  function deposit(uint256 amount) external { uint256 view_ = amount; emit E(view_); }\n"
            "}\n")
        self.assertIn("deposit", names)


if __name__ == "__main__":
    unittest.main()
