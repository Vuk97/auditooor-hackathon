#!/usr/bin/env python3
"""Regression: write_inscope_manifest's _interface_only_filter drops pure Solidity
interface files (no implementation/value-flow) but keeps contracts/libraries, and
never empties the manifest."""
import importlib.util
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_MOD = _HERE.parent / "workspace-coverage-heatmap.py"
_spec = importlib.util.spec_from_file_location("wch", _MOD)
_m = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_m)


class TestInterfaceOnlyFilter(unittest.TestCase):
    def _ws(self, files: dict):
        ws = Path(tempfile.mkdtemp())
        for rel, body in files.items():
            p = ws / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body)
        return ws

    def test_drops_interface_keeps_contract(self):
        ws = self._ws({
            "c/IFoo.sol": "// spdx\ninterface IFoo {\n  function f() external;\n}",
            "c/Bar.sol": "contract Bar {\n  function f() public {}\n}",
            "c/Lib.sol": "library Lib {\n  function g() internal pure {}\n}",
        })
        rows = [{"file": "c/IFoo.sol", "function": "f"},
                {"file": "c/Bar.sol", "function": "f"},
                {"file": "c/Lib.sol", "function": "g"}]
        kept = {r["file"] for r in _m._interface_only_filter(ws, rows)}
        self.assertNotIn("c/IFoo.sol", kept)
        self.assertIn("c/Bar.sol", kept)
        self.assertIn("c/Lib.sol", kept)

    def test_abstract_interface_also_dropped(self):
        ws = self._ws({"c/IA.sol": "abstract interface IA { function f() external; }"})
        rows = [{"file": "c/IA.sol", "function": "f"},
                {"file": "c/Real.sol", "function": "x"}]
        # Real.sol has no file on disk -> not an interface -> kept
        kept = {r["file"] for r in _m._interface_only_filter(ws, rows)}
        self.assertNotIn("c/IA.sol", kept)
        self.assertIn("c/Real.sol", kept)

    def test_file_with_both_interface_and_contract_is_kept(self):
        # a file declaring an interface AND an implementing contract is real code.
        ws = self._ws({"c/Mix.sol": "interface I { function f() external; }\ncontract C is I { function f() external {} }"})
        rows = [{"file": "c/Mix.sol", "function": "f"}]
        self.assertEqual([r["file"] for r in _m._interface_only_filter(ws, rows)], ["c/Mix.sol"])

    def test_never_empties(self):
        ws = self._ws({"c/IOnly.sol": "interface IOnly { function f() external; }"})
        rows = [{"file": "c/IOnly.sol", "function": "f"}]  # only row is an interface
        self.assertEqual(len(_m._interface_only_filter(ws, rows)), 1)  # fail-safe


if __name__ == "__main__":
    unittest.main()
