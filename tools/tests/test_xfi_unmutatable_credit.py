#!/usr/bin/env python3
"""Regression: a state-machine cross-function requirement whose EVERY function is a pure
assignment (mutation-verify verdict 'no-mutants', zero mutable operators) is credited
when the guarded state variable is exercised by a non-vacuous mvc harness - the
mutation-kill bar is inapplicable (demanding a kill would be impossible). Proof-gated:
requires a real no-mutants sidecar per function AND a real referencing harness."""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_MOD = _HERE.parent / "cross-function-invariant-coverage.py"
_spec = importlib.util.spec_from_file_location("xfi_unmut", _MOD)
_m = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = _m
_spec.loader.exec_module(_m)


class _Req:
    def __init__(self, kind, label, function_names):
        self.kind = kind
        self.label = label
        self.function_names = set(function_names)


class TestUnmutatableCredit(unittest.TestCase):
    def _ws(self, sidecars):
        ws = Path(tempfile.mkdtemp())
        d = ws / ".auditooor" / "mvc_sidecar"
        d.mkdir(parents=True)
        for name, rec in sidecars.items():
            (d / name).write_text(json.dumps(rec))
        return ws

    def test_all_no_mutants_and_exercised_covers(self):
        ws = self._ws({
            "a.json": {"function": "initialize", "verdict": "no-mutants"},
            "b.json": {"function": "updateIndex", "verdict": "no-mutants"},
        })
        req = _Req("state-machine", "state:indexTimestamp", {"initialize", "updateIndex"})
        refs = [{"file": "T.t.sol", "referenced": {"indexTimestamp", "updateAccounting"}}]
        ok, ev = _m._requirement_unmutatable_but_exercised(req, ws, refs)
        self.assertTrue(ok)
        self.assertIn("no-mutants", ev["reason"])

    def test_not_all_no_mutants_does_not_cover(self):
        ws = self._ws({
            "a.json": {"function": "initialize", "verdict": "no-mutants"},
            "b.json": {"function": "updateIndex", "verdict": "non-vacuous"},  # has mutants
        })
        req = _Req("state-machine", "state:indexTimestamp", {"initialize", "updateIndex"})
        refs = [{"file": "T.t.sol", "referenced": {"indexTimestamp"}}]
        ok, _ = _m._requirement_unmutatable_but_exercised(req, ws, refs)
        self.assertFalse(ok)

    def test_state_var_not_exercised_does_not_cover(self):
        ws = self._ws({
            "a.json": {"function": "initialize", "verdict": "no-mutants"},
            "b.json": {"function": "updateIndex", "verdict": "no-mutants"},
        })
        req = _Req("state-machine", "state:indexTimestamp", {"initialize", "updateIndex"})
        refs = [{"file": "T.t.sol", "referenced": {"somethingElse"}}]  # no indexTimestamp
        ok, _ = _m._requirement_unmutatable_but_exercised(req, ws, refs)
        self.assertFalse(ok)

    def test_sibling_pair_kind_not_credited(self):
        ws = self._ws({"a.json": {"function": "addX", "verdict": "no-mutants"}})
        req = _Req("sibling-pair", "add|remove@x", {"addX"})
        refs = [{"file": "T.t.sol", "referenced": {"addX"}}]
        ok, _ = _m._requirement_unmutatable_but_exercised(req, ws, refs)
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
