"""Regression tests for two invariant-fuzz-completeness false-red fixes found
driving SSV to pass-audit-complete:

A. mutation_kill.sidecar_is_genuine must credit the auditooor.mvc_sidecar.cluster.v1
   schema, where genuineness is carried by a non-empty mutation_verify[] list of
   {verdict: KILLED} rows (not a top-level mutation_verified flag). A genuine EB
   harness whose 3 mutants were KILLED was sitting uncredited (4th-gate serving-join,
   same class as corecov_cluster_sidecar_credit_fix). NEVER-FALSE-PASS: SURVIVED-only
   or empty campaigns must still return False.

B. invariant-fuzz-completeness must EXCLUDE an unfilled gen-invariants.sh scaffold
   (assert(true)/invariant_placeholder, CUT not wired) - it is not a harness, so it
   must neither block ("only 1 invariant") nor be credited. The all-placeholder case
   must still fail (genuine_harness_count==0 guard).
"""
from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLS = REPO_ROOT / "tools"


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, str(TOOLS / rel))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


MK = _load("mutation_kill", "lib/mutation_kill.py")
IFC = _load("invariant_fuzz_completeness", "invariant-fuzz-completeness.py")


class TestClusterMutationVerifyCredit(unittest.TestCase):
    def test_killed_list_is_genuine(self):
        d = {
            "schema_version": "auditooor.mvc_sidecar.cluster.v1",
            "mutation_verify": [
                {"mutant_id": "A", "verdict": "KILLED"},
                {"mutant_id": "B", "verdict": "KILLED"},
            ],
            "baseline_run": {"result": "PASS"},
        }
        self.assertTrue(MK.sidecar_is_genuine(d))

    def test_survived_only_not_genuine(self):
        d = {"mutation_verify": [{"verdict": "SURVIVED"}]}
        self.assertFalse(MK.sidecar_is_genuine(d))

    def test_empty_list_not_genuine(self):
        self.assertFalse(MK.sidecar_is_genuine({"mutation_verify": []}))

    def test_no_mutation_fields_not_genuine(self):
        self.assertFalse(MK.sidecar_is_genuine({"schema_version": "x"}))


def _write(p: Path, txt: str):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(txt, encoding="utf-8")


_SCAFFOLD = """// SPDX-License-Identifier: MIT
// Auto-scaffolded by tools/gen-invariants.sh on 2026-06-23
// TODO: agent fills in invariant_* functions
pragma solidity ^0.8.20;
import {Test, StdInvariant} from "forge-std/Test.sol";
contract Invariant_Foo is StdInvariant, Test {
    function setUp() public {
        // target = new Foo(...);
        // targetContract(address(handler));
    }
    function invariant_placeholder() public view { assert(true); }
}
"""

_REAL = """pragma solidity ^0.8.20;
import {Test, StdInvariant} from "forge-std/Test.sol";
contract Invariant_Real is StdInvariant, Test {
    Foo target;
    function setUp() public { target = new Foo(); targetContract(address(target)); }
    function invariant_balance_conserved() public view { assert(target.ok()); }
    function invariant_supply_bounded() public view { assert(target.ok2()); }
}
"""


class TestUnfilledScaffoldExclusion(unittest.TestCase):
    def test_unfilled_scaffold_detected(self):
        with tempfile.TemporaryDirectory() as td:
            hd = Path(td) / "test"
            _write(hd / "Invariant_Foo.t.sol", _SCAFFOLD)
            self.assertTrue(IFC._is_unfilled_scaffold_harness(hd))

    def test_real_harness_not_excluded(self):
        with tempfile.TemporaryDirectory() as td:
            hd = Path(td) / "test"
            _write(hd / "Invariant_Real.t.sol", _REAL)
            self.assertFalse(IFC._is_unfilled_scaffold_harness(hd))

    def test_all_placeholder_workspace_still_fails(self):
        # a ws whose ONLY harness is an unfilled scaffold + has in-scope Solidity
        # source must FAIL (never-false-pass), not pass on an empty failures list.
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _write(ws / "test" / "Invariant_Foo.t.sol", _SCAFFOLD)
            # in-scope production source so 'no genuine harness' is a GAP
            _write(ws / "src" / "Foo.sol", "pragma solidity ^0.8.20; contract Foo { function f() external {} }")
            res = IFC.evaluate(ws)
            self.assertEqual(res["verdict"], "fail-invariant-fuzz-incomplete", res)
            self.assertIn("no genuine invariant harness", res["reason"])


if __name__ == "__main__":
    unittest.main()
