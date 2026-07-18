#!/usr/bin/env python3
"""GEN-EL2 ABI selector / dispatch collision soundness screen - regression +
non-vacuity tests.

Pins tools/selector-dispatch-collision-screen.py: a selector->target dispatch
STRUCTURE (EIP-2535 facet map / transparent-proxy fallback clash / manual
assembly selector switch / bytes4->address router) that routes selectors WITHOUT
a collision-rejection guard. Rows carry verdict='needs-fuzz' (advisory,
NO-AUTO-CREDIT). The screen NEVER emits a numeric keccak4 coincidence - it flags
the UNGUARDED STRUCTURE.

Matrix (pure fixtures, no external toolchain):
  - fire_diamond.sol  : selectorToFacet add loop, no add-collision reject   -> 1
  - guarded_diamond.sol: same map WITH require(oldFacet==address(0))         -> 0
  - fire_router.sol   : bytes4->address router set + proxy fallback clash    -> 2
  - fire_proxy.sol    : proxy fallback + admin fns, no ifAdmin separation    -> 1
  - benign_proxy.sol  : ifAdmin admin/impl separation (safe form b)          -> 0
  - fire_assembly.sol : assembly selector switch, default routes delegatecall-> 1
  - benign_assembly.sol: assembly switch, default reverts (safe form c)      -> 0
  - fire_router.vy    : Vyper HashMap[bytes4,address] route, no reject        -> 1
  - fire_dispatch.move: Move dispatch table add, no contains check           -> 1

Off-by-default: default mode exits 0 even with fired rows (advisory-first);
--strict / env elevates.

Non-vacuity (test_mutate_add_collision_guard_predicate): neutralise the tool's
add-collision-guard suppressor; the GUARDED diamond must then collapse 0 -> >=1,
proving the require(oldFacet==address(0)) guard is load-bearing (not a vacuous
always-fire). This mirrors the real-fleet mutation-verify on beanstalk
LibDiamond.sol.
"""
from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "selector-dispatch-collision-screen.py"
FX = ROOT / "tools" / "tests" / "fixtures" / "gen_el2"
SIDE_NAME = "selector_dispatch_collision_hypotheses.jsonl"
SCHEMA = "auditooor.selector_dispatch_collision_hypotheses.v1"


def _load_tool():
    spec = importlib.util.spec_from_file_location("sdc_screen_el2", TOOL)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _scan(tool, fixture: str):
    p = FX / fixture
    return tool.scan_file(p, fixture)


class GenEl2MatrixTest(unittest.TestCase):
    def setUp(self):
        self.tool = _load_tool()

    def test_fire_diamond_one_row(self):
        rows = _scan(self.tool, "fire_diamond.sol")
        self.assertEqual(len(rows), 1, [r["dispatch_kind"] for r in rows])
        r = rows[0]
        self.assertEqual(r["capability"], "GEN_EL2")
        self.assertEqual(r["schema"], SCHEMA)
        self.assertEqual(r["dispatch_kind"], "diamond-facet-map")
        self.assertEqual(r["missing_guard"], "no-add-collision-require")
        self.assertEqual(r["lang"], "solidity")
        self.assertEqual(r["verdict"], "needs-fuzz")
        self.assertTrue(r["advisory"])
        self.assertFalse(r["auto_credit"])

    def test_guarded_diamond_zero(self):
        rows = _scan(self.tool, "guarded_diamond.sol")
        self.assertEqual(len(rows), 0, [r["excerpt"] for r in rows])

    def test_fire_router_two_arms(self):
        rows = _scan(self.tool, "fire_router.sol")
        kinds = sorted(r["dispatch_kind"] for r in rows)
        self.assertIn("router-map", kinds)
        self.assertIn("proxy-fallback-clash", kinds)

    def test_fire_proxy_clash(self):
        rows = _scan(self.tool, "fire_proxy.sol")
        self.assertEqual(len(rows), 1, [r["dispatch_kind"] for r in rows])
        r = rows[0]
        self.assertEqual(r["dispatch_kind"], "proxy-fallback-clash")
        self.assertEqual(r["missing_guard"], "no-admin-impl-separation")

    def test_benign_proxy_zero(self):
        # ifAdmin router == admin/impl selector-space separation (safe form b).
        rows = _scan(self.tool, "benign_proxy.sol")
        self.assertEqual(len(rows), 0, [r["excerpt"] for r in rows])

    def test_fire_assembly_switch(self):
        rows = _scan(self.tool, "fire_assembly.sol")
        self.assertEqual(len(rows), 1, [r["dispatch_kind"] for r in rows])
        r = rows[0]
        self.assertEqual(r["dispatch_kind"], "assembly-switch")
        self.assertEqual(r["missing_guard"], "no-duplicate-case-check")

    def test_benign_assembly_zero(self):
        # default { revert } == duplicate/unknown-selector reject (safe form c).
        rows = _scan(self.tool, "benign_assembly.sol")
        self.assertEqual(len(rows), 0, [r["excerpt"] for r in rows])

    def test_fire_vyper_router(self):
        rows = _scan(self.tool, "fire_router.vy")
        self.assertEqual(len(rows), 1, [r["dispatch_kind"] for r in rows])
        self.assertEqual(rows[0]["lang"], "vyper")
        self.assertEqual(rows[0]["dispatch_kind"], "router-map")

    def test_fire_move_dispatch(self):
        rows = _scan(self.tool, "fire_dispatch.move")
        self.assertEqual(len(rows), 1, [r["dispatch_kind"] for r in rows])
        self.assertEqual(rows[0]["lang"], "move")
        self.assertEqual(rows[0]["dispatch_kind"], "router-map")

    def test_no_numeric_hash_coincidence_emitted(self):
        # FP-control invariant: every fired row is anchored to a STRUCTURE
        # (a dispatch_kind + a missing_guard), never a bare selector-hash claim.
        for fx in ("fire_diamond.sol", "fire_router.sol", "fire_proxy.sol",
                   "fire_assembly.sol"):
            for r in _scan(self.tool, fx):
                self.assertIn(r["dispatch_kind"], (
                    "diamond-facet-map", "proxy-fallback-clash",
                    "assembly-switch", "router-map"))
                self.assertIn(r["missing_guard"], (
                    "no-add-collision-require", "no-admin-impl-separation",
                    "no-duplicate-case-check"))


class GenEl2AdvisoryExitTest(unittest.TestCase):
    """Advisory-first: default exit 0 even with fired rows; --strict elevates."""

    def _run_ws(self, extra_env=None, strict=False):
        with tempfile.TemporaryDirectory() as td:
            ws = pathlib.Path(td)
            src = ws / "src"
            src.mkdir()
            (src / "fire_diamond.sol").write_text(
                (FX / "fire_diamond.sol").read_text())
            argv = [sys.executable, str(TOOL), "--workspace", str(ws)]
            if strict:
                argv.append("--strict")
            env = dict(os.environ)
            env.pop("AUDITOOOR_SELECTOR_DISPATCH_COLLISION_STRICT", None)
            if extra_env:
                env.update(extra_env)
            proc = subprocess.run(argv, capture_output=True, text=True, env=env)
            side = ws / ".auditooor" / SIDE_NAME
            rows = []
            if side.exists():
                rows = [json.loads(l) for l in side.read_text().splitlines()
                        if l.strip()]
            return proc.returncode, rows, proc.stdout

    def test_default_advisory_exit0_with_sidecar(self):
        rc, rows, out = self._run_ws()
        self.assertEqual(rc, 0, out)
        self.assertEqual(len(rows), 1, out)
        self.assertEqual(rows[0]["schema"], SCHEMA)

    def test_strict_flag_elevates(self):
        rc, rows, out = self._run_ws(strict=True)
        self.assertEqual(rc, 1, out)
        self.assertEqual(len(rows), 1)

    def test_strict_env_elevates(self):
        rc, _rows, out = self._run_ws(
            extra_env={"AUDITOOOR_SELECTOR_DISPATCH_COLLISION_STRICT": "1"})
        self.assertEqual(rc, 1, out)


class GenEl2NonVacuityTest(unittest.TestCase):
    """Neutralise the add-collision-guard suppressor; the GUARDED diamond must
    then collapse 0 -> >=1, proving the guard predicate is load-bearing."""

    def test_mutate_add_collision_guard_predicate(self):
        tool = _load_tool()
        baseline = _scan(tool, "guarded_diamond.sol")
        self.assertEqual(len(baseline), 0,
                         "guarded diamond must be silent at baseline")
        # weaken: force _has_add_collision_guard to always report NO guard.
        tool._has_add_collision_guard = lambda text, maps: False
        weakened = tool.scan_file(FX / "guarded_diamond.sol",
                                  "guarded_diamond.sol")
        self.assertGreaterEqual(
            len(weakened), 1,
            "neutralising the add-collision-guard suppressor must make the "
            "guarded facet-map add newly fire - the guard is load-bearing")
        self.assertEqual(weakened[0]["dispatch_kind"], "diamond-facet-map")


if __name__ == "__main__":
    unittest.main()
