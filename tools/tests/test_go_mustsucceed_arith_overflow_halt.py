#!/usr/bin/env python3
"""Tests for tools/go-mustsucceed-arith-overflow-halt.py

The load-bearing test is the NON-VACUOUS MUTATION PAIR (test_mutation_*): a
survivor must DISAPPEAR when a bound-dominator is added on its magnitude operand,
and must move to the KEPT-unreachable witness set when its node is relocated off the
must-succeed call-closure. Plus a real must-fire re-surface on nuva when present.
"""

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_TOOL = _HERE.parent / "go-mustsucceed-arith-overflow-halt.py"

_spec = importlib.util.spec_from_file_location("ms_arith", _TOOL)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)


def _ws(files: dict) -> Path:
    """Materialize a throwaway workspace: {relpath: content} under a src/ tree."""
    d = Path(tempfile.mkdtemp(prefix="msarith_"))
    (d / ".auditooor").mkdir(parents=True, exist_ok=True)
    for rel, content in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return d


def _run(ws: Path):
    emit = ws / ".auditooor" / "out.jsonl"
    return mod.run([
        "--workspace", str(ws), "--src-root", str(ws / "src"),
        "--emit", str(emit), "--json",
    ])


_IMPORTS = 'import sdkmath "cosmossdk.io/math"\n'

# a reachable, tainted, UN-dominated Dec-mul inside a fn called from EndBlocker.
_BASE = _IMPORTS + '''
func (k Keeper) EndBlocker(ctx Context) error {
	return k.accrue(ctx, k.rate)
}

func (k Keeper) accrue(ctx Context, rate sdkmath.LegacyDec) error {
	t := sdkmath.LegacyNewDec(10)
	rt := rate.Mul(t)
	_ = rt
	return nil
}
'''


class TestArithOverflowHalt(unittest.TestCase):

    def test_survivor_reachable_tainted_undominated(self):
        ws = _ws({"src/x/keeper.go": "package keeper\n" + _BASE})
        s = _run(ws)
        self.assertIn("EndBlocker", s["mustsucceed_roots"])
        self.assertGreaterEqual(s["n_arith_panic_nodes"], 1)
        fns = [v["fn"] for v in s["survivors"]]
        self.assertTrue(any("accrue" in f for f in fns),
                        f"expected accrue survivor, got {fns}")

    def test_mutation_bound_dominator_removes_survivor(self):
        """MUTATION A: add a dominating IsZero/bound guard on the magnitude operand
        -> the survivor must disappear and reappear as bound-dominated KEPT."""
        guarded = _IMPORTS + '''
func (k Keeper) EndBlocker(ctx Context) error {
	return k.accrue(ctx, k.rate)
}

func (k Keeper) accrue(ctx Context, rate sdkmath.LegacyDec) error {
	t := sdkmath.LegacyNewDec(10)
	if rate.GT(MaxRate) {
		return nil
	}
	rt := rate.Mul(t)
	_ = rt
	return nil
}
'''
        base = _run(_ws({"src/x/keeper.go": "package keeper\n" + _BASE}))
        mut = _run(_ws({"src/x/keeper.go": "package keeper\n" + guarded}))
        base_fns = [v["fn"] for v in base["survivors"]]
        mut_fns = [v["fn"] for v in mut["survivors"]]
        self.assertTrue(any("accrue" in f for f in base_fns))
        self.assertFalse(any("accrue" in f for f in mut_fns),
                         "bound-dominated node must NOT survive")
        self.assertGreater(mut["n_kept_bound_dominated"], 0,
                           "the removed node must appear as a dominance witness")

    def test_mutation_move_off_mustsucceed_closure(self):
        """MUTATION B: relocate the arith node into a fn NOT reachable from any
        must-succeed root -> it must move to the KEPT-unreachable witness set."""
        off = _IMPORTS + '''
func (k Keeper) HandleMsgFoo(ctx Context, rate sdkmath.LegacyDec) error {
	t := sdkmath.LegacyNewDec(10)
	rt := rate.Mul(t)
	_ = rt
	return nil
}
'''
        s = _run(_ws({"src/x/msg.go": "package keeper\n" + off}))
        self.assertEqual(s["n_survivors"], 0,
                         "no must-succeed root reaches the node -> no survivor")
        self.assertGreater(s["n_kept_unreachable"], 0,
                           "the tainted node must be a KEPT-unreachable witness")

    def test_safe_variant_excluded(self):
        """SafeMul/SafeQuo return an error instead of panicking -> not a sink."""
        safe = _IMPORTS + '''
func (k Keeper) EndBlocker(ctx Context) error {
	return k.accrue(ctx, k.rate)
}

func (k Keeper) accrue(ctx Context, rate sdkmath.Int) error {
	t := sdkmath.NewInt(10)
	rt, _ := rate.SafeMul(t)
	_ = rt
	return nil
}
'''
        s = _run(_ws({"src/x/keeper.go": "package keeper\n" + safe}))
        self.assertEqual(s["n_arith_panic_nodes"], 0,
                         "SafeMul must not be counted as an arith-panic node")

    def test_divzero_quo_survivor(self):
        """A Quo with a state-tainted divisor and no IsZero dominator survives."""
        divz = _IMPORTS + '''
func (k Keeper) BeginBlocker(ctx Context) error {
	return k.nav(ctx)
}

func (k Keeper) nav(ctx Context) error {
	tvv := k.GetTVV(ctx)
	shares := k.GetShares(ctx)
	per := tvv.Quo(shares)
	_ = per
	return nil
}
'''
        s = _run(_ws({"src/x/nav.go": "package keeper\n" + divz}))
        self.assertTrue(any(v["arith_op"] in ("int-quo", "dec-quo")
                            for v in s["survivors"]),
                        f"expected a div-zero survivor, got {s['survivors']}")

    def test_substrate_vacuous_when_no_math(self):
        """A workspace with no Dec/Int math markers -> substrate_vacuous, honest."""
        plain = '''package keeper
func (k Keeper) EndBlocker(ctx Context) error {
	x := 1 + 2
	_ = x
	return nil
}
'''
        s = _run(_ws({"src/x/plain.go": plain}))
        self.assertEqual(s["n_arith_panic_nodes"], 0)
        self.assertTrue(s["substrate_vacuous"])
        self.assertFalse(s["cited_empty"])

    def test_obligation_schema_fields(self):
        ws = _ws({"src/x/keeper.go": "package keeper\n" + _BASE})
        _run(ws)
        rows = [json.loads(l) for l in
                (ws / ".auditooor" / "out.jsonl").read_text().splitlines() if l.strip()]
        self.assertTrue(rows)
        r = rows[0]
        for key in ("schema", "function", "contract", "file", "line",
                    "source_refs", "arith_op", "taint_source",
                    "mustsucceed_root_name", "attack_class"):
            self.assertIn(key, r)
        self.assertEqual(r["schema"], "auditooor.mustsucceed_arith_overflow.v1")

    def test_nuva_mustfire_resurfaces_expdec_and_nav(self):
        """MUST-FIRE proof: on the real nuva vault the tool re-surfaces the ExpDec
        Maclaurin power.Mul overflow AND the NAV-price div node. Skipped if the
        workspace is absent on this host."""
        nuva = Path("/Users/wolf/audits/nuva/src/vault")
        if not nuva.is_dir():
            self.skipTest("nuva workspace not present")
        emit = Path(tempfile.mkdtemp(prefix="nuva_")) / "out.jsonl"
        s = mod.run([
            "--workspace", "/Users/wolf/audits/nuva",
            "--src-root", str(nuva), "--emit", str(emit), "--json",
        ])
        survivors = [(v["fn"], v["file"], v["line"]) for v in s["survivors"]]
        expdec = [x for x in survivors
                  if "ExpDec" in x[0] and x[1].endswith("utils/math.go")]
        interest_mul = [x for x in survivors
                        if "CalculateInterestEarned" in x[0]
                        and x[1].endswith("interest/interest.go")]
        nav = [x for x in survivors if x[1].endswith("keeper/valuation_engine.go")]
        self.assertTrue(expdec, f"ExpDec power.Mul overflow not surfaced: {survivors}")
        self.assertTrue(interest_mul, f"interest.go Mul not surfaced: {survivors}")
        self.assertTrue(nav, f"NAV-price overflow not surfaced: {survivors}")
        # non-vacuity witnesses present
        self.assertGreater(s["n_kept_bound_dominated"] + s["n_kept_unreachable"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
