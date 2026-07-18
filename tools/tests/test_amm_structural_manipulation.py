#!/usr/bin/env python3
"""Tests for tools/amm-structural-manipulation.py (RANK-6 AMM structural
accounting coupled-update reasoner).

Neither of the PROVE workspaces (nuva vault, axelar-dlt Go) is a concentrated-
liquidity AMM, so over the REAL substrate the tool correctly reports
class_present=False (class_absent). Non-vacuity is therefore proven HERE, on a
synthetic Uniswap-v3-style dataflow fixture, INCLUDING a mutation pair: when the
crossTick mutator is made to update the FULL coupled tick-liquidity group, the
survivor DISAPPEARS.
"""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_TOOL = _HERE.parent / "amm-structural-manipulation.py"
_spec = importlib.util.spec_from_file_location("amm_struct_mod", _TOOL)
amm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(amm)


def _write_df(ws: Path, records: list[dict], name: str = "dataflow_paths.jsonl") -> Path:
    d = ws / ".auditooor"
    d.mkdir(parents=True, exist_ok=True)
    p = d / name
    with p.open("w") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")
    return p


def _ep(fn: str, var: str, file: str, line: int) -> dict:
    return {"kind": "param-entrypoint", "fn": fn, "var": var,
            "file": file, "line": line}


def _rec(language, ep, sink, hops=None, guards=None):
    return {
        "schema": "dataflow_path.v1", "language": language,
        "source": ep, "sink": sink, "hops": hops or [],
        "guard_nodes": guards or [], "degraded": False,
    }


def _run(ws: Path, **kw):
    argv = ["--workspace", str(ws), "--src-root", str(ws)]
    for k, v in kw.items():
        if v is True:
            argv.append(f"--{k.replace('_','-')}")
        elif v is not None:
            argv += [f"--{k.replace('_','-')}", str(v)]
    return amm.run(argv)


# --- Uniswap-v3-style fixture ------------------------------------------------
# A pool with tick liquidity accounting. FULL(tick_liquidity) observed =
# {liquidity_net, liquidity_gross, active_liquidity}. Two mutators:
#   * setPosition writes liquidityNet AND liquidityGross (updates BOTH per-tick
#     components) but NOT the global active liquidity -> partial-update survivor.
#   * cross() crosses a tick boundary and writes liquidityNet only, never the
#     aggregate active liquidity -> boundary-cross + partial-update survivor.
# A control mutator collectFees fully updates the fee_growth group so it is KEPT.
def _v3_fixture(src: str, cross_writes_active: bool = False):
    pool = f"{src}/UniswapV3Pool.sol"
    # observe active_liquidity somewhere so FULL(tick_liquidity) has 3 members
    swap_ep = _ep("UniswapV3Pool.swap(address,bool,int256)", "amountSpecified", pool, 700)
    swap_read = {"kind": "state_var_read", "callee": "liquidity",
                 "fn": swap_ep["fn"], "file": pool, "line": 705}
    recs = [_rec("solidity", swap_ep, swap_read)]

    # setPosition: writes liquidityNet + liquidityGross (per-tick), not active
    sp_ep = _ep("UniswapV3Pool.setPosition(int24,int24,int128)", "liquidityDelta", pool, 500)
    recs += [
        _rec("solidity", sp_ep,
             {"kind": "state-write", "callee": "liquidityNet",
              "fn": sp_ep["fn"], "file": pool, "line": 510, "cell": "ticks"}),
        _rec("solidity", sp_ep,
             {"kind": "state-write", "callee": "liquidityGross",
              "fn": sp_ep["fn"], "file": pool, "line": 512, "cell": "ticks"}),
    ]

    # cross(): tick boundary crossing writing liquidityNet (and active iff flag)
    cr_ep = _ep("UniswapV3Pool.cross(int24,uint256,uint256)", "tick", pool, 800)
    cross_sink = {"kind": "state-write", "callee": "liquidityNet",
                  "fn": cr_ep["fn"], "file": pool, "line": 810, "cell": "ticks"}
    cross_hops = [{"ir": "crossTick(tick)", "via": "crossTick", "fn": cr_ep["fn"]}]
    recs.append(_rec("solidity", cr_ep, cross_sink, hops=cross_hops))
    if cross_writes_active:
        recs.append(_rec("solidity", cr_ep,
                         {"kind": "state-write", "callee": "liquidity",
                          "fn": cr_ep["fn"], "file": pool, "line": 815},
                         hops=cross_hops))
        # also let cross write liquidityGross so its write set == FULL
        recs.append(_rec("solidity", cr_ep,
                         {"kind": "state-write", "callee": "liquidityGross",
                          "fn": cr_ep["fn"], "file": pool, "line": 816},
                         hops=cross_hops))

    # control: collectFees fully couples the fee_growth group (KEPT, not a survivor)
    cf_ep = _ep("UniswapV3Pool.collectFees(int24,int24)", "position", pool, 900)
    recs += [
        _rec("solidity", cf_ep,
             {"kind": "state-write", "callee": "feeGrowthInside",
              "fn": cf_ep["fn"], "file": pool, "line": 905}),
        _rec("solidity", cf_ep,
             {"kind": "state-write", "callee": "feeGrowthOutside",
              "fn": cf_ep["fn"], "file": pool, "line": 906}),
        _rec("solidity", cf_ep,
             {"kind": "state-write", "callee": "feeGrowthGlobal",
              "fn": cf_ep["fn"], "file": pool, "line": 907}),
    ]
    return recs


class TestRealSubstrate(unittest.TestCase):
    def test_nuva_class_absent_over_materialized_substrate(self):
        ws = Path("/Users/wolf/audits/nuva")
        if not (ws / ".auditooor" / "dataflow_paths.jsonl").is_file():
            self.skipTest("nuva substrate absent")
        with tempfile.TemporaryDirectory() as td:
            summ = _run(ws, emit=str(Path(td) / "out.jsonl"))
        # real records materialized, but NO AMM coupled group -> honest N/A
        self.assertGreater(summ["n_records"], 100)
        self.assertGreater(summ["n_entrypoint_units"], 0)
        self.assertFalse(summ["class_present"])
        self.assertEqual(summ["status"], "class_absent")
        self.assertFalse(summ["substrate_vacuous"])
        self.assertEqual(summ["obligations_written"], 0)


class TestSubstrateVacuous(unittest.TestCase):
    def test_empty_dataflow_is_vacuous_and_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _write_df(ws, [])
            rc = _run(ws, fail_closed=True)
            self.assertEqual(rc, 2)  # rc=2 substrate_vacuous under --fail-closed
            summ = _run(ws)          # without fail-closed returns summary
            self.assertTrue(summ["substrate_vacuous"])
            self.assertEqual(summ["status"], "substrate_vacuous")
            self.assertFalse(summ["class_present"])

    def test_all_degraded_records_warn(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            src = str(ws / "src")
            rec = _rec("go", _ep("pkg.F", "x", f"{src}/f.go", 1),
                       {"kind": "state-write", "callee": "liquidityNet",
                        "fn": "pkg.F", "file": f"{src}/f.go", "line": 2})
            rec["degraded"] = True
            _write_df(ws, [rec])
            summ = _run(ws)
            self.assertTrue(any("DEGRADED" in w for w in summ["warnings"]))
            self.assertFalse(summ["class_present"])


class TestNonVacuousFire(unittest.TestCase):
    def test_v3_fixture_fires_survivor(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            src = str(ws / "src")
            _write_df(ws, _v3_fixture(src, cross_writes_active=False))
            summ = _run(ws)
            self.assertTrue(summ["class_present"])
            self.assertIn("tick_liquidity", summ["coupled_groups"])
            self.assertEqual(summ["status"], "survivors")
            self.assertGreaterEqual(summ["obligations_written"], 1)

            surv_fns = {s["fn"] for s in summ["survivors"]}
            # setPosition writes {net,gross} but not active -> partial-update
            self.assertIn("setPosition", surv_fns)
            # cross crosses a tick boundary without re-establishing active
            self.assertIn("cross", surv_fns)

            # collectFees fully couples fee_growth -> NOT a survivor (KEPT)
            self.assertNotIn("collectFees", surv_fns)
            fg = summ["per_group"]["fee_growth"]
            self.assertIn("collectFees", fg["kept_full_update"])
            self.assertEqual(fg["n_partial_update"], 0)

            # tick_liquidity group: full member set has all 3, aggregate missing
            tl = summ["per_group"]["tick_liquidity"]
            self.assertEqual(sorted(tl["full_members"]),
                             ["active_liquidity", "liquidity_gross", "liquidity_net"])
            self.assertGreaterEqual(tl["n_partial_update"], 1)
            self.assertGreaterEqual(tl["n_boundary_cross"], 1)

    def test_survivor_reasons_and_boundary_missing_aggregate(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            src = str(ws / "src")
            _write_df(ws, _v3_fixture(src, cross_writes_active=False))
            emit = ws / ".auditooor" / "amm_structural_manipulation_obligations.jsonl"
            _run(ws)
            rows = [json.loads(l) for l in emit.read_text().splitlines() if l.strip()]
            cross = [r for r in rows if r["function"] == "cross"]
            self.assertEqual(len(cross), 1)
            r = cross[0]
            self.assertEqual(r["schema"], "auditooor.amm_structural_manipulation.v1")
            self.assertIn("boundary-cross", r["survivor_reasons"])
            tl = r["coupled_groups"]["tick_liquidity"]
            self.assertFalse(tl["wrote_aggregate"])
            self.assertIn("active_liquidity", tl["missing_members"])
            self.assertEqual(r["quality_gate_status"], "needs_source")
            self.assertTrue(r["needs_source"])


class TestMutationPair(unittest.TestCase):
    """NON-VACUOUS mutation pair: make the cross() mutator update the FULL coupled
    tick-liquidity group -> its survivor disappears (moves to KEPT)."""

    def test_full_coupled_update_removes_cross_survivor(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            src = str(ws / "src")
            # BASELINE: partial -> cross is a survivor
            _write_df(ws, _v3_fixture(src, cross_writes_active=False))
            base = _run(ws)
            self.assertIn("cross", {s["fn"] for s in base["survivors"]})

            # MUTATION: cross now writes net+gross+active (the full group)
            _write_df(ws, _v3_fixture(src, cross_writes_active=True))
            mut = _run(ws)
            surv = {s["fn"] for s in mut["survivors"]}
            self.assertNotIn("cross", surv)  # survivor DISAPPEARED
            tl = mut["per_group"]["tick_liquidity"]
            self.assertIn("cross", tl["kept_full_update"])
            self.assertEqual(tl["n_boundary_cross"], 0)
            # setPosition (still partial) remains a survivor -> not a vacuous flip
            self.assertIn("setPosition", surv)


if __name__ == "__main__":
    unittest.main(verbosity=2)
