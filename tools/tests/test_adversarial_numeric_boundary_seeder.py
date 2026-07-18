"""Regression tests for tools/adversarial-numeric-boundary-seeder.py (LOGIC #8).

Proves the numeric-domain boundary DERIVATION + the NEEDED\\SEEDED set-difference
over the owned dataflow backend - NOT a token match:
  1. a guard COMPARISON on the parameter is PARSED into a partition point and
     emitted with off-by-one neighbours (int literal -> {T-1,T,T+1}; symbolic
     threshold -> symbolic +-1 exprs) - interval reasoning, not a substring test;
  2. type-lattice EXTREMAL seeds are DERIVED from the signature width/signedness
     (uint256 -> {0,1,MAX,MAX-1}; intN adds {MIN,MIN+1});
  3. the fixed-point FINGERPRINT is a NUMERIC predicate on the constant VALUE
     (1e18 / 2**96 are scales; a random 12345 is not) -> fixed-point tier + scale
     +-1 + mul-overflow point MAX/scale;
  4. a tick-range edge literal (+-887272) fingerprints the tick tier + edge +-1;
  5. the ENFORCE answer is a SET-DIFFERENCE: a unit with a mutation-verified
     boundary seed in the verified ledger is SEEDED and is NOT emitted; an
     unseeded unit is a SURVIVOR and IS emitted as an obligation;
  6. a non-numeric (address) param that only reaches a bare state-write does NOT
     qualify (no obligation) - membership is a numeric property, not a name;
  7. a fully DEGRADED substrate yields an empty result + warning; --fail-closed
     exits 3; vendored / out-of-workspace files never carry an obligation.
"""
import importlib.util
import json
import unittest
from pathlib import Path
import tempfile
import shutil

_MOD_PATH = Path(__file__).resolve().parents[1] / "adversarial-numeric-boundary-seeder.py"
_spec = importlib.util.spec_from_file_location("nbs", _MOD_PATH)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)


def _rec(lang, entry_fn, entry_file, sink_kind, guard_exprs, *, var="amount",
         line=10, degraded=False):
    return {
        "schema": "dataflow_path.v1",
        "language": lang,
        "direction": "backward",
        "degraded": degraded,
        "source": {"kind": "param-entrypoint", "fn": entry_fn,
                   "file": entry_file, "line": line, "var": var},
        "sink": {"kind": sink_kind, "callee": "X",
                 "fn": entry_fn, "file": entry_file, "line": line + 5},
        "hops": [],
        "guard_nodes": [{"file": entry_file, "line": line + 1, "expr": e}
                        for e in guard_exprs],
    }


class NumericBoundarySeederTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.ws = self.tmp / "ws"
        (self.ws / ".auditooor").mkdir(parents=True)
        (self.ws / "src").mkdir(parents=True)
        self.sol = str(self.ws / "src" / "Vault.sol")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, records):
        df = self.ws / ".auditooor" / "dataflow_paths.jsonl"
        with df.open("w", encoding="utf-8") as fh:
            for r in records:
                fh.write(json.dumps(r) + "\n")

    def _run(self, extra=None):
        argv = ["--workspace", str(self.ws), "--json"] + (extra or [])
        return mod.run(argv)

    def _seeds(self):
        p = self.ws / ".auditooor" / "numeric_boundary_seeds.jsonl"
        return [json.loads(l) for l in p.read_text().splitlines() if l.strip()]

    def _obs(self):
        p = self.ws / ".auditooor" / "numeric_boundary_obligations.jsonl"
        return [json.loads(l) for l in p.read_text().splitlines() if l.strip()]

    # --- 1. guard partition point derivation ---------------------------------
    def test_guard_int_literal_partition_points(self):
        self._write([_rec("solidity", "Vault.deposit(uint256)", self.sol,
                          "value-move", ["amount == 100"])])
        self._run()
        vals = {s["value"] for s in self._seeds() if s["origin"] == "guard-boundary"}
        self.assertLessEqual({"99", "100", "101"}, vals)  # T-1, T, T+1

    def test_guard_symbolic_threshold(self):
        self._write([_rec("solidity", "Vault.setFee(uint256)", self.sol,
                          "value-move", ["newFee > MAX_ROUTER_FEE"], var="newFee")])
        self._run()
        vals = {s["value"] for s in self._seeds()
                if s["origin"] == "guard-boundary-symbolic"}
        self.assertIn("MAX_ROUTER_FEE", vals)
        self.assertIn("(MAX_ROUTER_FEE) - 1", vals)
        self.assertIn("(MAX_ROUTER_FEE) + 1", vals)

    # --- 2. type-lattice extremal derivation ---------------------------------
    def test_type_extremal_uint256(self):
        self._write([_rec("solidity", "Vault.deposit(uint256)", self.sol,
                          "value-move", ["amount == 0"])])
        self._run()
        ex = {s["value"] for s in self._seeds() if s["origin"] == "type-extremal"}
        self.assertIn("0", ex)
        self.assertIn("1", ex)
        self.assertIn(str((1 << 256) - 1), ex)  # uint256 max, derived not matched

    def test_type_extremal_signed_int_has_min(self):
        dom = mod.infer_type_domain("Pool.f(int128)", "solidity")
        seeds = {s["value"] for s in mod.type_extremal_seeds(dom)}
        self.assertIn(str(-(1 << 127)), seeds)      # int128 min
        self.assertIn(str((1 << 127) - 1), seeds)   # int128 max

    # --- 3. fixed-point fingerprint is a numeric VALUE predicate -------------
    def test_scale_value_predicate(self):
        self.assertEqual(mod._scale_value_of("1e18"), 10 ** 18)
        self.assertEqual(mod._scale_value_of("2**96"), 2 ** 96)
        self.assertEqual(mod._scale_value_of(str(10 ** 18)), 10 ** 18)
        self.assertIsNone(mod._scale_value_of("12345"))   # not a scale
        self.assertIsNone(mod._scale_value_of("2**7"))    # too small to be FP

    def test_fixed_point_tier_and_overflow_point(self):
        self._write([_rec("solidity", "Math.mulWad(uint256)", self.sol,
                          "value-move", ["amount > 1e18"])])
        res = self._run()
        self.assertIn("fixed-point", res["tiers"])
        origins = {s["origin"] for s in self._seeds()}
        self.assertIn("fixed-point-scale", origins)
        self.assertIn("fixed-point-overflow", origins)
        # mul-overflow point MAX/scale is DERIVED
        ov = ((1 << 256) - 1) // (10 ** 18)
        vals = {s["value"] for s in self._seeds()}
        self.assertIn(str(ov), vals)

    # --- 4. tick fingerprint --------------------------------------------------
    def test_tick_tier_edges(self):
        self._write([_rec("solidity", "Pool.getSqrtRatioAtTick(int24)", self.sol,
                          "value-move", ["tick >= -887272"], var="tick")])
        res = self._run()
        self.assertTrue(any("tick" in t for t in res["tiers"]))
        vals = {s["value"] for s in self._seeds() if s["origin"] == "tick-boundary"}
        self.assertIn("887272", vals)
        self.assertIn("-887272", vals)

    # --- 5. NEEDED \ SEEDED set-difference ------------------------------------
    def test_set_difference_seeded_unit_not_emitted(self):
        fn = "Vault.deposit(uint256)"
        self._write([_rec("solidity", fn, self.sol, "value-move", ["amount == 0"])])
        # first pass: unseeded -> survivor obligation
        self._run()
        self.assertEqual(len(self._obs()), 1)
        # now record a mutation-verified boundary seed for the unit
        ver = self.ws / ".auditooor" / "numeric_boundary_seeds_verified.jsonl"
        ver.write_text(json.dumps({
            "function_signature": fn, "param": "amount",
            "mutation_verified": True}) + "\n")
        res = self._run()
        self.assertEqual(res["size_SEEDED"], 1)
        self.assertEqual(res["size_DIFF_survivors"], 0)  # SEEDED removed from diff
        self.assertEqual(len(self._obs()), 0)

    # --- 6. non-numeric address param does not qualify ------------------------
    def test_address_param_no_obligation(self):
        self._write([_rec("solidity", "Vault.setOwner(address)", self.sol,
                          "state-write", [], var="newOwner")])
        res = self._run()
        self.assertEqual(res["size_DIFF_survivors"], 0)
        self.assertEqual(len(self._obs()), 0)

    def test_amount_name_needs_value_sink(self):
        # amount-lexicon var but only a bare state-write (config setter) -> no
        # qualification via the name path (avoids the config-setter flood).
        self._write([_rec("solidity", "Vault.setMaxRate(uint256)", self.sol,
                          "state-write", [], var="rate")])
        res = self._run()
        self.assertEqual(len(self._obs()), 0)
        # same var reaching a value-move DOES qualify
        self._write([_rec("solidity", "Vault.withdraw(uint256)", self.sol,
                          "value-move", [], var="rate")])
        res = self._run()
        self.assertEqual(len(self._obs()), 1)

    # --- 7. degraded substrate + fail-closed + vendored exclusion -------------
    def test_degraded_substrate_fail_closed(self):
        self._write([_rec("solidity", "Vault.deposit(uint256)", self.sol,
                          "value-move", ["amount == 0"], degraded=True)])
        rc = mod.run(["--workspace", str(self.ws), "--fail-closed"])
        self.assertEqual(rc, 3)

    def test_vendored_file_excluded(self):
        vend = "/Users/wolf/go/pkg/mod/cosmos-sdk/keeper.go"
        self._write([_rec("go", "(*Keeper).Send(math.Int)", vend, "value-move",
                          ["amt == 0"], var="amt")])
        res = self._run()
        self.assertEqual(len(self._obs()), 0)


if __name__ == "__main__":
    unittest.main()
