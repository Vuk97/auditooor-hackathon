#!/usr/bin/env python3
"""GEN-EL5 gas-metering / opcode-repricing fragility screen - regression +
non-vacuity tests.

Pins tools/gas-repricing-fragility-screen.py: a safety/correctness property
that rests on a HARD-CODED gas magic-number (the 2300-stipend transfer/send, a
fixed-gas call, a gasleft() threshold gate, a gas-bounded loop, or a 63/64
forwarding assumption) is repricing-fragile - an EIP-1884/2929/3529-class
hardfork shifts the real cost and invalidates the argument. Rows carry
verdict='needs-fuzz' (advisory, NO-AUTO-CREDIT).

FP-CONTROL matrix (pure fixtures, no external toolchain):
  - fire_transfer_stored.sol : transfer to a STORED addr          -> 1 medium
  - low_transfer_msgsender.sol: payable(msg.sender).transfer      -> 1 low
  - robust_call.sol          : addr.call{value:x}("") recommended -> 0 (SILENT)
  - erc20_transfer.sol       : token.transfer(to, amt) 2-arg      -> 0 (SILENT)
  - fire_fixed_gas.sol       : call{gas: 10000}                   -> 1 fixed-gas
  - fire_gasleft_gate.sol    : require(gasleft() > 100000) refund -> 1 gasleft
  - fire_gas_loop.sol        : while (gasleft() > 50000)          -> 1 gas-loop
  - fire_vyper_send.vy       : Vyper send(self.treasury, amount)  -> 1 (vyper)
  - fire_go_gasmeter.go      : ctx.GasMeter().GasConsumed() > N   -> 1 (go)

Off-by-default: default mode exits 0 even with fired rows (advisory-first);
--strict / env elevates.

Non-vacuity (test_mutate_arg_count_suppressor): neutralise the tool's
single-arg (native vs ERC20) discriminator; the 2-arg ERC20 transfer must then
collapse 0 -> >=1, proving the arg-count suppressor is load-bearing (not a
vacuous always-fire). This mirrors the real-fleet mutation-verify:
lido/stonks/AssetRecoverer.sol `AGENT.call{value:amount}("")` (silent) ->
`AGENT.transfer(amount)` (newly fires transfer-stipend).
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
TOOL = ROOT / "tools" / "gas-repricing-fragility-screen.py"
FX = ROOT / "tools" / "tests" / "fixtures" / "gen_el5"
SIDE_NAME = "gas_repricing_fragility_hypotheses.jsonl"
SCHEMA = "auditooor.gas_repricing_fragility_hypotheses.v1"
STRICT_ENV = "AUDITOOOR_GAS_REPRICING_FRAGILITY_STRICT"


def _load_tool():
    spec = importlib.util.spec_from_file_location("gas_reprice_el5", TOOL)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _scan(tool, fixture: str):
    p = FX / fixture
    return tool.scan_file(p, fixture)


class GenEl5MatrixTest(unittest.TestCase):
    def setUp(self):
        self.tool = _load_tool()

    def test_fire_transfer_stored_medium(self):
        rows = _scan(self.tool, "fire_transfer_stored.sol")
        self.assertEqual(len(rows), 1, [r["excerpt"] for r in rows])
        r = rows[0]
        self.assertEqual(r["capability"], "GEN_EL5")
        self.assertEqual(r["schema"], SCHEMA)
        self.assertEqual(r["gas_construct"], "transfer-stipend")
        self.assertEqual(r["load_bearing_for"], "reentrancy-protection")
        self.assertEqual(r["gas_const"], "2300")
        self.assertEqual(r["severity"], "medium")
        self.assertEqual(r["lang"], "solidity")
        self.assertEqual(r["verdict"], "needs-fuzz")
        self.assertTrue(r["advisory"])
        self.assertFalse(r["auto_credit"])

    def test_low_transfer_msgsender(self):
        # FP-control: a fresh msg.sender withdraw is weak -> severity=low.
        rows = _scan(self.tool, "low_transfer_msgsender.sol")
        self.assertEqual(len(rows), 1, [r["excerpt"] for r in rows])
        self.assertEqual(rows[0]["gas_construct"], "transfer-stipend")
        self.assertEqual(rows[0]["severity"], "low")

    def test_robust_call_silent(self):
        # The recommended `addr.call{value:x}("")` form must NOT fire.
        rows = _scan(self.tool, "robust_call.sol")
        self.assertEqual(len(rows), 0, [r["excerpt"] for r in rows])

    def test_erc20_two_arg_silent(self):
        # ERC20 transfer(to, amt) is NOT a native stipend call -> suppressed.
        rows = _scan(self.tool, "erc20_transfer.sol")
        self.assertEqual(len(rows), 0, [r["excerpt"] for r in rows])

    def test_fire_fixed_gas_call(self):
        rows = _scan(self.tool, "fire_fixed_gas.sol")
        self.assertEqual(len(rows), 1, [r["excerpt"] for r in rows])
        r = rows[0]
        self.assertEqual(r["gas_construct"], "fixed-gas-call")
        self.assertEqual(r["load_bearing_for"], "dos-liveness")
        self.assertEqual(r["gas_const"], "10000")

    def test_fire_gasleft_threshold_refund(self):
        rows = _scan(self.tool, "fire_gasleft_gate.sol")
        self.assertEqual(len(rows), 1, [r["excerpt"] for r in rows])
        r = rows[0]
        self.assertEqual(r["gas_construct"], "gasleft-threshold")
        self.assertEqual(r["load_bearing_for"], "refund")
        self.assertEqual(r["gas_const"], "100000")

    def test_fire_gas_bounded_loop(self):
        rows = _scan(self.tool, "fire_gas_loop.sol")
        self.assertEqual(len(rows), 1, [r["excerpt"] for r in rows])
        self.assertEqual(rows[0]["gas_construct"], "gas-bounded-loop")
        self.assertEqual(rows[0]["gas_const"], "50000")

    def test_fire_vyper_send(self):
        rows = _scan(self.tool, "fire_vyper_send.vy")
        self.assertEqual(len(rows), 1, [r["excerpt"] for r in rows])
        self.assertEqual(rows[0]["lang"], "vyper")
        self.assertEqual(rows[0]["gas_construct"], "transfer-stipend")

    def test_fire_go_gasmeter(self):
        rows = _scan(self.tool, "fire_go_gasmeter.go")
        self.assertEqual(len(rows), 1, [r["excerpt"] for r in rows])
        self.assertEqual(rows[0]["lang"], "go")
        self.assertEqual(rows[0]["gas_construct"], "gasleft-threshold")

    def test_every_row_carries_a_construct_and_anchor(self):
        # FP-control invariant: every fired row is anchored to a gas_construct
        # + a load_bearing_for + a gas_const, never a bare "gas is bad" claim.
        constructs = {"transfer-stipend", "fixed-gas-call", "gasleft-threshold",
                      "gas-bounded-loop", "63-64-forward"}
        lbs = {"reentrancy-protection", "dos-liveness", "refund", "retry"}
        for fx in ("fire_transfer_stored.sol", "fire_fixed_gas.sol",
                   "fire_gasleft_gate.sol", "fire_gas_loop.sol"):
            for r in _scan(self.tool, fx):
                self.assertIn(r["gas_construct"], constructs)
                self.assertIn(r["load_bearing_for"], lbs)
                self.assertTrue(r["gas_const"])
                self.assertIn("EIP", r["why_severity_anchored"])


class GenEl5AdvisoryExitTest(unittest.TestCase):
    """Advisory-first: default exit 0 even with fired rows; --strict elevates.

    Also pins that the workspace scan-tree EXCLUDES test/fixture paths, so we
    stage the fixture into a src/ dir named as production."""

    def _run_ws(self, extra_env=None, strict=False):
        with tempfile.TemporaryDirectory() as td:
            ws = pathlib.Path(td)
            src = ws / "src"
            src.mkdir()
            (src / "FeeVault.sol").write_text(
                (FX / "fire_transfer_stored.sol").read_text())
            argv = [sys.executable, str(TOOL), "--workspace", str(ws)]
            if strict:
                argv.append("--strict")
            env = dict(os.environ)
            env.pop(STRICT_ENV, None)
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
        self.assertEqual(rows[0]["gas_construct"], "transfer-stipend")

    def test_strict_flag_elevates(self):
        rc, rows, out = self._run_ws(strict=True)
        self.assertEqual(rc, 1, out)
        self.assertEqual(len(rows), 1)

    def test_strict_env_elevates(self):
        rc, _rows, out = self._run_ws(extra_env={STRICT_ENV: "1"})
        self.assertEqual(rc, 1, out)


class GenEl5NonVacuityTest(unittest.TestCase):
    """Neutralise the single-arg (native vs ERC20) discriminator; the 2-arg
    ERC20 transfer must then collapse 0 -> >=1, proving the arg-count suppressor
    is load-bearing (not a vacuous always-fire on every `.transfer(`)."""

    def test_mutate_arg_count_suppressor(self):
        tool = _load_tool()
        baseline = tool.scan_file(FX / "erc20_transfer.sol", "erc20_transfer.sol")
        self.assertEqual(len(baseline), 0,
                         "ERC20 2-arg transfer must be silent at baseline")
        # weaken: force every call-arg string to look like a single native arg.
        tool._top_level_args = lambda inner: [inner]
        weakened = tool.scan_file(FX / "erc20_transfer.sol",
                                  "erc20_transfer.sol")
        self.assertGreaterEqual(
            len(weakened), 1,
            "neutralising the arg-count suppressor must make the ERC20 2-arg "
            "transfer newly fire - the single-arg native discriminator is "
            "load-bearing")
        self.assertEqual(weakened[0]["gas_construct"], "transfer-stipend")


class GenEl5FleetMutationVerifyTest(unittest.TestCase):
    """Real-fleet-style byte-level mutation-verify (no repo dependency): a
    robust `STORED.call{value:x}("")` is silent; replacing it with
    `STORED.transfer(x)` (re-introducing the 2300-stipend fragility to a stored
    address) makes the screen newly fire; byte-identical restore is trivial
    (we mutate an in-memory copy). Mirrors the executed verify on
    lido/stonks/AssetRecoverer.sol AGENT.call -> AGENT.transfer."""

    def test_call_to_transfer_mutation_flips_silent_to_fire(self):
        tool = _load_tool()
        robust = (FX / "robust_call.sol").read_text()
        base = tool.scan_file(FX / "robust_call.sol", "robust_call.sol",
                              file_text=robust)
        self.assertEqual(len(base), 0, "robust .call{value} form must be silent")
        mutant = robust.replace(
            '(bool ok, ) = treasury.call{value: amt}("");',
            "treasury.transfer(amt);")
        self.assertIn("treasury.transfer(amt);", mutant)
        fired = tool.scan_file(FX / "robust_call.sol", "robust_call.sol",
                               file_text=mutant)
        self.assertGreaterEqual(len(fired), 1,
                                "mutating .call{value} -> .transfer to a stored "
                                "address must newly fire transfer-stipend")
        self.assertEqual(fired[0]["gas_construct"], "transfer-stipend")
        self.assertEqual(fired[0]["severity"], "medium")


if __name__ == "__main__":
    unittest.main()
