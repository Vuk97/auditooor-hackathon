#!/usr/bin/env python3
"""Regression (Obyte 2026-07-09): the JS/Oscript coverage denominator counted
genuinely non-value-moving JavaScript (ocore infra bots.js/breadcrumbs.js/
event_bus.js, pure helpers int2str/errorToString/opRender, config/CLI .eslintrc.js/
truffle-config.js/find-nonce.js/deploy-*.js), inflating it exactly like the
Solidity bodyless-interface case (Obyte: 391 total, pinned ~56%).

value-moving-functions.py gains a FILE-LEVEL JS/Oscript classifier
(``js_oscript_unit_value_moving_verdict``) that hunt-coverage-gate.py consumes to
EXEMPT positively-non-value-moving JS units from the coverage FRACTION
denominator - the JS/Oscript analog of ``denom_interface_exempt``.

MUTATION-VERIFY, BOTH DIRECTIONS (non-vacuous):
  (A) a value-moving JS unit (balances.js, or ANY infra-NAMED unit whose SOURCE
      shows a value/ledger/asset signal) is NEVER exempted - the anti-rubber-
      stamp guarantee (exempting it would HIDE attack surface).
  (B) a genuinely non-value-moving JS unit (bots.js, int2str.js, .eslintrc.js)
      IS exempted.
A Solidity-only + a Go-only denominator are byte-IDENTICAL (the classifier only
narrows JavaScript; Oscript is fail-open value-moving)."""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "hunt-coverage-gate.py"
VMF = REPO_ROOT / "tools" / "value-moving-functions.py"


def _load_vmf():
    spec = importlib.util.spec_from_file_location("_vmf_test", VMF)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


class JsClassifierUnitTest(unittest.TestCase):
    """Direct unit tests of the classifier function (fast, no subprocess)."""

    def setUp(self):
        self.vmf = _load_vmf()

    def verdict(self, rel, text=None):
        return self.vmf.js_oscript_unit_value_moving_verdict(rel, text)[0]

    # ---- direction (B): genuine infra/config/util -> non-value-moving ----
    def test_infra_module_exempt(self):
        self.assertEqual(self.verdict("src/ocore/bots.js", "function f(){ return httpGet(); }"),
                         "non-value-moving")

    def test_pure_util_exempt(self):
        self.assertEqual(self.verdict("int2str.js", "function int2str(n){ return ''+n; }"),
                         "non-value-moving")
        self.assertEqual(self.verdict("errorToString.js", "module.exports = e => e.message;"),
                         "non-value-moving")

    def test_config_exempt(self):
        self.assertEqual(self.verdict("src/x-aa/.eslintrc.js", "module.exports={};"),
                         "non-value-moving")
        self.assertEqual(self.verdict("truffle-config.js", "module.exports={networks:{}};"),
                         "non-value-moving")

    def test_cli_deploy_exempt(self):
        self.assertEqual(self.verdict("src/x/evm/deploy-contracts.js", "async function main(){}"),
                         "non-value-moving")
        self.assertEqual(self.verdict("src/x-aa/find-nonce.js", "// finds a nonce"),
                         "non-value-moving")

    # ---- direction (A): value-movers are NEVER exempted (anti-rubber-stamp) --
    def test_value_module_kept_by_default(self):
        # balances.js is not in any exempt category -> fail-open value-moving.
        self.assertEqual(self.verdict("src/ocore/balances.js",
                                      "function u(a){ balances[a]=balances[a]+amount; }"),
                         "value-moving")

    def test_infra_named_but_value_source_is_vetoed(self):
        # THE anti-rubber-stamp case: a unit whose NAME matched an exempt
        # category but whose SOURCE shows a value/ledger signal must be KEPT.
        src = "function f(){ var x = balances[addr]; addOutputs(payment); }"
        self.assertEqual(self.verdict("src/ocore/bots.js", src), "value-moving")

    def test_consensus_named_never_exempt(self):
        # a consensus/storage module name is never even categorized as exempt.
        self.assertIsNone(self.vmf._js_nonvaluemoving_category("src/ocore/validation.js"))
        self.assertIsNone(self.vmf._js_nonvaluemoving_category("src/ocore/writer.js"))

    # ---- classifier only narrows JS ----
    def test_solidity_not_applicable(self):
        self.assertEqual(self.verdict("src/Vault.sol", "contract V{}"), "not-applicable")

    def test_go_not_applicable(self):
        self.assertEqual(self.verdict("x/keeper.go", "package x"), "not-applicable")

    def test_oscript_fail_open_value_moving(self):
        self.assertEqual(self.verdict("agent.oscript", "{}"), "value-moving")
        self.assertEqual(self.verdict("src/x/agent.aa", "{}"), "value-moving")


class JsGateIntegrationTest(unittest.TestCase):
    """End-to-end via the gate: the exemption actually narrows the denominator."""

    def _run(self, ws: Path) -> dict:
        r = subprocess.run(
            [sys.executable, str(TOOL), "--workspace", str(ws), "--json"],
            capture_output=True, text=True, timeout=180,
        )
        self.assertTrue(r.stdout, r.stderr)
        return json.loads(r.stdout)

    def test_gate_exempts_infra_keeps_value(self):
        with tempfile.TemporaryDirectory() as t:
            ws = Path(t)
            src = ws / "src"
            src.mkdir(parents=True)
            (src / ".eslintrc.js").write_text("module.exports={};\n")
            (src / "bots.js").write_text("function getBots(){ return http('x'); }\n")
            (src / "balances.js").write_text(
                "function u(a){ balances[a]=balances[a]+amount; return outputs; }\n"
            )
            d = self._run(ws)
            exempt = set(d.get("nonvaluemoving_js_exempt_units") or [])
            # direction (B): infra + config exempted
            self.assertIn(".eslintrc.js", exempt)
            self.assertIn("bots.js", exempt)
            # direction (A): the value-mover is NEVER exempted
            self.assertNotIn("balances.js", exempt)
            self.assertEqual(d.get("nonvaluemoving_js_exempt_count"), 2, d.get("verdict"))

    def test_gate_antirubberstamp_value_source_named_infra(self):
        # a file NAMED like infra (bots.js) but with a value/ledger SOURCE must
        # NOT be exempted - the source value-signal veto keeps it. If this ever
        # exempts, the classifier is hiding attack surface.
        with tempfile.TemporaryDirectory() as t:
            ws = Path(t)
            src = ws / "src"
            src.mkdir(parents=True)
            (src / "bots.js").write_text(
                "function pay(a){ var b = balances[a]; sendPayment(b); }\n"
            )
            d = self._run(ws)
            exempt = set(d.get("nonvaluemoving_js_exempt_units") or [])
            self.assertNotIn("bots.js", exempt)
            self.assertEqual(d.get("nonvaluemoving_js_exempt_count"), 0)

    def test_solidity_and_go_denominator_unchanged(self):
        with tempfile.TemporaryDirectory() as t:
            ws = Path(t)
            src = ws / "src"
            src.mkdir(parents=True)
            (src / "Vault.sol").write_text(
                "pragma solidity ^0.8.0;\ncontract Vault{ mapping(address=>uint) b;\n"
                "  function deposit() external payable { b[msg.sender]+=msg.value; }\n"
                "  function config() external pure returns(uint){ return 1; } }\n"
            )
            (ws / "go.mod").write_text("module x\ngo 1.21\n")
            gx = ws / "x"
            gx.mkdir()
            (gx / "keeper.go").write_text(
                "package x\nfunc (k Keeper) Send(a int) int { return a }\n"
                "func Util() string { return \"s\" }\n"
            )
            d = self._run(ws)
            # classifier only narrows JS -> zero exemptions on a Sol+Go ws.
            self.assertEqual(d.get("nonvaluemoving_js_exempt_count"), 0)


if __name__ == "__main__":
    unittest.main()
