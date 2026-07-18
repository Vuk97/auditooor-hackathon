"""Tests for business_flow_decompose.py - the cross-module combination-bug axis."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parents[1] / "business_flow_decompose.py"
_spec = importlib.util.spec_from_file_location("business_flow_decompose", _TOOL)
BF = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(BF)


def _ws(units, sidecars=None):
    ws = Path(tempfile.mkdtemp())
    a = ws / ".auditooor"
    a.mkdir()
    (a / "inscope_units.jsonl").write_text(
        "".join(json.dumps(u) + "\n" for u in units), encoding="utf-8")
    if sidecars:
        sd = a / "hunt_findings_sidecars"
        sd.mkdir()
        for i, fn in enumerate(sidecars):
            (sd / f"h{i}.json").write_text(json.dumps(
                {"function_anchor": {"file": "x.sol", "fn": fn}, "result": {"verdict": "kill"}}))
    return ws


class TestDecompose(unittest.TestCase):
    def test_verb_cluster_spanning_multiple_modules(self):
        ws = _ws([
            {"file": "a/Vault.sol", "function": "deposit"},
            {"file": "b/Router.sol", "function": "deposit"},          # cross-module deposit
            {"file": "c/Acct.sol", "function": "previewDeposit"},
            {"file": "a/Vault.sol", "function": "burn"},              # single burn -> not a flow
        ])
        dec = BF.decompose(ws)
        ids = {f["flow_id"]: f for f in dec["flows"]}
        self.assertIn("BF-asset-lifecycle-deposit", ids)
        self.assertEqual(ids["BF-asset-lifecycle-deposit"]["member_count"], 3)
        # a single-member verb cluster is NOT a flow (per-fn axis covers it)
        self.assertNotIn("BF-asset-lifecycle-burn", ids)

    def test_flow_types_classified(self):
        # each verb-cluster needs >=2 members to be a flow (single fns are the
        # per-fn axis). 'request' x2 -> long-transaction; 'finalize' x2 -> state-machine.
        ws = _ws([
            {"file": "a.sol", "function": "requestRedeem"}, {"file": "b.sol", "function": "requestUnstake"},
            {"file": "a.sol", "function": "finalize"}, {"file": "b.sol", "function": "finalizeWithFee"},
        ])
        types = {f["flow_type"] for f in BF.decompose(ws)["flows"]}
        self.assertIn("long-transaction", types)
        self.assertIn("state-machine", types)

    def test_language_agnostic_go_rust(self):
        ws = _ws([
            {"file": "x/keeper/msg.go", "function": "MsgDeposit"},
            {"file": "y/bank/keeper.go", "function": "Deposit"},
            {"file": "vault/lib.rs", "function": "withdraw"},
            {"file": "router/lib.rs", "function": "withdraw"},
        ])
        ids = {f["flow_id"] for f in BF.decompose(ws)["flows"]}
        self.assertIn("BF-asset-lifecycle-deposit", ids)
        self.assertIn("BF-asset-lifecycle-withdraw", ids)


class TestCoverage(unittest.TestCase):
    def test_undriven_flow_flagged(self):
        ws = _ws(
            [{"file": "a.sol", "function": "deposit"}, {"file": "b.sol", "function": "deposit"}],
            sidecars=[],  # no hunt touched deposit
        )
        rep = BF.coverage(ws)
        self.assertEqual(rep["verdict"], "warn-undriven-flows")
        self.assertIn("BF-asset-lifecycle-deposit", rep["undriven_flows"])

    def test_driven_flow_passes(self):
        ws = _ws(
            [{"file": "a.sol", "function": "deposit"}, {"file": "b.sol", "function": "deposit"}],
            sidecars=["deposit"],  # a hunt touched deposit
        )
        self.assertEqual(BF.coverage(ws)["verdict"], "pass-all-flows-driven")

    def test_no_flows_passes(self):
        ws = _ws([{"file": "a.sol", "function": "getConfig"}])
        self.assertEqual(BF.coverage(ws)["verdict"], "pass-no-flows")

    def test_string_serialized_function_anchor_credited(self):
        # NUVA 2026-07-01: 184/380 hunt sidecars serialized function_anchor as a
        # JSON STRING, not a dict. _hunted_fnkeys read only the dict form and
        # silently dropped them -> business-flow-coverage false-red (burn/sendTokens
        # uncredited). Both string-serialized-dict and bare-string anchors must count.
        ws = _ws([{"file": "a.sol", "function": "deposit"},
                  {"file": "b.sol", "function": "deposit"}])
        sd = ws / ".auditooor" / "hunt_findings_sidecars"
        sd.mkdir()
        # function_anchor stored as a JSON-serialized dict STRING (the NUVA shape)
        (sd / "s0.json").write_text(json.dumps(
            {"function_anchor": json.dumps({"file": "a.sol", "fn": "a.sol::deposit"}),
             "result": {"verdict": "kill"}}))
        self.assertEqual(BF.coverage(ws)["verdict"], "pass-all-flows-driven")

    def test_bare_string_function_anchor_credited(self):
        ws = _ws([{"file": "a.sol", "function": "withdraw"},
                  {"file": "b.sol", "function": "withdraw"}])
        sd = ws / ".auditooor" / "hunt_findings_sidecars"
        sd.mkdir()
        # function_anchor as a bare fn-name string (not JSON) - treat the string as the fn
        (sd / "s0.json").write_text(json.dumps(
            {"function_anchor": "Vault.sol::withdraw", "result": {"verdict": "kill"}}))
        self.assertEqual(BF.coverage(ws)["verdict"], "pass-all-flows-driven")


if __name__ == "__main__":
    unittest.main()
