#!/usr/bin/env python3
"""Tests for push-payment-misroute.py - the recipient-provenance vs intended-owner
reasoning query. Includes a NON-VACUOUS mutation pair: fixing the recipient to the
recorded owner (or converting to a pull pattern) must make the survivor DISAPPEAR.
"""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_TOOL = _HERE.parent / "push-payment-misroute.py"

_spec = importlib.util.spec_from_file_location("push_payment_misroute", _TOOL)
ppm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ppm)


def _run(src_files: dict) -> dict:
    """Write src_files ({relpath: content}) into a temp ws/src and run the tool,
    returning the parsed summary dict."""
    td = tempfile.mkdtemp()
    ws = Path(td)
    src = ws / "src"
    src.mkdir(parents=True, exist_ok=True)
    for rel, content in src_files.items():
        p = src / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    emit = ws / "out.jsonl"
    return ppm.run(["--workspace", str(ws), "--emit", str(emit), "--json"])


# ---- Fixtures ---------------------------------------------------------------

# A refund that credits msg.sender while a recorded depositor exists = mismatch.
# Uses Address.sendValue (a checked, payable-verified push) so the ONLY surviving
# arm is the wrong-recipient provenance mismatch, isolating mutation A.
_SOL_WRONG_RECIPIENT = """
contract Escrow {
    mapping(uint => address) public depositor;
    mapping(uint => uint) public amount;
    function refund(uint id) external {
        uint amt = amount[id];
        amount[id] = 0;
        // BUG: refunds the caller, not the recorded depositor of THIS deposit
        Address.sendValue(payable(msg.sender), amt);
    }
}
"""

# The FIX (mutation A): route the refund to the recorded depositor.
_SOL_FIXED_RECIPIENT = """
contract Escrow {
    mapping(uint => address) public depositor;
    mapping(uint => uint) public amount;
    function refund(uint id) external {
        uint amt = amount[id];
        amount[id] = 0;
        // FIX: refund the recorded depositor
        Address.sendValue(payable(depositor[id]), amt);
    }
}
"""

# The FIX (mutation B): convert to a pull pattern (credited balance withdraw).
_SOL_PULL_PATTERN = """
contract Escrow {
    mapping(uint => address) public depositor;
    mapping(address => uint) public pendingWithdrawals;
    function withdraw() external {
        uint amt = pendingWithdrawals[msg.sender];
        pendingWithdrawals[msg.sender] = 0;
        Address.sendValue(payable(msg.sender), amt);
    }
}
"""

# Unverified-payable push: low-level call{value} with no success check, no pull.
_SOL_UNVERIFIED_PUSH = """
contract Payout {
    address public beneficiary;
    function pay(uint amt) external {
        // BUG: push via transfer to a possibly-non-payable stored receiver, no
        // pull-fallback, no payable verification
        payable(winnerReceiver).transfer(amt);
    }
    address public winnerReceiver;
}
"""

# A pure math library with no value delivery at all -> honest cited-empty.
_SOL_NO_SINK = """
contract MathLib {
    function add(uint a, uint b) internal pure returns (uint) { return a + b; }
    function mulDiv(uint a, uint b, uint c) internal pure returns (uint) {
        return a * b / c;
    }
}
"""

# Go cosmos payout to a recorded originator = correctly routed (TRACED, kept).
_GO_TRACED = """
package keeper
func (k Keeper) Refund(ctx Context, id uint64) error {
    originator := k.GetOriginator(ctx, id)
    amt := k.GetAmount(ctx, id)
    return k.bank.SendCoins(ctx, k.moduleAddr, originator, amt)
}
"""


class TestPushPaymentMisroute(unittest.TestCase):

    def test_wrong_recipient_is_survivor(self):
        s = _run({"Escrow.sol": _SOL_WRONG_RECIPIENT})
        self.assertGreaterEqual(s["size_value_delivery_sinks"], 1)
        self.assertEqual(s["size_survivors"], 1)
        surv = s["survivors"][0]
        self.assertEqual(surv["fn"], "refund")
        self.assertIn("wrong-recipient", surv["reasons"])

    def test_mutation_fix_recipient_removes_survivor(self):
        """NON-VACUOUS mutation A: routing to the recorded depositor kills it."""
        before = _run({"Escrow.sol": _SOL_WRONG_RECIPIENT})
        after = _run({"Escrow.sol": _SOL_FIXED_RECIPIENT})
        self.assertEqual(before["size_survivors"], 1)
        # the recipient now provenance-traces to the recorded owner -> no mismatch.
        wrong = [x for x in after["survivors"]
                 if "wrong-recipient" in x["reasons"]]
        self.assertEqual(len(wrong), 0,
                         "fixing recipient to recorded owner must remove the "
                         "wrong-recipient survivor")
        self.assertGreaterEqual(after["size_recipient_provenance_traced"], 1)

    def test_mutation_pull_pattern_removes_survivor(self):
        """NON-VACUOUS mutation B: a pull pattern (caller withdraws own credited
        balance) is not a misroute."""
        after = _run({"Escrow.sol": _SOL_PULL_PATTERN})
        wrong = [x for x in after["survivors"]
                 if "wrong-recipient" in x["reasons"]]
        self.assertEqual(len(wrong), 0,
                         "a pull pattern must not be flagged as wrong-recipient")

    def test_unverified_payable_push_survivor(self):
        s = _run({"Payout.sol": _SOL_UNVERIFIED_PUSH})
        reasons = [r for x in s["survivors"] for r in x["reasons"]]
        self.assertIn("unverified-payable-push", reasons)

    def test_honest_empty_when_no_sink(self):
        s = _run({"MathLib.sol": _SOL_NO_SINK})
        self.assertGreater(s["n_functions_indexed"], 0)
        self.assertFalse(s["class_present"])
        self.assertEqual(s["size_survivors"], 0)
        self.assertTrue(s["honest_empty_class_not_present"])

    def test_traced_go_payout_is_kept_not_survivor(self):
        s = _run({"refund.go": _GO_TRACED})
        wrong = [x for x in s["survivors"]
                 if "wrong-recipient" in x["reasons"]]
        self.assertEqual(len(wrong), 0,
                         "payout to a recorded originator must be TRACED/kept")

    def test_fail_closed_on_vacuous_substrate(self):
        td = tempfile.mkdtemp()
        ws = Path(td)
        (ws / "src").mkdir()
        rc = ppm.run(["--workspace", str(ws),
                      "--emit", str(ws / "o.jsonl"), "--fail-closed"])
        self.assertEqual(rc, 3)

    def test_obligation_schema_written(self):
        td = tempfile.mkdtemp()
        ws = Path(td)
        src = ws / "src"
        src.mkdir()
        (src / "Escrow.sol").write_text(_SOL_WRONG_RECIPIENT, encoding="utf-8")
        emit = ws / "obl.jsonl"
        ppm.run(["--workspace", str(ws), "--emit", str(emit)])
        rows = [json.loads(l) for l in emit.read_text().splitlines() if l.strip()]
        self.assertEqual(len(rows), 1)
        r = rows[0]
        self.assertEqual(r["schema"], "auditooor.push_payment_misroute.v1")
        self.assertEqual(r["quality_gate_status"], "needs_source")
        self.assertTrue(r["advisory_only"])
        self.assertIn("RECIPIENT_PROVENANCE", " ".join(r["falsification_requirements"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
