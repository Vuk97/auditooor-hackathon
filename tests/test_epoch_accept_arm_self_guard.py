"""Regression: epoch-restake-replay accept-arm self-guard (2026-07-14).

A DEGRADED / over-broad forward-closure spuriously attaches a module's global
vote/accept nodes (TallyVote, voteBeforeCompletion, ...) to unrelated functions
(axelar: 137 params.go / types.go / CLI fns that never tally a vote, all with
credit_nodes=[]). The accept-only arm must therefore require SELF-accept: a
genuine double-vote / double-sign replay lives IN the accept function itself, so
requiring self-accept drops the spurious survivors WITHOUT false-negating a
genuine accept-replay (the accept fn itself still emits) or the credit arm.
"""
import importlib.util
import pathlib
import unittest

_TOOL = pathlib.Path(__file__).resolve().parent.parent / "tools" / "epoch-restake-replay.py"
_spec = importlib.util.spec_from_file_location("_epoch_rr", _TOOL)
_m = importlib.util.module_from_spec(_spec)
import sys
sys.modules["_epoch_rr"] = _m
_spec.loader.exec_module(_m)


def _fn(name, *, credit=False, accept=False, epoch_key=False, callees=(), go_entry=True):
    f = _m.Fn(name, f"src/{name}.go", 1, "go")
    f.credit = credit
    f.accept = accept
    f.epoch_key = epoch_key
    f.callees = set(callees)
    f.is_go_entry = go_entry
    return f


class EpochAcceptArmSelfGuard(unittest.TestCase):
    def _classify(self, fns_list):
        fns = {f.name: f for f in fns_list}
        return _m.classify(fns, credit_fns=set(), key_guard={})

    def test_spurious_accept_only_non_self_accept_is_dropped(self):
        # A CLI/params fn that (via a degraded closure) reaches a global accept node
        # but is NOT itself an accept, no credit -> must NOT survive.
        keyfn = _fn("GetKeyID", epoch_key=True)
        vote = _fn("TallyVote", accept=True)
        params = _fn("BuildParams", callees=["TallyVote", "GetKeyID"])
        res = self._classify([keyfn, vote, params])
        self.assertNotIn("BuildParams", res["readers"],
                         "non-self-accept fn reaching a global accept via a degraded "
                         "closure must be dropped by the accept-arm self-guard")

    def test_genuine_self_accept_still_emits(self):
        # The accept function ITSELF (self-accept + reaches an epoch key) still emits -
        # a genuine double-vote replay is covered.
        keyfn = _fn("GetKeyID", epoch_key=True)
        vote = _fn("TallyVote", accept=True, callees=["GetKeyID"])
        res = self._classify([keyfn, vote])
        self.assertIn("TallyVote", res["readers"],
                      "self-accept fn must still emit (no false-negative on genuine "
                      "accept-replay)")

    def test_credit_arm_unchanged(self):
        # A transitive-credit entry point (no self-accept) is a legitimate replay
        # entry point and must still emit.
        keyfn = _fn("CalculateAUMFee", epoch_key=True)
        creditee = _fn("_doRequestRedeem", credit=True)
        entry = _fn("requestRedeem", callees=["_doRequestRedeem", "CalculateAUMFee"])
        res = self._classify([keyfn, creditee, entry])
        self.assertIn("requestRedeem", res["readers"],
                      "transitive-credit entry point must still emit (credit arm "
                      "unchanged)")


if __name__ == "__main__":
    unittest.main()
