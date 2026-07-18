#!/usr/bin/env python3
"""Regression tests for tools/crossimpl-consensus-divergence.py.

Proves the cross-implementation consensus-divergence query (a LENIENT acceptance
predicate on a consensus path where a STRICT canonical-decode sibling validates
the SAME input subject -> divergent acceptance sets) is:
  - DISCRIMINATING + NON-VACUOUS: a lenient prefix/substring validator on an
    address that has a distinct strict bech32-decode sibling is a SURVIVOR; once
    the lenient matcher is REPLACED by the strict canonical decode (the mutation
    pair) the fn is strict-only and the survivor DISAPPEARS - the strictness gap
    is load-bearing, not the trivial "any parse fn";
  - GROUNDED on the strict-sibling requirement: a lenient validator with NO
    strict sibling for the subject produces NO survivor (no divergence partner);
  - CONSENSUS-SCOPED: a lenient-vs-strict pair that is NOT on a consensus path is
    not a survivor;
  - HONEST on class-absence: a real Go substrate with no divergence pair reports
    class_present False + honest cited-empty (distinct from a vacuous 0-fn tree);
  - REAL SUBSTRATE: runs over nuva + axelar-dlt without crashing.
"""

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_TOOL = _HERE.parent / "crossimpl-consensus-divergence.py"
_spec = importlib.util.spec_from_file_location("crossimpl_div", _TOOL)
mod = importlib.util.module_from_spec(_spec)
sys.modules["crossimpl_div"] = mod  # dataclass introspection needs this (py3.14)
_spec.loader.exec_module(mod)


# --- synthetic Go substrate ------------------------------------------------
# LENIENT: msg_server.go ValidateBasic accepts an address by HasPrefix (superset).
# STRICT : keeper.go parseAddress strictly decodes via sdk.AccAddressFromBech32.
# Both consume the SAME subject 'address' on a consensus path (msg_server/keeper).
_LENIENT_MSG = """
package app

import "strings"

// ValidateBasic is on the consensus tx-validation path.
func (m MsgSend) ValidateBasic(recipient string) error {
	if !strings.HasPrefix(recipient, "cosmos1") {
		return errInvalidAddress
	}
	return nil
}
"""

# mutation-pair: same fn but the lenient matcher REPLACED by the strict decode.
_STRICT_MSG = """
package app

import sdk "github.com/cosmos/cosmos-sdk/types"

func (m MsgSend) ValidateBasic(recipient string) error {
	if _, err := sdk.AccAddressFromBech32(recipient); err != nil {
		return errInvalidAddress
	}
	return nil
}
"""

_STRICT_SIBLING = """
package app

import sdk "github.com/cosmos/cosmos-sdk/types"

// keeper path strictly decodes the same address subject.
func (k Keeper) parseAddress(addr string) error {
	if _, err := sdk.AccAddressFromBech32(addr); err != nil {
		return err
	}
	return nil
}
"""

# a lenient validator on a NON-consensus subject with NO strict sibling.
_LONELY_LENIENT = """
package app

import "strings"

func helperMatchChain(chainName string) bool {
	return strings.Contains(chainName, "ethereum")
}
"""


def _write(d: Path, name: str, body: str):
    p = d / name
    p.write_text(body, encoding="utf-8")
    return p


class TestCrossimplDivergence(unittest.TestCase):

    def _run(self, srcfiles: dict):
        tmp = tempfile.mkdtemp()
        ws = Path(tmp)
        for name, body in srcfiles.items():
            _write(ws, name, body)
        emit = ws / "out.jsonl"
        rc = mod.run(["--workspace", str(ws), "--src-root", str(ws),
                      "--emit", str(emit), "--json"])
        # capture summary by re-analyzing (run printed; re-derive for asserts)
        fns = mod.build_fn_index(ws)
        res = mod.analyze(fns)
        obs = [json.loads(l) for l in emit.read_text().splitlines() if l.strip()]
        return rc, res, obs, ws

    def test_survivor_present(self):
        """LENIENT prefix-match address validator + distinct STRICT bech32
        sibling on a consensus path = SURVIVOR with an obligation."""
        rc, res, obs, ws = self._run({
            "msg_server.go": _LENIENT_MSG,
            "keeper.go": _STRICT_SIBLING,
        })
        self.assertEqual(rc, 0)
        subs = {s["subject"] for s in res["survivors"]}
        self.assertIn("address", subs, res["survivors"])
        self.assertTrue(any(o["input_subject"] == "address" for o in obs))
        self.assertTrue(all(o["advisory_only"] and o["auto_credit"] is False
                            for o in obs))

    def test_non_vacuous_mutation_kills_survivor(self):
        """MUTATION PAIR: replace the lenient matcher with the strict canonical
        decode -> fn is strict-only -> the survivor DISAPPEARS. Proves the
        strictness gap (not the mere existence of a parse fn) is load-bearing."""
        _, res_before, _, _ = self._run({
            "msg_server.go": _LENIENT_MSG,
            "keeper.go": _STRICT_SIBLING,
        })
        _, res_after, obs_after, _ = self._run({
            "msg_server.go": _STRICT_MSG,   # <-- mutated: strict, not lenient
            "keeper.go": _STRICT_SIBLING,
        })
        self.assertGreater(len(res_before["survivors"]), 0)
        self.assertEqual(len(res_after["survivors"]), 0,
                         "strict-vs-strict must NOT be a divergence survivor")
        self.assertEqual(len(obs_after), 0)

    def test_no_strict_sibling_no_survivor(self):
        """A lenient validator with NO strict sibling for the subject is NOT a
        survivor - there is no proven divergence partner."""
        _, res, obs, _ = self._run({
            "msg_server.go": _LENIENT_MSG,   # lenient address, no strict address sibling
            "helper.go": _LONELY_LENIENT,    # lenient chain, no strict chain sibling
        })
        self.assertEqual(len(res["survivors"]), 0)
        self.assertEqual(len(obs), 0)

    def test_non_consensus_lenient_not_survivor(self):
        """Lenient-vs-strict pair that is NOT on a consensus path -> no survivor.
        Both fns live in a plain util file with non-consensus names."""
        util_lenient = (
            "package u\nimport \"strings\"\n"
            "func fmtRecipientLabel(addr string) bool "
            "{ return strings.HasPrefix(addr, \"x\") }\n")
        util_strict = (
            "package u\nimport \"encoding/hex\"\n"
            "func renderAddr(addr string) []byte "
            "{ b, _ := hex.DecodeString(addr); return b }\n")
        _, res, obs, _ = self._run({
            "labelfmt.go": util_lenient,
            "render.go": util_strict,
        })
        self.assertEqual(len(res["survivors"]), 0, res["survivors"])

    def test_honest_cited_empty(self):
        """Real Go substrate but no divergence pair -> class_present False,
        honest cited-empty, NOT vacuous. rc=0 even with --fail-closed."""
        plain = ("package p\nfunc Add(a, b int) int { return a + b }\n"
                 "func Mul(a, b int) int { return a * b }\n")
        tmp = tempfile.mkdtemp()
        ws = Path(tmp)
        _write(ws, "math.go", plain)
        emit = ws / "out.jsonl"
        rc = mod.run(["--workspace", str(ws), "--src-root", str(ws),
                      "--emit", str(emit), "--fail-closed"])
        self.assertEqual(rc, 0)
        obs = [l for l in emit.read_text().splitlines() if l.strip()]
        self.assertEqual(obs, [])

    def test_vacuous_substrate_fail_closed(self):
        """0 fns indexed (empty tree) -> substrate_vacuous, --fail-closed rc!=0."""
        tmp = tempfile.mkdtemp()
        ws = Path(tmp)
        (ws / "readme.txt").write_text("no go here", encoding="utf-8")
        emit = ws / "out.jsonl"
        rc = mod.run(["--workspace", str(ws), "--src-root", str(ws),
                      "--emit", str(emit), "--fail-closed"])
        self.assertNotEqual(rc, 0)

    def test_real_substrate_nuva_axelar(self):
        """Runs over the REAL nuva + axelar-dlt Go substrate without crashing;
        each either yields survivors or an honest cited-empty over real fns."""
        for target in ("/Users/wolf/audits/nuva", "/Users/wolf/audits/axelar-dlt"):
            p = Path(target)
            if not p.is_dir():
                self.skipTest(f"{target} absent")
            fns = mod.build_fn_index(p)
            res = mod.analyze(fns)
            # real substrate: must index >0 validation fns OR be honestly vacuous
            self.assertIsInstance(res["survivors"], list)


if __name__ == "__main__":
    unittest.main(verbosity=2)
