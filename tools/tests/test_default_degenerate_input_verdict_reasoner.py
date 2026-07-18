#!/usr/bin/env python3
"""Regression tests for tools/default-degenerate-input-verdict-reasoner.py
(LOGIC CAPABILITY #6). Proves the CFG-branch-coverage set-difference query
GATES \\ DEGEN_REASONED is:
  - a SET relation whose predicate DISCRIMINATES (a gate WITH a degenerate-input
    branch is KEPT out of the survivor set; a gate WITHOUT is a survivor) - i.e.
    it is NOT the trivial "all gates" answer;
  - NOT a shape (a gate whose body merely CONTAINS a '0' token but never BRANCHES
    on a degenerate value is a survivor; a degenerate reject N hops away in the
    closure correctly KEEPS the gate);
  - scope-aware (a vendored / OOS gate carries no obligation);
  - honest on a degraded substrate (fail-closed on all-degraded).
"""

import importlib.util
import json
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_TOOL = _HERE.parent / "default-degenerate-input-verdict-reasoner.py"
_spec = importlib.util.spec_from_file_location("degen_reasoner", _TOOL)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)


def _rec(fn, file, line, guards, lang="solidity", degraded=False):
    return {
        "schema": "dataflow_path.v1",
        "language": lang,
        "source": {"kind": "param-entrypoint", "fn": fn, "var": "sig",
                   "file": file, "line": line},
        "sink": {"kind": "state-write", "fn": fn, "file": file, "line": line},
        "guard_nodes": [{"file": file, "line": line, "expr": e} for e in guards],
        "degraded": degraded,
    }


class GateClassifierTest(unittest.TestCase):
    def test_verification_verbs_are_gates(self):
        for fn in ("C.verifyProof(bytes)", "C._verifyAML(bytes32,bytes,uint256)",
                   "C.validateSignature(bytes)", "C.isValid(bytes32)",
                   "C.checkQuorum(address[])", "(*pkg.T).AuthenticateVote"):
            self.assertTrue(mod.is_gate(fn), fn)

    def test_setter_noun_validator_is_not_a_gate(self):
        # the load-bearing precision: 'Validator' (a noun) matches the substring
        # 'validat' but is NOT a verification verb; a Set-prefixed mutator is not
        # a verdict gate. This is what kills the cosmos-sdk SetValidator... noise.
        for fn in ("(*keeper.Keeper).SetValidatorSigningInfo",
                   "(*keeper.Keeper).SetLastValidatorPower",
                   "C.getValidator(uint256)", "C.newValidatorSet()"):
            self.assertFalse(mod.is_gate(fn), fn)


class DegenerateBranchPredTest(unittest.TestCase):
    def test_positive_degenerate_branches(self):
        for e in ("signer == address(0)", "amount == 0", "sig.length == 0",
                   "sig.length > 0", "len(signers) == 0", "root != bytes32(0)",
                   "recovered == nil", "recovered.IsZero()", "name == \"\"",
                   "threshold != 0"):
            self.assertTrue(mod.degenerate_branch_pred(e), e)

    def test_non_degenerate_branches(self):
        # a comparison against a non-degenerate quantity, or a plain state read,
        # is NOT a degenerate-input verdict.
        for e in ("balance >= amount", "usedSignatures[messageHash]",
                   "block.timestamp > deadline", "owner == msg.sender",
                   "count == threshold"):
            self.assertFalse(mod.degenerate_branch_pred(e), e)


class SetDifferenceTest(unittest.TestCase):
    """The core: the query DISCRIMINATES - a gate WITH a degenerate branch is
    KEPT (removed from the diff), one WITHOUT survives. NOT the trivial answer."""

    def _run(self, tmp, records):
        ws = tmp / "ws"
        (ws / ".auditooor").mkdir(parents=True)
        # every gate file must exist under the ws root to be in-scope.
        src = ws / "src"
        src.mkdir()
        (src / "G.sol").write_text("// gate\n")
        df = ws / ".auditooor" / "dataflow_paths.jsonl"
        df.write_text("\n".join(json.dumps(r) for r in records))
        return mod.run(["--workspace", str(ws), "--json"]), ws

    def test_kept_vs_survivor_discriminates(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            f = str(tmp / "ws" / "src" / "G.sol")
            recs = [
                # KEPT gate: has a degenerate-reject branch (signer==address(0))
                _rec("Guarded.verifySig(bytes)", f, 10,
                     ["ECDSA.recover(hash,sig) == address(0)", "amount >= min"]),
                # SURVIVOR gate: only a non-degenerate state guard, never branches
                # on a zero/empty/default value.
                _rec("Leaky._verifyAML(bytes32,bytes,uint256)", f, 40,
                     ["usedSignatures[messageHash]"]),
            ]
            summary, ws = self._run(tmp, recs)
            self.assertEqual(summary["size_GATES"], 2)
            self.assertEqual(summary["size_DEGEN_REASONED_among_gates"], 1)
            self.assertEqual(summary["size_DIFF_survivors"], 1)
            self.assertIn("verifySig", summary["kept_gate_with_degenerate_verdict"])
            surv_fns = [s["fn"] for s in summary["survivors"]]
            self.assertEqual(surv_fns, ["_verifyAML"])
            # obligation persisted + shaped for exploit-queue ingest
            obs = [json.loads(l) for l in
                   (ws / ".auditooor" /
                    "degenerate_input_verdict_obligations.jsonl").read_text().splitlines()]
            self.assertEqual(len(obs), 1)
            o = obs[0]
            self.assertEqual(o["schema"], "auditooor.degenerate_input_verdict_gap.v1")
            self.assertEqual(o["function"], "_verifyAML")
            self.assertEqual(o["obligation_type"], "degenerate-input-unverdicted-gate")
            self.assertTrue(o["source_refs"])

    def test_token_present_but_no_branch_is_survivor(self):
        # guard-rail: a gate whose closure predicate MENTIONS a quantity but never
        # forms a degenerate comparison (no operator against 0/empty) must NOT be
        # credited as reasoned -> it survives. Proves this is a BRANCH query, not a
        # token-present scan.
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            f = str(tmp / "ws" / "src" / "G.sol")
            recs = [_rec("C.validateRoot(bytes32)", f, 5,
                         ["merkleRoot", "keccak256(leaf)"])]  # tokens, no 0/empty cmp
            summary, ws = self._run(tmp, recs)
            self.assertEqual(summary["size_DIFF_survivors"], 1)


class ScopeAndDegradeTest(unittest.TestCase):
    def test_vendored_gate_dropped(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            ws = tmp / "ws"
            (ws / ".auditooor").mkdir(parents=True)
            # a gate whose only file is a Go module-cache path is not in-scope
            vend = "/Users/x/go/pkg/mod/cosmos/keeper/verify.go"
            df = ws / ".auditooor" / "dataflow_paths.jsonl"
            df.write_text(json.dumps(
                _rec("(*keeper.K).VerifyVote", vend, 3, [], lang="go")))
            summary = mod.run(["--workspace", str(ws), "--json"])
            self.assertEqual(summary["size_GATES"], 0)

    def test_all_degraded_fail_closed(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            ws = tmp / "ws"
            src = ws / "src"
            src.mkdir(parents=True)
            (ws / ".auditooor").mkdir(parents=True)
            (src / "G.sol").write_text("//\n")
            f = str(src / "G.sol")
            df = ws / ".auditooor" / "dataflow_paths.jsonl"
            df.write_text(json.dumps(
                _rec("C.verifyProof(bytes)", f, 1, [], degraded=True)))
            rc = mod.run(["--workspace", str(ws), "--fail-closed"])
            self.assertEqual(rc, 3)


if __name__ == "__main__":
    unittest.main()
