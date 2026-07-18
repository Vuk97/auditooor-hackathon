#!/usr/bin/env python3
"""End-to-end (forge-gated) tests for tools/evm-0day-proof-pipeline.py.

These tests AUTHOR + COMPILE + RUN a real Foundry PoC against real in-tree
corpus targets and assert the pipeline returns `proof-backed` only on a genuine
exploit-PASS + control-PASS. They are skipped when forge or the cited workspace
checkout is unavailable, so CI on a clean box stays green; on the engagement
box (forge + ~/audits checkouts present) they enforce the iter6-A capability.

The HONESTY CONTRACT under test: a proof counts ONLY if forge actually compiled
+ ran the authored test AND both the exploit and negative-control tests PASSED.
"""

import importlib.util
import shutil
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location(
    "evm_0day_proof_pipeline", TOOLS / "evm-0day-proof-pipeline.py"
)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)


def _forge_available() -> bool:
    return bool(mod.resolve_forge()) and mod.find_forge_std() is not None


def _corpus_case_runnable(case_id: str) -> bool:
    try:
        cand, ws = mod.load_candidate_from_corpus(case_id)
    except Exception:
        return False
    return ws.exists() and (ws / cand["rel_path"]).exists()


# The three cases proven during iter6-A development.
PROVEN_CASES = [
    "hyperbridge--smt-eth-branch-isempty-value-conflation",   # HELD_OUT pure-library
    "hyperbridge--smt-library-latent-defects-LOW",            # HELD_OUT pure-library
    "hyperbridge--hb-univ3-univ4-wrapper-refund-deployer-MEDIUM",  # TRAIN deployable
]


@unittest.skipUnless(_forge_available(), "forge / forge-std not available")
class TestRealProofE2E(unittest.TestCase):
    def _run_case(self, case_id):
        cand, ws = mod.load_candidate_from_corpus(case_id)
        return mod.run_pipeline(cand, ws, None, do_run=True)

    def test_eth_branch_isempty_proof_backed(self):
        cid = "hyperbridge--smt-eth-branch-isempty-value-conflation"
        if not _corpus_case_runnable(cid):
            self.skipTest("workspace checkout not present")
        r = self._run_case(cid)
        self.assertEqual(r["verdict"], "proof-backed", r.get("reason"))
        self.assertTrue(r["forge_run"]["exploit_pass"])
        self.assertTrue(r["forge_run"]["control_pass"])
        self.assertEqual(r["real_proof_mode"], "pure-library")

    def test_bytes_remove_ending_zero_proof_backed(self):
        cid = "hyperbridge--smt-library-latent-defects-LOW"
        if not _corpus_case_runnable(cid):
            self.skipTest("workspace checkout not present")
        r = self._run_case(cid)
        self.assertEqual(r["verdict"], "proof-backed", r.get("reason"))
        self.assertTrue(r["forge_run"]["exploit_pass"])
        self.assertTrue(r["forge_run"]["control_pass"])

    def test_train_wrapper_refund_proof_backed(self):
        cid = "hyperbridge--hb-univ3-univ4-wrapper-refund-deployer-MEDIUM"
        if not _corpus_case_runnable(cid):
            self.skipTest("workspace checkout not present")
        r = self._run_case(cid)
        self.assertEqual(r["verdict"], "proof-backed", r.get("reason"))
        self.assertEqual(r["candidate"].get("split"), "TRAIN")
        self.assertTrue(r["forge_run"]["exploit_pass"])
        self.assertTrue(r["forge_run"]["control_pass"])
        self.assertEqual(r["real_proof_mode"], "deployable-in-place")

    def test_factory_fee_gap_business_logic_proof_backed(self):
        # iter7-A: a BUSINESS-LOGIC case (dynamic-fee-sentinel validation gap)
        # converted from blocked-with-obligation to a REAL run-backed proof by
        # the factory-fee-domain-validation-gap deploy author. Deploys the REAL
        # StableSwapHooksFactory (ctor only STORES the pool manager) and drives
        # the REAL deploy() with the dynamic-fee sentinel; no protocol-path mock.
        cid = "revert-stableswap-hooks--dynamic-fee-sentinel-medium"
        if not _corpus_case_runnable(cid):
            self.skipTest("workspace checkout not present")
        r = self._run_case(cid)
        self.assertEqual(r["verdict"], "proof-backed", r.get("reason"))
        self.assertEqual(r["candidate"].get("vuln_class"), "business-logic")
        self.assertTrue(r["forge_run"]["exploit_pass"])
        self.assertTrue(r["forge_run"]["control_pass"])
        self.assertFalse(r["forge_run"]["compile_fail"])
        self.assertEqual(r["real_proof_mode"], "deployable-in-place")

    def test_in_place_runner_leaves_no_pollution(self):
        cid = "hyperbridge--hb-univ3-univ4-wrapper-refund-deployer-MEDIUM"
        if not _corpus_case_runnable(cid):
            self.skipTest("workspace checkout not present")
        cand, ws = mod.load_candidate_from_corpus(cid)
        src_file = ws / cand["rel_path"]
        project = mod.find_enclosing_foundry_project(src_file, ws)
        self.assertIsNotNone(project)
        self._run_case(cid)
        # the in-place generated test dir must be removed after the run
        leftover = list((project).rglob("_evm0day_autoproof"))
        self.assertEqual(leftover, [], f"pollution left behind: {leftover}")
        # the factory-fee-gap deploy author must also leave no pollution
        fcid = "revert-stableswap-hooks--dynamic-fee-sentinel-medium"
        if _corpus_case_runnable(fcid):
            fcand, fws = mod.load_candidate_from_corpus(fcid)
            fproj = mod.find_enclosing_foundry_project(
                fws / fcand["rel_path"], fws)
            self._run_case(fcid)
            fleft = list((fproj).rglob("_evm0day_autoproof"))
            self.assertEqual(fleft, [], f"factory pollution left: {fleft}")


if __name__ == "__main__":
    unittest.main()
