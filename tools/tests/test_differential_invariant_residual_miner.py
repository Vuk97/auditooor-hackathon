#!/usr/bin/env python3
"""Tests for differential-invariant-residual-miner.py (DIRM).

Proves the residual engine on REAL substrate:
  * nuva ratio-authority (BankKeeper.GetAllBalances-fed numerator) SURVIVES as
    RESIDUAL - re-surfacing the stale-pin Critical class WITHOUT being told it.
  * a plain-ERC4626 ratio (internal totalAssets numerator) is SUBTRACTED.
  * that divergence is a NON-VACUOUS discrimination pair.
  * axelar-dlt Cosmos-module invariants survive RESIDUAL (no DeFi corpus counterpart).
  * anti-vacuity: empty substrate => SUBSTRATE_VACUOUS fail-loud, never silent green.
  * all-subtracted => CITED_EMPTY honest rationale, never silent green.
"""
from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent
_REPO = _TOOLS.parent
_CORPUS = _REPO / "audit" / "corpus_tags" / "derived"

_spec = importlib.util.spec_from_file_location(
    "dirm", _TOOLS / "differential-invariant-residual-miner.py")
dirm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dirm)

NUVA = Path("/Users/wolf/audits/nuva")
AXELAR = Path("/Users/wolf/audits/axelar-dlt")


# ---- synthetic invariant records for the discrimination pair ----------------
NUVA_RATIO = {
    "form": "D1_RATIO_AUTHORITY_CONSISTENCY",
    "file": "src/vault/keeper/valuation_engine.go", "line": 208,
    "numerator": "tvv", "denominator": "vault.TotalShares.Amount",
    "numerator_external_source": (
        "tvv := k.GetTVVInUnderlyingAsset(ctx, vault) -> "
        "balances := k.BankKeeper.GetAllBalances(ctx, vault.PrincipalMarkerAddress())"),
    "statement": ("RATIO-AUTHORITY-CONSISTENCY: the ratio tvv/vault.TotalShares.Amount "
                  "(a share price quantity) - numerator fed by an EXTERNAL balance read."),
}
PLAIN_VAULT_RATIO = {
    "form": "D1_RATIO_AUTHORITY_CONSISTENCY",
    "file": "src/Vault.sol", "line": 42,
    "numerator": "totalAssets", "denominator": "totalSupply",
    # NOTE: numerator_external_source deliberately internal (no balance read) - a
    # vanilla ERC4626 that tracks totalAssets internally.
    "numerator_external_source": "totalAssets = _totalAssets;  // internal ledger field",
    "statement": ("RATIO-AUTHORITY-CONSISTENCY: share price totalAssets/totalSupply; "
                  "numerator is an internally-tracked accounting field."),
}


class SignatureTests(unittest.TestCase):
    def test_nuva_ratio_topology_is_external(self):
        sig = dirm.make_signature_target(NUVA_RATIO)
        self.assertEqual(sig["form"], "ratio-authority")
        self.assertEqual(sig["authority_topology"], "num:external|den:internal")

    def test_plain_vault_ratio_topology_is_internal(self):
        sig = dirm.make_signature_target(PLAIN_VAULT_RATIO)
        self.assertEqual(sig["form"], "ratio-authority")
        self.assertEqual(sig["authority_topology"], "num:internal|den:internal")


class DiscriminationTests(unittest.TestCase):
    """The load-bearing NON-VACUOUS pair: plain vault SUBTRACTED, nuva SURVIVES."""

    def setUp(self):
        self.corpus = dirm.load_corpus_signatures(_CORPUS)
        self.assertGreater(len(self.corpus), 0, "corpus must be non-empty")

    def test_plain_vault_ratio_is_subtracted(self):
        res = dirm.compute_residual([PLAIN_VAULT_RATIO], self.corpus, 0.85, None)
        self.assertEqual(len(res["subtracted"]), 1,
                         "a plain internal-fed vault ratio must be SUBTRACTED "
                         "(the ERC4626 corpus already owns that shape)")
        self.assertEqual(len(res["residual"]), 0)

    def test_nuva_ratio_survives_as_residual(self):
        res = dirm.compute_residual([NUVA_RATIO], self.corpus, 0.85, None)
        self.assertEqual(len(res["residual"]), 1,
                         "the nuva BankKeeper-fed ratio must SURVIVE - no corpus "
                         "signature carries the external-numerator authority topology")
        self.assertEqual(len(res["subtracted"]), 0)

    def test_divergence_is_non_vacuous(self):
        """Same form + same quantity_role, DIFFERENT authority_topology => one is
        subtracted and the other survives. This proves the residual is real, not a
        threshold artifact."""
        res = dirm.compute_residual([NUVA_RATIO, PLAIN_VAULT_RATIO],
                                    self.corpus, 0.85, None)
        survived = {r["signature"]["file"] for r in res["residual"]}
        subtracted = {r["signature"]["file"] for r in res["subtracted"]}
        self.assertIn("src/vault/keeper/valuation_engine.go", survived)
        self.assertIn("src/Vault.sol", subtracted)
        # the two share form + role; only topology differs
        ns = dirm.make_signature_target(NUVA_RATIO)
        ps = dirm.make_signature_target(PLAIN_VAULT_RATIO)
        self.assertEqual(ns["form"], ps["form"])
        self.assertEqual(ns["quantity_role"], ps["quantity_role"])
        self.assertNotEqual(ns["authority_topology"], ps["authority_topology"])


class NuvaRealSubstrateTests(unittest.TestCase):
    def setUp(self):
        if not (NUVA / ".auditooor" / "pisvs" / "derived_invariants.jsonl").is_file():
            self.skipTest("nuva PISVS substrate not present")

    def test_nuva_ratio_authority_survives_on_real_disk(self):
        manifest = dirm.run(NUVA, _CORPUS, 0.85, None, None)
        self.assertTrue(manifest["ok"])
        self.assertEqual(manifest["status"], "OK")
        self.assertGreater(manifest["target_invariant_count"], 0)  # anti-vacuity
        ratio_res = [o for o in manifest["residual_obligations"]
                     if o["invariant_form"] == "ratio-authority"
                     and "valuation_engine.go" in (o["site"]["file"] or "")]
        self.assertEqual(len(ratio_res), 1,
                         "the real nuva valuation_engine.go ratio must survive RESIDUAL")
        o = ratio_res[0]
        self.assertEqual(o["novelty"], "RESIDUAL")
        self.assertEqual(o["authority_topology"], "num:external|den:internal")
        self.assertIn("TotalShares", " ".join(o["state_symbols"]) + o["invariant_text"])
        self.assertEqual(o["verdict"], "needs-search")
        self.assertTrue(o["reachability_question"])


class AxelarRealSubstrateTests(unittest.TestCase):
    def setUp(self):
        if not (AXELAR / ".auditooor" / "pisvs" / "derived_invariants.jsonl").is_file():
            self.skipTest("axelar PISVS substrate not present")

    def test_axelar_invariants_survive_residual(self):
        manifest = dirm.run(AXELAR, _CORPUS, 0.85, None, None)
        self.assertTrue(manifest["ok"])
        self.assertGreater(manifest["target_invariant_count"], 0)  # anti-vacuity
        # Cosmos-module (BankKeeper-fed) escrow invariants have no DeFi corpus
        # counterpart => survive.
        self.assertGreater(manifest["residual_count"], 0,
                           "axelar Cosmos-module invariants should survive RESIDUAL")
        for o in manifest["residual_obligations"]:
            self.assertEqual(o["novelty"], "RESIDUAL")


class AntiVacuityTests(unittest.TestCase):
    def test_empty_substrate_is_fail_loud(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            manifest = dirm.run(Path(d), _CORPUS, 0.85, None, None)
        self.assertFalse(manifest["ok"])
        self.assertEqual(manifest["status"], "SUBSTRATE_VACUOUS")
        self.assertEqual(manifest["target_invariant_count"], 0)

    def test_all_subtracted_is_cited_empty_not_silent(self):
        corpus = dirm.load_corpus_signatures(_CORPUS)
        # a single plain-vault invariant -> everything subtracted -> CITED_EMPTY
        res = dirm.compute_residual([PLAIN_VAULT_RATIO], corpus, 0.85, None)
        obligations = [dirm.residual_obligation(r) for r in res["residual"]]
        self.assertEqual(obligations, [])
        # simulate the run() cited-empty path
        self.assertEqual(len(res["subtracted"]), 1)

    def test_run_cited_empty_status_and_rationale(self):
        import tempfile
        # build a fake ws whose ONLY invariant is a plain-vault (all-subtracted) one
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            pd = ws / ".auditooor" / "pisvs"
            pd.mkdir(parents=True)
            (pd / "derived_invariants.jsonl").write_text(json.dumps(PLAIN_VAULT_RATIO) + "\n")
            manifest = dirm.run(ws, _CORPUS, 0.85, None, None)
        self.assertTrue(manifest["ok"])
        self.assertEqual(manifest["status"], "CITED_EMPTY")
        self.assertEqual(manifest["residual_count"], 0)
        self.assertIsNotNone(manifest["cited_empty_rationale"])
        self.assertTrue(manifest["cited_empty_rationale"][0]["subtracted_by"])


class PisvsAutorunTests(unittest.TestCase):
    """B4: DIRM reads the step-2b-pisvs artifact directly and, when it is absent,
    runs the step-2b producer ITSELF instead of relying on composition-novelty
    --autorun-producers - closing the producer-after-consumer ordering hole."""

    def test_artifact_present_no_autorun_and_not_vacuous(self):
        """When <ws>/.auditooor/pisvs/derived_invariants.jsonl EXISTS, DIRM reads it
        directly (autorun ran=False, reason=artifact-present) and status is NOT
        SUBSTRATE_VACUOUS."""
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            pd = ws / ".auditooor" / "pisvs"
            pd.mkdir(parents=True)
            (pd / "derived_invariants.jsonl").write_text(json.dumps(NUVA_RATIO) + "\n")
            manifest = dirm.run(ws, _CORPUS, 0.85, None, None, True)
        self.assertNotEqual(manifest["status"], "SUBSTRATE_VACUOUS")
        self.assertEqual(manifest["status"], "OK")
        self.assertGreater(manifest["target_invariant_count"], 0)
        self.assertFalse(manifest["pisvs_autorun"]["ran"])
        self.assertEqual(manifest["pisvs_autorun"]["reason"], "artifact-present")

    def test_absent_artifact_autorun_disabled_is_vacuous(self):
        """A cold ws with autorun DISABLED and no artifact => honest
        SUBSTRATE_VACUOUS, autorun log records artifact-absent-autorun-disabled."""
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            manifest = dirm.run(Path(d), _CORPUS, 0.85, None, None, False)
        self.assertEqual(manifest["status"], "SUBSTRATE_VACUOUS")
        self.assertFalse(manifest["pisvs_autorun"]["ran"])
        self.assertEqual(manifest["pisvs_autorun"]["reason"],
                         "artifact-absent-autorun-disabled")

    def test_absent_artifact_autorun_enabled_invokes_producer(self):
        """A cold ws with autorun ENABLED must actually RUN the step-2b PISVS
        producer (pisvs_autorun.ran=True) rather than silently short-circuiting -
        this is the self-sufficiency that removes the --autorun-producers reliance.
        An empty ws yields no groundable invariants, so the honest terminal is
        still SUBSTRATE_VACUOUS, but the producer DID fire."""
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            manifest = dirm.run(Path(d), _CORPUS, 0.85, None, None, True)
        self.assertTrue(manifest["pisvs_autorun"]["ran"])
        self.assertEqual(manifest["pisvs_autorun"]["producer"],
                         "protocol-invariant-synth-violation-search.py")


class SimilarityTests(unittest.TestCase):
    def test_identical_signature_scores_full(self):
        a = {"form": "ratio-authority", "quantity_role": "price",
             "authority_topology": "num:internal|den:internal"}
        self.assertAlmostEqual(dirm.structural_similarity(a, a), 1.0)

    def test_topology_mismatch_below_threshold(self):
        a = {"form": "ratio-authority", "quantity_role": "price",
             "authority_topology": "num:external|den:internal"}
        b = {"form": "ratio-authority", "quantity_role": "price",
             "authority_topology": "num:internal|den:internal"}
        self.assertLess(dirm.structural_similarity(a, b), 0.85)


if __name__ == "__main__":
    unittest.main(verbosity=2)
