#!/usr/bin/env python3
"""Tests for tools/novelty-gate-flywheel.py.

Covers:
  - KNOWN branch: a candidate whose derived invariant clearly overlaps a corpus
    class (erc4626 share skew) is labeled KNOWN and matched to that class.
  - NOVEL branch (the non-vacuity case that matters): a synthetic candidate
    whose tokens overlap NO corpus class and NO prior audit is labeled NOVEL,
    priority HIGHEST, and MINTS a new-class + burndown-feed record.
  - Non-vacuity guards: 0 candidates and 0 classes are hard failures.
"""
import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
TOOL = ROOT / "tools" / "novelty-gate-flywheel.py"

spec = importlib.util.spec_from_file_location("ngf", TOOL)
ngf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ngf)


class NoveltyGateTest(unittest.TestCase):
    def setUp(self):
        self.classes = ngf.load_taxonomy(ngf.DEFAULT_TAXONOMY)
        self.assertGreater(len(self.classes), 0, "taxonomy must load classes")

    def _run(self, candidates, prior_words=None):
        return ngf.classify(
            candidates, self.classes, prior_words or set(),
            match_threshold=3, prior_threshold=2)

    def test_known_candidate_matches_corpus_class(self):
        cand = [{
            "invariant_id": "vcis-deposit-0",
            "statement": ("derived conservation invariant on deposit: erc4626 "
                          "first depositor share inflation skew vault"),
            "property_form": "solvency-floor",
            "tokens": ["shareToken", "vault", "erc4626", "deposit"],
            "function": "deposit",
            "target": "src/NuvaVault.sol:120",
            "source_lane": "vcis",
        }]
        verdicts, novel, feed = self._run(cand)
        self.assertEqual(verdicts[0]["label"], "KNOWN")
        self.assertIsNotNone(verdicts[0]["matched_class"])
        self.assertEqual(len(novel), 0)
        self.assertEqual(len(feed), 0)

    def test_novel_candidate_no_corpus_match_mints_class(self):
        # tokens deliberately overlap NO corpus keyword/class vocabulary
        cand = [{
            "invariant_id": "vcis-chronoflux-0",
            "statement": ("derived chronoflux invariant on quantumEntangledEpoch: "
                          "warpDriftLedger equals hyperbolicManifold"),
            "property_form": "chronoflux-monotone",
            "tokens": ["quantumEntangledEpoch", "warpDriftLedger",
                       "hyperbolicManifold"],
            "function": "warpSettle",
            "target": "src/Chrono.sol:7",
            "source_lane": "vcis",
        }]
        verdicts, novel, feed = self._run(cand)
        self.assertEqual(verdicts[0]["label"], "NOVEL",
                         msg=f"expected NOVEL, got {verdicts[0]}")
        self.assertEqual(verdicts[0]["priority"], "HIGHEST")
        self.assertIsNone(verdicts[0]["matched_class"])
        # flywheel: a new corpus-class record + burndown feed row emitted
        self.assertEqual(len(novel), 1)
        self.assertEqual(novel[0]["schema"], "auditooor.novel_class.v1")
        self.assertEqual(novel[0]["class_id"], verdicts[0]["minted_class_id"])
        self.assertEqual(len(feed), 1)
        self.assertEqual(feed[0]["action"], "add-corpus-class")

    def test_prior_audit_demotes_novel_to_known(self):
        # prior audit already named these DISTINCTIVE symbols (camelCase) -> a
        # candidate reusing >=2 of them is not "novel" even w/o a corpus class.
        cand = [{
            "invariant_id": "vcis-zzz-0",
            "statement": "derived zzq invariant on flarbNixLedger wobbleGronkPool",
            "property_form": "flarb-monotone",
            "tokens": ["flarbNixLedger", "wobbleGronkPool", "plimForpVault"],
            "function": "flarbNixLedger",
            "target": "src/Z.sol:1",
            "source_lane": "vcis",
        }]
        prior = {"flarbnixledger", "wobblegronkpool", "plimforpvault"}
        verdicts, novel, feed = self._run(cand, prior_words=prior)
        self.assertEqual(verdicts[0]["label"], "KNOWN")
        self.assertEqual(verdicts[0]["matched_class"], "prior-audit")
        self.assertEqual(len(novel), 0)

    def test_prior_audit_prose_overlap_does_not_demote(self):
        # a NOVEL candidate must NOT be demoted just because generic English
        # prose words overlap the (huge) prior-audit text - the 76/89 over-match
        # the nuva proof exposed. Prior dedup keys on distinctive symbols only.
        cand = [{
            "invariant_id": "vcis-chrono-1",
            "statement": ("derived toroidal-flux invariant on quantumEntangledEpoch "
                          "warpDriftLedger equals hyperbolicManifold"),
            "property_form": "toroidal-flux-monotone",
            "tokens": ["quantumEntangledEpoch", "warpDriftLedger",
                       "hyperbolicManifold"],
            "function": "warpSettle",
            "target": "src/Synthetic.sol:7",
            "source_lane": "vcis",
        }]
        # prior audit shares only common prose, none of the candidate's symbols
        prior = {"balanceof", "totalshares", "protocol", "deposit"}
        verdicts, novel, feed = self._run(cand, prior_words=prior)
        self.assertEqual(verdicts[0]["label"], "NOVEL")
        self.assertEqual(len(novel), 1)

    def test_zero_candidates_is_hard_failure(self):
        with self.assertRaises(SystemExit):
            ngf.main(["/tmp/does-not-exist-ws-xyz"])

    def test_cli_json_on_synthetic_ws(self, ):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            cpath = ws / "cands.jsonl"
            cpath.write_text(
                json.dumps({"invariant_id": "c1",
                            "statement": "quantumEntangledEpoch warpDriftLedger",
                            "tokens": ["quantumEntangledEpoch"]}) + "\n"
                + json.dumps({"invariant_id": "c2",
                              "statement": "erc4626 first depositor share skew vault",
                              "tokens": ["erc4626", "share", "vault"]}) + "\n")
            rc = ngf.main([str(ws), "--candidates", str(cpath), "--json"])
            self.assertEqual(rc, 0)
            summ = json.loads((ws / ".auditooor" / "novelty"
                               / "novelty_summary.json").read_text())
            self.assertEqual(summ["candidates_examined"], 2)
            self.assertGreaterEqual(summ["novel"], 1)


if __name__ == "__main__":
    unittest.main()
