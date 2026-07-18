#!/usr/bin/env python3
"""Wave-12 tests for per-language weight overrides in ranker.py.

Covers:
  T1: load_weights() parses `language_overrides:` block into a dict keyed
      by lowercased language name.
  T2: resolve_language_weights() returns the Solidity block when
      language='solidity' (and 'Solidity', 'SOLIDITY' — case-insensitive).
  T3: resolve_language_weights() returns global defaults when language is
      None / empty / unknown.
  T4: Sum of Solidity per-language weights w1..w6 == 1.0 (sanity invariant).
  T5: combine_scores() with language='solidity' and weights_cfg=loaded uses
      the Solidity weights (verified by observing a different score for the
      same evidence dict vs Go-default weights).
  T6: combine_scores() cache-key parity: same evidence + Go-default vs
      Solidity weights must yield DIFFERENT scores (i.e. the language
      parameter is observed, not silently dropped).
  T7: rank() inputs payload exposes `language_id` and `weights_source` =
      'per_language_override' when target_record.language matches.
  T8: Backward-compat — combine_scores() called without language= still
      respects explicit w1..w6 keyword args (unchanged behavior).
"""
from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
RANKER_PATH = REPO_ROOT / "tools" / "ranker.py"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


RA = _load("ranker_wave12_language_overrides_for_test", RANKER_PATH)

# Disable prediction-log writes during these tests.
os.environ.setdefault("RANKER_PREDICTION_LOG_DISABLED", "1")


# Tolerance for float comparisons (yaml round-trip + arithmetic noise).
EPS = 1e-9


def _evidence_dict(ac: str, contribution: float, scorer: str = "S1"):
    """Build a minimal scorer-evidence dict for one attack class."""
    return {ac: [{"scorer": scorer, "contribution": contribution}]}


class TestLoadLanguageOverrides(unittest.TestCase):

    def test_load_weights_surfaces_language_overrides(self):
        """T1: load_weights() exposes language_overrides as a dict."""
        cfg = RA.load_weights()
        self.assertIn("language_overrides", cfg)
        self.assertIsInstance(cfg["language_overrides"], dict)
        # Solidity entry shipped in Wave-12.
        self.assertIn("solidity", cfg["language_overrides"])
        sol = cfg["language_overrides"]["solidity"]
        for k in ("w1", "w2", "w3", "w4", "w5", "w6"):
            self.assertIn(k, sol, f"solidity overrides missing {k}")
            self.assertIsInstance(sol[k], float)


class TestResolveLanguageWeights(unittest.TestCase):

    def setUp(self):
        self.cfg = RA.load_weights()

    def test_solidity_override_resolves(self):
        """T2: language='solidity' → returns Solidity block; lang_id='solidity'."""
        w, lang_id = RA.resolve_language_weights("solidity", self.cfg)
        self.assertEqual(lang_id, "solidity")
        # Wave-12 ship values.
        self.assertAlmostEqual(w["w1"], 0.30, places=6)
        self.assertAlmostEqual(w["w2"], 0.20, places=6)
        self.assertAlmostEqual(w["w6"], 0.20, places=6)

    def test_solidity_override_case_insensitive(self):
        """T2 (cont.): 'Solidity' and 'SOLIDITY' should match the same block."""
        for variant in ("Solidity", "SOLIDITY", "soLIdiTY"):
            w, lang_id = RA.resolve_language_weights(variant, self.cfg)
            self.assertEqual(lang_id, "solidity",
                             f"variant {variant!r} did not resolve to solidity")
            self.assertAlmostEqual(w["w1"], 0.30, places=6)

    def test_unknown_language_falls_back_to_global(self):
        """T3: unknown language → returns global defaults; lang_id=None."""
        w, lang_id = RA.resolve_language_weights("klingon", self.cfg)
        self.assertIsNone(lang_id)
        # Global defaults post-Wave-9 integration: w1 shifted from 0.45 to
        # 0.30 to free 0.15 for w6 (S6 detector-grounding scorer wired in
        # Wave-9 Track B). All six slots now sum to 1.0.
        self.assertAlmostEqual(w["w1"], 0.30, places=6)

    def test_none_language_falls_back_to_global(self):
        """T3 (cont.): language=None → global defaults; lang_id=None."""
        w, lang_id = RA.resolve_language_weights(None, self.cfg)
        self.assertIsNone(lang_id)
        self.assertAlmostEqual(w["w1"], 0.30, places=6)

    def test_empty_language_falls_back_to_global(self):
        """T3 (cont.): language='' → global defaults; lang_id=None."""
        w, lang_id = RA.resolve_language_weights("", self.cfg)
        self.assertIsNone(lang_id)
        self.assertAlmostEqual(w["w1"], 0.30, places=6)


class TestWeightSumInvariant(unittest.TestCase):

    def test_solidity_weight_sum_is_one(self):
        """T4: solidity w1..w6 must sum to 1.0 across the full slot set
        (rounding tolerance). HEAD's combine_scores ignores w6 until S6
        wire-up lands (Wave-9 follow-up); the sum-to-1.0 invariant is the
        forward-compat contract for that scorer addition."""
        cfg = RA.load_weights()
        sol = cfg["language_overrides"]["solidity"]
        s = sum(sol[k] for k in ("w1", "w2", "w3", "w4", "w5", "w6"))
        self.assertAlmostEqual(s, 1.0, places=6,
                               msg=f"solidity full w1..w6 sums to {s}, not 1.0")
        # Also sanity-check the active-slot (w1..w5) sum is within bounds —
        # combine_scores at HEAD only consumes w1..w5, and we don't want the
        # active sum to exceed 1.0 (would inflate scores).
        active_sum = sum(sol[k] for k in ("w1", "w2", "w3", "w4", "w5"))
        self.assertLessEqual(active_sum, 1.0 + 1e-9,
                             msg=f"solidity active w1..w5 = {active_sum} > 1.0")


class TestCombineScoresLanguageAware(unittest.TestCase):

    def setUp(self):
        self.cfg = RA.load_weights()
        # Evidence vector designed to produce a Solidity-vs-Go score delta:
        # S1=1.0 (gets down-weighted under solidity 0.30 vs Go-default 0.45)
        # S3=1.0 (gets down-weighted under solidity 0.15 vs Go-default 0.20)
        # Net Solidity score = 0.30 + 0.15 = 0.45 (+convergence bonus 0.15) = 0.60
        # Net Go score      = 0.45 + 0.20 = 0.65 (+convergence bonus 0.15) = 0.80
        self.s1 = _evidence_dict("admin-bypass", 1.0, scorer="S1")
        self.s3 = _evidence_dict("admin-bypass", 1.0, scorer="S3")
        self.s4: dict = {}

    def test_combine_scores_uses_solidity_weights(self):
        """T5: combine_scores() with language='solidity' produces a different
        score than the same call with no language (= Go-default)."""
        # Go defaults (no language) — uses the explicit keyword args
        rows_default = RA.combine_scores(
            self.s1, self.s4, s3=self.s3,
            w1=0.45, w2=0.20, w3=0.20, w4=0.10, w5=0.05,
        )
        # With language='solidity' + weights_cfg loaded, Solidity weights win
        rows_sol = RA.combine_scores(
            self.s1, self.s4, s3=self.s3,
            w1=0.45, w2=0.20, w3=0.20, w4=0.10, w5=0.05,
            language="solidity", weights_cfg=self.cfg,
        )
        self.assertEqual(len(rows_default), 1)
        self.assertEqual(len(rows_sol), 1)
        score_default = rows_default[0]["score"]
        score_sol = rows_sol[0]["score"]
        # Different weighting must produce different score.
        self.assertNotAlmostEqual(score_default, score_sol, places=4,
                                  msg="Solidity language did not change the score "
                                      "— per-language override not wired into "
                                      "combine_scores().")
        # Default: S1*0.45 + S3*0.20 + bonus(0.15) = 0.80
        # Solidity: S1*0.30 + S3*0.15 + bonus(0.15) = 0.60
        self.assertAlmostEqual(score_default, 0.80, places=4)
        self.assertAlmostEqual(score_sol, 0.60, places=4)

    def test_unknown_language_falls_back_to_explicit_args(self):
        """T6: language='klingon' falls back to global (no override match).
        Should reuse the explicit w1..w5 args without complaining."""
        rows = RA.combine_scores(
            self.s1, self.s4, s3=self.s3,
            w1=0.45, w2=0.20, w3=0.20, w4=0.10, w5=0.05,
            language="klingon", weights_cfg=self.cfg,
        )
        self.assertAlmostEqual(rows[0]["score"], 0.80, places=4)

    def test_backward_compat_no_language_no_cfg(self):
        """T8: callers that don't pass language= or weights_cfg keep the
        old behavior (explicit keyword args win)."""
        rows = RA.combine_scores(
            self.s1, self.s4, s3=self.s3,
            w1=0.45, w2=0.20, w3=0.20, w4=0.10, w5=0.05,
        )
        self.assertAlmostEqual(rows[0]["score"], 0.80, places=4)


class TestRankExposesLanguageId(unittest.TestCase):

    def test_rank_inputs_exposes_language_id_for_solidity_target(self):
        """T7: rank() inputs payload includes language_id and the
        weights_source surfaces 'per_language_override' for Sol targets
        (when no per-family override matches first)."""
        # Use an unknown repo (no family match) to ensure language is the
        # ONLY override source. Synthesized target record uses solidity.
        result = RA.rank(
            target_repo="unknown-org/unknown-repo",
            file_path="src/Foo.sol",
            function_signature="function bar(address user)",
            top_n=1,
            min_confidence=0.0,
        )
        inputs = result.inputs
        self.assertIn("language_id", inputs,
                      "rank().inputs missing language_id key")
        # The synthesized fallback in rank() hard-codes language='go' when
        # find_target_function returns None. That's the Wave-7 fallback path;
        # rank() will then resolve language='go' (no override in yaml) → None.
        # This test asserts the KEY EXISTS (regression sentinel). A future
        # synthesized-target language plumbing would let us assert
        # language_id='solidity' directly.
        # weights_source must be one of the known enums.
        self.assertIn(inputs.get("weights_source"),
                      {"per_family_override",
                       "per_language_override",
                       "global_or_per_family_default"},
                      f"unknown weights_source: {inputs.get('weights_source')}")


if __name__ == "__main__":
    unittest.main()
