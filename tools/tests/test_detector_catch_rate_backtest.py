#!/usr/bin/env python3
"""Tests for tools/audit/detector-catch-rate-backtest.py.

Stdlib-only. Does NOT require slither (the slither-dependent run path is
exercised separately by actually running the backtest). These tests cover
the taxonomy derivation, corpus discovery, aggregation math, and report
rendering - the pure-logic surface that must stay correct.
"""

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_TOOL = _REPO / "tools" / "audit" / "detector-catch-rate-backtest.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("detector_catch_rate_backtest", _TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


M = _load_module()


class TestAttackClassDerivation(unittest.TestCase):
    def test_reentrancy_from_slug(self):
        self.assertEqual(M.derive_attack_class("callback-reentrancy-no-guard", None),
                         "reentrancy-cross-contract")

    def test_access_control_from_slug(self):
        self.assertEqual(
            M.derive_attack_class("missing-access-control-on-authorizeupgrade", None),
            "proxy-hijack")

    def test_signature_replay_from_slug(self):
        self.assertEqual(
            M.derive_attack_class("eip-712-signature-replay-across-domains", None),
            "signature-replay-cross-domain")

    def test_oracle_from_slug(self):
        self.assertEqual(
            M.derive_attack_class("oracle-decimal-mis-scaling-hardcoded-scale", None),
            "oracle-price-manipulation")

    def test_erc4626_from_slug(self):
        self.assertEqual(
            M.derive_attack_class("erc4626-first-depositor-attack", None),
            "first-depositor-inflation")

    def test_tags_override_slug(self):
        # slug alone would be uncategorized; tag pins it
        cls = M.derive_attack_class("some-obscure-pattern-name", ["bridge"])
        self.assertEqual(cls, "bridge-proof-domain-bypass")

    def test_uncategorized_fallback(self):
        self.assertEqual(M.derive_attack_class("zzz-totally-unknown-thing", None),
                         "uncategorized")

    def test_underscore_slug_normalized(self):
        self.assertEqual(M.derive_attack_class("callback_reentrancy_no_guard", None),
                         "reentrancy-cross-contract")

    def test_shared_detector_map_classifies_previous_uncategorized_slug(self):
        # This slug is uncategorized by the old slug/tag heuristic but is
        # classified by the shared content-derived detector map.
        self.assertEqual(
            M.derive_attack_class(
                "a-malicious-settings-contract-can-call-onownershiptransferred-to",
                None,
            ),
            "admin-bypass",
        )

    def test_fund_loss_arithmetic_recall_lift_taxonomy(self):
        for slug in (
            "clamp-state-but-return-unclamped",
            "constructor-precision-factor-truncates-to-zero",
            "fx-v4core-safecast-int128-missing",
            "rounded-up-limit-debit-down-payout",
        ):
            with self.subTest(slug=slug):
                self.assertEqual(
                    M.derive_attack_class(slug, None),
                    "fund-loss-via-arithmetic",
                )

    def test_oracle_overflow_control_stays_oracle_class(self):
        # The fund-loss lift is not a blanket "overflow means fund loss"
        # relabel. Oracle market-freeze arithmetic stays in the oracle class.
        self.assertEqual(
            M.derive_attack_class(
                "oracle-multi-feed-product-unchecked-overflow",
                None,
            ),
            "oracle-price-manipulation",
        )

    def test_snowbridge_versioned_digest_detector_stays_bridge_class(self):
        self.assertEqual(
            M.derive_attack_class(
                "bridge-versioned-digest-tag-not-bound-to-version-flag",
                None,
            ),
            "bridge-proof-domain-bypass",
        )

    def test_explicit_attack_class_aliases_are_exposed(self):
        self.assertEqual(
            M.derive_attack_class("sig-signed-action-missing-deadline", None),
            "signature-replay-cross-domain",
        )
        classes = M.derive_attack_classes("sig-signed-action-missing-deadline", None)
        self.assertIn("signature-replay-cross-domain", classes)
        self.assertIn("timestamp-manipulation", classes)

    def test_matching_engine_fallback_classifies_new_slugs(self):
        for slug in (
            "matching-engine-amend-order-invariant-gap",
            "matching-engine-fok-dust-threshold-gap",
            "matching-engine-reduce-only-oi-accounting-gap",
        ):
            with self.subTest(slug=slug):
                self.assertEqual(
                    M.derive_attack_class(slug, None),
                    "matching-engine-misprice",
                )


class TestAggregation(unittest.TestCase):
    def _rec(self, cls, vuln_hits, clean_hits, vuln_err=None, clean_err=None):
        return {
            "pattern": "p", "attack_class": cls, "severity": "HIGH",
            "vuln_hits": vuln_hits, "clean_hits": clean_hits,
            "true_positive": vuln_hits > 0,
            "false_negative": vuln_hits == 0 and not vuln_err,
            "false_positive": clean_hits > 0,
            "true_negative": clean_hits == 0 and not clean_err,
            "compile_failed": bool(vuln_err) or bool(clean_err),
            "vuln_error": vuln_err, "clean_error": clean_err,
        }

    def test_perfect_catch(self):
        results = [self._rec("reentrancy", 1, 0), self._rec("reentrancy", 2, 0)]
        overall, _ = M.aggregate(results)
        self.assertEqual(overall["true_positives"], 2)
        self.assertEqual(overall["false_negatives"], 0)
        self.assertEqual(overall["recall_catch_rate"], 1.0)
        self.assertEqual(overall["false_positive_rate"], 0.0)
        self.assertEqual(overall["precision"], 1.0)

    def test_miss_lowers_recall(self):
        results = [self._rec("oracle", 1, 0), self._rec("oracle", 0, 0)]
        overall, _ = M.aggregate(results)
        self.assertEqual(overall["true_positives"], 1)
        self.assertEqual(overall["false_negatives"], 1)
        self.assertEqual(overall["recall_catch_rate"], 0.5)

    def test_false_positive_counted(self):
        results = [self._rec("dos", 1, 1)]  # fires on both
        overall, _ = M.aggregate(results)
        self.assertEqual(overall["false_positives"], 1)
        self.assertEqual(overall["false_positive_rate"], 1.0)
        # precision = tp/(tp+fp) = 1/2
        self.assertEqual(overall["precision"], 0.5)

    def test_compile_failure_excluded_from_recall(self):
        # a vuln fixture that failed to compile must not count as a miss
        results = [self._rec("x", 0, 0, vuln_err="compile-error: boom")]
        overall, _ = M.aggregate(results)
        self.assertEqual(overall["vuln_fixtures_scorable"], 0)
        self.assertEqual(overall["false_negatives"], 0)
        self.assertEqual(overall["recall_catch_rate"], 0.0)
        self.assertEqual(overall["patterns_compile_failed"], 1)

    def test_per_class_ranked_weakest_first(self):
        results = [
            self._rec("strong", 1, 0), self._rec("strong", 1, 0),
            self._rec("weak", 0, 0), self._rec("weak", 1, 0),
        ]
        _, class_rows = M.aggregate(results)
        self.assertEqual(class_rows[0]["attack_class"], "weak")
        self.assertEqual(class_rows[0]["recall"], 0.5)
        self.assertEqual(class_rows[-1]["attack_class"], "strong")
        self.assertEqual(class_rows[-1]["recall"], 1.0)


class TestReport(unittest.TestCase):
    def test_report_contains_headline_numbers(self):
        results = [
            {"pattern": "p1", "attack_class": "reentrancy", "severity": "HIGH",
             "vuln_hits": 1, "clean_hits": 0, "true_positive": True,
             "false_negative": False, "false_positive": False,
             "true_negative": True, "compile_failed": False,
             "vuln_error": None, "clean_error": None},
        ]
        overall, class_rows = M.aggregate(results)
        report = M.build_report(overall, class_rows)
        self.assertIn("CATCH RATE", report)
        self.assertIn("FALSE POSITIVE RATE", report)
        self.assertIn("WEAKEST 5 ATTACK CLASSES", report)


class TestSchema(unittest.TestCase):
    def test_schema_constant(self):
        self.assertEqual(M.SCHEMA, "auditooor.detector_catch_rate.v1")


class TestCorpusDiscovery(unittest.TestCase):
    def test_discover_skips_patterns_without_fixtures(self):
        try:
            import yaml  # noqa: F401
        except ImportError:
            self.skipTest("pyyaml not available")
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            (d / "no-fixture.yaml").write_text(
                "pattern: no-fixture\nseverity: HIGH\nmatch: []\n")
            items = M.discover_corpus(d)
            self.assertEqual(len(items), 0)

    def test_discover_skips_missing_fixture_files(self):
        try:
            import yaml  # noqa: F401
        except ImportError:
            self.skipTest("pyyaml not available")
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            (d / "ghost.yaml").write_text(
                "pattern: ghost\nseverity: HIGH\nmatch: []\n"
                "fixtures:\n  vuln: /nonexistent/vuln.sol\n"
                "  clean: /nonexistent/clean.sol\n")
            items = M.discover_corpus(d)
            self.assertEqual(len(items), 0)


if __name__ == "__main__":
    unittest.main()
