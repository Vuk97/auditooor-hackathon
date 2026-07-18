#!/usr/bin/env python3
"""Tests for tools/audit/detector-class-map-builder.py (Wave-5 lane W5-A6).

Stdlib + pyyaml. Covers the content-classifier, the legacy-derive parity, the
keyword-table canonicity invariant, map-build aggregation, and the
zero-coverage report math - the pure-logic surface that must stay correct.
"""

import importlib.util
import unittest
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_TOOL = _REPO / "tools" / "audit" / "detector-class-map-builder.py"
_VOCAB = _REPO / "reference" / "attack_class_vocab.yaml"


def _load_module():
    spec = importlib.util.spec_from_file_location("detector_class_map_builder", _TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


M = _load_module()


class TestKeywordTableCanonicity(unittest.TestCase):
    """Every class the keyword table references must exist in the vocab."""

    def test_keyword_table_classes_are_canonical(self):
        try:
            import yaml  # noqa: F401
        except ImportError:
            self.skipTest("pyyaml not available")
        vocab_ids, _ = M.load_vocab(_VOCAB)
        bad = M._verify_keyword_table(vocab_ids)
        self.assertEqual(bad, [], f"non-canonical classes in keyword table: {bad}")

    def test_legacy_fallback_targets_are_canonical(self):
        try:
            import yaml  # noqa: F401
        except ImportError:
            self.skipTest("pyyaml not available")
        vocab_ids, _ = M.load_vocab(_VOCAB)
        for target in M.LEGACY_FALLBACK.values():
            self.assertIn(target, vocab_ids)


class TestClassifyPattern(unittest.TestCase):
    def test_slug_classifies_reentrancy(self):
        r = M.classify_pattern({}, "external-call-before-state-update")
        self.assertEqual(r["attack_class"], "reentrancy-cross-contract")
        self.assertEqual(r["evidence"], "slug")
        self.assertEqual(r["confidence"], "high")

    def test_tags_take_priority(self):
        r = M.classify_pattern({"tags": ["oracle"]}, "some-obscure-name")
        self.assertEqual(r["attack_class"], "oracle-price-manipulation")
        self.assertEqual(r["evidence"], "tags")

    def test_description_classifies_when_slug_blank(self):
        # slug yields nothing; rich text pins it to a canonical class
        spec = {"wiki_description": "An attacker performs a donation attack "
                                    "directly to the vault to skew accounting"}
        r = M.classify_pattern(spec, "zzz-unknown-9001")
        self.assertEqual(r["attack_class"], "donation-attack")
        self.assertEqual(r["evidence"], "description")
        self.assertEqual(r["confidence"], "medium")

    def test_help_field_used(self):
        spec = {"help": "ECDSA signature can be forged against the wrong message"}
        r = M.classify_pattern(spec, "obscure")
        self.assertEqual(r["attack_class"], "signature-forgery")
        self.assertEqual(r["evidence"], "help-title")

    def test_uncategorized_when_nothing_matches(self):
        r = M.classify_pattern({}, "zzz-totally-unknown-thing-9999")
        self.assertEqual(r["attack_class"], "uncategorized")
        self.assertEqual(r["confidence"], "none")

    def test_specific_beats_generic_admin(self):
        # initializer should win over the generic admin-bypass keywords
        r = M.classify_pattern({}, "unprotected-initialize")
        self.assertEqual(r["attack_class"], "initializer-front-run")

    def test_cosmos_race_class(self):
        spec = {"wiki_description": "Two goroutines access shared state "
                                    "without synchronization, a race"}
        r = M.classify_pattern(spec, "obscure")
        self.assertEqual(r["attack_class"], "state-corruption-via-race")

    def test_evm_approve_race_is_transaction_ordering_not_state_corruption(self):
        spec = {
            "wiki_description": (
                "ERC20 approve(spender, amount) is called while a prior "
                "non-zero allowance exists; spender can front-run the allowance "
                "change and spend the old allowance before the new value lands."
            )
        }
        r = M.classify_pattern(spec, "erc20-approve-race-no-zero-reset")
        self.assertEqual(r["attack_class"], "transaction-ordering-race")

    def test_flag_unflag_race_is_transaction_ordering_not_state_corruption(self):
        spec = {
            "wiki_description": (
                "Admin unflags a question and a mempool observer bundles "
                "resolveQuestion in the same block because DELAY_PERIOD = 0."
            )
        }
        r = M.classify_pattern(spec, "flag-unflag-race-delay-period-zero")
        self.assertEqual(r["attack_class"], "transaction-ordering-race")

    def test_permit_front_run_grief_is_transaction_ordering_not_rounding(self):
        spec = {
            "wiki_description": (
                "Function forwards permit() without try/catch. A front-runner "
                "consumes the permit nonce first; the victim transaction then "
                "reverts on nonce mismatch."
            )
        }
        r = M.classify_pattern(spec, "glider-permit-grief-dos")
        self.assertEqual(r["attack_class"], "transaction-ordering-race")

    def test_yul_indexed_buffer_access_is_array_oob(self):
        spec = {
            "wiki_description": (
                "Inline Yul loop uses calldataload on a caller-derived index "
                "without checking calldatasize, causing out-of-bounds access."
            )
        }
        r = M.classify_pattern(spec, "yul-indexed-buffer-access-missing-bounds")
        self.assertEqual(r["attack_class"], "array-oob-access")

    def test_versioned_digest_bridge_classifier_beats_generic_replay(self):
        spec = {
            "wiki_description": (
                "A bridge verifier accepts a versioned digest tag without "
                "binding the tag to the protocol version flag; a signed "
                "parachain header can be replayed against the wrong verifier "
                "path, breaking version-isolation."
            )
        }
        r = M.classify_pattern(spec, "bridge-versioned-digest-tag-not-bound-to-version-flag")
        self.assertEqual(r["attack_class"], "bridge-proof-domain-bypass")

    def test_explicit_aliases_are_secondary_only(self):
        spec = {
            "tags": ["signature"],
            "attack_class_aliases": ["timestamp-manipulation", "signature-replay-cross-domain"],
        }
        primary = M.classify_pattern(spec, "signed-action-missing-deadline")
        aliases = M.explicit_attack_class_aliases(spec, primary["attack_class"])
        self.assertEqual(primary["attack_class"], "signature-replay-cross-domain")
        self.assertEqual(aliases, ["timestamp-manipulation"])

    def test_explicit_aliases_ignore_unknown_and_uncategorized_primary(self):
        spec = {
            "attack_class_aliases": ["not-a-real-class", "timestamp-manipulation"],
        }
        aliases = M.explicit_attack_class_aliases(spec, "uncategorized")
        self.assertEqual(aliases, [])
        aliases = M.explicit_attack_class_aliases(spec, "signature-replay-cross-domain")
        self.assertEqual(aliases, ["timestamp-manipulation"])


class TestLegacyDerive(unittest.TestCase):
    def test_legacy_reentrancy(self):
        self.assertEqual(
            M.legacy_derive_attack_class("callback-reentrancy-no-guard", None),
            "reentrancy")

    def test_legacy_uncategorized(self):
        self.assertEqual(
            M.legacy_derive_attack_class("zzz-unknown", None), "uncategorized")

    def test_legacy_underscore_normalized(self):
        self.assertEqual(
            M.legacy_derive_attack_class("callback_reentrancy_no_guard", None),
            "reentrancy")


class TestBuildMap(unittest.TestCase):
    def test_build_map_counts_and_lift(self):
        # one slug-classifiable, one uncategorized
        patterns = [
            ("external-call-before-state-update", {"severity": "high"}, True),
            ("zzz-totally-unknown-9999", {}, False),
        ]
        mappings, stats = M.build_map(patterns)
        self.assertEqual(stats["patterns_total"], 2)
        self.assertEqual(stats["after_uncategorized"], 1)
        self.assertEqual(len(mappings), 2)
        classes = {m["pattern"]: m["attack_class"] for m in mappings}
        self.assertEqual(classes["external-call-before-state-update"],
                         "reentrancy-cross-contract")
        self.assertEqual(classes["zzz-totally-unknown-9999"], "uncategorized")

    def test_build_map_preserves_explicit_aliases(self):
        patterns = [
            (
                "sig-signed-action-missing-deadline",
                {
                    "severity": "medium",
                    "tags": ["signature"],
                    "help": "ECDSA signature action has no deadline",
                    "attack_class_aliases": ["timestamp-manipulation"],
                },
                True,
            )
        ]
        mappings, _ = M.build_map(patterns)
        self.assertEqual(
            mappings[0]["attack_class_aliases"],
            ["timestamp-manipulation"],
        )

    def test_severity_normalized_uppercase(self):
        _, _ = M.build_map([("p", {"severity": "high"}, True)])
        mappings, _ = M.build_map([("p", {"severity": "high"}, True)])
        self.assertEqual(mappings[0]["severity"], "HIGH")


class TestCoverageReport(unittest.TestCase):
    def test_zero_coverage_partition(self):
        vocab_ids = {"reentrancy-cross-contract", "admin-bypass", "state-bloat"}
        vocab_entries = [
            {"class_id": "reentrancy-cross-contract", "name": "R"},
            {"class_id": "admin-bypass", "name": "A"},
            {"class_id": "state-bloat", "name": "S"},
        ]
        mappings = [
            {"pattern": "p1", "attack_class": "reentrancy-cross-contract"},
            {"pattern": "p2", "attack_class": "reentrancy-cross-contract"},
            {"pattern": "p3", "attack_class": "admin-bypass"},
            {"pattern": "p4", "attack_class": "uncategorized"},
            {"pattern": "p5", "attack_class": "admin-bypass",
             "attack_class_aliases": ["state-bloat"]},
        ]
        covered, zero = M.build_coverage_report(mappings, vocab_ids, vocab_entries)
        cov_ids = {c["class_id"] for c in covered}
        zero_ids = {z["class_id"] for z in zero}
        self.assertEqual(cov_ids, {"reentrancy-cross-contract", "admin-bypass"})
        self.assertEqual(zero_ids, {"state-bloat"})
        counts = {row["class_id"]: row["detector_count"] for row in covered}
        self.assertEqual(counts["reentrancy-cross-contract"], 2)
        self.assertEqual(counts["admin-bypass"], 2)
        alias_counts = {row["class_id"]: row["alias_detector_count"]
                        for row in covered + zero}
        self.assertEqual(alias_counts["state-bloat"], 1)

    def test_uncategorized_excluded_from_coverage(self):
        vocab_ids = {"admin-bypass"}
        vocab_entries = [{"class_id": "admin-bypass", "name": "A"}]
        mappings = [{"pattern": "p", "attack_class": "uncategorized"}]
        covered, zero = M.build_coverage_report(mappings, vocab_ids, vocab_entries)
        self.assertEqual(covered, [])
        self.assertEqual(len(zero), 1)


class TestSchema(unittest.TestCase):
    def test_schema_constants(self):
        self.assertEqual(M.MAP_SCHEMA, "auditooor.detector_class_map_complete.v1")
        self.assertEqual(M.REPORT_SCHEMA,
                         "auditooor.detector_zero_coverage_report.v1")


class TestRealCorpusLift(unittest.TestCase):
    """End-to-end check on the real DSL corpus - the map must measurably
    reduce the uncategorized bucket vs the legacy heuristic."""

    def test_content_map_beats_legacy_heuristic(self):
        try:
            import yaml  # noqa: F401
        except ImportError:
            self.skipTest("pyyaml not available")
        patterns_dir = _REPO / "reference" / "patterns.dsl"
        if not patterns_dir.exists():
            self.skipTest("patterns.dsl corpus not present")
        patterns = M.discover_patterns(patterns_dir, fixture_only=True)
        if len(patterns) < 100:
            self.skipTest("corpus too small to assert lift")
        _, stats = M.build_map(patterns)
        # the content-derived map must leave strictly fewer uncategorized
        self.assertLess(stats["after_uncategorized"],
                        stats["before_uncategorized"])
        # and cover strictly more distinct classes
        self.assertGreater(stats["after_distinct_classes"],
                           stats["before_distinct_classes"])


if __name__ == "__main__":
    unittest.main()
