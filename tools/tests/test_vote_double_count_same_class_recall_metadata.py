from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BACKTEST_TOOL = ROOT / "tools" / "audit" / "detector-catch-rate-backtest.py"
CLASS_MAP_BUILDER = ROOT / "tools" / "audit" / "detector-class-map-builder.py"
PATTERNS_DIR = ROOT / "reference" / "patterns.dsl"
STALE_FIXTURE = ROOT / "detectors" / "fixtures" / "vote_double_count_stale_source_retention"
SOURCE_SWITCH_FIXTURE = (
    ROOT / "detectors" / "fixtures" / "vote_power_source_switch_without_prior_receipt_debit"
)


def _load_backtest_module():
    spec = importlib.util.spec_from_file_location("detector_catch_rate_backtest", BACKTEST_TOOL)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def _load_class_map_builder():
    spec = importlib.util.spec_from_file_location("detector_class_map_builder", CLASS_MAP_BUILDER)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


class VoteDoubleCountSameClassRecallMetadataTest(unittest.TestCase):
    def test_vote_double_count_family_maps_to_same_class(self) -> None:
        mod = _load_backtest_module()
        expected_primary = {
            "vote-double-count-shared-generalizer-fire9",
            "vote-double-count-stale-source-retention",
            "vote-power-forwarded-balance-plus-delegate-double-count",
            "vote-power-reassignment-old-source-not-debited",
            "vote-power-source-switch-without-prior-receipt-debit",
        }
        for slug in expected_primary:
            with self.subTest(slug=slug):
                self.assertEqual(mod.derive_attack_class(slug, []), "vote-double-count")
                self.assertIn("vote-double-count", mod.derive_attack_classes(slug, []))

    def test_overlap_detectors_keep_delegation_alias(self) -> None:
        mod = _load_backtest_module()
        for slug in {
            "vote-double-count-stale-source-retention",
            "vote-power-reassignment-old-source-not-debited",
        }:
            with self.subTest(slug=slug):
                self.assertEqual(mod.derive_attack_class(slug, []), "vote-double-count")
                self.assertIn(
                    "delegation-power-inflation",
                    mod.derive_attack_classes(slug, []),
                )

    def test_source_dsl_rebuilds_vote_primary_with_delegation_alias(self) -> None:
        try:
            import yaml
        except ImportError:
            self.skipTest("pyyaml not available")
        builder = _load_class_map_builder()
        for slug in {
            "vote-double-count-stale-source-retention",
            "vote-power-reassignment-old-source-not-debited",
        }:
            with self.subTest(slug=slug):
                spec = yaml.safe_load((PATTERNS_DIR / f"{slug}.yaml").read_text(encoding="utf-8"))
                primary = builder.classify_pattern(spec, slug)
                aliases = builder.explicit_attack_class_aliases(spec, primary["attack_class"])
                self.assertEqual(primary["attack_class"], "vote-double-count")
                self.assertIn("delegation-power-inflation", aliases)

    def test_existing_vote_double_count_controls_document_debit_and_receipt_guards(self) -> None:
        stale_positive = (STALE_FIXTURE / "positive.sol").read_text(encoding="utf-8")
        stale_clean = (STALE_FIXTURE / "clean.sol").read_text(encoding="utf-8")
        source_switch_positive = (SOURCE_SWITCH_FIXTURE / "positive.sol").read_text(encoding="utf-8")
        source_switch_clean = (SOURCE_SWITCH_FIXTURE / "clean.sol").read_text(encoding="utf-8")

        self.assertIn("delegatedSources[newDelegate].push(sourceId);", stale_positive)
        self.assertIn("forVotes[proposalId] += weight;", stale_positive)
        self.assertIn("_removeDelegation(oldDelegate, sourceId);", stale_clean)
        self.assertIn("hasVoted[proposalId][msg.sender] = true;", stale_clean)

        self.assertIn("_balances[voter] + voteCheckpoints[delegates[voter]][snapshot]", source_switch_positive)
        self.assertNotIn("hasVoted[proposalId][voter] = true;", source_switch_positive)
        self.assertIn("require(delegatee != msg.sender", source_switch_clean)
        self.assertIn("hasVoted[proposalId][voter] = true;", source_switch_clean)


if __name__ == "__main__":
    unittest.main()
