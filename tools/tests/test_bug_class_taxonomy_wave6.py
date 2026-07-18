#!/usr/bin/env python3
"""
Wave-6 Phase F caveat-fix tests for bug_class_taxonomy.yaml and attack_class_vocab.yaml

Deliverable 5: Tests for TOCTOU class addition and ranker rules expansion.
"""

import unittest
import yaml
from pathlib import Path


class TestBugClassTaxonomyWave6(unittest.TestCase):
    """Test suite for TOCTOU class addition and attack class vocab expansion."""

    @classmethod
    def setUpClass(cls):
        """Load reference files."""
        workspace_root = Path(__file__).parent.parent.parent
        cls.taxonomy_path = workspace_root / "reference" / "bug_class_taxonomy.yaml"
        cls.vocab_path = workspace_root / "reference" / "attack_class_vocab.yaml"
        cls.ranker_path = workspace_root / "audit" / "ranker_rules.yaml"
        cls.mapping_path = workspace_root / "audit" / "bug_class_to_attack_classes_map.yaml"

        with open(cls.taxonomy_path) as f:
            cls.taxonomy = yaml.safe_load(f)

        with open(cls.vocab_path) as f:
            cls.vocab = yaml.safe_load(f)

        with open(cls.ranker_path) as f:
            cls.ranker = yaml.safe_load(f)

        with open(cls.mapping_path) as f:
            cls.mapping = yaml.safe_load(f)

    def test_toctou_class_present_in_taxonomy(self):
        """Assertion 1: TOCTOU class exists in bug_class_taxonomy.yaml"""
        class_ids = [entry["class_id"] for entry in self.taxonomy]
        self.assertIn(
            "time-of-check-time-of-use",
            class_ids,
            "TOCTOU class (time-of-check-time-of-use) must be present in taxonomy",
        )

    def test_toctou_class_has_keywords_and_description(self):
        """TOCTOU class has required fields: name, description, keywords."""
        toctou = next(
            (e for e in self.taxonomy if e["class_id"] == "time-of-check-time-of-use"),
            None,
        )
        self.assertIsNotNone(toctou, "TOCTOU entry must exist")
        self.assertIn("name", toctou)
        self.assertIn("description", toctou)
        self.assertIn("keywords", toctou)
        self.assertIn("toctou", toctou["keywords"])

    def test_attack_classes_in_vocab(self):
        """Assertion 2: Three new attack classes present in attack_class_vocab.yaml"""
        vocab_ids = [entry["class_id"] for entry in self.vocab]
        required_classes = [
            "timestamp-manipulation",
            "oracle-update-race",
            "state-change-between-check-and-use",
        ]
        for cls_id in required_classes:
            self.assertIn(
                cls_id,
                vocab_ids,
                f"Attack class {cls_id} must be present in vocab",
            )

    def test_attack_classes_severity_hints(self):
        """Attack classes have appropriate severity_hint."""
        vocab_ids = {entry["class_id"]: entry for entry in self.vocab}
        required_classes = [
            "timestamp-manipulation",
            "oracle-update-race",
            "state-change-between-check-and-use",
        ]
        for cls_id in required_classes:
            self.assertIn(cls_id, vocab_ids)
            entry = vocab_ids[cls_id]
            self.assertIn("severity_hint", entry)
            self.assertIn(entry["severity_hint"], ["HIGH", "CRITICAL", "MEDIUM"])

    def test_ranker_rules_count_is_16(self):
        """Assertion 3: Ranker rules YAML has 16 total rules (11 prior + 5 new)."""
        # ranker_rules.yaml uses dict-based (key-based) format, not list
        rule_count = len(self.ranker)
        expected = 16
        self.assertEqual(
            rule_count,
            expected,
            f"Ranker rules must have {expected} entries, got {rule_count}",
        )

    def test_ranker_rules_have_5_new_ones(self):
        """Five new ranker rules are present."""
        expected_new_rules = [
            "RULE_GO_TOCTOU_TIMESTAMP",
            "RULE_SOL_RECEIVE_NO_REENTRANCY",
            "RULE_GO_CONTEXT_DEADLINE_BYPASS",
            "RULE_RUST_ASYNC_NO_TIMEOUT",
            "RULE_GO_CHANNEL_NO_BUFFER_RACE",
        ]
        for rule_id in expected_new_rules:
            self.assertIn(rule_id, self.ranker, f"Rule {rule_id} must be present")

    def test_bug_class_to_attack_map_has_35_entries(self):
        """Assertion 4: Mapping YAML has 35 entries (30 prior + 5 new)."""
        mappings = self.mapping.get("mappings", {})
        expected = 35
        actual = len(mappings)
        self.assertEqual(
            actual,
            expected,
            f"Mappings must have {expected} entries, got {actual}",
        )

    def test_five_new_mappings_present(self):
        """Five new bug-class to attack-class mappings are present."""
        mappings = self.mapping.get("mappings", {})
        expected_mappings = [
            "time-of-check-time-of-use",
            "fallback-receive-reentrancy",
            "context-deadline-not-propagated",
            "async-await-no-timeout",
            "unbuffered-channel-race",
        ]
        for mapping_key in expected_mappings:
            self.assertIn(
                mapping_key, mappings, f"Mapping {mapping_key} must be present"
            )
            self.assertIsInstance(
                mappings[mapping_key],
                list,
                f"Mapping {mapping_key} value must be a list",
            )

    def test_toctou_mapping_correct(self):
        """TOCTOU mapping has correct attack classes."""
        mappings = self.mapping.get("mappings", {})
        toctou_mapping = mappings.get("time-of-check-time-of-use", [])
        expected_attack_classes = [
            "timestamp-manipulation",
            "oracle-update-race",
            "state-change-between-check-and-use",
        ]
        self.assertEqual(
            toctou_mapping,
            expected_attack_classes,
            "TOCTOU mapping must have exactly the three new attack classes",
        )


if __name__ == "__main__":
    unittest.main()
