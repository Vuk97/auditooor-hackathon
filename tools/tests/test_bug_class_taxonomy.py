"""Tests for reference/bug_class_taxonomy.yaml and reference/attack_class_vocab.yaml."""
from __future__ import annotations

import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TAXONOMY_PATH = REPO_ROOT / "reference" / "bug_class_taxonomy.yaml"
ATTACK_VOCAB_PATH = REPO_ROOT / "reference" / "attack_class_vocab.yaml"


def _load_yaml(path: Path):
    try:
        import yaml  # type: ignore
        with open(path, encoding="utf-8") as fh:
            return yaml.safe_load(fh)
    except ImportError:
        raise ImportError("PyYAML required: pip install pyyaml")


class TaxonomyStructureTests(unittest.TestCase):
    """Test 1: YAML parses and has correct top-level shape."""

    def setUp(self) -> None:
        try:
            import yaml  # noqa: F401
        except ImportError:
            self.skipTest("PyYAML not installed")

    def test_taxonomy_parses_as_list(self) -> None:
        """bug_class_taxonomy.yaml must parse as a YAML list."""
        data = _load_yaml(TAXONOMY_PATH)
        self.assertIsInstance(data, list, "Taxonomy must be a YAML list")
        self.assertGreater(len(data), 10, "Taxonomy must have at least 10 entries")

    def test_taxonomy_class_ids_unique(self) -> None:
        """All class_id values in bug_class_taxonomy.yaml must be unique."""
        data = _load_yaml(TAXONOMY_PATH)
        ids = [e["class_id"] for e in data if "class_id" in e]
        self.assertEqual(len(ids), len(set(ids)), "Duplicate class_id found in taxonomy")

    def test_taxonomy_required_fields_present(self) -> None:
        """Every entry must have: class_id, name, description, keywords."""
        data = _load_yaml(TAXONOMY_PATH)
        required = {"class_id", "name", "description", "keywords"}
        for entry in data:
            for field in required:
                self.assertIn(
                    field, entry,
                    f"Entry {entry.get('class_id', '?')} missing required field {field!r}",
                )
            self.assertIsInstance(
                entry["keywords"], list,
                f"Entry {entry['class_id']}: keywords must be a list",
            )
            self.assertGreater(
                len(entry["keywords"]), 0,
                f"Entry {entry['class_id']}: keywords must not be empty",
            )

    def test_taxonomy_associated_attack_classes_are_list(self) -> None:
        """associated_attack_classes, when present, must be a list."""
        data = _load_yaml(TAXONOMY_PATH)
        for entry in data:
            if "associated_attack_classes" in entry:
                self.assertIsInstance(
                    entry["associated_attack_classes"], list,
                    f"Entry {entry['class_id']}: associated_attack_classes must be a list",
                )

    def test_taxonomy_severity_hint_is_valid(self) -> None:
        """severity_hint, when present, must be one of the known tiers."""
        data = _load_yaml(TAXONOMY_PATH)
        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"}
        for entry in data:
            if "severity_hint" in entry:
                self.assertIn(
                    entry["severity_hint"], valid,
                    f"Entry {entry['class_id']}: invalid severity_hint {entry['severity_hint']!r}",
                )


class AttackVocabStructureTests(unittest.TestCase):
    """Test 2: attack_class_vocab.yaml structural integrity."""

    def setUp(self) -> None:
        try:
            import yaml  # noqa: F401
        except ImportError:
            self.skipTest("PyYAML not installed")

    def test_attack_vocab_parses_as_list(self) -> None:
        """attack_class_vocab.yaml must parse as a YAML list."""
        data = _load_yaml(ATTACK_VOCAB_PATH)
        self.assertIsInstance(data, list, "Attack vocab must be a YAML list")
        self.assertGreater(len(data), 30, "Attack vocab must have at least 30 entries")

    def test_attack_vocab_class_ids_unique(self) -> None:
        """All class_id values in attack_class_vocab.yaml must be unique."""
        data = _load_yaml(ATTACK_VOCAB_PATH)
        ids = [e["class_id"] for e in data if "class_id" in e]
        self.assertEqual(len(ids), len(set(ids)), "Duplicate class_id in attack vocab")

    def test_attack_vocab_required_fields(self) -> None:
        """Every attack vocab entry must have class_id, name, description."""
        data = _load_yaml(ATTACK_VOCAB_PATH)
        for entry in data:
            for field in ("class_id", "name", "description"):
                self.assertIn(
                    field, entry,
                    f"Attack vocab entry {entry.get('class_id','?')} missing {field!r}",
                )

    def test_attack_vocab_parent_class_references_exist(self) -> None:
        """parent_class, when present, must reference a known class_id."""
        data = _load_yaml(ATTACK_VOCAB_PATH)
        known_ids = {e["class_id"] for e in data if "class_id" in e}
        for entry in data:
            if "parent_class" in entry:
                self.assertIn(
                    entry["parent_class"], known_ids,
                    f"Entry {entry['class_id']}: parent_class {entry['parent_class']!r} not in vocab",
                )


class TaxonomyAttackCrossRefTests(unittest.TestCase):
    """Test 3: Cross-reference between taxonomy and attack vocab."""

    def setUp(self) -> None:
        try:
            import yaml  # noqa: F401
        except ImportError:
            self.skipTest("PyYAML not installed")

    def test_taxonomy_attack_classes_mostly_in_vocab(self) -> None:
        """At least 80% of attack classes referenced by taxonomy must be in the vocab."""
        taxonomy = _load_yaml(TAXONOMY_PATH)
        vocab = _load_yaml(ATTACK_VOCAB_PATH)
        vocab_ids = {e["class_id"] for e in vocab}

        all_refs: list = []
        missing: list = []
        for entry in taxonomy:
            for ac in entry.get("associated_attack_classes", []):
                all_refs.append(ac)
                if ac not in vocab_ids:
                    missing.append((entry["class_id"], ac))

        if not all_refs:
            return  # nothing to check

        coverage = 1.0 - len(missing) / len(all_refs)
        self.assertGreaterEqual(
            coverage, 0.80,
            f"Only {coverage*100:.1f}% of taxonomy attack_classes found in vocab. "
            f"Missing: {missing[:5]} ...",
        )

    def test_empirical_anchors_format(self) -> None:
        """empirical_anchors, when present, must be a list of non-empty strings."""
        taxonomy = _load_yaml(TAXONOMY_PATH)
        for entry in taxonomy:
            if "empirical_anchors" in entry:
                self.assertIsInstance(
                    entry["empirical_anchors"], list,
                    f"Entry {entry['class_id']}: empirical_anchors must be a list",
                )
                for anchor in entry["empirical_anchors"]:
                    self.assertIsInstance(anchor, str)
                    self.assertTrue(anchor.strip(), f"Empty anchor in {entry['class_id']}")


if __name__ == "__main__":
    unittest.main()
