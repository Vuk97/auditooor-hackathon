"""Tests for tools/verdict-tag-llm-filler.py — heuristic LLM-hybrid classifier."""
from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import textwrap
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "verdict-tag-llm-filler.py"
TAXONOMY_PATH = REPO_ROOT / "reference" / "bug_class_taxonomy.yaml"
ATTACK_VOCAB_PATH = REPO_ROOT / "reference" / "attack_class_vocab.yaml"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


class LLMFillerTests(unittest.TestCase):
    """Core heuristic classifier tests."""

    def setUp(self) -> None:
        try:
            import yaml  # noqa: F401
        except ImportError:
            self.skipTest("PyYAML not installed — skipping verdict-tag-llm-filler tests")
        self.filler = _load(TOOL_PATH, "_vtlf")
        self.taxonomy = self.filler.load_taxonomy(TAXONOMY_PATH)
        self.attack_vocab = self.filler.load_attack_vocab(ATTACK_VOCAB_PATH)

    # ------------------------------------------------------------------
    # Test 1: Classifier returns non-empty bug_class for known prose
    # ------------------------------------------------------------------

    def test_classify_blocked_addr_prose(self) -> None:
        """Prose about missing blocked-addr check should classify correctly."""
        prose = textwrap.dedent("""
            ## Finding
            The fee distribution path does not consult the blocked-address registry.
            An attacker can cause affiliate revenue share (rev_share) to be sent to a
            module account (blocked), permanently freezing the funds. The function
            AffiliateRevShareFee does not call IsBlockedAddr() / BlockedAddr before
            distributing to the affiliate address.
            Severity: CRITICAL
        """)
        bug_class, attacks, confidence = self.filler.classify_verdict(
            verdict_id="cantina-192-test",
            text=prose,
            taxonomy=self.taxonomy,
            attack_vocab=self.attack_vocab,
            min_confidence=0.1,
        )
        self.assertIsNotNone(bug_class, "Expected a bug_class to be returned")
        self.assertIsInstance(attacks, list)
        self.assertGreaterEqual(confidence, 0.1)
        # Should pick something related to blocked-addr or authority
        self.assertIn(
            bug_class,
            [
                "missing-blocked-addr-check-on-fee-distribution",
                "missing-authority-check",
                "fee-redirect",
            ],
            f"Unexpected bug_class={bug_class!r} for blocked-addr prose",
        )

    # ------------------------------------------------------------------
    # Test 2: Reads existing tag with empty semantic fields, fills them
    # ------------------------------------------------------------------

    def test_fill_empty_tag_writes_fields(self) -> None:
        """apply_fill populates bug_class and attack_classes_to_try in a tag dict."""
        tag = {
            "verdict_id": "dydx-hunt-iter-1/DYDX-HUNT-C3-bridge-proof-domain-verdict.md",
            "target_repo": "dydxprotocol/v4-chain",
            "audit_pin_sha": "5ee9766",
            "language": "go",
            "verdict_class": "DROP",
            "extraction_provenance": "regex",
            "extractor_version": "0.1.0",
            "extracted_at_utc": "2026-05-11T08:54:54Z",
        }
        # Confirm fields are absent
        self.assertNotIn("bug_class", tag)
        self.assertNotIn("attack_classes_to_try", tag)

        updated = self.filler.apply_fill(
            tag,
            bug_class="bridge-proof-domain-bypass",
            attack_classes=["bridge-proof-domain-bypass", "signature-replay-cross-domain"],
            confidence=0.72,
            dry_run=False,
        )
        self.assertEqual(updated["bug_class"], "bridge-proof-domain-bypass")
        self.assertIn("bridge-proof-domain-bypass", updated["attack_classes_to_try"])
        self.assertEqual(updated["extraction_provenance"], "hybrid")
        self.assertIn("phase-f-heuristic", updated.get("notes", ""))
        # Original tag must not be mutated (copy semantics)
        self.assertNotIn("bug_class", tag)

    # ------------------------------------------------------------------
    # Test 3: --dry-run does NOT write tag files
    # ------------------------------------------------------------------

    def test_dry_run_does_not_write(self) -> None:
        """apply_fill with dry_run=True returns updated dict but caller must not write."""
        import yaml  # noqa: F811

        tag = {
            "verdict_id": "spark-test/some-verdict.md",
            "target_repo": "buildonspark/spark",
            "audit_pin_sha": "abc1234",
            "language": "go",
            "verdict_class": "CANDIDATE",
            "extraction_provenance": "regex",
            "extractor_version": "0.1.0",
            "extracted_at_utc": "2026-05-11T00:00:00Z",
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            tag_path = Path(tmpdir) / "test_tag.yaml"
            # Write the original tag without bug_class
            tag_path.write_text(yaml.dump(tag), encoding="utf-8")

            # Simulate dry_run: apply_fill is called but tag_path is NOT written
            updated = self.filler.apply_fill(tag, "chain-watcher-bypass", ["chain-watcher-bypass"], 0.5, dry_run=True)

            # File on disk should remain unchanged (no bug_class)
            on_disk = yaml.safe_load(tag_path.read_text())
            self.assertNotIn("bug_class", on_disk, "dry_run must not write to disk")
            # updated dict has the field
            self.assertEqual(updated["bug_class"], "chain-watcher-bypass")

    # ------------------------------------------------------------------
    # Test 4: --require-min-confidence filters low-confidence tags
    # ------------------------------------------------------------------

    def test_require_min_confidence_filters(self) -> None:
        """classify_verdict returns (None, [], score) when score < min_confidence."""
        # Empty prose + a verdict_id with no meaningful signals
        prose = "This is a completely generic text with no security keywords at all."
        bug_class, attacks, confidence = self.filler.classify_verdict(
            verdict_id="generic-test",
            text=prose,
            taxonomy=self.taxonomy,
            attack_vocab=self.attack_vocab,
            min_confidence=0.99,  # extremely high threshold
        )
        self.assertIsNone(bug_class, "High min_confidence should yield None bug_class")
        self.assertEqual(attacks, [])
        self.assertLess(confidence, 0.99)

    # ------------------------------------------------------------------
    # Test 5: tag_needs_filling returns correct boolean
    # ------------------------------------------------------------------

    def test_tag_needs_filling_logic(self) -> None:
        """tag_needs_filling returns True when bug_class or attack_classes_to_try is absent."""
        # Missing both
        tag_empty = {"verdict_id": "x.md", "bug_class": "", "attack_classes_to_try": []}
        self.assertTrue(self.filler.tag_needs_filling(tag_empty))

        # Has bug_class but no attacks
        tag_partial = {"verdict_id": "x.md", "bug_class": "missing-authority-check", "attack_classes_to_try": []}
        self.assertTrue(self.filler.tag_needs_filling(tag_partial))

        # Has both
        tag_full = {
            "verdict_id": "x.md",
            "bug_class": "missing-authority-check",
            "attack_classes_to_try": ["admin-bypass"],
        }
        self.assertFalse(self.filler.tag_needs_filling(tag_full))

        # Missing keys entirely
        tag_none = {"verdict_id": "x.md"}
        self.assertTrue(self.filler.tag_needs_filling(tag_none))

    # ------------------------------------------------------------------
    # Test 6: Race condition prose classified correctly
    # ------------------------------------------------------------------

    def test_classify_race_condition_prose(self) -> None:
        """Prose mentioning race/goroutine/mutex should map to a race class."""
        prose = textwrap.dedent("""
            The fast-node cache is accessed concurrently from multiple goroutines.
            The mutex is not held during a read-modify-write sequence, causing
            data races detected by go test -race. apphash divergence follows.
        """)
        bug_class, attacks, confidence = self.filler.classify_verdict(
            verdict_id="iavl-race-test",
            text=prose,
            taxonomy=self.taxonomy,
            attack_vocab=self.attack_vocab,
            min_confidence=0.1,
        )
        self.assertIsNotNone(bug_class)
        self.assertIn(
            bug_class,
            ["race-condition-fast-node-cache", "race-condition-importer-commit-batch",
             "state-corruption-via-race", "race-condition-shutdown-deadlock"],
            f"Expected a race-class, got {bug_class!r}",
        )
        self.assertGreaterEqual(confidence, 0.1)

    # ------------------------------------------------------------------
    # Test 7: attack_class_vocab only returns known entries
    # ------------------------------------------------------------------

    def test_pick_attack_classes_returns_known_vocab(self) -> None:
        """pick_attack_classes only returns IDs present in the vocab."""
        # Use the blocked-addr entry from taxonomy
        entry = next(
            (e for e in self.taxonomy if e["class_id"] == "missing-blocked-addr-check-on-fee-distribution"),
            None,
        )
        self.assertIsNotNone(entry, "Taxonomy must contain missing-blocked-addr entry")
        result = self.filler.pick_attack_classes(entry, self.attack_vocab, "", min_attack=2)
        for ac in result:
            self.assertIn(ac, self.attack_vocab, f"Attack class {ac!r} not in vocab")


class LLMFillerWriteRoundtripTest(unittest.TestCase):
    """Test that write_tag_file / load_tag_file roundtrip preserves audit_pin_sha quoting."""

    def setUp(self) -> None:
        try:
            import yaml  # noqa: F401
        except ImportError:
            self.skipTest("PyYAML not installed")
        self.filler = _load(TOOL_PATH, "_vtlf_rtt")

    def test_write_read_roundtrip_sha_quoted(self) -> None:
        """audit_pin_sha must survive roundtrip as a string (not coerced to int)."""
        tag = {
            "verdict_id": "test/test-verdict.md",
            "target_repo": "dydxprotocol/v4-chain",
            "audit_pin_sha": "0000000",  # all-numeric edge case
            "language": "go",
            "verdict_class": "DROP",
            "extraction_provenance": "regex",
            "extractor_version": "0.1.0",
            "extracted_at_utc": "2026-05-11T12:00:00Z",
            "bug_class": "missing-authority-check",
            "attack_classes_to_try": ["admin-bypass"],
        }
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            tag_path = Path(f.name)
        try:
            self.filler.write_tag_file(tag_path, tag)
            loaded = self.filler.load_tag_file(tag_path)
            self.assertIsInstance(loaded["audit_pin_sha"], str)
            self.assertEqual(loaded["audit_pin_sha"], "0000000")
        finally:
            tag_path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
