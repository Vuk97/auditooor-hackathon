"""Unit tests for vault-frame-extractor L2 source ordering (PR #658 Tier-B #8).

Checks:
  1. L2_SOURCES list has r-rounds first, engagement-retros second.
  2. --source filter narrows scan to a single named source.
  3. In priority order (r-rounds first), an r-rounds anchor wins over a
     case_study anchor for the same root_cause_class when both are present.
  4. --source-priority reverse inverts: case_study anchor appears first in
     cluster when list is reversed.
  5. Unknown --source filter raises ValueError before scanning.
"""
from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "vault-frame-extractor.py"


def _load():
    spec = importlib.util.spec_from_file_location("vault_frame_extractor", MODULE_PATH)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


vfe = _load()

# A markdown body that matches the reentrancy heuristic (>= 200 chars)
_REENTRANT_BODY = (
    "# Reentrancy in withdraw\n\n"
    "The callback allows reentrant calls into the vault before the balance "
    "is updated. An attacker can drain all funds via repeated reentrant "
    "invocations. This is a classic reentrancy / callback vulnerability "
    "affecting the withdrawal flow in the Morpho engagement.\n"
    "Detailed analysis follows below. Remediation: add nonReentrant guard.\n"
)

# Another body for a distinct bug class (panic)
_PANIC_BODY = (
    "# Nil pointer crash in sync loop\n\n"
    "A nil-point dereference panic occurs when the chain-watcher receives "
    "an empty peer list during bootstrap. This leads to a crash of the "
    "sync goroutine and effectively freezes all outbound transfers until "
    "the operator manually restarts the service.\n"
    "Extensive reproduction notes and PoC test transcripts are below.\n"
)


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


class TestL2SourcesListOrder(unittest.TestCase):
    """Test 1: static list ordering."""

    def test_r_rounds_is_first(self):
        self.assertEqual(vfe.L2_SOURCES[0], "r-rounds/**/*.md")

    def test_engagement_retros_is_second(self):
        self.assertEqual(vfe.L2_SOURCES[1], "engagement-retros/**/*.md")

    def test_case_study_is_third(self):
        self.assertEqual(vfe.L2_SOURCES[2], "case_study/**/*.md")

    def test_all_five_sources_present(self):
        self.assertEqual(len(vfe.L2_SOURCES), 5)
        self.assertIn("findings/**/*.md", vfe.L2_SOURCES)
        self.assertIn("rollups/**/*.md", vfe.L2_SOURCES)


class TestSourceFilter(unittest.TestCase):
    """Test 2: --source filter narrows scan to one source."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="vfe-test-source-filter-")
        self.vault = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_source_filter_r_rounds_only(self):
        # Place a reentrancy note in r-rounds and a panic note in case_study
        _write(self.vault / "r-rounds" / "rr-001.md", _REENTRANT_BODY)
        _write(self.vault / "case_study" / "cs-001.md", _PANIC_BODY)

        clusters = vfe.scan_l2_sources(self.vault, source_filter="r-rounds")

        # Should find reentrancy (from r-rounds) but NOT panic (in case_study)
        self.assertIn("reentrancy", clusters)
        self.assertNotIn("panic_class", clusters)

    def test_source_filter_case_study_only(self):
        _write(self.vault / "r-rounds" / "rr-001.md", _REENTRANT_BODY)
        _write(self.vault / "case_study" / "cs-001.md", _PANIC_BODY)

        clusters = vfe.scan_l2_sources(self.vault, source_filter="case_study")

        self.assertIn("panic_class", clusters)
        self.assertNotIn("reentrancy", clusters)

    def test_source_filter_empty_source_yields_empty_clusters(self):
        # engagement-retros dir has no files
        clusters = vfe.scan_l2_sources(self.vault, source_filter="engagement-retros")
        self.assertEqual(clusters, {})

    def test_source_filter_unknown_raises(self):
        with self.assertRaises(ValueError):
            vfe.scan_l2_sources(self.vault, source_filter="nonexistent-source")


class TestSourcePriorityOrder(unittest.TestCase):
    """Test 3: r-rounds anchor wins over case_study for same root_cause_class
    when source_priority='list' (default).
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="vfe-test-priority-")
        self.vault = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_r_rounds_anchor_appears_first_in_default_order(self):
        # Both files match reentrancy
        _write(self.vault / "r-rounds" / "rr-001.md", _REENTRANT_BODY)
        _write(self.vault / "case_study" / "cs-001.md", _REENTRANT_BODY)

        clusters = vfe.scan_l2_sources(self.vault, source_priority="list")
        self.assertIn("reentrancy", clusters)
        members = clusters["reentrancy"]
        self.assertEqual(len(members), 2)
        # First member must come from r-rounds
        self.assertTrue(
            members[0]["path"].startswith("r-rounds/"),
            f"Expected first anchor from r-rounds, got: {members[0]['path']}",
        )

    def test_source_label_recorded_on_each_member(self):
        _write(self.vault / "r-rounds" / "rr-001.md", _REENTRANT_BODY)
        clusters = vfe.scan_l2_sources(self.vault, source_priority="list")
        self.assertIn("reentrancy", clusters)
        member = clusters["reentrancy"][0]
        self.assertIn("source", member)
        self.assertEqual(member["source"], "r-rounds")


class TestSourcePriorityReverse(unittest.TestCase):
    """Test 4: --source-priority reverse puts case_study before r-rounds."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="vfe-test-reverse-")
        self.vault = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_reverse_puts_rollups_before_r_rounds(self):
        # Both match reentrancy; in reverse order rollups comes before r-rounds
        _write(self.vault / "r-rounds" / "rr-001.md", _REENTRANT_BODY)
        _write(self.vault / "rollups" / "ru-001.md", _REENTRANT_BODY)

        clusters_fwd = vfe.scan_l2_sources(self.vault, source_priority="list")
        clusters_rev = vfe.scan_l2_sources(self.vault, source_priority="reverse")

        members_fwd = clusters_fwd.get("reentrancy", [])
        members_rev = clusters_rev.get("reentrancy", [])

        self.assertEqual(len(members_fwd), 2)
        self.assertEqual(len(members_rev), 2)

        # In forward order: r-rounds first
        self.assertTrue(members_fwd[0]["path"].startswith("r-rounds/"))
        # In reverse order: rollups first (rollups is last in L2_SOURCES, so
        # first in reversed list)
        self.assertTrue(members_rev[0]["path"].startswith("rollups/"))


if __name__ == "__main__":
    unittest.main()
