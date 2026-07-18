import importlib.util
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "memory-gap-analyzer.py"


def load_module():
    spec = importlib.util.spec_from_file_location("memory_gap_analyzer", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


analyzer = load_module()


class MemoryGapAnalyzerG2Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="auditooor-memory-gap-analyzer-")
        self.root = Path(self.tmp.name)
        self.vault = self.root / "obsidian-vault"
        self.calibration = self.vault / "calibration"
        self.task_types = self.calibration / "task-types"
        self.task_types.mkdir(parents=True)

    def tearDown(self):
        self.tmp.cleanup()

    def test_g2_distinguishes_decided_rows_from_total_dispatch_activity(self):
        self.calibration.joinpath("INDEX.md").write_text(
            "---\n"
            "category: \"calibration-index\"\n"
            "---\n"
            "\n"
            "# Agent + Provider Calibration - Index\n"
            "\n"
            "## Quick-answer routing table\n"
            "\n"
            "| Task type | Best provider | TP rate | n | Status |\n"
            "|-----------|--------------|---------|---|--------|\n"
            "| `scope-triage` | - | no data | 0 | no-data |\n"
            "\n"
            "## Task-type notes\n"
            "\n"
            "- [[calibration/task-types/scope-triage|scope-triage]] - "
            "n=4, decided=0, overall TP=no-data\n",
            encoding="utf-8",
        )
        self.task_types.joinpath("scope-triage.md").write_text(
            "---\n"
            "category: \"calibration-task-type\"\n"
            "task_type: \"scope-triage\"\n"
            "total_dispatches: \"4\"\n"
            "decided: \"0\"\n"
            "overall_tp_rate: \"no-data\"\n"
            "best_provider: \"no-data\"\n"
            "n: \"0\"\n"
            "---\n"
            "\n"
            "# Task type: `scope-triage`\n"
            "\n"
            "## Overview\n"
            "\n"
            "- **Total dispatches**: 4\n"
            "- **Decided** (TRUE+FALSE): 0\n",
            encoding="utf-8",
        )

        hits = analyzer.gather_g2(self.vault, min_n=5)

        self.assertEqual(1, len(hits))
        hit = hits[0]
        self.assertIn("decided n=0 (<5)", hit.title)
        self.assertIn("total dispatches=4", hit.title)
        self.assertNotIn("has n=0", hit.title)
        self.assertIn("not a no-activity claim", hit.description)
        self.assertIn("total_dispatches=4, decided=0", hit.evidence)
        self.assertNotIn("crank n up", hit.description)
        self.assertTrue(any(
            path.endswith("calibration/task-types/scope-triage.md")
            for path in hit.source_paths
        ))


class MemoryGapAnalyzerG5Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="auditooor-memory-gap-analyzer-")
        self.root = Path(self.tmp.name)
        self.vault = self.root / "obsidian-vault"
        self.errors = self.vault / "errors"
        self.errors.mkdir(parents=True)

    def tearDown(self):
        self.tmp.cleanup()

    def write_error(self, name: str, body: str) -> None:
        self.errors.joinpath(name).write_text(body, encoding="utf-8")

    def test_strip_yaml_frontmatter_preserves_body(self):
        note = (
            "---\n"
            "source: 'log-errors'\n"
            "last_synced: '2026-05-04T20:03:42Z'\n"
            "---\n"
            "\n"
            "body_token remains\n"
        )

        stripped = analyzer.strip_yaml_frontmatter(note)

        self.assertNotIn("last_synced", stripped)
        self.assertIn("body_token", stripped)

    def test_g5_ignores_frontmatter_only_repeat_tokens(self):
        frontmatter = (
            "---\n"
            "source: 'log-errors'\n"
            "last_synced: '2026-05-04T20:03:42Z'\n"
            "error_line_count: 1\n"
            "---\n"
        )
        self.write_error(
            "queue-a-2026-05-04.md",
            frontmatter + "\nphase_b_issue appears in body once\n",
        )
        self.write_error(
            "queue-b-2026-05-04.md",
            frontmatter + "\nphase_b_issue appears in body once\n",
        )

        hits = analyzer.gather_g5(self.vault, max_items=10)
        titles = [hit.title for hit in hits]

        self.assertIn("Repeat-error token `phase_b_issue` in 2 error notes", titles)
        self.assertFalse(any("last_synced" in title for title in titles))

    def test_g5_ignores_log_key_value_tokens(self):
        self.write_error(
            "queue-a-2026-05-04.md",
            "2026-05-04T10:19:23Z [start] skip_fail_threshold=3\n"
            "2026-05-04T10:19:24Z [err] task-a rc=2 consecutive_fails=1\n"
            "real_failure_mode appears in body once\n",
        )
        self.write_error(
            "queue-b-2026-05-04.md",
            "2026-05-04T10:20:23Z [start] skip_fail_threshold=3\n"
            "2026-05-04T10:20:24Z [err] task-b rc=3 consecutive_fails=2\n"
            "real_failure_mode appears in body once\n",
        )

        hits = analyzer.gather_g5(self.vault, max_items=10)
        titles = [hit.title for hit in hits]

        self.assertIn("Repeat-error token `real_failure_mode` in 2 error notes", titles)
        self.assertFalse(any("consecutive_fails" in title for title in titles))
        self.assertFalse(any("skip_fail_threshold" in title for title in titles))


class MemoryGapAnalyzerG7Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="auditooor-memory-gap-analyzer-")
        self.root = Path(self.tmp.name)
        self.vault = self.root / "obsidian-vault"
        self.routines = self.vault / "routines"
        self.sources = self.root / "scheduled-tasks"
        self.routines.mkdir(parents=True)
        self.sources.mkdir(parents=True)

    def tearDown(self):
        self.tmp.cleanup()

    def write_routine_pair(self, task_id: str, note_body: str, source_body: str) -> None:
        task_dir = self.sources / task_id
        task_dir.mkdir()
        source_path = task_dir / "SKILL.md"
        source_path.write_text(source_body, encoding="utf-8")
        self.routines.joinpath(f"{task_id}.md").write_text(
            "---\n"
            "source: 'scheduled-task'\n"
            f"task_id: '{task_id}'\n"
            f"canonical_path: '{source_path}'\n"
            "---\n"
            "\n"
            f"{note_body}",
            encoding="utf-8",
        )

    def age_routines_notes(self, hours: float) -> None:
        old = time.time() - hours * 3600.0
        for path in self.routines.glob("*.md"):
            os.utime(path, (old, old))

    def test_g7_skips_stale_routines_when_source_mirror_is_current(self):
        body = "# Routine\n\nStatic scheduled-task instructions.\n"
        self.write_routine_pair("auditooor-hourly", body, body)
        self.age_routines_notes(analyzer.VAULT_STALE_HOURS + 6)

        hits = analyzer.gather_g7(self.vault, max_items=10)

        self.assertFalse(any("`routines`" in hit.title for hit in hits))

    def test_g7_still_flags_stale_routines_when_source_content_changed(self):
        self.write_routine_pair(
            "auditooor-hourly",
            "# Routine\n\nOld scheduled-task instructions.\n",
            "# Routine\n\nChanged scheduled-task instructions.\n",
        )
        self.age_routines_notes(analyzer.VAULT_STALE_HOURS + 6)

        hits = analyzer.gather_g7(self.vault, max_items=10)

        self.assertTrue(any("`routines`" in hit.title for hit in hits))

    def test_g7_still_flags_stale_routines_when_source_task_is_missing_from_mirror(self):
        body = "# Routine\n\nStatic scheduled-task instructions.\n"
        self.write_routine_pair("auditooor-hourly", body, body)
        extra = self.sources / "new-routine" / "SKILL.md"
        extra.parent.mkdir()
        extra.write_text("# Routine\n\nNew scheduled-task instructions.\n", encoding="utf-8")
        self.age_routines_notes(analyzer.VAULT_STALE_HOURS + 6)

        hits = analyzer.gather_g7(self.vault, max_items=10)

        self.assertTrue(any("`routines`" in hit.title for hit in hits))


# r36-rebuttal: bugfix-inventory-claude-20260610
class MemoryGapAnalyzerNewestMtimeSymlinkTests(unittest.TestCase):
    """newest_mtime() must not follow symlink files into external targets.

    A symlink file inside a vault category dir whose external target has a
    fresh mtime must NOT mask stale real files in the same dir.  Before the
    fix, p.is_file() returned True for symlinks and p.stat().st_mtime
    followed the target, producing false-green G7 staleness detection.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="auditooor-mga-symlink-")
        self.root = Path(self.tmp.name)
        self.cat_dir = self.root / "vault" / "calibration"
        self.cat_dir.mkdir(parents=True)
        self.external_dir = self.root / "external"
        self.external_dir.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def test_newest_mtime_excludes_symlink_files(self):
        """newest_mtime() returns the stale real file's mtime, not the
        fresh external target's mtime reached via a symlink file."""
        # Stale real vault file - older than VAULT_STALE_HOURS (24h)
        stale_real = self.cat_dir / "stale_real.md"
        stale_real.write_text("stale content", encoding="utf-8")
        stale_mtime = time.time() - (analyzer.VAULT_STALE_HOURS + 6) * 3600
        os.utime(stale_real, (stale_mtime, stale_mtime))

        # Fresh external file (outside the vault) - mtime = now
        fresh_external = self.external_dir / "fresh_external.md"
        fresh_external.write_text("fresh external content", encoding="utf-8")
        # mtime is already now; no adjustment needed

        # Symlink inside vault category pointing at the fresh external file
        symlink_file = self.cat_dir / "symlink_to_fresh.md"
        symlink_file.symlink_to(fresh_external)

        # newest_mtime should return the stale real file's mtime, NOT the
        # fresh external target's mtime.
        result = analyzer.newest_mtime(self.cat_dir)

        self.assertIsNotNone(result)
        # Result must be close to the stale mtime, not the fresh external mtime.
        # Allow 1-second tolerance.
        self.assertAlmostEqual(result, stale_mtime, delta=1.0,
            msg="newest_mtime() followed a symlink to an external fresh file "
                "and returned its mtime instead of the stale real file's mtime "
                "(false-green: symlink masks staleness)")

    def test_g7_fires_when_only_fresh_symlink_masks_stale_real_file(self):
        """G7 staleness gap is emitted when the only 'fresh' file in a
        vault category is a symlink to an external target - the stale real
        file must still be seen as the newest real vault file."""
        vault = self.root / "obsidian-vault"
        vault.mkdir()
        cat_dir = vault / "calibration"
        cat_dir.mkdir()

        # Stale real vault file
        stale_real = cat_dir / "stale.md"
        stale_real.write_text("stale content", encoding="utf-8")
        stale_mtime = time.time() - (analyzer.VAULT_STALE_HOURS + 6) * 3600
        os.utime(stale_real, (stale_mtime, stale_mtime))

        # Fresh external file, symlinked into the category
        fresh_external = self.external_dir / "fresh.md"
        fresh_external.write_text("fresh content", encoding="utf-8")
        symlink_file = cat_dir / "link_to_fresh.md"
        symlink_file.symlink_to(fresh_external)

        hits = analyzer.gather_g7(vault, max_items=10)

        self.assertTrue(
            any("`calibration`" in hit.title for hit in hits),
            "G7 must flag the stale 'calibration' category even though a "
            "symlink to a fresh external file is present in the same dir "
            "(symlink must not mask real file staleness)")


if __name__ == "__main__":
    unittest.main()
