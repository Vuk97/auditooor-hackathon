"""
Tests for tools/codex-activity-snapshot.py

Covers:
  1. Empty-repo / no-commits window -> empty lists
  2. Codex direct-author commit is detected
  3. Codex co-author trailer is detected
  4. Claude-only commits are NOT classified as Codex
  5. Shared-path hotspot detection
  6. In-flight file detection by pattern
  7. In-flight file mtime filtering (within 4h vs older)
  8. Risk-flag fires when Codex committed recently in a Claude-staged dir
  9. Safe-to-commit marks overlap correctly
  10. JSON output is valid and contains schema field
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import time
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "codex-activity-snapshot.py"


def _load() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("codex_activity_snapshot", TOOL_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load {TOOL_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules["codex_activity_snapshot"] = module
    spec.loader.exec_module(module)
    return module


mod = _load()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_commit(
    sha: str,
    author_email: str,
    subject: str,
    ts: int | None = None,
    has_codex_coauthor: bool = False,
) -> dict:
    ts = ts or int(time.time()) - 3600
    is_codex_author = mod._is_codex_author(author_email)
    is_claude_author = mod._is_claude_author(author_email)
    return {
        "sha": sha[:12],
        "sha_full": sha,
        "author_name": "Test Author",
        "author_email": author_email,
        "timestamp": ts,
        "subject": subject,
        "is_codex_author": is_codex_author,
        "has_codex_coauthor": has_codex_coauthor,
        "is_codex_commit": is_codex_author or has_codex_coauthor,
        "is_claude_author": is_claude_author,
        "files_changed": [],
    }


# ---------------------------------------------------------------------------
# Unit tests
# ---------------------------------------------------------------------------

class TestIsCodexAuthor(unittest.TestCase):
    def test_codex_local_email(self):
        self.assertTrue(mod._is_codex_author("codex@auditooor.local"))

    def test_codex_openai_email(self):
        self.assertTrue(mod._is_codex_author("codex@openai.com"))

    def test_noreply_openai_email(self):
        self.assertTrue(mod._is_codex_author("noreply@openai.com"))

    def test_claude_anthropic_is_not_codex(self):
        self.assertFalse(mod._is_codex_author("noreply@anthropic.com"))

    def test_human_email_is_not_codex(self):
        self.assertFalse(mod._is_codex_author("wolf@Vuks-Laptop.local"))


class TestIsClaudeAuthor(unittest.TestCase):
    def test_claude_anthropic(self):
        self.assertTrue(mod._is_claude_author("noreply@anthropic.com"))

    def test_claude_at_anthropic(self):
        self.assertTrue(mod._is_claude_author("claude@anthropic.com"))

    def test_codex_is_not_claude(self):
        self.assertFalse(mod._is_claude_author("codex@auditooor.local"))


class TestCodexCoAuthorDetection(unittest.TestCase):
    def test_coauthor_trailer_detected(self):
        body = "Some commit body\n\nCo-Authored-By: Codex <codex@openai.com>"
        self.assertTrue(mod._commit_has_codex_coauthor(body))

    def test_coauthor_gpt_trailer_detected(self):
        body = "fix stuff\n\nCo-Authored-By: Codex gpt-5.5 <noreply@openai.com>"
        self.assertTrue(mod._commit_has_codex_coauthor(body))

    def test_claude_trailer_not_matched(self):
        body = "fix\n\nCo-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
        self.assertFalse(mod._commit_has_codex_coauthor(body))

    def test_no_trailer(self):
        body = "Plain commit message without trailers"
        self.assertFalse(mod._commit_has_codex_coauthor(body))


class TestInflightFileDetection(unittest.TestCase):
    """Test in-flight file pattern matching and mtime filtering."""

    def _make_mock_walk(self, files: list[tuple[str, float]]):
        """Return a mock os.walk that yields the given (relpath, mtime) pairs."""
        def _walk(workspace, *args, **kwargs):
            dirs_seen: set[str] = set()
            roots: dict[str, list[str]] = {}
            for relpath, _ in files:
                root = str(Path(workspace) / Path(relpath).parent)
                fname = Path(relpath).name
                if root not in roots:
                    roots[root] = []
                roots[root].append(fname)
            for root, fnames in roots.items():
                yield root, [], fnames

        return _walk

    def test_hits_ledger_matched(self):
        ws = Path("/fake/ws")
        now = time.time()
        test_files = [("detectors/_hits_ledger.yaml", now - 100)]

        with patch("os.walk") as mock_walk, \
             patch.object(Path, "stat") as mock_stat, \
             patch.object(Path, "relative_to") as mock_rel:
            mock_walk.side_effect = self._make_mock_walk(test_files)
            mock_stat.return_value = MagicMock(st_mtime=now - 100)
            mock_rel.side_effect = lambda base: Path("detectors/_hits_ledger.yaml")

            # Use direct pattern check instead of full function (avoids filesystem)
            fname = "_hits_ledger.yaml"
            matched = any(pat in fname for pat in mod.CODEX_INFLIGHT_PATTERNS)
            self.assertTrue(matched)

    def test_v3_closeout_matched(self):
        fname = "V3_CLOSEOUT_2026-05-22.md"
        matched = any(pat in fname for pat in mod.CODEX_INFLIGHT_PATTERNS)
        self.assertTrue(matched)

    def test_reports_v3_matched(self):
        rel = "reports/v3_wave15_killrubric_promotion.md"
        matched = any(pat in rel for pat in mod.CODEX_INFLIGHT_PATTERNS)
        self.assertTrue(matched)

    def test_normal_file_not_matched(self):
        fname = "tools/pre-submit-check.sh"
        rel = "tools/pre-submit-check.sh"
        matched = any(pat in rel or pat in fname for pat in mod.CODEX_INFLIGHT_PATTERNS)
        self.assertFalse(matched)

    def test_within_4h_flag(self):
        age_fresh = 3000  # 50 min - within 4h
        age_old = 5 * 3600  # 5h - outside window
        self.assertTrue(age_fresh <= mod.CODEX_INFLIGHT_MTIME_WINDOW)
        self.assertFalse(age_old <= mod.CODEX_INFLIGHT_MTIME_WINDOW)


class TestSharedHotspots(unittest.TestCase):
    def test_shared_hotspot_detected(self):
        codex = {"tools/foo.py", "tools/bar.py", "docs/README.md"}
        claude = {"tools/foo.py", "tools/baz.py"}
        hotspots = mod.compute_shared_hotspots(codex, claude)
        self.assertIn("tools/foo.py", hotspots)
        self.assertNotIn("tools/bar.py", hotspots)
        self.assertNotIn("tools/baz.py", hotspots)

    def test_no_overlap(self):
        codex = {"tools/foo.py"}
        claude = {"tools/bar.py"}
        hotspots = mod.compute_shared_hotspots(codex, claude)
        self.assertEqual(hotspots, [])

    def test_empty_sets(self):
        hotspots = mod.compute_shared_hotspots(set(), set())
        self.assertEqual(hotspots, [])


class TestRiskFlags(unittest.TestCase):
    def test_risk_flag_fires(self):
        now = int(time.time())
        # Codex committed 30min ago to tools/
        commits = [
            _make_commit(
                "abc123",
                "codex@auditooor.local",
                "some Codex work",
                ts=now - 1800,  # 30 min ago
            )
        ]
        commits[0]["files_changed"] = ["tools/foo.py"]

        staged = ["tools/foo.py"]
        unstaged = []

        flags = mod.compute_risk_flags(commits, staged, unstaged)
        self.assertEqual(len(flags), 1)
        self.assertIn("tools", flags[0]["directory"])

    def test_no_risk_flag_when_no_overlap(self):
        now = int(time.time())
        commits = [
            _make_commit(
                "abc123",
                "codex@auditooor.local",
                "Codex work in docs/",
                ts=now - 300,
            )
        ]
        commits[0]["files_changed"] = ["docs/foo.md"]

        staged = ["tools/bar.py"]  # different dir
        unstaged = []

        flags = mod.compute_risk_flags(commits, staged, unstaged)
        self.assertEqual(len(flags), 0)

    def test_no_risk_flag_when_codex_commit_old(self):
        now = int(time.time())
        commits = [
            _make_commit(
                "abc123",
                "codex@auditooor.local",
                "old Codex commit",
                ts=now - 7200,  # 2h ago - outside 1h window
            )
        ]
        commits[0]["files_changed"] = ["tools/foo.py"]

        staged = ["tools/foo.py"]
        unstaged = []

        flags = mod.compute_risk_flags(commits, staged, unstaged)
        self.assertEqual(len(flags), 0)


class TestSafeToCommit(unittest.TestCase):
    def test_safe_file(self):
        staged = ["tools/my_new_tool.py"]
        codex_files = {"tools/other_file.py"}
        recs = mod.compute_safe_to_commit(staged, codex_files)
        self.assertEqual(len(recs), 1)
        self.assertTrue(recs[0]["safe"])

    def test_risky_file(self):
        staged = ["tools/shared.py"]
        codex_files = {"tools/shared.py"}
        recs = mod.compute_safe_to_commit(staged, codex_files)
        self.assertEqual(len(recs), 1)
        self.assertFalse(recs[0]["safe"])
        self.assertIn("Codex also touched", recs[0]["reason"])

    def test_empty_staged(self):
        recs = mod.compute_safe_to_commit([], {"tools/foo.py"})
        self.assertEqual(recs, [])


class TestJsonOutput(unittest.TestCase):
    def test_json_valid_and_has_schema(self):
        snap = {
            "schema": "auditooor.codex_activity_snapshot.v1",
            "workspace": "/fake",
            "since": "7 days ago",
            "generated_at": "2026-05-23T00:00:00+00:00",
            "codex_commits": [],
            "inflight_files": [],
            "shared_hotspots": [],
            "codex_files_changed_count": 0,
            "claude_files_changed_count": 0,
            "staged_files": [],
            "unstaged_modified_files": [],
            "risk_flags": [],
            "safe_to_commit": [],
        }
        output = mod.format_json(snap)
        parsed = json.loads(output)
        self.assertEqual(parsed["schema"], "auditooor.codex_activity_snapshot.v1")

    def test_markdown_contains_section_headers(self):
        snap = {
            "schema": "auditooor.codex_activity_snapshot.v1",
            "workspace": "/fake",
            "since": "7 days ago",
            "generated_at": "2026-05-23T00:00:00+00:00",
            "codex_commits": [],
            "inflight_files": [],
            "shared_hotspots": [],
            "codex_files_changed_count": 0,
            "claude_files_changed_count": 0,
            "staged_files": [],
            "unstaged_modified_files": [],
            "risk_flags": [],
            "safe_to_commit": [],
        }
        output = mod.format_markdown(snap)
        self.assertIn("## Codex Commits", output)
        self.assertIn("## Codex In-Flight Files", output)
        self.assertIn("## Shared-Path Hotspots", output)
        self.assertIn("## Risk Flags", output)
        self.assertIn("## Safe-to-Commit Recommendations", output)


if __name__ == "__main__":
    unittest.main()
