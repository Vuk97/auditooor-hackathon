#!/usr/bin/env python3
"""Tests for tools/pattern-merge-rescan.py.

Hermetic. Stdlib-only. Builds throwaway git repos + workspace dirs in
``tempfile.TemporaryDirectory`` and exercises:

* SINCE resolution — commit SHA path (PR-number path is exercised via a
  unit test that monkey-patches ``_run`` to fake the gh response).
* Pattern diff — added / removed identification.
* Candidate-workspace selection logic — explicit, mtime-recent, max cap.
* Hit triage — DUPE / OOS / NEW tags.
* Manifest output is valid JSON with the expected schema fields.
* Markdown output renders the expected sections.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLS_DIR = REPO_ROOT / "tools"
sys.path.insert(0, str(TOOLS_DIR))

# pattern-merge-rescan.py has a dash; import via importlib.
import importlib.util as _il
_spec = _il.spec_from_file_location(
    "pattern_merge_rescan", str(TOOLS_DIR / "pattern-merge-rescan.py"))
assert _spec and _spec.loader
pmr = _il.module_from_spec(_spec)
_spec.loader.exec_module(pmr)  # type: ignore[union-attr]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _git(repo: Path, *args: str) -> str:
    """Run a git command, return stdout. Raise on failure."""
    p = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True, text=True, check=True,
        env={**os.environ,
             "GIT_AUTHOR_NAME": "Test", "GIT_AUTHOR_EMAIL": "t@t.t",
             "GIT_COMMITTER_NAME": "Test", "GIT_COMMITTER_EMAIL": "t@t.t"})
    return p.stdout


def _make_repo(tmp: Path) -> Path:
    repo = tmp / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "commit.gpgsign", "false")
    return repo


def _add_pattern(repo: Path, name: str, body: str) -> None:
    dsl_dir = repo / "reference" / "patterns.dsl"
    dsl_dir.mkdir(parents=True, exist_ok=True)
    (dsl_dir / f"{name}.yaml").write_text(body, encoding="utf-8")


def _commit(repo: Path, msg: str = "x") -> str:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", msg)
    return _git(repo, "rev-parse", "HEAD").strip()


def _sample_pattern(name: str = "test-pattern",
                    pos: str = r"function\s+vulnerable",
                    neg: str = r"safe_guard") -> str:
    return f"""\
pattern: {name}
source: test-source
severity: HIGH
confidence: MEDIUM

preconditions:
  - contract.source_matches_regex: '{pos}'

match:
  - function.kind: external
  - function.body_contains_regex: '{pos}'
  - function.body_not_contains_regex: '{neg}'
  - function.not_in_skip_list: true
"""


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestParsePatternYaml(unittest.TestCase):

    def test_basic_pattern_extraction(self):
        spec = pmr.parse_pattern_yaml(_sample_pattern("foo-bar"))
        self.assertEqual(spec["pattern"], "foo-bar")
        self.assertEqual(spec["source"], "test-source")
        keys = {p["key"] for p in spec["regex_predicates"]}
        self.assertIn("contract.source_matches_regex", keys)
        self.assertIn("function.body_contains_regex", keys)
        self.assertIn("function.body_not_contains_regex", keys)
        # Non-regex predicates dropped:
        self.assertNotIn("function.kind", keys)
        self.assertNotIn("function.not_in_skip_list", keys)

    def test_polarity_classification(self):
        spec = pmr.parse_pattern_yaml(_sample_pattern())
        polarities = {p["key"]: p["polarity"] for p in spec["regex_predicates"]}
        self.assertEqual(polarities["function.body_contains_regex"], "positive")
        self.assertEqual(
            polarities["function.body_not_contains_regex"], "negative")

    def test_quoted_regex_unwrapping(self):
        body = """\
pattern: q
source: q-src

match:
  - function.body_contains_regex: "abc def"
"""
        spec = pmr.parse_pattern_yaml(body)
        self.assertEqual(spec["regex_predicates"][0]["regex"], "abc def")


class TestSinceResolution(unittest.TestCase):

    def test_sha_form(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = _make_repo(Path(tmp))
            _add_pattern(repo, "p1", _sample_pattern("p1"))
            sha = _commit(repo, "init")
            parent, head = pmr.resolve_since(sha, repo, gh_lookup=False)
            self.assertEqual(head, sha)
            self.assertEqual(parent, sha + "~1")

    def test_pr_form_offline_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = _make_repo(Path(tmp))
            with self.assertRaises(ValueError):
                pmr.resolve_since("252", repo, gh_lookup=False)

    def test_pr_form_via_monkeypatched_gh(self):
        # Fake a gh response by monkey-patching _run.
        original_run = pmr._run
        fake_oid = "abc1234567890def"

        def fake_run(argv, cwd=None):
            if list(argv)[:3] == ["gh", "pr", "view"]:
                return 0, json.dumps({"mergeCommit": {"oid": fake_oid}}), ""
            return original_run(argv, cwd=cwd)

        pmr._run = fake_run
        try:
            with tempfile.TemporaryDirectory() as tmp:
                repo = _make_repo(Path(tmp))
                parent, head = pmr.resolve_since("252", repo, gh_lookup=True)
                self.assertEqual(head, fake_oid)
                self.assertEqual(parent, fake_oid + "~1")
        finally:
            pmr._run = original_run

    def test_invalid_since_value(self):
        with self.assertRaises(ValueError):
            pmr.resolve_since("not-a-sha-or-pr", Path("/tmp"))


class TestPatternDiff(unittest.TestCase):

    def test_added_and_removed(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = _make_repo(Path(tmp))
            _add_pattern(repo, "old-pattern", _sample_pattern("old-pattern"))
            base = _commit(repo, "base")

            # Add two new, remove old.
            (repo / "reference" / "patterns.dsl" /
             "old-pattern.yaml").unlink()
            _add_pattern(repo, "new-pattern-a", _sample_pattern("new-pattern-a"))
            _add_pattern(repo, "new-pattern-b", _sample_pattern("new-pattern-b"))
            head = _commit(repo, "shuffle")

            added, removed = pmr.diff_added_patterns(base, head, repo)
            self.assertEqual(added, ["new-pattern-a", "new-pattern-b"])
            self.assertEqual(removed, ["old-pattern"])


class TestSelectWorkspaces(unittest.TestCase):

    def _ws_with(self, root: Path, name: str, *,
                 has_engage: bool = True,
                 has_solidity: bool = True,
                 mtime_offset_days: float = 0) -> Path:
        ws = root / name
        ws.mkdir(parents=True, exist_ok=True)
        if has_engage:
            r = ws / "engage_report.md"
            r.write_text("# engage\n", encoding="utf-8")
            if mtime_offset_days:
                ts = (datetime.now(timezone.utc)
                      - timedelta(days=mtime_offset_days)).timestamp()
                os.utime(r, (ts, ts))
        if has_solidity:
            (ws / "src").mkdir(exist_ok=True)
            (ws / "src" / "X.sol").write_text(
                "pragma solidity ^0.8.0;\ncontract X{}\n", encoding="utf-8")
        return ws

    def test_explicit_workspaces_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws_a = self._ws_with(root, "a")
            ws_b = self._ws_with(root, "b")
            ws_c = self._ws_with(root, "c", has_engage=False)
            picked = pmr.select_workspaces(
                [ws_b, ws_c, ws_a], audits_dir=root,
                mtime_days=30, max_workspaces=9)
            # ws_c has no engage AND no solidity? It does have solidity.
            self.assertEqual([p.name for p in picked], ["b", "c", "a"])

    def test_explicit_skips_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws_a = self._ws_with(root, "a")
            picked = pmr.select_workspaces(
                [ws_a, root / "ghost"], audits_dir=root,
                mtime_days=30, max_workspaces=9)
            self.assertEqual([p.name for p in picked], ["a"])

    def test_explicit_skips_workspace_without_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            empty = root / "empty"
            empty.mkdir()
            picked = pmr.select_workspaces(
                [empty], audits_dir=root,
                mtime_days=30, max_workspaces=9)
            self.assertEqual(picked, [])

    def test_mtime_filter(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._ws_with(root, "fresh", mtime_offset_days=0)
            self._ws_with(root, "stale", mtime_offset_days=60)
            picked = pmr.select_workspaces(
                None, audits_dir=root, mtime_days=30, max_workspaces=9)
            self.assertEqual([p.name for p in picked], ["fresh"])

    def test_max_workspaces_cap(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for n in ("a", "b", "c", "d"):
                self._ws_with(root, n)
            picked = pmr.select_workspaces(
                None, audits_dir=root, mtime_days=30, max_workspaces=2)
            self.assertEqual(len(picked), 2)

    def test_alphabetical_determinism(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for n in ("zebra", "apple", "monetrix"):
                self._ws_with(root, n)
            picked = pmr.select_workspaces(
                None, audits_dir=root, mtime_days=30, max_workspaces=9)
            self.assertEqual([p.name for p in picked],
                             ["apple", "monetrix", "zebra"])


class TestScanFileForPattern(unittest.TestCase):

    def _compile(self, pos: List[str], neg: List[str]):
        preds = (
            [{"key": "k_pos", "regex": r, "polarity": "positive"} for r in pos]
            + [{"key": "k_neg", "regex": r, "polarity": "negative"} for r in neg]
        )
        return pmr._compile_predicates(preds)

    def test_all_positives_match_no_negative_hits(self):
        pos, neg = self._compile([r"foo", r"bar"], [r"safe"])
        hit = pmr.scan_file_for_pattern("foo bar baz", pos, neg)
        self.assertIsNotNone(hit)
        self.assertEqual(hit["matched_keys"], ["k_pos", "k_pos"])

    def test_negative_blocks_hit(self):
        pos, neg = self._compile([r"foo"], [r"safe"])
        hit = pmr.scan_file_for_pattern("foo plus safe-guard", pos, neg)
        self.assertIsNone(hit)

    def test_missing_positive_blocks_hit(self):
        pos, neg = self._compile([r"foo", r"bar"], [])
        hit = pmr.scan_file_for_pattern("foo only", pos, neg)
        self.assertIsNone(hit)

    def test_no_positives_means_no_hit(self):
        pos, neg = self._compile([], [r"never"])
        hit = pmr.scan_file_for_pattern("anything", pos, neg)
        self.assertIsNone(hit)

    def test_first_line_is_one_indexed(self):
        pos, neg = self._compile([r"target"], [])
        content = "line1\nline2\ntarget here\n"
        hit = pmr.scan_file_for_pattern(content, pos, neg)
        self.assertEqual(hit["first_line"], 3)


class TestTriage(unittest.TestCase):

    def _ws(self, root: Path) -> Path:
        ws = root / "ws"
        ws.mkdir()
        (ws / "src").mkdir()
        return ws

    def test_oos_tag_via_path_substring(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._ws(Path(tmp))
            (ws / "OOS_CHECKLIST.md").write_text(
                "- OOS-1: lib/** vendored libraries\n", encoding="utf-8")
            tagged = pmr.triage_hits([{
                "pattern_id": "p", "source": "", "file": "src/lib/Vendored.sol",
                "line": 1, "matched_keys": [],
            }], ws)
            self.assertEqual(tagged[0]["triage"], "OOS")

    def test_dupe_tag_via_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._ws(Path(tmp))
            (ws / "SCAN_REPORT.md").write_text(
                "Found in src/Vault.sol:42 something\n", encoding="utf-8")
            tagged = pmr.triage_hits([{
                "pattern_id": "p", "source": "", "file": "src/Vault.sol",
                "line": 99, "matched_keys": [],
            }], ws)
            self.assertEqual(tagged[0]["triage"], "DUPE")

    def test_new_tag_when_neither(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._ws(Path(tmp))
            (ws / "OOS_CHECKLIST.md").write_text(
                "- OOS-1: lib/** vendored\n", encoding="utf-8")
            (ws / "SCAN_REPORT.md").write_text(
                "Some other file: src/Other.sol:1\n", encoding="utf-8")
            tagged = pmr.triage_hits([{
                "pattern_id": "p", "source": "", "file": "src/NovelTarget.sol",
                "line": 7, "matched_keys": [],
            }], ws)
            self.assertEqual(tagged[0]["triage"], "NEW")


class TestRenderManifest(unittest.TestCase):

    def test_manifest_is_valid_json_with_expected_fields(self):
        ws = Path("/tmp/whatever")
        now = datetime(2026, 4, 26, 12, 0, 0, tzinfo=timezone.utc)
        hits = [{
            "pattern_id": "p1", "source": "src",
            "file": "src/X.sol", "line": 5,
            "matched_keys": ["k1"], "triage": "NEW",
        }]
        m = pmr.render_manifest(
            ws, "252", "abc~1", "abc",
            ["p1"], [], hits, [], now)
        # round-trip through JSON
        s = json.dumps(m, indent=2, sort_keys=True)
        m2 = json.loads(s)
        self.assertEqual(m2["schema"], "auditooor.pattern-merge-rescan.v1")
        self.assertEqual(m2["since"], "252")
        self.assertEqual(m2["counts"]["new_hits"], 1)
        self.assertEqual(m2["counts"]["total_hits"], 1)
        self.assertEqual(m2["added_patterns"], ["p1"])


class TestRenderMarkdown(unittest.TestCase):

    def test_markdown_renders_sections(self):
        ws = Path("/tmp/whatever")
        now = datetime(2026, 4, 26, 12, 0, 0, tzinfo=timezone.utc)
        hits = [{
            "pattern_id": "p1", "source": "src",
            "file": "src/X.sol", "line": 5,
            "matched_keys": ["k1"], "triage": "NEW",
        }, {
            "pattern_id": "p2", "source": "src",
            "file": "src/Y.sol", "line": 1,
            "matched_keys": ["k1"], "triage": "DUPE",
        }]
        out = pmr.render_markdown(
            ws, "abc1234", "abc1233", "abc1234",
            ["p1", "p2"], ["old"], hits, [], now)
        self.assertIn("# Post-merge pattern rescan", out)
        self.assertIn("## Patterns scanned", out)
        self.assertIn("## Triage table", out)
        self.assertIn("## NEW hits — operator action required", out)
        # NEW hit listed:
        self.assertIn("`p1` → `src/X.sol:5`", out)
        # DUPE present in triage table:
        self.assertIn("**DUPE**", out)
        self.assertIn("**NEW**", out)
        # Removed pattern surfaced:
        self.assertIn("`old`", out)

    def test_markdown_zero_hits_negative_result(self):
        ws = Path("/tmp/whatever")
        now = datetime(2026, 4, 26, tzinfo=timezone.utc)
        out = pmr.render_markdown(
            ws, "abc", "abc~1", "abc", ["p1"], [], [], [], now)
        self.assertIn("No candidate hits", out)
        self.assertIn("useful negative result", out)


class TestEndToEndDryRun(unittest.TestCase):
    """Smoke: full main() against a fake repo + workspace, dry-run only."""

    def test_main_dry_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            repo = _make_repo(tmp_p)

            # Base commit: one pattern.
            _add_pattern(repo, "old-p", _sample_pattern("old-p"))
            base_sha = _commit(repo, "base")

            # Head commit: add a vulnerable-marker pattern.
            _add_pattern(repo, "new-p", _sample_pattern(
                "new-p", pos=r"function\s+exploitMe",
                neg=r"AccessControl"))
            head_sha = _commit(repo, "add-new-p")

            # Build a workspace that contains a Solidity file matching the
            # positive but NOT the negative.
            ws = tmp_p / "audits" / "wsA"
            (ws / "src").mkdir(parents=True)
            (ws / "engage_report.md").write_text("ok\n", encoding="utf-8")
            (ws / "src" / "Vulny.sol").write_text(
                "pragma solidity ^0.8;\n"
                "contract Vulny {\n"
                "  function exploitMe() external {}\n"
                "}\n",
                encoding="utf-8")

            argv = [
                "--since", head_sha,
                "--workspaces", str(ws),
                "--repo-root", str(repo),
                "--audits-dir", str(tmp_p / "audits"),
                "--dry-run",
                "--no-calibration",
                "--offline",
                "--json",
            ]
            # Capture stdout
            from io import StringIO
            old_stdout = sys.stdout
            sys.stdout = StringIO()
            try:
                rc = pmr.main(argv)
            finally:
                captured = sys.stdout.getvalue()
                sys.stdout = old_stdout
            self.assertEqual(rc, 0)
            # The last line should be JSON.
            json_line = [
                ln for ln in captured.splitlines() if ln.startswith("{")][-1]
            data = json.loads(json_line)
            self.assertEqual(data["added"], ["new-p"])
            self.assertEqual(len(data["workspaces"]), 1)
            self.assertEqual(data["workspaces"][0]["counts"]["total_hits"], 1)
            # Dry-run: files should NOT be created.
            self.assertFalse(
                (ws / f"postmerge_rescan_"
                 f"{datetime.now(timezone.utc).strftime('%Y-%m-%d')}.md").exists()
            )


if __name__ == "__main__":
    unittest.main()
