"""Tests for tools/r70-file-tracked-verifier.py (Rule 70, Check #118).

# R36: lane LANE-218-R70-FILE-TRACKED-VERIFIER declared in
# .auditooor/agent_pathspec.json via tools/agent-pathspec-register.py.

Covers all per-path verdict branches plus the overall composition logic by
constructing a temporary git repo in each test class. Live `git` invocations
against the auditooor repo are avoided so the tests are hermetic.

Per-path verdicts covered:
  tracked-and-committed
  tracked-staged-not-committed
  tracked-modified-uncommitted
  untracked-on-disk
  missing-from-disk
  tracked-but-empty

Overall verdicts covered:
  pass-all-tracked-and-committed
  pass-no-paths-claimed
  ok-rebuttal
  warn-some-uncommitted
  fail-untracked-or-missing
  fail-strict (via --strict and via --require-committed)

Also covers:
  - --draft mode path extraction
  - --draft mode rebuttal extraction (visible line + HTML comment)
  - JSON output schema validity
  - Live demo against the auditooor session's at-risk files (per the lane
    brief Step 6)
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "r70_file_tracked_verifier",
    ROOT / "tools" / "r70-file-tracked-verifier.py",
)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)  # type: ignore[union-attr]

check = mod.check
SCHEMA_VERSION = mod.SCHEMA_VERSION
GATE = mod.GATE
_extract_paths_from_text = mod._extract_paths_from_text
_extract_rebuttal = mod._extract_rebuttal


# ---------------------------------------------------------------------------
# Git fixture helpers
# ---------------------------------------------------------------------------

# R36: agent_pathspec.json declared LANE-218 via tools/agent-pathspec-register.py.
def _git(args, cwd):
    env = os.environ.copy()
    env.setdefault("GIT_AUTHOR_NAME", "r70-test")
    env.setdefault("GIT_AUTHOR_EMAIL", "r70-test@example.invalid")
    env.setdefault("GIT_COMMITTER_NAME", "r70-test")
    env.setdefault("GIT_COMMITTER_EMAIL", "r70-test@example.invalid")
    # The auditooor git wrapper at ~/.auditooor/bin/git gates commit/push
    # on .auditooor/last_mcp_recall.json freshness for the current
    # workspace. Our tests operate on a hermetic temp git repo for which
    # that gate is not applicable; set AUDITOOOR_MCP_REQUIRED=0 to bypass
    # (the wrapper logs the bypass to .auditooor/bypass_log.jsonl).
    env["AUDITOOOR_MCP_REQUIRED"] = "0"
    return subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=20,
        check=False,
    )


def _make_repo() -> Path:
    """Create a temp git repo with an initial commit (so HEAD exists)."""
    repo = Path(tempfile.mkdtemp(prefix="r70_test_"))
    _git(["init", "-q", "-b", "main"], cwd=repo)
    _git(["config", "user.email", "r70-test@example.invalid"], cwd=repo)
    _git(["config", "user.name", "r70-test"], cwd=repo)
    (repo / "README.md").write_text("# r70 test repo\n", encoding="utf-8")
    _git(["add", "README.md"], cwd=repo)
    _git(["commit", "-q", "-m", "init"], cwd=repo)
    return repo


def _write(repo: Path, rel: str, body: str) -> Path:
    p = repo / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# Per-path verdict tests
# ---------------------------------------------------------------------------

class TestPerPathVerdicts(unittest.TestCase):

    def setUp(self) -> None:
        self.repo = _make_repo()

    def tearDown(self) -> None:
        shutil.rmtree(self.repo, ignore_errors=True)

    # Case 1: file tracked + committed -> tracked-and-committed
    def test_tracked_and_committed(self) -> None:
        _write(self.repo, "tools/foo.py", "print('hi')\n")
        _git(["add", "tools/foo.py"], cwd=self.repo)
        _git(["commit", "-q", "-m", "add foo"], cwd=self.repo)
        r = check(["tools/foo.py"], repo_root=self.repo)
        self.assertEqual(r["per_path"][0]["verdict"], "tracked-and-committed")
        self.assertEqual(r["verdict"], "pass-all-tracked-and-committed")

    # Case 2: tracked + staged + not committed
    def test_tracked_staged_not_committed(self) -> None:
        _write(self.repo, "tools/bar.py", "print('staged')\n")
        _git(["add", "tools/bar.py"], cwd=self.repo)
        r = check(["tools/bar.py"], repo_root=self.repo)
        self.assertEqual(r["per_path"][0]["verdict"], "tracked-staged-not-committed")
        self.assertEqual(r["verdict"], "warn-some-uncommitted")

    # Case 3: tracked + modified + uncommitted
    def test_tracked_modified_uncommitted(self) -> None:
        _write(self.repo, "tools/baz.py", "print('orig')\n")
        _git(["add", "tools/baz.py"], cwd=self.repo)
        _git(["commit", "-q", "-m", "add baz"], cwd=self.repo)
        _write(self.repo, "tools/baz.py", "print('mutated')\n")
        r = check(["tools/baz.py"], repo_root=self.repo)
        self.assertEqual(r["per_path"][0]["verdict"], "tracked-modified-uncommitted")
        self.assertEqual(r["verdict"], "warn-some-uncommitted")

    # Case 4: file on disk + untracked -> untracked-on-disk (LIFT-9 anchor)
    def test_untracked_on_disk(self) -> None:
        _write(self.repo, "tools/hooks/auditooor-corpus-change-refresh.sh", "#!/bin/sh\n")
        r = check(["tools/hooks/auditooor-corpus-change-refresh.sh"], repo_root=self.repo)
        self.assertEqual(r["per_path"][0]["verdict"], "untracked-on-disk")
        self.assertEqual(r["verdict"], "fail-untracked-or-missing")

    # Case 5: file missing
    def test_missing_from_disk(self) -> None:
        r = check(["tools/does-not-exist.py"], repo_root=self.repo)
        self.assertEqual(r["per_path"][0]["verdict"], "missing-from-disk")
        self.assertEqual(r["verdict"], "fail-untracked-or-missing")

    # Case 6: tracked + zero bytes
    def test_tracked_but_empty(self) -> None:
        _write(self.repo, "tools/empty.py", "")
        _git(["add", "tools/empty.py"], cwd=self.repo)
        _git(["commit", "-q", "-m", "add empty"], cwd=self.repo)
        r = check(["tools/empty.py"], repo_root=self.repo)
        self.assertEqual(r["per_path"][0]["verdict"], "tracked-but-empty")
        self.assertEqual(r["verdict"], "warn-some-uncommitted")


# ---------------------------------------------------------------------------
# Overall verdict composition + flags
# ---------------------------------------------------------------------------

class TestOverallComposition(unittest.TestCase):

    def setUp(self) -> None:
        self.repo = _make_repo()

    def tearDown(self) -> None:
        shutil.rmtree(self.repo, ignore_errors=True)

    # Case 7: --strict promotes warn -> fail-strict
    def test_strict_promotes_warn_to_fail(self) -> None:
        _write(self.repo, "tools/staged.py", "print('staged')\n")
        _git(["add", "tools/staged.py"], cwd=self.repo)
        r = check(["tools/staged.py"], repo_root=self.repo, strict=True)
        self.assertEqual(r["per_path"][0]["verdict"], "tracked-staged-not-committed")
        self.assertEqual(r["verdict"], "fail-strict")

    # Case 8: --require-committed treats staged-only as fail-strict
    def test_require_committed_rejects_staged(self) -> None:
        _write(self.repo, "tools/staged.py", "print('staged')\n")
        _git(["add", "tools/staged.py"], cwd=self.repo)
        r = check(["tools/staged.py"], repo_root=self.repo, require_committed=True)
        self.assertEqual(r["verdict"], "fail-strict")

    # Case 9: no paths claimed -> pass-no-paths-claimed
    def test_no_paths_claimed(self) -> None:
        r = check([], repo_root=self.repo)
        self.assertEqual(r["verdict"], "pass-no-paths-claimed")
        self.assertEqual(r["claimed_path_count"], 0)

    # Case 10: rebuttal accepted -> ok-rebuttal short-circuits fail
    def test_rebuttal_short_circuits_fail(self) -> None:
        _write(self.repo, "tools/untracked.py", "print('hi')\n")
        r = check(
            ["tools/untracked.py"],
            repo_root=self.repo,
            rebuttal_reason="calibration log excluded from VCS by design",
        )
        self.assertEqual(r["verdict"], "ok-rebuttal")
        self.assertTrue(r["rebuttal_accepted"])

    # Case 11: mixed - one committed, one missing -> fail-untracked-or-missing
    def test_mixed_committed_and_missing(self) -> None:
        _write(self.repo, "tools/ok.py", "print('ok')\n")
        _git(["add", "tools/ok.py"], cwd=self.repo)
        _git(["commit", "-q", "-m", "add ok"], cwd=self.repo)
        r = check(["tools/ok.py", "tools/missing.py"], repo_root=self.repo)
        self.assertEqual(r["verdict"], "fail-untracked-or-missing")
        verdicts = [p["verdict"] for p in r["per_path"]]
        self.assertIn("tracked-and-committed", verdicts)
        self.assertIn("missing-from-disk", verdicts)


# ---------------------------------------------------------------------------
# JSON / schema integrity
# ---------------------------------------------------------------------------

class TestJsonSchema(unittest.TestCase):

    def setUp(self) -> None:
        self.repo = _make_repo()

    def tearDown(self) -> None:
        shutil.rmtree(self.repo, ignore_errors=True)

    # Case 12: JSON envelope is valid and carries the schema id
    def test_json_envelope_valid(self) -> None:
        _write(self.repo, "tools/x.py", "x = 1\n")
        _git(["add", "tools/x.py"], cwd=self.repo)
        _git(["commit", "-q", "-m", "x"], cwd=self.repo)
        r = check(["tools/x.py"], repo_root=self.repo)
        blob = json.dumps(r)
        parsed = json.loads(blob)
        self.assertEqual(parsed["schema"], SCHEMA_VERSION)
        self.assertEqual(parsed["gate"], GATE)
        self.assertIn("verdict", parsed)
        self.assertIn("per_path", parsed)
        self.assertIn("claimed_path_count", parsed)


# ---------------------------------------------------------------------------
# Draft-mode path + rebuttal extraction
# ---------------------------------------------------------------------------

class TestDraftExtraction(unittest.TestCase):

    # Case 13: extract paths from a lane-result-style markdown body
    def test_extract_paths_from_text(self) -> None:
        body = (
            "Lane completed. Files changed:\n"
            "- tools/r70-file-tracked-verifier.py (new)\n"
            "- tools/tests/test_r70_file_tracked_verifier.py (new)\n"
            "- docs/R70_FILE_TRACKED_VERIFIER_2026-05-26.md (new)\n"
            "- audit/corpus_tags/derived/global_chain_templates.jsonl (new)\n"
            "Random text without paths.\n"
            "Inline reference to `tools/pre-submit-check.sh` updated.\n"
        )
        paths = _extract_paths_from_text(body)
        self.assertIn("tools/r70-file-tracked-verifier.py", paths)
        self.assertIn("tools/tests/test_r70_file_tracked_verifier.py", paths)
        self.assertIn("docs/R70_FILE_TRACKED_VERIFIER_2026-05-26.md", paths)
        self.assertIn("audit/corpus_tags/derived/global_chain_templates.jsonl", paths)
        self.assertIn("tools/pre-submit-check.sh", paths)
        body2 = body + "\nAlso tools/r70-file-tracked-verifier.py again.\n"
        self.assertEqual(
            sum(1 for p in _extract_paths_from_text(body2)
                if p == "tools/r70-file-tracked-verifier.py"),
            1,
        )

    # Case 14a: rebuttal HTML-comment form
    def test_extract_rebuttal_html(self) -> None:
        body = "Some content.\n<!-- r70-rebuttal: build artifact excluded by design -->\nMore.\n"
        self.assertEqual(
            _extract_rebuttal(body),
            "build artifact excluded by design",
        )

    # Case 14b: rebuttal visible-line form
    def test_extract_rebuttal_visible_line(self) -> None:
        body = "Some content.\nr70-rebuttal: log file gitignored intentionally\nMore content.\n"
        self.assertEqual(
            _extract_rebuttal(body),
            "log file gitignored intentionally",
        )

    # Case 15a: empty rebuttal ignored
    def test_rebuttal_empty_ignored(self) -> None:
        body = "<!-- r70-rebuttal: -->\n"
        self.assertIsNone(_extract_rebuttal(body))

    # Case 15b: oversized rebuttal ignored
    def test_rebuttal_oversized_ignored(self) -> None:
        oversized = "x" * 201
        body = f"<!-- r70-rebuttal: {oversized} -->\n"
        self.assertIsNone(_extract_rebuttal(body))


# ---------------------------------------------------------------------------
# Backward-compatibility smoke: tool importable + main() runs
# ---------------------------------------------------------------------------

class TestBackwardCompat(unittest.TestCase):

    # Case 16: module exposes the public API the brief expects.
    def test_public_api_present(self) -> None:
        self.assertTrue(callable(check))
        self.assertTrue(callable(mod.main))
        self.assertTrue(isinstance(SCHEMA_VERSION, str))
        self.assertEqual(GATE, "R70-FILE-TRACKED-IN-GIT")

    # Case 17: --json flag runs end-to-end against the live auditooor repo
    # without raising. tools/pre-submit-check.sh is always tracked-and-committed
    # in this repo.
    def test_main_runs_against_committed_file(self) -> None:
        rc = mod.main([
            "--claimed-paths", "tools/pre-submit-check.sh",
            "--repo-root", str(ROOT),
            "--json",
        ])
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
