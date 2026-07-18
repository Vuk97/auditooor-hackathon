#!/usr/bin/env python3
"""test_d5_wired_into_audit_deep.py - regression guard that the D5 fork
pseudo-version mislabel detector (tools/fork-pseudo-version-mislabel.py) is
actually WIRED into tools/audit-deep.sh, not merely present on disk.

Item-9 wave-2 capability wiring. The detector existed but was never invoked by
the pipeline, so on fork targets it sat dead. This test fails on the pre-wiring
audit-deep.sh (which contains zero references to the tool) and passes after the
Step 15b sub-stage is added.

Coverage:
  (1) dead-unwired guard: "fork-pseudo-version-mislabel.py" appears in the
      audit-deep.sh body, plus the Step 15b header, the fork-gated skip branch,
      and the DRY_RUN skip branch (mirrors test_orphan_producer_wiring.py:69).
  (2) bash -n syntax of the modified script still parses.
  (3) functional smoke: a tmp go.mod with a known-mislabeled replace
      pseudo-version + a tmp upstream clone where the embedded SHA is NOT an
      ancestor of the claimed prefix tag -> count_flagged == 1 and the flag
      reason names the ancestry failure (anchors
      fork-pseudo-version-mislabel.py:188-191).
  (4) negative: an in-lineage SHA (ancestor of the claimed tag) is NOT flagged.

The detector's own unit behavior is covered by test_d5_fork_pseudo_version.py;
THIS test covers the WIRING + the verify-path flag, which is what was missing.

Skips cleanly when bash / a real git binary / python3 is unavailable. The
repo ships a git wrapper on PATH that rejects write ops (init/commit/tag) but
allows reads; the temp upstream clone is therefore built with the real git at
/usr/bin/git (falling back to any non-wrapper git), while the detector itself
uses PATH git for its read-only ancestry queries.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
AUDIT_DEEP = REPO / "tools" / "audit-deep.sh"
D5_TOOL = REPO / "tools" / "fork-pseudo-version-mislabel.py"


def _real_git() -> str | None:
    """Return a git binary that is NOT the auditooor write-guard wrapper.

    The wrapper rejects init/commit/tag (it requires a session-recall marker),
    so the test builds its synthetic upstream repo with the real git.
    """
    for cand in ("/usr/bin/git", "/opt/homebrew/bin/git", "/usr/local/bin/git"):
        if Path(cand).is_file() and os.access(cand, os.X_OK):
            return cand
    found = shutil.which("git")
    if found and "auditooor" not in os.path.realpath(found):
        return found
    return None


class TestD5WiredInBody(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.body = AUDIT_DEEP.read_text(encoding="utf-8")

    def test_tool_referenced(self):
        # Dead-unwired guard: pre-wiring this is absent -> test FAILS pre-fix.
        self.assertIn("fork-pseudo-version-mislabel.py", self.body)

    def test_step_15b_header_present(self):
        self.assertIn("Step 15b - Fork pseudo-version mislabel (D5)", self.body)
        self.assertIn("D5_TOOL", self.body)

    def test_skip_branches_present(self):
        # fork-gated + DRY_RUN + tool-missing + python3-missing guard branches,
        # mirroring the Step 15 sibling-stage shape.
        self.assertIn("fork-pseudo-version-mislabel (not a fork target)", self.body)
        self.assertIn("fork-pseudo-version-mislabel (DRY_RUN=1)", self.body)
        self.assertIn("fork-pseudo-version-mislabel (tool missing)", self.body)
        self.assertIn("fork-pseudo-version-mislabel (python3 missing)", self.body)

    def test_verify_path_wired(self):
        # The high-value stage-2 ancestry verify must be reachable from the wiring.
        self.assertIn("--verify --upstream-clone", self.body)

    def test_bash_syntax_ok(self):
        if not shutil.which("bash"):
            self.skipTest("bash not on PATH")
        rc = subprocess.run(["bash", "-n", str(AUDIT_DEEP)],
                            capture_output=True, text=True)
        self.assertEqual(rc.returncode, 0, f"bash -n failed: {rc.stderr}")


class TestD5VerifyFunctional(unittest.TestCase):
    def setUp(self):
        if not shutil.which("python3"):
            self.skipTest("python3 not on PATH")
        if not D5_TOOL.exists():
            self.skipTest("fork-pseudo-version-mislabel.py absent")
        self.git = _real_git()
        if not self.git:
            self.skipTest("no non-wrapper git binary available")
        self.tmp = Path(tempfile.mkdtemp())
        self.clone = self.tmp / "upstream"
        self.clone.mkdir(parents=True)
        self._git("init", "-q", ".")
        self._git("config", "user.email", "t@example.com")
        self._git("config", "user.name", "t")
        (self.clone / "f").write_text("a\n", encoding="utf-8")
        self._git("add", "f")
        self._git("commit", "-qm", "c1")
        self._git("tag", "v1.0.0")
        self.sha_v1 = self._git("rev-parse", "--short=12", "HEAD").strip()
        (self.clone / "f").write_text("b\n", encoding="utf-8")
        self._git("commit", "-qam", "c2")
        self._git("tag", "v2.0.0")
        self.sha_v2 = self._git("rev-parse", "--short=12", "HEAD").strip()

    def tearDown(self):
        if getattr(self, "tmp", None):
            shutil.rmtree(self.tmp, ignore_errors=True)

    def _git(self, *args: str) -> str:
        rc = subprocess.run([self.git, "-C", str(self.clone), *args],
                            capture_output=True, text=True)
        self.assertEqual(rc.returncode, 0, f"git {args} failed: {rc.stderr}")
        return rc.stdout

    def _run_d5(self, gomod: Path):
        rc = subprocess.run(
            [sys.executable, str(D5_TOOL), str(gomod),
             "--verify", "--upstream-clone", str(self.clone)],
            capture_output=True, text=True, timeout=120)
        self.assertEqual(rc.returncode, 0, rc.stderr[:600])
        return json.loads(rc.stdout)

    def test_mislabeled_pseudo_version_flagged(self):
        # Claim v1.0.0 lineage but embed a SHA that lives on v2.0.0 (NOT an
        # ancestor of v1.0.0) -> mislabel, must flag with the ancestry reason.
        gomod = self.tmp / "go.mod"
        gomod.write_text(
            "module example.com/fork\ngo 1.21\n"
            "replace github.com/up/lib => github.com/fork/lib "
            f"v1.0.0-0.20260101000000-{self.sha_v2}\n",
            encoding="utf-8")
        payload = self._run_d5(gomod)
        self.assertEqual(payload["count_flagged"], 1, payload)
        reason = payload["flagged"][0]["reason"]
        self.assertIn("not an ancestor of claimed tag", reason, reason)

    def test_in_lineage_pseudo_version_not_flagged(self):
        # Negative control: SHA is the v1.0.0 commit itself (ancestor of the
        # claimed tag) -> honest lineage, must NOT flag.
        gomod = self.tmp / "go.mod"
        gomod.write_text(
            "module example.com/fork\ngo 1.21\n"
            "replace github.com/up/lib => github.com/fork/lib "
            f"v1.0.0-0.20260101000000-{self.sha_v1}\n",
            encoding="utf-8")
        payload = self._run_d5(gomod)
        self.assertEqual(payload["count_flagged"], 0, payload)


if __name__ == "__main__":
    unittest.main(verbosity=2)
