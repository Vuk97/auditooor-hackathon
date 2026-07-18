#!/usr/bin/env python3
"""Regression tests for the foot-gun #13a guard in
``tools/audit-progress.py``.

Parallel-agent dispatch occasionally drops a copy of ``audit-progress.py``
into a harness temp dir whose parent is *not* a git checkout. Without a
guard, downstream calls silently target whatever git repo happens to be
CWD (or none at all) and the operator has no way to notice. The script
now invokes ``git rev-parse --is-inside-work-tree`` against ``REPO`` and
fails closed when the answer is ``false``.

Coverage:

  1. The guard helper itself returns ``None`` for the real repo (legit
     invocation must not be blocked).
  2. The guard helper returns ``1`` and prints the documented diagnostic
     to stderr when pointed at a non-git directory.
  3. End-to-end invocation: the script exits 1 with the diagnostic when
     a copy is placed inside a non-git directory and run from there.
  4. End-to-end invocation against the real repo's checker still works
     (``--dry-run`` exits 0).
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "tools" / "audit-progress.py"


def _load_module():
    """Load ``audit-progress.py`` as ``audit_progress`` (hyphen → underscore)."""
    spec = importlib.util.spec_from_file_location("audit_progress", SCRIPT)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class AuditProgressGitWorkTreeGuardTest(unittest.TestCase):
    """Belt-and-suspenders: helper unit tests + subprocess end-to-end."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.module = _load_module()

    def test_helper_returns_none_for_real_repo(self) -> None:
        result = self.module._ensure_git_work_tree(REPO)
        self.assertIsNone(
            result,
            "guard should be transparent on the real auditooor repo",
        )

    def test_helper_fails_for_non_git_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            from io import StringIO
            saved = sys.stderr
            buf = StringIO()
            sys.stderr = buf
            try:
                rc = self.module._ensure_git_work_tree(tmp)
            finally:
                sys.stderr = saved
            self.assertEqual(rc, 1)
            self.assertIn(
                "audit-progress: working tree not a git repo",
                buf.getvalue(),
            )
            self.assertIn("GIT_WORK_TREE unset?", buf.getvalue())

    def test_real_repo_dry_run_exits_zero(self) -> None:
        """Sanity: the guard does not regress legit invocation."""
        proc = subprocess.run(
            [sys.executable, str(SCRIPT),
             "--workspace", str(REPO), "--dry-run"],
            capture_output=True, text=True, timeout=120,
        )
        self.assertEqual(
            proc.returncode, 0,
            f"dry-run regressed:\nstdout={proc.stdout[:500]}\n"
            f"stderr={proc.stderr[:500]}",
        )

    def test_subprocess_in_non_git_dir_fails(self) -> None:
        """End-to-end: copy the script into a non-git temp dir and run it.

        ``REPO`` inside the copy resolves to ``<tmp>`` (its
        ``Path(__file__).parent.parent``), which is not a git work tree.
        The guard must fire and the script must exit 1.
        """
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            (tmp / "tools").mkdir()
            shutil.copy2(SCRIPT, tmp / "tools" / "audit-progress.py")
            proc = subprocess.run(
                [sys.executable, str(tmp / "tools" / "audit-progress.py"),
                 "--workspace", str(tmp), "--dry-run"],
                capture_output=True, text=True, timeout=30,
                # Explicitly drop CWD-leaking env so the probe uses
                # ``cwd=REPO`` (== tmp) and not the test runner's repo.
                env={k: v for k, v in os.environ.items()
                     if k not in ("GIT_DIR", "GIT_WORK_TREE")},
            )
        self.assertEqual(
            proc.returncode, 1,
            f"non-git dir was not flagged:\nstdout={proc.stdout}\n"
            f"stderr={proc.stderr}",
        )
        self.assertIn(
            "audit-progress: working tree not a git repo",
            proc.stderr,
        )


if __name__ == "__main__":
    unittest.main()
