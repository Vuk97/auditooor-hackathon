#!/usr/bin/env python3
"""Regression tests for tools/cross-link-validator.py scope handling."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
VALIDATOR = REPO / "tools" / "cross-link-validator.py"
MAKEFILE = REPO / "Makefile"
CI_CHECK = REPO / "tools" / "ci-check-all.py"


def _run_validator(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(VALIDATOR), "--root", str(root), *args],
        capture_output=True,
        text=True,
        timeout=20,
    )


def _make_fixture() -> tuple[tempfile.TemporaryDirectory[str], Path]:
    tmp = tempfile.TemporaryDirectory()
    root = Path(tmp.name) / "repo"
    (root / "docs").mkdir(parents=True)
    return tmp, root


class CrossLinkValidatorScopeTest(unittest.TestCase):
    def test_repo_only_skips_out_of_repo_missing_link(self) -> None:
        tmp, root = _make_fixture()
        with tmp:
            (root / "docs" / "index.md").write_text(
                "[external](../../paused-workspace/missing.log)\n",
                encoding="utf-8",
            )

            proc = _run_validator(root, "--strict", "--scope", "repo-only")

            self.assertEqual(proc.returncode, 0, proc.stderr)
            report = (root / "docs" / "CROSS_LINK_REPORT.md").read_text(encoding="utf-8")
            self.assertIn("- Out-of-repo links skipped: **1**", report)
            self.assertIn("- Broken: **0**", report)
            self.assertIn("out-of-repo skipped", proc.stdout)

    def test_full_scope_flags_same_out_of_repo_missing_link(self) -> None:
        tmp, root = _make_fixture()
        with tmp:
            (root / "docs" / "index.md").write_text(
                "[external](../../paused-workspace/missing.log)\n",
                encoding="utf-8",
            )

            proc = _run_validator(root, "--strict", "--scope", "full")

            self.assertEqual(proc.returncode, 1)
            report = (root / "docs" / "CROSS_LINK_REPORT.md").read_text(encoding="utf-8")
            self.assertIn("- Out-of-repo links skipped: **0**", report)
            self.assertIn("- Broken: **1**", report)
            self.assertIn("../../paused-workspace/missing.log", report)

    def test_repo_only_still_flags_repo_local_missing_link(self) -> None:
        tmp, root = _make_fixture()
        with tmp:
            (root / "docs" / "index.md").write_text(
                "[local](missing.md)\n",
                encoding="utf-8",
            )

            proc = _run_validator(root, "--strict", "--scope", "repo-only")

            self.assertEqual(proc.returncode, 1)
            report = (root / "docs" / "CROSS_LINK_REPORT.md").read_text(encoding="utf-8")
            self.assertIn("- Out-of-repo links skipped: **0**", report)
            self.assertIn("- Broken: **1**", report)
            self.assertIn("missing.md", report)

    def test_default_scope_is_repo_only(self) -> None:
        tmp, root = _make_fixture()
        with tmp:
            (root / "docs" / "index.md").write_text(
                "[external](../../paused-workspace/missing.log)\n",
                encoding="utf-8",
            )

            proc = _run_validator(root, "--strict")

            self.assertEqual(proc.returncode, 0, proc.stderr)
            report = (root / "docs" / "CROSS_LINK_REPORT.md").read_text(encoding="utf-8")
            self.assertIn("- Out-of-repo links skipped: **1**", report)

    def test_makefile_and_ci_pin_repo_only_but_keep_full_mode(self) -> None:
        makefile = MAKEFILE.read_text(encoding="utf-8")
        ci_check = CI_CHECK.read_text(encoding="utf-8")

        self.assertIn("cross-link-full", makefile)
        self.assertIn("tools/cross-link-validator.py --fix-suggestions --scope repo-only", makefile)
        self.assertIn("tools/cross-link-validator.py --fix-suggestions --scope full", makefile)
        self.assertRegex(
            makefile,
            r"docs-check:\s+stage-reference-check tool-ref-check cross-link\b",
        )
        self.assertIn("section-sources-collision-check", makefile)
        self.assertIn('"--scope", "repo-only"', ci_check)


if __name__ == "__main__":
    unittest.main()
