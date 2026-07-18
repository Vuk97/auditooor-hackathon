#!/usr/bin/env python3
"""Makefile integration coverage for batch-boundary-preflight."""

from __future__ import annotations

import subprocess
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]


def make_dry_run(*args: str) -> str:
    result = subprocess.run(
        ["make", "-n", "batch-boundary-preflight", *args],
        cwd=REPO,
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"make dry-run failed with rc {result.returncode}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )
    return result.stdout


class MakefileBatchBoundaryPreflightTest(unittest.TestCase):
    def test_dry_run_wires_tool_strict_pr_body_and_timeout(self) -> None:
        output = make_dry_run("STRICT=1", "PR_STRICT=1", "PR_BODY=/tmp/pr-body.md", "TIMEOUT=17")

        self.assertIn("python3 tools/batch-boundary-preflight.py", output)
        self.assertIn('--pr-body "/tmp/pr-body.md"', output)
        self.assertIn("--strict", output)
        self.assertIn("--pr-strict", output)
        self.assertIn('--timeout "17"', output)

    def test_dry_run_omits_optional_pr_body_when_unset(self) -> None:
        output = make_dry_run("TIMEOUT=17")

        self.assertIn("python3 tools/batch-boundary-preflight.py", output)
        self.assertIn('--timeout "17"', output)
        self.assertNotIn("--pr-body", output)
        self.assertNotIn("--strict", output)


if __name__ == "__main__":
    unittest.main()
