#!/usr/bin/env python3
"""Public full-pipeline authority must be the receipt executor."""

from __future__ import annotations

import unittest
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MAKEFILE = ROOT / "Makefile"


def _target_body(text: str, target: str) -> str:
    marker = f"\n{target}:"
    start = text.find(marker)
    if start < 0:
        raise AssertionError(f"missing Makefile target: {target}")
    start = text.index("\n", start + 1) + 1
    lines: list[str] = []
    for line in text[start:].splitlines(keepends=True):
        if line and not line[0].isspace() and ":" in line.split("=", 1)[0]:
            break
        lines.append(line)
    return "".join(lines)


class PipelineFullExecutorAuthorityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = MAKEFILE.read_text(encoding="utf-8")
        cls.public = _target_body(cls.text, "audit-pipeline-full")
        cls.legacy = _target_body(cls.text, "_audit-pipeline-full")

    def test_public_target_uses_manifest_executor(self) -> None:
        self.assertIn("pipeline-manifest-validate.py", self.public)
        self.assertIn("pipeline-executor.py", self.public)
        self.assertIn("readme_runbook_steps.json", self.public)
        self.assertIn("run-all", self.public)

    def test_public_target_never_invokes_shell_driver(self) -> None:
        self.assertNotIn("_audit-pipeline-full", self.public)
        self.assertNotIn("strict-pipeline-run.py", self.public)

    def test_drive_consent_is_a_hard_prerequisite(self) -> None:
        self.assertIn("an affirmative LLM hunt or network consent value is required", self.public)
        self.assertIn("false/0/empty cannot authorize", self.public)
        self.assertIn("1:*|true:*|yes:*|*:1|*:true|*:yes", self.public)
        self.assertIn("exit 2", self.public)

    def test_runtime_modes_are_forwarded_as_environment(self) -> None:
        for name in (
            "SOURCE_ONLY",
            "GITHUB_ONLY",
            "AUDITOOOR_LLM_HUNT",
            "AUDITOOOR_LLM_NETWORK_CONSENT",
            "PIPELINE_FORCE",
            "PIPELINE_STRICT",
            "STRICT",
        ):
            self.assertIn(name, self.public)

    def test_intake_coverage_plane_has_no_continue_path(self) -> None:
        intake = _target_body(self.text, "pipeline-intake-coverage-plane")
        self.assertIn("--emit-inscope-manifest", intake)
        self.assertIn("inscope-manifest-validate.py", intake)
        self.assertIn("coverage-plane-build.py", intake)
        self.assertIn("--check --strict", intake)
        self.assertNotIn("||", intake)

    def test_legacy_recipe_is_explicitly_noncanonical(self) -> None:
        prefix = self.text[self.text.index("# Retired legacy shell driver.") :]
        self.assertIn("cannot receive executor authority", prefix[:300])
        self.assertIn("canonical receipts", prefix[:300])
        self.assertTrue(self.legacy.strip())

    def test_legacy_shell_driver_fails_before_workspace_work(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory) / "workspace"
            result = subprocess.run(
                ["make", "--no-print-directory", "_audit-pipeline-full", f"WS={workspace}"],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            pipeline_state_created = (workspace / ".auditooor" / "pipeline" / "state.json").exists()
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("_audit-pipeline-full is retired", result.stderr)
        self.assertFalse(pipeline_state_created)

    def test_no_unicode_dashes(self) -> None:
        self.assertNotIn(chr(0x2014), self.public)
        self.assertNotIn(chr(0x2013), self.public)


if __name__ == "__main__":
    unittest.main()
