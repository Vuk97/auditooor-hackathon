"""Regression coverage for canonical-only hard failure in the Step 1 target."""
from __future__ import annotations

import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]


def target_body(text: str, target: str) -> str:
    marker = f"\n{target}:"
    start = text.index(marker) + 1
    tail = text[start:]
    for line in tail.splitlines()[1:]:
        if line and not line.startswith(("\t", "#", " ")) and ":" in line:
            return tail[:tail.index("\n" + line)]
    return tail


class TestCanonicalStrictMakefile(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.body = target_body((REPO / "Makefile").read_text(encoding="utf-8"), "_audit-baseline")
        cls.manifest = (REPO / "tools" / "readme_runbook_steps.json").read_text(encoding="utf-8")

    def test_manifest_enables_canonical_strict_for_step_1(self) -> None:
        self.assertIn('"AUDITOOOR_CANONICAL_STRICT=1"', self.manifest)

    def test_canonical_mode_propagates_producer_failures(self) -> None:
        self.assertIn("require_canonical()", self.body)
        for producer in (
            "resolve-fork-bases", "inscope-manifest", "guard-completeness-check",
            "audit-preflight", "brain-prime", "audit-hacker-logic-bridge",
            "prior-disclosure-index", "exploit-queue", "auto-coverage-close",
        ):
            self.assertIn(f'"{producer}"', self.body)

    def test_marker_is_written_after_hunt_coverage_boundary(self) -> None:
        marker = self.body.index("audit-completion-marker.py write")
        coverage = self.body.index("hunt-coverage-gate.py")
        self.assertGreater(marker, coverage)


if __name__ == "__main__":
    unittest.main()
