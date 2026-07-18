#!/usr/bin/env python3
"""Focused regression for the initializer front-run route owner detector."""

from __future__ import annotations

import os
import py_compile
import re
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PATTERN = "initializer-front-run-unprotected-route-owner"
RUNNER = ROOT / "detectors" / "run_custom.py"
DETECTOR = ROOT / "detectors" / "wave17" / "initializer_front_run_unprotected_route_owner.py"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "initializer_front_run_unprotected_route_owner"
POSITIVE = FIXTURE_DIR / "positive.sol"
CLEAN = FIXTURE_DIR / "clean.sol"


def _python_with_slither() -> str | None:
    candidates = [
        os.environ.get("SLITHER_PYTHON"),
        sys.executable,
        "/opt/homebrew/opt/python@3.13/bin/python3.13",
        "/opt/homebrew/bin/python3.13",
    ]
    seen: set[str] = set()
    for candidate in candidates:
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        try:
            probe = subprocess.run(
                [
                    candidate,
                    "-c",
                    "import slither; import slither.detectors.abstract_detector",
                ],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if probe.returncode == 0:
            return candidate
    return None


class InitializerFrontRunUnprotectedRouteOwnerTest(unittest.TestCase):
    def _run_detector(self, fixture: Path) -> tuple[int, str]:
        slither_python = _python_with_slither()
        if slither_python is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        env = os.environ.copy()
        env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
        env["AUDITOOOR_SLITHER_NOCACHE"] = "1"
        proc = subprocess.run(
            [slither_python, str(RUNNER), "--tier=ALL", str(fixture), PATTERN],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertNotIn("No custom detectors found", proc.stdout)
        self.assertIn(PATTERN, proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1)), proc.stdout

    def test_detector_metadata_and_fixture_shape(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

        detector_text = DETECTOR.read_text(encoding="utf-8")
        positive_text = POSITIVE.read_text(encoding="utf-8")
        clean_text = CLEAN.read_text(encoding="utf-8")

        self.assertIn(f'ARGUMENT = "{PATTERN}"', detector_text)
        self.assertIn("authorization or initializer guard", detector_text)
        self.assertIn("writes_state_var_matching_regex", detector_text)
        self.assertIn("not_modifiers_match", detector_text)
        self.assertIn("body_not_contains_regex", detector_text)

        self.assertIn("function setupRoute(", positive_text)
        self.assertIn("owner = configuredOwner;", positive_text)
        self.assertIn("routes[sourceChainId][destinationChainId] = configuredGateway;", positive_text)
        self.assertNotIn("onlyOwner", positive_text)
        self.assertNotIn("initializer", positive_text)

        self.assertIn("function setupRoute(", clean_text)
        self.assertIn("external onlyOwner", clean_text)
        self.assertIn("external initializer", clean_text)
        self.assertIn("require(!initialized", clean_text)

    def test_positive_fixture_fires_and_clean_fixture_stays_quiet(self) -> None:
        positive_hits, positive_output = self._run_detector(POSITIVE)
        clean_hits, _clean_output = self._run_detector(CLEAN)

        self.assertGreaterEqual(positive_hits, 2, positive_output)
        self.assertIn("setupRoute", positive_output)
        self.assertIn("initializeGateway", positive_output)
        self.assertEqual(clean_hits, 0)


if __name__ == "__main__":
    unittest.main()
