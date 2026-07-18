from __future__ import annotations

import os
import py_compile
import re
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "detectors" / "run_custom.py"
PATTERN = "recipient-validation-ignored-or-hardcoded-sink"
DETECTOR = ROOT / "detectors" / "wave18" / "recipient_validation_ignored_or_hardcoded_sink.py"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "recipient_validation_ignored_or_hardcoded_sink"
POSITIVE = FIXTURE_DIR / "positive.sol"
CLEAN = FIXTURE_DIR / "clean.sol"

CONFIRMED_FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "withdraw_claim_recipient_ignored_hardcoded_sink"
CONFIRMED_POSITIVE = CONFIRMED_FIXTURE_DIR / "positive.sol"
CONFIRMED_CLEAN = CONFIRMED_FIXTURE_DIR / "clean.sol"


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
            proc = subprocess.run(
                [candidate, "-c", "import slither; import slither.detectors.abstract_detector"],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if proc.returncode == 0:
            return candidate
    return None


class RecipientValidationIgnoredOrHardcodedSinkTest(unittest.TestCase):
    def _hits(self, fixture: Path) -> tuple[int, str]:
        python = _python_with_slither()
        if python is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        env = os.environ.copy()
        env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
        env["AUDITOOOR_SLITHER_NOCACHE"] = "1"
        proc = subprocess.run(
            [python, str(RUNNER), "--tier=ALL", str(fixture), PATTERN],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertIn(PATTERN, proc.stdout)
        self.assertNotIn("No custom detectors found", proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1)), proc.stdout

    def test_detector_syntax_compiles(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

    def test_owned_fixture_pair_models_ignored_recipient(self) -> None:
        positive = POSITIVE.read_text(encoding="utf-8")
        clean = CLEAN.read_text(encoding="utf-8")
        self.assertIn("require(recipient != address(0)", positive)
        self.assertIn("asset.transfer(msg.sender, assets)", positive)
        self.assertIn("asset.transfer(recipient, assets)", clean)

    def test_positive_fixture_fires_and_clean_fixture_is_silent(self) -> None:
        positive_hits, _ = self._hits(POSITIVE)
        clean_hits, _ = self._hits(CLEAN)
        self.assertEqual(positive_hits, 1)
        self.assertEqual(clean_hits, 0)

    def test_confirmed_withdraw_claim_fixture_pair_replays(self) -> None:
        positive_hits, _ = self._hits(CONFIRMED_POSITIVE)
        clean_hits, _ = self._hits(CONFIRMED_CLEAN)
        self.assertEqual(positive_hits, 1)
        self.assertEqual(clean_hits, 0)


if __name__ == "__main__":
    unittest.main()
