from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "detectors" / "run_custom.py"
PATTERN = "division-rounding-to-zero-with-token-transfer"
DETECTOR = (
    ROOT
    / "detectors"
    / "wave_graveyard"
    / "wave13_broken"
    / "division_rounding_to_zero_with_token_transfer.py"
)
DSL = (
    ROOT
    / "detectors"
    / "_specs"
    / "drafts_glider"
    / "division-rounding-to-zero-with-token-transfer.yaml"
)
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "division_rounding_to_zero_with_token_transfer"
POSITIVE = FIXTURE_DIR / "positive.sol"
CLEAN = FIXTURE_DIR / "clean.sol"
SMOKE = FIXTURE_DIR / "smoke.json"


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
                [candidate, "-c", "import slither; import slither.detectors.abstract_detector"],
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


class DivisionRoundingToZeroWithTokenTransferTest(unittest.TestCase):
    def _hits(self, fixture: Path) -> int:
        slither_python = _python_with_slither()
        if slither_python is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        env = os.environ.copy()
        env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
        env["AUDITOOOR_SLITHER_NOCACHE"] = "1"
        proc = subprocess.run(
            [
                slither_python,
                str(RUNNER),
                "--include-graveyard",
                "--tier=ALL",
                str(fixture),
                PATTERN,
            ],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertIn(PATTERN, proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1))

    def test_row_sources_are_present_and_wired(self) -> None:
        detector_text = DETECTOR.read_text(encoding="utf-8")
        dsl_text = DSL.read_text(encoding="utf-8")

        self.assertIn(f'ARGUMENT = "{PATTERN}"', detector_text)
        self.assertIn("division-derived transfer amount", detector_text)
        self.assertIn('skeleton: "semantic_division_rounding_transfer_guard"', dsl_text)
        self.assertIn("division_rounding_to_zero_with_token_transfer/positive.sol", dsl_text)
        self.assertIn("division_rounding_to_zero_with_token_transfer/clean.sol", dsl_text)
        self.assertTrue(POSITIVE.is_file())
        self.assertTrue(CLEAN.is_file())

    def test_fixture_shape_models_guarded_and_unguarded_transfer(self) -> None:
        positive = POSITIVE.read_text(encoding="utf-8")
        clean = CLEAN.read_text(encoding="utf-8")

        self.assertIn("transferAmount = (rawAmount * DECIMALS) / rate;", positive)
        self.assertIn("token.safeTransferFrom(msg.sender, address(this), transferAmount);", positive)
        self.assertNotIn("require(transferAmount > 0", positive)

        self.assertIn("transferAmount = (rawAmount * DECIMALS) / rate;", clean)
        self.assertIn('require(transferAmount > 0, "dust transfer");', clean)
        self.assertIn("token.safeTransferFrom(msg.sender, address(this), transferAmount);", clean)

    def test_smoke_record_captures_positive_and_clean_counts(self) -> None:
        payload = json.loads(SMOKE.read_text(encoding="utf-8"))
        self.assertEqual(payload["status"], "smoke_pass")
        self.assertEqual(payload["pattern"], PATTERN)
        self.assertFalse(payload["promotion_allowed"])
        self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")
        self.assertGreaterEqual(payload["positive_hits"], 1)
        self.assertEqual(payload["clean_hits"], 0)

    def test_positive_fixture_fires_and_clean_fixture_stays_quiet(self) -> None:
        self.assertGreaterEqual(self._hits(POSITIVE), 1)
        self.assertEqual(self._hits(CLEAN), 0)


if __name__ == "__main__":
    unittest.main()
