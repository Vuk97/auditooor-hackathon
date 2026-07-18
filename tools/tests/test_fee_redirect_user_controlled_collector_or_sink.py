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
DETECTOR = ROOT / "detectors" / "wave17" / "fee_redirect_user_controlled_collector_or_sink.py"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "fee_redirect_user_controlled_collector_or_sink"
PATTERN = "fee-redirect-user-controlled-collector-or-sink"
EXISTING_DIRECT_SINK = "fee-redirect-user-controlled-sink"
EXISTING_LEDGER_SINK = "fee-ledger-sink-mismatch"
POSITIVE = FIXTURE_DIR / "positive.sol"
CLEAN = FIXTURE_DIR / "clean.sol"


def _python_with_slither() -> str | None:
    candidates = [
        os.environ.get("SLITHER_PYTHON"),
        sys.executable,
        "/opt/homebrew/opt/python@3.13/bin/python3.13",
        "/opt/homebrew/bin/python3.13",
        "python3",
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


class FeeRedirectUserControlledCollectorOrSinkTest(unittest.TestCase):
    def _hits(self, fixture: Path, pattern: str = PATTERN) -> tuple[int, str]:
        slither_python = _python_with_slither()
        if slither_python is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        env = os.environ.copy()
        env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
        env["AUDITOOOR_SLITHER_NOCACHE"] = "1"
        proc = subprocess.run(
            [slither_python, str(RUNNER), "--tier=ALL", str(fixture), pattern],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertIn(pattern, proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1)), proc.stdout

    def test_detector_compiles(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

    def test_positive_fixture_fires_and_clean_fixture_is_silent(self) -> None:
        positive_hits, positive_stdout = self._hits(POSITIVE)
        clean_hits, clean_stdout = self._hits(CLEAN)
        self.assertEqual(positive_hits, 1, positive_stdout)
        self.assertEqual(clean_hits, 0, clean_stdout)

    def test_existing_fee_redirect_detectors_do_not_catch_new_shape(self) -> None:
        direct_hits, direct_stdout = self._hits(POSITIVE, EXISTING_DIRECT_SINK)
        ledger_hits, ledger_stdout = self._hits(POSITIVE, EXISTING_LEDGER_SINK)
        self.assertEqual(direct_hits, 0, direct_stdout)
        self.assertEqual(ledger_hits, 0, ledger_stdout)

    def test_fixtures_lock_stored_collector_substitution_shape(self) -> None:
        positive = POSITIVE.read_text(encoding="utf-8")
        clean = CLEAN.read_text(encoding="utf-8")
        self.assertIn("function setFeeCollector(address newCollector) external", positive)
        self.assertIn("feeCollector = newCollector;", positive)
        self.assertIn("token.safeTransfer(feeCollector, feeAmount);", positive)
        self.assertNotIn("onlyOwner", positive)
        self.assertIn("external onlyOwner", clean)


if __name__ == "__main__":
    unittest.main()
