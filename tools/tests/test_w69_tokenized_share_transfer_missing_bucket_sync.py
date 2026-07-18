from __future__ import annotations

import json
import os
import py_compile
import re
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "detectors" / "run_custom.py"
PATTERN = "w69-tokenized-share-transfer-missing-bucket-sync"
DETECTOR = ROOT / "detectors" / "wave69" / "w69_tokenized_share_transfer_missing_bucket_sync.py"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "w69_tokenized_share_transfer_missing_bucket_sync"
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


class W69TokenizedShareTransferMissingBucketSyncTest(unittest.TestCase):
    def _hits(self, fixture: Path) -> int:
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
        self.assertIn(PATTERN, proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1))

    def test_detector_and_fixtures_encode_validator_bucket_drift(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

        detector_text = DETECTOR.read_text(encoding="utf-8")
        positive_text = POSITIVE.read_text(encoding="utf-8")
        clean_text = CLEAN.read_text(encoding="utf-8")
        smoke = json.loads(SMOKE.read_text(encoding="utf-8"))

        self.assertIn('ARGUMENT = "w69-tokenized-share-transfer-missing-bucket-sync"', detector_text)
        self.assertIn("validatorBondShares", detector_text)
        self.assertIn("_SYNC_CALL_RE", detector_text)

        self.assertIn("mapping(uint256 => mapping(address => uint256)) public validatorBondShares;", positive_text)
        self.assertIn("function _update(address from, address to, uint256 amount) internal {", positive_text)
        self.assertNotIn("_moveValidatorBondShares", positive_text)
        self.assertIn('require(validatorBondShares[validatorId][msg.sender] >= shares, "bucket");', positive_text)

        self.assertIn("function _moveValidatorBondShares(address from, address to, uint256 amount) internal {", clean_text)
        self.assertIn("validatorBondShares[validatorId][to] += amount;", clean_text)

        self.assertEqual(smoke["schema"], "auditooor.canonical_detector_fixture_smoke.v1")
        self.assertEqual(smoke["pattern"], PATTERN)
        self.assertEqual(smoke["positive_hits"], 1)
        self.assertEqual(smoke["clean_hits"], 0)
        self.assertEqual(smoke["coverage_claim"], "detector_fixture_smoke_only")
        self.assertFalse(smoke["promotion_allowed"])
        self.assertEqual(smoke["submission_posture"], "NOT_SUBMIT_READY")

    def test_positive_fixture_fires_and_clean_fixture_stays_quiet(self) -> None:
        self.assertGreaterEqual(self._hits(POSITIVE), 1)
        self.assertEqual(self._hits(CLEAN), 0)


if __name__ == "__main__":
    unittest.main()
