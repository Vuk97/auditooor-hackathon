from __future__ import annotations

import importlib.util
import py_compile
import re
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
REGEX_RUNNER = ROOT / "detectors" / "run_regex_detectors.py"
DETECTOR = ROOT / "detectors" / "wave17" / "memory_copy_not_writeback_value_loss_fire27.py"
PATTERN = "memory-copy-not-writeback-value-loss-fire27"
POSITIVE = (
    ROOT
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "memory_copy_not_writeback_value_loss_fire27.sol"
)
NEGATIVE = (
    ROOT
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "memory_copy_not_writeback_value_loss_fire27.sol"
)


def _load_detector_module():
    spec = importlib.util.spec_from_file_location("memory_copy_not_writeback_value_loss_fire27", DETECTOR)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {DETECTOR}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["memory_copy_not_writeback_value_loss_fire27"] = mod
    spec.loader.exec_module(mod)
    return mod


class MemoryCopyNotWritebackValueLossFire27Test(unittest.TestCase):
    def test_detector_and_fixture_sources_are_aligned(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)
        detector_text = DETECTOR.read_text(encoding="utf-8")
        positive_text = POSITIVE.read_text(encoding="utf-8")
        negative_text = NEGATIVE.read_text(encoding="utf-8")

        self.assertIn(f'DETECTOR_NAME = "{PATTERN}"', detector_text)
        self.assertIn("ARGUMENT = DETECTOR_NAME", detector_text)
        self.assertIn("NOT_SUBMIT_READY", detector_text)
        self.assertIn("PROMOTION_ALLOWED = False", detector_text)
        self.assertIn("detector_fixture_smoke_only", detector_text)

        self.assertIn("Account memory account = accounts[user];", positive_text)
        self.assertIn("account.debt += amount;", positive_text)
        self.assertIn("uint256[] memory buckets = rewardBuckets[user];", positive_text)
        self.assertIn("buckets[0] += payout;", positive_text)
        self.assertIn("Account memory account = globalAccount;", positive_text)

        self.assertIn("accounts[user] = account;", negative_text)
        self.assertIn("Account storage account = accounts[user];", negative_text)
        self.assertIn("Account memory account = accounts[user];", negative_text)
        self.assertIn("rewardBuckets[user] = buckets;", negative_text)
        self.assertIn("uint256[] storage buckets = rewardBuckets[user];", negative_text)

    def test_scan_positive_fixture_fires_and_negative_fixture_is_silent(self) -> None:
        mod = _load_detector_module()
        positive_hits = mod.scan(POSITIVE.read_text(encoding="utf-8"), str(POSITIVE))
        negative_hits = mod.scan(NEGATIVE.read_text(encoding="utf-8"), str(NEGATIVE))

        self.assertEqual(len(positive_hits), 3, positive_hits)
        self.assertEqual(len(negative_hits), 0, negative_hits)
        messages = "\n".join(hit.message for hit in positive_hits)
        self.assertIn("struct-copy", messages)
        self.assertIn("array-copy", messages)
        self.assertIn("NOT_SUBMIT_READY", messages)

    def test_regex_runner_positive_fires_and_negative_is_silent(self) -> None:
        positive = subprocess.run(
            [
                sys.executable,
                str(REGEX_RUNNER),
                str(POSITIVE),
                "--detector",
                PATTERN,
                "--no-manifest",
            ],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
        self.assertEqual(positive.returncode, 0, positive.stdout)
        self.assertIn("total hits: 3", positive.stdout)

        negative = subprocess.run(
            [
                sys.executable,
                str(REGEX_RUNNER),
                str(NEGATIVE),
                "--detector",
                PATTERN,
                "--no-manifest",
            ],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
        self.assertEqual(negative.returncode, 0, negative.stdout)
        self.assertIn("total hits: 0", negative.stdout)


if __name__ == "__main__":
    unittest.main()
