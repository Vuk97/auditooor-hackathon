from __future__ import annotations

import importlib.util
import json
import os
import py_compile
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
DETECTOR_PATH = (
    REPO / "detectors" / "wave17" / "integer_overflow_clamp_fee_vote_fire23.py"
)
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "integer_overflow_clamp_fee_vote_fire23.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "integer_overflow_clamp_fee_vote_fire23.sol"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "integer-overflow-clamp-fee-vote-fire23"


def _load_detector():
    module_name = "integer_overflow_clamp_fee_vote_fire23"
    if module_name in sys.modules:
        return sys.modules[module_name]
    spec = importlib.util.spec_from_file_location(module_name, DETECTOR_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


class IntegerOverflowClampFeeVoteFire23Test(unittest.TestCase):
    def test_detector_and_fixture_sources_pin_recall_semantics(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)

        detector_text = _read(DETECTOR_PATH)
        positive_text = _read(POSITIVE)
        negative_text = _read(NEGATIVE)

        self.assertIn(DETECTOR_NAME, detector_text)
        self.assertIn("candidate evidence only", detector_text)
        self.assertIn("_UINT96_NARROW_RE", detector_text)
        self.assertIn("_FEE_SUB_RE", detector_text)
        self.assertIn("_SURGE_SUB_RE", detector_text)

        self.assertIn("uint96(balance * voteMultiplier)", positive_text)
        self.assertIn("repayRequired = amount - feeAmount;", positive_text)
        self.assertIn("maxSurgeFeePercentage - staticFeePercentage", positive_text)

        self.assertIn("SafeCast.toUint96", negative_text)
        self.assertIn("require(feeAmount <= amount", negative_text)
        self.assertIn("maxSurgeFeePercentage < staticFeePercentage", negative_text)

    def test_positive_fixture_fires_and_negative_fixture_is_silent(self) -> None:
        detector = _load_detector()

        positive_findings = detector.scan(_read(POSITIVE), str(POSITIVE))
        negative_findings = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(len(positive_findings), 3)
        self.assertEqual(negative_findings, [])
        self.assertEqual({finding.detector for finding in positive_findings}, {DETECTOR_NAME})
        self.assertEqual({finding.severity for finding in positive_findings}, {"Medium"})
        self.assertEqual(
            {finding.function for finding in positive_findings},
            {"castDelegatedVotes", "flashLoan", "computeSurgeFee"},
        )
        messages = "\n".join(finding.message for finding in positive_findings)
        self.assertIn("uint96", messages)
        self.assertIn("fee <= amount", messages)
        self.assertIn("max >= static", messages)

    def _run_regex_runner(self, target: Path, manifest: Path) -> dict:
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        proc = subprocess.run(
            [
                sys.executable,
                str(RUNNER),
                str(target),
                "--workspace",
                str(manifest.parent),
                "--output",
                str(manifest),
                "--detector",
                DETECTOR_NAME,
                "--json-only",
            ],
            cwd=REPO,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout)
        return json.loads(manifest.read_text(encoding="utf-8"))

    def test_regex_runner_records_positive_and_silent_negative(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fire23_integer_clamp_") as tmp:
            positive_data = self._run_regex_runner(POSITIVE, Path(tmp) / "positive.json")
            negative_data = self._run_regex_runner(NEGATIVE, Path(tmp) / "negative.json")

            self.assertEqual(positive_data["per_detector_counts"][DETECTOR_NAME], 3)
            self.assertEqual(negative_data["per_detector_counts"][DETECTOR_NAME], 0)
            self.assertEqual(positive_data["files_scanned"], 1)
            self.assertEqual(negative_data["files_scanned"], 1)
            files = {Path(row["file"]).name for row in positive_data["findings"]}
            self.assertEqual(files, {POSITIVE.name})


if __name__ == "__main__":
    unittest.main()
