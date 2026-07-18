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


ROOT = Path(__file__).resolve().parents[2]
DETECTOR_PATH = ROOT / "detectors" / "wave17" / "integer_clamp_fee_scale_fire34.py"
RUNNER = ROOT / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "integer-clamp-fee-scale-fire34"
POSITIVE = (
    ROOT
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "integer_clamp_fee_scale_fire34.sol"
)
NEGATIVE = (
    ROOT
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "integer_clamp_fee_scale_fire34.sol"
)


def _load_detector():
    module_name = "integer_clamp_fee_scale_fire34"
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


class IntegerClampFeeScaleFire34Test(unittest.TestCase):
    def test_detector_compiles_and_declares_provenance(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        detector = _load_detector()
        detector_text = _read(DETECTOR_PATH)

        self.assertEqual(detector.DETECTOR_NAME, DETECTOR_NAME)
        self.assertEqual(detector.DETECTOR_SEVERITY_DEFAULT, "Medium")
        self.assertEqual(detector.SUBMISSION_POSTURE, "NOT_SUBMIT_READY")
        self.assertIn("integer-overflow-clamp", detector_text)
        self.assertIn("post_priorities_all.md", detector_text)
        self.assertIn("integer-overflow-clamp-arithmetic-loss.yaml", detector_text)
        self.assertIn("go-integer-overflow-config-clamp-fire31.py", detector_text)
        self.assertIn("integer_overflow_reserve_clamp_fire32.py", detector_text)

    def test_positive_fixture_fires_on_fee_reserve_scale_and_downcast_clamps(self) -> None:
        detector = _load_detector()
        findings = detector.scan(_read(POSITIVE), str(POSITIVE))

        self.assertEqual(len(findings), 4)
        self.assertEqual({finding.detector for finding in findings}, {DETECTOR_NAME})
        self.assertEqual({finding.severity for finding in findings}, {"Medium"})
        self.assertEqual(
            {finding.function for finding in findings},
            {
                "accrueProtocolFee",
                "updateScaledReserveCap",
                "setScaleAfterDiscount",
                "snapshotReserve",
            },
        )
        messages = "\n".join(finding.message for finding in findings)
        self.assertIn("feeAmount narrows amount * feeBps / BPS to uint128", messages)
        self.assertIn("packedReserve narrows balance * reserveScale to uint96", messages)
        self.assertIn("nextScale narrows grossScale - discountBps to uint128", messages)
        self.assertIn("packedReserve narrows rawReserve to uint96", messages)
        self.assertIn("integer-overflow-clamp", messages)
        self.assertIn("NOT_SUBMIT_READY", messages)

    def test_negative_fixture_pre_bounds_or_safecast_stays_silent(self) -> None:
        detector = _load_detector()
        findings = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(findings, [])
        clean_text = _read(NEGATIVE)
        self.assertIn("amount <= type(uint128).max / feeBps", clean_text)
        self.assertIn("wideFee.toUint128()", clean_text)
        self.assertIn("require(scaledReserve <= maxReserve", clean_text)
        self.assertIn("wideScale.toUint128()", clean_text)
        self.assertIn("require(rawReserve <= maxReserve", clean_text)
        self.assertIn("uint64 nextEpoch = uint64(epoch)", clean_text)

    def test_regex_runner_records_positive_hits_and_negative_silence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fire34_fee_scale_") as tmp:
            env = os.environ.copy()
            env["PYTHONDONTWRITEBYTECODE"] = "1"
            positive_manifest = Path(tmp) / "positive.json"
            negative_manifest = Path(tmp) / "negative.json"

            positive_proc = subprocess.run(
                [
                    sys.executable,
                    str(RUNNER),
                    str(POSITIVE),
                    "--workspace",
                    tmp,
                    "--output",
                    str(positive_manifest),
                    "--detector",
                    DETECTOR_NAME,
                    "--json-only",
                ],
                cwd=ROOT,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=30,
            )
            self.assertEqual(positive_proc.returncode, 0, positive_proc.stdout)

            negative_proc = subprocess.run(
                [
                    sys.executable,
                    str(RUNNER),
                    str(NEGATIVE),
                    "--workspace",
                    tmp,
                    "--output",
                    str(negative_manifest),
                    "--detector",
                    DETECTOR_NAME,
                    "--json-only",
                ],
                cwd=ROOT,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=30,
            )
            self.assertEqual(negative_proc.returncode, 0, negative_proc.stdout)

            positive_data = json.loads(positive_manifest.read_text(encoding="utf-8"))
            negative_data = json.loads(negative_manifest.read_text(encoding="utf-8"))

            self.assertEqual(positive_data["per_detector_counts"][DETECTOR_NAME], 4)
            self.assertEqual(negative_data["per_detector_counts"][DETECTOR_NAME], 0)
            self.assertEqual(
                {Path(row["file"]).name for row in positive_data["findings"]},
                {POSITIVE.name},
            )


if __name__ == "__main__":
    unittest.main()
