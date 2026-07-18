from __future__ import annotations

import importlib.util
import os
import py_compile
import re
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "detectors" / "run_custom.py"
PATTERN = "value-math-constructor-scale-fire29"
DETECTOR = ROOT / "detectors" / "wave17" / "value_math_constructor_scale_fire29.py"
POSITIVE = ROOT / "detectors" / "test_fixtures" / "positive" / "value_math_constructor_scale_fire29.sol"
NEGATIVE = ROOT / "detectors" / "test_fixtures" / "negative" / "value_math_constructor_scale_fire29.sol"


def _load_detector_module():
    spec = importlib.util.spec_from_file_location("value_math_constructor_scale_fire29", DETECTOR)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


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


class ValueMathConstructorScaleFire29Test(unittest.TestCase):
    def _runner_hits(self, fixture: Path) -> tuple[int, str]:
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
        self.assertIn(f"=== Running {PATTERN} ===", proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1)), proc.stdout

    def test_detector_and_fixtures_are_aligned(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

        detector_text = DETECTOR.read_text(encoding="utf-8")
        positive_text = POSITIVE.read_text(encoding="utf-8")
        negative_text = NEGATIVE.read_text(encoding="utf-8")

        self.assertIn(f'DETECTOR_NAME = "{PATTERN}"', detector_text)
        self.assertIn("fund-loss-via-arithmetic-value-math.yaml", detector_text)
        self.assertIn("glider-incorrect-self-referencing-compound-arithmetic-py.yaml", detector_text)
        self.assertIn("SUBMISSION_POSTURE = \"NOT_SUBMIT_READY\"", detector_text)
        self.assertIn("constructor-decimal-exponent-scale", detector_text)
        self.assertIn("constructor-ratio-division-scale", detector_text)

        self.assertIn("assetScale = 10 ** (18 - assetDecimals);", positive_text)
        self.assertIn("shareScale = referenceShares / referenceAssets;", positive_text)
        self.assertIn("uint256 minted = amount * assetScale / shareScale;", positive_text)
        self.assertIn("uint256 assetsOut = shareAmount * shareScale / assetScale;", positive_text)
        self.assertIn("function initialize(IERC20Like asset_, uint256 feeNumerator", positive_text)
        self.assertIn("feePrecision = feeNumerator / feeDenominator;", positive_text)
        self.assertIn("uint256 feeAmount = grossAmount / feePrecision;", positive_text)

        self.assertIn("require(assetDecimals <= 18", negative_text)
        self.assertIn("shareScale = MathLike.mulDiv(referenceShares, 1e18, referenceAssets);", negative_text)
        self.assertIn("require(assetScale > 0", negative_text)
        self.assertIn("require(shareScale > 0", negative_text)

    def test_scan_positive_fixture_fires_and_negative_is_silent(self) -> None:
        detector = _load_detector_module()
        positive_findings = detector.scan(POSITIVE.read_text(encoding="utf-8"), str(POSITIVE))
        negative_findings = detector.scan(NEGATIVE.read_text(encoding="utf-8"), str(NEGATIVE))

        self.assertGreaterEqual(len(positive_findings), 2)
        self.assertEqual(negative_findings, [])
        messages = "\n".join(f.message for f in positive_findings)
        self.assertIn("assetScale", messages)
        self.assertIn("shareScale", messages)
        self.assertIn("feePrecision", messages)
        self.assertIn("deposit", messages)
        self.assertIn("settleFee", messages)

    def test_slither_runner_positive_fires_and_negative_is_silent(self) -> None:
        positive_hits, positive_output = self._runner_hits(POSITIVE)
        negative_hits, negative_output = self._runner_hits(NEGATIVE)

        self.assertGreaterEqual(positive_hits, 1, positive_output)
        self.assertEqual(negative_hits, 0, negative_output)


if __name__ == "__main__":
    unittest.main()
