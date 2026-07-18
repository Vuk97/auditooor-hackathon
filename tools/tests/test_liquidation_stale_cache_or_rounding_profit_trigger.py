from __future__ import annotations

import json
import os
import py_compile
import re
import subprocess
import sys
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "detectors" / "run_custom.py"
PATTERN = "liquidation-stale-cache-or-rounding-profit-trigger"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
DETECTOR = ROOT / "detectors" / "wave17" / "liquidation_stale_cache_or_rounding_profit_trigger.py"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "liquidation_stale_cache_or_rounding_profit_trigger"
POSITIVE = FIXTURE_DIR / "positive.sol"
CLEAN = FIXTURE_DIR / "clean.sol"
ARITHMETIC_CONTROL = FIXTURE_DIR / "arithmetic_control.sol"
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


class LiquidationStaleCacheOrRoundingProfitTriggerTest(unittest.TestCase):
    def _hits(self, fixture: Path) -> tuple[int, str]:
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
        self.assertNotIn("No custom detectors found", proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1)), proc.stdout

    def test_reference_detector_and_fixture_metadata_stay_scoped(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)
        spec = yaml.safe_load(REFERENCE.read_text(encoding="utf-8"))
        smoke = json.loads(SMOKE.read_text(encoding="utf-8"))

        self.assertEqual(spec["pattern"], PATTERN)
        self.assertTrue(spec["manual_detector"])
        self.assertEqual(spec["source"], "auditooor-fire6-rwrq-liquidation-trigger-poison-c638d9e3c696")
        self.assertEqual(spec["submission_posture"], "NOT_SUBMIT_READY")
        self.assertFalse(spec["promotion_allowed"])
        self.assertIn("liquidation-trigger-poison", spec["tags"])
        self.assertIn("stale-collateral-cache", spec["tags"])
        self.assertIn("liquidation-rounding-profit", spec["tags"])
        self.assertEqual(spec["fixtures"]["vuln"], str(POSITIVE.relative_to(ROOT)))
        self.assertEqual(spec["fixtures"]["clean"], str(CLEAN.relative_to(ROOT)))
        self.assertEqual(spec["fixture_controls"]["arithmetic"], str(ARITHMETIC_CONTROL.relative_to(ROOT)))

        detector_text = DETECTOR.read_text(encoding="utf-8")
        self.assertIn(f'ARGUMENT = "{PATTERN}"', detector_text)
        self.assertIn("NOT_SUBMIT_READY", detector_text)
        self.assertIn("cachedLiquidity", detector_text)
        self.assertIn("repaidShares", detector_text)
        self.assertIn("_MAX_COLLATERAL_RE", detector_text)

        positive_text = POSITIVE.read_text(encoding="utf-8")
        clean_text = CLEAN.read_text(encoding="utf-8")
        control_text = ARITHMETIC_CONTROL.read_text(encoding="utf-8")
        self.assertIn("cachedLiquidity[tokenId]", positive_text)
        self.assertIn("repaidShares = toSharesDown", positive_text)
        self.assertIn("maxLiquidableCollateral = position.collateralValue", positive_text)
        self.assertIn("positionManager.positions(tokenId)", clean_text)
        self.assertIn("repaidAssets = toAssetsUp(repaidShares", clean_text)
        self.assertIn("normalizeValue(position.collateralValue", clean_text)
        self.assertIn("previewRedeemRoundTrip", control_text)

        self.assertEqual(smoke["pattern"], PATTERN)
        self.assertEqual(smoke["status"], "passed_vulnerable_clean_smoke")
        self.assertEqual(smoke["positive_hits"], 3)
        self.assertEqual(smoke["clean_hits"], 0)
        self.assertEqual(smoke["control_hits"], 0)
        self.assertEqual(smoke["coverage_claim"], "detector_fixture_smoke_only")
        self.assertFalse(smoke["promotion_allowed"])
        self.assertEqual(smoke["submission_posture"], "NOT_SUBMIT_READY")

    def test_positive_fixture_fires_and_controls_stay_quiet(self) -> None:
        positive_hits, positive_output = self._hits(POSITIVE)
        clean_hits, _clean_output = self._hits(CLEAN)
        control_hits, _control_output = self._hits(ARITHMETIC_CONTROL)

        self.assertGreaterEqual(positive_hits, 3, positive_output)
        self.assertEqual(clean_hits, 0)
        self.assertEqual(control_hits, 0)


if __name__ == "__main__":
    unittest.main()
