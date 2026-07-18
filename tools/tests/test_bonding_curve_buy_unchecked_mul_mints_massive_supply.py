from __future__ import annotations

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
PATTERN = "bonding-curve-buy-unchecked-mul-mints-massive-supply"
DETECTOR = ROOT / "detectors" / "wave17" / "bonding_curve_buy_unchecked_mul_mints_massive_supply.py"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / PATTERN
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


class BondingCurveBuyUncheckedMulMintsMassiveSupplyTest(unittest.TestCase):
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
        self.assertNotIn("UNKNOWN predicate key", proc.stdout)
        self.assertNotIn("No custom detectors found", proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1))

    def test_reference_and_fixtures_pin_unchecked_curve_mul_shape(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)
        spec = yaml.safe_load(REFERENCE.read_text(encoding="utf-8"))
        positive_text = POSITIVE.read_text(encoding="utf-8")
        clean_text = CLEAN.read_text(encoding="utf-8")

        self.assertEqual(spec["pattern"], PATTERN)
        self.assertEqual(spec["attack_class"], "integer-overflow-clamp")
        self.assertEqual(spec["status"], "not-submit-ready")
        self.assertEqual(spec["coverage_claim"], "detector_fixture_smoke_only")
        self.assertEqual(spec["submission_posture"], "NOT_SUBMIT_READY")
        self.assertEqual(
            spec["fixtures"]["vuln"],
            "detectors/fixtures/bonding-curve-buy-unchecked-mul-mints-massive-supply/positive.sol",
        )
        self.assertEqual(
            spec["fixtures"]["clean"],
            "detectors/fixtures/bonding-curve-buy-unchecked-mul-mints-massive-supply/clean.sol",
        )

        self.assertIn("requestedTokens * unitPrice", positive_text)
        self.assertIn("quantity * emissionMultiplier", positive_text)
        self.assertIn("require(requestedTokens <= MAX_BUY", clean_text)
        self.assertIn("FullMath.mulDiv", clean_text)

    def test_positive_fixture_fires_and_clean_fixture_stays_quiet(self) -> None:
        self.assertGreaterEqual(self._hits(POSITIVE), 2)
        self.assertEqual(self._hits(CLEAN), 0)


if __name__ == "__main__":
    unittest.main()
