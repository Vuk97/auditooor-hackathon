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
PATTERN = "rounding-boundary-or-position-self-sandwich"
DETECTOR = ROOT / "detectors" / "wave17" / "rounding_boundary_or_position_self_sandwich.py"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "rounding_boundary_or_position_self_sandwich"
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


def _hits(fixture: Path) -> tuple[int, str]:
    slither_python = _python_with_slither()
    if slither_python is None:
        raise unittest.SkipTest("slither-analyzer is not importable by the tested Python interpreters")

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
    if proc.returncode != 0:
        raise AssertionError(proc.stdout)
    match = re.search(r"total hits:\s*(\d+)", proc.stdout)
    if match is None:
        raise AssertionError(proc.stdout)
    return int(match.group(1)), proc.stdout


class RoundingBoundaryOrPositionSelfSandwichTest(unittest.TestCase):
    def test_detector_reference_and_fixtures_are_source_scoped(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

        detector_text = DETECTOR.read_text(encoding="utf-8")
        reference_text = REFERENCE.read_text(encoding="utf-8")
        positive_text = POSITIVE.read_text(encoding="utf-8")
        clean_text = CLEAN.read_text(encoding="utf-8")

        for path, text in {
            DETECTOR: detector_text,
            REFERENCE: reference_text,
            POSITIVE: positive_text,
            CLEAN: clean_text,
        }.items():
            self.assertNotIn("\u2013", text, f"en dash found in {path}")
            self.assertNotIn("\u2014", text, f"em dash found in {path}")

        self.assertIn(f'ARGUMENT = "{PATTERN}"', detector_text)
        self.assertIn("submission_posture: NOT_SUBMIT_READY", reference_text)
        self.assertIn("attacker_self_sandwiches_swap_in_open_close_position_positive.rs", reference_text)
        self.assertIn("bitmap_64_reserve_off_by_one_positive.rs", reference_text)
        self.assertIn(str(POSITIVE.relative_to(ROOT)), reference_text)
        self.assertIn(str(CLEAN.relative_to(ROOT)), reference_text)

        self.assertIn("minAmountOut: 0", positive_text)
        self.assertIn("maxSlippageBps: 10000", positive_text)
        self.assertIn("uint256 shift = reserveId * 2;", positive_text)
        self.assertIn("uint256 mask = 1 << shift;", positive_text)

        self.assertIn("MAX_SLIPPAGE_BPS", clean_text)
        self.assertIn("require(reserveId < 64", clean_text)
        self.assertIn("minted = (assets * totalSupply) / totalAssets;", clean_text)
        self.assertIn('require(minted > 0, "zero shares");', clean_text)

    def test_positive_fixture_fires_and_clean_fixture_stays_quiet(self) -> None:
        positive_hits, positive_output = _hits(POSITIVE)
        clean_hits, clean_output = _hits(CLEAN)

        self.assertGreaterEqual(positive_hits, 2, positive_output)
        self.assertEqual(clean_hits, 0, clean_output)

    def test_smoke_record_and_adjacent_arithmetic_clean_control(self) -> None:
        payload = json.loads(SMOKE.read_text(encoding="utf-8"))
        self.assertEqual(payload["pattern"], PATTERN)
        self.assertFalse(payload["promotion_allowed"])
        self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")
        self.assertGreaterEqual(payload["positive_hits_min"], 2)
        self.assertEqual(payload["clean_hits"], 0)

        clean_text = CLEAN.read_text(encoding="utf-8")
        self.assertIn("mintShares", clean_text)
        self.assertIn("(assets * totalSupply) / totalAssets", clean_text)
        self.assertNotIn("assets / totalAssets * totalSupply", clean_text)


if __name__ == "__main__":
    unittest.main()
