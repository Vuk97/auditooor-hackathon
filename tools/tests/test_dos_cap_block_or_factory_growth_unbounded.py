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
PATTERN = "dos-cap-block-or-factory-growth-unbounded"
DETECTOR = ROOT / "detectors" / "wave17" / "dos_cap_block_or_factory_growth_unbounded.py"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "dos_cap_block_or_factory_growth_unbounded"
POSITIVE = FIXTURE_DIR / "positive.sol"
CLEAN = FIXTURE_DIR / "clean.sol"
GAS_REFUND_VULN = ROOT / "patterns" / "fixtures" / "gas-refund-miscomputed-block-vs-tx_vuln.sol"
GAS_REFUND_CLEAN = ROOT / "patterns" / "fixtures" / "gas-refund-miscomputed-block-vs-tx_clean.sol"
CREATEPAIR_VULN = ROOT / "patterns" / "fixtures" / "glider-createpair-frontrun-dos_vuln.sol"
CREATEPAIR_CLEAN = ROOT / "patterns" / "fixtures" / "glider-createpair-frontrun-dos_clean.sol"
STICKY_FLAG_VULN = (
    ROOT / "patterns" / "fixtures" / "dos-cap-flag-or-estimation-oneway-exhaustion_vuln.sol"
)
BATCH_GAS_BOMB_VULN = ROOT / "patterns" / "fixtures" / "batch-call-gas-bomb-no-gaslimit_vuln.sol"


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


class DosCapBlockOrFactoryGrowthUnboundedTest(unittest.TestCase):
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
        self.assertNotIn("No custom detectors found", proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1))

    def test_detector_compiles_and_is_not_submit_ready(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

        detector_text = DETECTOR.read_text(encoding="utf-8")
        spec = yaml.safe_load(REFERENCE.read_text(encoding="utf-8"))

        self.assertIn(f'ARGUMENT = "{PATTERN}"', detector_text)
        self.assertIn("NOT_SUBMIT_READY detector recall only", detector_text)
        self.assertEqual(spec["attack_class"], "dos-cap-weakening")
        self.assertEqual(spec["coverage_claim"], "detector_fixture_smoke_only")
        self.assertFalse(spec["promotion_allowed"])
        self.assertEqual(spec["submission_posture"], "NOT_SUBMIT_READY")

    def test_fixture_pair_models_both_recall_shapes(self) -> None:
        positive = POSITIVE.read_text(encoding="utf-8")
        clean = CLEAN.read_text(encoding="utf-8")

        self.assertIn("block.gaslimit * tx.gasprice", positive)
        self.assertIn("msg.sender.call{value: gasRefund}", positive)
        self.assertIn("factory.createPair(token, weth)", positive)
        self.assertNotIn("getPair(token, weth)", positive)

        self.assertIn("startGas - gasleft() + FIXED_OVERHEAD", clean)
        self.assertIn("MAX_REFUND_GAS", clean)
        self.assertIn("factory.getPair(token, weth)", clean)
        self.assertIn("pair = factory.createPair(token, weth);", clean)

    def test_positive_fixture_fires_and_clean_fixture_stays_quiet(self) -> None:
        self.assertEqual(self._hits(POSITIVE), 2)
        self.assertEqual(self._hits(CLEAN), 0)

    def test_start_samples_fire_and_their_clean_controls_stay_quiet(self) -> None:
        self.assertEqual(self._hits(GAS_REFUND_VULN), 1)
        self.assertEqual(self._hits(GAS_REFUND_CLEAN), 0)
        self.assertEqual(self._hits(CREATEPAIR_VULN), 1)
        self.assertEqual(self._hits(CREATEPAIR_CLEAN), 0)

    def test_adjacent_generic_dos_fixtures_do_not_fire(self) -> None:
        self.assertEqual(self._hits(STICKY_FLAG_VULN), 0)
        self.assertEqual(self._hits(BATCH_GAS_BOMB_VULN), 0)


if __name__ == "__main__":
    unittest.main()
