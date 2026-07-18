from __future__ import annotations

import importlib.util
import json
import os
import py_compile
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "detectors" / "run_custom.py"
TOOL = ROOT / "tools" / "pattern-compile.py"
PATTERN = "reward-pool-identity-or-period-advance-skew"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
DETECTOR = ROOT / "detectors" / "wave17" / "reward_pool_identity_or_period_advance_skew.py"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "reward_pool_identity_or_period_advance_skew"
POSITIVE = FIXTURE_DIR / "positive.sol"
CLEAN = FIXTURE_DIR / "clean.sol"
CEI_CONTROL = FIXTURE_DIR / "cei_reward_transfer_control.sol"
FLASHLOAN_CONTROL = FIXTURE_DIR / "flashloan_noise_control.sol"
CASIMIR_CONTROL = FIXTURE_DIR / "casimir_withdrawal_skew_control.sol"
SMOKE = FIXTURE_DIR / "smoke.json"
SOURCE_POOL_POSITIVE = ROOT / "detectors" / "fixtures" / "rs_rewards_duplicate_pair_key_missing_pool_identity" / "positive.sol"
SOURCE_POOL_CLEAN = ROOT / "detectors" / "fixtures" / "rs_rewards_duplicate_pair_key_missing_pool_identity" / "clean.sol"
SOURCE_PERIOD_POSITIVE = ROOT / "patterns" / "fixtures" / "auction-failure-stalls-period-advance_vuln.sol"
SOURCE_PERIOD_CLEAN = ROOT / "patterns" / "fixtures" / "auction-failure-stalls-period-advance_clean.sol"


def _load_pattern_compile():
    spec = importlib.util.spec_from_file_location("pattern_compile", TOOL)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


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


class RewardPoolIdentityOrPeriodAdvanceSkewTest(unittest.TestCase):
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
        self.assertNotIn("UNKNOWN predicate key", proc.stdout)
        self.assertNotIn("UNKNOWN function predicate key", proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1))

    def test_manual_detector_metadata_and_yaml_skip_compile(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)
        spec = yaml.safe_load(REFERENCE.read_text(encoding="utf-8"))

        self.assertEqual(spec["pattern"], PATTERN)
        self.assertEqual(spec["source"], "fire6-rwrq-rewards-distribution-skew-8d88ac50e6c2")
        self.assertIs(spec["manual_detector"], True)
        self.assertEqual(spec["submission_posture"], "NOT_SUBMIT_READY")
        self.assertIn("rewards-distribution-skew", spec["tags"])
        self.assertIn("Solodit #63420", REFERENCE.read_text(encoding="utf-8"))
        self.assertIn(f'ARGUMENT = "{PATTERN}"', DETECTOR.read_text(encoding="utf-8"))

        compiler = _load_pattern_compile()
        with tempfile.TemporaryDirectory(prefix=".pattern_compile_reward_pool_identity_", dir=ROOT) as tmp:
            out_dir = Path(tmp) / "wave99"
            compiled = compiler.compile_pattern(
                REFERENCE,
                out_dir,
                strict_yaml_shapes=True,
                strict_unsupported_keys=True,
            )
            self.assertFalse(compiled)
            self.assertFalse((out_dir / DETECTOR.name).exists())

    def test_fixture_metadata_lists_source_backtests_and_controls(self) -> None:
        payload = json.loads(SMOKE.read_text(encoding="utf-8"))
        positive_text = POSITIVE.read_text(encoding="utf-8")
        clean_text = CLEAN.read_text(encoding="utf-8")
        cei_text = CEI_CONTROL.read_text(encoding="utf-8")
        flashloan_text = FLASHLOAN_CONTROL.read_text(encoding="utf-8")
        casimir_text = CASIMIR_CONTROL.read_text(encoding="utf-8")

        self.assertEqual(payload["schema"], "auditooor.canonical_detector_fixture_smoke.v1")
        self.assertEqual(payload["pattern"], PATTERN)
        self.assertEqual(payload["positive_hits"], 3)
        self.assertEqual(payload["clean_hits"], 0)
        self.assertEqual(payload["source_pool_identity_positive_hits"], 2)
        self.assertEqual(payload["source_period_advance_positive_hits"], 1)
        self.assertEqual(payload["cei_reward_transfer_control_hits"], 0)
        self.assertEqual(payload["flashloan_noise_control_hits"], 0)
        self.assertEqual(payload["casimir_withdrawal_skew_control_hits"], 0)
        self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")
        self.assertFalse(payload["promotion_allowed"])

        self.assertIn("rewardsByPair[pair] += amount;", positive_text)
        self.assertIn("return;", positive_text)
        self.assertIn("canonicalPoolForPair[pair] == poolId", clean_text)
        self.assertIn("currentPeriod++;", clean_text)
        self.assertIn("rewardToken.transfer(msg.sender, reward);", cei_text)
        self.assertIn("flashLoan", flashloan_text)
        self.assertIn("requestUnstake", casimir_text)

    def test_positive_backtests_fire_and_clean_controls_stay_quiet(self) -> None:
        self.assertEqual(self._hits(POSITIVE), 3)
        self.assertEqual(self._hits(CLEAN), 0)

        self.assertEqual(self._hits(SOURCE_POOL_POSITIVE), 2)
        self.assertEqual(self._hits(SOURCE_POOL_CLEAN), 0)
        self.assertEqual(self._hits(SOURCE_PERIOD_POSITIVE), 1)
        self.assertEqual(self._hits(SOURCE_PERIOD_CLEAN), 0)

        self.assertEqual(self._hits(CEI_CONTROL), 0)
        self.assertEqual(self._hits(FLASHLOAN_CONTROL), 0)
        self.assertEqual(self._hits(CASIMIR_CONTROL), 0)


if __name__ == "__main__":
    unittest.main()
