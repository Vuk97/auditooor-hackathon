from __future__ import annotations

import json
import os
import py_compile
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "detectors" / "run_custom.py"
INVENTORY_SMOKE = ROOT / "tools" / "inventory-smoke-test.py"
PATTERN = "reward-period-extend-no-access-control"
DETECTOR = ROOT / "detectors" / "wave17" / "reward_period_extend_no_access_control.py"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "reward_period_extend_no_access_control"
POSITIVE = FIXTURE_DIR / "positive.sol"
CLEAN = FIXTURE_DIR / "clean.sol"
CLEAN_AMOUNT = FIXTURE_DIR / "clean_amount.sol"
CLEAN_CUSTOM_AUTH = FIXTURE_DIR / "clean_custom_auth.sol"
CLEAN_EMISSION_ADMIN = FIXTURE_DIR / "clean_emission_admin.sol"
CLEAN_REQUIRES_DISTRIBUTOR_ROLE = FIXTURE_DIR / "clean_requires_distributor_role.sol"
CLEAN_HELPER_AUTH = FIXTURE_DIR / "clean_helper_auth.sol"
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


class RewardPeriodExtendNoAccessControlTest(unittest.TestCase):
    def _hits(self, fixture: Path) -> int:
        slither_python = _python_with_slither()
        if slither_python is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        env = os.environ.copy()
        env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
        env["AUDITOOOR_SLITHER_NOCACHE"] = "1"
        proc = subprocess.run(
            [
                slither_python,
                str(RUNNER),
                "--tier=ALL",
                str(fixture),
                PATTERN,
            ],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertNotIn("No custom detectors found", proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1))

    def test_detector_reference_and_fixture_metadata(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

        detector_text = DETECTOR.read_text(encoding="utf-8")
        reference_text = REFERENCE.read_text(encoding="utf-8")
        positive_text = POSITIVE.read_text(encoding="utf-8")
        clean_text = CLEAN.read_text(encoding="utf-8")
        clean_amount_text = CLEAN_AMOUNT.read_text(encoding="utf-8")
        clean_custom_auth_text = CLEAN_CUSTOM_AUTH.read_text(encoding="utf-8")
        clean_emission_admin_text = CLEAN_EMISSION_ADMIN.read_text(encoding="utf-8")
        clean_requires_distributor_role_text = CLEAN_REQUIRES_DISTRIBUTOR_ROLE.read_text(encoding="utf-8")
        clean_helper_auth_text = CLEAN_HELPER_AUTH.read_text(encoding="utf-8")
        payload = json.loads(SMOKE.read_text(encoding="utf-8"))

        self.assertIn(f'ARGUMENT = "{PATTERN}"', detector_text)
        self.assertIn(f"pattern: {PATTERN}", reference_text)
        self.assertNotIn("function.modifiers_not_matching", reference_text)
        self.assertIn("function.has_modifier", reference_text)
        self.assertIn("extendRewardPeriod", reference_text)
        self.assertIn("onlyRewardManager", reference_text)
        self.assertIn("'function.has_modifier'", detector_text)
        self.assertIn("amount", reference_text)
        self.assertIn("amount", detector_text)

        self.assertIn("function extendRewardPeriod(uint256 reward) external", positive_text)
        self.assertIn("hasRole(REWARD_ADMIN_ROLE, msg.sender)", positive_text)
        self.assertIn("periodFinish = block.timestamp + rewardsDuration;", positive_text)
        self.assertNotIn("onlyRewardManager", positive_text)
        self.assertNotIn("reward > 0", positive_text)

        self.assertIn("function notifyRewardAmount(uint256 reward) external onlyOwner", clean_text)
        self.assertIn("require(reward > 0", clean_text)
        self.assertIn("function depositReward(uint256 amount) external", clean_amount_text)
        self.assertIn("require(amount > 0", clean_amount_text)
        self.assertIn("function extendRewardPeriod(uint256 amount) external onlyRewardManager", clean_custom_auth_text)
        self.assertIn("_canExtendRewardPeriod(msg.sender)", clean_custom_auth_text)
        self.assertIn("require(amount > 0", clean_custom_auth_text)
        self.assertIn("modifier onlyEmissionAdmin()", clean_emission_admin_text)
        self.assertIn("function extendRewardPeriod(uint256 amount) external onlyEmissionAdmin", clean_emission_admin_text)
        self.assertIn("modifier requiresDistributorRole()", clean_requires_distributor_role_text)
        self.assertIn("function extendRewardPeriod(uint256 amount) external requiresDistributorRole", clean_requires_distributor_role_text)
        self.assertIn("require(_canExtendRewardPeriod(msg.sender)", clean_helper_auth_text)
        self.assertIn("function extendRewardPeriod(uint256 amount) external", clean_helper_auth_text)

        self.assertEqual(payload["pattern"], PATTERN)
        self.assertEqual(payload["status"], "smoke_pass")
        self.assertEqual(payload["coverage_claim"], "detector_fixture_smoke_only")
        self.assertFalse(payload["promotion_allowed"])
        self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")
        self.assertEqual(payload["positive_hits"], 1)
        self.assertEqual(payload["clean_hits"], 0)
        self.assertEqual(len(payload["additional_clean_fixtures"]), 5)
        smoke_text = SMOKE.read_text(encoding="utf-8")
        self.assertNotIn("/opt/homebrew", smoke_text)
        self.assertIn("python3 detectors/run_custom.py", payload["positive_command"])
        self.assertIn("python3 detectors/run_custom.py", payload["clean_command"])
        additional_clean = payload["additional_clean_fixtures"][0]
        self.assertEqual(
            additional_clean["path"],
            "detectors/fixtures/reward_period_extend_no_access_control/clean_amount.sol",
        )
        self.assertEqual(additional_clean["clean_hits"], 0)
        self.assertIn("clean_amount.sol", additional_clean["command"])
        custom_auth_clean = payload["additional_clean_fixtures"][1]
        self.assertEqual(
            custom_auth_clean["path"],
            "detectors/fixtures/reward_period_extend_no_access_control/clean_custom_auth.sol",
        )
        self.assertEqual(custom_auth_clean["clean_hits"], 0)
        self.assertIn("clean_custom_auth.sol", custom_auth_clean["command"])
        emission_admin_clean = payload["additional_clean_fixtures"][2]
        self.assertEqual(
            emission_admin_clean["path"],
            "detectors/fixtures/reward_period_extend_no_access_control/clean_emission_admin.sol",
        )
        self.assertEqual(emission_admin_clean["clean_hits"], 0)
        self.assertIn("clean_emission_admin.sol", emission_admin_clean["command"])
        distributor_role_clean = payload["additional_clean_fixtures"][3]
        self.assertEqual(
            distributor_role_clean["path"],
            "detectors/fixtures/reward_period_extend_no_access_control/clean_requires_distributor_role.sol",
        )
        self.assertEqual(distributor_role_clean["clean_hits"], 0)
        self.assertIn("clean_requires_distributor_role.sol", distributor_role_clean["command"])
        helper_auth_clean = payload["additional_clean_fixtures"][4]
        self.assertEqual(
            helper_auth_clean["path"],
            "detectors/fixtures/reward_period_extend_no_access_control/clean_helper_auth.sol",
        )
        self.assertEqual(helper_auth_clean["clean_hits"], 0)
        self.assertIn("clean_helper_auth.sol", helper_auth_clean["command"])

    def test_positive_fixture_fires_and_clean_fixture_stays_quiet(self) -> None:
        self.assertGreaterEqual(self._hits(POSITIVE), 1)
        self.assertEqual(self._hits(CLEAN), 0)
        self.assertEqual(self._hits(CLEAN_AMOUNT), 0)
        self.assertEqual(self._hits(CLEAN_CUSTOM_AUTH), 0)
        self.assertEqual(self._hits(CLEAN_EMISSION_ADMIN), 0)
        self.assertEqual(self._hits(CLEAN_REQUIRES_DISTRIBUTOR_ROLE), 0)
        self.assertEqual(self._hits(CLEAN_HELPER_AUTH), 0)

    def test_inventory_smoke_exact_detector_reports_one_pass(self) -> None:
        slither_python = _python_with_slither()
        if slither_python is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        env = os.environ.copy()
        env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
        env["AUDITOOOR_SLITHER_NOCACHE"] = "1"
        env["SLITHER_PYTHON"] = slither_python

        with tempfile.TemporaryDirectory(prefix="inventory-smoke-rpec-") as tmp:
            proc = subprocess.run(
                [
                    slither_python,
                    str(INVENTORY_SMOKE),
                    "--output-dir",
                    tmp,
                    "--detector",
                    PATTERN,
                    "--workers",
                    "1",
                ],
                cwd=ROOT,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=180,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout)
            summary = json.loads((Path(tmp) / "inventory_smoke_summary.json").read_text(encoding="utf-8"))

        self.assertEqual(summary["total_detectors_scanned"], 1)
        self.assertEqual(summary["by_status"].get("smoke_pass"), 1)
        self.assertEqual(len(summary["results"]), 1)
        self.assertEqual(summary["results"][0]["argument"], PATTERN)
        self.assertEqual(summary["results"][0]["status"], "smoke_pass")
        self.assertGreaterEqual(summary["results"][0]["vuln_hits"], 1)
        self.assertEqual(summary["results"][0]["clean_hits"], 0)


if __name__ == "__main__":
    unittest.main()
