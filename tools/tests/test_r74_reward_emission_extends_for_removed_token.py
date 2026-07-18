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
PATTERN = "r74-reward-emission-extends-for-removed-token"
DETECTOR = ROOT / "detectors" / "wave17" / "r74_reward_emission_extends_for_removed_token.py"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "r74_reward_emission_extends_for_removed_token"
MIRROR_DIR = ROOT / "detectors" / "fixtures" / PATTERN
POSITIVE = FIXTURE_DIR / "positive.sol"
CLEAN = FIXTURE_DIR / "clean.sol"
SMOKE = FIXTURE_DIR / "smoke.json"
MIRROR_POSITIVE = MIRROR_DIR / "positive.sol"
MIRROR_CLEAN = MIRROR_DIR / "clean.sol"
MIRROR_SMOKE = MIRROR_DIR / "smoke.json"


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


class R74RewardEmissionExtendsForRemovedTokenTest(unittest.TestCase):
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
        smoke = json.loads(SMOKE.read_text(encoding="utf-8"))
        mirror_smoke = json.loads(MIRROR_SMOKE.read_text(encoding="utf-8"))

        self.assertIn(f'ARGUMENT = "{PATTERN}"', detector_text)
        self.assertIn(f"pattern: {PATTERN}", reference_text)
        self.assertIn("status: not-submit-ready", reference_text)
        self.assertIn("coverage_claim: detector_fixture_smoke_only", reference_text)
        self.assertIn("submission_posture: NOT_SUBMIT_READY", reference_text)
        self.assertIn("fixture_mirrors:", reference_text)
        self.assertIn("rewardRate", detector_text)
        self.assertIn("periodFinish", detector_text)
        self.assertIn("isRewardToken", positive_text)
        self.assertIn("notifyRewardAmount(address token, uint256 amount) external", positive_text)
        self.assertNotIn("inactive reward token", positive_text)
        self.assertIn("require(isRewardToken[token], \"inactive reward token\");", clean_text)
        self.assertEqual(smoke["pattern"], PATTERN)
        self.assertEqual(smoke["status"], "passed_vulnerable_clean_smoke")
        self.assertEqual(smoke["positive_hits"], 1)
        self.assertEqual(smoke["clean_hits"], 0)
        self.assertEqual(smoke["submission_posture"], "NOT_SUBMIT_READY")
        self.assertEqual(mirror_smoke["pattern"], PATTERN)
        self.assertEqual(mirror_smoke["positive_hits"], 1)
        self.assertEqual(mirror_smoke["clean_hits"], 0)

    def test_positive_fixture_fires_and_clean_fixture_stays_quiet(self) -> None:
        self.assertGreaterEqual(self._hits(POSITIVE), 1)
        self.assertEqual(self._hits(CLEAN), 0)

    def test_mirror_fixture_pair_stays_in_sync(self) -> None:
        self.assertEqual(POSITIVE.read_text(encoding="utf-8"), MIRROR_POSITIVE.read_text(encoding="utf-8"))
        self.assertEqual(CLEAN.read_text(encoding="utf-8"), MIRROR_CLEAN.read_text(encoding="utf-8"))

    def test_inventory_smoke_exact_detector_reports_one_pass(self) -> None:
        slither_python = _python_with_slither()
        if slither_python is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        env = os.environ.copy()
        env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
        env["AUDITOOOR_SLITHER_NOCACHE"] = "1"
        env["SLITHER_PYTHON"] = slither_python

        with tempfile.TemporaryDirectory(prefix="inventory-smoke-r74-rpec-") as tmp:
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
