from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import unittest
from pathlib import Path

import yaml


REPO = Path(__file__).resolve().parents[2]
ARGUMENT = "certora-aave-ltv-bounded-by-liquidation-threshold"
PATTERN = REPO / "reference" / "patterns.dsl" / f"{ARGUMENT}.yaml"
FIXTURE_STEM = REPO / "detectors" / "test_fixtures" / "certora_aave_ltv_bounded_by_liquidation_threshold"
FIXTURE_VULN = FIXTURE_STEM.with_name(FIXTURE_STEM.name + "_vuln.sol")
FIXTURE_CLEAN = FIXTURE_STEM.with_name(FIXTURE_STEM.name + "_clean.sol")
SMOKE = FIXTURE_STEM.with_name(FIXTURE_STEM.name + "_smoke.json")
RUN_CUSTOM = REPO / "detectors" / "run_custom.py"


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
                cwd=REPO,
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


class KlbqCertoraAaveLtvBoundedByLiquidationThresholdWiringTest(unittest.TestCase):
    def _hits(self, fixture: Path) -> int:
        python = _python_with_slither()
        if python is None:
            self.skipTest("slither-analyzer is not installed in this workspace")

        proc = subprocess.run(
            [python, str(RUN_CUSTOM), "--tier=ALL", str(fixture), ARGUMENT],
            cwd=REPO,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
            env={**os.environ, "AUDITOOOR_SLITHER_NOCACHE": "1"},
        )
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertNotIn("UNKNOWN function predicate key", proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1))

    def test_registry_points_at_smokeable_fixture_pair(self) -> None:
        registry = yaml.safe_load((REPO / "detectors" / "_tier_registry.yaml").read_text(encoding="utf-8"))
        entry = registry["tiers"][ARGUMENT]

        self.assertEqual(
            entry["fixture_pair"],
            "detectors/test_fixtures/certora_aave_ltv_bounded_by_liquidation_threshold",
        )
        self.assertIn(
            "detectors/test_fixtures/certora_aave_ltv_bounded_by_liquidation_threshold_vuln.sol",
            entry["reason"],
        )
        self.assertEqual(
            entry["smoke_test_command"],
            "python3 detectors/run_custom.py --tier=ALL "
            "detectors/test_fixtures/certora_aave_ltv_bounded_by_liquidation_threshold_vuln.sol "
            "certora-aave-ltv-bounded-by-liquidation-threshold",
        )
        self.assertTrue(FIXTURE_VULN.is_file(), f"missing {FIXTURE_VULN}")
        self.assertTrue(FIXTURE_CLEAN.is_file(), f"missing {FIXTURE_CLEAN}")

    def test_pattern_yaml_points_at_same_fixture_pair(self) -> None:
        spec = yaml.safe_load(PATTERN.read_text(encoding="utf-8"))
        self.assertEqual(spec["pattern"], ARGUMENT)
        self.assertEqual(
            spec["fixtures"]["vuln"],
            "detectors/test_fixtures/certora_aave_ltv_bounded_by_liquidation_threshold_vuln.sol",
        )
        self.assertEqual(
            spec["fixtures"]["clean"],
            "detectors/test_fixtures/certora_aave_ltv_bounded_by_liquidation_threshold_clean.sol",
        )

    def test_smoke_record_captures_positive_and_clean_counts(self) -> None:
        payload = json.loads(SMOKE.read_text(encoding="utf-8"))
        self.assertEqual(payload["status"], "passed_vulnerable_clean_smoke")
        self.assertEqual(
            payload["positive_fixture_path"],
            "detectors/test_fixtures/certora_aave_ltv_bounded_by_liquidation_threshold_vuln.sol",
        )
        self.assertEqual(
            payload["clean_fixture_path"],
            "detectors/test_fixtures/certora_aave_ltv_bounded_by_liquidation_threshold_clean.sol",
        )
        self.assertGreaterEqual(payload["positive_hits"], 1)
        self.assertEqual(payload["clean_hits"], 0)

    def test_fixture_pair_hits_vuln_and_suppresses_clean(self) -> None:
        self.assertGreaterEqual(self._hits(FIXTURE_VULN), 1)
        self.assertEqual(self._hits(FIXTURE_CLEAN), 0)


if __name__ == "__main__":
    unittest.main()
