from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml


REPO = Path(__file__).resolve().parents[2]
ARGUMENT = "certora-aave-liquidity-index-monotonic"
PATTERN = REPO / "reference" / "patterns.dsl" / f"{ARGUMENT}.yaml"
FIXTURE_STEM = REPO / "detectors" / "test_fixtures" / "certora_aave_liquidity_index_monotonic"
FIXTURE_VULN = FIXTURE_STEM.with_name(FIXTURE_STEM.name + "_vuln.sol")
FIXTURE_CLEAN = FIXTURE_STEM.with_name(FIXTURE_STEM.name + "_clean.sol")
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


class KlbqCertoraAaveLiquidityIndexMonotonicWiringTest(unittest.TestCase):
    def test_registry_points_at_smokeable_fixture_pair(self) -> None:
        registry = yaml.safe_load((REPO / "detectors" / "_tier_registry.yaml").read_text(encoding="utf-8"))
        entry = registry["tiers"][ARGUMENT]

        self.assertEqual(
            entry["fixture_pair"],
            "detectors/test_fixtures/certora_aave_liquidity_index_monotonic",
        )
        self.assertIn(
            "detectors/test_fixtures/certora_aave_liquidity_index_monotonic_vuln.sol",
            entry["reason"],
        )
        self.assertEqual(
            entry["smoke_test_command"],
            "python3 detectors/run_custom.py --tier=ALL "
            "detectors/test_fixtures/certora_aave_liquidity_index_monotonic_vuln.sol "
            "certora-aave-liquidity-index-monotonic",
        )
        self.assertTrue(FIXTURE_VULN.is_file(), f"missing {FIXTURE_VULN}")
        self.assertTrue(FIXTURE_CLEAN.is_file(), f"missing {FIXTURE_CLEAN}")

    def test_pattern_yaml_points_at_same_fixture_pair(self) -> None:
        spec = yaml.safe_load(PATTERN.read_text(encoding="utf-8"))
        self.assertEqual(spec["pattern"], ARGUMENT)
        self.assertEqual(
            spec["fixtures"]["vuln"],
            "detectors/test_fixtures/certora_aave_liquidity_index_monotonic_vuln.sol",
        )
        self.assertEqual(
            spec["fixtures"]["clean"],
            "detectors/test_fixtures/certora_aave_liquidity_index_monotonic_clean.sol",
        )

    def test_fixture_shape_preserves_monotonic_guard_signal(self) -> None:
        vuln = FIXTURE_VULN.read_text(encoding="utf-8")
        clean = FIXTURE_CLEAN.read_text(encoding="utf-8")

        self.assertIn("function rescaleReserve", vuln)
        self.assertIn("function adjustIndex", vuln)
        self.assertNotIn("require(newIndex >= liquidityIndex", vuln)
        self.assertNotIn("require(newBorrowIndex >= variableBorrowIndex", vuln)

        self.assertIn("require(newIndex >= liquidityIndex", clean)
        self.assertIn("require(newBorrowIndex >= variableBorrowIndex", clean)
        self.assertNotIn("non‑decreasing", clean)


class KlbqCertoraAaveLiquidityIndexMonotonicSlitherSmokeTest(unittest.TestCase):
    def test_fixture_pair_hits_vuln_and_suppresses_clean_in_isolated_workspaces(self) -> None:
        python = _python_with_slither()
        if python is None:
            self.skipTest("slither-analyzer is not installed in this workspace")

        outputs: dict[str, str] = {}
        for label, fixture in (("vuln", FIXTURE_VULN), ("clean", FIXTURE_CLEAN)):
            with tempfile.TemporaryDirectory(prefix=f"klbq_aave_{label}_") as td:
                td_path = Path(td)
                isolated = td_path / fixture.name
                shutil.copy2(fixture, isolated)
                proc = subprocess.run(
                    [python, str(RUN_CUSTOM), "--tier=ALL", str(isolated), ARGUMENT],
                    cwd=REPO,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=120,
                    env={**os.environ, "AUDITOOOR_SLITHER_NOCACHE": "1"},
                )
                self.assertEqual(proc.returncode, 0, proc.stdout)
                outputs[label] = proc.stdout

        self.assertRegex(outputs["vuln"], r"total hits:\s*[1-9]")
        self.assertRegex(outputs["clean"], r"total hits:\s*0")
