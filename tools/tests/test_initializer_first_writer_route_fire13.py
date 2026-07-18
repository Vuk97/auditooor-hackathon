#!/usr/bin/env python3
"""Focused regression for the Fire13 initializer route first-writer detector."""

from __future__ import annotations

import os
import py_compile
import re
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "detectors" / "run_custom.py"
COMPILER = ROOT / "tools" / "pattern-compile.py"
PATTERN = "initializer-first-writer-route-fire13"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
DETECTOR = ROOT / "detectors" / "wave17" / f"{PATTERN.replace('-', '_')}.py"
POSITIVE = ROOT / "detectors" / "test_fixtures" / "positive" / f"{PATTERN}.sol"
NEGATIVE = ROOT / "detectors" / "test_fixtures" / "negative" / f"{PATTERN}.sol"
HELD_OUT_MIGRATED_POSITIVE = (
    ROOT
    / "detectors"
    / "fixtures"
    / "a_newly_created_chain_that_has_been_migrated_to_the_gateway_will"
    / "ssi-fix-048_positive.sol"
)
HELD_OUT_MIGRATED_CLEAN = (
    ROOT
    / "detectors"
    / "fixtures"
    / "a_newly_created_chain_that_has_been_migrated_to_the_gateway_will"
    / "ssi-fix-048_clean.sol"
)
HELD_OUT_ROUTE_POSITIVE = (
    ROOT
    / "detectors"
    / "fixtures"
    / "public_route_or_chain_migration_first_writer"
    / "positive.sol"
)
HELD_OUT_ROUTE_CLEAN = (
    ROOT
    / "detectors"
    / "fixtures"
    / "public_route_or_chain_migration_first_writer"
    / "clean.sol"
)
HELD_OUT_BRIDGE_ROUTE_POSITIVE = (
    ROOT
    / "detectors"
    / "fixtures"
    / "bridge_route_allows_identical_source_and_destination_chainid"
    / "positive.sol"
)
HELD_OUT_BRIDGE_ROUTE_CLEAN = (
    ROOT
    / "detectors"
    / "fixtures"
    / "bridge_route_allows_identical_source_and_destination_chainid"
    / "clean.sol"
)


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


class InitializerFirstWriterRouteFire13Test(unittest.TestCase):
    def _compile_pattern(self) -> None:
        proc = subprocess.run(
            [
                sys.executable,
                str(COMPILER),
                str(REFERENCE),
                "--wave",
                "17",
                "--strict-all",
            ],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=60,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertIn("compiled initializer-first-writer-route-fire13.yaml", proc.stdout)

    def _run_detector(self, fixture: Path) -> tuple[int, str]:
        slither_python = _python_with_slither()
        if slither_python is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        self._compile_pattern()
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
        self.assertNotIn("UNKNOWN function predicate key", proc.stdout)
        self.assertIn(PATTERN, proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1)), proc.stdout

    def test_reference_yaml_and_fixture_shape(self) -> None:
        text = REFERENCE.read_text(encoding="utf-8")
        positive_text = POSITIVE.read_text(encoding="utf-8")
        negative_text = NEGATIVE.read_text(encoding="utf-8")

        self.assertIn(f"pattern: {PATTERN}", text)
        self.assertIn("a-newly-created-chain-that-has-been-migrated-to-the-gateway-will", text)
        self.assertIn("function.body_not_contains_regex", text)
        self.assertIn("gatewayReturnQueued =", positive_text)
        self.assertIn("initializeBridgeRoute", positive_text)
        self.assertIn("_updateTreeSnapshot", negative_text)
        self.assertIn("NotFactory", negative_text)
        self.assertIn("SameChain", negative_text)
        self.assertIn("ZeroGateway", negative_text)

    def test_compiled_detector_metadata(self) -> None:
        self._compile_pattern()
        py_compile.compile(str(DETECTOR), doraise=True)
        detector_text = DETECTOR.read_text(encoding="utf-8")
        self.assertIn(f'ARGUMENT = "{PATTERN}"', detector_text)
        self.assertIn("_PRECONDITIONS", detector_text)
        self.assertIn("_MATCH", detector_text)

    def test_positive_fixture_fires_and_negative_fixture_stays_quiet(self) -> None:
        positive_hits, positive_output = self._run_detector(POSITIVE)
        negative_hits, negative_output = self._run_detector(NEGATIVE)

        self.assertGreaterEqual(positive_hits, 2, positive_output)
        self.assertIn("priorityTree", positive_output)
        self.assertIn("initializeBridgeRoute", positive_output)
        self.assertEqual(negative_hits, 0, negative_output)

    def test_held_out_migrated_gateway_and_route_samples_are_covered(self) -> None:
        migrated_hits, migrated_output = self._run_detector(HELD_OUT_MIGRATED_POSITIVE)
        migrated_clean_hits, migrated_clean_output = self._run_detector(HELD_OUT_MIGRATED_CLEAN)
        route_hits, route_output = self._run_detector(HELD_OUT_ROUTE_POSITIVE)
        route_clean_hits, route_clean_output = self._run_detector(HELD_OUT_ROUTE_CLEAN)

        self.assertGreaterEqual(migrated_hits, 1, migrated_output)
        self.assertIn("priorityTree", migrated_output)
        self.assertEqual(migrated_clean_hits, 0, migrated_clean_output)
        self.assertGreaterEqual(route_hits, 1, route_output)
        self.assertIn("migrateChainToGateway", route_output)
        self.assertEqual(route_clean_hits, 0, route_clean_output)

    def test_held_out_bridge_route_sample_is_covered(self) -> None:
        bridge_hits, bridge_output = self._run_detector(HELD_OUT_BRIDGE_ROUTE_POSITIVE)
        bridge_clean_hits, bridge_clean_output = self._run_detector(HELD_OUT_BRIDGE_ROUTE_CLEAN)

        self.assertGreaterEqual(bridge_hits, 1, bridge_output)
        self.assertIn("BridgeRoutePositive.configureRoute", bridge_output)
        self.assertEqual(bridge_clean_hits, 0, bridge_clean_output)


if __name__ == "__main__":
    unittest.main()
