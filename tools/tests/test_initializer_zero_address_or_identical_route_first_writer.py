#!/usr/bin/env python3
"""Focused regression for the route first-writer zero or same-domain guard detector."""

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
PATTERN = "initializer-zero-address-or-identical-route-first-writer"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
DETECTOR = ROOT / "detectors" / "wave17" / f"{PATTERN.replace('-', '_')}.py"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "initializer_zero_address_or_identical_route_first_writer"
POSITIVE = FIXTURE_DIR / "positive.sol"
CLEAN = FIXTURE_DIR / "clean.sol"
SOURCE_BACKED_ROUTE_POSITIVE = (
    ROOT
    / "detectors"
    / "fixtures"
    / "bridge_route_allows_identical_source_and_destination_chainid"
    / "positive.sol"
)
SOURCE_BACKED_PUBLIC_ROUTE_POSITIVE = (
    ROOT
    / "detectors"
    / "fixtures"
    / "public_route_or_chain_migration_first_writer"
    / "positive.sol"
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


class InitializerZeroAddressOrIdenticalRouteFirstWriterTest(unittest.TestCase):
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
        self.assertIn("compiled initializer-zero-address-or-identical-route-first-writer.yaml", proc.stdout)

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
        clean_text = CLEAN.read_text(encoding="utf-8")

        self.assertIn(f"pattern: {PATTERN}", text)
        self.assertIn("function.has_param_of_type", text)
        self.assertIn("function.has_modifier_not", text)
        self.assertIn("ZeroGateway", clean_text)
        self.assertIn("SameChain", clean_text)
        self.assertIn("msg.sender != factory", clean_text)

        self.assertIn("function initializeBridgeRoute(", positive_text)
        self.assertIn("gatewayFor[_sourceChainId][_destinationChainId] = _remoteGateway;", positive_text)
        self.assertNotIn("ZeroGateway", positive_text)
        self.assertNotIn("SameChain", positive_text)
        self.assertNotIn("msg.sender != factory", positive_text)

    def test_compiled_detector_metadata(self) -> None:
        self._compile_pattern()
        py_compile.compile(str(DETECTOR), doraise=True)
        detector_text = DETECTOR.read_text(encoding="utf-8")
        self.assertIn(f'ARGUMENT = "{PATTERN}"', detector_text)
        self.assertIn("_PRECONDITIONS", detector_text)
        self.assertIn("_MATCH", detector_text)

    def test_positive_fixture_fires_and_clean_fixture_stays_quiet(self) -> None:
        positive_hits, positive_output = self._run_detector(POSITIVE)
        clean_hits, clean_output = self._run_detector(CLEAN)

        self.assertGreaterEqual(positive_hits, 1, positive_output)
        self.assertIn("initializeBridgeRoute", positive_output)
        self.assertEqual(clean_hits, 0, clean_output)

    def test_source_backed_route_samples_fire(self) -> None:
        bridge_hits, bridge_output = self._run_detector(SOURCE_BACKED_ROUTE_POSITIVE)
        public_route_hits, public_route_output = self._run_detector(SOURCE_BACKED_PUBLIC_ROUTE_POSITIVE)

        self.assertGreaterEqual(bridge_hits, 1, bridge_output)
        self.assertIn("BridgeRoutePositive.configureRoute", bridge_output)
        self.assertGreaterEqual(public_route_hits, 1, public_route_output)
        self.assertIn("migrateChainToGateway", public_route_output)


if __name__ == "__main__":
    unittest.main()
