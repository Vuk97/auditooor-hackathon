#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
DETECTOR_PATH = REPO / "detectors" / "wave68" / "delegation_power_credit_without_debit.py"
RUNNER_PATH = REPO / "detectors" / "run_regex_detectors.py"
FIXTURES = REPO / "detectors" / "fixtures"
DETECTOR_NAME = "delegation-power-credit-without-debit"


def _load_module(path: Path, module_name: str):
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec and spec.loader, f"failed to load {path}"
    mod = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = mod
    spec.loader.exec_module(mod)
    return mod


def _load_detector():
    return _load_module(DETECTOR_PATH, "delegation_power_credit_without_debit_detector")


def _load_runner():
    return _load_module(RUNNER_PATH, "delegation_power_credit_without_debit_runner")


class DelegationPowerCreditWithoutDebitDetectorTest(unittest.TestCase):
    def test_positive_fixture_fires(self) -> None:
        mod = _load_detector()
        source = (FIXTURES / "delegation_power_credit_without_debit_positive.sol").read_text()
        findings = mod.scan(source, "delegation_power_credit_without_debit_positive.sol")
        self.assertGreaterEqual(len(findings), 1)
        first = findings[0]
        self.assertEqual(first.detector, DETECTOR_NAME)
        self.assertEqual(first.severity, "High")
        self.assertEqual(first.function, "delegate")
        self.assertIn("delegation-power-inflation", first.message)

    def test_negative_fixture_is_silent(self) -> None:
        mod = _load_detector()
        source = (FIXTURES / "delegation_power_credit_without_debit_negative.sol").read_text()
        findings = mod.scan(source, "delegation_power_credit_without_debit_negative.sol")
        self.assertEqual(findings, [])

    def test_regex_runner_discovers_and_filters_detector(self) -> None:
        runner = _load_runner()
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp) / "manifest.json"
            rc = runner.run(
                target=FIXTURES / "delegation_power_credit_without_debit_positive.sol",
                workspace=Path(tmp),
                manifest_path=manifest,
                name_filter=DETECTOR_NAME,
                json_only=True,
                no_manifest=False,
            )
            self.assertEqual(rc, 0)
            data = json.loads(manifest.read_text())
            self.assertEqual(data["per_detector_counts"][DETECTOR_NAME], 1)


if __name__ == "__main__":
    unittest.main()
