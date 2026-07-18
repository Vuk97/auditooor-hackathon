from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
DETECTOR_PATH = (
    REPO
    / "detectors"
    / "wave17"
    / "integer_clamp_fee_or_supply_companion_fire16.py"
)
FIXTURE_DIR = (
    REPO
    / "detectors"
    / "fixtures"
    / "solidity"
    / "integer_clamp_fee_or_supply_companion_fire16"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "integer-clamp-fee-or-supply-companion-fire16"


def _load_detector():
    module_name = "integer_clamp_fee_or_supply_companion_fire16"
    if module_name in sys.modules:
        return sys.modules[module_name]
    spec = importlib.util.spec_from_file_location(module_name, DETECTOR_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _read_fixture(name: str) -> str:
    return (FIXTURE_DIR / name).read_text(encoding="utf-8")


class IntegerClampFeeOrSupplyCompanionFire16Test(unittest.TestCase):
    def test_fires_on_fee_boundary_and_unchecked_supply_mint(self) -> None:
        detector = _load_detector()
        findings = detector.scan(_read_fixture("vulnerable.sol"), "vulnerable.sol")

        self.assertEqual(len(findings), 3)
        self.assertEqual({finding.detector for finding in findings}, {DETECTOR_NAME})
        self.assertEqual({finding.severity for finding in findings}, {"Medium"})
        self.assertEqual(
            {finding.function for finding in findings},
            {"computeSwapProtocolFee", "buy", "enter"},
        )
        messages = "\n".join(finding.message for finding in findings)
        self.assertIn("all-protocol-fee boundary", messages)
        self.assertIn("unchecked arithmetic", messages)

    def test_skips_explicit_fee_branch_and_checked_muldiv_supply_mint(self) -> None:
        detector = _load_detector()
        findings = detector.scan(_read_fixture("clean.sol"), "clean.sol")

        self.assertEqual(findings, [])

    def test_regex_runner_manifest_records_only_vulnerable_hits(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fire16_integer_clamp_") as tmp:
            manifest = Path(tmp) / "manifest.json"
            env = os.environ.copy()
            env["PYTHONDONTWRITEBYTECODE"] = "1"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(RUNNER),
                    str(FIXTURE_DIR),
                    "--workspace",
                    tmp,
                    "--output",
                    str(manifest),
                    "--detector",
                    DETECTOR_NAME,
                    "--json-only",
                ],
                cwd=REPO,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=30,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout)

            data = json.loads(manifest.read_text(encoding="utf-8"))
            self.assertEqual(data["per_detector_counts"][DETECTOR_NAME], 3)
            self.assertEqual(data["files_scanned"], 2)
            files = {Path(row["file"]).name for row in data["findings"]}
            self.assertEqual(files, {"vulnerable.sol"})


if __name__ == "__main__":
    unittest.main()
