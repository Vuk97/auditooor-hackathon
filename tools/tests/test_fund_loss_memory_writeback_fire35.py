from __future__ import annotations

import importlib.util
import json
import os
import py_compile
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DETECTOR = ROOT / "detectors" / "wave17" / "fund_loss_memory_writeback_fire35.py"
RUNNER = ROOT / "detectors" / "run_regex_detectors.py"
POSITIVE = (
    ROOT
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "fund_loss_memory_writeback_fire35.sol"
)
NEGATIVE = (
    ROOT
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "fund_loss_memory_writeback_fire35.sol"
)
PATTERN = "fund-loss-memory-writeback-fire35"


def _load_detector():
    module_name = "fund_loss_memory_writeback_fire35"
    if module_name in sys.modules:
        return sys.modules[module_name]
    spec = importlib.util.spec_from_file_location(module_name, DETECTOR)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


class FundLossMemoryWritebackFire35Test(unittest.TestCase):
    def test_detector_and_fixtures_are_aligned(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

        detector_text = _read(DETECTOR)
        positive_text = _read(POSITIVE)
        negative_text = _read(NEGATIVE)

        self.assertIn(f'DETECTOR_NAME = "{PATTERN}"', detector_text)
        self.assertIn("SUBMISSION_POSTURE = \"NOT_SUBMIT_READY\"", detector_text)
        self.assertIn("PROMOTION_ALLOWED = False", detector_text)
        self.assertIn("detector_fixture_smoke_only", detector_text)
        self.assertIn("fund-loss-via-arithmetic", detector_text)
        self.assertIn("library-memory-copy-not-writeback.yaml", detector_text)
        self.assertIn("fund-loss-via-arithmetic-value-math.yaml", detector_text)
        self.assertIn("value-bearing sink", detector_text)

        self.assertIn("Position memory position = positions[msg.sender];", positive_text)
        self.assertIn("position.collateral -= amount;", positive_text)
        self.assertIn("DebtBucket memory debt = debts[user];", positive_text)
        self.assertIn("debt.principal -= repayment;", positive_text)
        self.assertIn("uint256[] memory buckets = shareBuckets[msg.sender];", positive_text)
        self.assertIn("buckets[bucket] -= shares;", positive_text)
        self.assertIn("collateralToken.safeTransfer(msg.sender, amount);", positive_text)
        self.assertNotIn("positions[msg.sender] = position;", positive_text)
        self.assertNotIn("shareBuckets[msg.sender] = buckets;", positive_text)

        self.assertIn("positions[msg.sender] = position;", negative_text)
        self.assertIn("Position storage position = positions[msg.sender];", negative_text)
        self.assertIn("debts[user].principal = debt.principal;", negative_text)
        self.assertIn("shareBuckets[msg.sender] = buckets;", negative_text)
        self.assertIn("function memoryCopyNoValueSink", negative_text)

    def test_direct_scan_positive_fires_and_negative_is_silent(self) -> None:
        detector = _load_detector()
        positive_hits = detector.scan(_read(POSITIVE), str(POSITIVE))
        negative_hits = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(negative_hits, [])
        self.assertEqual(len(positive_hits), 4, positive_hits)
        self.assertEqual({hit.detector for hit in positive_hits}, {PATTERN})
        self.assertEqual({hit.severity for hit in positive_hits}, {"Medium"})
        self.assertEqual(
            {hit.function for hit in positive_hits},
            {
                "withdrawCollateral",
                "repayDebt",
                "redeemShares",
                "liquidate",
            },
        )

        messages = "\n".join(hit.message for hit in positive_hits)
        self.assertIn("positions[msg.sender]", messages)
        self.assertIn("debts[user]", messages)
        self.assertIn("shareBuckets[msg.sender]", messages)
        self.assertIn("struct-element:external-value-movement", messages)
        self.assertIn("array-element:external-value-movement", messages)
        self.assertIn("value-bearing accounting sink before an exact storage writeback", messages)
        self.assertIn("NOT_SUBMIT_READY", messages)

    def test_no_generic_memory_copy_warning_without_value_sink(self) -> None:
        detector = _load_detector()
        source = """
        pragma solidity ^0.8.24;
        contract NoSink {
            struct Account { uint256 debt; }
            mapping(address => Account) public accounts;
            function bump(address user, uint256 amount) external {
                Account memory account = accounts[user];
                account.debt += amount;
            }
        }
        """
        self.assertEqual(detector.scan(source, "NoSink.sol"), [])

    def test_writeback_before_transfer_is_silent(self) -> None:
        detector = _load_detector()
        source = """
        pragma solidity ^0.8.24;
        interface Token { function safeTransfer(address to, uint256 amount) external; }
        contract Clean {
            struct Position { uint256 collateral; }
            mapping(address => Position) public positions;
            Token public token;
            function withdraw(uint256 amount) external {
                Position memory position = positions[msg.sender];
                position.collateral -= amount;
                positions[msg.sender] = position;
                token.safeTransfer(msg.sender, amount);
            }
        }
        """
        self.assertEqual(detector.scan(source, "Clean.sol"), [])

    def test_regex_runner_positive_fixture_fires_and_negative_stays_quiet(self) -> None:
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        with tempfile.TemporaryDirectory(prefix="fund_loss_memory_writeback_fire35_") as tmp:
            positive_manifest = Path(tmp) / "positive.json"
            negative_manifest = Path(tmp) / "negative.json"

            positive_proc = subprocess.run(
                [
                    sys.executable,
                    str(RUNNER),
                    str(POSITIVE),
                    "--detector",
                    PATTERN,
                    "--output",
                    str(positive_manifest),
                    "--workspace",
                    tmp,
                    "--json-only",
                ],
                cwd=ROOT,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=60,
            )
            self.assertEqual(positive_proc.returncode, 0, positive_proc.stdout)

            negative_proc = subprocess.run(
                [
                    sys.executable,
                    str(RUNNER),
                    str(NEGATIVE),
                    "--detector",
                    PATTERN,
                    "--output",
                    str(negative_manifest),
                    "--workspace",
                    tmp,
                    "--json-only",
                ],
                cwd=ROOT,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=60,
            )
            self.assertEqual(negative_proc.returncode, 0, negative_proc.stdout)

            positive_data = json.loads(positive_manifest.read_text(encoding="utf-8"))
            negative_data = json.loads(negative_manifest.read_text(encoding="utf-8"))

            self.assertEqual(positive_data["per_detector_counts"][PATTERN], 4)
            self.assertEqual(negative_data["per_detector_counts"][PATTERN], 0)
            self.assertEqual(negative_data["findings"], [])


if __name__ == "__main__":
    unittest.main()
