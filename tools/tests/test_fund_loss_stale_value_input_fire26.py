from __future__ import annotations

import importlib.util
import os
import py_compile
import re
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "detectors" / "run_custom.py"
REGEX_RUNNER = ROOT / "detectors" / "run_regex_detectors.py"
CLASSIFIER_TOOL = ROOT / "tools" / "audit" / "detector-catch-rate-backtest.py"
PATTERN = "fund-loss-stale-value-input-fire26"
DETECTOR = ROOT / "detectors" / "wave17" / "fund_loss_stale_value_input_fire26.py"
POSITIVE = (
    ROOT
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "fund_loss_stale_value_input_fire26.sol"
)
NEGATIVE = (
    ROOT
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "fund_loss_stale_value_input_fire26.sol"
)
SOURCE_VULN = ROOT / "patterns" / "fixtures" / "interest-rate-update-stale-utilization_vuln.sol"
SOURCE_CLEAN = ROOT / "patterns" / "fixtures" / "interest-rate-update-stale-utilization_clean.sol"


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _python_with_slither() -> str | None:
    candidates = [
        os.environ.get("SLITHER_PYTHON"),
        sys.executable,
        "/opt/homebrew/opt/python@3.13/bin/python3.13",
        "/opt/homebrew/bin/python3.13",
        "python3",
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


class FundLossStaleValueInputFire26Test(unittest.TestCase):
    def _hits(self, fixture: Path) -> tuple[int, str]:
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
        self.assertIn(f"=== Running {PATTERN} ===", proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1)), proc.stdout

    def test_detector_metadata_and_source_alignment(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)
        classifier = _load_module(CLASSIFIER_TOOL, "detector_catch_rate_backtest_fire26_dd")

        detector_text = DETECTOR.read_text(encoding="utf-8")
        positive_text = POSITIVE.read_text(encoding="utf-8")
        negative_text = NEGATIVE.read_text(encoding="utf-8")

        self.assertIn(f'DETECTOR_NAME = "{PATTERN}"', detector_text)
        self.assertIn("ARGUMENT = DETECTOR_NAME", detector_text)
        self.assertIn("interest-rate-update-stale-utilization", detector_text)
        self.assertIn("NOT_SUBMIT_READY", detector_text)
        self.assertEqual(classifier.derive_attack_class(PATTERN, None), "fund-loss-via-arithmetic")

        self.assertIn("uint256 u = totalBorrows * 1e18 / (totalSupply + 1);", positive_text)
        self.assertIn("bytes32 settlementHash = blockhash(settlementBlock);", positive_text)
        self.assertIn("accountingValue[msg.sender] += principal * priceBps / 10000;", positive_text)

        self.assertIn("syncTotalBorrow();", negative_text)
        self.assertIn("block.number - settlementBlock <= 255", negative_text)
        self.assertIn("settlementHash != bytes32(0)", negative_text)
        self.assertIn("blockhash(block.number - 1)", negative_text)

    def test_positive_fixture_fires_and_negative_fixture_is_silent(self) -> None:
        positive_hits, positive_output = self._hits(POSITIVE)
        negative_hits, negative_output = self._hits(NEGATIVE)

        self.assertGreaterEqual(positive_hits, 2, positive_output)
        self.assertEqual(negative_hits, 0, negative_output)

    def test_regex_scoreboard_entrypoint_fires_and_stays_silent(self) -> None:
        positive = subprocess.run(
            [
                sys.executable,
                str(REGEX_RUNNER),
                str(POSITIVE),
                "--detector",
                PATTERN,
                "--no-manifest",
            ],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
        self.assertEqual(positive.returncode, 0, positive.stdout)
        self.assertIn("total hits: 2", positive.stdout)

        negative = subprocess.run(
            [
                sys.executable,
                str(REGEX_RUNNER),
                str(NEGATIVE),
                "--detector",
                PATTERN,
                "--no-manifest",
            ],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
        self.assertEqual(negative.returncode, 0, negative.stdout)
        self.assertIn("total hits: 0", negative.stdout)

    def test_source_backed_interest_fixture_replay(self) -> None:
        vulnerable = subprocess.run(
            [
                sys.executable,
                str(REGEX_RUNNER),
                str(SOURCE_VULN),
                "--detector",
                PATTERN,
                "--no-manifest",
            ],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
        self.assertEqual(vulnerable.returncode, 0, vulnerable.stdout)
        self.assertIn("total hits: 1", vulnerable.stdout)

        clean = subprocess.run(
            [
                sys.executable,
                str(REGEX_RUNNER),
                str(SOURCE_CLEAN),
                "--detector",
                PATTERN,
                "--no-manifest",
            ],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
        self.assertEqual(clean.returncode, 0, clean.stdout)
        self.assertIn("total hits: 0", clean.stdout)


if __name__ == "__main__":
    unittest.main()
