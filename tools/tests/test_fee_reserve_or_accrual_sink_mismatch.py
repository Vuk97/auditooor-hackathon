from __future__ import annotations

import os
import py_compile
import re
import subprocess
import sys
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "detectors" / "run_custom.py"
PATTERN = "fee-reserve-or-accrual-sink-mismatch"
DETECTOR = ROOT / "detectors" / "wave17" / f"{PATTERN.replace('-', '_')}.py"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "fee_reserve_or_accrual_sink_mismatch"
POSITIVE = FIXTURE_DIR / "positive.sol"
CLEAN = FIXTURE_DIR / "clean.sol"

SOURCE_BACKED_POSITIVES = [
    (ROOT / "patterns" / "fixtures" / "amm-reserves-fee-conflation_vuln.sol", 2),
    (ROOT / "patterns" / "fixtures" / "fee-calculation-accrual-missing_vuln.sol", 2),
    (ROOT / "patterns" / "fixtures" / "fx-euler-protocol-fee-share-unbounded_vuln.sol", 1),
]

SOURCE_BACKED_CONTROLS = [
    ROOT / "patterns" / "fixtures" / "amm-reserves-fee-conflation_clean.sol",
    ROOT / "patterns" / "fixtures" / "fee-calculation-accrual-missing_clean.sol",
    ROOT / "patterns" / "fixtures" / "fx-euler-protocol-fee-share-unbounded_clean.sol",
]


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


class FeeReserveOrAccrualSinkMismatchTest(unittest.TestCase):
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
        self.assertIn(PATTERN, proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1)), proc.stdout

    def test_detector_compiles(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

    def test_dsl_records_source_anchors_and_rejected_synthetic_rows(self) -> None:
        spec = yaml.safe_load(REFERENCE.read_text(encoding="utf-8"))
        self.assertEqual(spec["pattern"], PATTERN)
        self.assertIn("fee-redirect", spec["tags"])
        self.assertEqual(spec["fixtures"]["vuln"], "detectors/fixtures/fee_reserve_or_accrual_sink_mismatch/positive.sol")
        self.assertEqual(spec["fixtures"]["clean"], "detectors/fixtures/fee_reserve_or_accrual_sink_mismatch/clean.sol")

        anchor_slugs = {row["slug"] for row in spec["source_anchors"]}
        self.assertIn("amm-reserves-fee-conflation", anchor_slugs)
        self.assertIn("fee-calculation-accrual-missing", anchor_slugs)
        self.assertIn("fx-euler-protocol-fee-share-unbounded", anchor_slugs)
        self.assertIn("go-fee-redirect-msg-signer-controlled-collector-positive", anchor_slugs)
        self.assertGreaterEqual(len(spec["rejected_inputs"]), 8)

    def test_owned_fixture_pair_models_three_source_backed_families(self) -> None:
        positive = POSITIVE.read_text(encoding="utf-8")
        clean = CLEAN.read_text(encoding="utf-8")

        self.assertIn("amount0 = (liquidity * reserve0) / totalSupply;", positive)
        self.assertIn("feePerSecond = newRate;", positive)
        self.assertIn("return protocolShare;", positive)
        self.assertIn("IERC20Like(token).transfer(protocolReceiver, protocolAmount);", positive)
        self.assertNotIn("realReserve0 = reserve0 - accruedFee;", positive)
        self.assertNotIn("accrueFee();", positive)
        self.assertNotIn("feeReceiver == address(0)", positive)

        self.assertIn("realReserve0 = reserve0 - accruedFee;", clean)
        self.assertIn("accrueFee();", clean)
        self.assertIn("feeReceiver == address(0)", clean)
        self.assertIn("protocolShare > MAX_PROTOCOL_FEE_SHARE", clean)
        self.assertIn("protocolReceiver == address(0)", clean)
        self.assertIn("sweepUserDust", clean)

    def test_owned_positive_fires_and_clean_fixture_is_silent(self) -> None:
        positive_hits, positive_stdout = self._hits(POSITIVE)
        clean_hits, clean_stdout = self._hits(CLEAN)
        self.assertEqual(positive_hits, 6, positive_stdout)
        self.assertEqual(clean_hits, 0, clean_stdout)

    def test_source_backed_examples_fire_and_clean_controls_are_silent(self) -> None:
        for fixture, expected_hits in SOURCE_BACKED_POSITIVES:
            with self.subTest(fixture=fixture.name):
                hits, stdout = self._hits(fixture)
                self.assertEqual(hits, expected_hits, stdout)

        for fixture in SOURCE_BACKED_CONTROLS:
            with self.subTest(fixture=fixture.name):
                hits, stdout = self._hits(fixture)
                self.assertEqual(hits, 0, stdout)


if __name__ == "__main__":
    unittest.main()
