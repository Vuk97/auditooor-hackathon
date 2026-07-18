from __future__ import annotations

import importlib.util
import json
import py_compile
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DETECTOR = ROOT / "detectors" / "wave17" / "fund_loss_arithmetic_scale_order_fire32.py"
RUNNER = ROOT / "detectors" / "run_regex_detectors.py"
POSITIVE = (
    ROOT
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "fund_loss_arithmetic_scale_order_fire32.sol"
)
NEGATIVE = (
    ROOT
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "fund_loss_arithmetic_scale_order_fire32.sol"
)
PATTERN = "fund-loss-arithmetic-scale-order-fire32"


def _load_detector():
    module_name = "fund_loss_arithmetic_scale_order_fire32"
    if module_name in sys.modules:
        return sys.modules[module_name]
    spec = importlib.util.spec_from_file_location(module_name, DETECTOR)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


class FundLossArithmeticScaleOrderFire32Test(unittest.TestCase):
    def test_detector_compiles_and_declares_provenance(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)
        detector_text = DETECTOR.read_text(encoding="utf-8")

        self.assertIn(f'DETECTOR_NAME = "{PATTERN}"', detector_text)
        self.assertIn('SUBMISSION_POSTURE = "NOT_SUBMIT_READY"', detector_text)
        self.assertIn("fund-loss-via-arithmetic", detector_text)
        self.assertIn("post_priorities_all.md", detector_text)
        self.assertIn("value_math_transfer_rounding_fire31.py", detector_text)
        self.assertIn("fund-loss-value-math-external-transfer-fire10.yaml", detector_text)
        self.assertIn("bad-debt-rounding-can-be-exploited-to-pay.yaml", detector_text)
        self.assertIn("division-before-multiplication-value-math", detector_text)
        self.assertIn("scale-dropped-after-accounting-debit", detector_text)
        self.assertIn("stale-ratio-value-math", detector_text)

    def test_fixture_text_covers_positive_and_negative_boundaries(self) -> None:
        positive = POSITIVE.read_text(encoding="utf-8")
        negative = NEGATIVE.read_text(encoding="utf-8")

        self.assertIn("uint256 assetsOut = shareAmount / totalShares * totalAssets;", positive)
        self.assertIn("uint256 payoutAmount = creditScaled / WAD;", positive)
        self.assertIn("uint256 ratio = lastExchangeRate;", positive)
        self.assertIn("uint256 debtCredit = collateralAmount * ratio / WAD;", positive)
        self.assertIn("uint256 assetsOut = shareAmount * storedWithdrawRatio / WAD;", positive)
        self.assertIn("asset.transfer(msg.sender, assetsOut);", positive)
        self.assertIn("debtPrincipal[msg.sender] -= debtCredit;", positive)

        self.assertIn("uint256 assetsOut = MathLike.mulDiv(shareAmount, totalAssets, totalShares);", negative)
        self.assertIn('require(assetsOut >= minAssetsOut, "min assets");', negative)
        self.assertIn("uint256 payoutAmount = MathLike.ceilDiv(creditScaled, WAD);", negative)
        self.assertIn('require(payoutAmount > 0, "zero payout");', negative)
        self.assertIn("uint256 freshRatio = accrueDebtIndex();", negative)
        self.assertIn("function previewUnsafeFormula", negative)

    def test_direct_scan_positive_fires_and_negative_is_silent(self) -> None:
        detector = _load_detector()
        positive_hits = detector.scan(POSITIVE.read_text(encoding="utf-8"), str(POSITIVE))
        negative_hits = detector.scan(NEGATIVE.read_text(encoding="utf-8"), str(NEGATIVE))

        self.assertEqual(len(negative_hits), 0)
        self.assertGreaterEqual(len(positive_hits), 4)
        self.assertEqual({hit.detector for hit in positive_hits}, {PATTERN})
        self.assertEqual({hit.severity for hit in positive_hits}, {"Medium"})

        messages = "\n".join(hit.message for hit in positive_hits)
        self.assertIn("withdrawDivBeforeMul", messages)
        self.assertIn("claimDropsScaleAfterClearingCredit", messages)
        self.assertIn("repayWithStaleDebtIndex", messages)
        self.assertIn("withdrawWithStoredRatio", messages)
        self.assertIn("assetsOut", messages)
        self.assertIn("payoutAmount", messages)
        self.assertIn("debtCredit", messages)
        self.assertIn("NOT_SUBMIT_READY", messages)

        branches = {hit.branch for hit in positive_hits}
        self.assertIn("division-before-multiplication-value-math:external-token-movement", branches)
        self.assertIn("scale-dropped-after-accounting-debit:external-token-movement", branches)
        self.assertIn("stale-ratio-value-math:debt-collateral-or-vault-write", branches)
        self.assertIn("stale-ratio-value-math:external-token-movement", branches)

    def test_regex_runner_positive_fixture_fires_and_negative_stays_quiet(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fund_loss_arithmetic_scale_order_fire32_") as tmp:
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
                    str(ROOT),
                    "--json-only",
                ],
                cwd=ROOT,
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
                    str(ROOT),
                    "--json-only",
                ],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=60,
            )
            self.assertEqual(negative_proc.returncode, 0, negative_proc.stdout)

            positive_data = json.loads(positive_manifest.read_text(encoding="utf-8"))
            negative_data = json.loads(negative_manifest.read_text(encoding="utf-8"))

            self.assertGreaterEqual(positive_data["per_detector_counts"][PATTERN], 4)
            self.assertEqual(negative_data["per_detector_counts"][PATTERN], 0)
            self.assertEqual(negative_data["findings"], [])


if __name__ == "__main__":
    unittest.main()
