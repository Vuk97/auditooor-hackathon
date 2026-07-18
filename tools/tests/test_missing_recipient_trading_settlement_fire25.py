from __future__ import annotations

import importlib.util
import os
import py_compile
import re
import subprocess
import sys
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
DETECTOR_PATH = (
    REPO / "detectors" / "wave17" / "missing_recipient_trading_settlement_fire25.py"
)
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "missing_recipient_trading_settlement_fire25.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "missing_recipient_trading_settlement_fire25.sol"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "missing-recipient-trading-settlement-fire25"
REAL_SOURCE = Path(
    "/Users/wolf/audits/polymarket/chimera_harnesses/"
    "POLY-CLOB-ORDER-LIFECYCLE/lib/ctf-exchange/src/exchange/mixins/Trading.sol"
)


def _load_detector():
    module_name = "missing_recipient_trading_settlement_fire25"
    if module_name in sys.modules:
        return sys.modules[module_name]
    spec = importlib.util.spec_from_file_location(module_name, DETECTOR_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


class MissingRecipientTradingSettlementFire25Test(unittest.TestCase):
    def test_detector_compiles(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)

    def test_positive_fixture_fires_and_negative_fixture_is_silent(self) -> None:
        detector = _load_detector()

        positive_findings = detector.scan(_read(POSITIVE), str(POSITIVE))
        negative_findings = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(len(positive_findings), 2)
        self.assertEqual(negative_findings, [])
        self.assertEqual(
            {finding.function for finding in positive_findings},
            {"fillSignedOrder", "settleMakerPayout"},
        )
        self.assertEqual({finding.detector for finding in positive_findings}, {DETECTOR_NAME})

        messages = "\n".join(finding.message for finding in positive_findings)
        self.assertIn("signed order digest or proof recipient", messages)
        self.assertIn("routes trading settlement to an unbound recipient", messages)
        self.assertIn("ignores signed recipient and pays `msg.sender`", messages)

    def test_fixture_pair_locks_trading_recipient_binding_semantics(self) -> None:
        positive = _read(POSITIVE)
        negative = _read(NEGATIVE)

        self.assertIn("outcomeToken.safeTransferFrom(order.maker, recipient", positive)
        self.assertIn("collateral.safeTransfer(msg.sender, order.amountOut);", positive)
        self.assertNotIn("recipient != proof.recipient", positive)
        self.assertNotIn("hashOrder(order, recipient)", positive)

        self.assertIn("bytes32 orderHash = hashOrder(order, recipient);", negative)
        self.assertIn("if (recipient != proof.recipient) revert RecipientMismatch();", negative)
        self.assertIn("collateral.safeTransfer(recipient, proof.amount);", negative)

    def test_real_polymarket_fire25_source_anchor_exists(self) -> None:
        self.assertTrue(REAL_SOURCE.exists(), str(REAL_SOURCE))
        source = _read(REAL_SOURCE)
        self.assertIn("function _fillOrder(Order memory order, uint256 fillAmount, address to)", source)
        self.assertIn("_transfer(order.maker, to, makerAssetId, making);", source)

    def test_regex_runner_discovers_detector_for_owned_fixture_pair(self) -> None:
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        for fixture, expected_hits in ((POSITIVE, 2), (NEGATIVE, 0)):
            with self.subTest(fixture=fixture.name):
                proc = subprocess.run(
                    [
                        sys.executable,
                        str(RUNNER),
                        str(fixture),
                        "--detector",
                        DETECTOR_NAME,
                        "--no-manifest",
                    ],
                    cwd=REPO,
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=30,
                )
                self.assertEqual(proc.returncode, 0, proc.stdout)
                match = re.search(r"total hits:\s*(\d+)", proc.stdout)
                self.assertIsNotNone(match, proc.stdout)
                self.assertEqual(int(match.group(1)), expected_hits, proc.stdout)


if __name__ == "__main__":
    unittest.main()
