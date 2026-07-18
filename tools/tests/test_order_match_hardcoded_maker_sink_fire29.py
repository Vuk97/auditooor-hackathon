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
    REPO / "detectors" / "wave17" / "order_match_hardcoded_maker_sink_fire29.py"
)
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "order_match_hardcoded_maker_sink_fire29.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "order_match_hardcoded_maker_sink_fire29.sol"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "order-match-hardcoded-maker-sink-fire29"


def _load_detector():
    module_name = "order_match_hardcoded_maker_sink_fire29"
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


class OrderMatchHardcodedMakerSinkFire29Test(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

    def test_detector_cites_source_refs_and_candidate_posture(self) -> None:
        detector = _load_detector()
        text = _read(DETECTOR_PATH)

        self.assertEqual(detector.DETECTOR_NAME, DETECTOR_NAME)
        self.assertFalse(detector.PROMOTION_ALLOWED)
        self.assertEqual(detector.SUBMISSION_POSTURE, "NOT_SUBMIT_READY")
        for source_ref in (
            "reference/patterns.dsl/missing-recipient-validation-transfer-or-credit.yaml",
            "reference/patterns.dsl/withdraw-claim-recipient-ignored-hardcoded-sink.yaml",
            "reference/patterns.dsl/perp-liquidation-unwrap-native-ignores-cross-chain-recipient.yaml",
        ):
            self.assertIn(source_ref, detector.SOURCE_REFS)
            self.assertIn(source_ref, text)
            self.assertTrue((REPO / source_ref).is_file(), source_ref)

    def test_positive_fixture_fires_and_negative_fixture_is_silent(self) -> None:
        detector = _load_detector()

        findings = detector.scan(_read(POSITIVE), str(POSITIVE))
        clean_findings = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(len(findings), 2)
        self.assertEqual(clean_findings, [])
        self.assertEqual({finding.detector for finding in findings}, {DETECTOR_NAME})
        self.assertEqual(
            {finding.function for finding in findings},
            {"matchOrdersFor", "claimMatchedProceeds"},
        )

        messages = "\n".join(finding.message for finding in findings)
        self.assertIn("recipient evidence `recipient`", messages)
        self.assertIn("takerOrder.maker", messages)
        self.assertIn("recipient evidence `payoutSink`", messages)
        self.assertIn("msg.sender", messages)
        self.assertIn("NOT_SUBMIT_READY", messages)

    def test_fixture_pair_locks_false_positive_boundaries(self) -> None:
        positive = _read(POSITIVE)
        negative = _read(NEGATIVE)

        self.assertIn("address recipient", positive)
        self.assertIn("_transfer(address(this), takerOrder.maker", positive)
        self.assertIn("token.safeTransfer(msg.sender, amount);", positive)
        self.assertIn("_transfer(address(this), recipient", negative)
        self.assertIn("require(msg.sender == takerOrder.maker", negative)
        self.assertIn("token.safeTransfer(payoutSink, amount);", negative)

    def test_intentional_recipient_bound_maker_settlement_is_not_flagged(self) -> None:
        detector = _load_detector()
        source = """
        contract BoundMakerSettlement {
            struct Order {
                address maker;
                uint256 tokenId;
            }

            function matchOrdersFor(Order memory takerOrder, address recipient) public {
                require(recipient == takerOrder.maker, "maker self");
                _fillMakerOrders();
                _transfer(address(this), takerOrder.maker, takerOrder.tokenId, 1);
            }

            function _fillMakerOrders() internal {}
            function _transfer(address, address, uint256, uint256) internal {}
        }
        """
        self.assertEqual(detector.scan(source, "BoundMakerSettlement.sol"), [])

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
