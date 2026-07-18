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
    REPO / "detectors" / "wave17" / "missing_recipient_settlement_binding_fire24.py"
)
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "missing_recipient_settlement_binding_fire24.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "missing_recipient_settlement_binding_fire24.sol"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "missing-recipient-settlement-binding-fire24"


def _load_detector():
    module_name = "missing_recipient_settlement_binding_fire24"
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


class MissingRecipientSettlementBindingFire24Test(unittest.TestCase):
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
            {"settleSignedOrder", "claimPayout"},
        )
        self.assertEqual({finding.detector for finding in positive_findings}, {DETECTOR_NAME})

        messages = "\n".join(finding.message for finding in positive_findings)
        self.assertIn("signed or proof recipient", messages)
        self.assertIn("routes token settlement to a non-recipient sink", messages)
        self.assertIn("does not compare independent recipient fields", messages)

    def test_fixture_pair_locks_recipient_binding_semantics(self) -> None:
        positive = _read(POSITIVE)
        negative = _read(NEGATIVE)

        self.assertIn("address recipient;", positive)
        self.assertIn("token.safeTransfer(order.maker, order.amountOut);", positive)
        self.assertIn("token.safeTransfer(payout.recipient, payout.amount);", positive)
        self.assertNotIn("payout.recipient != proof.recipient", positive)
        self.assertIn("token.safeTransfer(order.recipient, order.amountOut);", negative)
        self.assertIn(
            "if (payout.recipient != proof.recipient) revert RecipientMismatch();",
            negative,
        )

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
