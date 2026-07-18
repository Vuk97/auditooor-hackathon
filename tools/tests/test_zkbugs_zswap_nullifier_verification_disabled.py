#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DETECTOR = (
    ROOT
    / "detectors"
    / "circom_wave1"
    / "zkbugs_zswap_nullifier_verification_disabled.py"
)
FIXTURES = ROOT / "detectors" / "circom_wave1" / "test_fixtures"


def _load_detector():
    spec = importlib.util.spec_from_file_location(
        "zkbugs_zswap_nullifier_verification_disabled", DETECTOR
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class ZkBugsZSwapNullifierVerificationDisabledTest(unittest.TestCase):
    def test_flags_nullifier_check_gated_by_spend_private_key(self) -> None:
        detector = _load_detector()
        source = (
            FIXTURES / "zkbugs_zswap_nullifier_verification_disabled_positive.circom"
        ).read_text(encoding="utf-8")

        hits = detector.zswap_nullifier_verification_disabled_hits(source)

        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["severity"], "critical")
        self.assertEqual(hits[0]["enabled"], "zAccountUtxoInSpendPrivKey")
        self.assertIn("ForceEqualIfEnabled", hits[0]["snippet"])

    def test_accepts_nullifier_check_forced_enabled(self) -> None:
        detector = _load_detector()
        source = (
            FIXTURES / "zkbugs_zswap_nullifier_verification_disabled_negative.circom"
        ).read_text(encoding="utf-8")

        self.assertEqual(detector.zswap_nullifier_verification_disabled_hits(source), [])

    def test_ignores_non_nullifier_force_equal_gate(self) -> None:
        detector = _load_detector()
        source = """
        template ZSwapFeeGate() {
            signal input fee;
            signal input expectedFee;
            signal input spendPrivKey;
            component feeProver = ForceEqualIfEnabled();
            feeProver.in[0] <== fee;
            feeProver.in[1] <== expectedFee;
            feeProver.enabled <== spendPrivKey;
        }
        """

        self.assertEqual(detector.zswap_nullifier_verification_disabled_hits(source), [])


if __name__ == "__main__":
    unittest.main()
