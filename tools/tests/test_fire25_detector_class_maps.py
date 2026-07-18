from __future__ import annotations

import unittest
from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
CLASS_MAP = REPO_ROOT / "reference" / "detector_class_map_complete.yaml"
ROUTE_MAP = REPO_ROOT / "reference" / "detector_to_attack_classes_map.yaml"


EXPECTED_PRIMARY = {
    "bridge-proof-snowbridge-adapter-fire25": "bridge-proof-domain-bypass",
    "bridge_proof_snowbridge_adapter_fire25": "bridge-proof-domain-bypass",
    "bridge-permissionless-route-setter-fire25": "bridge-proof-domain-bypass",
    "bridge_permissionless_route_setter_fire25": "bridge-proof-domain-bypass",
    "bridge-proof-consume-once-fire25": "bridge-proof-domain-bypass",
    "bridge_proof_consume_once_fire25": "bridge-proof-domain-bypass",
    "rewards-period-cache-skew-fire25": "rewards-distribution-skew",
    "rewards_period_cache_skew_fire25": "rewards-distribution-skew",
    "rewards-failed-dispatch-payment-fire25": "rewards-distribution-skew",
    "rewards_failed_dispatch_payment_fire25": "rewards-distribution-skew",
    "admin-hash-domain-missing-fire25": "admin-bypass",
    "admin_hash_domain_missing_fire25": "admin-bypass",
    "admin-receiver-chain-unvalidated-fire25": "admin-bypass",
    "admin_receiver_chain_unvalidated_fire25": "admin-bypass",
    "missing-recipient-trading-settlement-fire25": "missing-recipient-validation",
    "missing_recipient_trading_settlement_fire25": "missing-recipient-validation",
    "rounding-flashloan-fee-zero-fire25": "rounding-direction-attack",
    "rounding_flashloan_fee_zero_fire25": "rounding-direction-attack",
    "rust_wave1.signature_hash_domain_scope_fire25": "signature-hash-domain-scope-gap",
    "signature_hash_domain_scope_fire25": "signature-hash-domain-scope-gap",
    "rust_wave1.fee_redirect_claim_state_fire25": "fee-redirect",
    "fee_redirect_claim_state_fire25": "fee-redirect",
}


class Fire25DetectorClassMapTests(unittest.TestCase):
    def test_fire25_primary_class_map_rows_are_present(self) -> None:
        payload = yaml.safe_load(CLASS_MAP.read_text(encoding="utf-8"))
        self.assertEqual(payload["schema"], "auditooor.detector_class_map_complete.v1")
        mappings = payload["mappings"]

        for detector, attack_class in EXPECTED_PRIMARY.items():
            with self.subTest(detector=detector):
                row = mappings[detector]
                self.assertEqual(row["attack_class"], attack_class)
                self.assertEqual(row["confidence"], "high")
                self.assertTrue(row["has_fixture_pair"])

    def test_fire25_route_map_rows_include_primary_class(self) -> None:
        payload = yaml.safe_load(ROUTE_MAP.read_text(encoding="utf-8"))
        self.assertEqual(payload["schema"], "auditooor.detector_to_attack_classes_map.v1")
        mappings = payload["mappings"]

        for detector, attack_class in EXPECTED_PRIMARY.items():
            with self.subTest(detector=detector):
                self.assertIn(attack_class, mappings[detector])


if __name__ == "__main__":
    unittest.main()
