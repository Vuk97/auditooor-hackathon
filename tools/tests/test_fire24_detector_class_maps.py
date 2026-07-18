from __future__ import annotations

import unittest
from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
CLASS_MAP = REPO_ROOT / "reference" / "detector_class_map_complete.yaml"
ROUTE_MAP = REPO_ROOT / "reference" / "detector_to_attack_classes_map.yaml"


EXPECTED_PRIMARY = {
    "bridge-proof-domain-snowbridge-fire24": "bridge-proof-domain-bypass",
    "bridge_proof_domain_snowbridge_fire24": "bridge-proof-domain-bypass",
    "bridge-proof-route-consume-fire24": "bridge-proof-domain-bypass",
    "bridge_proof_route_consume_fire24": "bridge-proof-domain-bypass",
    "fund-loss-arithmetic-cast-fire24": "fund-loss-via-arithmetic",
    "fund_loss_arithmetic_cast_fire24": "fund-loss-via-arithmetic",
    "missing-recipient-settlement-binding-fire24": "missing-recipient-validation",
    "missing_recipient_settlement_binding_fire24": "missing-recipient-validation",
    "admin-bypass-auth-domain-fire24": "admin-bypass",
    "admin_bypass_auth_domain_fire24": "admin-bypass",
    "integer-overflow-vote-clamp-fire24": "integer-overflow-clamp",
    "integer_overflow_vote_clamp_fire24": "integer-overflow-clamp",
    "integer-overflow-fee-underflow-fire24": "integer-overflow-clamp",
    "integer_overflow_fee_underflow_fire24": "integer-overflow-clamp",
    "rewards-branch-asymmetry-fire24": "rewards-distribution-skew",
    "rewards_branch_asymmetry_fire24": "rewards-distribution-skew",
    "rounding-direction-fee-loss-fire24": "rounding-direction-attack",
    "rounding_direction_fee_loss_fire24": "rounding-direction-attack",
    "rust_wave1.rewards_distribution_skew_checkpoint_fire24": "rewards-distribution-skew",
    "rewards_distribution_skew_checkpoint_fire24": "rewards-distribution-skew",
    "rust_wave1.rounding_direction_div_before_mul_fire24": "rounding-direction-attack",
    "rounding_direction_div_before_mul_fire24": "rounding-direction-attack",
}


class Fire24DetectorClassMapTests(unittest.TestCase):
    def test_fire24_primary_class_map_rows_are_present(self) -> None:
        payload = yaml.safe_load(CLASS_MAP.read_text(encoding="utf-8"))
        self.assertEqual(payload["schema"], "auditooor.detector_class_map_complete.v1")
        mappings = payload["mappings"]

        for detector, attack_class in EXPECTED_PRIMARY.items():
            with self.subTest(detector=detector):
                row = mappings[detector]
                self.assertEqual(row["attack_class"], attack_class)
                self.assertEqual(row["confidence"], "high")
                self.assertTrue(row["has_fixture_pair"])

    def test_fire24_route_map_rows_include_primary_class(self) -> None:
        payload = yaml.safe_load(ROUTE_MAP.read_text(encoding="utf-8"))
        self.assertEqual(payload["schema"], "auditooor.detector_to_attack_classes_map.v1")
        mappings = payload["mappings"]

        for detector, attack_class in EXPECTED_PRIMARY.items():
            with self.subTest(detector=detector):
                self.assertIn(attack_class, mappings[detector])


if __name__ == "__main__":
    unittest.main()
