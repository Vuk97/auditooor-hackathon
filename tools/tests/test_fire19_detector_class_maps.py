from __future__ import annotations

import unittest
from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
CLASS_MAP = REPO_ROOT / "reference" / "detector_class_map_complete.yaml"
ROUTE_MAP = REPO_ROOT / "reference" / "detector_to_attack_classes_map.yaml"


EXPECTED_PRIMARY = {
    "rust_wave1.restaking_reward_queue_or_operator_skew_fire19": "rewards-distribution-skew",
    "restaking_reward_queue_or_operator_skew_fire19": "rewards-distribution-skew",
    "rust_wave1.bridge_domain_or_share_unlock_bypass_fire19": "bridge-proof-domain-bypass",
    "bridge_domain_or_share_unlock_bypass_fire19": "bridge-proof-domain-bypass",
    "rust_wave1.div_before_mul_or_unchecked_value_math_fire19": "rounding-direction-attack",
    "div_before_mul_or_unchecked_value_math_fire19": "rounding-direction-attack",
    "rust_wave1.state_asymmetry_or_reserve_snapshot_value_loss_fire19": "fund-loss-via-arithmetic",
    "state_asymmetry_or_reserve_snapshot_value_loss_fire19": "fund-loss-via-arithmetic",
    "rust_wave1.callback_balance_diff_or_cross_pool_reentrancy_fire19": "reentrancy-cross-contract",
    "callback_balance_diff_or_cross_pool_reentrancy_fire19": "reentrancy-cross-contract",
    "rust_wave1.first_deposit_share_inflation_fire19": "first-depositor-inflation",
    "first_deposit_share_inflation_fire19": "first-depositor-inflation",
    "go_wave1.go-bridge-domain-or-recipient-binding-fire19": "bridge-proof-domain-bypass",
    "go-bridge-domain-or-recipient-binding-fire19": "bridge-proof-domain-bypass",
    "bridge-batch-partial-state-or-domain-omission-fire19": "bridge-proof-domain-bypass",
    "bridge_batch_partial_state_or_domain_omission_fire19": "bridge-proof-domain-bypass",
    "fund-loss-arithmetic-fee-or-registration-fire19": "fund-loss-via-arithmetic",
    "fund_loss_arithmetic_fee_or_registration_fire19": "fund-loss-via-arithmetic",
    "reward-skew-branch-or-failed-dispatch-fire19": "rewards-distribution-skew",
    "reward_skew_branch_or_failed_dispatch_fire19": "rewards-distribution-skew",
}


class Fire19DetectorClassMapTests(unittest.TestCase):
    def test_fire19_primary_class_map_rows_are_present(self) -> None:
        payload = yaml.safe_load(CLASS_MAP.read_text(encoding="utf-8"))
        self.assertEqual(payload["schema"], "auditooor.detector_class_map_complete.v1")
        mappings = payload["mappings"]

        for detector, attack_class in EXPECTED_PRIMARY.items():
            with self.subTest(detector=detector):
                row = mappings[detector]
                self.assertEqual(row["attack_class"], attack_class)
                self.assertEqual(row["confidence"], "high")
                self.assertTrue(row["has_fixture_pair"])

    def test_fire19_route_map_rows_include_primary_class(self) -> None:
        payload = yaml.safe_load(ROUTE_MAP.read_text(encoding="utf-8"))
        self.assertEqual(payload["schema"], "auditooor.detector_to_attack_classes_map.v1")
        mappings = payload["mappings"]

        for detector, attack_class in EXPECTED_PRIMARY.items():
            with self.subTest(detector=detector):
                self.assertIn(attack_class, mappings[detector])


if __name__ == "__main__":
    unittest.main()
