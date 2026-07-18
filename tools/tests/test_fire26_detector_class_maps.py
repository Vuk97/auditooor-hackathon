from __future__ import annotations

import unittest
from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
CLASS_MAP = REPO_ROOT / "reference" / "detector_class_map_complete.yaml"
ROUTE_MAP = REPO_ROOT / "reference" / "detector_to_attack_classes_map.yaml"


EXPECTED_PRIMARY = {
    "bridge-proof-beefyclient-mmr-root-fire26": "bridge-proof-domain-bypass",
    "bridge_proof_beefyclient_mmr_root_fire26": "bridge-proof-domain-bypass",
    "bridge-merkle-leaf-domain-fire26": "bridge-proof-domain-bypass",
    "bridge_merkle_leaf_domain_fire26": "bridge-proof-domain-bypass",
    "fund-loss-safecast-int128-fire26": "fund-loss-via-arithmetic",
    "fund_loss_safecast_int128_fire26": "fund-loss-via-arithmetic",
    "fund-loss-stale-value-input-fire26": "fund-loss-via-arithmetic",
    "fund_loss_stale_value_input_fire26": "fund-loss-via-arithmetic",
    "admin-abi-packed-hash-collision-fire26": "admin-bypass",
    "admin_abi_packed_hash_collision_fire26": "admin-bypass",
    "admin-receiver-source-domain-fire26": "admin-bypass",
    "admin_receiver_source_domain_fire26": "admin-bypass",
    "rewards-branch-idempotency-asymmetry-fire26": "rewards-distribution-skew",
    "rewards_branch_idempotency_asymmetry_fire26": "rewards-distribution-skew",
    "rewards-epoch-advance-before-settle-fire26": "rewards-distribution-skew",
    "rewards_epoch_advance_before_settle_fire26": "rewards-distribution-skew",
    "rust_wave1.rewards_multiplier_reset_fire26": "rewards-distribution-skew",
    "rewards_multiplier_reset_fire26": "rewards-distribution-skew",
    "rust_wave1.rounding_user_input_fire26": "rounding-direction-attack",
    "rounding_user_input_fire26": "rounding-direction-attack",
    "emergency-bypass-market-or-claim-fire26": "emergency-bypass",
    "emergency_bypass_market_or_claim_fire26": "emergency-bypass",
    "initializer-front-run-first-writer-fire26": "initializer-front-run",
    "initializer_front_run_first_writer_fire26": "initializer-front-run",
}


class Fire26DetectorClassMapTests(unittest.TestCase):
    def test_fire26_primary_class_map_rows_are_present(self) -> None:
        payload = yaml.safe_load(CLASS_MAP.read_text(encoding="utf-8"))
        self.assertEqual(payload["schema"], "auditooor.detector_class_map_complete.v1")
        mappings = payload["mappings"]

        for detector, attack_class in EXPECTED_PRIMARY.items():
            with self.subTest(detector=detector):
                row = mappings[detector]
                self.assertEqual(row["attack_class"], attack_class)
                self.assertEqual(row["confidence"], "high")
                self.assertTrue(row["has_fixture_pair"])

    def test_fire26_route_map_rows_include_primary_class(self) -> None:
        payload = yaml.safe_load(ROUTE_MAP.read_text(encoding="utf-8"))
        self.assertEqual(payload["schema"], "auditooor.detector_to_attack_classes_map.v1")
        mappings = payload["mappings"]

        for detector, attack_class in EXPECTED_PRIMARY.items():
            with self.subTest(detector=detector):
                self.assertIn(attack_class, mappings[detector])


if __name__ == "__main__":
    unittest.main()
