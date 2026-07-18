"""Registry coverage for wave17 Slither detectors added after YAML compilation.

These detectors are generated from ``reference/patterns.dsl`` into
``detectors/wave17``. If they are absent from ``detectors/_tier_registry.yaml``,
``detectors/run_custom.py`` treats them as Tier-D and skips them in the default
Solidity deep-engine profile. The test keeps the FIND path honest: compiled
and smoke-verified detectors must be default-loadable, not just present on disk.
"""

from __future__ import annotations

import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
REGISTRY_PATH = REPO / "detectors" / "_tier_registry.yaml"


TARGET_DETECTORS = [
    {
        "name": "permit-call-no-trycatch-frontrun-grief",
        "path": "detectors/wave17/permit_call_no_trycatch_frontrun_grief.py",
        "vuln_hits": 1,
    },
    {
        "name": "round-to-zero-dust-bypass-no-guard",
        "path": "detectors/wave17/round_to_zero_dust_bypass_no_guard.py",
        "vuln_hits": 3,
    },
    {
        "name": "external-call-before-state-finalization-reentrancy",
        "path": "detectors/wave17/external_call_before_state_finalization_reentrancy.py",
        "vuln_hits": 3,
    },
    {
        "name": "cached-accounting-read-without-refresh",
        "path": "detectors/wave17/cached_accounting_read_without_refresh.py",
        "vuln_hits": 1,
    },
    {
        "name": "fee-ledger-sink-mismatch",
        "path": "detectors/wave17/fee_ledger_sink_mismatch.py",
        "vuln_hits": 2,
    },
    {
        "name": "freeze-control-unguarded-state-flip",
        "path": "detectors/wave17/freeze_control_unguarded_state_flip.py",
        "vuln_hits": 2,
    },
    {
        "name": "fund-loss-via-arithmetic-conversion-output-zero",
        "path": "detectors/wave17/fund_loss_via_arithmetic_conversion_output_zero.py",
        "vuln_hits": 4,
    },
    {
        "name": "admin-bypass-umbrella",
        "path": "detectors/wave17/admin_bypass_umbrella.py",
        "vuln_hits": 11,
    },
    {
        "name": "r74-abi-quorum-lost-after-manual-value-set",
        "path": "detectors/wave17/r74_abi_quorum_lost_after_manual_value_set.py",
        "vuln_hits": 3,
    },
    {
        "name": "optimistic-proposal-consumed-before-window",
        "path": "detectors/wave17/optimistic_proposal_consumed_before_window.py",
        "vuln_hits": 1,
    },
    {
        "name": "restricted-token-action-missing-registry-check",
        "path": "detectors/wave17/restricted_token_action_missing_registry_check.py",
        "vuln_hits": 2,
    },
    {
        "name": "selector-target-binding-missing-authority",
        "path": "detectors/wave17/selector_target_binding_missing_authority.py",
        "vuln_hits": 3,
    },
    {
        "name": "signed-approval-consumption-missing",
        "path": "detectors/wave17/signed_approval_consumption_missing.py",
        "vuln_hits": 1,
    },
    {
        "name": "quorum-threshold-setter-missing-live-bounds",
        "path": "detectors/wave17/quorum_threshold_setter_missing_live_bounds.py",
        "vuln_hits": 1,
    },
    {
        "name": "swap-pop-set-forward-remove-skip",
        "path": "detectors/wave17/swap_pop_set_forward_remove_skip.py",
        "vuln_hits": 1,
    },
    {
        "name": "pending-state-external-call-without-terminal-reset",
        "path": "detectors/wave17/pending_state_external_call_without_terminal_reset.py",
        "vuln_hits": 1,
    },
]


def _load_registry() -> dict:
    try:
        import yaml  # type: ignore
    except ImportError:  # pragma: no cover
        raise unittest.SkipTest("PyYAML not installed; cannot validate registry")
    with REGISTRY_PATH.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


class Wave17SlitherDetectorRegistryEntriesTest(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = _load_registry()
        self.tiers = self.registry.get("tiers", {}) or {}

    def test_target_detectors_are_registered_default_loaded_slither(self) -> None:
        for det in TARGET_DETECTORS:
            with self.subTest(detector=det["name"]):
                entry = self.tiers.get(det["name"], {})
                self.assertTrue(entry, f"{det['name']}: missing registry entry")
                self.assertEqual(entry.get("engine"), "slither")
                self.assertEqual(entry.get("argument"), det["name"])
                self.assertIn(entry.get("tier"), {"S", "E", "A"})
                self.assertEqual(entry.get("smoke_test_clean_hits"), 0)
                self.assertEqual(entry.get("smoke_test_vuln_hits"), det["vuln_hits"])
                detector_path = REPO / det["path"]
                self.assertTrue(detector_path.is_file(), f"missing {detector_path}")


if __name__ == "__main__":
    unittest.main()
