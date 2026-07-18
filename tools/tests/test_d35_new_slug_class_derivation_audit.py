from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
BACKTEST = ROOT / "tools" / "audit" / "detector-catch-rate-backtest.py"
CLASS_MAP = ROOT / "reference" / "detector_class_map_complete.yaml"


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


EXPECTED = {
    "go_wave1.go-ante-msg-auth-mixed-msg-privileged-bypass": ("admin-bypass", {"admin-bypass"}),
    "go-ante-msg-auth-mixed-msg-privileged-bypass": ("admin-bypass", {"admin-bypass"}),
    "go_wave1.go-signing-scope-raw-signature-domain-missing": ("signature-replay-cross-domain", {"signature-replay-cross-domain"}),
    "go-signing-scope-raw-signature-domain-missing": ("signature-replay-cross-domain", {"signature-replay-cross-domain"}),
    "go_wave1.go-cosmos-mutation-validation-guard-missing": ("missing-recipient-validation", {"missing-recipient-validation"}),
    "go-cosmos-mutation-validation-guard-missing": ("missing-recipient-validation", {"missing-recipient-validation"}),
    "go_wave1.go-cosmos-signature-replay-scope-missing": ("signature-replay-cross-domain", {"signature-replay-cross-domain"}),
    "go-cosmos-signature-replay-scope-missing": ("signature-replay-cross-domain", {"signature-replay-cross-domain"}),
    "go_wave1.go-cosmos-privileged-bypass-requires-all-msgs": ("admin-bypass", {"admin-bypass"}),
    "go-cosmos-privileged-bypass-requires-all-msgs": ("admin-bypass", {"admin-bypass"}),
    "rust_wave1.rust-consensus-state-root-commitment-divergence": (
        "apphash-divergence",
        {"apphash-divergence", "root-hash-mismatch", "state-tree-corruption"},
    ),
    "rust-consensus-state-root-commitment-divergence": (
        "apphash-divergence",
        {"apphash-divergence", "root-hash-mismatch", "state-tree-corruption"},
    ),
    "rust_wave1.critical_math_stale_snapshot_or_scale_mismatch": ("fund-loss-via-arithmetic", {"fund-loss-via-arithmetic"}),
    "critical_math_stale_snapshot_or_scale_mismatch": ("fund-loss-via-arithmetic", {"fund-loss-via-arithmetic"}),
    "rust_wave1.ineffective_deadline_or_global_flag_permanent_dos": ("dos-cap-weakening", {"dos-cap-weakening"}),
    "ineffective_deadline_or_global_flag_permanent_dos": ("dos-cap-weakening", {"dos-cap-weakening"}),
    "rust_wave1.callback_external_call_before_accounting_finalized": ("reentrancy-cross-contract", {"reentrancy-cross-contract"}),
    "callback_external_call_before_accounting_finalized": ("reentrancy-cross-contract", {"reentrancy-cross-contract"}),
    "rust_wave1.admin_origin_or_role_guard_missing": ("admin-bypass", {"admin-bypass"}),
    "admin_origin_or_role_guard_missing": ("admin-bypass", {"admin-bypass"}),
    "rust_wave1.rust_rpc_generate_uncapped_loop": ("unbounded-loop-attacker-controlled-count", {"unbounded-loop-attacker-controlled-count"}),
    "rust_rpc_generate_uncapped_loop": ("unbounded-loop-attacker-controlled-count", {"unbounded-loop-attacker-controlled-count"}),
    "rust_wave1.rust_rpc_address_result_uncapped_accumulation": ("unbounded-vec-accumulation-rpc-address-set", {"unbounded-vec-accumulation-rpc-address-set"}),
    "rust_rpc_address_result_uncapped_accumulation": ("unbounded-vec-accumulation-rpc-address-set", {"unbounded-vec-accumulation-rpc-address-set"}),
    "rust_wave1.rust_rpc_height_range_uncapped_span": ("rpc-height-range-uncapped-span", {"rpc-height-range-uncapped-span"}),
    "rust_rpc_height_range_uncapped_span": ("rpc-height-range-uncapped-span", {"rpc-height-range-uncapped-span"}),
    "rust_wave1.rust_rpc_multi_address_no_count_cap": ("rpc-unbounded-address-scan", {"rpc-unbounded-address-scan"}),
    "rust_rpc_multi_address_no_count_cap": ("rpc-unbounded-address-scan", {"rpc-unbounded-address-scan"}),
    "rust_wave1.rust_option_is_some_then_unwrap_panic": ("reachable-panic-option-unwrap", {"reachable-panic-option-unwrap"}),
    "rust_option_is_some_then_unwrap_panic": ("reachable-panic-option-unwrap", {"reachable-panic-option-unwrap"}),
    "rust_wave1.rust_network_codec_unwrap_on_utf8_peer_bytes": ("network-codec-utf8-unwrap-panic", {"network-codec-utf8-unwrap-panic"}),
    "rust_network_codec_unwrap_on_utf8_peer_bytes": ("network-codec-utf8-unwrap-panic", {"network-codec-utf8-unwrap-panic"}),
    "rust_wave1.rust_rpc_handler_expect_on_block_field_parse": ("reachable-panic-rpc-block-field-parse", {"reachable-panic-rpc-block-field-parse"}),
    "rust_rpc_handler_expect_on_block_field_parse": ("reachable-panic-rpc-block-field-parse", {"reachable-panic-rpc-block-field-parse"}),
    "rust_wave1.rust_spawn_blocking_expect_panics_async_task": ("async-panic-propagation-via-join-handle", {"async-panic-propagation-via-join-handle"}),
    "rust_spawn_blocking_expect_panics_async_task": ("async-panic-propagation-via-join-handle", {"async-panic-propagation-via-join-handle"}),
    "rust_wave1.rust_coinbase_maturity_mempool_only_guard": ("consensus-validation-path-asymmetry", {"consensus-validation-path-asymmetry"}),
    "rust_coinbase_maturity_mempool_only_guard": ("consensus-validation-path-asymmetry", {"consensus-validation-path-asymmetry"}),
    "rust_wave1.rust_shielded_coinbase_decryptability_block_only_guard": ("consensus-validation-path-asymmetry", {"consensus-validation-path-asymmetry"}),
    "rust_shielded_coinbase_decryptability_block_only_guard": ("consensus-validation-path-asymmetry", {"consensus-validation-path-asymmetry"}),
    "rust_wave1.rust_mempool_anchor_nullifier_check_absent_block_path": ("consensus-validation-path-asymmetry", {"consensus-validation-path-asymmetry"}),
    "rust_mempool_anchor_nullifier_check_absent_block_path": ("consensus-validation-path-asymmetry", {"consensus-validation-path-asymmetry"}),
    "rust_wave1.rust_tx_version_passthrough_missing_version_specific_check": ("consensus-validation-path-asymmetry", {"consensus-validation-path-asymmetry"}),
    "rust_tx_version_passthrough_missing_version_specific_check": ("consensus-validation-path-asymmetry", {"consensus-validation-path-asymmetry"}),
    "rust_wave1.rust_trusted_preallocate_message_len_divisor": ("amplified-heap-preallocation-dos", {"amplified-heap-preallocation-dos"}),
    "rust_trusted_preallocate_message_len_divisor": ("amplified-heap-preallocation-dos", {"amplified-heap-preallocation-dos"}),
    "rust_wave1.rust_zcash_deserialize_bytes_without_consensus_precheck": ("unguarded-wire-length-allocation", {"unguarded-wire-length-allocation"}),
    "rust_zcash_deserialize_bytes_without_consensus_precheck": ("unguarded-wire-length-allocation", {"unguarded-wire-length-allocation"}),
    "rust_wave1.rust_trusted_preallocate_max_delegation_overcounting": ("trusted-preallocate-max-delegation-overcounting", {"trusted-preallocate-max-delegation-overcounting"}),
    "rust_trusted_preallocate_max_delegation_overcounting": ("trusted-preallocate-max-delegation-overcounting", {"trusted-preallocate-max-delegation-overcounting"}),
    "rust_wave1.rust_height_field_raw_u32_sub_no_checked": ("silent-integer-underflow", {"silent-integer-underflow"}),
    "rust_height_field_raw_u32_sub_no_checked": ("silent-integer-underflow", {"silent-integer-underflow"}),
    "rust_wave1.rust_consensus_heightdiff_i64_to_u32_panicking_expect": ("arithmetic-narrowing-panic", {"arithmetic-narrowing-panic"}),
    "rust_consensus_heightdiff_i64_to_u32_panicking_expect": ("arithmetic-narrowing-panic", {"arithmetic-narrowing-panic"}),
    "rust_wave1.rust_height_field_raw_u32_add_no_bounds_guard": ("integer-overflow-wrap-height", {"integer-overflow-wrap-height"}),
    "rust_height_field_raw_u32_add_no_bounds_guard": ("integer-overflow-wrap-height", {"integer-overflow-wrap-height"}),
    "rust_wave1.rust_std_sync_mutex_direct_in_async_fn": ("sync-blocking-call-in-async-context", {"sync-blocking-call-in-async-context"}),
    "rust_std_sync_mutex_direct_in_async_fn": ("sync-blocking-call-in-async-context", {"sync-blocking-call-in-async-context"}),
    "rust_wave1.rust_std_sync_mutex_blocking_helper_called_from_async": ("sync-blocking-call-in-async-context", {"sync-blocking-call-in-async-context"}),
    "rust_std_sync_mutex_blocking_helper_called_from_async": ("sync-blocking-call-in-async-context", {"sync-blocking-call-in-async-context"}),
    "rust_wave1.rust_std_sync_mutex_in_tokio_spawn_async_block": ("sync-blocking-call-in-async-context", {"sync-blocking-call-in-async-context"}),
    "rust_std_sync_mutex_in_tokio_spawn_async_block": ("sync-blocking-call-in-async-context", {"sync-blocking-call-in-async-context"}),
    "rust_wave1.rust_height_wrapper_field_bare_subtraction": ("unsigned-integer-underflow", {"unsigned-integer-underflow"}),
    "rust_height_wrapper_field_bare_subtraction": ("unsigned-integer-underflow", {"unsigned-integer-underflow"}),
    "rust_wave1.rust_block_depth_toctou_u32_underflow": ("toctou-arithmetic-underflow", {"toctou-arithmetic-underflow"}),
    "rust_block_depth_toctou_u32_underflow": ("toctou-arithmetic-underflow", {"toctou-arithmetic-underflow"}),
    "rust_wave1.rust_consensus_loop_gap_u32_unchecked_sub": ("unsigned-integer-underflow", {"unsigned-integer-underflow"}),
    "rust_consensus_loop_gap_u32_unchecked_sub": ("unsigned-integer-underflow", {"unsigned-integer-underflow"}),
    "rust_wave1.rust_per_actor_cap_keyed_on_composite_addr": ("cross-component-key-asymmetry", {"cross-component-key-asymmetry"}),
    "rust_per_actor_cap_keyed_on_composite_addr": ("cross-component-key-asymmetry", {"cross-component-key-asymmetry"}),
    "w68-cached-swap-pop-set-forward-remove-skip": (
        "missing-last-element-validation",
        {"missing-last-element-validation", "loop-invariant-bypass"},
    ),
    "w68-delegation-reassignment-stale-vote-source": (
        "vote-double-count",
        {"vote-double-count", "delegation-power-inflation"},
    ),
    "w68-vote-double-count-delegation": ("vote-double-count", {"vote-double-count"}),
    "w69-governor-quorum-live-supply-snapshot-mismatch": ("governance-snapshot-mismatch", {"governance-snapshot-mismatch"}),
    "w69-vault-share-mint-division-before-multiplication": ("fund-loss-via-arithmetic", {"fund-loss-via-arithmetic"}),
    "w70-stale-check-value-used-after-hook-callback": (
        "state-change-between-check-and-use",
        {"state-change-between-check-and-use", "callback-hook-exploit"},
    ),
}


class D35NewSlugClassDerivationAuditTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.backtest = _load_module(BACKTEST, "detector_catch_rate_backtest_d35")
        cls.class_map = yaml.safe_load(CLASS_MAP.read_text(encoding="utf-8"))["mappings"]

    def test_current_batch_slugs_are_explicitly_mapped_and_derive_cleanly(self) -> None:
        for slug, (expected_primary, expected_classes) in EXPECTED.items():
            with self.subTest(slug=slug):
                self.assertIn(slug, self.class_map)
                self.assertEqual(
                    self.class_map[slug]["attack_class"],
                    expected_primary,
                )
                self.assertEqual(
                    self.backtest.derive_attack_class(slug, None),
                    expected_primary,
                )
                self.assertEqual(
                    self.backtest.derive_attack_classes(slug, None),
                    expected_classes,
                )


if __name__ == "__main__":
    unittest.main()
