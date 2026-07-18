#!/usr/bin/env bash
# test_detectors.sh - regression-check each rust_wave1 detector against its
# positive/negative fixtures.  Emits pass/fail per assertion and exits 1 on
# any failure.
#
# Usage:
#   ./detectors/rust_wave1/test_fixtures/test_detectors.sh
#   ./detectors/rust_wave1/test_fixtures/test_detectors.sh --detector <name>
#   ./detectors/rust_wave1/test_fixtures/test_detectors.sh --detector=<name>

set -u
set -o pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
TOOLS="$HERE/../../../tools"
TMPLOG="$(mktemp -t rust-detect-test.XXXXXX.log)"
trap 'rm -f "$TMPLOG"' EXIT

DETECTORS=(
    missing_require_auth_on_mutation
    rust-consensus-state-root-commitment-divergence
    rust_fee_settlement_invariant_mismatch
    unwrap_or_zero_on_persistent_storage
    missing_ttl_bump_on_persistent_read
    two_step_admin_missing
    division_before_multiplication
    unchecked_unwrap_in_public_fn
    u256_truncation_to_i128
    abi_mismatch_external_call
    instance_vs_persistent_storage_confusion
    bitmap_64_reserve_off_by_one
    circuit_breaker_staleness_bypass
    cei_violation_external_call_after_state
    missing_slippage_in_swap_call
    callback_mid_state_mutation
    missing_input_validation_zero_address
    paired_function_state_write_asymmetry
    # --- wave1 batch 2 ---
    arbitrary_external_call_with_user_calldata
    delegatecall_to_user_address
    flashloan_no_premium_charged
    fee_charged_to_wrong_party
    rewards_claim_double_settle
    erc4626_inflation_attack
    share_token_reentrancy_callback
    borrow_against_collateral_after_withdraw_revert
    liquidation_replay_via_signed_msg
    frontrun_initialize_takeover
    uninitialized_storage_read
    integer_overflow_unchecked_block
    tx_origin_used_for_auth
    timestamp_dependence_in_lottery_or_random
    price_feed_used_without_freshness_check
    shadowed_state_variable
    dead_code_unreachable_branch
    deprecated_function_call
    gas_limit_exhaustion_via_unbounded_loop
    storage_slot_collision_in_proxy
    # --- wave1 batch 3 ---
    liquidation_close_factor_off_by_one
    liquidation_no_health_factor_post_check
    liquidation_seize_collateral_wrong_user
    liquidation_bad_debt_socialization_skipped
    rewards_accrual_double_count_on_transfer
    rewards_emission_rate_change_retroactive
    rewards_distribution_end_overflow_or_skip
    flashloan_premium_rounded_down
    flashloan_callback_state_mutation_before_repay
    anchor_account_constraint_missing
    anchor_signer_check_missing_on_authority
    anchor_pda_seeds_dont_bind_account
    # --- R94-F: forward-ported Solidity bug classes ---
    r94_signature_missing_deadline_or_expiry
    r94_signature_missing_chainid
    r94_pause_function_no_auth
    r94_governance_execute_no_timelock
    r94_merkle_claim_no_claimed_flag
    r94_admin_self_grant_role
    r94_spot_price_used_as_oracle
    r94_unrestricted_mint
    # --- wave1 loop cycle 1 (MINE from Solodit) ---
    r94_unchecked_approve_return
    # --- wave1 loop cycle 3 (ceiling-raise + 3 new GAP_RUST closers) ---
    r94_loop_division_by_zero_on_user_input
    r94_loop_stale_snapshot_refund
    r94_loop_bridge_token_mint_not_verified
    # --- wave1 loop cycle 4 (close UNCOVERED_BOTH) ---
    r94_loop_queue_intake_permissionless_no_fee
    r94_loop_observer_untrusted_role
    r94_loop_refund_no_supply_decrement
    # --- wave1 loop cycle 5 (close CPI GAP_RUST) ---
    r94_loop_cpi_remaining_accounts_unvalidated
    r94_loop_cpi_sysvar_unvalidated
    # --- wave1 loop cycle 6 (ceiling +5 classes, 3 new detectors) ---
    r94_loop_airdrop_double_claim
    r94_loop_stableswap_precision_overflow
    # --- wave1 loop cycle 8 (ZK close + PROMOTE rounding-theft) ---
    r94_loop_zk_circuit_missing_constraint
    r94_loop_dex_rounding_direction_theft
    # --- wave1 loop cycle 9 (ceiling +5; 2 new detectors) ---
    r94_loop_asymmetric_liquidity_flat_oracle
    r94_loop_fiat_shamir_missing_observe
    # --- wave1 loop cycle 11 (ceiling +6; PDA + oracle-feed-id) ---
    r94_loop_pda_seed_collision
    r94_loop_oracle_feed_id_mismatch
    # --- wave1 loop cycle 12 (wormhole + 2 rust_only PDA/rent gaps) ---
    r94_loop_wormhole_guardian_quorum_bypass
    r94_loop_pda_canonical_bump_missing
    r94_loop_rent_exempt_not_enforced
    # --- wave1 loop cycle 13 (ceiling +6; 2 Rust detectors) ---
    r94_loop_zero_share_first_deposit
    r94_loop_nft_collection_verified_bypass
    # --- wave1 loop cycle 14 (close 3 UNCOVERED_BOTH) ---
    r94_loop_payload_hash_cross_contract_desync
    r94_loop_oracle_confidence_negative_accept
    r94_loop_stake_activation_epoch_mismatch
    # --- wave1 loop cycle 15 (cross-chain classes) ---
    r94_loop_pyth_exponent_mismatch
    r94_loop_layerzero_channel_mismatch
    r94_loop_hyperlane_ism_bypass
    # --- wave1 loop cycle 16 (platform-only rust_only closers) ---
    r94_loop_move_capability_leak
    r94_loop_cosmwasm_reply_handler_missing
    r94_loop_vector_init_length_as_element
    # --- wave1 loop cycle 17 (last 3 rust_only closers) ---
    r94_loop_account_size_miscalc
    r94_loop_cointype_wrap_unvalidated
    r94_loop_beacon_lookahead_ignored
    # --- wave1 loop cycle 18 (Cairo corpus + ceiling +5) ---
    r94_loop_state_mutation_before_check
    r94_loop_namespace_hash_inconsistency
    # --- wave1 loop cycle 19 (close 3 remaining gaps) ---
    r94_loop_perps_liquidation_state_flip
    r94_loop_hierarchy_permission_bypass
    r94_loop_field_modulus_timestamp_overflow
    # --- wave1 loop cycle 20 (Move corpus + 2 new detectors) ---
    r94_loop_reversed_comparison_operator
    r94_loop_bound_check_delta_only
    # --- wave1 loop cycle 21 (close 3 Move UNCOVERED_BOTH) ---
    r94_loop_double_subtraction_accounting
    r94_loop_cross_segment_limiter_netting
    r94_loop_global_vs_per_group_trigger
    # --- wave1 loop cycle 22 (Go/Cosmos corpus + 2 new) ---
    r94_loop_context_queue_not_drained
    r94_loop_stake_exit_slashing_lag
    # --- wave1 loop cycle 23 (close missing-init + storage-root) ---
    r94_loop_missing_init_fallthrough
    r94_loop_storage_root_unassigned
    # --- wave1 loop cycle 24 (close last 3 gaps) ---
    r94_loop_indexer_finalize_dos
    r94_loop_bitcoin_sighash_confusion
    # --- wave1 loop cycle 25 (PROMOTE + HARDEN) ---
    r94_loop_deposit_signer_vs_depositor_mismatch
    # --- wave1 loop cycle 26 (HTLC classes from Hexens) ---
    r94_loop_htlc_zero_hashlock_accepted
    r94_loop_htlc_timelock_delta_unenforced
    # --- wave1 loop cycle 27 (close last 2 HTLC gaps) ---
    r94_loop_htlc_reward_overwrite
    r94_loop_htlc_refund_off_by_one
    # --- wave1 loop cycle 30 (close 3 TOB gaps) ---
    r94_loop_admin_rug_pull_token_removal
    r94_loop_merkle_proof_forgeable
    # --- wave1 loop cycle 31 (close rust_only platform gaps) ---
    r94_loop_ibc_version_negotiation_bypass
    r94_loop_zk_expired_cert_accepted
    # --- wave1 loop cycle 33 (close 4 Vyper gaps) ---
    r94_loop_per_user_baseline_not_initialized
    r94_loop_imbalanced_pool_proportional_deposit
    r94_loop_rebase_race_unstake
    r94_loop_curve_remove_liquidity_zero_min
    # --- wave1 loop cycle 35 (FunC/TON corpus) ---
    r94_loop_burn_notification_sender_unvalidated
    # --- wave1 loop cycle 36 (Circom/ZK corpus) ---
    r94_loop_ecrecover_malleability_no_check
    # --- wave1 loop cycle 38 (close 4 Sway/Fuel gaps) ---
    r94_loop_cross_timestamp_source_drift
    r94_loop_sorted_list_wrong_end_traversal
    r94_loop_cancel_path_state_drift
    r94_loop_update_price_fee_unvalidated
    # --- wave1 loop cycle 42 (close 5 oracle gaps) ---
    r94_loop_chainlink_feed_decimals_hardcoded
    r94_loop_lp_price_via_manipulable_getrate
    r94_loop_oracle_heartbeat_no_fallback
    r94_loop_oracle_version_expired_stale_return
    r94_loop_oracle_readonly_reentrancy
    # --- wave1 loop cycle 44 (close 4 reentrancy gaps) ---
    r94_loop_erc721_safe_transfer_reentrancy
    r94_loop_erc777_hook_reentrancy
    r94_loop_liquidation_reentrancy_takeover
    r94_loop_post_exec_check_reentrancy_bypass
    # --- wave1 loop cycle 46 (close 4 flash-loan gaps) ---
    r94_loop_flashloan_delegated_vote_bypass
    r94_loop_pmm_internal_price_manipulation
    r94_loop_il_compensation_reserve_snapshot
    r94_loop_checkpoint_same_block_ambiguity
    # --- wave1 loop cycle 47 (close 3 wrong-math gaps) ---
    r94_loop_reward_cliff_boundary_wrong_supply
    r94_loop_tax_refund_post_fee_amount
    r94_loop_draw_reward_wrong_denominator
    # --- wave1 loop cycle 48 (close 3 remaining wrong-math gaps) ---
    r94_loop_reward_cached_vs_current_index_drift
    r94_loop_allowance_spend_cross_function_leak
    r94_loop_withdraw_contribution_wrong_divisor
    # --- wave1 loop cycle 49 (close 3 access-control gaps) ---
    r94_loop_vault_add_reward_accepts_underlying
    r94_loop_withdraw_fee_no_claimed_flag
    r94_loop_dual_admin_modifier_override
    # --- wave1 loop cycle 50 (close 2 remaining access-control gaps) ---
    r94_loop_bridge_generic_call_arbitrary_target
    r94_loop_commitment_caller_not_collateral_owner
    # --- wave1 loop cycle 51 (close 3 governance gaps) ---
    r94_loop_delegation_overwrite_no_auth
    r94_loop_timelock_eth_stranded_no_refund
    r94_loop_governance_proposal_duplicate_action_queue_collision
    # --- wave1 loop cycle 52 (close 3 remaining governance gaps) ---
    r94_loop_veto_selector_check_wrapper_bypass
    r94_loop_vote_checkpoint_same_block_multiple_entries
    r94_loop_quorum_denominator_static_stale_total_power
    # --- wave1 loop cycle 53 (close 3 sig-replay gaps) ---
    r94_loop_erc1271_replay_no_nonce
    r94_loop_merkle_leaf_no_used_flag
    r94_loop_signature_not_bound_to_target_consumer
    # --- wave1 loop cycle 54 (close 3 remaining sig-replay gaps) ---
    r94_loop_compact_sig_variant_allows_replay
    r94_loop_permit_swap_frontrun_zero_min_out
    r94_loop_permit2_intent_binding_missing
    # --- wave1 loop cycle 55 (close 3 erc4626 gaps) ---
    r94_loop_vault_asset_injection_without_share_mint
    r94_loop_erc4626_vault_strategy_decimal_mismatch
    r94_loop_erc4626_first_deposit_mint_vs_deposit_asymmetry
    # --- wave1 loop cycle 56 (close 3 remaining erc4626 gaps) ---
    r94_loop_nested_erc4626_fee_not_accounted
    r94_loop_erc4626_rounding_direction_mixed
    r94_loop_erc4626_asset_diff_vs_preview_fee_drift
    # --- wave1 loop cycle 57 (close 3 bridge gaps) ---
    r94_loop_ccip_receive_source_chain_not_validated
    r94_loop_bridge_receive_message_conditional_auth_missing
    r94_loop_deposit_and_bridge_unlock_bypass
    # --- wave1 loop cycle 58 (close 3 remaining bridge gaps) ---
    r94_loop_bridge_destination_frontrun_after_approve
    r94_loop_bridge_signal_hash_value_not_bound
    r94_loop_bridge_retry_settlement_award_replay
    # --- wave1 loop cycle 59 (close 3 mev/sandwich gaps) ---
    r94_loop_fee_harvest_swap_zero_min_out
    r94_loop_deadline_block_timestamp_passthrough
    r94_loop_lsd_stake_internal_deposit_no_slippage
    # --- wave1 loop cycle 60 (close 3 remaining mev gaps) ---
    r94_loop_self_sandwich_caller_controlled_slippage_bad_debt
    r94_loop_reserve_sell_no_slippage_min_out
    r94_loop_withdraw_amount_request_time_tvl_mev
    # --- wave1 loop cycle 61 (close 3 amm/uniswap gaps) ---
    r94_loop_amm_rebalance_slot0_manipulation
    r94_loop_cached_uniswap_liquidity_stale_collateral
    r94_loop_erc6909_partial_unwrap_fee_theft
    liquidation_stale_cache_or_rounding_profit_trigger
    # --- wave1 loop cycle 62 (close 3 remaining amm gaps) ---
    r94_loop_v3_fee_growth_safemath_underflow_revert
    r94_loop_v3_seconds_per_liquidity_overflow_lock
    r94_loop_lp_shared_tick_range_accounting_theft
    # --- wave1 loop cycle 63 (close 3 liquidation gaps) ---
    r94_loop_post_liquidation_borrow_no_health_check
    r94_loop_liquidation_rounding_up_collateral_down_debt
    r94_loop_liquidation_ema_lag_seizes_solvent_borrower
    # --- wave1 loop cycle 64 (close 3 remaining liquidation gaps) ---
    r94_loop_liquidation_bonus_strict_reverts_when_underfunded
    r94_loop_max_liquidable_calc_inconsistent_scaling
    r94_loop_health_vs_slashable_collateral_discrepancy
    # --- wave1 loop cycle 65 (close 3 tokenomics/FoT gaps) ---
    r94_loop_erc20_transfer_return_unchecked
    r94_loop_mint_based_on_pre_transfer_input_amount_fot
    r94_loop_fee_config_intermediate_overflow_vault_drain
    # --- wave1 loop cycle 66 (close 3 remaining tokenomics gaps) ---
    r94_loop_ledger_delta_unmeasured_fot_drift
    r94_loop_erc1155_amount_hardcoded_not_order_amount
    r94_loop_token_transfer_orphans_accrued_rewards
    # --- wave1 loop cycle 67 (close 3 perps gaps) ---
    r94_loop_perp_open_price_rounds_down_drift
    r94_loop_liquidation_ltv_ignores_accrued_interest
    r94_loop_nav_uses_spot_not_perp_mark
    # --- wave1 loop cycle 68 (close 3 remaining perps gaps) ---
    r94_loop_funding_rate_maker_only_skew_applied_whole_market
    r94_loop_perp_value_uses_underlying_not_perp_price
    r94_loop_perp_post_liquidation_market_state_not_reset
    # --- wave1 loop cycle 69 (close 3 staking gaps) ---
    r94_loop_unstake_no_balance_deduction_drain
    r94_loop_staking_balance_overwrite_not_add
    r94_loop_boost_mutation_without_settling_rewards
    # --- wave1 loop cycle 70 (close 3 remaining staking gaps) ---
    r94_loop_reward_multiplier_reset_by_griefer
    r94_loop_vrf_redraw_allowed_rig_outcome
    r94_loop_gauge_reward_stake_withdraw_burst_game
    # --- wave1 loop cycle 71 (close 3 proxy/upgrade gaps) ---
    r94_loop_uups_implementation_takeover_destroy
    r94_loop_ownable_non_upgradeable_in_proxy
    r94_loop_initialize_frontrun_ownership_steal
    # --- wave1 loop cycle 72 (close 3 remaining proxy gaps) ---
    r94_loop_proxy_constructor_state_not_initialize
    r94_loop_proxy_admin_wrong_address_blocks_upgrade
    r94_loop_storage_migration_missing_reinitializer
    # --- wave1 loop cycle 73 (close 3 oracle2 gaps) ---
    r94_loop_twap_fallback_to_spot_on_staleness
    r94_loop_amm_getAmountsIn_used_as_oracle
    r94_loop_chainlink_getTokenPrice_lookback_param_ignored
    # --- wave1 loop cycle 74 (close 3 remaining oracle2 gaps) ---
    r94_loop_oracle_no_outlier_filter_single_feed
    r94_loop_price_feed_force_update_simulated_swap
    r94_loop_perp_underlying_px_from_orderbook_last_px
    # --- wave1 loop cycle 75 (close 3 governance2 gaps) ---
    r94_loop_vote_uses_current_balance_not_snapshot
    r94_loop_snapshot_function_never_called
    r94_loop_quorum_quadratic_vote_mismatch
    # --- wave1 loop cycle 76 (close 3 remaining governance2 gaps) ---
    r94_loop_votes_binary_search_duplicate_timestamp
    r94_loop_veto_skipped_single_host_majority
    r94_loop_state_mutation_between_read_and_write_delta
    # --- wave1 loop cycle 77 (close 3 vault2/yield gaps) ---
    r94_loop_vault_donation_locks_ratio_permanent
    r94_loop_liquidate_uses_stored_outdated_liabilities
    r94_loop_vault_allocate_rewards_timing_theft
    # --- wave1 loop cycle 78 (close 3 remaining vault2 gaps) ---
    r94_loop_yt_interest_claim_blocked_by_donation
    r94_loop_yt_external_reward_distribution_formula_wrong
    r94_loop_cross_chain_borrow_no_interest_accrual_on_subsequent
    # --- wave1 loop cycle 79 (close 3 nft-marketplace gaps) ---
    r94_loop_nft_multiple_auctions_same_token_escrow_lock
    r94_loop_nft_royalty_receiver_external_call_reentrancy
    r94_loop_auction_stage_skip_via_hook_return_false
    # --- wave1 loop cycle 80 (close 3 remaining nft gaps) ---
    r94_loop_dutch_auction_phantom_bid_escrow_lock
    r94_loop_liquidation_seaport_pair_wrong_collateral
    r94_loop_erc1155_escrow_check_dos_all_listings
    # --- wave1 loop cycle 81 (close 3 crypto gaps) ---
    r94_loop_ecrecover_null_address_not_rejected
    r94_loop_multisig_accepts_duplicate_signer
    r94_loop_eip712_domain_separator_immutable_forks_unsafe
    # --- wave1 loop cycle 82 (close 3 remaining crypto gaps) ---
    r94_loop_ecrecover_high_s_value_not_rejected
    r94_loop_multisig_threshold_signature_reuse_no_dedup
    r94_loop_eip712_nested_array_incorrect_hashing
    # --- wave1 loop cycle 83 (close 3 callback/error gaps) ---
    r94_loop_callback_error_handler_revert_reason_brick
    r94_loop_unsafe_cast_uint256_to_uint128_no_safecast
    r94_loop_bridge_recipient_non_20_byte_silent_burn
    # --- wave1 loop cycle 84 (close 3 remaining callback/accounting gaps) ---
    r94_loop_revert_reason_faked_length_decode_overread
    r94_loop_callback_63_64_gas_rule_bypass_stuck_withdraw
    r94_loop_debt_erased_via_fee_offset_without_collateral_check
    # --- wave1 loop cycle 85 (close 3 amm2 gaps) ---
    r94_loop_cpmm_pool_n_token_unsupported_broken
    r94_loop_deposit_tick_range_not_validated_against_vault
    r94_loop_swap_amount_specified_not_updated_after_clamp
    # --- wave1 loop cycle 86 (close 3 remaining amm2 gaps) ---
    r94_loop_linear_curve_batch_price_sum_vs_product
    r94_loop_tick_tracking_array_unbounded_brick_mint_burn
    r94_loop_stableswap_slippage_tolerance_wrong_reference_side
    # --- wave1 loop cycle 87 (close 3 reentrancy2/hook gaps) ---
    r94_loop_hook_bypasses_reentrancy_guard_cross_pool
    r94_loop_pending_withdrawal_amount_reset_by_view
    r94_loop_buy_erc777_reentrancy_stale_reserve_price
    # --- wave1 loop cycle 88 (close 3 remaining reentrancy2 gaps) ---
    r94_loop_erc777_balance_diff_reentrancy_spoof_amount
    r94_loop_reward_update_at_end_reentrancy
    r94_loop_clob_order_erc777_reentrancy
    # --- wave1 loop cycle 89 (close 3 sigreplay2/timelock gaps) ---
    r94_loop_meta_tx_nonce_not_bumped_on_revert
    r94_loop_deployer_privileged_access_not_revoked
    r94_loop_timelock_bypassable_governor_direct_call
    # --- wave1 loop cycle 90 (close 3 remaining sigreplay2 gaps) ---
    r94_loop_session_sig_digest_missing_space_nonce
    r94_loop_cosigner_nonce_not_invalidated_on_role_swap
    r94_loop_bridge_execute_calldata_missing_chainid_replay
    # --- wave1 loop cycle 91 (close 3 CLOB/rental/liquidation gaps) ---
    r94_loop_order_cancel_no_owner_check
    r94_loop_rental_stop_no_caller_verification
    r94_loop_self_liquidation_reward_harvest
    # --- wave1 loop cycle 92 (close 3 remaining CLOB gaps) ---
    r94_loop_cancel_order_closed_record_skips_collateral_refund
    r94_loop_exit_short_collateral_not_returned
    r94_loop_nft_burn_stale_owner_mapping
    # --- wave1 loop cycle 93 (zk / Merkle / BLS corpus) ---
    r94_loop_merkle_proof_depth_not_enforced_forgery
    r94_loop_bls_rogue_key_attack_no_pop
    r94_loop_zkvm_timestamp_field_modulus_overflow
    # --- wave1 loop cycle 94 (close 3 remaining zk/crypto UNCOVERED_BOTH) ---
    r94_loop_kzg_weak_fiat_shamir_challenge
    r94_loop_prover_ordering_fetches_extra_chips
    r94_loop_bls_point_doubling_edge_case_forgery
    # --- wave1 loop cycle 95 (account abstraction / 4337 / paymaster corpus) ---
    r94_loop_aa_userop_hash_missing_entrypoint_replay
    r94_loop_ecdsa_recover_zero_address_validation_bypass
    r94_loop_paymaster_refund_excludes_pubdata_gas
    # --- wave1 loop cycle 96 (close 3 remaining AA UNCOVERED_BOTH) ---
    r94_loop_aa_limit_module_bypass_via_executor_entrypoint
    r94_loop_aa_validation_bypass_via_sig_validation_fallback
    r94_loop_aa_resource_lock_validator_missing_scope_bind
    # --- wave1 loop cycle 97 (restaking / EigenLayer / LRT corpus) ---
    r94_loop_restaking_strategy_cap_zero_skips_shares_queue_sync
    r94_loop_restaking_operator_self_undelegate_lrt_rate_manipulation
    r94_loop_restaking_withdraw_dos_erc20_buffer_overflow
    # --- wave1 loop cycle 98 (close 3 remaining restaking UNCOVERED_BOTH) ---
    r94_loop_restaking_node_operator_withdraw_credentials_overwrite
    r94_loop_restaking_operator_heap_removed_id_stale_divzero
    r94_loop_upgrade_moved_storage_uninitialised_post_upgrade
    # --- wave1 loop cycle 99 (Uniswap V4 hook / reward / MEV corpus) ---
    r94_loop_hook_addliquidity_attacker_chosen_poolkey
    r94_loop_hook_native_token_settle_erc20_path
    r94_loop_v4_donate_sandwich_in_single_tx
    # --- wave1 loop cycle 100 MILESTONE (close 3 remaining hook UNCOVERED_BOTH) ---
    r94_loop_jit_penalty_bypass_per_position_salt
    r94_loop_incentivized_erc20_recursive_liquidity_reward_amplification
    r94_loop_reward_hook_duplicate_pool_listed_token_steal
    # --- wave1 loop cycle 101 (LayerZero / cross-chain corpus) ---
    r94_loop_layerzero_toaddress_oversized_payload_dos
    r94_loop_layerzero_remote_transfer_caller_supplied_from_unauth_pull
    r94_loop_layerzero_replay_skips_access_control
    # --- wave1 loop cycle 102 (close 3 remaining LZ UNCOVERED_BOTH) ---
    r94_loop_stargate_mtoft_native_rebalance_sgrecieve_missing
    r94_loop_nonblocking_lzapp_channel_block_via_receive_precheck_revert
    r94_loop_layerzero_payload_save_gas_grief_channel_block
    # --- wave1 loop cycle 103 (governance / voting / quorum corpus) ---
    r94_loop_quorum_denominator_uses_cast_votes_not_total_supply
    r94_loop_ve_total_voting_power_equals_total_supply_inflation
    r94_loop_governance_only_state_fn_exposed_as_public
    # --- wave1 loop cycle 104 (close 3 remaining governance UNCOVERED_BOTH) ---
    r94_loop_quorum_denominator_total_supply_vs_quadratic_sqrt_mismatch
    r94_loop_vote_checkpoint_same_block_overwrite_missing
    r94_loop_quorum_counts_against_abstain_instead_of_for_abstain
    # --- wave1 loop cycle 105 (NFT / ERC721 / royalty corpus) ---
    r94_loop_bridge_nft_burn_missing_owner_check
    r94_loop_royalty_distribution_rounding_dust_siphon
    r94_loop_erc721_recover_uses_transfer_not_safetransfer_locks
    # --- wave1 loop cycle 106 (close 3 remaining NFT UNCOVERED_BOTH) ---
    r94_loop_erc721_mint_transfer_skips_safe_callback
    r94_loop_safe_fallback_handler_setter_missing_address_guard
    r94_loop_onerc721received_reentrancy_collateral_shares_manipulation
    # --- wave1 loop cycle 107 (stablecoin / stableswap / liquidation corpus) ---
    r94_loop_liquidation_partial_settlement_leaves_zombie_debt
    r94_loop_stableswap_missing_rate_multipliers_decimal_normalization
    r94_loop_cpmm_pool_creation_allows_n_gt_2_tokens_broken_math
    stable_swap_pools_don_t_apply_rate_multipliers_for_decimals
    # --- wave1 loop cycle 108 (close 3 remaining stablecoin UNCOVERED_BOTH) ---
    r94_loop_stableswap_disjoint_multihop_breaks_invariant
    r94_loop_cdp_borrow_repay_cycle_rate_inflate_grief
    r94_loop_liquidation_atoken_burn_reserve_illiquidity_dos
    # --- wave1 loop cycle 109 (oracle / TWAP / Chainlink corpus) ---
    r94_loop_chainlink_feed_updatedat_not_checked
    r94_loop_chainlink_negative_price_not_rejected_signed_cast
    r94_loop_curve_lp_virtual_price_read_only_reentrancy_oracle
    # --- wave1 loop cycle 110 (close 3 remaining oracle UNCOVERED_BOTH) ---
    r94_loop_single_dex_spot_reserves_flashloan_manipulable_oracle
    r94_loop_lp_value_sum_of_balances_priced_flashloan_manipulable
    r94_loop_lp_token_claim_redemption_ratio_spot_reserves_manipulable
    # --- wave1 loop cycle 111 (token standards / approvals / FoT rebasing) ---
    r94_loop_usdt_non_standard_return_missing_safetransfer
    r94_loop_token_deposit_no_balance_delta_fot_rebasing_drift
    r94_loop_erc20_no_revert_on_failure_return_value_ignored_shares_mint
    # --- wave1 loop cycle 112 (close 3 remaining token-standard UNCOVERED_BOTH) ---
    r94_loop_erc20_approve_nonzero_to_nonzero_race_condition
    r94_loop_usdt_nonzero_to_nonzero_approve_dos_grief
    r94_loop_vault_share_balance_of_self_rebasing_steal
    # --- wave1 loop cycle 113 (reentrancy / callback-timing corpus) ---
    r94_loop_rewards_update_after_external_transfer_reentrancy_steal
    r94_loop_nft_packet_open_reentrancy_duplicate_card_mint
    r94_loop_deposit_balance_delta_no_reentrancy_guard_erc777_inflate
    # --- wave1 loop cycle 114 (close 3 remaining reentrancy UNCOVERED_BOTH) ---
    r94_loop_balancer_pair_oracle_read_only_reentrancy_no_vault_guard_check
    r94_loop_redeem_burn_before_transfer_erc777_hook_reenter_drain
    r94_loop_transient_eth_balance_relied_on_as_accounting_reentrancy_steal
    # --- wave1 loop cycle 115 (MEV / slippage / sandwich corpus) ---
    r94_loop_dex_swap_amountoutmin_zero_no_slippage
    r94_loop_slippage_memory_var_not_propagated_unlimited
    r94_loop_lp_join_asymmetric_min_ratio_sandwich_overpay
    # --- wave1 loop cycle 116 (close 3 remaining MEV UNCOVERED_BOTH) ---
    r94_loop_reserve_sale_missing_amount_out_min_mev_sandwich
    r94_loop_uniswap_swap_slippage_deadline_not_set
    r94_loop_wsteth_steth_1to1_peg_assumption_overvalue
    # --- wave1 loop cycle 117 (perps / CL / vault NAV, 5-agent parallel) ---
    r94_loop_concentrated_liquidity_deposit_tick_range_not_validated_against_vault
    r94_loop_tick_tracking_array_unbounded_growth_brick_mint_burn
    r94_loop_perp_vault_nav_uses_spot_not_mark_price_divergence
    # --- wave1 loop cycle 118 (close 3 remaining perps UNCOVERED_BOTH, 5-agent parallel) ---
    r94_loop_funding_rate_derived_from_partial_skew_applied_globally
    r94_loop_swap_amount_not_reduced_after_price_clamp_lock_funds
    r94_loop_perp_liquidation_market_totals_updated_after_settle_partial_state
    # --- wave1 loop cycle 119 (sig verification / replay / EIP-712, 5-agent parallel) ---
    r94_loop_sig_verify_message_hash_missing_nonce_replay
    r94_loop_user_supplied_domain_separator_cross_chain_replay
    r94_loop_batch_claim_no_used_flag_params_replay
    # --- wave1 loop cycle 120 (close 3 remaining sig UNCOVERED_BOTH, 5-agent parallel) ---
    r94_loop_chainid_cached_at_deploy_fork_replay
    r94_loop_ecdsa_high_s_malleability_not_rejected
    r94_loop_vulnerable_ecdsa_library_eip2098_malleable_version
    # --- wave1 loop cycle 121 (Kelp rsETH $220M exploit - LayerZero DVN / OFT adapter) ---
    r94_loop_lz_oft_single_dvn_configuration_quorum_bypass
    r94_loop_oft_adapter_lzreceive_no_source_burn_proof
    r94_loop_oft_adapter_release_no_post_release_min_supply_cap
    # --- wave1 loop cycle 122 (close 3 remaining Kelp UNCOVERED_BOTH, 5-agent parallel) ---
    r94_loop_bridge_receive_library_quorum_single_signer_is_sole_gate
    r94_loop_cross_chain_destination_accepts_out_of_sequence_inbound_nonce
    r94_loop_dvn_admin_execute_unilateral_no_multisig_no_timelock
    # --- per-language recall lift batch (Go/Rust/Solidity split) ---
    r94_loop_shared_aggregate_cap_doses_independent_items
    stale_source_or_value_feeds_critical_math
    cross_contract_partial_state_finalization_reentrancy
    critical_math_stale_snapshot_or_scale_mismatch
    ineffective_deadline_or_global_flag_permanent_dos
    callback_external_call_before_accounting_finalized
    admin_origin_or_role_guard_missing
    # --- wave1 loop cycle 123 (Kelp attack-chain deep-mine) ---
    r94_loop_dvn_admin_role_grant_no_timelock_delay
    r94_loop_lz_oapp_configured_executor_advisory_not_enforced
    r94_loop_bridge_pause_only_tokens_not_attestation_layer
    # --- wave1 loop cycle 124 (close 3 remaining Kelp-deep UNCOVERED_BOTH, true parallel) ---
    r94_loop_oft_adapter_inventory_vs_source_supply_divergence_unchecked
    r94_loop_oapp_config_safe_dvn_threshold_not_enforced_on_setconfig
    r94_loop_bridge_destination_adapter_ignores_source_pause_state
    # --- wave1 loop cycle 125 (vesting/grant/claim, 5-agent true-parallel) ---
    r94_loop_vesting_share_instant_pool_balance_pro_rata_steal
    r94_loop_vesting_revoke_freezes_already_vested_unclaimed
    r94_loop_vesting_update_overwrites_unsnapshotted_accrued_vested
    # --- wave1 loop cycle 126 (close 2 remaining vesting UNCOVERED_BOTH, 4-agent true-parallel) ---
    r94_loop_vesting_transfer_releaserate_uses_stale_step_count
    r94_loop_linear_vesting_reserve_missing_concurrent_instant_claim_drain
    # --- phase 48b (forward-port 3 Polymarket-mined classes to Rust) ---
    r94_loop_collateral_sweep_without_pre_post_delta_check
    r94_loop_packed_lane_increment_no_overflow_guard
    r94_loop_no_admin_sweep_for_stuck_erc20
    r94_loop_pause_state_not_propagated_to_sibling_contracts
    # --- zkBugs provider-farmed Bellperson class ---
    zkbugs_bellperson_unconstrained_zero_default
    # --- zkBugs provider-farmed Arkworks classes ---
    r94_loop_arkworks_fixedpoint_cmp_no_prefix_state
    zkbugs_unsound_fixed_point_addition
    # --- KNOWN_LIMITATIONS Rust parity burn-down ---
    r94_loop_constraint_inequality_when_equality
    # --- handover plan item #7: stablecoin family Rust parity (rust gap → 1) ---
    r94_loop_stablecoin_mint_no_supply_cap
    # --- R114/R115: r76 stablecoin Rust parity hardwired into full regression ---
    broken_tri_crypto_cpmm_pools_created_without_weight_check
    liquidation_dosed_by_collateral_reserve_illiquidity
    liquidation_leaves_zombie_debt_on_borrower
    rapid_borrow_repay_cycle_inflates_interest_rates
    stableswap_disjoint_swaps_break_invariant
    # --- Zebra 4.5.0 public-advisory recall batch ---
    zebra_anchor_contextual_validation_gap
    zebra_duplicate_nullifier_or_outpoint_scope_gap
    zebra_network_upgrade_height_gate_gap
    zebra_header_context_validation_gap
    zebra_finalized_nonfinalized_fallback_gap
    zebra_signature_hash_domain_scope_gap
    bridge_validator_set_hash_not_domain_separated
    r94_loop_bridge_message_hash_missing_lane_or_chain_domain
    zebra_p2sh_sigop_legacy_mode_gap
)

STATIC_DETECTORS=("${DETECTORS[@]}")
GENERATED_ADDED_DETECTORS=()

contains_detector() {
    local needle="$1"; shift
    local candidate
    for candidate in "$@"; do
        [[ "$candidate" == "$needle" ]] && return 0
    done
    return 1
}

if [[ -f "$TOOLS/rust-fixture-regression-list.py" ]]; then
    GENERATED_DETECTORS=()
    while IFS= read -r det; do
        [[ -n "$det" ]] && GENERATED_DETECTORS+=("$det")
    done < <(python3 "$TOOLS/rust-fixture-regression-list.py" \
        --repo "$HERE/../../.." \
        --report "$HERE/../../../reports/rust_detector_coverage_2026-05-05.json")
    if [[ ${#GENERATED_DETECTORS[@]} -gt 0 ]]; then
        DETECTORS=("${STATIC_DETECTORS[@]}")
        for det in "${GENERATED_DETECTORS[@]}"; do
            if ! contains_detector "$det" "${DETECTORS[@]}"; then
                DETECTORS+=("$det")
                GENERATED_ADDED_DETECTORS+=("$det")
            fi
        done
    fi
fi

PASS=0
FAIL=0
XFAIL=0
FAIL_LINES=()
XFAIL_LINES=()
DET_FILTER=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --detector)
            if [[ $# -lt 2 || -z "${2:-}" ]]; then
                echo "[err] --detector requires a detector name" >&2
                exit 2
            fi
            DET_FILTER="$2"
            shift 2
            ;;
        --detector=*)
            DET_FILTER="${1#--detector=}"
            if [[ -z "$DET_FILTER" ]]; then
                echo "[err] --detector requires a detector name" >&2
                exit 2
            fi
            shift
            ;;
        -h|--help|help)
            sed -n '2,8p' "$0" | sed 's/^# //; s/^#//'
            exit 0
            ;;
        *)
            echo "[err] unknown arg: $1" >&2
            exit 2
            ;;
    esac
done

RUN_DETECTORS=("${DETECTORS[@]}")
if [[ -n "$DET_FILTER" ]]; then
    RUN_DETECTORS=()
    for det in "${DETECTORS[@]}"; do
        if [[ "$det" == "$DET_FILTER" ]]; then
            RUN_DETECTORS=("$det")
            break
        fi
    done
    if [[ ${#RUN_DETECTORS[@]} -eq 0 ]]; then
        echo "[err] unknown detector: $DET_FILTER" >&2
        exit 2
    fi
fi

count_hits() {
    # Count hits for a specific detector in the log (portable: gawk, mawk, BSD awk)
    local det="$1"; local log="$2"
    python3 -c "
import re, sys
pat = re.compile(r'^=== ' + re.escape('$det') + r'\s+\((\d+) hits\)')
for line in open('$log', errors='ignore'):
    m = pat.match(line)
    if m:
        print(m.group(1)); sys.exit(0)
print(0)
"
}

shopt -s nullglob
for det in "${RUN_DETECTORS[@]}"; do
    positive_fixtures=("$HERE/${det}_positive"*.rs)
    if [[ ${#positive_fixtures[@]} -eq 0 ]]; then
        if contains_detector "$det" "${GENERATED_ADDED_DETECTORS[@]}"; then
            echo "  XFAIL $det positive - fixture missing"
            XFAIL=$((XFAIL+1))
            XFAIL_LINES+=("$det positive: fixture missing")
        else
            echo "  MISS $det positive - fixture missing"
            FAIL=$((FAIL+1))
            FAIL_LINES+=("$det positive: fixture missing")
        fi
        continue
    fi

    for positive_fixture in "${positive_fixtures[@]}"; do
        suffix="${positive_fixture#"$HERE/${det}_positive"}"
        negative_fixture="$HERE/${det}_negative${suffix}"
        label_suffix="${suffix%.rs}"
        positive_label="positive${label_suffix}"
        negative_label="negative${label_suffix}"

        python3 "$TOOLS/rust-detect.py" "$HERE" \
            --only "$det" --file "$positive_fixture" \
            --log "$TMPLOG" >/dev/null 2>&1
        hits="$(count_hits "$det" "$TMPLOG")"
        hits="${hits:-0}"
        if (( hits >= 1 )); then
            echo "  PASS  $det $positive_label  ($hits hits)"
            PASS=$((PASS+1))
        else
            if contains_detector "$det" "${GENERATED_ADDED_DETECTORS[@]}"; then
                echo "  XFAIL $det $positive_label  (expected >=1, got 0)"
                XFAIL=$((XFAIL+1))
                XFAIL_LINES+=("$det $positive_label: expected >=1 hit, got 0")
            else
                echo "  FAIL  $det $positive_label  (expected >=1, got 0)"
                FAIL=$((FAIL+1))
                FAIL_LINES+=("$det $positive_label: expected >=1 hit, got 0")
            fi
        fi

        if [[ ! -f "$negative_fixture" ]]; then
            if contains_detector "$det" "${GENERATED_ADDED_DETECTORS[@]}"; then
                echo "  XFAIL $det $negative_label - fixture missing"
                XFAIL=$((XFAIL+1))
                XFAIL_LINES+=("$det $negative_label: fixture missing")
            else
                echo "  MISS $det $negative_label - fixture missing"
                FAIL=$((FAIL+1))
                FAIL_LINES+=("$det $negative_label: fixture missing")
            fi
            continue
        fi

        # Run orchestrator with --only + --file. Workspace arg is ignored
        # when --file is provided, but we still pass one.
        python3 "$TOOLS/rust-detect.py" "$HERE" \
            --only "$det" --file "$negative_fixture" \
            --log "$TMPLOG" >/dev/null 2>&1
        hits="$(count_hits "$det" "$TMPLOG")"
        hits="${hits:-0}"
        if (( hits == 0 )); then
            echo "  PASS  $det $negative_label  (0 hits)"
            PASS=$((PASS+1))
        else
            if contains_detector "$det" "${GENERATED_ADDED_DETECTORS[@]}"; then
                echo "  XFAIL $det $negative_label  (expected 0, got $hits)"
                XFAIL=$((XFAIL+1))
                XFAIL_LINES+=("$det $negative_label: expected 0 hits, got $hits")
            else
                echo "  FAIL  $det $negative_label  (expected 0, got $hits)"
                FAIL=$((FAIL+1))
                FAIL_LINES+=("$det $negative_label: expected 0 hits, got $hits")
            fi
        fi
    done
done

echo ""
echo "========================================="
echo " Rust wave1 regression:  $PASS/$((PASS+FAIL+XFAIL)) passed"
if (( XFAIL > 0 )); then
    echo " Generated fixture residual xfail: $XFAIL"
fi
echo "========================================="
if (( FAIL > 0 )); then
    echo "Failures:"
    for l in "${FAIL_LINES[@]}"; do
        echo "  - $l"
    done
    exit 1
fi
if (( XFAIL > 0 )); then
    echo "Generated residual xfails:"
    for l in "${XFAIL_LINES[@]}"; do
        echo "  - $l"
    done
fi
exit 0
