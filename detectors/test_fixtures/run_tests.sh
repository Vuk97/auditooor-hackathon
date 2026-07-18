#!/usr/bin/env bash
# run_tests.sh — regression test suite for auditooor custom Slither detectors
#
# PARALLELISM (Round 21 upgrade): the per-test work is dispatched to
# `xargs -P N` workers. N defaults to the number of CPU cores, overridable
# via JOBS env var. The serial mode is still available via JOBS=1.
#
# Usage:
#     bash run_tests.sh              # auto-detect cores
#     JOBS=16 bash run_tests.sh      # force 16 parallel workers
#     JOBS=1 bash run_tests.sh       # classic serial mode
#
# Exits non-zero if any detector FAIL.
set -uo pipefail

export PATH="$HOME/.foundry/bin:$HOME/.local/bin:$PATH"

FIXTURE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DETECTORS_DIR="$(dirname "$FIXTURE_DIR")"
RUNNER="$DETECTORS_DIR/run_custom.py"

find_python_with_slither() {
    if [ -n "${AUDITOOOR_PYTHON_SLITHER:-}" ] && "$AUDITOOOR_PYTHON_SLITHER" -c 'import slither; import slither.detectors.abstract_detector' >/dev/null 2>&1; then
        printf '%s\n' "$AUDITOOOR_PYTHON_SLITHER"
        return 0
    fi
    local py
    for py in python3 python3.14 python3.13 python3.12 python3.11; do
        if command -v "$py" >/dev/null 2>&1 && "$py" -c 'import slither; import slither.detectors.abstract_detector' >/dev/null 2>&1; then
            command -v "$py"
            return 0
        fi
    done
    return 1
}

PYTHON_SLITHER="$(find_python_with_slither || true)"
if [ -z "$PYTHON_SLITHER" ]; then
    echo "[dependency-preflight] no Python interpreter can import slither-analyzer"
    echo "[dependency-preflight] set AUDITOOOR_PYTHON_SLITHER=/path/to/python or install slither-analyzer"
    exit 2
fi

# Worker count: default 32 (M3-tuned), overridable via JOBS.
# Each test is ~2s forge compile + slither load, CPU+IO bound. 32 saturates
# an M3 Max (16 cores + IO overlap) without thrashing. Raise to 48-64 if
# you have spare headroom and fast storage; drop to 8-16 on older hardware.
JOBS="${JOBS:-32}"

# Staging file — each row is "MODE<TAB>DETECTOR<TAB>FIXTURE<TAB>LABEL"
STAGE="$(mktemp -t run_tests_stage.XXXXXX)"
trap 'rm -f "$STAGE"' EXIT

# Worker output dir — one file per job so we can stitch them back in order
RESULTS_DIR="$(mktemp -d -t run_tests_results.XXXXXX)"
trap 'rm -f "$STAGE"; rm -rf "$RESULTS_DIR"' EXIT

# run_test / run_clean_test now just APPEND a staging row. The actual
# execution happens via xargs -P below after all rows are staged.
run_test() {
    local DETECTOR="$1"
    local FIXTURE="$2"
    local LABEL="$3"
    printf 'vuln\t%s\t%s\t%s\n' "$DETECTOR" "$FIXTURE" "$LABEL" >> "$STAGE"
}

run_clean_test() {
    local DETECTOR="$1"
    local FIXTURE="$2"
    local LABEL="$3"
    printf 'clean\t%s\t%s\t%s\n' "$DETECTOR" "$FIXTURE" "$LABEL" >> "$STAGE"
}

echo "========================================="
echo " auditooor detector regression tests"
echo " parallel workers: $JOBS"
echo "========================================="
echo

echo "--- VULNERABLE fixtures (expect >= 1 hit) ---"
run_test "role-grant-divergence"         "role_grant_divergence_vulnerable.sol"         "role-grant-divergence"
# Wave 2
# Wave 3
# Wave 3 batch 1
# Wave 4
# Wave 4 — signature/replay
# Wave 5
# Wave 6

echo
echo "--- CLEAN fixtures (expect 0 hits — no false positive) ---"
# blockhash-staleness has no clean test: detector is an intentional over-
# approximation (flags ANY blockhash usage). See detectors/_taxonomy.md.
# Wave 2 clean tests
# Wave 3 clean tests
# Wave 4 clean tests
# Wave 4 — signature/replay clean tests
# Wave 5 clean tests
# Wave 6
# Wave 7
# Wave 7 — batch B (slice_ah/ab/ac/ag)
# Wave 8 — batch A
# Wave 8 — batch B
# Wave 8 — batch D
# Wave 8 — batch E
# Wave 8 — batch C
# Wave 9 — batch A
# Wave 9 — batch B
# Wave 9 — batch D
# Wave 9 — batch C
# Wave 9 — batch E
# Wave 9 — batch F
# Wave 9 — batch J
# Wave 9 — batch H
# Wave 9 — batch I
# Wave 9 — batch G
# Wave 10 — SKILL_ISSUE #48 lift
run_test       "absolute-balance-flush-no-delta-check" "absolute_balance_flush_no_delta_check_vulnerable.sol" "absolute-balance-flush-no-delta-check"
run_clean_test "absolute-balance-flush-no-delta-check" "absolute_balance_flush_no_delta_check_clean.sol"      "absolute-balance-flush-no-delta-check (clean)"
# Wave 11 — batch L (slice_ac + slice_ad)

# Wave 11 — batch Q (slice_ac body findings)

# Wave 11 — batch A (slice ag + ah)

# Wave 11 — batch P (slice_ab body findings)

# Wave 11 — batch R (slice_ad body findings not in top-20)

# Wave 11 — batch O (code4arena slice_aa body findings NOT in wave9 top-12)

# Wave 11 — batch M (slice_ae + slice_af novel findings)

# Wave 11 — batch T (Cantina + Quantstamp ctf-exchange-v2 mining)
run_test       "order-tokenid-zero-sentinel-unchecked"      "order_tokenid_zero_sentinel_unchecked_vulnerable.sol"      "order-tokenid-zero-sentinel-unchecked"
run_clean_test "order-tokenid-zero-sentinel-unchecked"      "order_tokenid_zero_sentinel_unchecked_clean.sol"      "order-tokenid-zero-sentinel-unchecked (clean)"

# Wave 10 — batch K (slice_aa + slice_ab Zellic port)

# Wave 11 — batch S (DeFiHackLabs body: Venus vTHE, Predy, Sumer, Balancer V2, yETH + generic rug class)

# R100 — HyperEVM / HyperCore-specific detectors (Monetrix C4 + Zellic V12 mining)
run_test       "hyperevm-spot-total-vs-hold-mismatch"               "hyperevm_spot_total_vs_hold_mismatch_vulnerable.sol"               "hyperevm-spot-total-vs-hold-mismatch"
run_clean_test "hyperevm-spot-total-vs-hold-mismatch"               "hyperevm_spot_total_vs_hold_mismatch_clean.sol"                    "hyperevm-spot-total-vs-hold-mismatch (clean)"
run_test       "hyperevm-precompile-staticcall-no-length-check"     "hyperevm_precompile_staticcall_no_length_check_vulnerable.sol"     "hyperevm-precompile-staticcall-no-length-check"
run_clean_test "hyperevm-precompile-staticcall-no-length-check"     "hyperevm_precompile_staticcall_no_length_check_clean.sol"          "hyperevm-precompile-staticcall-no-length-check (clean)"
run_test       "hyperevm-oracle-px-zero-not-rejected"               "hyperevm_oracle_px_zero_not_rejected_vulnerable.sol"               "hyperevm-oracle-px-zero-not-rejected"
run_clean_test "hyperevm-oracle-px-zero-not-rejected"               "hyperevm_oracle_px_zero_not_rejected_clean.sol"                    "hyperevm-oracle-px-zero-not-rejected (clean)"
run_test       "hyperevm-vault-equity-locked-until-not-checked"     "hyperevm_vault_equity_locked_until_not_checked_vulnerable.sol"     "hyperevm-vault-equity-locked-until-not-checked"
run_clean_test "hyperevm-vault-equity-locked-until-not-checked"     "hyperevm_vault_equity_locked_until_not_checked_clean.sol"          "hyperevm-vault-equity-locked-until-not-checked (clean)"
run_test       "hyperevm-supplied-balance-without-pmenabled-flag"   "hyperevm_supplied_balance_without_pmenabled_flag_vulnerable.sol"   "hyperevm-supplied-balance-without-pmenabled-flag"
run_clean_test "hyperevm-supplied-balance-without-pmenabled-flag"   "hyperevm_supplied_balance_without_pmenabled_flag_clean.sol"        "hyperevm-supplied-balance-without-pmenabled-flag (clean)"
run_test       "hyperevm-usdc-evm-l1-decimals-conversion-missing"   "hyperevm_usdc_evm_l1_decimals_conversion_missing_vulnerable.sol"   "hyperevm-usdc-evm-l1-decimals-conversion-missing"
run_clean_test "hyperevm-usdc-evm-l1-decimals-conversion-missing"   "hyperevm_usdc_evm_l1_decimals_conversion_missing_clean.sol"        "hyperevm-usdc-evm-l1-decimals-conversion-missing (clean)"
run_test       "hyperevm-hardcoded-system-address-no-network-config" "hyperevm_hardcoded_system_address_no_network_config_vulnerable.sol" "hyperevm-hardcoded-system-address-no-network-config"
run_clean_test "hyperevm-hardcoded-system-address-no-network-config" "hyperevm_hardcoded_system_address_no_network_config_clean.sol"     "hyperevm-hardcoded-system-address-no-network-config (clean)"
run_test       "hyperevm-corewriter-action-missing-version-prefix"  "hyperevm_corewriter_action_missing_version_prefix_vulnerable.sol"  "hyperevm-corewriter-action-missing-version-prefix"
run_clean_test "hyperevm-corewriter-action-missing-version-prefix"  "hyperevm_corewriter_action_missing_version_prefix_clean.sol"       "hyperevm-corewriter-action-missing-version-prefix (clean)"


# R108 — kiln-v1 source mining (PR #263 reentrancy seed + 2 prior audits)
run_test       "eth-fee-splitter-no-reentrancy-guard-multiple-external-calls"  "eth_fee_splitter_no_reentrancy_guard_multiple_external_calls_vulnerable.sol"  "eth-fee-splitter-no-reentrancy-guard-multiple-external-calls"
run_clean_test "eth-fee-splitter-no-reentrancy-guard-multiple-external-calls"  "eth_fee_splitter_no_reentrancy_guard_multiple_external_calls_clean.sol"       "eth-fee-splitter-no-reentrancy-guard-multiple-external-calls (clean)"
run_test       "clone-fee-recipient-init-permissionless-frontrun"              "clone_fee_recipient_init_permissionless_frontrun_vulnerable.sol"              "clone-fee-recipient-init-permissionless-frontrun"
run_clean_test "clone-fee-recipient-init-permissionless-frontrun"              "clone_fee_recipient_init_permissionless_frontrun_clean.sol"                   "clone-fee-recipient-init-permissionless-frontrun (clean)"
run_test       "branch-asymmetric-idempotency-flag-toggled-in-only-one-arm"    "branch_asymmetric_idempotency_flag_toggled_in_only_one_arm_vulnerable.sol"    "branch-asymmetric-idempotency-flag-toggled-in-only-one-arm"
run_clean_test "branch-asymmetric-idempotency-flag-toggled-in-only-one-arm"    "branch_asymmetric_idempotency_flag_toggled_in_only_one_arm_clean.sol"         "branch-asymmetric-idempotency-flag-toggled-in-only-one-arm (clean)"
run_test       "deposit-allocator-hardcoded-index-with-multi-operator-array"   "deposit_allocator_hardcoded_index_with_multi_operator_array_vulnerable.sol"   "deposit-allocator-hardcoded-index-with-multi-operator-array"
run_clean_test "deposit-allocator-hardcoded-index-with-multi-operator-array"   "deposit_allocator_hardcoded_index_with_multi_operator_array_clean.sol"        "deposit-allocator-hardcoded-index-with-multi-operator-array (clean)"
run_test       "operator-deactivation-fee-recipient-swap-strands-accrued"      "operator_deactivation_fee_recipient_swap_strands_accrued_vulnerable.sol"      "operator-deactivation-fee-recipient-swap-strands-accrued"
run_clean_test "operator-deactivation-fee-recipient-swap-strands-accrued"      "operator_deactivation_fee_recipient_swap_strands_accrued_clean.sol"           "operator-deactivation-fee-recipient-swap-strands-accrued (clean)"


# R99 LISA-Bench batch PR #248 — 5 generated detectors
run_test       "auction-conclusion-strict-less-than-allows-cancel-at-boundary" "auction_conclusion_strict_less_than_allows_cancel_at_boundary_vulnerable.sol" "auction-conclusion-strict-less-than-allows-cancel-at-boundary"
run_clean_test "auction-conclusion-strict-less-than-allows-cancel-at-boundary" "auction_conclusion_strict_less_than_allows_cancel_at_boundary_clean.sol" "auction-conclusion-strict-less-than-allows-cancel-at-boundary (clean)"
run_test       "error-handler-cancels-without-feature-validation" "error_handler_cancels_without_feature_validation_vulnerable.sol" "error-handler-cancels-without-feature-validation"
run_clean_test "error-handler-cancels-without-feature-validation" "error_handler_cancels_without_feature_validation_clean.sol" "error-handler-cancels-without-feature-validation (clean)"
run_test       "min-output-overwritten-by-internal-calc-ignoring-user-slippage" "min_output_overwritten_by_internal_calc_ignoring_user_slippage_vulnerable.sol" "min-output-overwritten-by-internal-calc-ignoring-user-slippage"
run_clean_test "min-output-overwritten-by-internal-calc-ignoring-user-slippage" "min_output_overwritten_by_internal_calc_ignoring_user_slippage_clean.sol" "min-output-overwritten-by-internal-calc-ignoring-user-slippage (clean)"
run_test       "orderbook-id-reuses-length-after-decrement-overwrites-prior" "orderbook_id_reuses_length_after_decrement_overwrites_prior_vulnerable.sol" "orderbook-id-reuses-length-after-decrement-overwrites-prior"
run_clean_test "orderbook-id-reuses-length-after-decrement-overwrites-prior" "orderbook_id_reuses_length_after_decrement_overwrites_prior_clean.sol" "orderbook-id-reuses-length-after-decrement-overwrites-prior (clean)"
run_test       "update-admin-revokes-old-without-self-equality-check" "update_admin_revokes_old_without_self_equality_check_vulnerable.sol" "update-admin-revokes-old-without-self-equality-check"
run_clean_test "update-admin-revokes-old-without-self-equality-check" "update_admin_revokes_old_without_self_equality_check_clean.sol" "update-admin-revokes-old-without-self-equality-check (clean)"


# R99 LISA-Bench batch PR #249 — 5 generated detectors
run_test       "curve-pool-lp-token-call-without-fallback-to-token" "curve_pool_lp_token_call_without_fallback_to_token_vulnerable.sol" "curve-pool-lp-token-call-without-fallback-to-token"
run_clean_test "curve-pool-lp-token-call-without-fallback-to-token" "curve_pool_lp_token_call_without_fallback_to_token_clean.sol" "curve-pool-lp-token-call-without-fallback-to-token (clean)"
run_test       "factory-immutable-registry-pointer-no-setter" "factory_immutable_registry_pointer_no_setter_vulnerable.sol" "factory-immutable-registry-pointer-no-setter"
run_clean_test "factory-immutable-registry-pointer-no-setter" "factory_immutable_registry_pointer_no_setter_clean.sol" "factory-immutable-registry-pointer-no-setter (clean)"
run_test       "parser-not-found-fallback-to-input-length-overruns-len" "parser_not_found_fallback_to_input_length_overruns_len_vulnerable.sol" "parser-not-found-fallback-to-input-length-overruns-len"
run_clean_test "parser-not-found-fallback-to-input-length-overruns-len" "parser_not_found_fallback_to_input_length_overruns_len_clean.sol" "parser-not-found-fallback-to-input-length-overruns-len (clean)"
run_test       "price-decimal-fix-assumes-decimals-le-18" "price_decimal_fix_assumes_decimals_le_18_vulnerable.sol" "price-decimal-fix-assumes-decimals-le-18"
run_clean_test "price-decimal-fix-assumes-decimals-le-18" "price_decimal_fix_assumes_decimals_le_18_clean.sol" "price-decimal-fix-assumes-decimals-le-18 (clean)"
run_test       "validate-range-uses-value-only-in-revert-no-bounds-check" "validate_range_uses_value_only_in_revert_no_bounds_check_vulnerable.sol" "validate-range-uses-value-only-in-revert-no-bounds-check"
run_clean_test "validate-range-uses-value-only-in-revert-no-bounds-check" "validate_range_uses_value_only_in_revert_no_bounds_check_clean.sol" "validate-range-uses-value-only-in-revert-no-bounds-check (clean)"


# R99 LISA-Bench batch PR #250 — 5 generated detectors
run_test       "blast-configure-governor-without-claimable-gas-yield" "blast_configure_governor_without_claimable_gas_yield_vulnerable.sol" "blast-configure-governor-without-claimable-gas-yield"
run_clean_test "blast-configure-governor-without-claimable-gas-yield" "blast_configure_governor_without_claimable_gas_yield_clean.sol" "blast-configure-governor-without-claimable-gas-yield (clean)"
run_test       "factory-uses-new-keyword-no-create2-reorg-vulnerable" "factory_uses_new_keyword_no_create2_reorg_vulnerable_vulnerable.sol" "factory-uses-new-keyword-no-create2-reorg-vulnerable"
run_clean_test "factory-uses-new-keyword-no-create2-reorg-vulnerable" "factory_uses_new_keyword_no_create2_reorg_vulnerable_clean.sol" "factory-uses-new-keyword-no-create2-reorg-vulnerable (clean)"
run_test       "marketplace-listing-only-operator-signed-no-seller-sig" "marketplace_listing_only_operator_signed_no_seller_sig_vulnerable.sol" "marketplace-listing-only-operator-signed-no-seller-sig"
run_clean_test "marketplace-listing-only-operator-signed-no-seller-sig" "marketplace_listing_only_operator_signed_no_seller_sig_clean.sol" "marketplace-listing-only-operator-signed-no-seller-sig (clean)"
run_test       "optimism-l1-fee-uses-deprecated-scalar-no-ecotone-fallback" "optimism_l1_fee_uses_deprecated_scalar_no_ecotone_fallback_vulnerable.sol" "optimism-l1-fee-uses-deprecated-scalar-no-ecotone-fallback"
run_clean_test "optimism-l1-fee-uses-deprecated-scalar-no-ecotone-fallback" "optimism_l1_fee_uses_deprecated_scalar_no_ecotone_fallback_clean.sol" "optimism-l1-fee-uses-deprecated-scalar-no-ecotone-fallback (clean)"
run_test       "oracle-getlatestprice-returns-custom-price-shared-with-swap" "oracle_getlatestprice_returns_custom_price_shared_with_swap_vulnerable.sol" "oracle-getlatestprice-returns-custom-price-shared-with-swap"
run_clean_test "oracle-getlatestprice-returns-custom-price-shared-with-swap" "oracle_getlatestprice_returns_custom_price_shared_with_swap_clean.sol" "oracle-getlatestprice-returns-custom-price-shared-with-swap (clean)"


# R99 LISA-Bench batch PR #251 — 5 generated detectors
run_test       "collateral-ratio-buffer-uses-subtraction-not-multiplication" "collateral_ratio_buffer_uses_subtraction_not_multiplication_vulnerable.sol" "collateral-ratio-buffer-uses-subtraction-not-multiplication"
run_clean_test "collateral-ratio-buffer-uses-subtraction-not-multiplication" "collateral_ratio_buffer_uses_subtraction_not_multiplication_clean.sol" "collateral-ratio-buffer-uses-subtraction-not-multiplication (clean)"
run_test       "ec-validate-signature-jacobian-conversion-on-projective" "ec_validate_signature_jacobian_conversion_on_projective_vulnerable.sol" "ec-validate-signature-jacobian-conversion-on-projective"
run_clean_test "ec-validate-signature-jacobian-conversion-on-projective" "ec_validate_signature_jacobian_conversion_on_projective_clean.sol" "ec-validate-signature-jacobian-conversion-on-projective (clean)"
run_test       "governance-offboard-flag-not-cleared-on-onboard" "governance_offboard_flag_not_cleared_on_onboard_vulnerable.sol" "governance-offboard-flag-not-cleared-on-onboard"
run_clean_test "governance-offboard-flag-not-cleared-on-onboard" "governance_offboard_flag_not_cleared_on_onboard_clean.sol" "governance-offboard-flag-not-cleared-on-onboard (clean)"
run_test       "merkle-proof-no-leaf-bottom-hash-distinguisher" "merkle_proof_no_leaf_bottom_hash_distinguisher_vulnerable.sol" "merkle-proof-no-leaf-bottom-hash-distinguisher"
run_clean_test "merkle-proof-no-leaf-bottom-hash-distinguisher" "merkle_proof_no_leaf_bottom_hash_distinguisher_clean.sol" "merkle-proof-no-leaf-bottom-hash-distinguisher (clean)"
run_test       "sd59x18-exp-called-without-negative-input-bound-check" "sd59x18_exp_called_without_negative_input_bound_check_vulnerable.sol" "sd59x18-exp-called-without-negative-input-bound-check"
run_clean_test "sd59x18-exp-called-without-negative-input-bound-check" "sd59x18_exp_called_without_negative_input_bound_check_clean.sol" "sd59x18-exp-called-without-negative-input-bound-check (clean)"


# R99 LISA-Bench batch PR #254 — 5 generated detectors
run_test       "multi-oracle-aggregator-reverts-on-divergence-no-fallback" "multi_oracle_aggregator_reverts_on_divergence_no_fallback_vulnerable.sol" "multi-oracle-aggregator-reverts-on-divergence-no-fallback"
run_clean_test "multi-oracle-aggregator-reverts-on-divergence-no-fallback" "multi_oracle_aggregator_reverts_on_divergence_no_fallback_clean.sol" "multi-oracle-aggregator-reverts-on-divergence-no-fallback (clean)"
run_test       "rng-source-controller-no-fallback-after-max-failed-attempts" "rng_source_controller_no_fallback_after_max_failed_attempts_vulnerable.sol" "rng-source-controller-no-fallback-after-max-failed-attempts"
run_clean_test "rng-source-controller-no-fallback-after-max-failed-attempts" "rng_source_controller_no_fallback_after_max_failed_attempts_clean.sol" "rng-source-controller-no-fallback-after-max-failed-attempts (clean)"
run_test       "setwrapper-leaves-stale-canonical-to-adopted-mapping" "setwrapper_leaves_stale_canonical_to_adopted_mapping_vulnerable.sol" "setwrapper-leaves-stale-canonical-to-adopted-mapping"
run_clean_test "setwrapper-leaves-stale-canonical-to-adopted-mapping" "setwrapper_leaves_stale_canonical_to_adopted_mapping_clean.sol" "setwrapper-leaves-stale-canonical-to-adopted-mapping (clean)"
run_test       "staking-controller-overloaded-deposit-ignores-claim-bool" "staking_controller_overloaded_deposit_ignores_claim_bool_vulnerable.sol" "staking-controller-overloaded-deposit-ignores-claim-bool"
run_clean_test "staking-controller-overloaded-deposit-ignores-claim-bool" "staking_controller_overloaded_deposit_ignores_claim_bool_clean.sol" "staking-controller-overloaded-deposit-ignores-claim-bool (clean)"
run_test       "virtual-swap-impact-skipped-when-one-token-missing" "virtual_swap_impact_skipped_when_one_token_missing_vulnerable.sol" "virtual-swap-impact-skipped-when-one-token-missing"
run_clean_test "virtual-swap-impact-skipped-when-one-token-missing" "virtual_swap_impact_skipped_when_one_token_missing_clean.sol" "virtual-swap-impact-skipped-when-one-token-missing (clean)"


# R99 LISA-Bench batch PR #256 — 5 generated detectors
run_test       "continuous-gda-purchase-price-uses-emission-rate-as-decay" "continuous_gda_purchase_price_uses_emission_rate_as_decay_vulnerable.sol" "continuous-gda-purchase-price-uses-emission-rate-as-decay"
run_clean_test "continuous-gda-purchase-price-uses-emission-rate-as-decay" "continuous_gda_purchase_price_uses_emission_rate_as_decay_clean.sol" "continuous-gda-purchase-price-uses-emission-rate-as-decay (clean)"
run_test       "deposit-failure-cancellation-uses-remaining-gas-not-original-fee" "deposit_failure_cancellation_uses_remaining_gas_not_original_fee_vulnerable.sol" "deposit-failure-cancellation-uses-remaining-gas-not-original-fee"
run_clean_test "deposit-failure-cancellation-uses-remaining-gas-not-original-fee" "deposit_failure_cancellation_uses_remaining_gas_not_original_fee_clean.sol" "deposit-failure-cancellation-uses-remaining-gas-not-original-fee (clean)"
run_test       "match-orders-buyer-constraint-checked-vs-seller-constraint" "match_orders_buyer_constraint_checked_vs_seller_constraint_vulnerable.sol" "match-orders-buyer-constraint-checked-vs-seller-constraint"
run_clean_test "match-orders-buyer-constraint-checked-vs-seller-constraint" "match_orders_buyer_constraint_checked_vs_seller_constraint_clean.sol" "match-orders-buyer-constraint-checked-vs-seller-constraint (clean)"
run_test       "pay-execution-fee-ignores-eip150-63-64-rule" "pay_execution_fee_ignores_eip150_63_64_rule_vulnerable.sol" "pay-execution-fee-ignores-eip150-63-64-rule"
run_clean_test "pay-execution-fee-ignores-eip150-63-64-rule" "pay_execution_fee_ignores_eip150_63_64_rule_clean.sol" "pay-execution-fee-ignores-eip150-63-64-rule (clean)"
run_test       "place-value-ruler-loop-divides-by-zero-on-small-input" "place_value_ruler_loop_divides_by_zero_on_small_input_vulnerable.sol" "place-value-ruler-loop-divides-by-zero-on-small-input"
run_clean_test "place-value-ruler-loop-divides-by-zero-on-small-input" "place_value_ruler_loop_divides_by_zero_on_small_input_clean.sol" "place-value-ruler-loop-divides-by-zero-on-small-input (clean)"


# R99 LISA-Bench batch PR #257 — 5 generated detectors
run_test       "asm-patch-calldata-mstore-no-index-bound-check" "asm_patch_calldata_mstore_no_index_bound_check_vulnerable.sol" "asm-patch-calldata-mstore-no-index-bound-check"
run_clean_test "asm-patch-calldata-mstore-no-index-bound-check" "asm_patch_calldata_mstore_no_index_bound_check_clean.sol" "asm-patch-calldata-mstore-no-index-bound-check (clean)"
run_test       "delta-hedge-clamp-revabs-forces-positive-sign" "delta_hedge_clamp_revabs_forces_positive_sign_vulnerable.sol" "delta-hedge-clamp-revabs-forces-positive-sign"
run_clean_test "delta-hedge-clamp-revabs-forces-positive-sign" "delta_hedge_clamp_revabs_forces_positive_sign_clean.sol" "delta-hedge-clamp-revabs-forces-positive-sign (clean)"
run_test       "erc20-wrapper-deposit-for-allows-wrapper-as-recipient" "erc20_wrapper_deposit_for_allows_wrapper_as_recipient_vulnerable.sol" "erc20-wrapper-deposit-for-allows-wrapper-as-recipient"
run_clean_test "erc20-wrapper-deposit-for-allows-wrapper-as-recipient" "erc20_wrapper_deposit_for_allows_wrapper_as_recipient_clean.sol" "erc20-wrapper-deposit-for-allows-wrapper-as-recipient (clean)"
run_test       "erc4626-oracle-uses-vault-decimals-not-asset-decimals" "erc4626_oracle_uses_vault_decimals_not_asset_decimals_vulnerable.sol" "erc4626-oracle-uses-vault-decimals-not-asset-decimals"
run_clean_test "erc4626-oracle-uses-vault-decimals-not-asset-decimals" "erc4626_oracle_uses_vault_decimals_not_asset_decimals_clean.sol" "erc4626-oracle-uses-vault-decimals-not-asset-decimals (clean)"
run_test       "iscontract-via-extcodesize-bypass-during-construction" "iscontract_via_extcodesize_bypass_during_construction_vulnerable.sol" "iscontract-via-extcodesize-bypass-during-construction"
run_clean_test "iscontract-via-extcodesize-bypass-during-construction" "iscontract_via_extcodesize_bypass_during_construction_clean.sol" "iscontract-via-extcodesize-bypass-during-construction (clean)"


# R101 — in-house prior-audit mined detectors (PR #255 smoke coverage)
run_test       "adapter-realassets-balanceof-self-donatable"           "adapter_realassets_balanceof_self_donatable_vulnerable.sol"           "adapter-realassets-balanceof-self-donatable"
run_clean_test "adapter-realassets-balanceof-self-donatable"           "adapter_realassets_balanceof_self_donatable_clean.sol"                "adapter-realassets-balanceof-self-donatable (clean)"
run_test       "constructor-precision-factor-truncates-to-zero"        "constructor_precision_factor_truncates_to_zero_vulnerable.sol"        "constructor-precision-factor-truncates-to-zero"
run_clean_test "constructor-precision-factor-truncates-to-zero"        "constructor_precision_factor_truncates_to_zero_clean.sol"             "constructor-precision-factor-truncates-to-zero (clean)"
run_test       "liquidation-callback-payment-pulled-after-callback"    "liquidation_callback_payment_pulled_after_callback_vulnerable.sol"    "liquidation-callback-payment-pulled-after-callback"
run_clean_test "liquidation-callback-payment-pulled-after-callback"    "liquidation_callback_payment_pulled_after_callback_clean.sol"         "liquidation-callback-payment-pulled-after-callback (clean)"
run_test       "recipient-reassignment-only-in-one-branch"             "recipient_reassignment_only_in_one_branch_vulnerable.sol"             "recipient-reassignment-only-in-one-branch"
run_clean_test "recipient-reassignment-only-in-one-branch"             "recipient_reassignment_only_in_one_branch_clean.sol"                  "recipient-reassignment-only-in-one-branch (clean)"
run_test       "vault-adapter-remove-without-zero-allocation-check"     "vault_adapter_remove_without_zero_allocation_check_vulnerable.sol"     "vault-adapter-remove-without-zero-allocation-check"
run_clean_test "vault-adapter-remove-without-zero-allocation-check"     "vault_adapter_remove_without_zero_allocation_check_clean.sol"          "vault-adapter-remove-without-zero-allocation-check (clean)"

# R110 — morpho-source mining followup (PR followup to R101 / PR #255)
run_test       "adapter-realassets-loop-no-revert-isolation"           "adapter_realassets_loop_no_revert_isolation_vulnerable.sol"           "adapter-realassets-loop-no-revert-isolation"
run_clean_test "adapter-realassets-loop-no-revert-isolation"           "adapter_realassets_loop_no_revert_isolation_clean.sol"                "adapter-realassets-loop-no-revert-isolation (clean)"
run_test       "fee-withdraw-uses-eth-transfer-2300-gas-stipend"       "fee_withdraw_uses_eth_transfer_2300_gas_stipend_vulnerable.sol"       "fee-withdraw-uses-eth-transfer-2300-gas-stipend"
run_clean_test "fee-withdraw-uses-eth-transfer-2300-gas-stipend"       "fee_withdraw_uses_eth_transfer_2300_gas_stipend_clean.sol"            "fee-withdraw-uses-eth-transfer-2300-gas-stipend (clean)"
run_test       "oracle-multi-feed-product-unchecked-overflow"          "oracle_multi_feed_product_unchecked_overflow_vulnerable.sol"          "oracle-multi-feed-product-unchecked-overflow"
run_clean_test "oracle-multi-feed-product-unchecked-overflow"          "oracle_multi_feed_product_unchecked_overflow_clean.sol"               "oracle-multi-feed-product-unchecked-overflow (clean)"
run_test       "vault-multicall-self-delegatecall-no-reentrancy-guard" "vault_multicall_self_delegatecall_no_reentrancy_guard_vulnerable.sol" "vault-multicall-self-delegatecall-no-reentrancy-guard"
run_clean_test "vault-multicall-self-delegatecall-no-reentrancy-guard" "vault_multicall_self_delegatecall_no_reentrancy_guard_clean.sol"      "vault-multicall-self-delegatecall-no-reentrancy-guard (clean)"
run_test       "wrapper-and-inner-protocol-use-different-oracles-divergence" "wrapper_and_inner_protocol_use_different_oracles_divergence_vulnerable.sol" "wrapper-and-inner-protocol-use-different-oracles-divergence"
run_clean_test "wrapper-and-inner-protocol-use-different-oracles-divergence" "wrapper_and_inner_protocol_use_different_oracles_divergence_clean.sol"      "wrapper-and-inner-protocol-use-different-oracles-divergence (clean)"

# === wave17-cleanup recovery — patterns with YAML + wave17/.py + fixtures ===
# Surfaced by PR #283's yaml-wave17-consistency check. These patterns had
# all artifacts present but were missing run_tests.sh wiring.
run_test       "adapter-routed-call-emits-event-with-self-origin"        "adapter_routed_call_emits_event_with_self_origin_vulnerable.sol"        "adapter-routed-call-emits-event-with-self-origin"
run_clean_test "adapter-routed-call-emits-event-with-self-origin"        "adapter_routed_call_emits_event_with_self_origin_clean.sol"             "adapter-routed-call-emits-event-with-self-origin (clean)"
run_test       "cei-violation-fulfill-before-storage"                    "cei_violation_fulfill_before_storage_vulnerable.sol"                    "cei-violation-fulfill-before-storage"
run_clean_test "cei-violation-fulfill-before-storage"                    "cei_violation_fulfill_before_storage_clean.sol"                         "cei-violation-fulfill-before-storage (clean)"
run_test       "clone-constants-uninitialized"                           "clone_constants_uninitialized_vulnerable.sol"                           "clone-constants-uninitialized"
run_clean_test "clone-constants-uninitialized"                           "clone_constants_uninitialized_clean.sol"                                "clone-constants-uninitialized (clean)"
run_test       "collateral-sweep-without-pre-post-delta-check"           "collateral_sweep_without_pre_post_delta_check_vulnerable.sol"           "collateral-sweep-without-pre-post-delta-check"
run_clean_test "collateral-sweep-without-pre-post-delta-check"           "collateral_sweep_without_pre_post_delta_check_clean.sol"                "collateral-sweep-without-pre-post-delta-check (clean)"
run_test       "cross-function-reentrancy"                               "cross_function_reentrancy_vulnerable.sol"                               "cross-function-reentrancy"
run_clean_test "cross-function-reentrancy"                               "cross_function_reentrancy_clean.sol"                                    "cross-function-reentrancy (clean)"
run_test       "decimal-truncation-price-check"                          "decimal_truncation_price_check_vulnerable.sol"                          "decimal-truncation-price-check"
run_clean_test "decimal-truncation-price-check"                          "decimal_truncation_price_check_clean.sol"                               "decimal-truncation-price-check (clean)"
run_test       "fee-uncapped-in-constructor"                             "fee_uncapped_in_constructor_vulnerable.sol"                             "fee-uncapped-in-constructor"
run_clean_test "fee-uncapped-in-constructor"                             "fee_uncapped_in_constructor_clean.sol"                                  "fee-uncapped-in-constructor (clean)"
run_test       "harvest-unvalidated-agent"                               "harvest_unvalidated_agent_vulnerable.sol"                               "harvest-unvalidated-agent"
run_clean_test "harvest-unvalidated-agent"                               "harvest_unvalidated_agent_clean.sol"                                    "harvest-unvalidated-agent (clean)"
run_test       "interest-index-not-updated-on-transfer"                  "interest_index_not_updated_on_transfer_vulnerable.sol"                  "interest-index-not-updated-on-transfer"
run_clean_test "interest-index-not-updated-on-transfer"                  "interest_index_not_updated_on_transfer_clean.sol"                       "interest-index-not-updated-on-transfer (clean)"
run_test       "lock-extension-griefing"                                 "lock_extension_griefing_vulnerable.sol"                                 "lock-extension-griefing"
run_clean_test "lock-extension-griefing"                                 "lock_extension_griefing_clean.sol"                                      "lock-extension-griefing (clean)"
run_test       "merkle-index-unchecked"                                  "merkle_index_unchecked_vulnerable.sol"                                  "merkle-index-unchecked"
run_clean_test "merkle-index-unchecked"                                  "merkle_index_unchecked_clean.sol"                                       "merkle-index-unchecked (clean)"
run_test       "nft-approval-not-owner-check"                            "nft_approval_not_owner_check_vulnerable.sol"                            "nft-approval-not-owner-check"
run_clean_test "nft-approval-not-owner-check"                            "nft_approval_not_owner_check_clean.sol"                                 "nft-approval-not-owner-check (clean)"
run_test       "ownable-override-role-check-mismatch"                    "ownable_override_role_check_mismatch_vulnerable.sol"                    "ownable-override-role-check-mismatch"
run_clean_test "ownable-override-role-check-mismatch"                    "ownable_override_role_check_mismatch_clean.sol"                         "ownable-override-role-check-mismatch (clean)"
run_test       "state-update-before-try-catch"                           "state_update_before_try_catch_vulnerable.sol"                           "state-update-before-try-catch"
run_clean_test "state-update-before-try-catch"                           "state_update_before_try_catch_clean.sol"                                "state-update-before-try-catch (clean)"
run_test       "unbounded-order-list-iteration"                          "unbounded_order_list_iteration_vulnerable.sol"                          "unbounded-order-list-iteration"
run_clean_test "unbounded-order-list-iteration"                          "unbounded_order_list_iteration_clean.sol"                               "unbounded-order-list-iteration (clean)"

# === wave17-cleanup recovery — newly-compiled patterns (PR #121 A6/A7 hand-authored YAMLs) ===
# These YAMLs already had fixtures but no compiled wave17/.py until this PR.
run_test       "pause-asymmetric-blocks-only-some-actions"               "pause_asymmetric_blocks_only_some_actions_vulnerable.sol"               "pause-asymmetric-blocks-only-some-actions"
run_clean_test "pause-asymmetric-blocks-only-some-actions"               "pause_asymmetric_blocks_only_some_actions_clean.sol"                    "pause-asymmetric-blocks-only-some-actions (clean)"
run_test       "snapshot-vs-live-withdrawable-drift"                     "snapshot_vs_live_withdrawable_drift_vulnerable.sol"                     "snapshot-vs-live-withdrawable-drift"
run_clean_test "snapshot-vs-live-withdrawable-drift"                     "snapshot_vs_live_withdrawable_drift_clean.sol"                          "snapshot-vs-live-withdrawable-drift (clean)"

echo
TOTAL=$(wc -l < "$STAGE" | tr -d ' ')
echo "[staged] $TOTAL test(s) queued for execution"
echo

# === BATCH MODE (default in Round 21) ===
# Instead of running 2670 × 2 separate `slither` invocations (one per test),
# we compile the entire test_fixtures/ directory ONCE and loop detectors
# against the compiled artifacts in memory. Expected speedup: 30-50×.
#
# Legacy parallel mode is still available via LEGACY_PARALLEL=1 env var.

if [ "${LEGACY_PARALLEL:-0}" = "1" ]; then
    echo "[parallel] dispatching via python multiprocessing.Pool($JOBS)..."
    START_T=$(date +%s)
    PYOUT=$(JOBS="$JOBS" FIXTURE_DIR="$FIXTURE_DIR" RUNNER="$RUNNER" STAGE="$STAGE" PYTHON_SLITHER="$PYTHON_SLITHER" "$PYTHON_SLITHER" - <<'PY'
import os, re, subprocess, sys
from multiprocessing import get_context
FIXTURE_DIR = os.environ["FIXTURE_DIR"]
RUNNER = os.environ["RUNNER"]
STAGE = os.environ["STAGE"]
JOBS = int(os.environ["JOBS"])
PYTHON_SLITHER = os.environ["PYTHON_SLITHER"]

def run_row(row):
    parts = row.rstrip("\n").split("\t")
    if len(parts) < 4:
        return ("skip", row)
    mode, detector, fixture, label = parts[:4]
    try:
        out = subprocess.check_output(
            [PYTHON_SLITHER, RUNNER, "--include-graveyard", "--tier=ALL", os.path.join(FIXTURE_DIR, fixture), detector],
            stderr=subprocess.STDOUT, timeout=90,
        ).decode()
    except subprocess.CalledProcessError as e:
        detail = e.output.decode(errors="ignore").strip().splitlines()
        tail = " | ".join(detail[-3:]) if detail else f"rc={e.returncode}"
        return ("fail", f"{label} ({detector}) — runner error: {tail[:500]}")
    except subprocess.TimeoutExpired:
        return ("fail", f"{label} ({detector}) — timeout")
    m = re.search(r"total hits:\s*(\d+)", out)
    hits = int(m.group(1)) if m else 0
    if mode == "vuln":
        return ("pass" if hits >= 1 else "fail", f"{label} ({detector}) — {hits} hits")
    else:
        return ("pass" if hits == 0 else "fail", f"{label} ({detector}) — {hits} hits on CLEAN (FP)")

with open(STAGE) as f:
    rows = [l for l in f if l.strip()]
print(f"[parallel] running {len(rows)} tests with {JOBS} workers...", flush=True)
with get_context("fork").Pool(JOBS) as p:
    results = p.map(run_row, rows, chunksize=4)
passes = sum(1 for s, _ in results if s == "pass")
fails = [msg for s, msg in results if s == "fail"]
print(f"PASSES={passes}")
print(f"FAILS={len(fails)}")
for f in fails[:20]:
    print(f"FAIL_LINE={f}")
PY
    )
    PYRC=$?
    END_T=$(date +%s)
    ELAPSED=$((END_T - START_T))
    PASS=$(echo "$PYOUT" | awk -F= '/^PASSES=/{print $2}')
    FAIL=$(echo "$PYOUT" | awk -F= '/^FAILS=/{print $2}')
    echo "========================================="
    echo " Results: ${PASS:-0} passed, ${FAIL:-0} failed  (${ELAPSED}s, parallel $JOBS)"
    echo "========================================="
    if [ "${FAIL:-0}" != "0" ]; then
        echo "FAILED (first 20):"
        echo "$PYOUT" | awk -F= '/^FAIL_LINE=/{print "  - " substr($0, index($0, "=")+1)}'
        exit 1
    fi
    exit 0
fi

# === DEFAULT: BATCH COMPILE ===
echo "[batch] delegating to run_custom.py --batch ..."
START_T=$(date +%s)
"$PYTHON_SLITHER" "$RUNNER" --batch "$FIXTURE_DIR" "$STAGE" --tier=ALL
RC=$?
END_T=$(date +%s)
ELAPSED=$((END_T - START_T))
echo "[batch] elapsed ${ELAPSED}s"
exit $RC

# Generated by gen-detector.py — 1 detectors


# Generated by gen-detector.py — 1 detectors


# Generated by gen-detector.py — 1 detectors


# Generated by gen-detector.py — 1 detectors


# Generated by gen-detector.py — 1 detectors


# Generated by gen-detector.py — 98 detectors
run_test "burn-overestimates-distribution-with-accruedfees" "burn_overestimates_distribution_with_accruedfees_vulnerable.sol" "burn-overestimates-distribution-with-accruedfees"
run_clean_test "burn-overestimates-distribution-with-accruedfees" "burn_overestimates_distribution_with_accruedfees_clean.sol" "burn-overestimates-distribution-with-accruedfees (clean)"
run_test "expired-orders-in-mid-impact-price" "expired_orders_in_mid_impact_price_vulnerable.sol" "expired-orders-in-mid-impact-price"
run_clean_test "expired-orders-in-mid-impact-price" "expired_orders_in_mid_impact_price_clean.sol" "expired-orders-in-mid-impact-price (clean)"
run_test "extraneous-approval-in-withdrawal-allows-double-withdrawal" "extraneous_approval_in_withdrawal_allows_double_withdrawal_vulnerable.sol" "extraneous-approval-in-withdrawal-allows-double-withdrawal"
run_clean_test "extraneous-approval-in-withdrawal-allows-double-withdrawal" "extraneous_approval_in_withdrawal_allows_double_withdrawal_clean.sol" "extraneous-approval-in-withdrawal-allows-double-withdrawal (clean)"
run_test "free-lp-mint-with-accrued-fees" "free_lp_mint_with_accrued_fees_vulnerable.sol" "free-lp-mint-with-accrued-fees"
run_clean_test "free-lp-mint-with-accrued-fees" "free_lp_mint_with_accrued_fees_clean.sol" "free-lp-mint-with-accrued-fees (clean)"
run_test "multi-asset-reentrancy-via-erc-777-drains-vault" "multi_asset_reentrancy_via_erc_777_drains_vault_vulnerable.sol" "multi-asset-reentrancy-via-erc-777-drains-vault"
run_clean_test "multi-asset-reentrancy-via-erc-777-drains-vault" "multi_asset_reentrancy_via_erc_777_drains_vault_clean.sol" "multi-asset-reentrancy-via-erc-777-drains-vault (clean)"
run_test "order-dll-prevorderid-not-persisted" "order_dll_prevorderid_not_persisted_vulnerable.sol" "order-dll-prevorderid-not-persisted"
run_clean_test "order-dll-prevorderid-not-persisted" "order_dll_prevorderid_not_persisted_clean.sol" "order-dll-prevorderid-not-persisted (clean)"


# Generated by gen-detector.py — 101 detectors


# Generated by gen-detector.py — 1 detectors


# Generated by gen-detector.py — 1 detectors


# Generated by gen-detector.py — 1 detectors


# Generated by gen-detector.py — 1 detectors


# Generated by gen-detector.py — 2 detectors


# Generated by gen-detector.py — 1 detectors


# Generated by gen-detector.py — 10 detectors


# Generated by gen-detector.py — 20 detectors


# Generated by gen-detector.py — 10 detectors


# Generated by gen-detector.py — 10 detectors


# Generated by gen-detector.py — 20 detectors

# Wave 12 — hand-rescued batch
run_test "clob-order-amendment-bypasses-tick-spacing-for-price" "clob_order_amendment_bypasses_tick_spacing_for_price_vulnerable.sol" "clob-order-amendment-bypasses-tick-spacing-for-price"
run_clean_test "clob-order-amendment-bypasses-tick-spacing-for-price" "clob_order_amendment_bypasses_tick_spacing_for_price_clean.sol" "clob-order-amendment-bypasses-tick-spacing-for-price (clean)"


# Generated by gen-detector.py — 50 detectors


# Generated by gen-detector.py — 100 detectors
run_test "arbitrary-token-transfers-in-wrapanddistributeerc20amounts" "arbitrary_token_transfers_in_wrapanddistributeerc20amounts_vulnerable.sol" "arbitrary-token-transfers-in-wrapanddistributeerc20amounts"
run_clean_test "arbitrary-token-transfers-in-wrapanddistributeerc20amounts" "arbitrary_token_transfers_in_wrapanddistributeerc20amounts_clean.sol" "arbitrary-token-transfers-in-wrapanddistributeerc20amounts (clean)"


# Generated by gen-detector.py — 50 detectors


# Generated by gen-detector.py — 50 detectors


# Generated by gen-detector.py — 100 detectors


# Generated by gen-detector.py — 50 detectors


# Generated by gen-detector.py — 39 detectors


# Generated by gen-detector.py — 100 detectors
run_test "checkpoints-are-incorrectly-cleared-during-transferfrom" "checkpoints_are_incorrectly_cleared_during_transferfrom_vulnerable.sol" "checkpoints-are-incorrectly-cleared-during-transferfrom"
run_clean_test "checkpoints-are-incorrectly-cleared-during-transferfrom" "checkpoints_are_incorrectly_cleared_during_transferfrom_clean.sol" "checkpoints-are-incorrectly-cleared-during-transferfrom (clean)"


# Generated by gen-detector.py — 100 detectors
run_test "cross-msg-recipient-can-block-checkpoint-submission" "cross_msg_recipient_can_block_checkpoint_submission_vulnerable.sol" "cross-msg-recipient-can-block-checkpoint-submission"
run_clean_test "cross-msg-recipient-can-block-checkpoint-submission" "cross_msg_recipient_can_block_checkpoint_submission_clean.sol" "cross-msg-recipient-can-block-checkpoint-submission (clean)"
run_test "directly-sending-dust-token-amount-will-slow-down-distributi-x" "directly_sending_dust_token_amount_will_slow_down_distributi_x_vulnerable.sol" "directly-sending-dust-token-amount-will-slow-down-distributi-x"
run_clean_test "directly-sending-dust-token-amount-will-slow-down-distributi-x" "directly_sending_dust_token_amount_will_slow_down_distributi_x_clean.sol" "directly-sending-dust-token-amount-will-slow-down-distributi-x (clean)"


# Generated by gen-detector.py — 100 detectors
run_test "erc-20-allowance-bypass-spender-can-force-sender-to-pay-extr-x" "erc_20_allowance_bypass_spender_can_force_sender_to_pay_extr_x_vulnerable.sol" "erc-20-allowance-bypass-spender-can-force-sender-to-pay-extr-x"
run_clean_test "erc-20-allowance-bypass-spender-can-force-sender-to-pay-extr-x" "erc_20_allowance_bypass_spender_can_force_sender_to_pay_extr_x_clean.sol" "erc-20-allowance-bypass-spender-can-force-sender-to-pay-extr-x (clean)"


# Generated by gen-detector.py — 100 detectors
run_test "getperiodreward-function-allows-transfers-to-zero-address-wi-x" "getperiodreward_function_allows_transfers_to_zero_address_wi_x_vulnerable.sol" "getperiodreward-function-allows-transfers-to-zero-address-wi-x"
run_clean_test "getperiodreward-function-allows-transfers-to-zero-address-wi-x" "getperiodreward_function_allows_transfers_to_zero_address_wi_x_clean.sol" "getperiodreward-function-allows-transfers-to-zero-address-wi-x (clean)"


# Generated by gen-detector.py — 100 detectors


# Generated by gen-detector.py — 100 detectors


# Generated by gen-detector.py — 100 detectors
run_test "invalid-token-address-used-in-chakrasettlementhandler-cross--x" "invalid_token_address_used_in_chakrasettlementhandler_cross__x_vulnerable.sol" "invalid-token-address-used-in-chakrasettlementhandler-cross--x"
run_clean_test "invalid-token-address-used-in-chakrasettlementhandler-cross--x" "invalid_token_address_used_in_chakrasettlementhandler_cross__x_clean.sol" "invalid-token-address-used-in-chakrasettlementhandler-cross--x (clean)"


# Generated by gen-detector.py — 100 detectors


# Generated by gen-detector.py — 100 detectors


# Generated by gen-detector.py — 100 detectors


# Generated by gen-detector.py — 100 detectors


# Generated by gen-detector.py — 100 detectors


# Generated by gen-detector.py — 100 detectors


# Generated by gen-detector.py — 100 detectors


# Generated by gen-detector.py — 100 detectors


# Generated by gen-detector.py — 100 detectors
run_test "the-implementation-of-pulltokenswithpermit-poses-a-risk-allo-x" "the_implementation_of_pulltokenswithpermit_poses_a_risk_allo_x_vulnerable.sol" "the-implementation-of-pulltokenswithpermit-poses-a-risk-allo-x"
run_clean_test "the-implementation-of-pulltokenswithpermit-poses-a-risk-allo-x" "the_implementation_of_pulltokenswithpermit_poses_a_risk_allo_x_clean.sol" "the-implementation-of-pulltokenswithpermit-poses-a-risk-allo-x (clean)"


# Generated by gen-detector.py — 100 detectors


# Generated by gen-detector.py — 100 detectors


# Generated by gen-detector.py — 100 detectors


# Generated by gen-detector.py — 31 detectors


# Generated by gen-detector.py — 20 detectors
run_test "approve-function-return-value-not-validated" "approve_function_return_value_not_validated_vulnerable.sol" "approve-function-return-value-not-validated"
run_clean_test "approve-function-return-value-not-validated" "approve_function_return_value_not_validated_clean.sol" "approve-function-return-value-not-validated (clean)"

# === Round 22 Phase 1 graduations (real-code validated on 4 targets) ===
run_test "anyone-can-transfer" "anyone_can_transfer_vulnerable.sol" "anyone-can-transfer"
run_clean_test "anyone-can-transfer" "anyone_can_transfer_clean.sol" "anyone-can-transfer (clean)"
run_test "approve-without-reset-dos" "approve_without_reset_dos_vulnerable.sol" "approve-without-reset-dos"
run_clean_test "approve-without-reset-dos" "approve_without_reset_dos_clean.sol" "approve-without-reset-dos (clean)"
run_test "bnbx-2024-04" "bnbx_2024_04_vulnerable.sol" "bnbx-2024-04"
run_clean_test "bnbx-2024-04" "bnbx_2024_04_clean.sol" "bnbx-2024-04 (clean)"
run_test "bool-accumulator-overwrite" "bool_accumulator_overwrite_vulnerable.sol" "bool-accumulator-overwrite"
run_clean_test "bool-accumulator-overwrite" "bool_accumulator_overwrite_clean.sol" "bool-accumulator-overwrite (clean)"
run_test "burnsdefi-2024-02" "burnsdefi_2024_02_vulnerable.sol" "burnsdefi-2024-02"
run_clean_test "burnsdefi-2024-02" "burnsdefi_2024_02_clean.sol" "burnsdefi-2024-02 (clean)"
run_test "cloberdex-2024-12" "cloberdex_2024_12_vulnerable.sol" "cloberdex-2024-12"
run_clean_test "cloberdex-2024-12" "cloberdex_2024_12_clean.sol" "cloberdex-2024-12 (clean)"
run_test "clone-construction-leaves-constants-uninitialized" "clone_construction_leaves_constants_uninitialized_vulnerable.sol" "clone-construction-leaves-constants-uninitialized"
run_clean_test "clone-construction-leaves-constants-uninitialized" "clone_construction_leaves_constants_uninitialized_clean.sol" "clone-construction-leaves-constants-uninitialized (clean)"
run_test "component-falcon-finance-token" "component_falcon_finance_token_vulnerable.sol" "component-falcon-finance-token"
run_clean_test "component-falcon-finance-token" "component_falcon_finance_token_clean.sol" "component-falcon-finance-token (clean)"
run_test "corkprotocol-2025-05" "corkprotocol_2025_05_vulnerable.sol" "corkprotocol-2025-05"
run_clean_test "corkprotocol-2025-05" "corkprotocol_2025_05_clean.sol" "corkprotocol-2025-05 (clean)"
run_test "deposit-withdrawal-request-replay" "deposit_withdrawal_request_replay_vulnerable.sol" "deposit-withdrawal-request-replay"
run_clean_test "deposit-withdrawal-request-replay" "deposit_withdrawal_request_replay_clean.sol" "deposit-withdrawal-request-replay (clean)"
run_test "dos-attack-to-swapaction-transferandswap-when-using-an-erc20-x" "dos_attack_to_swapaction_transferandswap_when_using_an_erc20_x_vulnerable.sol" "dos-attack-to-swapaction-transferandswap-when-using-an-erc20-x"
run_clean_test "dos-attack-to-swapaction-transferandswap-when-using-an-erc20-x" "dos_attack_to_swapaction_transferandswap_when_using_an_erc20_x_clean.sol" "dos-attack-to-swapaction-transferandswap-when-using-an-erc20-x (clean)"
run_test "duplicate-checks-in-deployer-14" "duplicate_checks_in_deployer_14_vulnerable.sol" "duplicate-checks-in-deployer-14"
run_clean_test "duplicate-checks-in-deployer-14" "duplicate_checks_in_deployer_14_clean.sol" "duplicate-checks-in-deployer-14 (clean)"
run_test "erc1155-receiver-missing-supportsinterface" "erc1155_receiver_missing_supportsinterface_vulnerable.sol" "erc1155-receiver-missing-supportsinterface"
run_clean_test "erc1155-receiver-missing-supportsinterface" "erc1155_receiver_missing_supportsinterface_clean.sol" "erc1155-receiver-missing-supportsinterface (clean)"
run_test "erc777-re-entrancy-attack" "erc777_re_entrancy_attack_vulnerable.sol" "erc777-re-entrancy-attack"
run_clean_test "erc777-re-entrancy-attack" "erc777_re_entrancy_attack_clean.sol" "erc777-re-entrancy-attack (clean)"
run_test "ethfin-2024-03" "ethfin_2024_03_vulnerable.sol" "ethfin-2024-03"
run_clean_test "ethfin-2024-03" "ethfin_2024_03_clean.sol" "ethfin-2024-03 (clean)"
run_test "extraneous-approval-during-withdrawal" "extraneous_approval_during_withdrawal_vulnerable.sol" "extraneous-approval-during-withdrawal"
run_clean_test "extraneous-approval-during-withdrawal" "extraneous_approval_during_withdrawal_clean.sol" "extraneous-approval-during-withdrawal (clean)"
run_test "forwarder-nonce-increment-on-revert" "forwarder_nonce_increment_on_revert_vulnerable.sol" "forwarder-nonce-increment-on-revert"
run_clean_test "forwarder-nonce-increment-on-revert" "forwarder_nonce_increment_on_revert_clean.sol" "forwarder-nonce-increment-on-revert (clean)"
run_test "gas-optimization" "gas_optimization_vulnerable.sol" "gas-optimization"
run_clean_test "gas-optimization" "gas_optimization_clean.sol" "gas-optimization (clean)"
run_test "ght-2024-03" "ght_2024_03_vulnerable.sol" "ght-2024-03"
run_clean_test "ght-2024-03" "ght_2024_03_clean.sol" "ght-2024-03 (clean)"
run_test "grokd-2024-04" "grokd_2024_04_vulnerable.sol" "grokd-2024-04"
run_clean_test "grokd-2024-04" "grokd_2024_04_clean.sol" "grokd-2024-04 (clean)"
run_test "health-check-bypass-pay-interest" "health_check_bypass_pay_interest_vulnerable.sol" "health-check-bypass-pay-interest"
run_clean_test "health-check-bypass-pay-interest" "health_check_bypass_pay_interest_clean.sol" "health-check-bypass-pay-interest (clean)"
run_test "interface-auto-gen-getter-array-mismatch" "interface_auto_gen_getter_array_mismatch_vulnerable.sol" "interface-auto-gen-getter-array-mismatch"
run_clean_test "interface-auto-gen-getter-array-mismatch" "interface_auto_gen_getter_array_mismatch_clean.sol" "interface-auto-gen-getter-array-mismatch (clean)"
run_test "interface-function-not-in-impl" "interface_function_not_in_impl_vulnerable.sol" "interface-function-not-in-impl"
run_clean_test "interface-function-not-in-impl" "interface_function_not_in_impl_clean.sol" "interface-function-not-in-impl (clean)"
run_test "invalid-threshold-can-halt-the-protocol-30" "invalid_threshold_can_halt_the_protocol_30_vulnerable.sol" "invalid-threshold-can-halt-the-protocol-30"
run_clean_test "invalid-threshold-can-halt-the-protocol-30" "invalid_threshold_can_halt_the_protocol_30_clean.sol" "invalid-threshold-can-halt-the-protocol-30 (clean)"
run_test "islong-flag-not-reset-on-liquidation-long-position-grief" "islong_flag_not_reset_on_liquidation_long_position_grief_vulnerable.sol" "islong-flag-not-reset-on-liquidation-long-position-grief"
run_clean_test "islong-flag-not-reset-on-liquidation-long-position-grief" "islong_flag_not_reset_on_liquidation_long_position_grief_clean.sol" "islong-flag-not-reset-on-liquidation-long-position-grief (clean)"
run_test "lack-of-safe-erc-20-functions" "lack_of_safe_erc_20_functions_vulnerable.sol" "lack-of-safe-erc-20-functions"
run_clean_test "lack-of-safe-erc-20-functions" "lack_of_safe_erc_20_functions_clean.sol" "lack-of-safe-erc-20-functions (clean)"
run_test "laxo-token-2026-02" "laxo_token_2026_02_vulnerable.sol" "laxo-token-2026-02"
run_clean_test "laxo-token-2026-02" "laxo_token_2026_02_clean.sol" "laxo-token-2026-02 (clean)"
run_test "lqdx-alert-2024-01" "lqdx_alert_2024_01_vulnerable.sol" "lqdx-alert-2024-01"
run_clean_test "lqdx-alert-2024-01" "lqdx_alert_2024_01_clean.sol" "lqdx-alert-2024-01 (clean)"
run_test "mft-2024-11" "mft_2024_11_vulnerable.sol" "mft-2024-11"
run_clean_test "mft-2024-11" "mft_2024_11_clean.sol" "mft-2024-11 (clean)"
run_test "missing-balance-difference-check-in-tokenbundleescrowobliga" "missing_balance_difference_check_in_tokenbundleescrowobliga_vulnerable.sol" "missing-balance-difference-check-in-tokenbundleescrowobliga"
run_clean_test "missing-balance-difference-check-in-tokenbundleescrowobliga" "missing_balance_difference_check_in_tokenbundleescrowobliga_clean.sol" "missing-balance-difference-check-in-tokenbundleescrowobliga (clean)"
run_test "missing-result-check-in-transferfrom-helper" "missing_result_check_in_transferfrom_helper_vulnerable.sol" "missing-result-check-in-transferfrom-helper"
run_clean_test "missing-result-check-in-transferfrom-helper" "missing_result_check_in_transferfrom_helper_clean.sol" "missing-result-check-in-transferfrom-helper (clean)"
run_test "missing-safe-transferring-in-some-contracts" "missing_safe_transferring_in_some_contracts_vulnerable.sol" "missing-safe-transferring-in-some-contracts"
run_clean_test "missing-safe-transferring-in-some-contracts" "missing_safe_transferring_in_some_contracts_clean.sol" "missing-safe-transferring-in-some-contracts (clean)"
run_test "mttoken-2026-01" "mttoken_2026_01_vulnerable.sol" "mttoken-2026-01"
run_clean_test "mttoken-2026-01" "mttoken_2026_01_clean.sol" "mttoken-2026-01 (clean)"
run_test "openleverage2-2024-04" "openleverage2_2024_04_vulnerable.sol" "openleverage2-2024-04"
run_clean_test "openleverage2-2024-04" "openleverage2_2024_04_clean.sol" "openleverage2-2024-04 (clean)"
run_test "owner-self-assigns-operator-role-via-default-admin-role" "owner_self_assigns_operator_role_via_default_admin_role_vulnerable.sol" "owner-self-assigns-operator-role-via-default-admin-role"
run_clean_test "owner-self-assigns-operator-role-via-default-admin-role" "owner_self_assigns_operator_role_via_default_admin_role_clean.sol" "owner-self-assigns-operator-role-via-default-admin-role (clean)"
run_test "per-leg-credit-overwritten" "per_leg_credit_overwritten_vulnerable.sol" "per-leg-credit-overwritten"
run_clean_test "per-leg-credit-overwritten" "per_leg_credit_overwritten_clean.sol" "per-leg-credit-overwritten (clean)"
run_test "pool-graduation-preseed-check-missing" "pool_graduation_preseed_check_missing_vulnerable.sol" "pool-graduation-preseed-check-missing"
run_clean_test "pool-graduation-preseed-check-missing" "pool_graduation_preseed_check_missing_clean.sol" "pool-graduation-preseed-check-missing (clean)"
run_test "public-pulltoken-function-allows-to-steal-erc20-tokens-for" "public_pulltoken_function_allows_to_steal_erc20_tokens_for_vulnerable.sol" "public-pulltoken-function-allows-to-steal-erc20-tokens-for"
run_clean_test "public-pulltoken-function-allows-to-steal-erc20-tokens-for" "public_pulltoken_function_allows_to_steal_erc20_tokens_for_clean.sol" "public-pulltoken-function-allows-to-steal-erc20-tokens-for (clean)"
run_test "raw-erc-20-interface-usage" "raw_erc_20_interface_usage_vulnerable.sol" "raw-erc-20-interface-usage"
run_clean_test "raw-erc-20-interface-usage" "raw_erc_20_interface_usage_clean.sol" "raw-erc-20-interface-usage (clean)"
run_test "return-value-from-transferfrom-should-be-checked" "return_value_from_transferfrom_should_be_checked_vulnerable.sol" "return-value-from-transferfrom-should-be-checked"
run_clean_test "return-value-from-transferfrom-should-be-checked" "return_value_from_transferfrom_should_be_checked_clean.sol" "return-value-from-transferfrom-should-be-checked (clean)"
run_test "reward-distribution-precision-loss" "reward_distribution_precision_loss_vulnerable.sol" "reward-distribution-precision-loss"
run_clean_test "reward-distribution-precision-loss" "reward_distribution_precision_loss_clean.sol" "reward-distribution-precision-loss (clean)"
run_test "round-in-flight-admin-setter" "round_in_flight_admin_setter_vulnerable.sol" "round-in-flight-admin-setter"
run_clean_test "round-in-flight-admin-setter" "round_in_flight_admin_setter_clean.sol" "round-in-flight-admin-setter (clean)"
run_test "rounding-errors-in-computing-fee-13" "rounding_errors_in_computing_fee_13_vulnerable.sol" "rounding-errors-in-computing-fee-13"
run_clean_test "rounding-errors-in-computing-fee-13" "rounding_errors_in_computing_fee_13_clean.sol" "rounding-errors-in-computing-fee-13 (clean)"
run_test "saturn-2024-05" "saturn_2024_05_vulnerable.sol" "saturn-2024-05"
run_clean_test "saturn-2024-05" "saturn_2024_05_clean.sol" "saturn-2024-05 (clean)"
run_test "scroll-2024-05" "scroll_2024_05_vulnerable.sol" "scroll-2024-05"
run_clean_test "scroll-2024-05" "scroll_2024_05_clean.sol" "scroll-2024-05 (clean)"
run_test "signature-clash-allows-calls-to-transferreserve-to-steal-nft" "signature_clash_allows_calls_to_transferreserve_to_steal_nft_vulnerable.sol" "signature-clash-allows-calls-to-transferreserve-to-steal-nft"
run_clean_test "signature-clash-allows-calls-to-transferreserve-to-steal-nft" "signature_clash_allows_calls_to_transferreserve_to_steal_nft_clean.sol" "signature-clash-allows-calls-to-transferreserve-to-steal-nft (clean)"
run_test "sizecredit-2025-08" "sizecredit_2025_08_vulnerable.sol" "sizecredit-2025-08"
run_clean_test "sizecredit-2025-08" "sizecredit_2025_08_clean.sol" "sizecredit-2025-08 (clean)"
run_test "sss-2024-03" "sss_2024_03_vulnerable.sol" "sss-2024-03"
run_clean_test "sss-2024-03" "sss_2024_03_clean.sol" "sss-2024-03 (clean)"
run_test "tree-tail-removal-no-size-decrement" "tree_tail_removal_no_size_decrement_vulnerable.sol" "tree-tail-removal-no-size-decrement"
run_clean_test "tree-tail-removal-no-size-decrement" "tree_tail_removal_no_size_decrement_clean.sol" "tree-tail-removal-no-size-decrement (clean)"
run_test "unhandled-return-value-of-collateral-transfer" "unhandled_return_value_of_collateral_transfer_vulnerable.sol" "unhandled-return-value-of-collateral-transfer"
run_clean_test "unhandled-return-value-of-collateral-transfer" "unhandled_return_value_of_collateral_transfer_clean.sol" "unhandled-return-value-of-collateral-transfer (clean)"
run_test "unneeded-receive-function-12" "unneeded_receive_function_12_vulnerable.sol" "unneeded-receive-function-12"
run_clean_test "unneeded-receive-function-12" "unneeded_receive_function_12_clean.sol" "unneeded-receive-function-12 (clean)"
run_test "use-safe-erc20-functions" "use_safe_erc20_functions_vulnerable.sol" "use-safe-erc20-functions"
run_clean_test "use-safe-erc20-functions" "use_safe_erc20_functions_clean.sol" "use-safe-erc20-functions (clean)"
run_test "users-can-cast-their-votes-multiple-times-for-the-proposal-b-x" "users_can_cast_their_votes_multiple_times_for_the_proposal_b_x_vulnerable.sol" "users-can-cast-their-votes-multiple-times-for-the-proposal-b-x"
run_clean_test "users-can-cast-their-votes-multiple-times-for-the-proposal-b-x" "users_can_cast_their_votes_multiple_times_for_the_proposal_b_x_clean.sol" "users-can-cast-their-votes-multiple-times-for-the-proposal-b-x (clean)"
run_test "v1-v2-domain-collision" "v1_v2_domain_collision_vulnerable.sol" "v1-v2-domain-collision"
run_clean_test "v1-v2-domain-collision" "v1_v2_domain_collision_clean.sol" "v1-v2-domain-collision (clean)"
run_test "wiselending02-2024-01" "wiselending02_2024_01_vulnerable.sol" "wiselending02-2024-01"
run_clean_test "wiselending02-2024-01" "wiselending02_2024_01_clean.sol" "wiselending02-2024-01 (clean)"
run_test "wrapnativetokeninwallet-always-reverts-on-arbitrum" "wrapnativetokeninwallet_always_reverts_on_arbitrum_vulnerable.sol" "wrapnativetokeninwallet-always-reverts-on-arbitrum"
run_clean_test "wrapnativetokeninwallet-always-reverts-on-arbitrum" "wrapnativetokeninwallet_always_reverts_on_arbitrum_clean.sol" "wrapnativetokeninwallet-always-reverts-on-arbitrum (clean)"
run_test "ybtoken-2025-04" "ybtoken_2025_04_vulnerable.sol" "ybtoken-2025-04"
run_clean_test "ybtoken-2025-04" "ybtoken_2025_04_clean.sol" "ybtoken-2025-04 (clean)"


# Generated by gen-detector.py — 19 detectors


# Generated by gen-detector.py — 1 detectors
run_test "erc4626-share-inflation-at-zero-total" "erc4626_share_inflation_at_zero_total_vulnerable.sol" "erc4626-share-inflation-at-zero-total"
run_clean_test "erc4626-share-inflation-at-zero-total" "erc4626_share_inflation_at_zero_total_clean.sol" "erc4626-share-inflation-at-zero-total (clean)"


# Generated by gen-detector.py — 1 detectors
run_test "conditional-skip-before-stateful-external-call" "conditional_skip_before_stateful_external_call_vulnerable.sol" "conditional-skip-before-stateful-external-call"
run_clean_test "conditional-skip-before-stateful-external-call" "conditional_skip_before_stateful_external_call_clean.sol" "conditional-skip-before-stateful-external-call (clean)"


# Generated by gen-detector.py — 1 detectors


# Generated by gen-detector.py — 1 detectors
run_test "unchecked-compound-v2-return-code" "unchecked_compound_v2_return_code_vulnerable.sol" "unchecked-compound-v2-return-code"
run_clean_test "unchecked-compound-v2-return-code" "unchecked_compound_v2_return_code_clean.sol" "unchecked-compound-v2-return-code (clean)"


# Generated by gen-detector.py — 1 detectors
run_test "callback-reentrancy-no-guard" "callback_reentrancy_no_guard_vulnerable.sol" "callback-reentrancy-no-guard"
run_clean_test "callback-reentrancy-no-guard" "callback_reentrancy_no_guard_clean.sol" "callback-reentrancy-no-guard (clean)"


# PR #121 W5 — interface-function-missing (DSL-first, Codex three-star)
run_test       "interface-function-missing" "interface_function_missing_vulnerable.sol" "interface-function-missing"
run_clean_test "interface-function-missing" "interface_function_missing_clean.sol"      "interface-function-missing (clean)"

# PR #121 W5 — asset-type-mismatch-on-refund (DSL-first, Codex three-star)
run_test       "asset-type-mismatch-on-refund" "asset_type_mismatch_on_refund_vulnerable.sol" "asset-type-mismatch-on-refund"
run_clean_test "asset-type-mismatch-on-refund" "asset_type_mismatch_on_refund_clean.sol"      "asset-type-mismatch-on-refund (clean)"

# PR #121 A9 — legacy-vs-current-shadow-code-path (advisory). PR #132 Codex
# blocker regression: clean fixture has `function legacySettle(...) external
# pure { revert("deprecated"); }` and MUST stay silent. The earlier
# `^\s*revert\s*\(` regex was broken because `function.source_mapping.content`
# includes the signature before the body, so the start-of-string anchor never
# matched and the detector fired on the clean shape. Fixed to `\brevert\s*\(`.
run_test "legacy-vs-current-shadow-code-path" "legacy_vs_current_shadow_code_path_vulnerable.sol" "legacy-vs-current-shadow-code-path"
run_clean_test "legacy-vs-current-shadow-code-path" "legacy_vs_current_shadow_code_path_clean.sol" "legacy-vs-current-shadow-code-path (clean)"
# PR #121 W5 — flashloan-callback-missing-initiator-check (DSL-first, Codex three-star)
run_test       "flashloan-callback-missing-initiator-check" "flashloan_callback_missing_initiator_check_vulnerable.sol" "flashloan-callback-missing-initiator-check"
run_clean_test "flashloan-callback-missing-initiator-check" "flashloan_callback_missing_initiator_check_clean.sol"      "flashloan-callback-missing-initiator-check (clean)"

# Wave 18 hand-written: library-memory-copy-not-writeback (caller-side IR analysis)
run_test       "library-memory-copy-not-writeback" "library_memory_copy_not_writeback_vulnerable.sol" "library-memory-copy-not-writeback"
run_clean_test "library-memory-copy-not-writeback" "library_memory_copy_not_writeback_clean.sol"      "library-memory-copy-not-writeback (clean)"


# PR #121 W5 — forwarder-nonce-on-revert (CFG hand-written, Codex three-star)
run_test       "forwarder-nonce-on-revert" "forwarder_nonce_on_revert_vulnerable.sol" "forwarder-nonce-on-revert"
run_clean_test "forwarder-nonce-on-revert" "forwarder_nonce_on_revert_clean.sol"      "forwarder-nonce-on-revert (clean)"

# PR #172 cross-engagement mining — 3 detectors
run_test "settle-batch-refund-flushes-self-balance" "settle-batch-refund-flushes-self-balance_vuln.sol" "settle-batch-refund-flushes-self-balance"
run_clean_test "settle-batch-refund-flushes-self-balance" "settle-batch-refund-flushes-self-balance_clean.sol" "settle-batch-refund-flushes-self-balance (clean)"
run_test "branch-status-update-without-recipient-reassignment" "branch-status-update-without-recipient-reassignment_vuln.sol" "branch-status-update-without-recipient-reassignment"
run_clean_test "branch-status-update-without-recipient-reassignment" "branch-status-update-without-recipient-reassignment_clean.sol" "branch-status-update-without-recipient-reassignment (clean)"
run_test "one-way-circuit-breaker-no-recovery-on-shared-singleton" "one-way-circuit-breaker-no-recovery-on-shared-singleton_vuln.sol" "one-way-circuit-breaker-no-recovery-on-shared-singleton"
run_clean_test "one-way-circuit-breaker-no-recovery-on-shared-singleton" "one-way-circuit-breaker-no-recovery-on-shared-singleton_clean.sol" "one-way-circuit-breaker-no-recovery-on-shared-singleton (clean)"

# 2026-04 exploit mining — 5 detectors from defimon_alerts feed
# (Giddy $1.3M / Kipseli $72K / Juicebox $52K / LootBot $9.6K / Hyperbridge $237K)
run_test       "eip712-typehash-omits-trusted-swap-fields"  "eip712_typehash_omits_trusted_swap_fields_vulnerable.sol"  "eip712-typehash-omits-trusted-swap-fields"
run_clean_test "eip712-typehash-omits-trusted-swap-fields"  "eip712_typehash_omits_trusted_swap_fields_clean.sol"       "eip712-typehash-omits-trusted-swap-fields (clean)"
run_test       "signer-binds-tokens-only-not-amount"        "signer_binds_tokens_only_not_amount_vulnerable.sol"        "signer-binds-tokens-only-not-amount"
run_clean_test "signer-binds-tokens-only-not-amount"        "signer_binds_tokens_only_not_amount_clean.sol"             "signer-binds-tokens-only-not-amount (clean)"
run_test       "borrow-source-not-verified-against-registry" "borrow_source_not_verified_against_registry_vulnerable.sol" "borrow-source-not-verified-against-registry"
run_clean_test "borrow-source-not-verified-against-registry" "borrow_source_not_verified_against_registry_clean.sol"      "borrow-source-not-verified-against-registry (clean)"
run_test       "redeem-array-deferred-update-duplicate-ids" "redeem_array_deferred_update_duplicate_ids_vulnerable.sol" "redeem-array-deferred-update-duplicate-ids"
run_clean_test "redeem-array-deferred-update-duplicate-ids" "redeem_array_deferred_update_duplicate_ids_clean.sol"      "redeem-array-deferred-update-duplicate-ids (clean)"
run_test       "merkle-leaf-count-one-trivial-proof"        "merkle_leaf_count_one_trivial_proof_vulnerable.sol"        "merkle-leaf-count-one-trivial-proof"
run_clean_test "merkle-leaf-count-one-trivial-proof"        "merkle_leaf_count_one_trivial_proof_clean.sol"             "merkle-leaf-count-one-trivial-proof (clean)"

# Defimon deep-mining — 3 patterns from t.me/s/defimon_alerts (R96)
run_test       "staking-claim-immediate-roi-no-cooldown-stake"            "staking-claim-immediate-roi-no-cooldown-stake_vuln.sol"            "staking-claim-immediate-roi-no-cooldown-stake"
run_clean_test "staking-claim-immediate-roi-no-cooldown-stake"            "staking-claim-immediate-roi-no-cooldown-stake_clean.sol"           "staking-claim-immediate-roi-no-cooldown-stake (clean)"
run_test       "staking-claim-pays-from-accumulated-not-funded-balance"   "staking-claim-pays-from-accumulated-not-funded-balance_vuln.sol"   "staking-claim-pays-from-accumulated-not-funded-balance"
run_clean_test "staking-claim-pays-from-accumulated-not-funded-balance"   "staking-claim-pays-from-accumulated-not-funded-balance_clean.sol"  "staking-claim-pays-from-accumulated-not-funded-balance (clean)"
run_test       "amm-pool-storage-not-cleared-after-position-burn"         "amm-pool-storage-not-cleared-after-position-burn_vuln.sol"         "amm-pool-storage-not-cleared-after-position-burn"
run_clean_test "amm-pool-storage-not-cleared-after-position-burn"         "amm-pool-storage-not-cleared-after-position-burn_clean.sol"        "amm-pool-storage-not-cleared-after-position-burn (clean)"

# Defimon bulk-mining — 4 patterns from t.me/s/defimon_alerts (Apr 2026)
run_test       "router-payer-from-calldata-tail-not-bound-to-signature" "router-payer-from-calldata-tail-not-bound-to-signature_vuln.sol" "router-payer-from-calldata-tail-not-bound-to-signature"
run_clean_test "router-payer-from-calldata-tail-not-bound-to-signature" "router-payer-from-calldata-tail-not-bound-to-signature_clean.sol" "router-payer-from-calldata-tail-not-bound-to-signature (clean)"
run_test       "univ4-hook-midpoint-average-not-time-weighted-integral" "univ4-hook-midpoint-average-not-time-weighted-integral_vuln.sol" "univ4-hook-midpoint-average-not-time-weighted-integral"
run_clean_test "univ4-hook-midpoint-average-not-time-weighted-integral" "univ4-hook-midpoint-average-not-time-weighted-integral_clean.sol" "univ4-hook-midpoint-average-not-time-weighted-integral (clean)"
run_test       "bonding-curve-buy-unchecked-mul-mints-massive-supply"   "bonding-curve-buy-unchecked-mul-mints-massive-supply_vuln.sol"   "bonding-curve-buy-unchecked-mul-mints-massive-supply"
run_clean_test "bonding-curve-buy-unchecked-mul-mints-massive-supply"   "bonding-curve-buy-unchecked-mul-mints-massive-supply_clean.sol"   "bonding-curve-buy-unchecked-mul-mints-massive-supply (clean)"
run_test       "staking-reward-period-restart-credits-historical-debt"  "staking-reward-period-restart-credits-historical-debt_vuln.sol"  "staking-reward-period-restart-credits-historical-debt"
run_clean_test "staking-reward-period-restart-credits-historical-debt"  "staking-reward-period-restart-credits-historical-debt_clean.sol"  "staking-reward-period-restart-credits-historical-debt (clean)"

# Defimon bulk-mining — MONA add-back (was DROPPED in PR #231; writeup now available)
run_test       "deferred-burn-credit-settled-against-pair-reserves"     "deferred-burn-credit-settled-against-pair-reserves_vuln.sol"     "deferred-burn-credit-settled-against-pair-reserves"
run_clean_test "deferred-burn-credit-settled-against-pair-reserves"     "deferred-burn-credit-settled-against-pair-reserves_clean.sol"     "deferred-burn-credit-settled-against-pair-reserves (clean)"

# r106 centrifuge-v3 source-mine — 7 generic patterns from BatchRequestManager / AsyncRequestManager / SyncManager / MessageProcessor / VaultRegistry / NAVManager / OracleValuation source surface, evidenced by both Kimi and MiniMax
run_test       "batch-claim-loop-cancel-overwrites-last-write"          "batch-claim-loop-cancel-overwrites-last-write_vulnerable.sol"          "batch-claim-loop-cancel-overwrites-last-write"
run_clean_test "batch-claim-loop-cancel-overwrites-last-write"          "batch-claim-loop-cancel-overwrites-last-write_clean.sol"               "batch-claim-loop-cancel-overwrites-last-write (clean)"
run_test       "uint256-check-uint128-transfer-truncation-asymmetry"    "uint256-check-uint128-transfer-truncation-asymmetry_vulnerable.sol"    "uint256-check-uint128-transfer-truncation-asymmetry"
run_clean_test "uint256-check-uint128-transfer-truncation-asymmetry"    "uint256-check-uint128-transfer-truncation-asymmetry_clean.sol"         "uint256-check-uint128-transfer-truncation-asymmetry (clean)"
run_test       "erc6909-conditional-allowance-bypass-on-tokenid"        "erc6909-conditional-allowance-bypass-on-tokenid_vulnerable.sol"        "erc6909-conditional-allowance-bypass-on-tokenid"
run_clean_test "erc6909-conditional-allowance-bypass-on-tokenid"        "erc6909-conditional-allowance-bypass-on-tokenid_clean.sol"             "erc6909-conditional-allowance-bypass-on-tokenid (clean)"
run_test       "crosschain-handler-partial-source-chain-validation"     "crosschain-handler-partial-source-chain-validation_vulnerable.sol"     "crosschain-handler-partial-source-chain-validation"
run_clean_test "crosschain-handler-partial-source-chain-validation"     "crosschain-handler-partial-source-chain-validation_clean.sol"          "crosschain-handler-partial-source-chain-validation (clean)"
run_test       "registry-link-overwrites-existing-mapping-no-asset-key-check"  "registry-link-overwrites-existing-mapping-no-asset-key-check_vulnerable.sol"  "registry-link-overwrites-existing-mapping-no-asset-key-check"
run_clean_test "registry-link-overwrites-existing-mapping-no-asset-key-check"  "registry-link-overwrites-existing-mapping-no-asset-key-check_clean.sol"       "registry-link-overwrites-existing-mapping-no-asset-key-check (clean)"
run_test       "nav-aggregator-clamps-negative-diff-to-zero-skews-multipool-readers"  "nav-aggregator-clamps-negative-diff-to-zero-skews-multipool-readers_vulnerable.sol"  "nav-aggregator-clamps-negative-diff-to-zero-skews-multipool-readers"
run_clean_test "nav-aggregator-clamps-negative-diff-to-zero-skews-multipool-readers"  "nav-aggregator-clamps-negative-diff-to-zero-skews-multipool-readers_clean.sol"       "nav-aggregator-clamps-negative-diff-to-zero-skews-multipool-readers (clean)"
run_test       "preview-deposit-restriction-checks-receiver-only-execution-skips-owner"  "preview-deposit-restriction-checks-receiver-only-execution-skips-owner_vulnerable.sol"  "preview-deposit-restriction-checks-receiver-only-execution-skips-owner"
run_clean_test "preview-deposit-restriction-checks-receiver-only-execution-skips-owner"  "preview-deposit-restriction-checks-receiver-only-execution-skips-owner_clean.sol"       "preview-deposit-restriction-checks-receiver-only-execution-skips-owner (clean)"
# R107 thegraph-source-mine — 7 patterns from Trust + OZ Horizon audits
run_test       "unsafe-uint64-cast-block-timestamp-plus-period"            "unsafe_uint64_cast_block_timestamp_plus_period_vulnerable.sol"            "unsafe-uint64-cast-block-timestamp-plus-period"
run_clean_test "unsafe-uint64-cast-block-timestamp-plus-period"            "unsafe_uint64_cast_block_timestamp_plus_period_clean.sol"                 "unsafe-uint64-cast-block-timestamp-plus-period (clean)"
run_test       "slash-thawing-pool-rounds-up-via-fraction-complement"      "slash_thawing_pool_rounds_up_via_fraction_complement_vulnerable.sol"      "slash-thawing-pool-rounds-up-via-fraction-complement"
run_clean_test "slash-thawing-pool-rounds-up-via-fraction-complement"      "slash_thawing_pool_rounds_up_via_fraction_complement_clean.sol"           "slash-thawing-pool-rounds-up-via-fraction-complement (clean)"
run_test       "view-aggregator-no-epoch-or-nonce-filter"                  "view_aggregator_no_epoch_or_nonce_filter_vulnerable.sol"                  "view-aggregator-no-epoch-or-nonce-filter"
run_clean_test "view-aggregator-no-epoch-or-nonce-filter"                  "view_aggregator_no_epoch_or_nonce_filter_clean.sol"                       "view-aggregator-no-epoch-or-nonce-filter (clean)"
run_test       "set-recipient-skips-flush-pending-stream"                  "set_recipient_skips_flush_pending_stream_vulnerable.sol"                  "set-recipient-skips-flush-pending-stream"
run_clean_test "set-recipient-skips-flush-pending-stream"                  "set_recipient_skips_flush_pending_stream_clean.sol"                       "set-recipient-skips-flush-pending-stream (clean)"
run_test       "chained-subtraction-no-overflow-guard"                     "chained_subtraction_no_overflow_guard_vulnerable.sol"                     "chained-subtraction-no-overflow-guard"
run_clean_test "chained-subtraction-no-overflow-guard"                     "chained_subtraction_no_overflow_guard_clean.sol"                          "chained-subtraction-no-overflow-guard (clean)"
run_test       "monotonic-counter-strict-gt-allows-replay-at-equal"        "monotonic_counter_strict_gt_allows_replay_at_equal_vulnerable.sol"        "monotonic-counter-strict-gt-allows-replay-at-equal"
run_clean_test "monotonic-counter-strict-gt-allows-replay-at-equal"        "monotonic_counter_strict_gt_allows_replay_at_equal_clean.sol"             "monotonic-counter-strict-gt-allows-replay-at-equal (clean)"
run_test       "permissionless-add-to-bounded-victim-position"             "permissionless_add_to_bounded_victim_position_vulnerable.sol"             "permissionless-add-to-bounded-victim-position"
run_clean_test "permissionless-add-to-bounded-victim-position"             "permissionless_add_to_bounded_victim_position_clean.sol"                  "permissionless-add-to-bounded-victim-position (clean)"
# Polymarket source-mine R112 — 3 generic detectors from CTFExchange v2 + collateral + factories
run_test       "hardcoded-binary-partition-ctf-integration"             "hardcoded-binary-partition-ctf-integration_vuln.sol"             "hardcoded-binary-partition-ctf-integration"
run_clean_test "hardcoded-binary-partition-ctf-integration"             "hardcoded-binary-partition-ctf-integration_clean.sol"            "hardcoded-binary-partition-ctf-integration (clean)"
run_test       "wrap-mint-before-vault-transfer-callback-window"        "wrap-mint-before-vault-transfer-callback-window_vuln.sol"        "wrap-mint-before-vault-transfer-callback-window"
run_clean_test "wrap-mint-before-vault-transfer-callback-window"        "wrap-mint-before-vault-transfer-callback-window_clean.sol"       "wrap-mint-before-vault-transfer-callback-window (clean)"
run_test       "factory-create-proxy-eip712-no-nonce-no-deadline"       "factory-create-proxy-eip712-no-nonce-no-deadline_vuln.sol"       "factory-create-proxy-eip712-no-nonce-no-deadline"
run_clean_test "factory-create-proxy-eip712-no-nonce-no-deadline"       "factory-create-proxy-eip712-no-nonce-no-deadline_clean.sol"      "factory-create-proxy-eip712-no-nonce-no-deadline (clean)"
# P1 fixture extraction — polymarket bucket demo (workspace-cited residue from PR #289 triage)
run_test       "balance-of-self-instead-of-delta-consumes-donations" "balance-of-self-instead-of-delta-consumes-donations_vulnerable.sol" "balance-of-self-instead-of-delta-consumes-donations"
run_clean_test "balance-of-self-instead-of-delta-consumes-donations" "balance-of-self-instead-of-delta-consumes-donations_clean.sol"      "balance-of-self-instead-of-delta-consumes-donations (clean)"
# R109 — Snowbridge / Polkadot-Ethereum bridge generic patterns (BeefyClient + Gateway + storage migration)
run_test       "bridge-batch-dispatch-try-catch-continue-partial-state"  "bridge_batch_dispatch_try_catch_continue_partial_state_vulnerable.sol"  "bridge-batch-dispatch-try-catch-continue-partial-state"
run_clean_test "bridge-batch-dispatch-try-catch-continue-partial-state"  "bridge_batch_dispatch_try_catch_continue_partial_state_clean.sol"        "bridge-batch-dispatch-try-catch-continue-partial-state (clean)"
run_test       "erc7201-namespace-struct-field-removal-slot-collision"   "erc7201_namespace_struct_field_removal_slot_collision_vulnerable.sol"   "erc7201-namespace-struct-field-removal-slot-collision"
run_clean_test "erc7201-namespace-struct-field-removal-slot-collision"   "erc7201_namespace_struct_field_removal_slot_collision_clean.sol"        "erc7201-namespace-struct-field-removal-slot-collision (clean)"
run_test       "bridge-versioned-digest-tag-not-bound-to-version-flag"   "bridge_versioned_digest_tag_not_bound_to_version_flag_vulnerable.sol"   "bridge-versioned-digest-tag-not-bound-to-version-flag"
run_clean_test "bridge-versioned-digest-tag-not-bound-to-version-flag"   "bridge_versioned_digest_tag_not_bound_to_version_flag_clean.sol"        "bridge-versioned-digest-tag-not-bound-to-version-flag (clean)"
run_test       "bridge-relayer-reward-paid-on-failed-dispatch"           "bridge_relayer_reward_paid_on_failed_dispatch_vulnerable.sol"           "bridge-relayer-reward-paid-on-failed-dispatch"
run_clean_test "bridge-relayer-reward-paid-on-failed-dispatch"           "bridge_relayer_reward_paid_on_failed_dispatch_clean.sol"                "bridge-relayer-reward-paid-on-failed-dispatch (clean)"
run_test       "bridge-outbound-no-fee-floor-zero-message-spam"          "bridge_outbound_no_fee_floor_zero_message_spam_vulnerable.sol"          "bridge-outbound-no-fee-floor-zero-message-spam"
run_clean_test "bridge-outbound-no-fee-floor-zero-message-spam"          "bridge_outbound_no_fee_floor_zero_message_spam_clean.sol"               "bridge-outbound-no-fee-floor-zero-message-spam (clean)"
run_test       "bridge-strict-channel-nonce-blocks-governance"           "bridge_strict_channel_nonce_blocks_governance_vulnerable.sol"           "bridge-strict-channel-nonce-blocks-governance"
run_clean_test "bridge-strict-channel-nonce-blocks-governance"           "bridge_strict_channel_nonce_blocks_governance_clean.sol"                "bridge-strict-channel-nonce-blocks-governance (clean)"
run_test       "library-external-handler-callable-bypasses-onlyself"     "library_external_handler_callable_bypasses_onlyself_vulnerable.sol"     "library-external-handler-callable-bypasses-onlyself"
run_clean_test "library-external-handler-callable-bypasses-onlyself"     "library_external_handler_callable_bypasses_onlyself_clean.sol"          "library-external-handler-callable-bypasses-onlyself (clean)"
# R111 — base-azul source-mining (Engagement-3 AggregateVerifier / AnchorStateRegistry / Verifier)
run_test       "per-element-blacklist-without-ancestry-cascade-in-tree-state" "per_element_blacklist_without_ancestry_cascade_in_tree_state_vulnerable.sol" "per-element-blacklist-without-ancestry-cascade-in-tree-state"
run_clean_test "per-element-blacklist-without-ancestry-cascade-in-tree-state" "per_element_blacklist_without_ancestry_cascade_in_tree_state_clean.sol"      "per-element-blacklist-without-ancestry-cascade-in-tree-state (clean)"
run_test       "validity-threshold-bump-leaves-stale-pointer-without-reset"   "validity_threshold_bump_leaves_stale_pointer_without_reset_vulnerable.sol"   "validity-threshold-bump-leaves-stale-pointer-without-reset"
run_clean_test "validity-threshold-bump-leaves-stale-pointer-without-reset"   "validity_threshold_bump_leaves_stale_pointer_without_reset_clean.sol"        "validity-threshold-bump-leaves-stale-pointer-without-reset (clean)"
run_test       "clone-only-gate-permits-shared-singleton-bricking"            "clone_only_gate_permits_shared_singleton_bricking_vulnerable.sol"            "clone-only-gate-permits-shared-singleton-bricking"
run_clean_test "clone-only-gate-permits-shared-singleton-bricking"            "clone_only_gate_permits_shared_singleton_bricking_clean.sol"                 "clone-only-gate-permits-shared-singleton-bricking (clean)"

# P1 fixture extraction — morpho bucket
run_test       "fx-morpho-create-market-irm-zero-call"                         "fx_morpho_create_market_irm_zero_call_vulnerable.sol"                         "fx-morpho-create-market-irm-zero-call"
run_clean_test "fx-morpho-create-market-irm-zero-call"                         "fx_morpho_create_market_irm_zero_call_clean.sol"                              "fx-morpho-create-market-irm-zero-call (clean)"
run_test       "fx-morpho-flashloan-zero-assets"                               "fx_morpho_flashloan_zero_assets_vulnerable.sol"                               "fx-morpho-flashloan-zero-assets"
run_clean_test "fx-morpho-flashloan-zero-assets"                               "fx_morpho_flashloan_zero_assets_clean.sol"                                    "fx-morpho-flashloan-zero-assets (clean)"
run_test       "fx-morpho-liquidation-rounding-double-conversion"              "fx_morpho_liquidation_rounding_double_conversion_vulnerable.sol"              "fx-morpho-liquidation-rounding-double-conversion"
run_clean_test "fx-morpho-liquidation-rounding-double-conversion"              "fx_morpho_liquidation_rounding_double_conversion_clean.sol"                   "fx-morpho-liquidation-rounding-double-conversion (clean)"
run_test       "fx-morpho-safe-transfer-no-code-check"                         "fx_morpho_safe_transfer_no_code_check_vulnerable.sol"                         "fx-morpho-safe-transfer-no-code-check"
run_clean_test "fx-morpho-safe-transfer-no-code-check"                         "fx_morpho_safe_transfer_no_code_check_clean.sol"                              "fx-morpho-safe-transfer-no-code-check (clean)"
run_test       "accrue-interest-irm-callback-before-lastupdate-write"          "accrue_interest_irm_callback_before_lastupdate_write_vulnerable.sol"          "accrue-interest-irm-callback-before-lastupdate-write"
run_clean_test "accrue-interest-irm-callback-before-lastupdate-write"          "accrue_interest_irm_callback_before_lastupdate_write_clean.sol"               "accrue-interest-irm-callback-before-lastupdate-write (clean)"
run_test       "bad-debt-realization-underflow-shares-inflated"                "bad_debt_realization_underflow_shares_inflated_vulnerable.sol"                "bad-debt-realization-underflow-shares-inflated"
run_clean_test "bad-debt-realization-underflow-shares-inflated"                "bad_debt_realization_underflow_shares_inflated_clean.sol"                     "bad-debt-realization-underflow-shares-inflated (clean)"
run_test       "repay-assetsup-exceeds-total-borrow-underflow"                 "repay_assetsup_exceeds_total_borrow_underflow_vulnerable.sol"                 "repay-assetsup-exceeds-total-borrow-underflow"
run_clean_test "repay-assetsup-exceeds-total-borrow-underflow"                 "repay_assetsup_exceeds_total_borrow_underflow_clean.sol"                      "repay-assetsup-exceeds-total-borrow-underflow (clean)"

# P1 fixture extraction — post-PR #350 deferred retry
run_test       "payable-branch-ignores-msgvalue-no-refund"          "payable_branch_ignores_msgvalue_no_refund_vulnerable.sol"          "payable-branch-ignores-msgvalue-no-refund"
run_clean_test "payable-branch-ignores-msgvalue-no-refund"          "payable_branch_ignores_msgvalue_no_refund_clean.sol"               "payable-branch-ignores-msgvalue-no-refund (clean)"
run_test       "unauth-balance-sweep-to-caller-recipient"           "unauth_balance_sweep_to_caller_recipient_vulnerable.sol"           "unauth-balance-sweep-to-caller-recipient"
run_clean_test "unauth-balance-sweep-to-caller-recipient"           "unauth_balance_sweep_to_caller_recipient_clean.sol"                "unauth-balance-sweep-to-caller-recipient (clean)"
run_test       "division-to-zero-solvency"                          "division_to_zero_solvency_vulnerable.sol"                          "division-to-zero-solvency"
run_clean_test "division-to-zero-solvency"                          "division_to_zero_solvency_clean.sol"                               "division-to-zero-solvency (clean)"
run_test       "missing-two-step-ownership-transfer"                "missing_two_step_ownership_transfer_vulnerable.sol"                "missing-two-step-ownership-transfer"
run_clean_test "missing-two-step-ownership-transfer"                "missing_two_step_ownership_transfer_clean.sol"                     "missing-two-step-ownership-transfer (clean)"

# P1 fixture extraction — Kelp rsETH archive queue
run_test       "r94-loop-bridge-destination-adapter-ignores-source-pause-state" "r94_loop_bridge_destination_adapter_ignores_source_pause_state_vulnerable.sol" "r94-loop-bridge-destination-adapter-ignores-source-pause-state"
run_clean_test "r94-loop-bridge-destination-adapter-ignores-source-pause-state" "r94_loop_bridge_destination_adapter_ignores_source_pause_state_clean.sol"      "r94-loop-bridge-destination-adapter-ignores-source-pause-state (clean)"
run_test       "r94-loop-bridge-pause-only-tokens-not-attestation-layer"        "r94_loop_bridge_pause_only_tokens_not_attestation_layer_vulnerable.sol"        "r94-loop-bridge-pause-only-tokens-not-attestation-layer"
run_clean_test "r94-loop-bridge-pause-only-tokens-not-attestation-layer"        "r94_loop_bridge_pause_only_tokens_not_attestation_layer_clean.sol"             "r94-loop-bridge-pause-only-tokens-not-attestation-layer (clean)"
run_test       "r94-loop-bridge-receive-library-quorum-single-signer-is-sole-gate" "r94_loop_bridge_receive_library_quorum_single_signer_is_sole_gate_vulnerable.sol" "r94-loop-bridge-receive-library-quorum-single-signer-is-sole-gate"
run_clean_test "r94-loop-bridge-receive-library-quorum-single-signer-is-sole-gate" "r94_loop_bridge_receive_library_quorum_single_signer_is_sole_gate_clean.sol"      "r94-loop-bridge-receive-library-quorum-single-signer-is-sole-gate (clean)"

# P1 fixture extraction — reverse-port archive queue
run_test       "r94-reverse-rewards-accrual-double-count-self-transfer" "r94_reverse_rewards_accrual_double_count_self_transfer_vulnerable.sol" "r94-reverse-rewards-accrual-double-count-self-transfer"
run_clean_test "r94-reverse-rewards-accrual-double-count-self-transfer" "r94_reverse_rewards_accrual_double_count_self_transfer_clean.sol"      "r94-reverse-rewards-accrual-double-count-self-transfer (clean)"
run_test       "r94-reverse-flashloan-callback-state-mutation-before-repay" "r94_reverse_flashloan_callback_state_mutation_before_repay_vulnerable.sol" "r94-reverse-flashloan-callback-state-mutation-before-repay"
run_clean_test "r94-reverse-flashloan-callback-state-mutation-before-repay" "r94_reverse_flashloan_callback_state_mutation_before_repay_clean.sol"      "r94-reverse-flashloan-callback-state-mutation-before-repay (clean)"
run_test       "r94-reverse-fee-charged-to-wrong-party" "r94_reverse_fee_charged_to_wrong_party_vulnerable.sol" "r94-reverse-fee-charged-to-wrong-party"
run_clean_test "r94-reverse-fee-charged-to-wrong-party" "r94_reverse_fee_charged_to_wrong_party_clean.sol"      "r94-reverse-fee-charged-to-wrong-party (clean)"
run_test       "r94-reverse-rewards-claim-all-missing-per-pool-settle" "r94_reverse_rewards_claim_all_missing_per_pool_settle_vulnerable.sol" "r94-reverse-rewards-claim-all-missing-per-pool-settle"
run_clean_test "r94-reverse-rewards-claim-all-missing-per-pool-settle" "r94_reverse_rewards_claim_all_missing_per_pool_settle_clean.sol"      "r94-reverse-rewards-claim-all-missing-per-pool-settle (clean)"

# Generated by gen-detector.py — 5 detectors
run_test "a-borrower-can-list-their-collateral-on-seaport-and-receive-almo" "a_borrower_can_list_their_collateral_on_seaport_and_receive_almo_vulnerable.sol" "a-borrower-can-list-their-collateral-on-seaport-and-receive-almo"
run_clean_test "a-borrower-can-list-their-collateral-on-seaport-and-receive-almo" "a_borrower_can_list_their_collateral_on_seaport_and_receive_almo_clean.sol" "a-borrower-can-list-their-collateral-on-seaport-and-receive-almo (clean)"
run_test "a-broken-hook-can-block-user-funds" "a_broken_hook_can_block_user_funds_vulnerable.sol" "a-broken-hook-can-block-user-funds"
run_clean_test "a-broken-hook-can-block-user-funds" "a_broken_hook_can_block_user_funds_clean.sol" "a-broken-hook-can-block-user-funds (clean)"
run_test "a-buyer-of-a-gold-card-can-manipulate-randomness-won-t-fix" "a_buyer_of_a_gold_card_can_manipulate_randomness_won_t_fix_vulnerable.sol" "a-buyer-of-a-gold-card-can-manipulate-randomness-won-t-fix"
run_clean_test "a-buyer-of-a-gold-card-can-manipulate-randomness-won-t-fix" "a_buyer_of_a_gold_card_can_manipulate_randomness_won_t_fix_clean.sol" "a-buyer-of-a-gold-card-can-manipulate-randomness-won-t-fix (clean)"
run_test "a-claim-cannot-be-paid-out-or-escalated-if-the-protocol-agent-ch" "a_claim_cannot_be_paid_out_or_escalated_if_the_protocol_agent_ch_vulnerable.sol" "a-claim-cannot-be-paid-out-or-escalated-if-the-protocol-agent-ch"
run_clean_test "a-claim-cannot-be-paid-out-or-escalated-if-the-protocol-agent-ch" "a_claim_cannot_be_paid_out_or_escalated_if_the_protocol_agent_ch_clean.sol" "a-claim-cannot-be-paid-out-or-escalated-if-the-protocol-agent-ch (clean)"
run_test "a-cross-check-of-contract-parameters" "a_cross_check_of_contract_parameters_vulnerable.sol" "a-cross-check-of-contract-parameters"
run_clean_test "a-cross-check-of-contract-parameters" "a_cross_check_of_contract_parameters_clean.sol" "a-cross-check-of-contract-parameters (clean)"


# Generated by gen-detector.py — 48 detectors
run_test "a-dark-age-can-end-prematurely" "a_dark_age_can_end_prematurely_vulnerable.sol" "a-dark-age-can-end-prematurely"
run_clean_test "a-dark-age-can-end-prematurely" "a_dark_age_can_end_prematurely_clean.sol" "a-dark-age-can-end-prematurely (clean)"
run_test "a-denial-of-ervice-attack-can-obstruct-flop-auctions" "a_denial_of_ervice_attack_can_obstruct_flop_auctions_vulnerable.sol" "a-denial-of-ervice-attack-can-obstruct-flop-auctions"
run_clean_test "a-denial-of-ervice-attack-can-obstruct-flop-auctions" "a_denial_of_ervice_attack_can_obstruct_flop_auctions_clean.sol" "a-denial-of-ervice-attack-can-obstruct-flop-auctions (clean)"
run_test "a-depositor-of-the-gmxvault-can-bypass-paying-the-fee-when-the-d" "a_depositor_of_the_gmxvault_can_bypass_paying_the_fee_when_the_d_vulnerable.sol" "a-depositor-of-the-gmxvault-can-bypass-paying-the-fee-when-the-d"
run_clean_test "a-depositor-of-the-gmxvault-can-bypass-paying-the-fee-when-the-d" "a_depositor_of_the_gmxvault_can_bypass_paying_the_fee_when_the_d_clean.sol" "a-depositor-of-the-gmxvault-can-bypass-paying-the-fee-when-the-d (clean)"
run_test "a-dos-attack-can-prevent-teleports" "a_dos_attack_can_prevent_teleports_vulnerable.sol" "a-dos-attack-can-prevent-teleports"
run_clean_test "a-dos-attack-can-prevent-teleports" "a_dos_attack_can_prevent_teleports_clean.sol" "a-dos-attack-can-prevent-teleports (clean)"
run_test "a-flashloan-will-be-broken-if-the-usdt-fee-is-more-than-zero" "a_flashloan_will_be_broken_if_the_usdt_fee_is_more_than_zero_vulnerable.sol" "a-flashloan-will-be-broken-if-the-usdt-fee-is-more-than-zero"
run_clean_test "a-flashloan-will-be-broken-if-the-usdt-fee-is-more-than-zero" "a_flashloan_will_be_broken_if_the_usdt_fee_is_more_than_zero_clean.sol" "a-flashloan-will-be-broken-if-the-usdt-fee-is-more-than-zero (clean)"
run_test "a-guardian-cannot-cancel-a-malicious-proposal-in-adminvoting" "a_guardian_cannot_cancel_a_malicious_proposal_in_adminvoting_vulnerable.sol" "a-guardian-cannot-cancel-a-malicious-proposal-in-adminvoting"
run_clean_test "a-guardian-cannot-cancel-a-malicious-proposal-in-adminvoting" "a_guardian_cannot_cancel_a_malicious_proposal_in_adminvoting_clean.sol" "a-guardian-cannot-cancel-a-malicious-proposal-in-adminvoting (clean)"
run_test "a-high-value-of-defaultiterations-could-make-the-withdrawal-and-" "a_high_value_of_defaultiterations_could_make_the_withdrawal_and__vulnerable.sol" "a-high-value-of-defaultiterations-could-make-the-withdrawal-and-"
run_clean_test "a-high-value-of-defaultiterations-could-make-the-withdrawal-and-" "a_high_value_of_defaultiterations_could_make_the_withdrawal_and__clean.sol" "a-high-value-of-defaultiterations-could-make-the-withdrawal-and- (clean)"
run_test "a-killed-gauge-keeps-receiving-rewards" "a_killed_gauge_keeps_receiving_rewards_vulnerable.sol" "a-killed-gauge-keeps-receiving-rewards"
run_clean_test "a-killed-gauge-keeps-receiving-rewards" "a_killed_gauge_keeps_receiving_rewards_clean.sol" "a-killed-gauge-keeps-receiving-rewards (clean)"
run_test "a-linear-increase-in-the-withdrawal-wait-time-for-lido-for-reque" "a_linear_increase_in_the_withdrawal_wait_time_for_lido_for_reque_vulnerable.sol" "a-linear-increase-in-the-withdrawal-wait-time-for-lido-for-reque"
run_clean_test "a-linear-increase-in-the-withdrawal-wait-time-for-lido-for-reque" "a_linear_increase_in_the_withdrawal_wait_time_for_lido_for_reque_clean.sol" "a-linear-increase-in-the-withdrawal-wait-time-for-lido-for-reque (clean)"
run_test "a-liquidity-provider-can-withdraw-all-his-funds-anytime-fixed" "a_liquidity_provider_can_withdraw_all_his_funds_anytime_fixed_vulnerable.sol" "a-liquidity-provider-can-withdraw-all-his-funds-anytime-fixed"
run_clean_test "a-liquidity-provider-can-withdraw-all-his-funds-anytime-fixed" "a_liquidity_provider_can_withdraw_all_his_funds_anytime_fixed_clean.sol" "a-liquidity-provider-can-withdraw-all-his-funds-anytime-fixed (clean)"
run_test "a-malicious-collateralized-nft-token-can-block-liquidation-and-a" "a_malicious_collateralized_nft_token_can_block_liquidation_and_a_vulnerable.sol" "a-malicious-collateralized-nft-token-can-block-liquidation-and-a"
run_clean_test "a-malicious-collateralized-nft-token-can-block-liquidation-and-a" "a_malicious_collateralized_nft_token_can_block_liquidation_and_a_clean.sol" "a-malicious-collateralized-nft-token-can-block-liquidation-and-a (clean)"
run_test "a-malicious-collection-admin-can-reclaim-a-pair-at-any-time-to-d" "a_malicious_collection_admin_can_reclaim_a_pair_at_any_time_to_d_vulnerable.sol" "a-malicious-collection-admin-can-reclaim-a-pair-at-any-time-to-d"
run_clean_test "a-malicious-collection-admin-can-reclaim-a-pair-at-any-time-to-d" "a_malicious_collection_admin_can_reclaim_a_pair_at_any_time_to_d_clean.sol" "a-malicious-collection-admin-can-reclaim-a-pair-at-any-time-to-d (clean)"
run_test "a-malicious-dao-can-hold-token-holders-captive-by-setting-forkpe" "a_malicious_dao_can_hold_token_holders_captive_by_setting_forkpe_vulnerable.sol" "a-malicious-dao-can-hold-token-holders-captive-by-setting-forkpe"
run_clean_test "a-malicious-dao-can-hold-token-holders-captive-by-setting-forkpe" "a_malicious_dao_can_hold_token_holders_captive_by_setting_forkpe_clean.sol" "a-malicious-dao-can-hold-token-holders-captive-by-setting-forkpe (clean)"
run_test "a-malicious-dao-can-mint-arbitrary-fork-dao-tokens" "a_malicious_dao_can_mint_arbitrary_fork_dao_tokens_vulnerable.sol" "a-malicious-dao-can-mint-arbitrary-fork-dao-tokens"
run_clean_test "a-malicious-dao-can-mint-arbitrary-fork-dao-tokens" "a_malicious_dao_can_mint_arbitrary_fork_dao_tokens_clean.sol" "a-malicious-dao-can-mint-arbitrary-fork-dao-tokens (clean)"
run_test "a-malicious-dao-can-prevent-deter-token-holders-from-executing-j" "a_malicious_dao_can_prevent_deter_token_holders_from_executing_j_vulnerable.sol" "a-malicious-dao-can-prevent-deter-token-holders-from-executing-j"
run_clean_test "a-malicious-dao-can-prevent-deter-token-holders-from-executing-j" "a_malicious_dao_can_prevent_deter_token_holders_from_executing_j_clean.sol" "a-malicious-dao-can-prevent-deter-token-holders-from-executing-j (clean)"
run_test "a-malicious-dao-can-prevent-forking-by-manipulating-the-forkthre" "a_malicious_dao_can_prevent_forking_by_manipulating_the_forkthre_vulnerable.sol" "a-malicious-dao-can-prevent-forking-by-manipulating-the-forkthre"
run_clean_test "a-malicious-dao-can-prevent-forking-by-manipulating-the-forkthre" "a_malicious_dao_can_prevent_forking_by_manipulating_the_forkthre_clean.sol" "a-malicious-dao-can-prevent-forking-by-manipulating-the-forkthre (clean)"
run_test "a-malicious-dao-pool-can-create-a-token-sale-tier-without-actual" "a_malicious_dao_pool_can_create_a_token_sale_tier_without_actual_vulnerable.sol" "a-malicious-dao-pool-can-create-a-token-sale-tier-without-actual"
run_clean_test "a-malicious-dao-pool-can-create-a-token-sale-tier-without-actual" "a_malicious_dao_pool_can_create_a_token_sale_tier_without_actual_clean.sol" "a-malicious-dao-pool-can-create-a-token-sale-tier-without-actual (clean)"
run_test "a-malicious-fee-receiver-can-cause-a-denial-of-service" "a_malicious_fee_receiver_can_cause_a_denial_of_service_vulnerable.sol" "a-malicious-fee-receiver-can-cause-a-denial-of-service"
run_clean_test "a-malicious-fee-receiver-can-cause-a-denial-of-service" "a_malicious_fee_receiver_can_cause_a_denial_of_service_clean.sol" "a-malicious-fee-receiver-can-cause-a-denial-of-service (clean)"
run_test "a-malicious-guardian-can-steal-funds-won-t-fix" "a_malicious_guardian_can_steal_funds_won_t_fix_vulnerable.sol" "a-malicious-guardian-can-steal-funds-won-t-fix"
run_clean_test "a-malicious-guardian-can-steal-funds-won-t-fix" "a_malicious_guardian_can_steal_funds_won_t_fix_clean.sol" "a-malicious-guardian-can-steal-funds-won-t-fix (clean)"
run_test "a-malicious-new-dao-can-prevent-deter-token-holders-from-rage-qu" "a_malicious_new_dao_can_prevent_deter_token_holders_from_rage_qu_vulnerable.sol" "a-malicious-new-dao-can-prevent-deter-token-holders-from-rage-qu"
run_clean_test "a-malicious-new-dao-can-prevent-deter-token-holders-from-rage-qu" "a_malicious_new_dao_can_prevent_deter_token_holders_from_rage_qu_clean.sol" "a-malicious-new-dao-can-prevent-deter-token-holders-from-rage-qu (clean)"
run_test "a-malicious-owner-or-user-with-a-role-router-role-can-drain-a-ro" "a_malicious_owner_or_user_with_a_role_router_role_can_drain_a_ro_vulnerable.sol" "a-malicious-owner-or-user-with-a-role-router-role-can-drain-a-ro"
run_clean_test "a-malicious-owner-or-user-with-a-role-router-role-can-drain-a-ro" "a_malicious_owner_or_user_with_a_role_router_role_can_drain_a_ro_clean.sol" "a-malicious-owner-or-user-with-a-role-router-role-can-drain-a-ro (clean)"
run_test "a-malicious-proposer-can-create-arbitrary-number-of-maliciously-" "a_malicious_proposer_can_create_arbitrary_number_of_maliciously__vulnerable.sol" "a-malicious-proposer-can-create-arbitrary-number-of-maliciously-"
run_clean_test "a-malicious-proposer-can-create-arbitrary-number-of-maliciously-" "a_malicious_proposer_can_create_arbitrary_number_of_maliciously__clean.sol" "a-malicious-proposer-can-create-arbitrary-number-of-maliciously- (clean)"
run_test "a-malicious-reward-token-can-dos-reward-claiming-for-all-users-i" "a_malicious_reward_token_can_dos_reward_claiming_for_all_users_i_vulnerable.sol" "a-malicious-reward-token-can-dos-reward-claiming-for-all-users-i"
run_clean_test "a-malicious-reward-token-can-dos-reward-claiming-for-all-users-i" "a_malicious_reward_token_can_dos_reward_claiming_for_all_users_i_clean.sol" "a-malicious-reward-token-can-dos-reward-claiming-for-all-users-i (clean)"
run_test "a-malicious-router-can-skip-transfer-of-royalties-and-protocol-f" "a_malicious_router_can_skip_transfer_of_royalties_and_protocol_f_vulnerable.sol" "a-malicious-router-can-skip-transfer-of-royalties-and-protocol-f"
run_clean_test "a-malicious-router-can-skip-transfer-of-royalties-and-protocol-f" "a_malicious_router_can_skip_transfer_of_royalties_and_protocol_f_clean.sol" "a-malicious-router-can-skip-transfer-of-royalties-and-protocol-f (clean)"
run_test "a-malicious-settings-contract-can-call-onownershiptransferred-to" "a_malicious_settings_contract_can_call_onownershiptransferred_to_vulnerable.sol" "a-malicious-settings-contract-can-call-onownershiptransferred-to"
run_clean_test "a-malicious-settings-contract-can-call-onownershiptransferred-to" "a_malicious_settings_contract_can_call_onownershiptransferred_to_clean.sol" "a-malicious-settings-contract-can-call-onownershiptransferred-to (clean)"
run_test "a-malicious-staker-can-delay-the-increase-of-any-delegator-s-vot" "a_malicious_staker_can_delay_the_increase_of_any_delegator_s_vot_vulnerable.sol" "a-malicious-staker-can-delay-the-increase-of-any-delegator-s-vot"
run_clean_test "a-malicious-staker-can-delay-the-increase-of-any-delegator-s-vot" "a_malicious_staker_can_delay_the_increase_of_any_delegator_s_vot_clean.sol" "a-malicious-staker-can-delay-the-increase-of-any-delegator-s-vot (clean)"
run_test "a-malicious-staker-can-force-validator-withdrawals-by-instantly-" "a_malicious_staker_can_force_validator_withdrawals_by_instantly__vulnerable.sol" "a-malicious-staker-can-force-validator-withdrawals-by-instantly-"
run_clean_test "a-malicious-staker-can-force-validator-withdrawals-by-instantly-" "a_malicious_staker_can_force_validator_withdrawals_by_instantly__clean.sol" "a-malicious-staker-can-force-validator-withdrawals-by-instantly- (clean)"
run_test "a-malicious-user-can-add-themselves-as-a-referrer-in-the-referra" "a_malicious_user_can_add_themselves_as_a_referrer_in_the_referra_vulnerable.sol" "a-malicious-user-can-add-themselves-as-a-referrer-in-the-referra"
run_clean_test "a-malicious-user-can-add-themselves-as-a-referrer-in-the-referra" "a_malicious_user_can_add_themselves_as_a_referrer_in_the_referra_clean.sol" "a-malicious-user-can-add-themselves-as-a-referrer-in-the-referra (clean)"
run_test "a-malicious-user-can-cancel-an-itm-order-at-a-given-target-tick-" "a_malicious_user_can_cancel_an_itm_order_at_a_given_target_tick__vulnerable.sol" "a-malicious-user-can-cancel-an-itm-order-at-a-given-target-tick-"
run_clean_test "a-malicious-user-can-cancel-an-itm-order-at-a-given-target-tick-" "a_malicious_user_can_cancel_an_itm_order_at_a_given_target_tick__clean.sol" "a-malicious-user-can-cancel-an-itm-order-at-a-given-target-tick- (clean)"
run_test "a-malicious-user-can-craft-valid-calldata-to-call-packed-version" "a_malicious_user_can_craft_valid_calldata_to_call_packed_version_vulnerable.sol" "a-malicious-user-can-craft-valid-calldata-to-call-packed-version"
run_clean_test "a-malicious-user-can-craft-valid-calldata-to-call-packed-version" "a_malicious_user_can_craft_valid_calldata_to_call_packed_version_clean.sol" "a-malicious-user-can-craft-valid-calldata-to-call-packed-version (clean)"
run_test "a-malicious-user-can-in-ate-his-voting-power-via-merge" "a_malicious_user_can_in_ate_his_voting_power_via_merge_vulnerable.sol" "a-malicious-user-can-in-ate-his-voting-power-via-merge"
run_clean_test "a-malicious-user-can-in-ate-his-voting-power-via-merge" "a_malicious_user_can_in_ate_his_voting_power_via_merge_clean.sol" "a-malicious-user-can-in-ate-his-voting-power-via-merge (clean)"
run_test "a-malicious-user-can-prevent-vote-creation-at-almost-no-cost" "a_malicious_user_can_prevent_vote_creation_at_almost_no_cost_vulnerable.sol" "a-malicious-user-can-prevent-vote-creation-at-almost-no-cost"
run_clean_test "a-malicious-user-can-prevent-vote-creation-at-almost-no-cost" "a_malicious_user_can_prevent_vote_creation_at_almost_no_cost_clean.sol" "a-malicious-user-can-prevent-vote-creation-at-almost-no-cost (clean)"
run_test "a-malicious-user-can-reduce-other-users-rewards-due-to-incorrect" "a_malicious_user_can_reduce_other_users_rewards_due_to_incorrect_vulnerable.sol" "a-malicious-user-can-reduce-other-users-rewards-due-to-incorrect"
run_clean_test "a-malicious-user-can-reduce-other-users-rewards-due-to-incorrect" "a_malicious_user_can_reduce_other_users_rewards_due_to_incorrect_clean.sol" "a-malicious-user-can-reduce-other-users-rewards-due-to-incorrect (clean)"
run_test "a-malicious-user-could-dos-a-vesting-schedule-by-sending-only-1-" "a_malicious_user_could_dos_a_vesting_schedule_by_sending_only_1__vulnerable.sol" "a-malicious-user-could-dos-a-vesting-schedule-by-sending-only-1-"
run_clean_test "a-malicious-user-could-dos-a-vesting-schedule-by-sending-only-1-" "a_malicious_user_could_dos_a_vesting_schedule_by_sending_only_1__clean.sol" "a-malicious-user-could-dos-a-vesting-schedule-by-sending-only-1- (clean)"
run_test "a-market-could-be-deprecated-but-still-prevent-liquidators-to-li" "a_market_could_be_deprecated_but_still_prevent_liquidators_to_li_vulnerable.sol" "a-market-could-be-deprecated-but-still-prevent-liquidators-to-li"
run_clean_test "a-market-could-be-deprecated-but-still-prevent-liquidators-to-li" "a_market_could_be_deprecated_but_still_prevent_liquidators_to_li_clean.sol" "a-market-could-be-deprecated-but-still-prevent-liquidators-to-li (clean)"
run_test "a-misbehaving-validator-can-influence-voting-outcomes-even-after" "a_misbehaving_validator_can_influence_voting_outcomes_even_after_vulnerable.sol" "a-misbehaving-validator-can-influence-voting-outcomes-even-after"
run_clean_test "a-misbehaving-validator-can-influence-voting-outcomes-even-after" "a_misbehaving_validator_can_influence_voting_outcomes_even_after_clean.sol" "a-misbehaving-validator-can-influence-voting-outcomes-even-after (clean)"
run_test "a-missed-requirement" "a_missed_requirement_vulnerable.sol" "a-missed-requirement"
run_clean_test "a-missed-requirement" "a_missed_requirement_clean.sol" "a-missed-requirement (clean)"
run_test "a-multiplication-over-low-allows-an-attacker-to-block-the-tally" "a_multiplication_over_low_allows_an_attacker_to_block_the_tally_vulnerable.sol" "a-multiplication-over-low-allows-an-attacker-to-block-the-tally"
run_clean_test "a-multiplication-over-low-allows-an-attacker-to-block-the-tally" "a_multiplication_over_low_allows_an_attacker_to_block_the_tally_clean.sol" "a-multiplication-over-low-allows-an-attacker-to-block-the-tally (clean)"
run_test "a-new-buyer-address-is-not-assigned-if-the-previous-one-was-reje" "a_new_buyer_address_is_not_assigned_if_the_previous_one_was_reje_vulnerable.sol" "a-new-buyer-address-is-not-assigned-if-the-previous-one-was-reje"
run_clean_test "a-new-buyer-address-is-not-assigned-if-the-previous-one-was-reje" "a_new_buyer_address_is_not_assigned_if_the_previous_one_was_reje_clean.sol" "a-new-buyer-address-is-not-assigned-if-the-previous-one-was-reje (clean)"
run_test "a-new-malicious-adapter-can-access-users-tokens-fixed" "a_new_malicious_adapter_can_access_users_tokens_fixed_vulnerable.sol" "a-new-malicious-adapter-can-access-users-tokens-fixed"
run_clean_test "a-new-malicious-adapter-can-access-users-tokens-fixed" "a_new_malicious_adapter_can_access_users_tokens_fixed_clean.sol" "a-new-malicious-adapter-can-access-users-tokens-fixed (clean)"
run_test "a-newly-created-chain-that-has-been-migrated-to-the-gateway-will" "a_newly_created_chain_that_has_been_migrated_to_the_gateway_will_vulnerable.sol" "a-newly-created-chain-that-has-been-migrated-to-the-gateway-will"
run_clean_test "a-newly-created-chain-that-has-been-migrated-to-the-gateway-will" "a_newly_created_chain_that_has_been_migrated_to_the_gateway_will_clean.sol" "a-newly-created-chain-that-has-been-migrated-to-the-gateway-will (clean)"
run_test "a-node-exit-prevents-some-other-nodes-from-exiting-for-some-peri" "a_node_exit_prevents_some_other_nodes_from_exiting_for_some_peri_vulnerable.sol" "a-node-exit-prevents-some-other-nodes-from-exiting-for-some-peri"
run_clean_test "a-node-exit-prevents-some-other-nodes-from-exiting-for-some-peri" "a_node_exit_prevents_some_other_nodes_from_exiting_for_some_peri_clean.sol" "a-node-exit-prevents-some-other-nodes-from-exiting-for-some-peri (clean)"
run_test "a-non-zero-discount-prevents-all-purchases-of-cards" "a_non_zero_discount_prevents_all_purchases_of_cards_vulnerable.sol" "a-non-zero-discount-prevents-all-purchases-of-cards"
run_clean_test "a-non-zero-discount-prevents-all-purchases-of-cards" "a_non_zero_discount_prevents_all_purchases_of_cards_clean.sol" "a-non-zero-discount-prevents-all-purchases-of-cards (clean)"

# Generated by gen-detector.py — 2 detectors
run_test "a-failed-send-to-to-address-in-recoverether-leads-to-over-distri" "a_failed_send_to_to_address_in_recoverether_leads_to_over_distri_vulnerable.sol" "a-failed-send-to-to-address-in-recoverether-leads-to-over-distri"
run_clean_test "a-failed-send-to-to-address-in-recoverether-leads-to-over-distri" "a_failed_send_to_to_address_in_recoverether_leads_to_over_distri_clean.sol" "a-failed-send-to-to-address-in-recoverether-leads-to-over-distri (clean)"
run_test "a-malicious-proposer-can-update-proposal-past-inattentive-voters" "a_malicious_proposer_can_update_proposal_past_inattentive_voters_vulnerable.sol" "a-malicious-proposer-can-update-proposal-past-inattentive-voters"
run_clean_test "a-malicious-proposer-can-update-proposal-past-inattentive-voters" "a_malicious_proposer_can_update_proposal_past_inattentive_voters_clean.sol" "a-malicious-proposer-can-update-proposal-past-inattentive-voters (clean)"
run_test "incorrect-self-referencing-compound-arithmetic" "incorrect_self_referencing_compound_arithmetic_vulnerable.sol" "incorrect-self-referencing-compound-arithmetic"
run_clean_test "incorrect-self-referencing-compound-arithmetic" "incorrect_self_referencing_compound_arithmetic_clean.sol" "incorrect-self-referencing-compound-arithmetic (clean)"
run_test "misinterpretation-of-safe-transfer-function-return-values" "misinterpretation_of_safe_transfer_function_return_values_vulnerable.sol" "misinterpretation-of-safe-transfer-function-return-values"
run_clean_test "misinterpretation-of-safe-transfer-function-return-values" "misinterpretation_of_safe_transfer_function_return_values_clean.sol" "misinterpretation-of-safe-transfer-function-return-values (clean)"
run_test "missing-access-control-on-authorizeupgrade" "missing_access_control_on_authorizeupgrade_vulnerable.sol" "missing-access-control-on-authorizeupgrade"
run_clean_test "missing-access-control-on-authorizeupgrade" "missing_access_control_on_authorizeupgrade_clean.sol" "missing-access-control-on-authorizeupgrade (clean)"
run_test "missing-two-step-ownership-transfer-hunter" "missing_two_step_ownership_transfer_hunter_vulnerable.sol" "missing-two-step-ownership-transfer-hunter"
run_clean_test "missing-two-step-ownership-transfer-hunter" "missing_two_step_ownership_transfer_hunter_clean.sol" "missing-two-step-ownership-transfer-hunter (clean)"
run_test "non-compliant-erc165-self-identification" "non_compliant_erc165_self_identification_vulnerable.sol" "non-compliant-erc165-self-identification"
run_clean_test "non-compliant-erc165-self-identification" "non_compliant_erc165_self_identification_clean.sol" "non-compliant-erc165-self-identification (clean)"
run_test "pausable-contract-which-exposed-whennotpaused-only-exposed-pause-thus" "pausable_contract_which_exposed_whennotpaused_only_exposed_pause_thus_vulnerable.sol" "pausable-contract-which-exposed-whennotpaused-only-exposed-pause-thus"
run_clean_test "pausable-contract-which-exposed-whennotpaused-only-exposed-pause-thus" "pausable_contract_which_exposed_whennotpaused_only_exposed_pause_thus_clean.sol" "pausable-contract-which-exposed-whennotpaused-only-exposed-pause-thus (clean)"
