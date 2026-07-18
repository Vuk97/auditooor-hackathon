"""
solana-anchor-mut-missing-on-pool-state-in-token-moving-handler — generated from reference/patterns.dsl/solana-anchor-mut-missing-on-pool-state-in-token-moving-handler.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py solana-anchor-mut-missing-on-pool-state-in-token-moving-handler.yaml
Source: auditooor-R76-c4-glow-finance-bug-bounty-39
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class SolanaAnchorMutMissingOnPoolStateInTokenMovingHandler(AbstractDetector):
    ARGUMENT = "solana-anchor-mut-missing-on-pool-state-in-token-moving-handler"
    HELP = "Anchor handler transfers tokens from pool vault and burns deposit notes but the pool-state account lacks `#[account(mut)]`, so accounting fields can't be decremented — causes compounding pool/vault desync → insolvency."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/solana-anchor-mut-missing-on-pool-state-in-token-moving-handler.yaml"
    WIKI_TITLE = "Anchor account missing `mut` on pool state in fee-withdrawal handler → permanent accounting desync"
    WIKI_DESCRIPTION = "In a Solana/Anchor program, a handler that moves real tokens out of the pool vault (SPL `token::transfer`, burns deposit notes, etc.) must also decrement the pool's tracked `deposit_tokens`/`deposit_notes` counters. If the pool-state account is declared as `Account<'info, MarginPool>` WITHOUT `#[account(mut)]`, the pool reference is immutable inside the handler and calls like `pool.withdraw(&amoun"
    WIKI_EXPLOIT_SCENARIO = "A keeper calls `withdraw_fees` which sends 71,428 tokens from the vault to the fee receiver and burns 50K fee notes, but `pool.deposit_tokens` is never decremented. After many rounds, redeemers computing their entitlement from the inflated rate drain the vault; the last redeemers get nothing."
    WIKI_RECOMMENDATION = "Mark the pool-state account as `#[account(mut)]` in the `Accounts` struct and call the same `pool.withdraw(&claimed_amount)` / `pool.accrue_interest()` sequence that every other token-moving handler uses. Add a regression test asserting that `pool.deposit_tokens == vault.balance` after every fee wit"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)programs?/.+\\.rs$|anchor_lang|anchor_spl'}, {'contract.source_matches_regex': '(?i)margin_pool|lending_pool|liquidity_pool|vault_state'}]
    _MATCH = [{'function.kind': 'handler'}, {'function.name_matches': '(?i)withdraw_fees|claim_protocol_fees|harvest_fees|collect_fees|skim_protocol'}, {'function.body_contains_regex': '(?i)token::transfer|transfer_checked|CpiContext|BankMsg::Send'}, {'function.body_contains_regex': '(?i)pub\\s+(margin_pool|pool|lending_pool|state|pool_state)\\s*:\\s*Account<'}, {'function.body_not_contains_regex': '(?i)#\\[account\\s*\\(\\s*mut.*(margin_pool|pool|lending_pool|pool_state)|pool\\.(withdraw|accrue_interest|update_accounting)\\b'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

    _INCLUDE_LEAF_HELPERS = False
    _INVERSE_CEI = False

    def _detect(self):
        results = []
        for c in self.contracts:
            if is_vendored_or_test_contract(c):
                continue
            if not eval_preconditions(c, self._PRECONDITIONS):
                continue
            for f in c.functions_and_modifiers_declared:
                if not self._INCLUDE_LEAF_HELPERS and is_leaf_helper(f):
                    continue
                if not eval_function_match(f, self._MATCH):
                    continue
                info = [f, f" — solana-anchor-mut-missing-on-pool-state-in-token-moving-handler: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
