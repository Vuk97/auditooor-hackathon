"""
cosmwasm-orderbook-consumed-offer-conditional-debit — generated from reference/patterns.dsl/cosmwasm-orderbook-consumed-offer-conditional-debit.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py cosmwasm-orderbook-consumed-offer-conditional-debit.yaml
Source: auditooor-R76-c4-rujira-bug-bounty-44
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CosmwasmOrderbookConsumedOfferConditionalDebit(AbstractDetector):
    ARGUMENT = "cosmwasm-orderbook-consumed-offer-conditional-debit"
    HELP = "Taker output credit is unconditional, but taker input debit is gated on `self.receive.has(bid_denom)`. A zero-funded taker bypasses the debit and withdraws matched maker liquidity for free."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/cosmwasm-orderbook-consumed-offer-conditional-debit.yaml"
    WIKI_TITLE = "CosmWasm orderbook: conditional `has()`-gated debit of consumed offer allows zero-funded matching"
    WIKI_DESCRIPTION = "`execute_new_order` applies two accounting operations after a matching swap: (1) unconditionally credits `return_amount` of the ASK denom to `self.receive`; (2) debits `consumed_offer` of the BID denom only if `self.receive.has(bid_denom)` is true. For a taker who supplied zero funds on the bid side, the has() check is false and the debit is skipped. The final per-batch solvency loop subtracts `se"
    WIKI_EXPLOIT_SCENARIO = "Maker posts 10,000 USDC resting. Attacker calls `ExecuteMsg::Order` with Side::Base, price 1.0, amount 10_000, funds=[] (no RUJI input). The swap matches the maker at consumed_offer=10_000 RUJI, return_amount=10_000 USDC. Credit: receive += 10_000 USDC. Debit: receive.has(RUJI)? false → skipped. Final check: receive has 10_000 USDC - send(0) = OK. Attacker withdraws 10_000 USDC for zero cost. Make"
    WIKI_RECOMMENDATION = "Remove the `has()` guard: unconditionally subtract `consumed_offer` from `self.receive` and let the `NativeBalance - coin` operation return an error if the caller did not fund the bid side. Add a regression test: a zero-funded taker order that immediately matches must revert with `InsufficientFunds`"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)\\.rs$|cosmwasm_std|NativeBalance'}, {'contract.has_function_matching': '(?i)execute_(order|swap|new_order)|match_order'}]
    _MATCH = [{'function.kind': 'internal_or_public'}, {'function.name_matches': '(?i)execute_new_order|execute_order|match_swap|cross_orders|handle_match'}, {'function.body_contains_regex': '(?i)self\\.receive\\s*\\+=\\s*coin\\s*\\(.*return_amount|self\\.received\\s*\\+=\\s*coin'}, {'function.body_contains_regex': '(?i)self\\.receive.*(has|contains_key)\\s*\\(.*(consumed_offer|offer_denom|bid_denom)'}, {'function.body_contains_regex': '(?i)consumed_offer'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — cosmwasm-orderbook-consumed-offer-conditional-debit: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
