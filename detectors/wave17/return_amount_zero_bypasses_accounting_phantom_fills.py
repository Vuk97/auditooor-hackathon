"""
return-amount-zero-bypasses-accounting-phantom-fills — generated from reference/patterns.dsl/return-amount-zero-bypasses-accounting-phantom-fills.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py return-amount-zero-bypasses-accounting-phantom-fills.yaml
Source: auditooor-R76-c4-rujira-bug-bounty-30
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ReturnAmountZeroBypassesAccountingPhantomFills(AbstractDetector):
    ARGUMENT = "return-amount-zero-bypasses-accounting-phantom-fills"
    HELP = "Accounting guarded by `if return_amount != 0` skips consumed-offer debit when integer truncation forces return=0 — attacker extracts phantom fills without paying."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/return-amount-zero-bypasses-accounting-phantom-fills.yaml"
    WIKI_TITLE = "`if return_amount != 0` wraps consumed-offer debit → integer-truncated swaps bypass accounting"
    WIKI_DESCRIPTION = "An order / matching handler wraps the entire swap accounting block in `if !return_amount.is_zero() { credit_output; debit_consumed_offer }`. When a swap is submitted at an extreme price, the math `bids_value = floor(offer * price) = 0` yields `return_amount == 0` even though `consumed_offer > 0` (the pool's `sum` and `product` snapshots were committed). The accounting block is skipped, consumed_of"
    WIKI_EXPLOIT_SCENARIO = "Three-step batch at price 10^18: (1) place base-side seed order for 2 tokens, creating a bid with `sum_snapshot=0, product_snapshot=1, total=2`; (2) quote-side order for V triggers `distribute_partial(0, V)` — `sum` inflates to V/2 without consuming bids; the swap returns `consumed_offer=V, return_amount=0`; guard skips debit, V quote tokens are NOT subtracted from receive. (3) Re-sync the seed bi"
    WIKI_RECOMMENDATION = "Split the guard: credit `return_amount` under `if return_amount != 0`, but debit `consumed_offer` under a separate `if consumed_offer != 0` guard. Better: debit unconditionally and let the balance subtraction return an error when the taker did not pre-fund the bid side. Also audit `distribute_partia"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)\\.rs$|order_pool|swap_engine'}, {'contract.has_function_matching': '(?i)execute_(new|existing)_order|match_swap|do_swap'}]
    _MATCH = [{'function.kind': 'internal_or_public'}, {'function.name_matches': '(?i)execute_new_order|execute_order|process_swap|handle_match'}, {'function.body_contains_regex': '(?i)if\\s*!\\s*swap\\.return_amount\\.is_zero\\s*\\(\\s*\\)|if\\s+swap\\.return_amount\\s*>\\s*Uint128::zero\\s*\\(\\s*\\)|if\\s*!\\s*return_amount\\.is_zero\\s*\\(\\s*\\)'}, {'function.body_contains_regex': '(?i)consumed_offer'}, {'function.body_not_contains_regex': '(?i)if\\s*!\\s*swap\\.consumed_offer\\.is_zero|unconditionally\\s+debit'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — return-amount-zero-bypasses-accounting-phantom-fills: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
