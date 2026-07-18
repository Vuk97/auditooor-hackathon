"""
gmx-solana-cross-market-swap-debits-wrong-market — generated from reference/patterns.dsl/gmx-solana-cross-market-swap-debits-wrong-market.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py gmx-solana-cross-market-swap-debits-wrong-market.yaml
Source: auditooor-R76-c4-gmtrade-bug-bounty-45
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GmxSolanaCrossMarketSwapDebitsWrongMarket(AbstractDetector):
    ARGUMENT = "gmx-solana-cross-market-swap-debits-wrong-market"
    HELP = "Swap output ownership is recorded to order_market but payout still debits last_market of the swap path — phantom credit on order_market enables double-pay via LP withdrawal."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/gmx-solana-cross-market-swap-debits-wrong-market.yaml"
    WIKI_TITLE = "Cross-market GMX-style swap debits last-path market but credits order market → LP double-pay"
    WIKI_DESCRIPTION = "The router calls `revertible_swap(SwapDirection::Into(current_order_market), ...)` which internally: removes the output from the LAST swap-path market and credits the current ORDER market. When the two markets differ (user places order on market A but routes via B), the subsequent `ProcessTransferOutOperation` resolves `final_output_market` by calling `swap.find_and_unpack_last_market()` — returni"
    WIKI_EXPLOIT_SCENARIO = "Shared vault holds 100 fBTC: A=40, B=60. Attacker (dominant LP in thin market A) swaps 40M USDG order on A routed via B. Swap output is 5878 fBTC. Revertible-swap moves 5878 from B to A: A=5878+40, B=60-5878 (conceptually); final_output_market resolves to B, so transfer_out debits B by another 5878 and sends 5878 to attacker. Shared vault=94122, A credited 45878 but really owns ~40, B credited 482"
    WIKI_RECOMMENDATION = "Make `final_output_market` equal to the market that received the transferred-in credit (the current order market when direction is `Into(current)`), NOT the last swap-path market. Add an invariant test: `sum(market.tracked_balance for all markets) == shared_vault.balance` before AND after every swap"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)\\.rs$|swap_market|exchange|order\\.rs'}, {'contract.has_function_matching': '(?i)(revertible|execute)_swap'}]
    _MATCH = [{'function.kind': 'internal_or_public'}, {'function.name_matches': '(?i)revertible_swap|process_transfer_out|execute_order|finalize_swap'}, {'function.body_contains_regex': '(?i)SwapDirection::Into|record_transferred_in_by_token|record_transferred_out_by_token'}, {'function.body_contains_regex': '(?i)find_and_unpack_last_market|swap\\.last_market|final_output_market\\s*='}, {'function.body_not_contains_regex': '(?i)final_output_market\\s*=\\s*.*order.*market|final_output_market\\s*=\\s*into_market|holder_market\\s*=.*transferred_in'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — gmx-solana-cross-market-swap-debits-wrong-market: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
