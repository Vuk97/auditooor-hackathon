"""
burn-on-transfer-to-pair-inflates-price — generated from reference/patterns.dsl/burn-on-transfer-to-pair-inflates-price.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py burn-on-transfer-to-pair-inflates-price.yaml
Source: DeFiHackLabs/FPC (2025-07, $4.7M USDT) — FPC._transfer burned tokens whenever `to == pair`, shrinking the FPC reserve inside the pair and inflating the FPC price in subsequent swaps
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BurnOnTransferToPairInflatesPrice(AbstractDetector):
    ARGUMENT = "burn-on-transfer-to-pair-inflates-price"
    HELP = "Token's _transfer burns tokens when the recipient is an AMM pair. Each pair-directed transfer shrinks the FPC reserve and inflates the price without a matching counterparty move — attackers farm the distortion with a flash-loan swap loop."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/burn-on-transfer-to-pair-inflates-price.yaml"
    WIKI_TITLE = "ERC20 burns on transfer to AMM pair — breakable reserve invariant"
    WIKI_DESCRIPTION = "The ERC20 implementation's internal _transfer (or _update override) burns tokens whenever `to == pair` (PancakePair, UniV2Pair, custom LP). This violates the reserve invariant Uniswap-family pairs assume: the pair's FPC reserve silently decreases while its USDT/WETH reserve stays constant, so the next `sync()` on the pair re-prices FPC upward. An attacker flash-loans a stable, purchases FPC normal"
    WIKI_EXPLOIT_SCENARIO = "FPC (2025-07, $4.7M USDT). Attacker flash-borrowed 23,020,000 USDT from Pancake V3 pool, swapped it for FPC via the pair, then used a helper contract to transfer 247,441 FPC into the pair — FPC._transfer burned a chunk on landing — and finally called swapExactTokensForTokensSupportingFeeOnTransferTokens to dump FPC-for-USDT at the inflated price. Net: 4.7M USDT extracted, loan repaid."
    WIKI_RECOMMENDATION = "Never burn tokens on transfer-to-pair. If deflation is desired, either (a) burn only on transfer-from-pair (i.e., on sells initiated by the pair, not LP deposits), with explicit exclusions for LP router addresses, (b) implement fee-on-transfer as a taxed `_beforeTokenTransfer` that forwards tax to a"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'pancakePair|uniswapV2Pair|lpPair|_pair'}, {'contract.has_function_matching': '_transfer|_update'}]
    _MATCH = [{'function.kind': 'internal_or_private'}, {'function.name_matches': '^_transfer$|^_update$|^_beforeTokenTransfer$'}, {'function.body_contains_regex': 'to\\s*==\\s*(pancakePair|uniswapV2Pair|lpPair|pair|_pair).*_burn|to\\s*==\\s*(pancakePair|uniswapV2Pair|lpPair|pair|_pair).*balances\\[to\\]\\s*-=|to\\s*==\\s*(pancakePair|uniswapV2Pair|lpPair|pair|_pair).*dead|transfer\\s*\\(\\s*deadAddress'}, {'function.body_not_contains_regex': 'isExcludedFromFee\\[from\\]|isExcludedFromFee\\[to\\]|excludedFromBurn|_isExcluded\\[from\\]|isWhitelistedSender'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': False}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — burn-on-transfer-to-pair-inflates-price: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
