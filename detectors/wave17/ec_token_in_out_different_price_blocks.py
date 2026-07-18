"""
ec-token-in-out-different-price-blocks — generated from reference/patterns.dsl/ec-token-in-out-different-price-blocks.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py ec-token-in-out-different-price-blocks.yaml
Source: economic-mining-R61
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class EcTokenInOutDifferentPriceBlocks(AbstractDetector):
    ARGUMENT = "ec-token-in-out-different-price-blocks"
    HELP = "Swap prices tokenIn and tokenOut using separate oracle calls with an external transfer between them, allowing manipulation of one price relative to the other."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/ec-token-in-out-different-price-blocks.yaml"
    WIKI_TITLE = "TokenIn and tokenOut priced in separate oracle calls with external call between"
    WIKI_DESCRIPTION = "The swap/exchange function reads the tokenIn price from an external oracle, performs a token transfer (which can trigger a hook or reentrant call), then reads the tokenOut price from a second oracle call. The intervening external call allows an attacker to move one price relative to the other, extracting value from the mid-transaction spread."
    WIKI_EXPLOIT_SCENARIO = "Protocol reads priceA = oracle.getPrice(tokenIn) = 1.00. Transfers tokenIn — triggers fee-on-transfer hook. During hook: attacker executes a trade that moves oracle. Protocol reads priceB = oracle.getPrice(tokenOut) = 0.80 (moved). User receives tokenOut priced 20% cheaper than the real exchange rate."
    WIKI_RECOMMENDATION = "Read both prices atomically before any external call. Use a single multi-price feed query if available. Store both prices in memory variables before the first external interaction. Consider using a commit-reveal pattern if the pricing must be split across calls."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'swap|exchange|convert|getAmountOut|getAmountsOut'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(swap|exchange|convert|getAmountOut|quote)'}, {'function.body_contains_regex': 'getPrice\\s*\\(.*token[Ii]n|priceOf\\s*\\(.*[Ii]n|latestAnswer.*[Ii]n'}, {'function.body_contains_regex': 'getPrice\\s*\\(.*token[Oo]ut|priceOf\\s*\\(.*[Oo]ut|latestAnswer.*[Oo]ut'}, {'function.body_contains_regex': '\\.call\\(|\\.transfer\\(|\\.safeTransfer\\(|IERC20.*transfer'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — ec-token-in-out-different-price-blocks: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
