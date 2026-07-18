"""
r94-loop-buy-erc777-reentrancy-stale-reserve-price — generated from reference/patterns.dsl/r94-loop-buy-erc777-reentrancy-stale-reserve-price.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-buy-erc777-reentrancy-stale-reserve-price.yaml
Source: loop-cycle-87-sol-sibling
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopBuyErc777ReentrancyStaleReservePrice(AbstractDetector):
    ARGUMENT = "r94-loop-buy-erc777-reentrancy-stale-reserve-price"
    HELP = "r94-loop-buy-erc777-reentrancy-stale-reserve-price"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-buy-erc777-reentrancy-stale-reserve-price.yaml"
    WIKI_TITLE = "r94-loop-buy-erc777-reentrancy-stale-reserve-price"
    WIKI_DESCRIPTION = "r94-loop-buy-erc777-reentrancy-stale-reserve-price"
    WIKI_EXPLOIT_SCENARIO = "r94-loop-buy-erc777-reentrancy-stale-reserve-price"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(reserve0|reserve1|Pair)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(buy|sell|swap|purchase|exchange)'}, {'function.source_matches_regex': '(\\.transfer\\s*\\(|safeTransfer\\s*\\()[\\s\\S]{0,300}?(reserve0\\s*=|reserve1\\s*=|updateReserves\\s*\\()'}, {'function.not_source_matches_regex': '(nonReentrant|ReentrancyGuard|reentrancyLock)'}]

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
                info = [f, f" — r94-loop-buy-erc777-reentrancy-stale-reserve-price: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
