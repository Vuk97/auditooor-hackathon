"""
ec-lp-virtual-price-read-only-reentrancy — generated from reference/patterns.dsl/ec-lp-virtual-price-read-only-reentrancy.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py ec-lp-virtual-price-read-only-reentrancy.yaml
Source: economic-mining-R61
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class EcLpVirtualPriceReadOnlyReentrancy(AbstractDetector):
    ARGUMENT = "ec-lp-virtual-price-read-only-reentrancy"
    HELP = "Curve get_virtual_price() read in a non-reentrant-guarded function; mid-remove_liquidity callback inflates virtual_price enabling over-collateralization."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/ec-lp-virtual-price-read-only-reentrancy.yaml"
    WIKI_TITLE = "Curve LP get_virtual_price read-only reentrancy — no nonReentrant guard"
    WIKI_DESCRIPTION = "The contract reads Curve's get_virtual_price() or getPricePerShare() for collateral valuation in a function that lacks a reentrancy guard. Curve ETH pools call msg.sender (via ETH transfer) during add_liquidity/remove_liquidity before updating virtual_price. An attacker entering the unguarded function from within that callback reads an inflated virtual_price and receives excess collateral credit."
    WIKI_EXPLOIT_SCENARIO = "Attacker calls CurvePool.remove_liquidity(). Before virtual_price updates, Curve sends ETH to attacker. In receive(), attacker calls LendingProtocol.borrow(CurveLP). LendingProtocol reads get_virtual_price() which still reflects pre-removal (inflated) state. Attacker borrows against over-valued LP collateral."
    WIKI_RECOMMENDATION = "Add nonReentrant to any function reading get_virtual_price(). Alternatively, check the Curve pool's reentrancy lock directly: call pool.claim_admin_fees() (no-op that reverts if locked) or use the CurvePoolOracle wrapper that enforces lock checks. Consider using a TWAP of virtual_price over multiple"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'get_virtual_price|ICurvePool|IStableSwap|getPricePerShare'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': 'get_virtual_price\\(\\)|getPricePerShare\\(\\)|pricePerShare\\(\\)'}, {'function.body_contains_regex': 'collateral|value|price|worth|amount.*\\*.*virtual|virtual.*\\*.*amount'}, {'function.body_not_contains_regex': 'nonReentrant|ReentrancyGuard|_status\\s*==|locked\\s*=|mutex'}, {'function.body_not_contains_regex': 'is_killed\\(\\)|lock\\(\\)|\\.locked\\b'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — ec-lp-virtual-price-read-only-reentrancy: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
