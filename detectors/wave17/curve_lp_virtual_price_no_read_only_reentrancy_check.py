"""
curve-lp-virtual-price-no-read-only-reentrancy-check — generated from reference/patterns.dsl/curve-lp-virtual-price-no-read-only-reentrancy-check.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py curve-lp-virtual-price-no-read-only-reentrancy-check.yaml
Source: solodit/sherlock/sentiment-H1-5643
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CurveLpVirtualPriceNoReadOnlyReentrancyCheck(AbstractDetector):
    ARGUMENT = "curve-lp-virtual-price-no-read-only-reentrancy-check"
    HELP = "Oracle reads `get_virtual_price()` on a Curve ETH pool without first calling `remove_liquidity(0, [0,0])` to poke the pool's reentrancy lock. During an attacker's `remove_liquidity` callback the virtual price is deflated ~10x, triggering unfair liquidations."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/curve-lp-virtual-price-no-read-only-reentrancy-check.yaml"
    WIKI_TITLE = "Curve oracle reads virtual_price without triggering the pool's reentrancy lock"
    WIKI_DESCRIPTION = "Curve ETH pools transfer ETH to the LP exiter before updating their internal accounting inside `remove_liquidity`. During the ETH `receive` callback, `get_virtual_price`, `price_oracle`, `get_dy`, and `balances()` all return manipulated values. Any downstream oracle that reads these primitives without first invoking the pool's reentrancy lock (`POOL.remove_liquidity(0, [0,0])` reverts when the poo"
    WIKI_EXPLOIT_SCENARIO = "Attacker flashloans WETH, deposits into Curve ETH-wstETH pool, calls `remove_liquidity(lp, [0,0])`. The pool's `raw_call` to the attacker's receive handler runs mid-state. In that handler, attacker calls `riskEngine.liquidate(victim)`; the risk engine reads `stableCurveEthOracle.getPrice(lpToken)` which calls `POOL.get_virtual_price()` — now returning ~10x depressed. Victim's LP collateral is valu"
    WIKI_RECOMMENDATION = "Before each read, invoke `POOL.remove_liquidity(0, new uint[](N))` — a zero-amount remove that requires the pool's reentrancy lock to be free. If the pool is mid-op, this call reverts and the oracle read aborts. Additionally, consider adding a Chainlink fallback and refusing to price when virtual_pr"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.body_contains_regex': 'get_virtual_price|price_oracle|get_dy|\\.balances\\s*\\('}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.state_mutability': 'view'}, {'function.body_contains_regex': '\\.get_virtual_price\\s*\\(\\s*\\)|\\.price_oracle\\s*\\(|\\.get_dy\\s*\\('}, {'function.body_contains_regex': '(price|mulWad|mulDiv|amount|value)\\s*=.*(get_virtual_price|price_oracle|get_dy)'}, {'function.body_not_contains_regex': 'remove_liquidity\\s*\\(\\s*0\\s*,|claim_admin_fees|check_reentrancy_lock'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — curve-lp-virtual-price-no-read-only-reentrancy-check: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
