"""
bonding-curve-buy-sell-inverse-mismatch — generated from reference/patterns.dsl/bonding-curve-buy-sell-inverse-mismatch.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py bonding-curve-buy-sell-inverse-mismatch.yaml
Source: defihacklabs/Truebit-2026-01
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BondingCurveBuySellInverseMismatch(AbstractDetector):
    ARGUMENT = "bonding-curve-buy-sell-inverse-mismatch"
    HELP = "Bonding-curve contract exposes buy / sell with divergent pricing formulas against the same state. Attacker loops buy-then-sell to drain reserves because the inverse identity does not hold."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/bonding-curve-buy-sell-inverse-mismatch.yaml"
    WIKI_TITLE = "Bonding curve buy/sell inverse mismatch"
    WIKI_DESCRIPTION = "A correct bonding curve guarantees that buying and selling the same delta at the same state returns the same quote (modulo fees). When the two code paths derive output via non-inverse math, repeated buy+sell cycles accrue profit to the trader. Often happens when the two functions were implemented separately and pulled apart during refactor."
    WIKI_EXPLOIT_SCENARIO = "Truebit 2026-01 (~$20M equivalent in 8540 ETH): `buyTRU` priced at `theta * reserve / totalSupply`, `sellTRU` priced at `theta * totalSupply / reserve`. Attacker with starting 1 ETH iteratively bought then sold, netting ETH on each cycle as the curves disagreed. 40+ loops drained the protocol."
    WIKI_RECOMMENDATION = "Share a single `_price(supply, reserve, isBuy)` helper between both buy and sell paths. Unit-test the invariant: for any state, `sell(buy(x)) == x` (minus fees). Prefer established Balancer/Bancor math libraries over hand-rolled bonding curves."

    _PRECONDITIONS = [{'contract.has_function_matching': '^(buy|purchase|getPurchasePrice|quoteBuy)'}, {'contract.has_function_matching': '^(sell|sale|getSalePrice|quoteSell)'}, {'contract.source_matches_regex': '(?i)(bondingCurve|BondingCurve|reserve|theta|curve|slope|totalSupply)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(buy|sell|purchase|redeem|mint|burn|getPurchasePrice|getSalePrice|quoteBuy|quoteSell)[A-Z_]?'}, {'function.body_contains_regex': '(?s)(reserve|pool).*(totalSupply|supply)|(totalSupply|supply).*(reserve|pool)'}, {'function.body_contains_regex': '\\btheta\\b'}, {'function.body_contains_regex': '[*/]'}, {'function.body_not_contains_regex': 'bondingCurveLibrary|priceFn\\s*\\(|_price\\s*\\(|sharedPrice\\s*\\(|_quote\\s*\\('}, {'function.not_source_matches_regex': '(_price\\s*\\(\\s*\\w+\\s*,\\s*\\w+\\s*,\\s*bool|sharedPrice\\s*\\(|BalancerMath|BancorFormula|LogExpMath\\.|UD60x18\\s+function\\s+price)'}, {'function.not_in_skip_list': True}]

    _INCLUDE_LEAF_HELPERS = True
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
                info = [f, f" — bonding-curve-buy-sell-inverse-mismatch: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
