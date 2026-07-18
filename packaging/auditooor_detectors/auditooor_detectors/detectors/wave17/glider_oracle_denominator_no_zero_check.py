"""
glider-oracle-denominator-no-zero-check — generated from reference/patterns.dsl/glider-oracle-denominator-no-zero-check.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-oracle-denominator-no-zero-check.yaml
Source: hexens-glider/oracle-price-used-as-denominator-without-zero-chec
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderOracleDenominatorNoZeroCheck(AbstractDetector):
    ARGUMENT = "glider-oracle-denominator-no-zero-check"
    HELP = "Exchange-rate setter computes `rate = 1e36 / oracle.getPrice()` with no zero-check on the oracle output. If the oracle ever returns zero the rate becomes max uint or reverts — whichever breaks the invariant — and solvency checks built on `rate` silently pass all balances."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-oracle-denominator-no-zero-check.yaml"
    WIKI_TITLE = "Oracle price used as denominator without zero-check — solvency bypass"
    WIKI_DESCRIPTION = "Inverse-rate computations (`rate = CONST / price`) are a silent bomb when the oracle can return 0. In the multiplication direction (`value = amount * rate`) a tiny rate means `value=0`, and comparisons like `if (value <= threshold) allowWithdraw()` always pass. Gives an attacker free collateral."
    WIKI_EXPLOIT_SCENARIO = "Oracle wrapper: `exchangeRate = 1e36 / underlyingOracle.getPrice();` — underlyingOracle returns 1 during a brief depeg flash. rate ≈ 1e36. Any `debt * rate / 1e18` overflows or simply produces a huge collateral value; liquidation path sees positions as healthy that are actually underwater, loss socialised to lenders."
    WIKI_RECOMMENDATION = "`uint256 p = oracle.getPrice(); require(p > MIN_PRICE && p < MAX_PRICE, \"bad price\"); rate = CONST / p;`. Better: cap or floor the derived rate in a sanity band."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'latestAnswer|latestRoundData|getPrice|pricePerShare|exchangeRate'}]
    _MATCH = [{'function.name_matches': '^(_?updateExchangeRate|exchangeRate|updateRate|_?updateRate)$'}, {'function.kind': 'any'}, {'function.body_contains_regex': '(1e18|1e27|1e36|10\\s*\\*\\*\\s*18|10\\s*\\*\\*\\s*27|10\\s*\\*\\*\\s*36)\\s*\\/\\s*\\w+\\s*\\.\\s*(latestAnswer|latestRoundData|getPrice|price|consult|observe|getRate)|=\\s*\\w+\\s*\\/\\s*\\w+\\.(latestAnswer|latestRoundData|getPrice|price)'}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*\\w*[Pp]rice\\s*(>|!=)|require\\s*\\(\\s*\\w*[Rr]ate\\s*(>|!=)|require\\s*\\(\\s*\\w+\\s*>\\s*0|if\\s*\\(\\s*\\w*[Pp]rice\\s*==\\s*0\\s*\\)\\s*revert'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-oracle-denominator-no-zero-check: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
