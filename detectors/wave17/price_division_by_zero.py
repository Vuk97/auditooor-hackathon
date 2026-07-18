"""
price-division-by-zero — generated from reference/patterns.dsl/price-division-by-zero.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py price-division-by-zero.yaml
Source: solodit-cluster/cross-cluster
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PriceDivisionByZero(AbstractDetector):
    ARGUMENT = "price-division-by-zero"
    HELP = "External/public price or conversion function divides by a totalSupply / reserve / balance / supply read without a prior non-zero guard — empty pool / fresh vault / unseeded reserve will revert and brick the feature."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/price-division-by-zero.yaml"
    WIKI_TITLE = "Price / conversion division-by-zero on empty supply or reserve"
    WIKI_DESCRIPTION = "An external or public function computes a ratio of the form `x / totalSupply`, `amount / reserves`, `shares * total / supply`, or the library variant `x.div(totalSupply)` where the denominator is a state read from a supply-family variable (totalSupply, reserve*, balance*, supply). When the vault has not yet received a deposit, the AMM pool has not been seeded, or the market is fresh, the denominat"
    WIKI_EXPLOIT_SCENARIO = "An ERC4626 vault exposes `convertToAssets(shares) = shares * totalAssets() / totalSupply()`. At deployment, totalSupply() is zero. A third-party integrator calling `previewDeposit` on the fresh vault reverts with a DIV-by-zero error instead of returning 1:1 share pricing. Integrations that treat the vault as a price source (oracles, LP aggregators, UIs) fail their liveness check and de-list the va"
    WIKI_RECOMMENDATION = "Add an explicit zero-check before the division: `require(totalSupply > 0, \"no supply\")` or a short-circuit `if (totalSupply == 0) return initialRate;` returning a sensible default (1:1 for ERC4626, the oracle price for AMM spot, the market's initial exchange rate for lending). For pricing function"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.not_slither_synthetic': True}, {'function.body_contains_regex': '\\/\\s*(total\\w+|reserve\\w*|balance\\w*|supply)|\\.div\\s*\\(\\s*(total|reserve|balance|supply)'}, {'function.body_not_contains_regex': 'require\\s*\\(.*(total|reserve|balance|supply)\\s*(>|!=)\\s*0|if\\s*\\(.*\\s*(total|reserve|balance|supply)\\s*==\\s*0\\s*\\)\\s*\\{[^}]*return'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — price-division-by-zero: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
