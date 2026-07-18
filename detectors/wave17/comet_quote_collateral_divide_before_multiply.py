"""
comet-quote-collateral-divide-before-multiply — generated from reference/patterns.dsl/comet-quote-collateral-divide-before-multiply.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py comet-quote-collateral-divide-before-multiply.yaml
Source: auditooor-R71-fixdiff-mined-compound-comet-63cb6e3ff
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CometQuoteCollateralDivideBeforeMultiply(AbstractDetector):
    ARGUMENT = "comet-quote-collateral-divide-before-multiply"
    HELP = "quoteCollateral / absorb collateral-pricing path divides before multiplying (e.g. `assetInfo.scale * basePrice / assetPriceDiscounted; then * baseAmount / baseScale`). The first division truncates tens of basis points off the quoted collateral, and the error is magnified when `assetPriceDiscounted` "
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/comet-quote-collateral-divide-before-multiply.yaml"
    WIKI_TITLE = "Collateral quote truncates via division-before-multiplication"
    WIKI_DESCRIPTION = "Comet computes `quoteCollateral(asset, baseAmount)` to price protocol-for-sale collateral during the storefront auction. The original implementation was `assetWeiPerUnitBase = assetInfo.scale * basePrice / assetPriceDiscounted; return assetWeiPerUnitBase * baseAmount / baseScale`. The first line is a division that truncates toward zero, losing up to one `assetPriceDiscounted`-sized unit of precisi"
    WIKI_EXPLOIT_SCENARIO = "A Comet market with an expensive collateral (WBTC, `assetPriceDiscounted = 60000e8`) is being absorbed. An arbitrageur calls `buyCollateral(asset, minAmount=0, baseAmount=small, recipient=self)` with a `baseAmount` chosen to make the first division round down by near-one-unit. Repeated tiny buys siphon protocol reserves while the attacker receives slightly less collateral than quoted; the cumulati"
    WIKI_RECOMMENDATION = "Reorder all scaled-price expressions so all multiplications happen before any division: `basePrice * baseAmount * assetInfo.scale / assetPriceDiscounted / baseScale`. For safety against uint256 overflow of the triple product, use `Math.mulDiv(basePrice * baseAmount, assetInfo.scale, assetPriceDiscou"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'storeFrontPriceFactor|liquidationFactor|quoteCollateral|basePrice'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(quoteCollateral|priceCollateral|collateralFor|buyQuote|absorb|liquidate)$'}, {'function.body_contains_regex': '(assetScale|assetInfo\\.scale|collateralScale)\\s*\\*\\s*basePrice\\s*\\/|baseScale\\s*\\/\\s*assetPrice|scale\\s*\\*\\s*\\w+Price\\s*\\/'}, {'function.body_not_contains_regex': 'mulDiv|FullMath|PRBMath|basePrice\\s*\\*\\s*baseAmount\\s*\\*\\s*assetInfo\\.scale\\s*\\/'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — comet-quote-collateral-divide-before-multiply: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
