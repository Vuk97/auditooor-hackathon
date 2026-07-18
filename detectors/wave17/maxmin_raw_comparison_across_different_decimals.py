"""
maxmin-raw-comparison-across-different-decimals — generated from reference/patterns.dsl/maxmin-raw-comparison-across-different-decimals.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py maxmin-raw-comparison-across-different-decimals.yaml
Source: auditooor-R75-nethermind-panoptic-v2-HIGH
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class MaxminRawComparisonAcrossDifferentDecimals(AbstractDetector):
    ARGUMENT = "maxmin-raw-comparison-across-different-decimals"
    HELP = "A collateral-requirement function computes two token-denominated requirements (one per leg of a synthetic/LP position) and picks the larger via Math.max or Math.min without first normalizing to a common unit (USD, wei, 18 decimals). When the two tokens have different decimals or very different marke"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/maxmin-raw-comparison-across-different-decimals.yaml"
    WIKI_TITLE = "Math.max/min compares collateral requirements in different token bases (decimals/value) without normalization"
    WIKI_DESCRIPTION = "Multi-leg positions (synthetic stocks, CDO tranches, options) have per-leg requirements denominated in their own token. Code that takes Math.max(reqInTokenA, reqInTokenB) and assigns the result to a single side compares raw integer magnitudes — 1e17 WETH (0.1 ETH ≈ $200) appears 'larger' than 1e8 WBTC (1 BTC ≈ $60k). Depending on which side the winning number is assigned to, the position is either"
    WIKI_EXPLOIT_SCENARIO = "Panoptic-V2 synthetic stock WBTC/WETH: `_getRequiredCollateralSingleLegPartner` computes WETH-leg requirement = 0.1 WETH (1e17) and WBTC-leg requirement = 1 WBTC (1e8). Math.max(1e17, 1e8) = 1e17. Result assigned as the requirement for the lower-indexed token (WETH). User only posts 0.1 WETH (~$200) to secure a synthetic short against 1 WBTC (~$60k). Price moves; protocol eats the shortfall."
    WIKI_RECOMMENDATION = "Normalize both requirements to a common unit before comparison — convert each leg's raw requirement to USD (via oracle) or to 1e18 base units, pick the larger of the normalized values, then convert the selected requirement back to the token units of the side it is assigned to. Never compare raw uint"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(token0|token1|USDC|WBTC|WETH|synthetic).*(Math\\.max|Math\\.min|>|<)'}]
    _MATCH = [{'function.kind': 'internal_or_external'}, {'function.name_matches': '^(getRequiredCollateral|_getRequiredCollateral|_getRequiredCollateralSingleLegPartner|getRequiredCollateralAtTick|computeRequirement|calcRequirement|calculateRequirement|getMaxBorrow|getMinHealthy|_computeRequirement|_calcRequirement)$'}, {'function.body_contains_regex': 'Math\\.(max|min)\\s*\\([^)]*\\bindex\\b[^)]*\\bpartnerIndex\\b|Math\\.(max|min)\\s*\\([^)]*token0[^)]*token1'}, {'function.body_not_contains_regex': '(normalize|toBase|wadMul|mulDiv|scaleTo18|convert0to1|convert1to0)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — maxmin-raw-comparison-across-different-decimals: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
