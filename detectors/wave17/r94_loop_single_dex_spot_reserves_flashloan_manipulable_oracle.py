"""
r94-loop-single-dex-spot-reserves-flashloan-manipulable-oracle — generated from reference/patterns.dsl/r94-loop-single-dex-spot-reserves-flashloan-manipulable-oracle.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-single-dex-spot-reserves-flashloan-manipulable-oracle.yaml
Source: solodit-56440-zokyo-radiant-capital
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopSingleDexSpotReservesFlashloanManipulableOracle(AbstractDetector):
    ARGUMENT = "r94-loop-single-dex-spot-reserves-flashloan-manipulable-oracle"
    HELP = "r94-loop-single-dex-spot-reserves-flashloan-manipulable-oracle"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-single-dex-spot-reserves-flashloan-manipulable-oracle.yaml"
    WIKI_TITLE = "r94-loop-single-dex-spot-reserves-flashloan-manipulable-oracle"
    WIKI_DESCRIPTION = "r94-loop-single-dex-spot-reserves-flashloan-manipulable-oracle"
    WIKI_EXPLOIT_SCENARIO = "r94-loop-single-dex-spot-reserves-flashloan-manipulable-oracle"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(PriceProvider|Oracle|UniswapV2|Balancer|PriceFeed)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(getTokenPrice|getLpTokenPrice|getPriceFromPool|priceFromReserves|computePrice|fetchPrice|usdPrice|getAssetPrice)'}, {'function.source_matches_regex': '(getReserves\\s*\\(|balanceOf\\s*\\(\\s*\\w*(pool|pair)|pair\\.reserve0|pair\\.reserve1)'}, {'function.not_source_matches_regex': '(twap|priceCumulative|observe\\s*\\(|observations\\[|lastUpdateTimestamp|TWAP_PERIOD|consult\\s*\\(|quoteAtTick\\s*\\()'}]

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
                info = [f, f" — r94-loop-single-dex-spot-reserves-flashloan-manipulable-oracle: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
