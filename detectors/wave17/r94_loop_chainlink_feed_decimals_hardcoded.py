"""
r94-loop-chainlink-feed-decimals-hardcoded — generated from reference/patterns.dsl/r94-loop-chainlink-feed-decimals-hardcoded.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-chainlink-feed-decimals-hardcoded.yaml
Source: loop-cycle-42-sol-sibling
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopChainlinkFeedDecimalsHardcoded(AbstractDetector):
    ARGUMENT = "r94-loop-chainlink-feed-decimals-hardcoded"
    HELP = "r94-loop-chainlink-feed-decimals-hardcoded"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-chainlink-feed-decimals-hardcoded.yaml"
    WIKI_TITLE = "r94-loop-chainlink-feed-decimals-hardcoded"
    WIKI_DESCRIPTION = "r94-loop-chainlink-feed-decimals-hardcoded"
    WIKI_EXPLOIT_SCENARIO = "r94-loop-chainlink-feed-decimals-hardcoded"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(Chainlink|AggregatorV3Interface|latestRoundData)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': '(?i)(getPrice|priceOf|scalePrice|normalizePrice)'}, {'function.source_matches_regex': 'latestRoundData'}, {'function.source_matches_regex': '1e8\\b|10\\s*\\*\\*\\s*8|100000000'}, {'function.not_source_matches_regex': '\\.decimals\\s*\\(\\s*\\)'}]

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
                info = [f, f" — r94-loop-chainlink-feed-decimals-hardcoded: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
