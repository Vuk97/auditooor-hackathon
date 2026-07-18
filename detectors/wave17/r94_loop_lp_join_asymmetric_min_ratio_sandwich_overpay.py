"""
r94-loop-lp-join-asymmetric-min-ratio-sandwich-overpay — generated from reference/patterns.dsl/r94-loop-lp-join-asymmetric-min-ratio-sandwich-overpay.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-lp-join-asymmetric-min-ratio-sandwich-overpay.yaml
Source: solodit-7113-spearbit-cron-finance-cronv1pool
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopLpJoinAsymmetricMinRatioSandwichOverpay(AbstractDetector):
    ARGUMENT = "r94-loop-lp-join-asymmetric-min-ratio-sandwich-overpay"
    HELP = "r94-loop-lp-join-asymmetric-min-ratio-sandwich-overpay"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-lp-join-asymmetric-min-ratio-sandwich-overpay.yaml"
    WIKI_TITLE = "r94-loop-lp-join-asymmetric-min-ratio-sandwich-overpay"
    WIKI_DESCRIPTION = "r94-loop-lp-join-asymmetric-min-ratio-sandwich-overpay"
    WIKI_EXPLOIT_SCENARIO = "r94-loop-lp-join-asymmetric-min-ratio-sandwich-overpay"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(CronV1Pool|BalancerPool|LP|JoinPool|Pool)'}]
    _MATCH = [{'function.name_matches': '(?i)^(onJoinPool|addLiquidity|joinPool|mintLp|depositToPool|lpMint)$'}, {'function.source_matches_regex': '(Math\\.min\\s*\\(\\s*\\w*token0In\\s*\\*\\s*\\w*supply\\s*\\/\\s*\\w*reserve0\\s*,\\s*\\w*token1In\\s*\\*\\s*\\w*supply\\s*\\/\\s*\\w*reserve1|amountLP\\s*=\\s*\\w*Math\\.min\\s*\\(\\s*\\w*_token0In\\w*\\s*\\.\\s*mul\\s*\\(\\s*\\w*supplyLP\\s*\\))'}, {'function.not_source_matches_regex': '(minAmountLpOut|slippageCheck|oraclePriceCheck|require\\s*\\(\\s*\\w*amountLP\\s*>=\\s*\\w*min|preJoinPrice|weightedPriceCheck|checkJoinRatio)'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — r94-loop-lp-join-asymmetric-min-ratio-sandwich-overpay: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
