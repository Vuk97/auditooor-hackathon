"""
twap-tick-delta-not-rounded-for-negative-values — generated from reference/patterns.dsl/twap-tick-delta-not-rounded-for-negative-values.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py twap-tick-delta-not-rounded-for-negative-values.yaml
Source: auditooor-R75-c4-yield-2024-03-revert-lend-127
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class TwapTickDeltaNotRoundedForNegativeValues(AbstractDetector):
    ARGUMENT = "twap-tick-delta-not-rounded-for-negative-values"
    HELP = "Custom Uniswap v3 TWAP computes (cum0 - cum1) / seconds without rounding DOWN for negative deltas — off-by-one tick favors the liquidator on negative-side moves."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/twap-tick-delta-not-rounded-for-negative-values.yaml"
    WIKI_TITLE = "Custom TWAP misses round-down for negative tickCumulative delta"
    WIKI_DESCRIPTION = "Uniswap v3 TWAP computation must round the tick quotient DOWN for negative values because Solidity integer division truncates toward zero. OracleLibrary explicitly does `if (delta < 0 && delta % secondsAgo != 0) tick--`. Custom implementations that forget this branch produce a tick that is off by 1 whenever the TWAP delta is negative and not cleanly divisible. Over the range this inflates or defla"
    WIKI_EXPLOIT_SCENARIO = "Revert V3Oracle._getReferencePoolPriceX96: tickCumulativesDelta = -5, twapSeconds = 60. Solidity yields `-5 / 60 = 0` (truncation) instead of `-1` (floor). The derived sqrtPriceX96 is too high by one tick. A borrower's health factor is miscomputed — they evade liquidation or are wrongly liquidated depending on direction."
    WIKI_RECOMMENDATION = "Mirror Uniswap OracleLibrary exactly: `int24 tick = int24(delta / int56(uint56(secondsAgo))); if (delta < 0 && (delta % int56(uint56(secondsAgo)) != 0)) tick--;`. Re-use OracleLibrary instead of reimplementing."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': 'pool\\.observe\\s*\\(|IUniswapV3Pool\\s*\\(\\s*\\w+\\s*\\)\\.observe'}, {'function.body_contains_regex': '(?i)tickCumulatives\\s*\\[\\s*0\\s*\\]\\s*-\\s*tickCumulatives\\s*\\[\\s*1\\s*\\]|tickCumulatives\\s*\\[\\s*1\\s*\\]\\s*-\\s*tickCumulatives\\s*\\[\\s*0\\s*\\]'}, {'function.body_contains_regex': 'int24\\s*\\(\\s*\\(.*tickCumulatives.*\\)\\s*/'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, "!function.body_contains_regex: '(?i)(delta\\s*<\\s*0|if.*<\\s*0.*\\-\\-|delta\\s*%\\s*int|tickDelta\\s*%)'", {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — twap-tick-delta-not-rounded-for-negative-values: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
