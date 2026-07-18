"""
funding-rate-raw-seconds-fixedpoint-mismatch - generated from reference/patterns.dsl/funding-rate-raw-seconds-fixedpoint-mismatch.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py funding-rate-raw-seconds-fixedpoint-mismatch.yaml
Source: auditooor-realworld-recall-gap-funding-rate-manipulation-2026-06-02
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FundingRateRawSecondsFixedpointMismatch(AbstractDetector):
    ARGUMENT = "funding-rate-raw-seconds-fixedpoint-mismatch"
    HELP = "Funding accrual passes an unscaled seconds delta into a fixed-point multiplication helper, shrinking or distorting funding growth."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/funding-rate-raw-seconds-fixedpoint-mismatch.yaml"
    WIKI_TITLE = "Funding accrual uses fixed-point multiplication with raw elapsed seconds"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only. NOT_SUBMIT_READY. Perp funding accrual must keep units consistent between the funding rate and elapsed time. If a WAD-scaled funding rate is passed into `wadMul`, `mulWadDown`, `mulDecimal`, or an equivalent fixed-point helper with a raw seconds delta, the helper divides by the fixed-point scale even though the time delta was never scaled."
    WIKI_EXPLOIT_SCENARIO = "A market accrues funding by computing `elapsed = block.timestamp - lastAccrualTime`, then applies `mulWadDown(fundingRatePerSecondWad, elapsed)` and writes the result into a funding accumulator. Because `elapsed` is raw seconds, the accumulator advances at the wrong scale. Traders can hold skewed positions through the under-accrued interval and settle funding at a manipulated rate."
    WIKI_RECOMMENDATION = "Use plain multiplication for per-second WAD rates and raw seconds, or scale the elapsed seconds into WAD before calling a fixed-point multiplication helper. Add invariant tests that compare one-second, one-hour, and one-day funding accrual against the expected unit model."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(funding|perpetual|perp|markPrice|indexPrice|openInterest|cumulativeFunding|fundingAccumulator)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': '(?i)((update|accrue|apply|compute|settle).*(funding|rate)|(funding|rate).*(update|accrue|settle|compute))'}, {'function.reads_block_timestamp': True}, {'function.body_ordered_regex': {'first': '\\b(?:uint(?:256)?\\s+)?(elapsed|dt|deltaTime|timeElapsed|secondsElapsed)\\b\\s*=\\s*block\\.timestamp\\s*-\\s*[A-Za-z_][A-Za-z0-9_]*', 'second': '(wadMul|mulWad(?:Down|Up)?|wmul|mulDivFixedPoint|mulDecimal)\\s*\\([^;]*\\b(elapsed|dt|deltaTime|timeElapsed|secondsElapsed)\\b', 'ignore_comments_and_strings': True}}, {'function.body_contains_regex': '(?i)(cumulativeFunding|fundingAccumulator|totalFunding|fundingDelta|normalizationFactor|fundingIndex)\\s*[-+]?='}, {'function.body_not_contains_regex': '(?i)(elapsedWad|dtWad|deltaTimeWad|timeElapsedWad|secondsElapsedWad|toWad|toFixed|SECONDS_PER|1\\s+days|365\\s+days)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)\\b'}]

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
                info = [f, f" - funding-rate-raw-seconds-fixedpoint-mismatch: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
