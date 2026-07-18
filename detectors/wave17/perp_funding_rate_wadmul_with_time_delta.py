"""
perp-funding-rate-wadmul-with-time-delta — generated from reference/patterns.dsl/perp-funding-rate-wadmul-with-time-delta.yaml
Source: auditooor-R75-c4-2023-03-polynomial-H101
"""

# NOT_SUBMIT_READY: fixture-smoke/source-shape proof only for this row.

import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))

from _predicate_engine import eval_function_match, eval_preconditions
from _template_utils import is_leaf_helper, is_vendored_or_test_contract
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PerpFundingRateWadmulWithTimeDelta(AbstractDetector):
    ARGUMENT = "perp-funding-rate-wadmul-with-time-delta"
    HELP = (
        "NOT_SUBMIT_READY fixture-smoke/source-shape proof only: a perp funding "
        "update multiplies a WAD-scaled funding rate by a raw seconds delta via "
        "`wadMul(fundingRatePerSecond, dt)`, shrinking accrued funding by 1e18."
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = (
        "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/"
        "perp-funding-rate-wadmul-with-time-delta.yaml"
    )
    WIKI_TITLE = "Funding accrual uses wadMul with a raw timestamp delta"
    WIKI_DESCRIPTION = (
        "Fixture-smoke/source-shape proof only. NOT_SUBMIT_READY. This row "
        "flags only the direct perp funding shape where a function derives a raw "
        "`dt`/`timeElapsed` from `block.timestamp - lastFundingTime` and then "
        "calls `wadMul(fundingRatePerSecond, dt)` or an equivalent "
        "`fundingRate`/`timeElapsed` spelling. Because `wadMul(a, b)` divides by "
        "1e18, using a non-WAD time delta under-accrues total funding by 1e18x."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "Motivating Polynomial-shaped scenario: a market stores "
        "`fundingRatePerSecond` in WAD, computes `dt = block.timestamp - "
        "lastFundingTime`, and then applies `wadMul(fundingRatePerSecond, dt)` "
        "to grow `totalFunding` or `normalizationFactor`. Funding stays nearly "
        "flat even across long delays. This row does not claim corpus-backed "
        "exploit evidence beyond the owned fixture/source-shape smoke."
    )
    WIKI_RECOMMENDATION = (
        "Use plain multiplication for the raw time delta, e.g. "
        "`fundingRatePerSecond * dt`, or explicitly normalize day-based rates "
        "before multiplying by seconds. Do not promote from this fixture smoke "
        "alone; add protocol-specific evidence proving the scaling contract."
    )

    _PRECONDITIONS = [
        {
            "contract.source_matches_regex": (
                "(fundingRatePerSecond|fundingRate|totalFunding|"
                "normalizationFactor|lastFundingTime)"
            )
        }
    ]
    _MATCH = [
        {"function.kind": "external_or_public_or_internal"},
        {
            "function.name_matches": (
                "(getMarkPrice|updateFunding|_updateFunding|accrueFunding|"
                "applyFunding|computeFunding|getFundingRate)"
            )
        },
        {"function.reads_block_timestamp": True},
        {
            "function.body_contains_regex": (
                r"uint(?:256)?\s+(dt|timeElapsed|deltaTime)\s*=\s*"
                r"block\.timestamp\s*-\s*[A-Za-z_][A-Za-z0-9_]*"
            )
        },
        {
            "function.body_contains_regex": (
                r"wadMul\s*\(\s*"
                r"(fundingRatePerSecond|fundingRate|rate|fundingPerSecond)"
                r"\s*,\s*(dt|timeElapsed|deltaTime)\s*\)"
            )
        },
        {
            "function.body_not_contains_regex": (
                r"(fundingRatePerSecond|fundingRate|rate|fundingPerSecond)"
                r"\s*\*\s*(dt|timeElapsed|deltaTime)"
            )
        },
        {"function.not_in_skip_list": True},
        {"function.not_leaf_helper": True},
        {"function.not_source_matches_regex": r"(?i)\b(mock|test|fixture)"},
    ]

    _INCLUDE_LEAF_HELPERS = False
    _INVERSE_CEI = False

    def _detect(self):
        results = []
        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if not eval_preconditions(contract, self._PRECONDITIONS):
                continue
            for function in contract.functions_and_modifiers_declared:
                if not self._INCLUDE_LEAF_HELPERS and is_leaf_helper(function):
                    continue
                if not eval_function_match(function, self._MATCH):
                    continue
                info = [
                    function,
                    " — perp-funding-rate-wadmul-with-time-delta: pattern matched. "
                    "See WIKI for details.",
                ]
                results.append(self.generate_result(info))
        return results
