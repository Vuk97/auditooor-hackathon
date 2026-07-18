"""
oracle-price-bounds-or-asymmetric-min-fire18 custom Slither detector.

This recall-lift detector groups oracle price manipulation shapes that share
the same risk math invariant:

* multi-oracle lending math must use min for collateral and max for debt;
* Chainlink-style reads must reject stale answers and enforce sanity bounds;
* LTV setters must keep LTV below liquidation threshold;
* hardcoded price denominators must be tied to the feed decimals;
* oracle-controlled supply deltas must be refreshed before tally math.

Detector evidence is fixture-smoke only. Hits are candidate evidence, not a
submission-ready proof.
"""

import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _predicate_engine import eval_function_match, eval_preconditions
from _template_utils import is_leaf_helper, is_vendored_or_test_contract

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class OraclePriceBoundsOrAsymmetricMinFire18(AbstractDetector):
    ARGUMENT = "oracle-price-bounds-or-asymmetric-min-fire18"
    HELP = (
        "Oracle price or lending-risk math misses asymmetric min/max, "
        "freshness, bound, LTV, or denominator checks."
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/"
    WIKI_TITLE = "Oracle price bound or asymmetric min violation"
    WIKI_DESCRIPTION = (
        "Lending, collateral, liquidation, and tally code that consumes oracle "
        "prices must preserve price-domain safety. Unsafe shapes include "
        "using min on both collateral and debt valuation, accepting a "
        "Chainlink answer without freshness or min/max bounds, setting LTV "
        "without checking liquidationThreshold, hardcoding a price divisor "
        "without feed decimals, or tallying oracle-controlled supply deltas "
        "without refreshing the local accounting state."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A borrower opens or avoids liquidation while two oracle prices diverge, "
        "or a governance/config path admits LTV above liquidation threshold. "
        "The protocol then values collateral, debt, or tally state against the "
        "wrong side of the price domain."
    )
    WIKI_RECOMMENDATION = (
        "Use min for collateral and max for debt, enforce oracle freshness and "
        "sanity bounds, keep LTV below liquidation threshold, derive scale from "
        "feed decimals, and refresh oracle-controlled accounting before tally "
        "math."
    )
    SUBMISSION_POSTURE = "NOT_SUBMIT_READY"

    _PRECONDITIONS = [
        {
            "contract.source_matches_regex": (
                "oracle|priceFeed|aggregator|latestRoundData|getPrice|"
                "collateral|borrow|debt|liquidat|ltv|loanToValue|"
                "liquidationThreshold|oracleSupplyChange|supplyChange"
            )
        }
    ]

    _BRANCHES = [
        (
            "symmetric-min-price-sides",
            [
                {"function.kind": "external_or_public"},
                {
                    "function.name_matches": (
                        "(borrow|withdraw|liquidate|health|account|collateral|"
                        "solvency|open|close|preview)"
                    )
                },
                {
                    "function.source_matches_regex": (
                        "(oracle|price|feed|twap|chainlink)[\\s\\S]*"
                        "(_min\\s*\\(|Math\\.min\\s*\\(|\\bmin\\s*\\()"
                    )
                },
                {
                    "function.source_matches_regex": (
                        "collateral[\\s\\S]*(debt|borrow|liability)|"
                        "(debt|borrow|liability)[\\s\\S]*collateral"
                    )
                },
                {
                    "function.not_source_matches_regex": (
                        "(debtPrice|liabilityPrice|borrowPrice)\\s*=\\s*[^;]*"
                        "(_max\\s*\\(|Math\\.max\\s*\\(|\\bmax\\s*\\()|"
                        "collateralPrice\\s*=\\s*[^;]*(_min|Math\\.min|min)"
                        "[\\s\\S]*(debtPrice|liabilityPrice|borrowPrice)"
                        "\\s*=\\s*[^;]*(_max|Math\\.max|max)"
                    )
                },
                {"function.not_in_skip_list": True},
            ],
        ),
        (
            "missing-oracle-bound-or-freshness",
            [
                {"function.kind": "external_or_public"},
                {
                    "function.name_matches": (
                        "(borrow|withdraw|liquidate|health|quote|getPrice|"
                        "priceOf|account|collateral|solvency)"
                    )
                },
                {
                    "function.source_matches_regex": (
                        "latestRoundData\\s*\\(|latestAnswer\\s*\\(|"
                        "getPrice\\s*\\("
                    )
                },
                {
                    "function.source_matches_regex": (
                        "collateral|debt|borrow|liquidat|ltv|health|"
                        "threshold|tally|vote"
                    )
                },
                {
                    "function.not_source_matches_regex": (
                        "MIN_PRICE|MAX_PRICE|minPrice|maxPrice|minAnswer|"
                        "maxAnswer|lowerBound|upperBound|priceBound|"
                        "sanityBound|deviation|updatedAt|answeredInRound|"
                        "block\\.timestamp|stale|fallback|secondary|twap|"
                        "median|crossCheck"
                    )
                },
                {"function.not_in_skip_list": True},
            ],
        ),
        (
            "ltv-liquidation-threshold-bound-missing",
            [
                {"function.kind": "external_or_public"},
                {
                    "function.name_matches": (
                        "setLtv|setLoanToValue|setLiquidationThreshold|"
                        "configureReserveAsCollateral|setReserveParams|"
                        "setCollateralConfig|updateReserve|setEMode"
                    )
                },
                {
                    "function.source_matches_regex": (
                        "ltv|loanToValue|liquidationThreshold|liqThreshold"
                    )
                },
                {
                    "function.body_not_contains_regex": (
                        "\\b(ltv|newLtv|loanToValue)\\s*<=\\s*[^;]*"
                        "(liquidationThreshold|liqThreshold|\\blt\\b)|"
                        "(liquidationThreshold|liqThreshold|\\blt\\b)\\s*>=\\s*"
                        "(ltv|newLtv|loanToValue)|"
                        "require\\s*\\([^)]*\\b(ltv|newLtv|loanToValue)\\b[^)]*"
                        "(liquidationThreshold|liqThreshold|\\blt\\b)"
                    )
                },
                {
                    "function.not_source_matches_regex": (
                        "view\\s+returns|pure\\s+returns|_packConfiguration|"
                        "PercentageMath\\.percentMul"
                    )
                },
            ],
        ),
        (
            "hardcoded-oracle-price-denominator",
            [
                {"function.kind": "external_or_public"},
                {
                    "function.source_matches_regex": (
                        "latestRoundData\\s*\\(|latestAnswer\\s*\\(|"
                        "priceFeed"
                    )
                },
                {
                    "function.source_matches_regex": (
                        "(collateral|debt|borrow|liquidat|ltv|health|quote)"
                        "[\\s\\S]*(/|\\*)\\s*(1e6|1e8|1e18|10\\s*\\*\\*\\s*"
                        "\\d+)"
                    )
                },
                {
                    "function.not_source_matches_regex": (
                        "\\.decimals\\s*\\(|feedDecimals|oracleDecimals|"
                        "priceDecimals|scale\\s*=|denominator\\s*=|"
                        "checkedScale|normalizePrice|MIN_PRICE|MAX_PRICE|"
                        "updatedAt|answeredInRound|block\\.timestamp|"
                        "debtPrice|collateralPrice|_max\\s*\\(|"
                        "Math\\.max\\s*\\(|\\bmax\\s*\\("
                    )
                },
                {"function.not_in_skip_list": True},
            ],
        ),
        (
            "oracle-supply-tally-refresh-missing",
            [
                {"function.kind": "external_or_public"},
                {
                    "function.name_matches": (
                        "postOracleSupplyChange|tallyOracleSupplyChange|"
                        "convertSupplyChangeToPercentileChange|tally"
                    )
                },
                {
                    "function.source_matches_regex": (
                        "oracleSupplyChange|supplyChange|percentileChange"
                    )
                },
                {"function.source_matches_regex": "\\*"},
                {
                    "function.not_source_matches_regex": (
                        "(accrue|update|sync|validate|check|refresh)\\s*\\("
                    )
                },
                {"function.not_in_skip_list": True},
            ],
        ),
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
                for branch_name, branch in self._BRANCHES:
                    if (
                        branch_name != "ltv-liquidation-threshold-bound-missing"
                        and not self._INCLUDE_LEAF_HELPERS
                        and is_leaf_helper(function)
                    ):
                        continue
                    if not eval_function_match(function, branch):
                        continue
                    info = [
                        function,
                        " - oracle-price-bounds-or-asymmetric-min-fire18: ",
                        f"{branch_name} pattern matched. ",
                        "Treat as candidate evidence only.",
                    ]
                    results.append(self.generate_result(info))
        return results
