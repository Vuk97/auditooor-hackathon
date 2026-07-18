"""
ec-stale-oracle-no-freshness-check — generated from reference/patterns.dsl/ec-stale-oracle-no-freshness-check.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py ec-stale-oracle-no-freshness-check.yaml
Source: economic-mining-R61
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class EcStaleOracleNoFreshnessCheck(AbstractDetector):
    ARGUMENT = "ec-stale-oracle-no-freshness-check"
    HELP = "latestRoundData() called but updatedAt timestamp never checked against block.timestamp; stale prices used silently during oracle outages."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/ec-stale-oracle-no-freshness-check.yaml"
    WIKI_TITLE = "Stale Chainlink oracle — missing freshness check on updatedAt"
    WIKI_DESCRIPTION = "The contract calls AggregatorV3Interface.latestRoundData() to obtain a price but discards the updatedAt return value without comparing it to block.timestamp. During a Chainlink heartbeat gap, network congestion, or oracle deprecation, the price can be hours or days stale. Any borrow, liquidation, or valuation using the price is computed against an incorrect rate."
    WIKI_EXPLOIT_SCENARIO = "USDC depegs to $0.87. Chainlink oracle hasn't updated in 2 hours. Lending protocol still prices USDC at $1.00 (stale). Attacker deposits USDC as collateral, borrows at 100% LTV against stale $1.00 price, walks away with overcollateralized loan proceeds."
    WIKI_RECOMMENDATION = "After calling latestRoundData, require: `require(block.timestamp - updatedAt <= MAX_STALENESS, 'stale price')`. Choose MAX_STALENESS to be slightly above the feed's configured heartbeat. Also validate roundId > 0 and answer > 0."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'latestRoundData|AggregatorV3Interface|ChainlinkOracle'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': '\\.latestRoundData\\(\\)'}, {'function.body_not_contains_regex': 'updatedAt|block\\.timestamp\\s*-\\s*\\w+|heartbeat|maxStaleness|MAX_DELAY|MAX_AGE|stale'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — ec-stale-oracle-no-freshness-check: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
