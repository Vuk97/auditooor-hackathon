"""
ec-oracle-decimals-mismatch — generated from reference/patterns.dsl/ec-oracle-decimals-mismatch.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py ec-oracle-decimals-mismatch.yaml
Source: economic-mining-R61
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class EcOracleDecimalsMismatch(AbstractDetector):
    ARGUMENT = "ec-oracle-decimals-mismatch"
    HELP = "Chainlink oracle price (8 decimals) multiplied by token amount (18 decimals) without decimal normalization — price off by 10^10."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/ec-oracle-decimals-mismatch.yaml"
    WIKI_TITLE = "Oracle decimals mismatch — Chainlink 8-dec price used with 18-dec token amounts"
    WIKI_DESCRIPTION = "Chainlink price feeds return values with 8 decimal places, while most ERC-20 tokens use 18 decimal places. Multiplying the raw oracle price by a token amount without scaling by 10^decimals produces a value that is 10 orders of magnitude off from the intended economic quantity. This causes massively under- or over-valued collateral, borrow limits, and liquidation thresholds."
    WIKI_EXPLOIT_SCENARIO = "ETH Chainlink price = 2000e8 (2000 USD, 8 decimals). User deposits 1 ETH = 1e18 wei. Contract computes value = price * amount = 2000e8 * 1e18 = 2000e26. Expected: 2000e18 (2000 USD in 18 decimals). Contract thinks collateral is worth 10^8 times more, allowing unlimited borrowing."
    WIKI_RECOMMENDATION = "Always normalize oracle prices: `uint256 normalizedPrice = rawPrice * 10**(18 - priceFeed.decimals())`. Query priceFeed.decimals() dynamically rather than hardcoding 8 — some feeds use different precisions. Consider using a wrapper oracle that standardizes all outputs to 18 decimals."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'decimals|latestAnswer|latestRoundData|PRECISION|1e8|1e18'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': '\\.latestAnswer\\(\\)|\\.latestRoundData\\(\\)'}, {'function.body_contains_regex': 'price\\s*\\*\\s*amount|amount\\s*\\*\\s*price|value\\s*=.*price.*amount'}, {'function.body_not_contains_regex': '10\\s*\\*\\*\\s*8|1e8|decimals\\(\\)|PRICE_DECIMALS|8\\s*\\)|normaliz|scal.*price|price.*scal'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — ec-oracle-decimals-mismatch: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
