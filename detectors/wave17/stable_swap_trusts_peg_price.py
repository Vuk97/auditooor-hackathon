"""
stable-swap-trusts-peg-price — generated from reference/patterns.dsl/stable-swap-trusts-peg-price.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py stable-swap-trusts-peg-price.yaml
Source: auditooor-cross-cluster
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class StableSwapTrustsPegPrice(AbstractDetector):
    ARGUMENT = "stable-swap-trusts-peg-price"
    HELP = "Function values a stablecoin at a hardcoded 1:1 peg (1e6/1e8/1e18) without consulting any oracle — depeg events (UST, USDC, FRAX) instantly mis-price collateral/debt and make the protocol insolvent."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/stable-swap-trusts-peg-price.yaml"
    WIKI_TITLE = "Stablecoin priced at hardcoded peg without oracle (peg-trust)"
    WIKI_DESCRIPTION = "A lending / vault / swap helper values USDC, USDT, DAI (or wrapped stable derivatives) at par by returning a constant precision literal (1e6, 1e8, 1e18) or an isStable-gated short-circuit, instead of fetching a live price from Chainlink or an equivalent oracle. The assumption that a stablecoin always equals $1 has been falsified multiple times (UST 2022 → $0.10, USDC SVB Mar 2023 → $0.88, several "
    WIKI_EXPLOIT_SCENARIO = "USDC depegs to $0.88 during an SVB-style event. The lending pool's _getPrice(USDC) returns 1e18 because the contract hardcodes the stable at par. An attacker deposits USDC worth $8.8M (marked as $10M collateral), borrows $9M of ETH against it, and walks away. The pool is left with $8.8M of collateral backing $9M of debt, insolvent at rehydration."
    WIKI_RECOMMENDATION = "Never assume a stablecoin equals $1. Route every stable valuation through the same oracle path used for volatile assets (Chainlink USDC/USD, USDT/USD, DAI/USD) with staleness and L2-sequencer checks. If a par-peg is truly desired as a fallback, bound it behind a circuit-breaker that trips when the l"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': '\\breturn\\s+1e(6|8|18)\\b|1e18\\s*\\*\\s*amount|priceE18\\s*=\\s*1e18|return\\s+PRECISION|isStable|assumeOne'}, {'function.body_not_contains_regex': 'oracle\\.getPrice|priceFeed\\.|\\.latestAnswer|\\.latestRoundData|chainlink\\.'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — stable-swap-trusts-peg-price: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
