"""
ec-twap-single-block-observation — generated from reference/patterns.dsl/ec-twap-single-block-observation.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py ec-twap-single-block-observation.yaml
Source: economic-mining-R61
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class EcTwapSingleBlockObservation(AbstractDetector):
    ARGUMENT = "ec-twap-single-block-observation"
    HELP = "Uniswap V3 TWAP observation uses a dangerously short window with no minimum enforcement, making the price equivalent to near-spot and easily manipulated."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/ec-twap-single-block-observation.yaml"
    WIKI_TITLE = "TWAP oracle with insufficient observation window (single-block risk)"
    WIKI_DESCRIPTION = "The contract queries a Uniswap V3 TWAP using observe() or OracleLibrary.consult() with a secondsAgo value that is either 0 (spot price), or a very small literal without a minimum-window requirement check. Short TWAP windows can be moved within a single block on low-liquidity pools, or within a few blocks via sustained manipulation on higher-liquidity pools."
    WIKI_EXPLOIT_SCENARIO = "Protocol uses consult(pool, 60) — a 60-second TWAP. On low-liquidity Uniswap V3 pool attacker pushes price 50% in block N via large trade, waits one block, reads TWAP which reflects the manipulated state, uses distorted price to borrow against inflated collateral value."
    WIKI_RECOMMENDATION = "Enforce a minimum TWAP window: `require(twapWindow >= MIN_TWAP_WINDOW, 'window too short')` with MIN_TWAP_WINDOW >= 1800 (30 min) on mainnet. On L2s with faster finality consider >= 300. Use Uniswap V3's built-in cardinality-increase mechanism to ensure enough historical observations exist."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'observe|OracleLibrary|consult|IUniswapV3Pool'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': '\\.observe\\(|OracleLibrary\\.consult\\(|\\.consult\\('}, {'function.body_contains_regex': 'secondsAgo|seconds_ago|period|twapWindow'}, {'function.body_contains_regex': '\\b(0|1|2|3|4|5|10|30|60)\\b'}, {'function.body_not_contains_regex': 'MIN_TWAP|minTwap|minPeriod|require\\s*\\(.*period|require\\s*\\(.*seconds'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — ec-twap-single-block-observation: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
