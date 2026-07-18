"""
oracle-observation-cardinality-grief-reverts-liquidation — generated from reference/patterns.dsl/oracle-observation-cardinality-grief-reverts-liquidation.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py oracle-observation-cardinality-grief-reverts-liquidation.yaml
Source: auditooor-R75-c4-lending-wise-lending-86
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class OracleObservationCardinalityGriefRevertsLiquidation(AbstractDetector):
    ARGUMENT = "oracle-observation-cardinality-grief-reverts-liquidation"
    HELP = "Oracle path reads a rolling TWAP window but the protocol never enforces sufficient observation cardinality, and does not catch the `OracleTargetTooOld`/observe-revert. Attacker can DoS the oracle (and therefore liquidations) by spamming AMM writes."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/oracle-observation-cardinality-grief-reverts-liquidation.yaml"
    WIKI_TITLE = "TWAP observation cardinality not enforced, enables oracle DoS of liquidations"
    WIKI_DESCRIPTION = "Uniswap V3 and Pendle expose a ring buffer of `MAX_CARDINALITY` observation slots. Reading a TWAP over `twapSeconds` requires the oldest observation to be at least `twapSeconds` in the past. If cardinality is small and block time is short, an attacker can write one new observation per block (a minimal swap / redeem) to overwrite the oldest slot, making `oldest < twapSeconds` ago. The call `observe"
    WIKI_EXPLOIT_SCENARIO = "Pendle market has 15 observation slots; block time 12s; `twapSeconds = 1800`. Attacker posts a 1-wei swap every block: after 180s they overwrite the oldest slot. Oldest observation is now ~180s ago, which is < 1800s. `market.observe([0, 1800])` reverts. Liquidator can't price the collateral, liquidation reverts. ETH drops, collateral ratio goes negative, bad debt is permanent."
    WIKI_RECOMMENDATION = "On oracle add, require `cardinality * expected_block_time >= twapSeconds * SAFETY_FACTOR`. Proactively call `increaseObservationsCardinalityNext` to push cardinality to the safe value. Wrap TWAP reads in `try/catch` so a reverting oracle degrades gracefully (pause liquidations, fall back to Chainlin"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(PendleLpOracle|IPMarket|IUniswapV3Pool|observe|getOracleState|increaseObservationCardinality)'}]
    _MATCH = [{'function.kind': 'internal_or_external'}, {'function.name_matches': '(?i)(latestAnswer|latestResolver|getPrice|_getTwap|consult|_oracleTargetCheck|_getPendleTwap)'}, {'function.body_contains_regex': '(?i)(market\\.observe|IPMarket.*observe|pool\\.observe|oracleState|getOldestObservation)'}, {'function.body_not_contains_regex': '(?i)(increaseObservationsCardinalityNext|cardinalityNext|OracleTargetTooOld.*catch|try\\s+\\w+\\.(observe|getOracleState)\\s*\\(|MAX_CARDINALITY|checkObservationCardinality)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — oracle-observation-cardinality-grief-reverts-liquidation: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
