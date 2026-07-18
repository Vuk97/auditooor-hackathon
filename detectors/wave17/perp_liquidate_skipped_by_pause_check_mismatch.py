"""
perp-liquidate-skipped-by-pause-check-mismatch — generated from reference/patterns.dsl/perp-liquidate-skipped-by-pause-check-mismatch.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py perp-liquidate-skipped-by-pause-check-mismatch.yaml
Source: auditooor-R73-fixdiff-mined-mux3-protocol-bd5511cc3b
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PerpLiquidateSkippedByPauseCheckMismatch(AbstractDetector):
    ARGUMENT = "perp-liquidate-skipped-by-pause-check-mismatch"
    HELP = "Liquidate function is gated with the wrong OrderType in whenNotPaused. Pausing liquidity/position orders stops liquidations (or worse, the dedicated liquidate-pause flag has no effect)."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/perp-liquidate-skipped-by-pause-check-mismatch.yaml"
    WIKI_TITLE = "Liquidate gated on wrong OrderType enum — pause flag misrouted"
    WIKI_DESCRIPTION = "When a protocol adds granular pause flags per order type (PositionOrder, LiquidityOrder, WithdrawalOrder, RebalanceOrder, AdlOrder, LiquidateOrder), the gate on each function must use the matching enum. A copy-paste mistake — e.g. liquidate gated on `OrderType.LiquidityOrder` — ties liquidation liveness to the LP pause flag. Admin pausing LP operations (for a migration) also halts liquidations; ad"
    WIKI_EXPLOIT_SCENARIO = "(1) Protocol admin pauses liquidations via `setPaused(OrderType.LiquidateOrder, true)` in preparation for a migration. (2) `fillLiquidateOrder` is gated on `whenNotPaused(OrderType.LiquidityOrder)` — the LP flag. (3) Liquidations continue to execute against migration-frozen positions at stale prices, producing bad debt. Inverse failure: admin pauses LP ops for an upgrade; liquidations are silently"
    WIKI_RECOMMENDATION = "Every pauseable action must gate on its own distinct enum value. Add a compile-time or test-time matrix: for each function name containing the action word (liquidate / adl / rebalance), assert the gate references the matching enum. In review, always check that the function family (`liquidate*`, `pla"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(whenNotPaused|OrderType\\.).*(liquidate|Liquidate)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': '(liquidate|_liquidate|fillLiquidateOrder|placeLiquidate)'}, {'function.body_contains_regex': 'whenNotPaused\\s*\\(\\s*OrderType\\.(LiquidityOrder|PositionOrder|WithdrawalOrder|RebalanceOrder|AdlOrder)\\s*\\)'}, {'function.body_not_contains_regex': 'whenNotPaused\\s*\\(\\s*OrderType\\.LiquidateOrder\\s*\\)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — perp-liquidate-skipped-by-pause-check-mismatch: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
