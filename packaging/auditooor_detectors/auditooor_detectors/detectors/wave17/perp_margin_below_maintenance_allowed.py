"""
perp-margin-below-maintenance-allowed — generated from reference/patterns.dsl/perp-margin-below-maintenance-allowed.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py perp-margin-below-maintenance-allowed.yaml
Source: solodit/perp-maintenance-margin-class
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PerpMarginBelowMaintenanceAllowed(AbstractDetector):
    ARGUMENT = "perp-margin-below-maintenance-allowed"
    HELP = "Perpetual-futures increase-position / adjust-margin / change-leverage path lets a caller reach a post-tx margin ratio BELOW the maintenance threshold. The resulting position is immediately liquidatable; the attacker can self-liquidate for the bonus or bait the insurance fund for a protocol-level los"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/perp-margin-below-maintenance-allowed.yaml"
    WIKI_TITLE = "Perp margin path allows margin ratio below maintenance threshold"
    WIKI_DESCRIPTION = "A perpetual-futures protocol splits solvency into an initial-margin requirement (needed to open or grow a position) and a maintenance-margin requirement (minimum to avoid liquidation). The function under review moves margin — increasing size, reducing collateral, raising leverage, or rebalancing — but does not re-verify the resulting ratio against the maintenance threshold. The caller can land in "
    WIKI_EXPLOIT_SCENARIO = "A perp exchange exposes `adjustMargin(int256 delta) external` that decrements trader collateral by `delta` without re-checking the resulting margin ratio. Alice deposits $1,000 collateral and opens a 10x long. She calls `adjustMargin(-950)` and withdraws $950 collateral, leaving $50 to back a $10,000 notional position — a 0.5% margin ratio, well below the 5% maintenance threshold. In the same tran"
    WIKI_RECOMMENDATION = "Every margin-moving entry point must call a shared `_requireHealthy(trader)` / `_checkMaintenance(trader)` helper at the END of its execution (after all state writes) that asserts `marginRatio(trader) >= maintenanceMargin`. Where leverage change and margin withdrawal are composed, run the check afte"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'margin|leverage|maintenanceMargin|imRatio|mmRatio'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'openPosition|increasePosition|adjustMargin|withdrawMargin|changeLeverage|rebalance'}, {'function.body_contains_regex': 'margin|leverage|imRatio'}, {'function.body_not_contains_regex': 'maintenanceMargin|mmRatio|require\\s*\\(.*(imRatio|margin|marginRatio)\\s*>=?\\s*(mm|maintenance|MM)|isHealthy|_checkHealth'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — perp-margin-below-maintenance-allowed: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
