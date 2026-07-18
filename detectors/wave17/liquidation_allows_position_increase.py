"""
liquidation-allows-position-increase — generated from reference/patterns.dsl/liquidation-allows-position-increase.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py liquidation-allows-position-increase.yaml
Source: solodit/sherlock/perennial-v2-H4-45979
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class LiquidationAllowsPositionIncrease(AbstractDetector):
    ARGUMENT = "liquidation-allows-position-increase"
    HELP = "Liquidation path disables margin/solvency checks on the assumption liquidations only shrink positions, but never asserts `newSize < oldSize`. A collusive liquidator can grow the victim's position to an arbitrary size (2**62-1), then profit from the next price tick."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/liquidation-allows-position-increase.yaml"
    WIKI_TITLE = "Liquidation skips margin check without enforcing reduce-only on position"
    WIKI_DESCRIPTION = "Perps / margined markets frequently grant the liquidation path a relaxation of invariants — collateral floors, maintenance margin, and position-size caps are bypassed because liquidations are assumed to monotonically reduce risk. If the code doesn't enforce `require(newSize <= oldSize)` (reduce-only), the relaxation becomes a capability: a collusive self-liquidator submits a liquidation order that"
    WIKI_EXPLOIT_SCENARIO = "Attacker opens a tiny long from account A and a tiny maker from account B. A becomes liquidatable (or attacker forces it via partial close). The invariant `pending.neg == latestPosition.magnitude` holds because A pre-closed. Attacker calls liquidate(A, newLong=2**62-1). Because `protected` is true, InvariantLib skips margin and collateral checks; only the pending-magnitude equality is re-checked a"
    WIKI_RECOMMENDATION = "Add an explicit reduce-only assertion in the liquidation path: `require(newMagnitude <= oldMagnitude, 'liquidation must reduce position')`. Keep the relaxation of collateral / margin checks, but only under this guarantee. Add a unit test that attempts to increase size during a liquidation call and e"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_func_matching': '_?(liquidate|liquidation|closePositionForced)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(liquidate|liquidateAccount|liquidatePosition|liquidateCollateral|_liquidate|triggerLiquidation|executeLiquidation|forceClose|forceClosePosition|closePositionForced)$'}, {'function.has_param_of_type': 'uint'}, {'function.body_contains_regex': 'if\\s*\\(\\s*(protected|isLiquidation|liquidating|skipInvariant)\\s*\\)|protection\\s*==?\\s*true'}, {'function.body_not_contains_regex': 'require\\s*\\([^)]*newSize\\s*<=?\\s*oldSize|reduceOnly|require\\s*\\([^)]*(newPos|newAmount|newSize|newMagnitude)\\s*<\\s*(old|current|prev)|\\.magnitude\\(\\)\\s*<\\s*(old|latest|prev)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — liquidation-allows-position-increase: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
