"""
liquidation-bonus-zero-prevents-liquidation — generated from reference/patterns.dsl/liquidation-bonus-zero-prevents-liquidation.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py liquidation-bonus-zero-prevents-liquidation.yaml
Source: solodit-cluster-LIQBONUS
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class LiquidationBonusZeroPreventsLiquidation(AbstractDetector):
    ARGUMENT = "liquidation-bonus-zero-prevents-liquidation"
    HELP = "Liquidation function computes seizeAmount = debt * (100 + bonus) / 100 where `bonus` can be zero (unset / default). A zero bonus yields seizeAmount == debt, leaving the liquidator with no profit after gas + oracle + swap costs, so no keeper liquidates and bad debt accumulates indefinitely."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/liquidation-bonus-zero-prevents-liquidation.yaml"
    WIKI_TITLE = "Liquidation bonus of zero disables liquidations (bad-debt accumulation)"
    WIKI_DESCRIPTION = "A lending / CDP protocol parameterises the liquidation payout as `seizeAmount = debt * (100 + liquidationBonus) / 100` (or an equivalent `bonusBps` / `incentive` scalar). If the bonus is zero — either because it was never set, was reset by a buggy setter, or the storage slot defaulted to zero after an upgrade — the liquidator's seize amount exactly equals the debt they must repay. They are then gu"
    WIKI_EXPLOIT_SCENARIO = "A new market is listed with `liquidationBonus` left at its default of zero. Prices move and Alice's position becomes insolvent. Liquidator keepers evaluate the `liquidate(alice)` call: seizeAmount equals debt, so profit is `0 - gas - slippage < 0`. They all abstain. Alice's position deteriorates from slightly underwater to deeply underwater as the price keeps moving. By the time the team notices a"
    WIKI_RECOMMENDATION = "Enforce a nonzero-bonus invariant at the contract or market level: (1) add `require(liquidationBonus > 0, \"bonus unset\")` at the top of every liquidation entry point, or (2) reject market-listing / setter calls that would leave the bonus at zero, or (3) define a `MIN_BONUS` constant (e.g., 200 bps"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'liquidationBonus|bonusBps|bonus|liqBonus|incentive'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'liquidate|_liquidate|liquidatePosition|seizeCollateral'}, {'function.body_contains_regex': 'liquidationBonus|bonusBps|\\+\\s*bonus|\\*\\s*bonus|incentive'}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*(liquidationBonus|bonus|incentive)\\s*>\\s*0|if\\s*\\(\\s*(bonus|incentive)\\s*==\\s*0\\s*\\)\\s*revert|\\bBONUS_MINIMUM\\b|\\bMIN_BONUS\\b'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — liquidation-bonus-zero-prevents-liquidation: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
