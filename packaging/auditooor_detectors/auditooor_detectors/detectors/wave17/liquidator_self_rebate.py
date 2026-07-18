"""
liquidator-self-rebate — generated from reference/patterns.dsl/liquidator-self-rebate.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py liquidator-self-rebate.yaml
Source: solodit/C0345
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class LiquidatorSelfRebate(AbstractDetector):
    ARGUMENT = "liquidator-self-rebate"
    HELP = "Liquidation pays seized collateral to `msg.sender` with no `msg.sender != borrower` guard. A borrower can liquidate their own unhealthy position, collect the liquidation bonus AND have their own debt written down — effectively self-rebating at the protocol's expense."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/liquidator-self-rebate.yaml"
    WIKI_TITLE = "Liquidator self-rebate: missing `msg.sender != borrower` guard"
    WIKI_DESCRIPTION = "The liquidation routine transfers collateral to `msg.sender` and separately credits the debt write-down against the `borrower` argument. With no check that the caller and borrower are distinct, the borrower can call `liquidate(self, ...)` once their own position becomes liquidatable and pocket the seized collateral PLUS the bonus PLUS the debt reduction — converting what should be a protocol-prote"
    WIKI_EXPLOIT_SCENARIO = "Alice's lending position is liquidatable (`healthFactor < 1`). Instead of waiting to be liquidated by an external searcher, she calls `liquidate(alice, maxDebt)` from her own EOA. The contract validates only that the position is unhealthy, transfers her seized collateral to `msg.sender` (== alice), and credits the debt reduction against the borrower field (== alice). Alice keeps the collateral and"
    WIKI_RECOMMENDATION = "Add an explicit `require(msg.sender != borrower, \"self-liquidation\")` guard at the top of every liquidation entry point. For multi-asset protocols, also forbid the liquidator from being a delegate / smart-wallet owner of the borrower. Consider routing liquidator proceeds through a short-delay escr"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'debt|borrow|position|borrowers'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(liquidate|_liquidate|liquidatePosition|seizeCollateral)$'}, {'function.body_contains_regex': {'regex': 'transfer\\s*\\(\\s*msg\\.sender|_transfer\\s*\\(\\s*msg\\.sender|safeTransfer\\s*\\(\\s*msg\\.sender'}}, {'function.body_not_contains_regex': 'require\\s*\\(.*(msg\\.sender\\s*!=\\s*borrower|borrower\\s*!=\\s*msg\\.sender|liquidator\\s*!=\\s*borrower)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — liquidator-self-rebate: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
