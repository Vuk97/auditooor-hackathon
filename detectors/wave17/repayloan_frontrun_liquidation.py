"""
repayloan-frontrun-liquidation — generated from reference/patterns.dsl/repayloan-frontrun-liquidation.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py repayloan-frontrun-liquidation.yaml
Source: solodit/C0311
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class RepayloanFrontrunLiquidation(AbstractDetector):
    ARGUMENT = "repayloan-frontrun-liquidation"
    HELP = "Repay entry point guards on a mutable `not-liquidated / position-active / healthy` state variable that a permissionless liquidate() call can flip. Attacker frontruns the repay tx with a liquidation to capture the liquidation penalty."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/repayloan-frontrun-liquidation.yaml"
    WIKI_TITLE = "Repay function blocked by permissionless liquidation frontrun"
    WIKI_DESCRIPTION = "A `repay` / `repayLoan` / `payBack` function requires the borrower's position to still be in an active / non-liquidated / healthy state. Because the matching `liquidate()` entry point on the same contract is permissionless, a searcher observing a repay transaction in the mempool can frontrun it with a liquidation call, causing the repay to revert on the require() and leaving the borrower with the "
    WIKI_EXPLOIT_SCENARIO = "Borrower's collateralisation ratio dips into the liquidatable band for one block. The borrower sends a `repayLoan(...)` tx to restore health. A searcher sees the pending repay in the mempool, submits `liquidate(borrower, ...)` with higher priority fee, and gets included first. The repay tx now reverts on `require(!positions[borrower].liquidated, ...)` — the borrower loses the liquidation bonus to "
    WIKI_RECOMMENDATION = "Either (a) make repayments always succeed up until the position is fully seized (allow partial repay on a being-liquidated position, crediting against outstanding debt), or (b) require liquidations to go through a commit-reveal / per-block auction so they cannot frontrun a mempool repay, or (c) gate"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': '^(liquidate|_liquidate|liquidatePosition|forceLiquidate)$'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(repay|repayLoan|repayDebt|_repay|payBack)$'}, {'function.body_contains_regex': {'regex': 'require\\s*\\(.*(liquidat|positionStatus|active|healthy|closeFactor)'}}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — repayloan-frontrun-liquidation: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
