"""
r94-loop-pending-withdrawal-amount-reset-by-view — generated from reference/patterns.dsl/r94-loop-pending-withdrawal-amount-reset-by-view.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-pending-withdrawal-amount-reset-by-view.yaml
Source: loop-cycle-87-sol-sibling
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopPendingWithdrawalAmountResetByView(AbstractDetector):
    ARGUMENT = "r94-loop-pending-withdrawal-amount-reset-by-view"
    HELP = "r94-loop-pending-withdrawal-amount-reset-by-view"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-pending-withdrawal-amount-reset-by-view.yaml"
    WIKI_TITLE = "r94-loop-pending-withdrawal-amount-reset-by-view"
    WIKI_DESCRIPTION = "r94-loop-pending-withdrawal-amount-reset-by-view"
    WIKI_EXPLOIT_SCENARIO = "r94-loop-pending-withdrawal-amount-reset-by-view"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(_pendingWithdrawalAmount|pendingAmount|_pendingAmount)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(get[A-Z_][a-zA-Z0-9_]*|view[A-Z_][a-zA-Z0-9_]*|total[A-Z_][a-zA-Z0-9_]*|read[A-Z_][a-zA-Z0-9_]*|fetch[A-Z_][a-zA-Z0-9_]*|query[A-Z_][a-zA-Z0-9_]*|pendingAmount|pendingWithdrawal[a-zA-Z0-9_]*|withdrawalTotal[a-zA-Z0-9_]*|totalPending[a-zA-Z0-9_]*|balanceOf|previewWithdraw|previewRedeem)$'}, {'function.source_matches_regex': '(_pendingWithdrawalAmount|pendingWithdrawalAmount|pendingAmount|_pendingAmount|withdrawalQueueTotal)\\s*=\\s*(0|\\w+)'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — r94-loop-pending-withdrawal-amount-reset-by-view: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
