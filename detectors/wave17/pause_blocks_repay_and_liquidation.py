"""
pause-blocks-repay-and-liquidation — generated from reference/patterns.dsl/pause-blocks-repay-and-liquidation.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py pause-blocks-repay-and-liquidation.yaml
Source: solodit/C0165
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PauseBlocksRepayAndLiquidation(AbstractDetector):
    ARGUMENT = "pause-blocks-repay-and-liquidation"
    HELP = "repay() / liquidate() guarded by whenNotPaused — interest still accrues, so pause traps borrowers into insolvency and blocks protocol de-leveraging."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/pause-blocks-repay-and-liquidation.yaml"
    WIKI_TITLE = "Pause blocks repay/liquidate: borrowers cannot de-risk while interest accrues"
    WIKI_DESCRIPTION = "Lending protocols apply a blanket pause modifier to every external action. When `repay` and `liquidate` are included, a protocol pause prevents borrowers from reducing debt and prevents liquidators from closing bad positions, while interest continues to accrue. Users are punished for the operator's pause."
    WIKI_EXPLOIT_SCENARIO = "Protocol pauses during a market shock. Borrower tries to repay before they go underwater — reverts due to whenNotPaused. Interest continues to compound against their collateral. When pause lifts, the position is deeply underwater and the borrower is force-liquidated at a steep penalty."
    WIKI_RECOMMENDATION = "Leave de-risking paths (repay, liquidate, withdraw-excess-collateral) permissionless during pause. Only pause borrow / new-deposit / new-market-creation. Alternatively, stop accruing interest while paused so borrowers are not punished for pause duration."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': '(?i)(paused|_paused|stopped)'}, {'contract.has_function_matching': '(?i)(repay|liquidate)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(repay|repayBorrow|repayBehalf|repayOnBehalf|liquidate|liquidateBorrow|liquidatePosition|liquidatePartyA|liquidateAccount)$'}, {'function.has_modifier': {'includes': ['whenNotPaused', 'onlyWhenNotPaused', 'notPaused', 'whenActive']}}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — pause-blocks-repay-and-liquidation: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
