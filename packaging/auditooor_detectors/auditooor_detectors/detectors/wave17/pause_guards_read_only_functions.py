"""
pause-guards-read-only-functions — generated from reference/patterns.dsl/pause-guards-read-only-functions.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py pause-guards-read-only-functions.yaml
Source: auditooor-round-32
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PauseGuardsReadOnlyFunctions(AbstractDetector):
    ARGUMENT = "pause-guards-read-only-functions"
    HELP = "Read-only view/pure function carries whenNotPaused (or notPaused/isNotPaused) modifier. When the contract is paused, every integration that reads protocol state reverts — almost always an unintended over-application of the pause guard."
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/pause-guards-read-only-functions.yaml"
    WIKI_TITLE = "Pause modifier on read-only view/pure function blocks state queries during emergencies"
    WIKI_DESCRIPTION = "Pausable patterns exist to stop state mutations during an emergency. Applying `whenNotPaused` (or `notPaused` / `isNotPaused`) to a view/pure function breaks every consumer that needs to read protocol state while the contract is paused: UIs cannot render positions, indexers can't checkpoint, integrating protocols can't compute exit prices. The read has no security value to pause — it cannot move f"
    WIKI_EXPLOIT_SCENARIO = "A lending market pauses after an oracle incident. Its `getAccountLiquidity(address user) external view whenNotPaused returns (uint256)` reverts. A liquidator bot that tried to precompute safe exit prices gets a revert instead of a number, a dashboard that lets users see their health factor goes blank, and an integrating vault that marks-to-market through this read cannot finalise its NAV. The paus"
    WIKI_RECOMMENDATION = "Remove `whenNotPaused` from view/pure functions. The pause modifier should gate mutating entry-points only (deposits, withdrawals, liquidations, transfers). If the goal is to gate an *integration surface* (e.g. a price feed that other protocols consume), expose an explicit `pausedPrice()` accessor t"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.has_modifier': {'includes': ['whenNotPaused', 'notPaused', 'isNotPaused'], 'negate': False}}, {'function.body_contains_regex': '\\bview\\b|\\bpure\\b'}, {'function.body_not_contains_regex': '=\\s*[\\w.]+\\s*;|\\+=|-=|\\*=|\\/=|delete\\s+|push\\s*\\(|pop\\s*\\('}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

    _INCLUDE_LEAF_HELPERS = True
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
                info = [f, f" — pause-guards-read-only-functions: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
