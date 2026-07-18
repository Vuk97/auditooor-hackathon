"""
swap-pop-set-forward-remove-skip - generated from reference/patterns.dsl/swap-pop-set-forward-remove-skip.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py swap-pop-set-forward-remove-skip.yaml
Source: auditooor capability lift 2026-06-02 sibling generalizer
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class SwapPopSetForwardRemoveSkip(AbstractDetector):
    ARGUMENT = "swap-pop-set-forward-remove-skip"
    HELP = "Forward loop reads an EnumerableSet slot and removes from the same swap-pop set, skipping the swapped-in tail element."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/swap-pop-set-forward-remove-skip.yaml"
    WIKI_TITLE = "Swap-pop set forward remove skips validation"
    WIKI_DESCRIPTION = "A forward loop over a swap-pop set reads `set.at(i)` and removes from the same set. The tail element moves into the current slot, but the loop increments past it, so the swapped-in last element is not validated."
    WIKI_EXPLOIT_SCENARIO = "Forward loop reads an EnumerableSet slot and removes from the same swap-pop set, skipping the swapped-in tail element."
    WIKI_RECOMMENDATION = "Iterate swap-pop sets in reverse, defer removals to a second pass, or keep the cursor on the same index after a removal."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(EnumerableSet|AddressSet|UintSet|Bytes32Set|\\.remove\\s*\\(|\\.at\\s*\\()'}]
    _MATCH = [{'function.kind': 'any'}, {'function.not_leaf_helper': True}, {'function.not_in_skip_list': True}, {'function.body_contains_regex': 'for\\s*\\([^;]*;[^;]*(\\.length\\s*\\(\\s*\\)|<\\s*[A-Za-z_][A-Za-z0-9_]*)[^;]*;\\s*[A-Za-z_][A-Za-z0-9_]*\\s*\\+\\+\\s*\\)'}, {'function.body_contains_regex': '\\.at\\s*\\(\\s*[A-Za-z_][A-Za-z0-9_]*\\s*\\)'}, {'function.body_contains_regex': '\\.remove\\s*\\('}, {'function.body_not_contains_regex': 'for\\s*\\([^;]*;[^;]*>\\s*0[^;]*;\\s*[A-Za-z_][A-Za-z0-9_]*\\s*--'}, {'function.body_not_contains_regex': '(?i)(continue\\s*;|i\\s*=\\s*i|i\\s*--|--\\s*i|defer|toRemove|removeLater)'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)\\b'}]

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
                info = [f, f" - swap-pop-set-forward-remove-skip: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
