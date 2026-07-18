"""
glider-enumerable-set-remove-iteration-skip - generated from reference/patterns.dsl/glider-enumerable-set-remove-iteration-skip.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-enumerable-set-remove-iteration-skip.yaml
Source: glider/flawed-enumerable-set-remove-iteration-can-skip-el
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderEnumerableSetRemoveIterationSkip(AbstractDetector):
    ARGUMENT = "glider-enumerable-set-remove-iteration-skip"
    HELP = "Forward-iterating a swap-pop EnumerableSet while removing from the same set can skip the swapped-in tail element or revert under a stale cached bound."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-enumerable-set-remove-iteration-skip.yaml"
    WIKI_TITLE = "EnumerableSet forward-iteration with remove skips elements"
    WIKI_DESCRIPTION = "`EnumerableSet.remove` performs a swap-and-pop. When a forward `for` loop reads `set.at(i)` and then removes from that same set, the tail element can be swapped into slot `i` and never revisited because the loop post-increment advances to `i + 1`. If the loop caches `uint256 len = set.length();` before iterating, removals also make the upper bound stale, so later `set.at(i)` reads can revert or mi"
    WIKI_EXPLOIT_SCENARIO = "Governance sweep iterates blacklisted addresses, removing any address whose ban has expired. Attacker positions two addresses adjacently; when the first is removed the last (attacker) swaps in and is skipped, remaining banned zero-time instead of the intended-period."
    WIKI_RECOMMENDATION = "Iterate in reverse (`for (i=length; i>0; i--) { ... remove(at(i-1)); }`), collect to-remove items first and delete in a second pass, or use manual index control (`for (i=0; i<set.length(); )`) so the cursor stays on the current slot after a removal. Do not cache `length()` across removals unless the"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'EnumerableSet|AddressSet|UintSet|Bytes32Set'}]
    _MATCH = [{'function.kind': 'any'}, {'function.body_contains_regex': '(for\\s*\\([^)]*;[^)]*\\.length\\s*\\(\\s*\\)\\s*;[^)]*[a-zA-Z_][a-zA-Z0-9_]*\\s*\\+\\+\\s*\\))|(uint(?:256)?\\s+[a-zA-Z_][a-zA-Z0-9_]*\\s*=\\s*[a-zA-Z_][a-zA-Z0-9_\\.]*\\.length\\s*\\(\\s*\\)\\s*;\\s*for\\s*\\([^)]*;[^)]*<\\s*[a-zA-Z_][a-zA-Z0-9_]*\\s*;[^)]*[a-zA-Z_][a-zA-Z0-9_]*\\s*\\+\\+\\s*\\))'}, {'function.body_contains_regex': '\\.remove\\s*\\(\\s*[a-zA-Z_]+\\.at\\s*\\(|\\.remove\\s*\\(\\s*[a-zA-Z_]+\\s*\\)'}, {'function.body_not_contains_regex': 'length\\s*\\(\\s*\\)\\s*;\\s*[a-zA-Z_]+\\s*-'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" - glider-enumerable-set-remove-iteration-skip: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
