"""
glider-deletion-of-nested-struct — generated from reference/patterns.dsl/glider-deletion-of-nested-struct.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-deletion-of-nested-struct.yaml
Source: glider/deletion-of-nested-enumerable
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderDeletionOfNestedStruct(AbstractDetector):
    ARGUMENT = "glider-deletion-of-nested-struct"
    HELP = "`delete struct[id]` leaves nested mappings intact. Stale child data breaks re-insert paths and surfaces in state queries after `delete`."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-deletion-of-nested-struct.yaml"
    WIKI_TITLE = "delete on struct with nested mapping leaves stale child state"
    WIKI_DESCRIPTION = "Solidity's `delete` zero-initializes only the directly-addressed slots. Nested mappings are stored at keccak(slot) addresses the `delete` operation cannot know to iterate, so their values persist. A user who expects `delete positions[id]` to wipe the position's per-user sub-balance sees those sub-balances still readable after the delete, which breaks re-use of the same `id` or misleads downstream "
    WIKI_EXPLOIT_SCENARIO = "Vault has `struct Position { uint256 amount; mapping(address => uint256) rewardsOwed; }`. On `closePosition(id)`, code runs `delete positions[id]`. `positions[id].amount == 0` as expected, but `positions[id].rewardsOwed[alice]` still holds the pre-close reward value. A second `openPosition` reusing the same id inherits alice's reward — free claim."
    WIKI_RECOMMENDATION = "Never store nested mappings inside structs that are deleted. Use flat top-level mappings keyed by `(id, user)` so individual slots can be cleared explicitly. Or track every key the nested mapping touches and iterate-and-delete before the outer delete."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(mapping|array|struct)'}]
    _MATCH = [{'function.kind': 'any'}, {'function.body_contains_regex': 'delete\\s+\\w+\\s*\\[\\s*\\w+\\s*\\]\\s*;'}, {'contract.has_state_declaration_matching': 'struct\\s+\\w+\\s*\\{[^}]*mapping\\s*\\('}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-deletion-of-nested-struct: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
