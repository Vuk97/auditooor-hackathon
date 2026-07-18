"""
merkle-tree-insert-overflow-past-capacity — generated from reference/patterns.dsl/merkle-tree-insert-overflow-past-capacity.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py merkle-tree-insert-overflow-past-capacity.yaml
Source: solodit/quantstamp/hinkal-60150
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class MerkleTreeInsertOverflowPastCapacity(AbstractDetector):
    ARGUMENT = "merkle-tree-insert-overflow-past-capacity"
    HELP = "Append-only Merkle tree uses `require(idx != 2**LEVELS)` as its capacity guard. The check fails open for idx > 2**LEVELS, and `insertMany` loops can push past capacity. Subsequent parent updates overwrite existing commitments, invalidating their nullifiers."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/merkle-tree-insert-overflow-past-capacity.yaml"
    WIKI_TITLE = "Merkle tree capacity check uses `!=` instead of `<`: overflow overwrites earlier commitments"
    WIKI_DESCRIPTION = "An append-only commitment tree (shielded pool, privacy mixer, ZK rollup) uses `require(newIndex != 2**LEVELS, 'Tree is full.')` to cap inserts. The `!=` form correctly blocks exactly one value but does not block `> 2**LEVELS`. A bulk-insert helper (`insertMany(leaves)`) calls `insert()` in a loop without its own cap check; once the tree reaches capacity, the next iteration's newIndex = 2**LEVELS +"
    WIKI_EXPLOIT_SCENARIO = "Tree has 16-leaf capacity (LEVELS=4). Attacker calls `insertMany([L1, L2, ..., L20])`. The first 16 insertions fill the tree. The 17th call: newIndex = 16, require(16 != 16) reverts — but require(16 != 16) is false so actually reverts. OK; the original bug fires at 17: newIndex = 17 at start, `17 != 16` passes. Parent index = 17/2 = 8, which is an existing leaf commitment. Parent-update hash write"
    WIKI_RECOMMENDATION = "Replace `!=` / `==` with `<` in the capacity guard: `require(newIndex < 2**LEVELS, 'Tree is full.')`. Duplicate the guard in every insert helper, including batch `insertMany`. Add an invariant test that tries to insert 2**LEVELS + k leaves and asserts revert for every overflow attempt."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': '(LEVELS|DEPTH|TREE_HEIGHT)'}]
    _MATCH = [{'function.kind': 'internal_or_external'}, {'function.name_matches': '(insert|append|addCommitment|pushLeaf)'}, {'function.body_contains_regex': 'require\\s*\\(\\s*\\w+Index\\s*!=\\s*(2\\s*\\*\\*\\s*\\w+|1\\s*<<\\s*\\w+)|require\\s*\\(\\s*\\w+Index\\s*==\\s*(2\\s*\\*\\*\\s*\\w+|1\\s*<<\\s*\\w+)'}, {'function.body_contains_regex': '/\\s*2|>>\\s*1|filledSubtrees|zeros\\s*\\('}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — merkle-tree-insert-overflow-past-capacity: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
