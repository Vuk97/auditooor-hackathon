"""
merkle-index-unchecked — generated from reference/patterns.dsl/merkle-index-unchecked.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py merkle-index-unchecked.yaml
Source: solodit-novel/slice_aa-EigenLayer
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class MerkleIndexUnchecked(AbstractDetector):
    ARGUMENT = "merkle-index-unchecked"
    HELP = "Merkle-proof function takes a user-supplied leaf `index`/`leafIndex` but never bounds it against the tree height. Without `index < 2**TREE_HEIGHT`, an attacker can submit an index larger than the tree and re-map their proof to unreachable leaves (EigenLayer-style finding)."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/merkle-index-unchecked.yaml"
    WIKI_TITLE = "Merkle leaf index not bounded to tree height"
    WIKI_DESCRIPTION = "When a verifier reconstructs a merkle leaf from (index, proof), the index encodes the path direction (left/right). Without an upper bound, attackers can submit arbitrarily large indices that re-index paths and target uncommitted leaves, creating proof collisions."
    WIKI_EXPLOIT_SCENARIO = "Airdrop verifier reads `(index, amount, proof)` from calldata and computes `verifyCalldata(proof, root, leaf)`. No `require(index < TOTAL_LEAVES)`. An attacker crafts `(index=2**256-1, amount=LARGE, proof=...)` that collides with a valid sibling and steals the allocation."
    WIKI_RECOMMENDATION = "Add `require(index < TREE_SIZE)` where TREE_SIZE is 2**height (or the explicit leaf count committed in the root)."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'MerkleProof|merkleRoot|verifyProof|verifyCalldata'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.has_param_name_matching': 'index|idx|leafIndex|proofIndex'}, {'function.body_contains_regex': 'MerkleProof\\.|verifyProof|verifyCalldata|_verify\\s*\\('}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*index\\s*<|require\\s*\\(\\s*idx\\s*<|index\\s*<\\s*2\\s*\\*\\*|require\\s*\\(\\s*leafIndex\\s*<|if\\s*\\(\\s*index\\s*>=\\s*|index\\s*>\\s*\\w+\\s*\\)\\s*revert'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — merkle-index-unchecked: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
