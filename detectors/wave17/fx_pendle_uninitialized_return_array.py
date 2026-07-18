"""
fx-pendle-uninitialized-return-array — generated from reference/patterns.dsl/fx-pendle-uninitialized-return-array.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py fx-pendle-uninitialized-return-array.yaml
Source: github:pendle-finance/pendle-core-v2-public@4df7abc
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FxPendleUninitializedReturnArray(AbstractDetector):
    ARGUMENT = "fx-pendle-uninitialized-return-array"
    HELP = "claimVerified() declares a uint256[] return variable but never initializes it with `new uint256[](n)`. The function iterates over indices writing to amountOuts[i], which accesses out-of-bounds storage and reverts or writes to a zero-length array."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/fx-pendle-uninitialized-return-array.yaml"
    WIKI_TITLE = "claimVerified() return array not initialized — out-of-bounds write reverts all claims"
    WIKI_DESCRIPTION = "Functions that return a dynamic array and populate it in a loop must explicitly initialize the array before writing: `amountOuts = new uint256[](n)`. Without initialization, the named return variable is a zero-length array; any index write `amountOuts[i] = x` will revert with an out-of-bounds panic, making the function completely non-functional."
    WIKI_EXPLOIT_SCENARIO = "Pendle MerkleDistributor (2024): claimVerified() has named return `amountOuts` but no `= new uint256[]` assignment. The first loop iteration writes amountOuts[0], panics with array-out-of-bounds, and all claim transactions revert."
    WIKI_RECOMMENDATION = "Before the loop, add: `amountOuts = new uint256[](tokens.length);`. Alternatively use the array-with-initialization pattern in the return variable declaration."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': '^claim$|^claimVerified$'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'claim|claimRewards|claimVerified|claimBatch'}, {'function.body_contains_regex': 'returns\\s*\\(\\s*uint256\\[\\]\\s*memory\\s*\\w+\\s*\\)|uint256\\[\\]\\s*memory\\s*\\w+\\s*='}, {'function.body_not_contains_regex': 'amountOuts\\s*=\\s*new\\s*uint256|result\\s*=\\s*new\\s*uint256'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — fx-pendle-uninitialized-return-array: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
