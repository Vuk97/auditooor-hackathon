"""
weight-calc-index-mismatch — generated from reference/patterns.dsl/weight-calc-index-mismatch.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py weight-calc-index-mismatch.yaml
Source: solodit/C0083
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class WeightCalcIndexMismatch(AbstractDetector):
    ARGUMENT = "weight-calc-index-mismatch"
    HELP = "Weighted-pool weight-update or weight-read function indexes into weights[] without asserting the index is in-bounds or that weights.length matches tokens.length — silent off-by-one loads the wrong token's weight and corrupts the invariant."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/weight-calc-index-mismatch.yaml"
    WIKI_TITLE = "Weight array indexed without length consistency or bounds check"
    WIKI_DESCRIPTION = "Balancer-style weighted AMMs keep two parallel arrays: `tokens[]` and `weights[]` (or `normalizedWeights[]`). Every swap, join, or exit price calculation relies on `tokens[i]` and `weights[i]` referring to the SAME pool asset. When a weight-update or weight-read function loads `weights[i]` without first asserting (a) `i < weights.length` AND (b) `weights.length == tokens.length`, any drift between"
    WIKI_EXPLOIT_SCENARIO = "A weighted pool holds 3 tokens with weights [0.5, 0.3, 0.2]. An admin calls `removeToken(2)` which pops `tokens[2]` but leaves `weights[2]` in place (len(weights)=3, len(tokens)=2). A user calls `getNormalizedWeights()`; the function loops `i=0..weights.length` without checking `tokens.length`, returns [0.5, 0.3, 0.2] summing to 1.0 — but the pool only has two assets. A swap router integrating wit"
    WIKI_RECOMMENDATION = "Every function that indexes `weights[i]` or `normalizedWeights[i]` must assert `i < weights.length` AND assert `weights.length == tokens.length` at entry. Better: collapse the two arrays into a single `Token[] { address token; uint96 weight; }` struct so the invariant is impossible to violate. Add a"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'weights|normalizedWeights|tokenWeight|poolWeight|_weights'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'updateWeights|setWeights|_updateWeight|getNormalizedWeights|_setWeight|rebalanceWeights|calculateWeight'}, {'function.body_contains_regex': 'weights\\[|normalizedWeights\\[|_weights\\['}, {'function.body_not_contains_regex': 'require\\s*\\(.*(i|index|idx)\\s*<\\s*weights\\.length|i\\s*<\\s*tokens\\.length|require\\s*\\(.*(weights|tokens)\\.length\\s*(==|>)'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — weight-calc-index-mismatch: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
