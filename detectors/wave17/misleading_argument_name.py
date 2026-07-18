"""
misleading-argument-name — generated from reference/patterns.dsl/misleading-argument-name.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py misleading-argument-name.yaml
Source: hexens audit Algebra_public_11_08
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class MisleadingArgumentName(AbstractDetector):
    ARGUMENT = "misleading-argument-name"
    HELP = "A `verifyCallback` helper names its first parameter `factory` while the implementation visibly routes through `poolDeployer`."
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/misleading-argument-name.yaml"
    WIKI_TITLE = "Misleading argument name"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only: this row proves only that the owned fixture pair separates a `verifyCallback(address factory, ...)` helper whose body visibly uses `poolDeployer` from a local variant that renames the parameter to match the source. NOT_SUBMIT_READY."
    WIKI_EXPLOIT_SCENARIO = "An Algebra-style callback helper exposes `verifyCallback(address factory, ...)`, but the implementation derives the callback pool from `poolDeployer`. Reviewers and integrators can misread the trust boundary because the parameter name implies a factory contract that the function body does not actually use."
    WIKI_RECOMMENDATION = "Rename the parameter to match the actual trust boundary, and keep this row NOT_SUBMIT_READY until evidence expands beyond the owned fixture pair."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(verifyCallback|poolDeployer|getPoolKey)'}]
    _MATCH = [{'function.name_matches': '^verifyCallback$'}, {'function.parameter_names_match': '^factory,'}, {'function.source_contains': 'getPoolKey(poolDeployer, tokenA, tokenB)'}, {'function.source_not_contains': 'function verifyCallback(address poolDeployer_'}]

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
                info = [f, f" — misleading-argument-name: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
