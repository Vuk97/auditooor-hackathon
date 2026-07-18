"""
glider-destroyable-contracts-with-ecrecover — generated from reference/patterns.dsl/glider-destroyable-contracts-with-ecrecover.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-destroyable-contracts-with-ecrecover.yaml
Source: hexens-glider/destroyable-contracts-with-ecrecover
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderDestroyableContractsWithEcrecover(AbstractDetector):
    ARGUMENT = "glider-destroyable-contracts-with-ecrecover"
    HELP = "Contracts that process signatures nonces should not be destroyable"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-destroyable-contracts-with-ecrecover.yaml"
    WIKI_TITLE = "Contracts that process signatures nonces should not be destroyable"
    WIKI_DESCRIPTION = "Contracts that process signatures and store nonces should not be destroyable. If the contract is destroyed and the contract is re-created, then it is possible for the signature to be replayed."
    WIKI_EXPLOIT_SCENARIO = "Transpiled from Hexens Glider query destroyable-contracts-with-ecrecover. Tags: signatures, selfdestruct."
    WIKI_RECOMMENDATION = "Apply the check implied by the original Glider query — see hexens-glider source for context."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.calls_function_matching': '^(selfdestruct)$'}, {'function.calls_function_matching': '^(ecrecover)$'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-destroyable-contracts-with-ecrecover: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
