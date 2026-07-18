"""
glider-lack-of-validator-duplication-check-during-validat — generated from reference/patterns.dsl/glider-lack-of-validator-duplication-check-during-validat.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-lack-of-validator-duplication-check-during-validat.yaml
Source: hexens-glider/lack-of-validator-duplication-check-during-validat
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderLackOfValidatorDuplicationCheckDuringValidat(AbstractDetector):
    ARGUMENT = "glider-lack-of-validator-duplication-check-during-validat"
    HELP = "Bridge Validator set update without duplicate-validator check (power amplification)"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-lack-of-validator-duplication-check-during-validat.yaml"
    WIKI_TITLE = "Bridge Validator set update without duplicate-validator check (power amplification)"
    WIKI_DESCRIPTION = "Finds updateValset-like entrypoints that accept a new validator set but never de-duplicate validator addresses (no pairwise i/j check and no mapping(address=>bool) \"seen\" gate) in the entrypoint or any directly-called helper (e.g., ValsetUpdate.updateValsetChecks, SignatureUtils.*). This enables a single key to appear multiple times in a valset and inflate cumulative power. Filters applied: - Ex"
    WIKI_EXPLOIT_SCENARIO = "Transpiled from Hexens Glider query lack-of-validator-duplication-check-during-validat. Tags: bridge, consensus, valset, signatures, duplicate, validation."
    WIKI_RECOMMENDATION = "Apply the check implied by the original Glider query — see hexens-glider source for context."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'function.name_matches': '(updateValset|updateValidatorSet|setValset|setValidatorSet)'}]
    _MATCH = [{'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-lack-of-validator-duplication-check-during-validat: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
