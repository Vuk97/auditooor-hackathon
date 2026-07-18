"""
glider-missing-two-step-ownership-transfer-hunter — generated from reference/patterns.dsl/glider-missing-two-step-ownership-transfer-hunter.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-missing-two-step-ownership-transfer-hunter.yaml
Source: hexens-glider/missing-two-step-ownership-transfer-hunter
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderMissingTwoStepOwnershipTransferHunter(AbstractDetector):
    ARGUMENT = "glider-missing-two-step-ownership-transfer-hunter"
    HELP = "Missing Two-Step Ownership Transfer Hunter"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-missing-two-step-ownership-transfer-hunter.yaml"
    WIKI_TITLE = "Missing Two-Step Ownership Transfer Hunter"
    WIKI_DESCRIPTION = "Detects main contracts that implement transferOwnership but do not expose a two-step ownership acceptance path."
    WIKI_EXPLOIT_SCENARIO = "Transpiled from Hexens Glider query missing-two-step-ownership-transfer-hunter. Tags: ownership, access-control, two-step, admin-safety."
    WIKI_RECOMMENDATION = "Apply the check implied by the original Glider query — see hexens-glider source for context."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'function.name_matches': '^(transferOwnership)$'}]
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
                info = [f, f" — glider-missing-two-step-ownership-transfer-hunter: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
