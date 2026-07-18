"""
w68-freeze-flag-flip-unauthorized — generated from reference/patterns.dsl/w68-freeze-flag-flip-unauthorized.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py w68-freeze-flag-flip-unauthorized.yaml
Source: W6-8 zero-coverage detector batch (auditooor capability lift)
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class W68FreezeFlagFlipUnauthorized(AbstractDetector):
    ARGUMENT = "w68-freeze-flag-flip-unauthorized"
    HELP = "Freeze flag flipped to wrong state by unauthorized caller - setter lacks an authority guard"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/w68-freeze-flag-flip-unauthorized.yaml"
    WIKI_TITLE = "Freeze flag flipped to wrong state by unauthorized caller"
    WIKI_DESCRIPTION = "The freeze flag setter has no access control, so any caller can flip the freeze state of the protocol."
    WIKI_EXPLOIT_SCENARIO = "Freeze flag flipped to wrong state by unauthorized caller - setter lacks an authority guard"
    WIKI_RECOMMENDATION = "Gate the freeze flag setter behind an owner or admin check."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.name_matches': '.*(setFreeze|freeze|setPause).*'}, {'function.not_leaf_helper': True}, {'function.not_in_skip_list': True}, {'function.body_contains_regex': '(?i)(freezeFlag|frozen|paused)\\s*='}, {'function.body_not_contains_regex': '(?i)(msg\\.sender\\s*==|onlyOwner|onlyAdmin|require\\s*\\(\\s*msg\\.sender)'}]

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
                info = [f, f" — w68-freeze-flag-flip-unauthorized: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
