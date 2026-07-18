"""
w68-loop-invariant-bypass-off-by-one — generated from reference/patterns.dsl/w68-loop-invariant-bypass-off-by-one.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py w68-loop-invariant-bypass-off-by-one.yaml
Source: W6-8 zero-coverage detector batch (auditooor capability lift)
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class W68LoopInvariantBypassOffByOne(AbstractDetector):
    ARGUMENT = "w68-loop-invariant-bypass-off-by-one"
    HELP = "Loop invariant bypassed by off-by-one boundary condition using <= against array length"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/w68-loop-invariant-bypass-off-by-one.yaml"
    WIKI_TITLE = "Loop invariant bypassed by off-by-one or boundary condition"
    WIKI_DESCRIPTION = "A loop iterates with i <= array.length instead of i < array.length, reading one element past the end of the array."
    WIKI_EXPLOIT_SCENARIO = "Loop invariant bypassed by off-by-one boundary condition using <= against array length"
    WIKI_RECOMMENDATION = "Use a strict < comparison against array length."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.name_matches': '.*'}, {'function.not_leaf_helper': True}, {'function.not_in_skip_list': True}, {'function.body_contains_regex': '(?i)for\\s*\\([^;]*;[^;]*<=\\s*[A-Za-z0-9_.]+\\.length'}]

    _INCLUDE_LEAF_HELPERS = True
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
                info = [f, f" — w68-loop-invariant-bypass-off-by-one: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
