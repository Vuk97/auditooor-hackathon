"""
r94-loop-dead-branch-wrong-constant — generated from reference/patterns.dsl/r94-loop-dead-branch-wrong-constant.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-dead-branch-wrong-constant.yaml
Source: loop-cycle-30-dead-branch-sol-sibling
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopDeadBranchWrongConstant(AbstractDetector):
    ARGUMENT = "r94-loop-dead-branch-wrong-constant"
    HELP = "NOT_SUBMIT_READY detector-fixture-smoke-only: an owned loop assigns `routeKind` only to `0` or `1`, but still gates a sibling branch on `routeKind == 2`."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-dead-branch-wrong-constant.yaml"
    WIKI_TITLE = "Loop-local branch compares an unreachable constant"
    WIKI_DESCRIPTION = "Detector-fixture-smoke-only. NOT_SUBMIT_READY. This row stays intentionally narrow: it flags only the owned Solidity shape where a loop-local `routeKind` variable is assigned from a two-value domain (`0` / `1`) and a sibling branch in the same loop still checks `if (routeKind == 2)`. Under that shape the guarded branch is dead code and any invariant or accounting update inside it never executes."
    WIKI_EXPLOIT_SCENARIO = "In the owned fixture, `processRoutes()` classifies each route as `routeKind = 0` for active or `routeKind = 1` for inactive, then checks `if (routeKind == 2)` before incrementing `deadBranchExecutions`. That counter can never move because the compared constant is outside the loop-local domain. This row does not claim real-protocol exploitability beyond the owned fixture smoke."
    WIKI_RECOMMENDATION = "Align the branch constant with the actual local domain or widen the domain assignment so every checked constant is reachable. Keep this row NOT_SUBMIT_READY and advisory-only until evidence expands beyond the owned fixture pair."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(routeKind|branch == 2|routeKind == 2|for\\s*\\()'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.body_contains_regex': 'for\\s*\\('}, {'function.body_contains_regex': 'uint(?:8|16|32|64|128|256)?\\s+routeKind\\s*;'}, {'function.body_contains_regex': 'routeKind\\s*=\\s*0\\s*;'}, {'function.body_contains_regex': 'routeKind\\s*=\\s*1\\s*;'}, {'function.body_contains_regex': 'if\\s*\\(\\s*routeKind\\s*==\\s*2\\s*\\)'}, {'function.body_not_contains_regex': 'routeKind\\s*=\\s*2\\s*;'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)\\b'}]

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
                info = [f, f" — r94-loop-dead-branch-wrong-constant: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
