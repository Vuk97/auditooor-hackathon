"""
glider-timelock-operation-ready-missing — generated from reference/patterns.dsl/glider-timelock-operation-ready-missing.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-timelock-operation-ready-missing.yaml
Source: hexens-glider/timelock-contracts-doesnt-contain-operation-ready
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderTimelockOperationReadyMissing(AbstractDetector):
    ARGUMENT = "glider-timelock-operation-ready-missing"
    HELP = "Custom `TimelockController._beforeCall` does not call `isOperationReady`. An executor-role account can execute a queued operation before its `eta` — defeating the timelock delay."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-timelock-operation-ready-missing.yaml"
    WIKI_TITLE = "TimelockController _beforeCall missing isOperationReady check (OZ < 4.3.1)"
    WIKI_DESCRIPTION = "OpenZeppelin TimelockController's `_beforeCall` hook exists to enforce (a) predecessor dependency and (b) readiness (`eta` has passed). Versions before 4.3.1 / 3.4.2 had a variant that omitted the readiness check, allowing the executor role to bypass the mandatory delay. Forks and hand-rolled timelocks routinely replicate the bug."
    WIKI_EXPLOIT_SCENARIO = "Treasury uses a timelock with 48h delay. Governance schedules a `withdraw(1e24)` operation. Attacker is the executor (role compromised or public execute). Because `_beforeCall` never calls `isOperationReady`, the executor calls `execute` on the operation immediately after scheduling — full withdraw, no 48h window for governance to cancel."
    WIKI_RECOMMENDATION = "Call `require(isOperationReady(id), \"not ready\")` inside `_beforeCall`. If forking OZ, use ≥ 4.3.1. Add a fuzz test that schedules and immediately executes — must revert."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'TimelockController|_beforeCall|_afterCall|isOperationReady|_checkPredecessor'}]
    _MATCH = [{'function.name_matches': '^_beforeCall$'}, {'function.kind': 'any'}, {'function.body_not_contains_regex': 'isOperationReady\\s*\\(|isOperationPending\\s*\\(|readyTimestamp\\s*<=\\s*block\\.timestamp|getTimestamp\\s*\\(.+\\)\\s*<=\\s*block\\.timestamp'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-timelock-operation-ready-missing: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
