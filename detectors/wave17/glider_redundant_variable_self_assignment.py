"""
glider-redundant-variable-self-assignment — generated from reference/patterns.dsl/glider-redundant-variable-self-assignment.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-redundant-variable-self-assignment.yaml
Source: hexens-glider/redundant-variable-self-assignment
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderRedundantVariableSelfAssignment(AbstractDetector):
    ARGUMENT = "glider-redundant-variable-self-assignment"
    HELP = "Function body contains a redundant self-assignment `x = x;`. Most often a copy-paste typo where the author meant `x = newX;`. Silent: the variable is unchanged, the compiler does not warn, and a mis-spelled state update can ship unnoticed."
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-redundant-variable-self-assignment.yaml"
    WIKI_TITLE = "Redundant self-assignment `x = x` — likely typo / overlooked update"
    WIKI_DESCRIPTION = "A statement of the form `variable = variable;` has no effect. It typically appears because the author copied a template line and forgot to rename one side, or intended `variable = parameter_named_similarly;` and mis-typed. The consequence ranges from harmless dead code to a state update that silently never happens — the latter is a live security issue when the omitted update is e.g. `pendingOwner "
    WIKI_EXPLOIT_SCENARIO = "Setter function `function setFeeRecipient(address feeRecipient) external { feeRecipient = feeRecipient; }` — the parameter shadows the state variable, the assignment is a no-op, the state variable never updates. Governance believes the recipient is now the new address; in reality the old recipient continues to collect fees. Slither would flag this as a local variable shadowing, but the same class "
    WIKI_RECOMMENDATION = "Grep the codebase for `^\\s*\\w+\\s*=\\s*\\1\\s*;$`. For each hit, decide whether the line is dead (delete) or a typo (fix). Add a lint rule to CI (Slither has `SELF_ASSIGN` partial coverage; extend with a Glider query if you want full coverage). Prefer explicit parameter naming conventions (`newRec"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.source_not_contains_regex': '^$'}]
    _MATCH = [{'function.kind': 'any'}, {'function.body_contains_regex': '(?m)^\\s*([A-Za-z_][A-Za-z0-9_]*)\\s*=\\s*\\1\\s*;'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-redundant-variable-self-assignment: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
