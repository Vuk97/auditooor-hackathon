"""
revoke-operator-no-sweep — generated from reference/patterns.dsl/revoke-operator-no-sweep.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py revoke-operator-no-sweep.yaml
Source: solodit-novel/slice_ae-GTE-CLOB
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class RevokeOperatorNoSweep(AbstractDetector):
    ARGUMENT = "revoke-operator-no-sweep"
    HELP = "Global operator-revocation clears the per-operator flag but leaves per-user operatorApprovals intact. Revoked operator still acts for users who previously opted in."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/revoke-operator-no-sweep.yaml"
    WIKI_TITLE = "Operator revocation does not clear per-user approvals"
    WIKI_DESCRIPTION = "Contracts expose both a global `isOperator[addr]` allowlist and per-user `operatorApprovals[user][addr]` opt-in. `disallowOperator(addr)` unsets the global flag but does not iterate/clear per-user approvals. If per-user approval is checked independently, the revoked operator retains capability to act for every user who had previously approved them."
    WIKI_EXPLOIT_SCENARIO = "Protocol revokes OperatorX after evidence of abuse. OperatorX still submits `placeOrder(user, ...)` and per-user check sees `operatorApprovals[user][OperatorX] == true`, so the call succeeds."
    WIKI_RECOMMENDATION = "On global revoke, either (a) gate per-user approvals behind the global flag (AND-compose), or (b) track approvals in an enumerable set so you can iterate and clear them."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'operator(Approvals?|s|Allowed)|isOperator|operatorApprovals'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(disallow|revoke|deregister|removeOperator|disableOperator)'}, {'function.has_param_of_type': 'address'}, {'function.body_contains_regex': 'isOperator|operatorAllowed|operators\\s*\\['}, {'function.body_not_contains_regex': 'operatorApprovals\\s*\\[|_clearOperatorApprovals|_revokeAll|forEach.*operatorApprovals'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — revoke-operator-no-sweep: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
