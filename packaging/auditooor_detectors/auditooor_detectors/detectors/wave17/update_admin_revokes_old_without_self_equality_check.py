"""
update-admin-revokes-old-without-self-equality-check — generated from reference/patterns.dsl/update-admin-revokes-old-without-self-equality-check.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py update-admin-revokes-old-without-self-equality-check.yaml
Source: lisa-mine-r99-case-06418-c4-stader-2023-06
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class UpdateAdminRevokesOldWithoutSelfEqualityCheck(AbstractDetector):
    ARGUMENT = "update-admin-revokes-old-without-self-equality-check"
    HELP = "An admin-rotation function (`updateAdmin` / `changeAdmin` / `transferAdmin`) revokes DEFAULT_ADMIN_ROLE from the previous holder and grants it to the new one — but does not check that the new holder differs from the old one. If a multisig or operator accidentally calls `updateAdmin(currentAdmin)`, t"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/update-admin-revokes-old-without-self-equality-check.yaml"
    WIKI_TITLE = "Admin update revokes previous admin without checking newAdmin != oldAdmin"
    WIKI_DESCRIPTION = "Pattern fires on external admin-rotation functions that issue both `_grantRole(DEFAULT_ADMIN_ROLE, _admin)` and `_revokeRole(DEFAULT_ADMIN_ROLE, oldAdmin)` without an `oldAdmin != _admin` precondition. OpenZeppelin's `_revokeRole` runs unconditionally even when the addresses match, so the natural sequence (write `accountsMap[ADMIN] = _admin; _grantRole(role, _admin); _revokeRole(role, oldAdmin);`)"
    WIKI_EXPLOIT_SCENARIO = "Stader's updateAdmin signature is `updateAdmin(address _admin)`. An operator rotates keys but mis-pastes the address — they call `updateAdmin(currentAdmin)` from the current admin's wallet. The function reads `oldAdmin = currentAdmin`, writes the new address (same value), grants role to `_admin`, then revokes role from `oldAdmin` (also `_admin`). DEFAULT_ADMIN_ROLE is now held by no address. Futur"
    WIKI_RECOMMENDATION = "Add `require(oldAdmin != _admin, 'Already admin')` (or its custom-error equivalent) BEFORE any role mutation. Consider also adding a two-step admin transfer (`Ownable2Step`-style) so the new admin must actively claim — that closes both the same-address mistake and the wrong-address typo at the same "

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': 'updateAdmin|changeAdmin|transferAdmin|setAdmin'}]
    _MATCH = [{'function.kind': 'external'}, {'function.name_matches': 'updateAdmin|changeAdmin|transferAdmin|setAdmin'}, {'function.body_contains_regex': '_revokeRole\\s*\\(\\s*(DEFAULT_ADMIN_ROLE|ADMIN_ROLE|adminRole)'}, {'function.body_contains_regex': '_grantRole\\s*\\(\\s*(DEFAULT_ADMIN_ROLE|ADMIN_ROLE|adminRole)'}, {'function.body_not_contains_regex': '(?:require|revert|if).*\\b(oldAdmin|currentAdmin|previousAdmin|_old\\w*)\\s*(!=|==)\\s*(_admin|_newAdmin|newAdmin|admin_)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — update-admin-revokes-old-without-self-equality-check: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
