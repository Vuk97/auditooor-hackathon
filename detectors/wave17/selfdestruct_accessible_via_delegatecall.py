"""
selfdestruct-accessible-via-delegatecall — generated from reference/patterns.dsl/selfdestruct-accessible-via-delegatecall.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py selfdestruct-accessible-via-delegatecall.yaml
Source: auditooor-seed
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class SelfdestructAccessibleViaDelegatecall(AbstractDetector):
    ARGUMENT = "selfdestruct-accessible-via-delegatecall"
    HELP = "External/public function calls selfdestruct without an owner/admin/role modifier — directly callable or reachable via delegatecall (parity-wallet pattern)."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/selfdestruct-accessible-via-delegatecall.yaml"
    WIKI_TITLE = "Unprotected selfdestruct reachable externally or via delegatecall"
    WIKI_DESCRIPTION = "A function that executes `selfdestruct` (or its `.selfdestruct` method form) is declared external or public but lacks any access-control modifier such as `onlyOwner`, `onlyAdmin`, `onlyRole`, `onlyGovernance`, `auth`, or `restricted`. Any caller can invoke it directly to destroy the contract. When the contract is used as a delegatecall target (a proxy implementation, a shared library, or a multisi"
    WIKI_EXPLOIT_SCENARIO = "A proxy contract delegatecalls into a logic contract to initialize or execute owner functions. The logic contract exposes `kill()` which calls `selfdestruct(msg.sender)` with no modifier. An attacker invokes `kill()` directly on the logic contract: the logic bytecode is wiped, and every proxy that uses it for `delegatecall` now reverts, permanently freezing user funds."
    WIKI_RECOMMENDATION = "Gate every function that can execute `selfdestruct` behind a modifier such as `onlyOwner`, `onlyAdmin`, `onlyRole(DEFAULT_ADMIN_ROLE)`, or `onlyGovernance`. For logic contracts used as delegatecall targets, additionally run `_disableInitializers()` in the constructor and never expose a selfdestruct "

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.has_high_level_call_named': 'selfdestruct|suicide'}, {'function.has_high_level_call_named': 'selfdestruct|suicide'}, {'function.has_high_level_call_named': 'selfdestruct|suicide'}, {'function.has_high_level_call_named': 'selfdestruct|suicide'}, {'function.has_high_level_call_named': 'selfdestruct|suicide'}, {'function.has_high_level_call_named': 'selfdestruct|suicide'}, {'function.has_high_level_call_named': 'selfdestruct|suicide'}, {'function.has_high_level_call_named': 'selfdestruct|suicide'}, {'function.has_high_level_call_named': 'selfdestruct|suicide'}, {'function.has_high_level_call_named': 'selfdestruct|suicide'}, {'function.has_high_level_call_named': 'selfdestruct|suicide'}, {'function.has_high_level_call_named': 'selfdestruct|suicide'}, {'function.has_high_level_call_named': 'selfdestruct|suicide'}, {'function.has_high_level_call_named': 'selfdestruct|suicide'}, {'function.body_contains_regex': 'selfdestruct\\s*\\(|\\.selfdestruct\\s*\\('}, {'function.has_modifier': {'includes': ['onlyOwner', 'onlyAdmin', 'onlyRoles', 'onlyGovernance', 'onlyRole', 'auth', 'restricted'], 'negate': True}}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — selfdestruct-accessible-via-delegatecall: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
