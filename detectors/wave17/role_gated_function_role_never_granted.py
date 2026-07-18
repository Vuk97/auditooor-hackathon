"""
role-gated-function-role-never-granted — generated from reference/patterns.dsl/role-gated-function-role-never-granted.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py role-gated-function-role-never-granted.yaml
Source: auditooor-R48-polymarket-OFF.A
"""

import sys
import re
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class RoleGatedFunctionRoleNeverGranted(AbstractDetector):
    ARGUMENT = "role-gated-function-role-never-granted"
    HELP = "Function is gated by `onlyRole(ROLE_X)` but the contract's constructor / initialize never grants ROLE_X to any address. If no deploy-script wiring compensates, the function is permanently unreachable — user funds routed through it are locked or features are broken."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/role-gated-function-role-never-granted.yaml"
    WIKI_TITLE = "Role-gated function where role is never granted"
    WIKI_DESCRIPTION = "A state-changing function carries an `onlyRole(ROLE_X)` / `_checkRole(ROLE_X)` modifier. The contract's own constructor, `initialize`, or `_init` implementation does not call `_grantRole(ROLE_X, …)` / `_setupRole(ROLE_X, …)` / `grantRole(ROLE_X, …)`. Later admin helpers do not count: if the bootstrap path never grants ROLE_X to the intended caller (the contract itself, a wrapper, a vault), the function is unreachable in production."
    WIKI_EXPLOIT_SCENARIO = "A wrapper protocol routes user deposits through `CollateralOfframp.unwrap()`, which is gated by `onlyRole(WRAPPER_ROLE)`. The deploy script configures the wrapper to call `CollateralOfframp.unwrap` on user withdrawals. The constructor never grants `WRAPPER_ROLE` to the wrapper contract address; a later admin-only function can grant it, but that does not help bootstrap. Every user withdrawal reverts with `AccessControlUnauthorizedAccount(wrapper, WRAPPER_ROLE)`. User dep"
    WIKI_RECOMMENDATION = "Add a deploy-time step that explicitly grants ROLE_X to the intended caller, and add a constructor-time grant where the expected caller is known at deploy time (e.g., `_grantRole(WRAPPER_ROLE, address(wrapper));` inside the offramp's constructor if passed the wrapper address). Add a post-deploy veri"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': '[A-Z_]+_ROLE|ROLE_[A-Z_]+'}, {'contract.source_matches_regex': '(?i)onlyRole\\s*\\(|_checkRole\\s*\\('}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': '_checkRole\\s*\\(\\s*[A-Z_]+_ROLE|onlyRole\\s*\\(\\s*[A-Z_]+_ROLE'}, {'function.name_matches': 'unwrap|withdraw|redeem|mint|burn|claim|release|swap|bridge|send|submit'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

    _INCLUDE_LEAF_HELPERS = False
    _INVERSE_CEI = False

    _ROLE_RE = re.compile(r'\b([A-Z_]+_ROLE|ROLE_[A-Z_]+)\b')
    _GATE_RE = re.compile(r'(?:onlyRole|_checkRole)\s*\(\s*([A-Z_]+_ROLE|ROLE_[A-Z_]+)\s*(?:,|\))', re.IGNORECASE)
    _GRANT_RE = re.compile(r'(?:_grantRole|grantRole|_setupRole)\s*\(\s*([A-Z_]+_ROLE|ROLE_[A-Z_]+)\s*,', re.IGNORECASE)
    _CALL_RE = re.compile(r'\b(_[A-Za-z][A-Za-z0-9_]*)\s*\(')
    _INITIALIZER_NAME_RE = re.compile(r'(?i)^(initialize|init|setup|bootstrap)([A-Za-z0-9_]*)?$|^__.*_init')

    def _contract_source(self, contract) -> str:
        try:
            return contract.source_mapping.content or ""
        except Exception:
            return ""

    def _function_source(self, function) -> str:
        try:
            return function.source_mapping.content or ""
        except Exception:
            return ""

    def _bootstrap_functions(self, contract):
        for function in getattr(contract, "functions_declared", []) or []:
            if getattr(function, "is_constructor", False):
                yield function
                continue
            name = (getattr(function, "name", "") or "").lower()
            if self._INITIALIZER_NAME_RE.match(name):
                yield function

    def _gated_roles(self, contract) -> set[str]:
        roles: set[str] = set()
        for match in self._GATE_RE.finditer(self._contract_source(contract)):
            roles.add(match.group(1))
        return roles

    def _bootstrap_granted_roles(self, contract) -> set[str]:
        roles: set[str] = set()
        helper_sources: dict[str, str] = {}
        for function in getattr(contract, "functions_declared", []) or []:
            name = getattr(function, "name", "") or ""
            if name.startswith("_"):
                helper_sources[name] = self._function_source(function)

        visited_helpers: set[str] = set()

        def collect_from_source(src: str, follow_helpers: bool) -> None:
            for match in self._GRANT_RE.finditer(src):
                roles.add(match.group(1))
            if not follow_helpers:
                return
            for call in self._CALL_RE.finditer(src):
                helper_name = call.group(1)
                if helper_name in visited_helpers:
                    continue
                helper_src = helper_sources.get(helper_name)
                if not helper_src:
                    continue
                visited_helpers.add(helper_name)
                collect_from_source(helper_src, False)

        for function in self._bootstrap_functions(contract):
            src = self._function_source(function)
            collect_from_source(src, True)
        return roles

    def _detect(self):
        results = []
        for c in self.contracts:
            if is_vendored_or_test_contract(c):
                continue
            if not eval_preconditions(c, self._PRECONDITIONS):
                continue
            gated_roles = self._gated_roles(c)
            if not gated_roles:
                continue
            bootstrap_granted_roles = self._bootstrap_granted_roles(c)
            for f in c.functions_and_modifiers_declared:
                if not self._INCLUDE_LEAF_HELPERS and is_leaf_helper(f):
                    continue
                if not eval_function_match(f, self._MATCH):
                    continue
                function_roles = {match.group(1) for match in self._GATE_RE.finditer(self._function_source(f))}
                if not function_roles:
                    continue
                if function_roles & gated_roles and function_roles.issubset(bootstrap_granted_roles):
                    continue
                info = [f, f" — role-gated-function-role-never-granted: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
