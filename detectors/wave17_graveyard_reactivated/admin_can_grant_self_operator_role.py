"""
admin_can_grant_self_operator_role.py - Custom Slither detector.

Pattern (Zellic slice_ae Hyperbeat Pay, CRITICAL): `initialize` / constructor
grants DEFAULT_ADMIN_ROLE to `owner`. Elsewhere, a non-admin role (e.g.
OPERATOR_ROLE) gates settlement. Because DEFAULT_ADMIN_ROLE is, by OpenZeppelin
default, the role-admin of every role, the owner can call `grantRole` to
award themselves OPERATOR_ROLE at any time - collapsing two-key separation
to a single key. The fix is an explicit `_setRoleAdmin(OPERATOR_ROLE, NON_DEFAULT)`
inside initialize.

Detection strategy:
    1. Find a contract where a function (initialize/constructor) calls
       `_grantRole(DEFAULT_ADMIN_ROLE, ...)`.
    2. The same contract must have a function modified by
       `onlyRole(<NON_DEFAULT_ROLE>)` for some role variable whose name is
       NOT DEFAULT_ADMIN_ROLE.
    3. No function in the contract calls `_setRoleAdmin(<that role>, ...)`
       to move the admin away from DEFAULT_ADMIN_ROLE.
    4. Flag the initialize function.

@author auditooor wave8
@pattern slice_ae Hyperbeat Pay
"""

import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract

from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.core.declarations import Function
from slither.slithir.operations import InternalCall
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_DEFAULT_ADMIN_NAMES = frozenset({"DEFAULT_ADMIN_ROLE"})


def _calls_grant_default_admin(function) -> bool:
    """True if function calls _grantRole/grantRole with DEFAULT_ADMIN_ROLE arg."""
    for node in function.nodes:
        for ir in node.irs:
            if not isinstance(ir, InternalCall):
                continue
            callee = ir.function
            if not isinstance(callee, Function):
                continue
            nm = (callee.name or "")
            if nm not in ("_grantRole", "grantRole"):
                continue
            # First arg is the role constant.
            args = ir.arguments or []
            if not args:
                continue
            first = args[0]
            first_name = getattr(first, "name", None) or ""
            if first_name in _DEFAULT_ADMIN_NAMES:
                return True
    return False


def _non_default_onlyrole_refs(contract) -> set:
    """Return set of role-variable names used in onlyRole() modifier calls
    that are NOT DEFAULT_ADMIN_ROLE.
    """
    refs: set = set()
    for f in contract.functions:
        # Iterate modifiers attached to this function.
        for m in f.modifiers:
            if not getattr(m, "name", "") == "onlyRole":
                continue
            # Inspect the modifier call expression on the function.
            pass
        # Better: walk nodes of the function for InternalCall to `onlyRole`.
    # Approach via expression inspection: walk the function's modifier
    # statements via function.modifiers_statements is not public. Use the
    # source-level call string by scanning any InternalCall / SolidityCall
    # on every function that has modifiers.
    for f in contract.functions_and_modifiers_declared:
        # Look inside modifier bodies OR look at calls to a modifier named
        # "onlyRole" from function entry nodes. Slither represents modifier
        # invocations as nodes inside the function of type PLACEHOLDER/ENTRY.
        for node in f.nodes:
            for ir in node.irs:
                if isinstance(ir, InternalCall):
                    callee = ir.function
                    if not isinstance(callee, Function):
                        continue
                    if (callee.name or "") != "onlyRole":
                        continue
                    args = ir.arguments or []
                    if not args:
                        continue
                    role_name = getattr(args[0], "name", None) or ""
                    if role_name and role_name not in _DEFAULT_ADMIN_NAMES:
                        refs.add(role_name)
    return refs


def _calls_set_role_admin_for(contract, role_names: set) -> bool:
    """True if any function in contract calls _setRoleAdmin(role, _) where
    role is in role_names.
    """
    for f in contract.functions_and_modifiers_declared:
        for node in f.nodes:
            for ir in node.irs:
                if not isinstance(ir, InternalCall):
                    continue
                callee = ir.function
                if not isinstance(callee, Function):
                    continue
                if (callee.name or "") not in ("_setRoleAdmin", "setRoleAdmin"):
                    continue
                args = ir.arguments or []
                if not args:
                    continue
                role_arg_name = getattr(args[0], "name", None) or ""
                if role_arg_name in role_names:
                    return True
    return False


class AdminCanGrantSelfOperatorRole(AbstractDetector):
    """Detect DEFAULT_ADMIN_ROLE grant that lets owner self-grant operator-gated role."""

    ARGUMENT = "admin-can-grant-self-operator-role"
    HELP = (
        "initialize grants DEFAULT_ADMIN_ROLE to owner while a non-admin role "
        "gates settlement - admin can self-grant the operator role"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Admin Can Self-Grant Operator Role"
    WIKI_DESCRIPTION = (
        "In OpenZeppelin AccessControl, `DEFAULT_ADMIN_ROLE` is by default the "
        "role-admin of every role, which means any account holding it can call "
        "`grantRole(OTHER_ROLE, self)` at any time. When an initializer grants "
        "DEFAULT_ADMIN_ROLE to `owner` AND the contract also gates settlement on "
        "a separate operator role, the advertised two-key separation silently "
        "collapses to a single key. The fix is an explicit "
        "`_setRoleAdmin(OPERATOR_ROLE, GUARDIAN_ROLE)` before handing out the "
        "admin role."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function initialize(address owner) external {
    _grantRole(DEFAULT_ADMIN_ROLE, owner); // BUG: can self-grant any role
    _grantRole(OPERATOR_ROLE, owner);
}
function settle() external onlyRole(OPERATOR_ROLE) { /* ... */ }
```
1. Owner key is compromised.
2. Attacker calls `grantRole(OPERATOR_ROLE, attacker)` (DEFAULT_ADMIN is admin).
3. Attacker calls `settle()` and drains user funds - no second key required."""
    WIKI_RECOMMENDATION = (
        "Call `_setRoleAdmin(OPERATOR_ROLE, GUARDIAN_ROLE)` inside initialize "
        "so that the operator role is administered by a separate guardian key, "
        "preserving two-key separation."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            non_default_roles = _non_default_onlyrole_refs(contract)
            if not non_default_roles:
                continue

            if _calls_set_role_admin_for(contract, non_default_roles):
                continue

            # Find initializer/constructor that grants DEFAULT_ADMIN_ROLE
            for function in contract.functions_and_modifiers_declared:
                if not (function.is_constructor or
                        (function.name or "").lower() in ("initialize", "__init__", "init")):
                    continue
                if not _calls_grant_default_admin(function):
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " grants DEFAULT_ADMIN_ROLE while the contract gates "
                    "settlement on a separate role (",
                    ", ".join(sorted(non_default_roles)),
                    "). The admin can self-grant that role at any time - "
                    "call _setRoleAdmin(<role>, <guardian>) to preserve "
                    "two-key separation.\n",
                ]
                results.append(self.generate_result(info))

        return results
