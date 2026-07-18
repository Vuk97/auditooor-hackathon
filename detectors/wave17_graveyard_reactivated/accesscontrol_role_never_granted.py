"""
accesscontrol_role_never_granted.py - Custom Slither detector.

Pattern (LoopFi H-04, slice_aa P43): Contract inherits an OZ-style
AccessControl base, declares onlyRole-gated functions, but neither the
constructor nor an `initialize` ever calls `_grantRole` / `_setupRole` /
`grantRole`. As a result every onlyRole-gated function permanently reverts
and the protocol is bricked once deployed.

Detection strategy:
    1. For each non-vendored contract that has at least one declared
       function whose modifier list contains `onlyRole` (signaling the
       contract uses role-based access control).
    2. Inspect every constructor or initializer DECLARED on the contract.
       (We require an explicit constructor/initializer, otherwise we don't
       know whether an inherited initializer takes care of grants.)
    3. Scan all initializer bodies for a call to `_grantRole`,
       `_setupRole`, or `grantRole`. If none of them grant any role, flag
       the contract - every onlyRole gate is dead on arrival.

@author auditooor wave9
@pattern slice_aa LoopFi H-04 / AccessControl-role-never-granted
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

_GRANT_NAMES = frozenset({"_grantRole", "grantRole", "_setupRole"})

_INIT_NAMES = frozenset({"initialize", "__init__", "init", "initializer"})


def _function_uses_onlyrole(function) -> bool:
    """True if function has an `onlyRole(...)` modifier in its modifier list."""
    for m in function.modifiers:
        if (getattr(m, "name", "") or "") == "onlyRole":
            return True
    return False


def _function_calls_grant(function) -> bool:
    """True if function body contains a call to _grantRole / grantRole /
    _setupRole (any role argument)."""
    for node in function.nodes:
        for ir in node.irs:
            if not isinstance(ir, InternalCall):
                continue
            callee = ir.function
            if not isinstance(callee, Function):
                continue
            if (callee.name or "") in _GRANT_NAMES:
                return True
    return False


class AccessControlRoleNeverGranted(AbstractDetector):
    """Detect AccessControl contracts whose constructor/initializer never
    grants any role - every onlyRole function is dead-on-arrival."""

    ARGUMENT = "accesscontrol-role-never-granted"
    HELP = (
        "Contract has onlyRole-gated functions but constructor/initializer "
        "never calls _grantRole - every gated function permanently reverts"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "AccessControl Role Never Granted"
    WIKI_DESCRIPTION = (
        "When a contract inherits an OpenZeppelin-style AccessControl base and "
        "declares functions guarded by `onlyRole(SOME_ROLE)` but neither its "
        "constructor nor its initializer ever calls `_grantRole` / `_setupRole` / "
        "`grantRole`, no account ever holds DEFAULT_ADMIN_ROLE. Because "
        "DEFAULT_ADMIN_ROLE is the role-admin of every other role by default, "
        "no one can ever grant `SOME_ROLE` either, and every guarded function "
        "permanently reverts. The protocol is bricked the moment it is deployed."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
contract Vault is AccessControl {
    bytes32 public constant SETTLER_ROLE = keccak256("SETTLER");
    constructor() { /* nothing - never grants any role */ }
    function settle() external onlyRole(SETTLER_ROLE) { /* dead */ }
}
```
1. Vault is deployed.
2. Anyone calls settle() - reverts. Owner tries grantRole(SETTLER_ROLE, alice)
   - also reverts because no one holds DEFAULT_ADMIN_ROLE.
3. The contract is unrecoverable; funds locked or feature disabled forever."""
    WIKI_RECOMMENDATION = (
        "In the constructor or initializer call "
        "`_grantRole(DEFAULT_ADMIN_ROLE, msg.sender)` (or another bootstrap "
        "address) so that the admin can later distribute operational roles."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            # 1. Contract must declare at least one onlyRole-gated function.
            uses_role_gate = False
            for f in contract.functions_declared:
                if _function_uses_onlyrole(f):
                    uses_role_gate = True
                    break
            if not uses_role_gate:
                continue

            # 2. Find explicit constructor / initializer DECLARED on this contract.
            initializers = []
            for f in contract.functions_declared:
                if f.is_constructor:
                    initializers.append(f)
                    continue
                nm = (f.name or "").lower()
                if nm in _INIT_NAMES:
                    initializers.append(f)
            if not initializers:
                continue

            # 3. None of the initializers must call a grant primitive.
            if any(_function_calls_grant(f) for f in initializers):
                continue

            flagged = initializers[0]
            info: DETECTOR_INFO = [
                contract,
                " inherits AccessControl and gates functions with onlyRole, "
                "but ",
                flagged,
                " never calls _grantRole / _setupRole / grantRole. No account "
                "will ever hold DEFAULT_ADMIN_ROLE, so every onlyRole-gated "
                "function permanently reverts and the contract is bricked.\n",
            ]
            results.append(self.generate_result(info))

        return results
