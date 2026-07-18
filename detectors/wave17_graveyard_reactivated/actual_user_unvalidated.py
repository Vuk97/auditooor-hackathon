"""
actual_user_unvalidated.py - Custom Slither detector.

Pattern (Zellic slice_ab Zealous ActualUser-Unvalidated-Discount, MEDIUM):
A public/external function accepts a caller-supplied address parameter named
like `actualUser`, `beneficiary`, `recipient`, `onBehalfOf`, or `owner` AND
uses that parameter as a mapping key for a discount / whitelist / permission
lookup - but the function body never verifies `msg.sender == <that param>`
and has no ACL modifier that would otherwise authorise the caller.

A classic manifestation is Zealous's `swap()` accepting `actualUser` for fee
discount lookup: anyone can pass a whitelisted address and skim the discount.
The same pattern appears in "borrow on behalf of" flows without a delegation
check (wave11 `borrow_behalf_no_delegation_check` catches a narrower
variant).

Detection strategy:
    1. Walk every external/public non-constructor function with at least one
       address-typed parameter whose name matches a known "beneficiary"
       keyword.
    2. The function must NOT carry an ACL modifier (onlyOwner, onlyRole,
       onlyOperator, ...).
    3. The function's body must use the flagged parameter as an INDEX into
       a state-variable mapping (i.e. a node reads `state_var[param]`).
    4. The function must NOT contain a `require`/`assert` node whose
       node.solidity_variables_read includes `msg.sender` AND whose
       local_variables_read includes that same parameter - the signature
       of a proper `require(msg.sender == actualUser)` guard.
    5. Flag the function.

@author auditooor wave10
@pattern slice_ab zealous-may-25 ActualUser-Unvalidated-Discount
"""

import re
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract

from slither.core.solidity_types.elementary_type import ElementaryType
from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.slithir.operations import Index
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_ACL_MODIFIERS = frozenset({
    "onlyowner", "onlyadmin", "onlyoperator", "onlyrole", "onlyroles",
    "onlygovernance", "onlymanager", "onlykeeper", "onlysigner",
    "authorized", "authorised", "whenauthorized",
})

_BENEFICIARY_RE = re.compile(
    r"^(actualuser|beneficiary|recipient|onbehalfof|behalfof|forwhom|forUser|user|userAddr|"
    r"holder|account)$",
    re.IGNORECASE,
)


def _has_acl_modifier(function) -> bool:
    for m in function.modifiers:
        name = (m.name or "").lower()
        if name in _ACL_MODIFIERS:
            return True
    return False


def _is_address_param(param) -> bool:
    t = param.type
    if isinstance(t, ElementaryType) and t.name == "address":
        return True
    return False


def _param_used_as_mapping_index(function, param) -> bool:
    """
    Return True if somewhere in the function body, there is an Index IR whose
    right operand (the key) is `param` and whose left operand is a state var
    (or dereferenced state mapping).
    """
    for node in function.nodes:
        for ir in node.irs:
            if isinstance(ir, Index):
                key = ir.variable_right
                if key is param:
                    return True
    # fall back to node-level local_variables_read intersecting with a state read
    for node in function.nodes:
        if param in node.local_variables_read and node.state_variables_read:
            return True
    return False


def _has_msg_sender_equality_with(function, param) -> bool:
    """
    True if any require/assert node reads both msg.sender and `param`.
    """
    for node in function.nodes:
        if not node.contains_require_or_assert():
            continue
        reads_sender = any(
            getattr(sv, "name", None) == "msg.sender"
            for sv in node.solidity_variables_read
        )
        if not reads_sender:
            continue
        if param in node.local_variables_read:
            return True
    return False


class ActualUserUnvalidated(AbstractDetector):
    """Detect caller-supplied beneficiary address used in state lookup without msg.sender check."""

    ARGUMENT = "actual-user-unvalidated"
    HELP = (
        "External function accepts beneficiary-like address parameter used as "
        "a mapping key with no `require(msg.sender == param)` check"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Unvalidated Beneficiary Address (actualUser)"
    WIKI_DESCRIPTION = (
        "Zealous's `swap()` accepts an `actualUser` parameter that drives "
        "per-user fee discount lookup. The function never checks that "
        "`msg.sender == actualUser` or that msg.sender is delegated by "
        "actualUser, so any caller can pass a whitelisted address to claim "
        "that address's discount tier. The same bug class appears in "
        "'on-behalf-of' deposit/borrow flows without an isApproved check - "
        "anywhere a caller-supplied address is read from a state mapping "
        "that encodes user privilege and the function neither gates itself "
        "with an ACL modifier nor compares msg.sender against the parameter."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function swap(uint256 amount, address actualUser) external returns (uint256) {
    uint256 bps = discountBps[actualUser];   // BUG: no msg.sender check
    uint256 fee = amount * (10_000 - bps) / 10_000;
    token.transferFrom(msg.sender, address(this), fee);
}
```
Attacker passes a whitelisted VIP's address as `actualUser`. They pay the
VIP discount on their own swap while the VIP never authorized the call."""
    WIKI_RECOMMENDATION = (
        "Either remove the parameter and use `msg.sender` directly, or "
        "require(msg.sender == actualUser, \"not actualUser\"), or verify "
        "delegation via an explicit `isApprovedFor[actualUser][msg.sender]` "
        "mapping."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            for function in contract.functions_and_modifiers_declared:
                if function.is_constructor:
                    continue
                if function.visibility not in ("external", "public"):
                    continue
                if function.view or function.pure:
                    continue
                if _has_acl_modifier(function):
                    continue

                # Find a candidate beneficiary address parameter
                candidates = [
                    p for p in function.parameters
                    if _is_address_param(p) and _BENEFICIARY_RE.match(p.name or "")
                ]
                if not candidates:
                    continue

                for param in candidates:
                    if not _param_used_as_mapping_index(function, param):
                        continue
                    if _has_msg_sender_equality_with(function, param):
                        continue

                    info: DETECTOR_INFO = [
                        function,
                        " takes caller-supplied beneficiary ",
                        param,
                        " and uses it as a mapping key without a "
                        "require(msg.sender == param) guard or a delegation "
                        "check. Any caller can act on another user's state.\n",
                    ]
                    results.append(self.generate_result(info))

        return results
