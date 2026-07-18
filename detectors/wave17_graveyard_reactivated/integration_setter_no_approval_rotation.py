"""
integration_setter_no_approval_rotation.py - Custom Slither detector.

Pattern (Morpheus M-03, slice_ad): An admin setter rotates an integration
address (e.g. `aavePool`, `uniswapRouter`, `bridge`, `vault`) but does NOT
revoke the OLD address's token approvals. The old contract still holds
`approve(old, MAX)` from this contract and can keep pulling funds until the
approval is manually rescinded - sometimes silently for the lifetime of the
contract.

Detection strategy:
    1. Iterate every external/public setter that writes to a state variable
       of address (or interface) type whose name matches `pool|router|
       integration|bridge|vault|aave|uni|gateway|adapter`.
    2. The setter must take a single address parameter and assign it to that
       state variable.
    3. Inspect the function for any HighLevelCall to `approve(...)` /
       `safeApprove(...)`. If absent → flag.
    4. Skip constructors and skip functions that contain a non-zero approve
       call only - i.e. a setter that re-approves the new address but
       doesn't zero the old one is also flagged (heuristic: must zero the
       OLD address). To stay simple we require BOTH an `approve(..., 0)` and
       any approve in the body; if neither approve form is present, flag.

@author auditooor wave9
@pattern slice_ad Morpheus M-03
"""

import re
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract

from slither.core.declarations import Function
from slither.core.solidity_types.elementary_type import ElementaryType
from slither.core.solidity_types.user_defined_type import UserDefinedType
from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.slithir.operations import HighLevelCall
from slither.slithir.variables import Constant
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_INTEGRATION_NAME_RE = re.compile(
    r"pool|router|integration|bridge|vault|aave|uni|gateway|adapter|strategy",
    re.IGNORECASE,
)
_APPROVE_SIGS = (
    "approve(address,uint256)",
    "safeApprove(address,uint256)",
    "forceApprove(address,uint256)",
)


def _is_address_like(state_var) -> bool:
    t = getattr(state_var, "type", None)
    if isinstance(t, ElementaryType) and str(t) == "address":
        return True
    if isinstance(t, UserDefinedType):
        # Interface / contract reference - counts as integration handle.
        return True
    return False


def _setter_target_state_var(function):
    """If `function` is a single-param setter writing exactly one matching
    integration state variable, return that state variable; else None."""
    if function.is_constructor:
        return None
    if function.visibility not in ("public", "external"):
        return None
    params = function.parameters or []
    if len(params) != 1:
        return None
    if str(getattr(params[0], "type", "") or "") != "address":
        return None

    candidates = []
    for sv in function.state_variables_written:
        if not _is_address_like(sv):
            continue
        if not _INTEGRATION_NAME_RE.search(sv.name or ""):
            continue
        candidates.append(sv)
    if len(candidates) != 1:
        return None
    return candidates[0]


def _has_zero_approve_call(function) -> bool:
    """True if function contains an `approve(..., 0)` / `safeApprove(..., 0)`."""
    for node in function.nodes:
        for ir in node.irs:
            if isinstance(ir, HighLevelCall) and isinstance(ir.function, Function):
                if ir.function.solidity_signature not in _APPROVE_SIGS:
                    continue
                args = ir.arguments or []
                if len(args) < 2:
                    continue
                amt = args[1]
                if isinstance(amt, Constant) and amt.value == 0:
                    return True
    return False


def _has_any_approve_call(function) -> bool:
    for node in function.nodes:
        for ir in node.irs:
            if isinstance(ir, HighLevelCall) and isinstance(ir.function, Function):
                if ir.function.solidity_signature in _APPROVE_SIGS:
                    return True
    return False


class IntegrationSetterNoApprovalRotation(AbstractDetector):
    """Detect setters that rotate an integration address without revoking the
    previous address's token approvals."""

    ARGUMENT = "integration-setter-no-approval-rotation"
    HELP = (
        "setter rotates an integration address without zeroing the previous "
        "address's token approval - old integration retains drain capability"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Integration Setter Skips Approval Rotation"
    WIKI_DESCRIPTION = (
        "When a contract holds funds and grants `type(uint256).max` approvals "
        "to integration contracts (Aave, Uniswap, a custom bridge, a strategy "
        "vault), any admin setter that swaps the integration address must "
        "first set the old address's approval to zero. Otherwise the previous "
        "integration remains forever able to pull tokens from this contract - "
        "a compromised, removed, or malicious old integration can keep "
        "draining the balance long after it was supposedly rotated out."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function setPool(address newPool) external onlyOwner {
    pool = newPool;            // BUG: old pool still has MAX approval
}
```
1. Constructor approves the original `pool` for `type(uint256).max`.
2. Owner rotates to `newPool` because the old pool was deprecated.
3. Old pool (or a hacker that compromised it) calls `transferFrom(thisContract,
   attacker, balance)` and drains the contract."""
    WIKI_RECOMMENDATION = (
        "Before assigning the new integration address, call "
        "`IERC20(token).approve(oldAddress, 0)` (or `forceApprove`) for every "
        "asset the contract previously approved. Then assign the new address "
        "and re-approve as needed. Prefer pull-based escrow over MAX approvals "
        "where possible."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            for function in contract.functions_declared:
                target = _setter_target_state_var(function)
                if target is None:
                    continue
                if _has_zero_approve_call(function):
                    continue
                # Some setters call approve(new, MAX) but skip zeroing old -
                # still a bug; only skip if a zero-approve was found above.
                # Keep `_has_any_approve_call` as informational only.
                _ = _has_any_approve_call(function)

                info: DETECTOR_INFO = [
                    function,
                    " in ",
                    contract,
                    " rotates integration address ",
                    target,
                    " but does not call approve(old, 0) - old integration "
                    "retains its prior token approval and can still drain "
                    "this contract.\n",
                ]
                results.append(self.generate_result(info))

        return results
