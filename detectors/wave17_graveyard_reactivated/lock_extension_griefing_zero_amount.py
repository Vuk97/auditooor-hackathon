"""
lock_extension_griefing_zero_amount.py - Custom Slither detector.

Pattern (Zellic slice_aa line 414, HIGH): a `depositFor(address beneficiary,
uint256 amount, uint256 duration)`-style function extends the beneficiary's
lock by `duration` even when `amount == 0`. An attacker can repeatedly call
it with amount=0 to push any user's unlock time forward, blocking withdrawal
indefinitely.

Detection strategy:
    1. Walk user functions. Require first parameter is `address` and at
       least one subsequent parameter is a uint named "amount" (case-
       insensitive).
    2. Require the function writes a state variable whose name contains
       "lock" or "unlock" - i.e. a lock-bookkeeping state.
    3. Require the function does NOT contain a Binary(GREATER) comparing
       the `amount` local to Constant(0) inside a require/assert or IF-
       revert node. That is the missing `require(amount > 0)`.
    4. Flag if all conditions hold.

@author auditooor wave8
@pattern slice_aa LockExtensionGriefing
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
from slither.slithir.operations import Binary, BinaryType
from slither.slithir.variables import Constant
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_LOCK_SV_HINTS = ("lock", "unlock")


def _first_param_is_address_and_has_amount(function):
    """
    Return the `amount` parameter variable if:
      - function has at least 2 params,
      - first param is of type address,
      - one of the other params is a uint named 'amount' (case-insensitive).
    Otherwise return None.
    """
    params = function.parameters
    if len(params) < 2:
        return None
    first = params[0]
    t = getattr(first, "type", None)
    if t is None or "address" not in str(t):
        return None
    for p in params[1:]:
        pname = (getattr(p, "name", "") or "").lower()
        ptype = str(getattr(p, "type", "") or "")
        if pname == "amount" and "uint" in ptype:
            return p
    return None


def _writes_lock_state(function) -> bool:
    for sv in function.state_variables_written:
        nm = (getattr(sv, "name", "") or "").lower()
        if any(h in nm for h in _LOCK_SV_HINTS):
            return True
    return False


def _has_amount_gt_zero_guard(function, amount_param) -> bool:
    """
    Return True if any require/assert/if node in the function contains a
    Binary(GREATER) comparing the `amount` local to Constant(0), OR a
    Binary(NOT_EQUAL) amount != 0.
    """
    target_names = {(amount_param.name or "").lower(), "amount"}
    for node in function.nodes:
        if not (node.contains_require_or_assert() or node.contains_if()):
            continue
        for ir in node.irs:
            if not isinstance(ir, Binary):
                continue
            if ir.type not in (BinaryType.GREATER, BinaryType.NOT_EQUAL, BinaryType.GREATER_EQUAL):
                continue
            lhs = ir.variable_left
            rhs = ir.variable_right
            lhs_nm = (getattr(lhs, "name", "") or "").lower()
            if lhs_nm not in target_names:
                continue
            # right must be a zero constant (or 1 for >=)
            if not isinstance(rhs, Constant):
                continue
            try:
                val = int(rhs.value)
            except (TypeError, ValueError):
                continue
            if ir.type == BinaryType.GREATER_EQUAL and val == 1:
                return True
            if ir.type in (BinaryType.GREATER, BinaryType.NOT_EQUAL) and val == 0:
                return True
    return False


class LockExtensionGriefingZeroAmount(AbstractDetector):
    """Detect lock-extension deposit functions missing a non-zero amount check."""

    ARGUMENT = "lock-extension-griefing-zero-amount"
    HELP = (
        "depositFor(address user, uint256 amount, uint256 duration) extends "
        "user's lock without require(amount > 0) - zero-amount griefing"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Lock-Extension Griefing via Zero-Amount Deposit"
    WIKI_DESCRIPTION = (
        "A deposit-for-other function takes `(address user, uint256 amount, "
        "uint256 duration)` and updates the user's lock-bookkeeping state "
        "(e.g. `locks[user].unlockTime = max(locks[user].unlockTime, "
        "block.timestamp + duration)`) unconditionally. Without a "
        "`require(amount > 0)` guard, an attacker can repeatedly call the "
        "function with `amount == 0` to push any victim's unlock time out "
        "to MAX_LOCK, permanently denying them the ability to withdraw. "
        "Found in Zellic slice_aa (HIGH)."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function depositFor(address user, uint256 amount, uint256 duration) external {
    locks[user].unlockTime = max(locks[user].unlockTime, block.timestamp + duration);
    balances[user] += amount;   // amount can be 0; lock still extended
}
```
Attacker calls `depositFor(alice, 0, MAX_LOCK)` every block. Alice's unlock
time is pinned to the maximum, so she can never withdraw - denial-of-service
griefing of her staked balance."""
    WIKI_RECOMMENDATION = (
        "Add `require(amount > 0, \"zero amount\")` at the top of the function "
        "so zero-amount calls revert before touching the lock state. If a zero-"
        "amount lock extension is ever legitimate, gate it behind msg.sender == user."
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
                if function.view or function.pure:
                    continue
                if function.visibility not in ("public", "external"):
                    continue

                amount_param = _first_param_is_address_and_has_amount(function)
                if amount_param is None:
                    continue

                if not _writes_lock_state(function):
                    continue

                if _has_amount_gt_zero_guard(function, amount_param):
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " updates lock state for the first-argument address "
                    "without a `require(amount > 0)` guard. Attacker can "
                    "call with amount == 0 to extend any user's unlock "
                    "time, griefing withdrawals.\n",
                ]
                results.append(self.generate_result(info))

        return results
