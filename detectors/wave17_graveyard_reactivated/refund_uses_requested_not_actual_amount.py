"""
refund_uses_requested_not_actual_amount.py - Custom Slither detector.

Pattern (Superposition H-02, slice_ab): A payable swap-and-refund function
computes the refund as `amount - actualOut`, where `amount` is the
function's INPUT parameter rather than the actually-received delta. With a
fee-on-transfer token (or a partial-fill pool that consumes less than the
caller advertised) `amount > actuallySpent`, so the contract refunds more
than the user paid in - anyone with a custom fee-on-transfer asset can drain
the contract.

Detection strategy:
    1. Iterate declared functions whose name suggests refund/swap/swap-and-X
       AND that take a `uint256` parameter named matching `amount|amt|in`.
    2. Confirm there is a transfer/refund of the form `param - X` (Binary
       SUBTRACTION whose left operand reads the input parameter and whose
       result reaches a HighLevelCall to `transfer(...)` / `safeTransfer(...)`
       OR a `payable(...).transfer(...)` low-level send).
    3. Negative gate: skip if the function ALSO computes a balance-of delta
       (it tracks actual received). Heuristic: function reads `balance` /
       `balanceOf` / `address(this).balance` at least twice (snapshot + final),
       or stores a "before" balance into a local var.

@author auditooor wave9
@pattern slice_ab Superposition H-02
"""

import re
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract

from slither.core.declarations import Function
from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.slithir.operations import (
    Binary,
    BinaryType,
    HighLevelCall,
    LowLevelCall,
    Send,
    Transfer,
)
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_FN_NAME_RE = re.compile(r"swap|refund|deposit|wrap|fill", re.IGNORECASE)
_AMOUNT_PARAM_RE = re.compile(r"^(amount|amt|amountin|amount_in|input|wad)$", re.IGNORECASE)
_TRANSFER_SIGS = (
    "transfer(address,uint256)",
    "safeTransfer(address,uint256)",
)
_BALANCE_RE = re.compile(r"balanceOf|address\(this\)\.balance|\.balance\b", re.IGNORECASE)


def _get_amount_param(function):
    for p in function.parameters or []:
        nm = (getattr(p, "name", "") or "")
        t = str(getattr(p, "type", "") or "")
        if t == "uint256" and _AMOUNT_PARAM_RE.match(nm):
            return p
    return None


def _function_tracks_balance_delta(function) -> bool:
    """True if the function appears to snapshot a balance (heuristic)."""
    snapshots = 0
    for node in function.nodes:
        sm = getattr(node, "source_mapping", None)
        content = getattr(sm, "content", None) if sm else None
        if not content:
            continue
        if _BALANCE_RE.search(content):
            snapshots += 1
            if snapshots >= 2:
                return True
    return False


def _binary_subs_using_param(function, param):
    """Return list of (node, binary_ir) where ir is a SUBTRACTION whose
    left/either operand directly reads the parameter."""
    found = []
    for node in function.nodes:
        for ir in node.irs:
            if isinstance(ir, Binary) and ir.type == BinaryType.SUBTRACTION:
                # left/right are SlithIR variables; compare by identity to param
                lv = getattr(ir, "variable_left", None)
                rv = getattr(ir, "variable_right", None)
                if lv is param or rv is param:
                    found.append((node, ir))
    return found


def _function_does_transfer(function) -> bool:
    """True if the function performs a token transfer or native send."""
    for node in function.nodes:
        for ir in node.irs:
            if isinstance(ir, HighLevelCall) and isinstance(ir.function, Function):
                if ir.function.solidity_signature in _TRANSFER_SIGS:
                    return True
            if isinstance(ir, (Send, Transfer)):
                return True
            if isinstance(ir, LowLevelCall):
                # call{value:...}("") qualifies as a refund channel
                if getattr(ir, "function_name", None) in ("call", "transfer", "send"):
                    return True
    return False


class RefundUsesRequestedNotActualAmount(AbstractDetector):
    """Detect refund computations that subtract from the caller-supplied
    `amount` parameter instead of the actually-received delta."""

    ARGUMENT = "refund-uses-requested-not-actual-amount"
    HELP = (
        "Refund derived from input `amount` parameter rather than actual "
        "balance delta - fee-on-transfer / partial-fill drains funds"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Refund Computed From Requested Amount, Not Actual Spent"
    WIKI_DESCRIPTION = (
        "A swap/wrap/refund function takes an `amount` parameter and refunds "
        "`amount - actuallySpent` to the caller without first measuring how "
        "much was actually consumed via a balance-of delta. With a fee-on-"
        "transfer token, a partial-fill pool, or any path where less than "
        "`amount` is consumed, the contract refunds more than the user paid "
        "in - letting anyone drain the contract by supplying a custom token."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function swapAndRefund(uint256 amount) external payable returns (uint256 out) {
    out = pool.swap{value: msg.value}(amount);
    payable(msg.sender).transfer(amount - out); // BUG: parameter, not delta
}
```
1. Attacker passes `amount = 1e18` but supplies a fee-on-transfer token whose
   pool consumes only 0.9e18.
2. `out` returns 0.9e18, refund = 1e18 - 0.9e18 = 0.1e18 of native funds.
3. Repeating drains the contract balance the attacker never deposited."""
    WIKI_RECOMMENDATION = (
        "Snapshot the contract's token / native balance before the swap, take "
        "the post-swap delta as the actually-spent amount, and refund based "
        "on that delta - never on the raw `amount` parameter."
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
                name = (function.name or "").lower()
                if not _FN_NAME_RE.search(name):
                    continue
                p = _get_amount_param(function)
                if p is None:
                    continue
                if not _function_does_transfer(function):
                    continue
                if _function_tracks_balance_delta(function):
                    continue
                subs = _binary_subs_using_param(function, p)
                if not subs:
                    continue

                node = subs[0][0]
                info: DETECTOR_INFO = [
                    function,
                    " in ",
                    contract,
                    " refunds based on input `",
                    p.name or "amount",
                    "` parameter (",
                    node,
                    ") instead of the actual spent delta - fee-on-transfer / "
                    "partial-fill drains funds.\n",
                ]
                results.append(self.generate_result(info))

        return results
