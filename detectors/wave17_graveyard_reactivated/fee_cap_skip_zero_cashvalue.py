"""
fee_cap_skip_zero_cashvalue.py - Custom Slither detector.

Pattern (Cantina 3.1.4 / Quantstamp POL-EX-3 - ctf-exchange-v2 Fees.sol):
A fee-validation function early-returns when a `cashValue`/`notional`/
`fillAmount` parameter is zero, BEFORE applying the percentage fee cap.
An operator can then charge an arbitrary fee against a zero-fill order,
bypassing the rate cap. Live in Polymarket v2 (fixed in commit 5936812).

Detection strategy:
    1. Find fee-validation-shaped functions (name contains /fee/ and
       /valid|check|assert|cap/, OR parameter names include both a fee
       amount and a value/notional param).
    2. Look for the shape: `if (value == 0) return;` where `value` is one
       of the function parameters - implemented as a Binary EQUAL against
       0 that controls a node whose successors include a RETURN with no
       prior require/assert on the fee amount.

@author auditooor wave11
@pattern Cantina 3.1.4 / Quantstamp POL-EX-3
"""

import re
import sys as _sys
from pathlib import Path as _Path

_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract

from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.core.cfg.node import NodeType
from slither.slithir.operations import Binary, BinaryType
from slither.slithir.variables import Constant
from slither.utils.output import Output


SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup")
_FEE_FN_RE = re.compile(r"(fee|charge).*?(valid|check|cap|assert|rate)", re.IGNORECASE)
_VALUE_PARAM_RE = re.compile(
    r"(cash|notional|value|fill|amount|principal|size)",
    re.IGNORECASE,
)
_FEE_PARAM_RE = re.compile(r"fee", re.IGNORECASE)


def _function_looks_like_fee_validator(function) -> bool:
    name = (function.name or "").lower()
    if _FEE_FN_RE.search(name):
        return True
    # Fallback: has both a fee-named param and a value-named param.
    has_fee = False
    has_value = False
    for p in function.parameters or []:
        pname = (p.name or "").lower()
        if _FEE_PARAM_RE.search(pname):
            has_fee = True
        if _VALUE_PARAM_RE.search(pname):
            has_value = True
    return has_fee and has_value


def _param_equal_zero_early_return(function):
    """
    Return (node, param) if the function has an `if (param == 0) return;`
    pattern before any require/assert on the fee amount.
    """
    params = function.parameters or []
    if not params:
        return None

    # Build name -> parameter index
    value_params = [p for p in params if _VALUE_PARAM_RE.search((p.name or "").lower())]
    if not value_params:
        return None

    for node in function.nodes:
        if node.type != NodeType.IF:
            continue
        # IR walking: find a Binary EQUAL between a value-param and Constant(0)
        for ir in node.irs:
            if not isinstance(ir, Binary) or ir.type != BinaryType.EQUAL:
                continue
            left, right = ir.variable_left, ir.variable_right
            param_side = None
            zero_side = None
            for side in (left, right):
                if isinstance(side, Constant) and str(side.value) in ("0", "0x0"):
                    zero_side = side
                elif side in value_params:
                    param_side = side
            if param_side is None or zero_side is None:
                continue
            # Check that this IF branch leads to a RETURN / THROW without
            # a require/assert on the fee guarding downstream.
            # Walk successors of the IF: the 'true' branch is son_true.
            true_branch = node.son_true
            if true_branch is None:
                continue
            # Walk forward up to a small depth looking for a RETURN or END_IF
            # without any require/assert on the way.
            seen = set()
            stack = [true_branch]
            found_return = False
            while stack:
                cur = stack.pop()
                if cur in seen:
                    continue
                seen.add(cur)
                if cur.type == NodeType.RETURN:
                    found_return = True
                    break
                if cur.contains_require_or_assert():
                    # Guarded, not a bypass
                    found_return = False
                    break
                # Stop at END_IF - the branch joined back, so the if
                # short-circuited the fee check.
                if cur.type == NodeType.ENDIF:
                    found_return = True
                    break
                for succ in cur.sons:
                    stack.append(succ)
            if found_return:
                return node, param_side
    return None


class FeeCapSkipZeroCashvalue(AbstractDetector):
    """Fee-validation function short-circuits on zero cash value, letting
    the caller charge an uncapped fee on empty fills."""

    ARGUMENT = "fee-cap-skip-zero-cashvalue"
    HELP = (
        "Fee validator early-returns when cashValue/notional == 0 so the "
        "percentage cap is never applied - uncapped fee on zero-fill orders."
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Fee cap bypass via zero cashValue early return"
    WIKI_DESCRIPTION = (
        "A fee-validation helper such as `validateFeeWithMaxFeeRate(fee, cashValue)` "
        "early-returns when `cashValue == 0` before applying the `feeAmount <= "
        "maxFee` check. Because the fee is computed as a percentage of cashValue, "
        "percentage-math is undefined at zero, so the implementation skips the "
        "check. A malicious operator who submits an empty-fill / zero-notional "
        "settlement can then charge an arbitrary fee, draining the taker's "
        "approved collateral without executing any trade. Seen live in "
        "Polymarket ctf-exchange-v2 (Cantina 3.1.4, Quantstamp POL-EX-3)."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function validateFeeWithMaxFeeRate(uint256 feeAmount, uint256 cashValue) internal view {
    if (cashValue == 0) return;   // <-- fee check skipped entirely
    require(feeAmount <= (cashValue * maxFeeRateBps) / 10000, "too high");
}
```
Operator calls `matchOrders(..., takerFillAmount=0, takerFeeAmount=N)`. The
validator returns immediately, and the full approved balance is transferred
to the fee receiver."""
    WIKI_RECOMMENDATION = (
        "Apply a flat fee cap (e.g. `require(feeAmount <= FLAT_FEE_CAP)`) or "
        "reject zero-value settlements outright instead of early-returning."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []
        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in SKIP_KEYWORDS):
                continue
            for function in contract.functions_and_modifiers_declared:
                if function.is_constructor:
                    continue
                if not _function_looks_like_fee_validator(function):
                    continue
                hit = _param_equal_zero_early_return(function)
                if hit is None:
                    continue
                node, param = hit
                info: DETECTOR_INFO = [
                    function,
                    " early-returns when ",
                    param.name or "?",
                    " == 0 at ",
                    node,
                    " - fee cap is skipped and the caller can charge an "
                    "uncapped fee on zero-value settlements.\n",
                ]
                results.append(self.generate_result(info))
        return results
