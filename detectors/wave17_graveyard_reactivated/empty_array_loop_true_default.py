"""
empty_array_loop_true_default.py - Custom Slither detector.

Pattern (Cantina 3.1.4 / Quantstamp POL-EX-2 - ctf-exchange-v2 Trading.sol):
A boolean "all match a predicate" helper iterates an array parameter and
returns `false` on mismatch, then `true` at the end. Because the function
never checks for a non-empty array, an empty input defaults to `true` and
the caller takes a branch that should have required at least one element.
Exactly the `_isAllComplementary()` bug in Polymarket v2 Trading.sol:
with `makers.length == 0` the complementary branch ran and still
charged the taker a fee.

Detection strategy:
    1. For each function with a single bool return and at least one
       array parameter, walk its CFG.
    2. Look for the shape:
         - a FOR / WHILE loop over the array
         - inside the loop, a RETURN with constant `false`
         - outside the loop (after the loop exits), a RETURN with
           constant `true`
    3. If the function body has NO length==0 guard before the loop
       (require / revert / return false), flag it.

@author auditooor wave11
@pattern Cantina 3.1.4 / Quantstamp POL-EX-2
"""

import sys as _sys
from pathlib import Path as _Path

_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract

from slither.core.solidity_types.array_type import ArrayType
from slither.core.cfg.node import NodeType
from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.slithir.operations import Binary, BinaryType, Return
from slither.slithir.variables import Constant
from slither.utils.output import Output


SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup")


def _function_returns_bool(function) -> bool:
    rets = function.returns or []
    if len(rets) != 1:
        return False
    t = rets[0].type
    return t is not None and str(t) == "bool"


def _array_parameter(function):
    for p in function.parameters or []:
        if isinstance(p.type, ArrayType):
            return p
    return None


def _function_has_length_zero_guard(function, array_param) -> bool:
    """True if function body reads `array_param.length` and compares it to
    0 in a guarding context (before any loop)."""
    for node in function.nodes:
        if node.type in (NodeType.STARTLOOP, NodeType.IFLOOP):
            return False  # stop - we hit the loop first, no guard above it
        if not (node.contains_if() or node.contains_require_or_assert()):
            continue
        for ir in node.irs:
            if not isinstance(ir, Binary):
                continue
            if ir.type not in (BinaryType.EQUAL, BinaryType.NOT_EQUAL,
                               BinaryType.GREATER, BinaryType.LESS,
                               BinaryType.GREATER_EQUAL, BinaryType.LESS_EQUAL):
                continue
            ops = (ir.variable_left, ir.variable_right)
            has_zero = any(
                isinstance(o, Constant) and str(o.value) in ("0", "0x0")
                for o in ops
            )
            if not has_zero:
                continue
            # Does any IR in this node read the length of array_param?
            # Slither encodes `.length` access; the array param appears in
            # node.variables_read. We approximate: if the array param is
            # read in this guarding node → treat as length guard.
            if array_param in node.variables_read:
                return True
    return False


def _find_return_const_bool(function, want_value: bool):
    """Return the first node whose IR contains a Return of Constant(want_value)."""
    hits = []
    for node in function.nodes:
        if node.type != NodeType.RETURN:
            continue
        for ir in node.irs:
            if not isinstance(ir, Return):
                continue
            for val in ir.values:
                if isinstance(val, Constant) and bool(val.value) == want_value:
                    hits.append(node)
                    break
    return hits


class EmptyArrayLoopTrueDefault(AbstractDetector):
    """Bool helper returning `true` as the tail of a for-loop over an array
    parameter - empty input defaults to `true`."""

    ARGUMENT = "empty-array-loop-true-default"
    HELP = (
        "Boolean `all match` helper returns true by default on an empty "
        "array parameter - caller takes a branch that should require "
        "at least one element."
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Universal-quantifier helper returns true on empty arrays"
    WIKI_DESCRIPTION = (
        "Boolean helpers shaped as `for (i = 0; i < xs.length; i++) { if "
        "(!p(xs[i])) return false; } return true;` implement ∀x∈xs. p(x), "
        "which is vacuously true on an empty array. If the caller uses the "
        "result to gate a privileged branch (such as 'all makers are "
        "complementary' in Polymarket v2's `_isAllComplementary`), an empty "
        "batch triggers that branch with no elements validated - in the "
        "Polymarket case, this allowed an operator to run the complementary-"
        "settlement path with zero makers and charge the taker a fee against "
        "an empty fill."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function _isAllComplementary(Side takerSide, Order[] memory makers) internal pure returns (bool) {
    for (uint256 i = 0; i < makers.length; i++) {
        if (makers[i].side == takerSide) return false;
    }
    return true; // <-- true when makers.length == 0
}
```
Operator passes an empty `makerOrders` array. `_isAllComplementary` returns
true, the complementary branch runs, and the taker is charged a fee with
no maker fills executed."""
    WIKI_RECOMMENDATION = (
        "Guard the helper with `require(array.length > 0)` (or `revert` on "
        "empty batches), or change the early-return/tail polarity so that "
        "the empty-input case returns false."
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
                if not _function_returns_bool(function):
                    continue
                array_param = _array_parameter(function)
                if array_param is None:
                    continue
                # Needs a loop
                if not any(n.type in (NodeType.STARTLOOP, NodeType.IFLOOP)
                           for n in function.nodes):
                    continue
                true_returns = _find_return_const_bool(function, True)
                false_returns = _find_return_const_bool(function, False)
                if not true_returns or not false_returns:
                    continue
                if _function_has_length_zero_guard(function, array_param):
                    continue
                info: DETECTOR_INFO = [
                    function,
                    " iterates array parameter ",
                    array_param.name or "?",
                    " with a for-loop that returns `false` on mismatch and "
                    "`true` at the tail - empty input defaults to true at ",
                    true_returns[0],
                    "\n",
                ]
                results.append(self.generate_result(info))
        return results
