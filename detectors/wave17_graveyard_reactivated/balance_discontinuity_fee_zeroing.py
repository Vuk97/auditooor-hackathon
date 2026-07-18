"""
balance_discontinuity_fee_zeroing.py - Custom Slither detector.

Pattern (Zellic slice_ac - Beefy UniswapV3 BalanceDiscontinuity, HIGH):
    A `balances()` / `totalAssets()` view is intended to return
    `total - fees`. To avoid underflow the author writes
        if (fees > total) { fees = 0; }
        return total - fees;
    but the resulting function is DISCONTINUOUS: at the boundary
    `fees = total + 1` the return value JUMPS from 0 to `total`. An
    attacker can cross the boundary by donating 1 wei of the underlying
    token, changing share-math in a downstream deposit() that uses this
    view as the "balance before" term.

Detection strategy:
    1. Walk all functions (prefer view/pure reporters but don't require).
    2. Find a node that contains an IF whose condition is a Binary
       GREATER / GREATER_EQUAL / LESS / LESS_EQUAL comparing two local
       variables (or local vs state).
    3. In a successor node reachable from the true branch, find an
       Assignment whose lvalue is one of the compared variables and whose
       rvalue is Constant(0).
    4. In the SAME function, find a Binary SUBTRACTION whose right-hand
       operand is the same variable that was conditionally zeroed.
    5. All three signals → flag.

The idea: `if (fees > total) { fees = 0; } ... return total - fees;` is
exactly a conditional-zero + later-subtract of the zeroed var.

@author auditooor wave11
@pattern slice_ac Beefy BalanceDiscontinuity
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
from slither.core.cfg.node import NodeType
from slither.slithir.operations import Assignment, Binary, BinaryType
from slither.slithir.variables import Constant
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_COMPARE_TYPES = frozenset({
    BinaryType.GREATER,
    BinaryType.GREATER_EQUAL,
    BinaryType.LESS,
    BinaryType.LESS_EQUAL,
})


def _find_zeroed_local(function):
    """
    Return set of variable objects that are conditionally assigned Constant(0)
    inside an IF-body in this function.
    """
    zeroed = set()
    for node in function.nodes:
        # Is this node inside an IF body (dominated by an IF conditional)?
        # Slither exposes node.type. We gate on Assignment nodes whose
        # predecessor contains an IF.
        has_if_pred = False
        for pred in node.fathers or []:
            if pred.contains_if() or pred.type == NodeType.IF:
                has_if_pred = True
                break
        if not has_if_pred:
            continue
        for ir in node.irs:
            if not isinstance(ir, Assignment):
                continue
            rv = ir.rvalue
            if not isinstance(rv, Constant):
                continue
            try:
                if int(rv.value) != 0:
                    continue
            except (TypeError, ValueError):
                continue
            zeroed.add(ir.lvalue)
    return zeroed


def _function_has_compare_on_vars(function, targets):
    """True if any Binary comparison in the function has one of `targets`
    as an operand."""
    for node in function.nodes:
        for ir in node.irs:
            if not isinstance(ir, Binary):
                continue
            if ir.type not in _COMPARE_TYPES:
                continue
            if ir.variable_left in targets or ir.variable_right in targets:
                return True
    return False


def _function_subtracts_target(function, targets):
    """True if any Binary SUBTRACTION has a target on its right-hand side."""
    for node in function.nodes:
        for ir in node.irs:
            if not isinstance(ir, Binary):
                continue
            if ir.type != BinaryType.SUBTRACTION:
                continue
            if ir.variable_right in targets:
                return node
    return None


class BalanceDiscontinuityFeeZeroing(AbstractDetector):
    """Detect `if (b > a) { b = 0; } ... return a - b;` discontinuity pattern."""

    ARGUMENT = "balance-discontinuity-fee-zeroing"
    HELP = (
        "Balance view conditionally zeros the fee then subtracts it, creating "
        "a jump discontinuity exploitable via 1-wei donation"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Balance View Discontinuity via Conditional Fee Zeroing"
    WIKI_DESCRIPTION = (
        "A view that is expected to return `total - fees` uses a conditional "
        "`if (fees > total) { fees = 0; }` guard to avoid revert, then "
        "subtracts fees from total anyway. The resulting function is "
        "discontinuous at the boundary `fees == total + 1`, where the return "
        "jumps from `0` to `total`. When this view feeds a deposit's share "
        "calculation, an attacker can cross the boundary with a 1-wei donation "
        "to create a massive mis-pricing. Observed in Beefy UniswapV3 "
        "strategy `balances()` (Zellic H-03)."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function balances() public view returns (uint256) {
    uint256 total = IERC20(token).balanceOf(address(this));
    uint256 fees = pendingFees;
    if (fees > total) {
        fees = 0;       // DISCONTINUITY
    }
    return total - fees; // returns `total` when fees > total, else total-fees
}
```
1. Before donation: fees = 100, total = 90 → return 90 (fees zeroed).
2. Attacker donates 11 wei → total = 101, fees = 100 → return 1.
3. Share denominator jumps from 90 → 1: next depositor mints 90× shares."""
    WIKI_RECOMMENDATION = (
        "Clamp the subtraction with `total > fees ? total - fees : 0` and "
        "ensure downstream share math uses the clamped monotonic result, or "
        "revert when `fees > total` instead of silently zeroing."
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

                zeroed = _find_zeroed_local(function)
                if not zeroed:
                    continue
                if not _function_has_compare_on_vars(function, zeroed):
                    continue
                sub_node = _function_subtracts_target(function, zeroed)
                if sub_node is None:
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " conditionally zeroes a fee-like local then subtracts it "
                    "at ",
                    sub_node,
                    " - the function is discontinuous at the `fees > total` "
                    "boundary and downstream share math jumps by `total`.\n",
                ]
                results.append(self.generate_result(info))

        return results
