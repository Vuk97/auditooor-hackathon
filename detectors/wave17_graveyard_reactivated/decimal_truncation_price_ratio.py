"""
decimal_truncation_price_ratio.py - Custom Slither detector.

Pattern (Zellic slice_aa SOCKET, CRITICAL): a price-ratio sanity check
computes `fromPrice / toPrice` as bare integer division without first
scaling the numerator by 1e18. For Chainlink-style feeds that return
values like 2000e8, the result always truncates to a single-digit
integer, and the downstream `require(ratio <= limit)` is trivially
satisfied for any sensible `limit`, making the price-deviation guard
useless.

Detection strategy:
    1. Walk user functions that make at least one Chainlink-style oracle
       call (latestAnswer / latestRoundData / latestRoundDataByName).
    2. Find any Binary(DIVISION) IR in the same function whose numerator
       is NOT the result of an earlier Binary(MULTIPLICATION) by a
       large constant (>= 1e10 - i.e. a proper scaling factor). If the
       numerator came straight out of a variable / oracle call, it is
       unscaled.
    3. In the same function, find a Binary comparison (LESS/LESS_EQUAL/
       GREATER/GREATER_EQUAL) whose right operand is a Constant < 1e10.
       A limit less than 1e10 is inconsistent with a properly scaled
       1e18 ratio and therefore signals truncated integer-division math.
    4. Flag if all three conditions hold.

This is deliberately over-approximate; confidence is MEDIUM.

@author auditooor wave8
@pattern slice_aa SOCKET DecimalTruncationPriceRatio
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
from slither.slithir.operations import Binary, BinaryType, HighLevelCall
from slither.slithir.variables import Constant
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_ORACLE_SIGS = frozenset({
    "latestAnswer()",
    "latestRoundData()",
    "latestRoundDataByName(string)",
})

# Scaling threshold: a constant factor >= 1e10 is assumed to be a proper
# decimal scaling factor (e.g. 1e18, 1e27). Smaller constants are too small
# to preserve Chainlink 1e8 precision.
_MIN_SCALE = 10 ** 10

# Comparison operators that form a "bound check"
_CMP_OPS = {
    BinaryType.LESS, BinaryType.LESS_EQUAL,
    BinaryType.GREATER, BinaryType.GREATER_EQUAL,
}


def _function_calls_oracle(function) -> bool:
    for _c, ir in function.high_level_calls:
        fn = getattr(ir, "function", None)
        if fn is None:
            continue
        if getattr(fn, "solidity_signature", None) in _ORACLE_SIGS:
            return True
    return False


def _collect_scaled_lvalues(function):
    """
    Return a set of lvalues that are the result of a Binary(MULTIPLICATION)
    whose right (or left) operand is a Constant >= _MIN_SCALE. These are
    "properly scaled" temporaries.
    """
    scaled = set()
    for node in function.nodes:
        for ir in node.irs:
            if not (isinstance(ir, Binary) and ir.type == BinaryType.MULTIPLICATION):
                continue
            for side in (ir.variable_left, ir.variable_right):
                if isinstance(side, Constant):
                    try:
                        if int(side.value) >= _MIN_SCALE:
                            if ir.lvalue is not None:
                                scaled.add(ir.lvalue)
                            break
                    except (TypeError, ValueError):
                        continue
    return scaled


def _unscaled_division(function, scaled_lvalues):
    """
    Return the first Binary(DIVISION) whose numerator (variable_left) is
    NOT in scaled_lvalues and is NOT a Constant. (i.e. it is a plain
    variable / temporary - unscaled.) Returns (node, ir) or (None, None).
    """
    for node in function.nodes:
        for ir in node.irs:
            if not (isinstance(ir, Binary) and ir.type == BinaryType.DIVISION):
                continue
            lhs = ir.variable_left
            if isinstance(lhs, Constant):
                continue
            if lhs in scaled_lvalues:
                continue
            return node, ir
    return None, None


def _has_small_bound_compare(function):
    """
    Return True if the function contains a Binary comparison whose right-hand
    side is a Constant with absolute value < _MIN_SCALE.
    """
    for node in function.nodes:
        for ir in node.irs:
            if not isinstance(ir, Binary):
                continue
            if ir.type not in _CMP_OPS:
                continue
            right = ir.variable_right
            if not isinstance(right, Constant):
                continue
            try:
                val = int(right.value)
            except (TypeError, ValueError):
                continue
            if abs(val) < _MIN_SCALE:
                return True
    return False


class DecimalTruncationPriceRatio(AbstractDetector):
    """Detect unscaled integer-division price ratios that defeat bound checks."""

    ARGUMENT = "decimal-truncation-price-ratio"
    HELP = (
        "Price ratio computed as fromPrice / toPrice without 1e18 scaling - "
        "integer truncation silently satisfies any deviation bound"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Unscaled Integer-Division Price Ratio"
    WIKI_DESCRIPTION = (
        "A price-deviation check computes `a / b` on two oracle-sourced values "
        "without first multiplying the numerator by a decimal-scaling factor "
        "(e.g. 1e18). Chainlink feeds return integers like 2000e8; integer "
        "division truncates the fractional part entirely, so the ratio collapses "
        "to a tiny integer (0, 1, 2…). Any downstream bound check "
        "(`require(ratio <= X)`) with a constant `X` smaller than 1e10 is "
        "trivially satisfied, silently disabling the guard. This is the SOCKET "
        "bug from Zellic slice_aa (CRITICAL)."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
int256 a = oracle1.latestAnswer();   // 2000_00000000
int256 b = oracle2.latestAnswer();   // 1000_00000000
int256 ratio = a / b;                // = 2 (truncated)
require(ratio <= 2, "too big");      // passes for any real price
```
The deviation check is a no-op: even a 50% price divergence still yields
an integer ratio within the naive bound, so oracle-manipulation and stale-
price inputs pass through the guard unchanged."""
    WIKI_RECOMMENDATION = (
        "Scale the numerator before dividing: `ratio = (a * 1e18) / b;` and "
        "compare against a bound in the same scale (e.g. `require(ratio <= "
        "2e18)`). Or use FullMath.mulDiv / a dedicated fixed-point library."
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
                if not _function_calls_oracle(function):
                    continue

                scaled = _collect_scaled_lvalues(function)
                div_node, div_ir = _unscaled_division(function, scaled)
                if div_node is None:
                    continue

                if not _has_small_bound_compare(function):
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " divides oracle-sourced values at ",
                    div_node,
                    " without first scaling by a 1e18-class factor, and "
                    "compares the result against a small constant. Integer "
                    "truncation makes the deviation bound a no-op.\n",
                ]
                results.append(self.generate_result(info))

        return results
