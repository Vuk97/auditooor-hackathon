"""
unsafe_int_cast_profit.py - Custom Slither detector.

Pattern (Zellic slice_ac - Avantis UnsafeCastTP, CRITICAL):
    A profit / PnL calculation casts a user-controlled uint256 to int256
    (or smaller int type) without first capping it to `type(int256).max`.
    When a sell order is updated with `updateTp(type(uint256).max)` the
    stored TP fits in uint256 but the `int(tp)` cast in the profit formula
    overflows to a negative value, inverting the direction of the check
    and allowing the attacker to drain the pool.

    Canonical unsafe pattern:
        function updateTp(uint256 newTp) external {
            trades[msg.sender].tp = newTp;   // stored as uint256, unchecked
        }
        function profit() internal view returns (int256) {
            int256 tp = int256(trades[msg.sender].tp);    // OVERFLOWS
            ...
        }

Detection strategy:
    1. Walk every non-view function.
    2. Find TypeConversion IRs where the TARGET type is a signed int
       (int / int256 / int128 / int64) and the SOURCE is either a
       parameter, a state variable, or a local tainted from either.
    3. Require that the function ALSO performs a Binary SUBTRACTION or
       subsequent compare using the converted value (i.e. it is used in
       arithmetic, not merely an event emission).
    4. Require that the function has NO bounds check on the source value
       of the form `require(src <= <constant>)` or `require(src < <const>)`
       via a Binary LESS/LESS_EQUAL in a require-containing node.

@author auditooor wave11
@pattern slice_ac Avantis UnsafeCastTP
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
from slither.core.solidity_types.elementary_type import ElementaryType
from slither.core.variables.state_variable import StateVariable
from slither.core.variables.local_variable import LocalVariable
from slither.slithir.operations import (
    TypeConversion, Binary, BinaryType,
)
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_SIGNED_INT_NAMES = frozenset({
    "int", "int256", "int128", "int64", "int32", "int16", "int8",
})


def _is_signed_int(t) -> bool:
    if not isinstance(t, ElementaryType):
        return False
    return getattr(t, "name", None) in _SIGNED_INT_NAMES


def _collect_profit_casts(function):
    """
    Return list of (node, TypeConversion IR) for each cast whose source is
    a parameter / state var / local and target is a signed int type, and
    where the resulting temporary is used by a Binary SUBTRACTION or
    compare downstream in the same function.
    """
    casts = []
    cast_lvs = {}
    for node in function.nodes:
        for ir in node.irs:
            if not isinstance(ir, TypeConversion):
                continue
            if not _is_signed_int(ir.type):
                continue
            src = ir.variable
            if isinstance(src, (StateVariable, LocalVariable)) or src in function.parameters:
                lv = ir.lvalue
                cast_lvs[id(lv)] = (node, ir)

    if not cast_lvs:
        return []

    # Confirm the cast result is consumed by a Binary arithmetic / compare.
    used = set()
    for node in function.nodes:
        for ir in node.irs:
            if not isinstance(ir, Binary):
                continue
            for operand in (ir.variable_left, ir.variable_right):
                if id(operand) in cast_lvs:
                    used.add(id(operand))

    for lv_id, tup in cast_lvs.items():
        if lv_id in used:
            casts.append(tup)
    return casts


def _function_has_upper_bound_require(function, param):
    """Rough check: any require/assert node with a LESS or LESS_EQUAL
    binary referencing `param`."""
    for node in function.nodes:
        if not node.contains_require_or_assert():
            continue
        for ir in node.irs:
            if not isinstance(ir, Binary):
                continue
            if ir.type not in (BinaryType.LESS, BinaryType.LESS_EQUAL):
                continue
            if ir.variable_left is param or ir.variable_right is param:
                return True
    return False


class UnsafeIntCastProfit(AbstractDetector):
    """Detect unsafe uint->int cast in PnL math with no upper-bound guard."""

    ARGUMENT = "unsafe-int-cast-profit"
    HELP = (
        "uint->int cast in PnL/profit arithmetic with no upper-bound "
        "require on the source - attacker can flip sign of the math"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Unsafe uint->int Cast in Profit Math"
    WIKI_DESCRIPTION = (
        "Profit / PnL / health calculations that cast a user-controlled "
        "uint256 (or smaller) to `int256` without first bounding the source "
        "to `type(int256).max` can wrap around to a negative value. The "
        "inverted sign flips the direction of downstream subtraction or "
        "compare, letting the attacker fabricate a huge fictional profit. "
        "Observed in Avantis `updateTp(type(uint256).max)` → `_currentPercentProfit` "
        "overflow (Zellic critical)."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function updateTp(uint256 newTp) external { trades[msg.sender].tp = newTp; }

function currentPercentProfit() internal view returns (int256) {
    uint256 tp = trades[msg.sender].tp;
    int256 diff = int256(tp) - int256(openPrice);   // OVERFLOW when tp is huge
    return diff * 100 / int256(openPrice);
}
```
1. Attacker calls `updateTp(type(uint256).max)` → passes the uint256 setter.
2. `int256(tp)` overflows to `-1`, so `diff = -1 - openPrice`.
3. Profit calc returns a large positive number (after another sign flip).
4. Attacker claims fabricated profit."""
    WIKI_RECOMMENDATION = (
        "Clamp user-controlled price / size / TP inputs to `type(int256).max` "
        "via `require(x <= uint256(type(int256).max))` BEFORE storing. "
        "Prefer OZ SafeCast (`SafeCast.toInt256`) which reverts on overflow."
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

                casts = _collect_profit_casts(function)
                if not casts:
                    continue

                # Only flag if at least one cast's source is a parameter
                # without an upper-bound require in the same function.
                for node, ir in casts:
                    src = ir.variable
                    if src in function.parameters:
                        if _function_has_upper_bound_require(function, src):
                            continue
                    # state var / local: always flag (couldn't trace the write
                    # site via param-level check).
                    info: DETECTOR_INFO = [
                        function,
                        " casts ",
                        src,
                        " to a signed int type at ",
                        node,
                        " and uses the result in arithmetic without an "
                        "upper-bound guard - unsafe cast can wrap to a "
                        "negative value and flip PnL sign.\n",
                    ]
                    results.append(self.generate_result(info))
                    break  # one finding per function

        return results
