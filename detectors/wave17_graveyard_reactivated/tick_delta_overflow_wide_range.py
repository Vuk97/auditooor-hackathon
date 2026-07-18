"""
tick_delta_overflow_wide_range.py - Custom Slither detector.

Pattern (Panoptic M-08, slice_ad): Uniswap V3 tick math computes
`tickDelta = upper - lower` where both bounds are `int24`. The valid range
of a Uniswap V3 tick is roughly +/- 887272, so the delta can be up to
~1.77M. A protocol that stores the delta in `uint16` (or any type narrower
than int24/uint24) silently truncates wide-range positions.

Detection strategy:
    1. Find functions that take at least one `int24` parameter (Uniswap tick).
    2. The function must contain a `Binary` IR of type SUBTRACTION whose
       operand types are int24/uint24 (the tick subtraction).
    3. The function must contain a `TypeConversion` IR whose destination
       type is narrower than int24 - i.e. uint8/int8/uint16/int16. These
       are the truncation targets that cannot hold the full tick range.

@author auditooor wave9
@pattern slice_ad Panoptic M-08
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
from slither.slithir.operations import Binary, BinaryType, TypeConversion
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")
_NARROW_DST_TYPES = {"uint8", "int8", "uint16", "int16"}
_TICK_LIKE_OPERAND_TYPES = {"int24", "uint24"}


def _is_int24_param(p) -> bool:
    t = p.type
    return isinstance(t, ElementaryType) and t.name == "int24"


def _operand_type_name(v) -> str:
    t = getattr(v, "type", None)
    return getattr(t, "name", "") if t is not None else ""


class TickDeltaOverflowWideRange(AbstractDetector):
    """Flag tick subtractions whose result is cast to a type narrower than
    int24 (uint16/int16/etc), losing the high bits on wide ranges."""

    ARGUMENT = "tick-delta-overflow-wide-range"
    HELP = (
        "tick delta (int24 - int24) cast to uint16/int16 silently truncates "
        "wide-range Uniswap V3 positions"
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Tick Delta Truncated By Narrowing Cast"
    WIKI_DESCRIPTION = (
        "Uniswap V3 ticks span roughly +/- 887272, so the delta between two "
        "ticks can be up to ~1.77M - well beyond the range of `uint16` or "
        "`int16`. Casting `upper - lower` to a 16-bit type silently truncates "
        "wide-range LP positions, breaking fee/share accounting. Panoptic "
        "M-08 from slice_ad is the canonical example."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function getDelta(int24 lower, int24 upper) external pure returns (uint16) {
    return uint16(uint24(upper - lower));   // BUG: truncates above 65535
}
```
A user opens a wide-range LP with `lower = -887200`, `upper = 887200`.
The delta is 1,774,400 which wraps to 1,774,400 mod 65,536 = 22,464 - the
position is accounted as ~80x smaller than its true width."""
    WIKI_RECOMMENDATION = (
        "Compute and store tick deltas in `int256` (or at minimum `int32`). "
        "Never cast subtraction of two `int24` ticks to a 16-bit type."
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
                params = list(function.parameters or [])
                if not any(_is_int24_param(p) for p in params):
                    continue

                # Look for a tick-like SUBTRACTION binary op.
                sub_node = None
                for node in function.nodes:
                    for ir in node.irs:
                        if not isinstance(ir, Binary):
                            continue
                        if ir.type != BinaryType.SUBTRACTION:
                            continue
                        lt = _operand_type_name(ir.variable_left)
                        rt = _operand_type_name(ir.variable_right)
                        if lt in _TICK_LIKE_OPERAND_TYPES or rt in _TICK_LIKE_OPERAND_TYPES:
                            sub_node = node
                            break
                    if sub_node is not None:
                        break
                if sub_node is None:
                    continue

                # Look for a narrowing cast to uint8/int8/uint16/int16.
                bad_cast_node = None
                bad_dst = None
                for node in function.nodes:
                    for ir in node.irs:
                        if not isinstance(ir, TypeConversion):
                            continue
                        dst = ir.type
                        if not isinstance(dst, ElementaryType):
                            continue
                        if dst.name in _NARROW_DST_TYPES:
                            bad_cast_node = node
                            bad_dst = dst.name
                            break
                    if bad_cast_node is not None:
                        break
                if bad_cast_node is None:
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " subtracts two int24 ticks at ",
                    sub_node,
                    " and narrows the result to ",
                    bad_dst or "?",
                    " at ",
                    bad_cast_node,
                    " - wide-range positions overflow the 16-bit destination.\n",
                ]
                results.append(self.generate_result(info))

        return results
