"""
fee_deadcode_wrong_return.py - Custom Slither detector.

Pattern (slice_ah - ether.fi EigenLayer-Fee-Wrong-Return, HIGH):
    `getFeeAmount()` computes
        feeAmount = gasSpendings * block.basefee;
    then returns `gasSpendings` (the multiplier constant) instead of
    `feeAmount`. The arithmetic line is dead code; the fee charged is
    the raw multiplier - effectively zero economic fee.

Detection strategy:
    1. Consider non-view/non-pure AND view/pure fee-like getters - any
       function whose name contains `fee|amount|price|cost|charge|quote`.
    2. For the function, find LocalVariables that are assigned via a
       Binary arithmetic IR (MULTIPLICATION, ADDITION, DIVISION,
       SUBTRACTION) - call this set `computed_locals`.
    3. Find the function's RETURN IR(s); collect the LocalVariable(s)
       read by Return IR operations - call this set `returned_locals`.
    4. If `computed_locals` is non-empty AND `computed_locals` is
       DISJOINT from `returned_locals`, AND at least one of the computed
       locals' names looks like a fee result (contains fee/amount/total
       /result) → flag. This captures "the arithmetic product was never
       returned; a different local was".

Confidence: MEDIUM. Narrow - requires both a computed local and a
non-overlapping return.
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
from slither.core.variables.local_variable import LocalVariable
from slither.slithir.operations import Binary, BinaryType, Assignment, Return
from slither.slithir.variables import TemporaryVariable
from slither.utils.output import Output


_ARITH_OPS = frozenset({
    BinaryType.MULTIPLICATION,
    BinaryType.ADDITION,
    BinaryType.DIVISION,
    BinaryType.SUBTRACTION,
})

_FEE_FN_FRAGMENTS = ("fee", "amount", "price", "cost", "charge", "quote", "rate")
_RESULT_NAME_FRAGMENTS = ("fee", "amount", "total", "result", "cost", "price", "charge")
_SKIP_KEYWORDS = ("test", "mock", "setup", "fixture", "helper", "deploy", "script")


class FeeDeadcodeWrongReturn(AbstractDetector):
    """Detect fee getters that compute a value then return a different local."""

    ARGUMENT = "fee-deadcode-wrong-return"
    HELP = (
        "Fee getter computes `result = A * B` then returns a DIFFERENT "
        "local (e.g. the multiplier) - the arithmetic is dead code"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Fee Getter Returns Wrong Local (Arithmetic Dead Code)"
    WIKI_DESCRIPTION = (
        "A fee/amount/price getter computes a local variable via an "
        "arithmetic expression (e.g. `feeAmount = gas * basefee`) but its "
        "return statement reads a different, un-computed local - typically "
        "one of the inputs to the dead arithmetic. The fee charged is "
        "therefore the raw multiplier, not the computed product. Observed "
        "in ether.fi `getFeeAmount()` (Zellic audit, HIGH)."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function getFeeAmount() external view returns (uint256) {
    uint256 gasSpendings = 150000;
    uint256 feeAmount = gasSpendings * block.basefee; // dead
    return gasSpendings;                              // BUG: wrong local
}
```
1. Protocol charges `getFeeAmount()` on every operation.
2. Because the returned value is the raw constant multiplier, the fee is
   effectively a fixed nominal amount instead of a gas-denominated fee.
3. Users under-pay, protocol loses revenue or gets DOS'd when basefee
   spikes."""
    WIKI_RECOMMENDATION = (
        "Return the computed local (`return feeAmount`) and delete any "
        "dead intermediate bindings. Prefer a single expression "
        "(`return gasSpendings * block.basefee`) to eliminate naming "
        "errors entirely."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            for function in contract.functions_and_modifiers_declared:
                fname = (function.name or "").lower()
                if not any(frag in fname for frag in _FEE_FN_FRAGMENTS):
                    continue
                if not function.returns:
                    continue

                # Step A: find locals assigned from a Binary arith result
                computed: dict[str, LocalVariable] = {}
                for node in function.nodes:
                    # Map TMP lvalues from Binary ops
                    arith_tmps: set = set()
                    for ir in node.irs:
                        if isinstance(ir, Binary) and ir.type in _ARITH_OPS:
                            arith_tmps.add(id(ir.lvalue))
                    for ir in node.irs:
                        if not isinstance(ir, Assignment):
                            continue
                        lv = ir.lvalue
                        if not isinstance(lv, LocalVariable):
                            continue
                        rv = getattr(ir, "rvalue", None)
                        if rv is None:
                            continue
                        if isinstance(rv, TemporaryVariable) and id(rv) in arith_tmps:
                            computed[lv.name] = lv

                if not computed:
                    continue

                # Step B: collect return-read locals
                returned_names: set = set()
                for node in function.nodes:
                    for ir in node.irs:
                        if isinstance(ir, Return):
                            for r in ir.read:
                                if isinstance(r, LocalVariable):
                                    returned_names.add(r.name)

                if not returned_names:
                    continue

                # Step C: any computed local is NOT among returned locals,
                # AND the computed local's name looks like the intended result
                dead_computed = [
                    lv for name, lv in computed.items()
                    if name not in returned_names
                    and any(frag in name.lower() for frag in _RESULT_NAME_FRAGMENTS)
                ]
                if not dead_computed:
                    continue

                for lv in dead_computed:
                    info: DETECTOR_INFO = [
                        function,
                        " computes local `",
                        lv.name,
                        "` via arithmetic but returns a different local - the "
                        "computation is dead code; fee/amount actually returned "
                        "is the un-multiplied operand.\n",
                    ]
                    results.append(self.generate_result(info))

        return results
