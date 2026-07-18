"""
uncapped_user_input_accumulator.py - Custom Slither detector.

Pattern (slice_ag - Plaza Core Protocol, HIGH):
    A function accepts a user-controlled numeric parameter and folds it
    into a state-variable accumulator via `stateVar += param` (or
    `stateVar = stateVar + param`) WITHOUT any upper-bound check on the
    parameter. A malicious caller submits the maximum uint256, causing
    subsequent additions to overflow (unchecked) or revert (checked 0.8+).
    Either way the protocol accumulator is poisoned.

Detection strategy (conservative):
    1. Iterate external/public non-view functions with at least one
       numeric-typed parameter (uint256, uint128, ...).
    2. For each function, find Binary IRs of type ADDITION whose LVALUE
       is a StateVariable AND whose RHS reads one of the function's
       numeric parameters.
    3. Check the function for ANY Binary IR of type
       LESS / LESS_EQUAL / GREATER / GREATER_EQUAL whose read set
       contains that same parameter - this indicates a bound check.
    4. If the parameter appears in the accumulator addition AND no
       bound-check Binary on that parameter exists → flag.

Confidence: MEDIUM. Over-approximates when the bound check is performed
inside an internal helper (not inlined). Under-approximates when the
accumulator uses `+ param * rate` (multiplication through a temp).
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
from slither.core.solidity_types import ElementaryType
from slither.core.variables.state_variable import StateVariable
from slither.slithir.operations import Binary, BinaryType
from slither.utils.output import Output


_COMPARISON_OPS = frozenset({
    BinaryType.LESS,
    BinaryType.LESS_EQUAL,
    BinaryType.GREATER,
    BinaryType.GREATER_EQUAL,
})

_SKIP_KEYWORDS = ("test", "mock", "setup", "fixture", "helper", "deploy", "script")
_VIEW_MUTABILITY = frozenset({"view", "pure"})


def _numeric_params(function):
    out = {}
    for p in function.parameters:
        tp = p.type
        if not isinstance(tp, ElementaryType):
            continue
        s = str(tp)
        if s.startswith("uint") or s.startswith("int"):
            out[p.name] = p
    return out


class UncappedUserInputAccumulator(AbstractDetector):
    """Detect `stateVar += userParam` with no bound-check on userParam."""

    ARGUMENT = "uncapped-user-input-accumulator"
    HELP = (
        "User-controlled numeric parameter is added into a state-variable "
        "accumulator without any upper-bound check - enables overflow/DoS"
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Uncapped User Input Added to State Accumulator"
    WIKI_DESCRIPTION = (
        "A function takes a user-controlled numeric parameter and adds it "
        "directly into a state variable accumulator (`totalX += param`). "
        "With no upper-bound check, a malicious caller can supply the "
        "maximum uint256 value; subsequent additions either overflow "
        "silently (unchecked) or revert permanently (0.8+ checked math) - "
        "in both cases the protocol accumulator is poisoned. Observed in "
        "Plaza Core Protocol `buyReserveAmount` (Zellic audit, HIGH)."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function placeBid(uint256 buyReserveAmount) external {
    totalSellReserveAmount += buyReserveAmount;   // BUG: no cap
    // ...
}
```
1. Attacker calls `placeBid(type(uint256).max - totalSellReserveAmount)`.
2. `totalSellReserveAmount` becomes ≈ `2**256 - 1`.
3. Every subsequent legitimate bid reverts in checked math, or wraps
   around in unchecked math - protocol accounting is broken."""
    WIKI_RECOMMENDATION = (
        "Add an explicit `require(param <= MAX_ALLOWED, ...)` before the "
        "accumulator write, or cap the parameter using a governance-set "
        "limit. Never accept unbounded user input into a monotonic "
        "accumulator."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            for function in contract.functions_and_modifiers_declared:
                if function.visibility not in ("external", "public"):
                    continue
                mut = function.pure or function.view
                if mut:
                    continue
                params = _numeric_params(function)
                if not params:
                    continue

                # Step 1: identify bound-checked params
                bound_checked: set = set()
                for node in function.nodes:
                    for ir in node.irs:
                        if isinstance(ir, Binary) and ir.type in _COMPARISON_OPS:
                            for r in ir.read:
                                nm = getattr(r, "name", None)
                                if nm in params:
                                    bound_checked.add(nm)

                # Step 2: find accumulator additions of unchecked params
                flagged_pairs = []
                for node in function.nodes:
                    for ir in node.irs:
                        if not isinstance(ir, Binary):
                            continue
                        if ir.type != BinaryType.ADDITION:
                            continue
                        lv = ir.lvalue
                        if not isinstance(lv, StateVariable):
                            continue
                        reads = list(ir.read)
                        # One operand must be the same state variable (the
                        # accumulator being incremented); the other must
                        # be one of our numeric params, unchecked.
                        has_sv_self = any(
                            isinstance(r, StateVariable) and r is lv
                            for r in reads
                        )
                        if not has_sv_self:
                            continue
                        for r in reads:
                            nm = getattr(r, "name", None)
                            if nm in params and nm not in bound_checked:
                                flagged_pairs.append((lv, params[nm]))
                                break

                for sv, p in flagged_pairs:
                    info: DETECTOR_INFO = [
                        function,
                        " adds user-controlled parameter `",
                        p.name,
                        "` into state-variable accumulator ",
                        sv,
                        " with no upper-bound check - supply max uint256 to "
                        "poison the accumulator (overflow / permanent revert).\n",
                    ]
                    results.append(self.generate_result(info))

        return results
