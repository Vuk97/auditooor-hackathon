"""
min_commission_fee_zero_bypass.py - Custom Slither detector.

Pattern (Panoptic H-03, slice_ad): A fee/commission formula caps the on-chain
computed value with a user-supplied maximum, e.g.

    fee = computedFee < userMaxFee ? computedFee : userMaxFee;
    // or
    fee = Math.min(computedFee, userMaxFee);

A trader can pass `userMaxFee = 0` and pay zero fee regardless of trade size.

Detection strategy:
    1. For each declared function, find local variables whose name matches
       /(fee|commission)/i.
    2. For each such variable, look at every Assignment IR that writes it.
       Flag the function if AT LEAST ONE assignment's right-hand side is a
       LocalVariable that is also a function parameter - i.e. the fee can be
       directly set to a user-controlled value via the min branch.
    3. Filter to functions where the fee variable is also assigned from a
       computed expression (TemporaryVariable / Binary result), so we only
       flag the "min(computed, user)" shape and not pure pass-throughs.

@author auditooor wave9
@pattern slice_ad Panoptic H-03
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
from slither.core.variables.local_variable import LocalVariable
from slither.slithir.operations import Assignment
from slither.slithir.variables import TemporaryVariable
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")
_FEE_RE = re.compile(r"(fee|commission)", re.IGNORECASE)


class MinCommissionFeeZeroBypass(AbstractDetector):
    """Flag a fee/commission computation that takes the min of an on-chain
    formula and a user-supplied maximum, allowing a user to pay zero by
    passing zero."""

    ARGUMENT = "min-commission-fee-zero-bypass"
    HELP = (
        "fee/commission computed as min(computedFee, userMaxFee) lets a "
        "trader pass userMaxFee=0 and pay zero fee"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Fee Capped By User-Supplied Maximum (min branch zeroes fee)"
    WIKI_DESCRIPTION = (
        "A fee/commission formula that takes the minimum of an on-chain "
        "computed value and a user-supplied maximum is a high-severity bug: "
        "the trader can pass `userMaxFee = 0` and pay zero fee on any trade "
        "size. This is the Panoptic H-03 pattern from slice_ad."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function trade(uint256 amount, uint256 userMaxFee) external returns (uint256 fee) {
    uint256 computedFee = (amount * 50) / 10000;
    fee = computedFee < userMaxFee ? computedFee : userMaxFee;
}
```
A user calls `trade(1e24, 0)` - the ternary picks the `userMaxFee` branch and
sets `fee = 0`, so the protocol collects nothing on a $1M trade."""
    WIKI_RECOMMENDATION = (
        "Never cap a protocol fee at a user-supplied value. Compute the fee "
        "from on-chain state alone, or use `max(computedFee, userMinFee)` if "
        "the intent is a floor (not a ceiling) on the trader's payment."
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
                params = {p for p in function.parameters or []}
                if not params:
                    continue

                # Track assignments to fee-named locals.
                fee_var_param_assigns: dict = {}     # var -> Node where param assigned
                fee_var_computed_assigns: dict = {}  # var -> Node where computed
                for node in function.nodes:
                    for ir in node.irs:
                        if not isinstance(ir, Assignment):
                            continue
                        lv = ir.lvalue
                        if not isinstance(lv, LocalVariable):
                            continue
                        if not _FEE_RE.search(lv.name or ""):
                            continue
                        rv = ir.rvalue
                        if isinstance(rv, LocalVariable) and rv in params:
                            fee_var_param_assigns.setdefault(lv, node)
                        elif isinstance(rv, TemporaryVariable):
                            fee_var_computed_assigns.setdefault(lv, node)
                        elif isinstance(rv, LocalVariable):
                            # Could be computedFee local - count as computed
                            # if its name does NOT match a parameter name.
                            fee_var_computed_assigns.setdefault(lv, node)

                # Flag any fee-named local that has BOTH a param assignment
                # and a computed assignment (the two ternary branches).
                for fee_var, param_node in fee_var_param_assigns.items():
                    if fee_var not in fee_var_computed_assigns:
                        continue
                    info: DETECTOR_INFO = [
                        function,
                        " caps fee/commission '",
                        fee_var.name or "?",
                        "' with a user-supplied parameter at ",
                        param_node,
                        " - a trader can pass 0 and skip the fee entirely.\n",
                    ]
                    results.append(self.generate_result(info))

        return results
