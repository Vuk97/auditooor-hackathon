"""
governance_setter_revert_on_current_gt_cap.py - Custom Slither detector.

Pattern (Megapot M-03, slice_ad): A governance setter for a cap/limit/max
parameter rejects new values that are below the live accounting state
(`totalDeposits`, `totalSupply`, `totalLocked`, ...). Once the live state
grows past the intended cap, governance can NEVER lower the cap again, so
LP-limiting is permanently disabled. The classic "lock governance to a value
that grew past bounds" footgun.

Detection strategy:
    1. Find functions named `set...(cap|limit|max|ceiling|threshold)...`.
    2. The function must take at least one numeric parameter `newCap`.
    3. The function must contain a `require(newCap >= <state var>)` where
       `<state var>` is mutable (not constant/immutable) AND is written by
       at least one OTHER function in the contract - i.e. it's a live
       accounting variable, not just the cap itself.
    4. Skip when the state var on the RHS is the cap variable being set
       (that would be a "monotonic cap" pattern, which is fine).

@author auditooor wave9
@pattern slice_ad Megapot M-03
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
from slither.core.declarations import SolidityFunction
from slither.core.variables.local_variable import LocalVariable
from slither.core.variables.state_variable import StateVariable
from slither.slithir.operations import Binary, BinaryType, SolidityCall
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")
_SETTER_RE = re.compile(
    r"set.*(cap|limit|max|ceiling|threshold)", re.IGNORECASE
)
_REQUIRE_FNS = {
    SolidityFunction("require(bool,string)"),
    SolidityFunction("require(bool)"),
    SolidityFunction("require(bool,error)"),
}


def _function_writes_var(function, sv) -> bool:
    return sv in (function.state_variables_written or [])


class GovernanceSetterRevertOnCurrentGtCap(AbstractDetector):
    """Cap setter rejects values below a live accounting state variable -
    cap can never be lowered once the live state grows past it."""

    ARGUMENT = "governance-setter-revert-on-current-gt-cap"
    HELP = (
        "set<Cap> reverts if newCap < liveAccounting; once live > intended "
        "cap, governance can never lower the cap again"
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Cap Setter Locked By Live Accounting State"
    WIKI_DESCRIPTION = (
        "A governance setter that enforces `require(newCap >= currentValue)` "
        "where `currentValue` is the live total of LP deposits / supply / "
        "etc. permanently locks the cap once accounting grows past the "
        "intended bound. Governance can no longer protect the protocol with "
        "a smaller cap. Megapot M-03 is the canonical example."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
uint256 public totalDeposits;
uint256 public cap;
function setCap(uint256 c) external onlyOwner {
    require(c >= totalDeposits, "below current"); // BUG
    cap = c;
}
```
LPs deposit past the intended cap during a frenzy. Governance now cannot
lower the cap back to the intended limit because the require always fails."""
    WIKI_RECOMMENDATION = (
        "Remove the lower-bound check on cap setters. Existing depositors "
        "should be grandfathered in; gate NEW deposits on `cap` instead of "
        "preventing governance from changing it."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            # Pre-compute which state vars are written by which non-setter
            # function (so we can identify "live accounting" variables).
            setter_fns = []
            for f in contract.functions_and_modifiers_declared:
                if not f.name:
                    continue
                if _SETTER_RE.search(f.name):
                    setter_fns.append(f)
            if not setter_fns:
                continue

            for setter in setter_fns:
                params = list(setter.parameters or [])
                if not params:
                    continue
                param_set = set(params)
                # Walk for require(... >= state_var) where left ~= a param
                # and state_var is mutable + written by some OTHER function.
                for node in setter.nodes:
                    if not node.contains_require_or_assert():
                        continue
                    # We want a Binary of type GREATER_EQUAL whose left is a
                    # param and right is a StateVariable, fed into require.
                    geq_irs = [
                        ir for ir in node.irs
                        if isinstance(ir, Binary)
                        and ir.type == BinaryType.GREATER_EQUAL
                    ]
                    require_irs = [
                        ir for ir in node.irs
                        if isinstance(ir, SolidityCall)
                        and ir.function in _REQUIRE_FNS
                    ]
                    if not geq_irs or not require_irs:
                        continue
                    for binop in geq_irs:
                        left = binop.variable_left
                        right = binop.variable_right
                        if not (
                            isinstance(left, LocalVariable) and left in param_set
                        ):
                            continue
                        if not isinstance(right, StateVariable):
                            continue
                        # Skip constant / immutable state vars.
                        if getattr(right, "is_constant", False):
                            continue
                        if getattr(right, "is_immutable", False):
                            continue
                        # Right must be written by at least one OTHER
                        # function (i.e. live accounting), not just the
                        # setter itself.
                        live_writers = [
                            g for g in contract.functions_and_modifiers_declared
                            if g is not setter
                            and not g.is_constructor
                            and right in (g.state_variables_written or [])
                        ]
                        if not live_writers:
                            continue
                        # The cap variable that the setter writes - make sure
                        # `right` is NOT that variable (monotonic cap is OK).
                        cap_writes = setter.state_variables_written or []
                        if right in cap_writes:
                            continue

                        info: DETECTOR_INFO = [
                            setter,
                            " requires the new value to be >= live "
                            "accounting state variable '",
                            right.name or "?",
                            "' at ",
                            node,
                            " - once '",
                            right.name or "?",
                            "' grows past the intended cap, governance "
                            "can never lower the cap again.\n",
                        ]
                        results.append(self.generate_result(info))
                        break  # one finding per setter

        return results
