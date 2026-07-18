"""
fee_uncapped_in_constructor.py — Custom Slither detector.

Pattern (Zellic slice_aa ASTRO-19, MEDIUM): a `setFee*()` function enforces
`require(fee <= MAX_FEE)`, but the constructor initialises the same fee
state variable with NO cap. The deployer can plant a fee above MAX_FEE at
deploy time, escaping the cap the setter advertises.

Detection strategy:
    1. Find a contract with a constructor that writes to a state variable
       whose name contains "fee" (case-insensitive).
    2. Find any function whose name starts with `setFee` that writes to the
       SAME state variable AND contains a require/assert node.
    3. Verify the constructor contains NO require/assert node that would
       plausibly bound the fee parameter.
    4. Flag the constructor.

@author auditooor wave8
@pattern slice_aa ASTRO-19
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
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")


def _fee_state_vars_written(function) -> set:
    out = set()
    for sv in function.state_variables_written:
        if sv is None:
            continue
        if "fee" in (getattr(sv, "name", "") or "").lower():
            out.add(sv)
    return out


def _has_require_or_assert(function) -> bool:
    for node in function.nodes:
        if node.contains_require_or_assert():
            return True
    return False


class FeeUncappedInConstructor(AbstractDetector):
    """Detect constructors that write a fee state var without the cap enforced by setFee*."""

    ARGUMENT = "fee-uncapped-in-constructor"
    HELP = (
        "Constructor sets a fee state variable with no cap check, while "
        "setFee*() enforces require(fee <= MAX) on the same variable"
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Fee Cap Bypass via Constructor"
    WIKI_DESCRIPTION = (
        "Fee-bearing contracts commonly expose a `setFee*()` admin function that "
        "enforces `require(newFee <= MAX_FEE)`. When the constructor initialises "
        "the same fee state variable without that cap, the deployer can plant a "
        "value above MAX_FEE on day zero, silently breaking the invariant the "
        "setter advertises to users and auditors."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
uint256 public fee;
uint256 public constant MAX_FEE = 500;

constructor(uint256 _fee) { fee = _fee; }            // BUG: no cap
function setFee(uint256 _fee) external onlyOwner {
    require(_fee <= MAX_FEE, "cap");
    fee = _fee;
}
```
Deployer passes `_fee = 10_000` at deploy time — the cap is silently bypassed."""
    WIKI_RECOMMENDATION = (
        "Mirror the setter's cap check inside the constructor: "
        "`require(_fee <= MAX_FEE, \"cap\");` before assigning."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            # 1. find constructor(s)
            constructors = [
                f for f in contract.functions_and_modifiers_declared
                if f.is_constructor
            ]
            if not constructors:
                continue

            for ctor in constructors:
                ctor_fee_vars = _fee_state_vars_written(ctor)
                if not ctor_fee_vars:
                    continue

                # 2. find setFee* function that writes same var and has require
                capped_setters = []
                for f in contract.functions_and_modifiers_declared:
                    if f.is_constructor:
                        continue
                    name = (f.name or "")
                    if not name.lower().startswith("setfee"):
                        continue
                    setter_vars = _fee_state_vars_written(f)
                    if not (setter_vars & ctor_fee_vars):
                        continue
                    if not _has_require_or_assert(f):
                        continue
                    capped_setters.append(f)

                if not capped_setters:
                    continue

                # 3. constructor must NOT have a require/assert
                if _has_require_or_assert(ctor):
                    continue

                shared = sorted(ctor_fee_vars & {
                    v for f in capped_setters for v in _fee_state_vars_written(f)
                }, key=lambda v: v.name)
                var_for_info = shared[0] if shared else next(iter(ctor_fee_vars))

                info: DETECTOR_INFO = [
                    ctor,
                    " writes the fee state variable ",
                    var_for_info,
                    " with NO cap check, while ",
                    capped_setters[0],
                    " enforces require(fee <= MAX) on the same variable. "
                    "Deployer can bypass the cap at construction time.\n",
                ]
                results.append(self.generate_result(info))

        return results
