"""
gross_vs_net_validation_pre_fee.py - Custom Slither detector.

Pattern (Merkl M-01, slice_ad): A function validates an input amount against
a minimum BEFORE deducting a fee, then performs the business logic on the
post-fee net value. A user submitting exactly the minimum slips below the
threshold once the fee is subtracted, so the effective deposit/transfer
violates the stated invariant.

Detection strategy:
    1. For each function declared on a non-vendored contract, find a top-of-
       function `require(p >= X)` (or `p > X`) where `p` is one of the
       function's input parameters.
    2. Walk subsequent nodes for an Assignment of the form
       `local = p - other` (Binary SUBTRACTION whose left operand is the
       same parameter `p`).
    3. Check whether the resulting local variable (`net`) is later used in
       a state write or external transfer. If so, flag.

@author auditooor wave9
@pattern slice_ad Merkl M-01
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
from slither.core.declarations import SolidityFunction
from slither.core.variables.local_variable import LocalVariable
from slither.slithir.operations import (
    Binary,
    BinaryType,
    SolidityCall,
    Assignment,
)
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_REQUIRE_FUNCS = (
    SolidityFunction("require(bool)"),
    SolidityFunction("require(bool,string)"),
    SolidityFunction("require(bool,error)"),
)

_GE_TYPES = frozenset({
    BinaryType.GREATER_EQUAL,
    BinaryType.GREATER,
})


def _find_require_min_check(function):
    """Return the set of LocalVariable parameters that appear on the LHS of
    a top-level `require(p >= X)` / `require(p > X)` call."""
    params = set(function.parameters)
    bound_params: set = set()

    # Track which Binary IRs produce a "param >= ..." boolean and feed it
    # to a require call.
    cmp_results: dict = {}  # tmp var → param

    for node in function.nodes:
        for ir in node.irs:
            if isinstance(ir, Binary) and ir.type in _GE_TYPES:
                left = ir.variable_left
                if left in params:
                    cmp_results[ir.lvalue] = left
            elif isinstance(ir, SolidityCall) and ir.function in _REQUIRE_FUNCS:
                if not ir.arguments:
                    continue
                cond_var = ir.arguments[0]
                if cond_var in cmp_results:
                    bound_params.add(cmp_results[cond_var])
    return bound_params


def _find_subtraction_locals(function, params):
    """Return a set of LocalVariable `net`s assigned from `p - other` for
    some `p` in `params`."""
    nets: set = set()
    sub_results: dict = {}  # tmp var → param

    for node in function.nodes:
        for ir in node.irs:
            if isinstance(ir, Binary) and ir.type == BinaryType.SUBTRACTION:
                if ir.variable_left in params:
                    sub_results[ir.lvalue] = ir.variable_left
            elif isinstance(ir, Assignment):
                if ir.rvalue in sub_results and isinstance(ir.lvalue, LocalVariable):
                    nets.add(ir.lvalue)
    return nets


def _local_used_in_state_write(function, locals_set):
    """True if any local in `locals_set` is read while a state variable is
    being written in the same node."""
    if not locals_set:
        return False
    for node in function.nodes:
        if not node.state_variables_written:
            continue
        if any(lv in node.local_variables_read for lv in locals_set):
            return True
    return False


class GrossVsNetValidationPreFee(AbstractDetector):
    """Detect functions that validate gross input against a minimum but then
    spend net (post-fee) on the business path."""

    ARGUMENT = "gross-vs-net-validation-pre-fee"
    HELP = (
        "require(amount >= min) is checked on the gross amount but the "
        "function later spends `amount - fee` - net can fall below the min"
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Gross-vs-Net Threshold Check Before Fee Deduction"
    WIKI_DESCRIPTION = (
        "A function validates an input amount against a minimum threshold "
        "(`require(amount >= minDeposit)`) BEFORE deducting a protocol fee, "
        "then performs the business logic on the post-fee `net = amount - "
        "fee`. A user who submits exactly `minDeposit` slips below the "
        "threshold after the fee is taken - the effective deposit / "
        "transfer / mint violates the stated invariant. This is the classic "
        "'checked the outside, spent the inside' bug."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function deposit(uint256 amount) external {
    require(amount >= minDeposit, "too small"); // BUG: gross check
    uint256 fee = (amount * feeBps) / 10000;
    uint256 net = amount - fee;
    userBal[msg.sender] += net;                  // spends net
}
```
1. minDeposit = 100, feeBps = 500 (5%).
2. Alice sends 100. Require passes.
3. fee = 5, net = 95. Alice is credited 95, BELOW the stated minimum.
4. Anyone can spam tiny effective deposits and bypass the floor."""
    WIKI_RECOMMENDATION = (
        "Compute the net value first and validate it against the minimum: "
        "`uint256 net = amount - fee; require(net >= minDeposit, \"net too "
        "small\");`."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            for function in contract.functions_declared:
                if function.is_constructor:
                    continue

                bound_params = _find_require_min_check(function)
                if not bound_params:
                    continue

                nets = _find_subtraction_locals(function, bound_params)
                if not nets:
                    continue

                if not _local_used_in_state_write(function, nets):
                    continue

                # Pick a representative param for the report.
                param = sorted(bound_params, key=lambda p: p.name or "")[0]
                info: DETECTOR_INFO = [
                    function,
                    " in ",
                    contract,
                    " validates ",
                    param,
                    " against a minimum BEFORE deducting a fee, then spends "
                    "the post-fee net on the business path - net can fall "
                    "below the stated minimum.\n",
                ]
                results.append(self.generate_result(info))

        return results
