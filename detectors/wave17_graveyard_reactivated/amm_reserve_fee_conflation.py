"""
amm_reserve_fee_conflation.py - Custom Slither detector.

Pattern (GTE-launchpad H-03/H-04/H-05, slice_ac): a custom Uniswap-V2-
style pair tracks pending protocol fees in `accruedFee0` / `accruedFee1`
state variables but reads `reserve0` / `reserve1` directly in `swap` /
`mint` / `burn` math without first subtracting the accrued fee. The
result: LPs are paid against the fee-inclusive reserve (over-mint), or
the fee accounting is double-counted on a swap.

Detection strategy:
    1. Look at every contract that declares at least one
       reserve-named state variable AND at least one accrued-fee-named
       state variable.
    2. For each declared function on that contract, walk the IR and
       check whether ANY arithmetic Binary uses the reserve var without
       the matching accrued-fee var being read in the same function.
    3. Flag the function - the swap math is conflating reserve and fee.

@author auditooor wave9
@pattern slice_ac GTE-launchpad H-03/H-04/H-05
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
from slither.slithir.operations import Binary, BinaryType
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_RESERVE_RE = re.compile(r"^reserve(?:[01]|a|b)?$", re.IGNORECASE)
_FEE_RE = re.compile(r"(accruedfee|feeaccumul|protocolfee)", re.IGNORECASE)

_ARITH_TYPES = frozenset({
    BinaryType.ADDITION,
    BinaryType.SUBTRACTION,
    BinaryType.MULTIPLICATION,
    BinaryType.DIVISION,
})


def _is_reserve_var(v) -> bool:
    nm = (getattr(v, "name", "") or "")
    return bool(_RESERVE_RE.match(nm))


def _is_fee_var(v) -> bool:
    nm = (getattr(v, "name", "") or "")
    return bool(_FEE_RE.search(nm))


class AmmReserveFeeConflation(AbstractDetector):
    """Reserve var is used in swap math without first subtracting accruedFee."""

    ARGUMENT = "amm-reserve-fee-conflation"
    HELP = (
        "AMM swap/mint/burn math reads reserve0/reserve1 without first "
        "subtracting the accruedFee state - fee is conflated with reserve"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Reserve / Accrued-Fee Conflation In AMM Math"
    WIKI_DESCRIPTION = (
        "A custom Uniswap-V2-style pair tracks pending protocol fees in an "
        "`accruedFee0` / `accruedFee1` state variable but performs swap, "
        "mint, or burn math directly against `reserve0` / `reserve1` without "
        "first subtracting the accrued fee. LPs are then paid against a "
        "fee-inclusive reserve (over-mint) or fees are double-counted on a "
        "swap. Confirmed in GTE-launchpad H-03/H-04/H-05."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
uint256 public reserve0;
uint256 public accruedFee0;
function swap(uint256 amountIn) external returns (uint256) {
    return (amountIn * reserve1) / (reserve0 + amountIn); // BUG
}
```
The trader is quoted against `reserve0`, which still contains the
unclaimed protocol fee. Whoever later collects the fee finds the pool
under-collateralised; or, on a `mint`, an LP is issued shares against
liquidity that does not belong to them."""
    WIKI_RECOMMENDATION = (
        "Always compute an effective reserve as `reserveX - accruedFeeX` "
        "before passing it to swap / mint / burn math, or settle the accrued "
        "fee out of the reserve before reading it."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            reserve_vars = [s for s in contract.state_variables if _is_reserve_var(s)]
            fee_vars = [s for s in contract.state_variables if _is_fee_var(s)]
            if len(reserve_vars) < 2 or not fee_vars:
                continue

            reserve_names = {v.name for v in reserve_vars}
            fee_names = {v.name for v in fee_vars}

            for function in contract.functions_declared:
                if function.is_constructor or function.view or function.pure:
                    continue

                # Function must read at least one reserve var.
                read_state_names = {
                    (v.name or "")
                    for v in function.state_variables_read
                }
                if not (read_state_names & reserve_names):
                    continue

                # Skip if the function ALSO reads any accrued-fee var (likely
                # already nets it out) - keeps false positives low.
                if read_state_names & fee_names:
                    continue

                # Find a Binary op that uses the reserve var to anchor the report.
                anchor_node = None
                for node in function.nodes:
                    for ir in node.irs:
                        if not isinstance(ir, Binary):
                            continue
                        if ir.type not in _ARITH_TYPES:
                            continue
                        operands = (ir.variable_left, ir.variable_right)
                        if any(_is_reserve_var(op) for op in operands):
                            anchor_node = node
                            break
                    if anchor_node is not None:
                        break

                if anchor_node is None:
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " uses reserve state in arithmetic at ",
                    anchor_node,
                    " without subtracting the accruedFee state - pending "
                    "protocol fees are conflated with trader-owned reserves.\n",
                ]
                results.append(self.generate_result(info))

        return results
