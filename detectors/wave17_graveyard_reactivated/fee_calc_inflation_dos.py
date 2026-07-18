"""
fee_calc_inflation_dos.py - Custom Slither detector.

Pattern: a fee calculation function uses a fee-bps state variable in a
multiplication then divides by a small constant (10, 100, or 1000) instead
of the standard 10000 basis-points divisor. At modest feeBps values this
inflates the computed fee far beyond totalAssets, causing any
`require(fee <= balance)` or `_subtractFee(fee)` call to revert, DoSing
the vault.

Source: reference/corpus_mined/slice_ad.md - FeeCalcDOSInflation (Concrete)

Dedup check: no Slither builtin covers fee divisor correctness.
    slither --list-detectors | grep -iE "fee|bps|divisor" → 0 builtins match.

Detection strategy:
    1. Find functions with a Binary(MULTIPLICATION) whose operands include a
       StateVariable whose name contains a fee hint ("fee", "bps", "basis",
       "rate").
    2. In the same function, find a Binary(DIVISION) where the divisor is a
       Constant with a value in {10, 100, 1000} - the sub-standard divisors.
       (10000 is the canonical bps divisor; anything smaller causes inflation.)
    3. If both conditions hold → flag.

False-positive risk: percentage-based (non-bps) fee systems intentionally
divide by 100. Confidence is LOW by design.

Key IR insight (from fixture inspection):
    `assets * feeBps / 100` compiles to:
        Binary TMP_4 = assets * feeBps   (variable_right = StateVariable "feeBps")
        Binary TMP_5 = TMP_4 / 100       (variable_right = Constant(100))

@author auditooor wave6
@pattern FeeCalcDOSInflation - corpus slice_ad
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
from slither.slithir.operations import Binary, BinaryType
from slither.slithir.variables import Constant
from slither.core.variables.state_variable import StateVariable
from slither.utils.output import Output

SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

# Substrings that indicate a fee-rate state variable
_FEE_VAR_HINTS = ("fee", "bps", "basis", "rate", "toll", "levy")

# Divisor constants that are too small for standard basis points math.
# 10000 is the canonical bps base; using 10/100/1000 inflates the result.
_BAD_DIVISORS = frozenset({10, 100, 1000})


def _is_fee_sv(var) -> bool:
    """True if var is a StateVariable with a fee-hint name."""
    if not isinstance(var, StateVariable):
        return False
    name = (var.name or "").lower()
    return any(h in name for h in _FEE_VAR_HINTS)


def _function_mul_fee_sv(function):
    """
    Return the first fee-named StateVariable found as an operand in any
    Binary(MULTIPLICATION) in the function, or None.
    """
    for node in function.nodes:
        for ir in node.irs:
            if not (isinstance(ir, Binary) and ir.type == BinaryType.MULTIPLICATION):
                continue
            for v in ir.read:
                if _is_fee_sv(v):
                    return v
    return None


def _function_divides_by_small_constant(function):
    """
    Return the small Constant divisor (value in _BAD_DIVISORS) found in any
    Binary(DIVISION) in the function, or None if not present.
    """
    for node in function.nodes:
        for ir in node.irs:
            if not (isinstance(ir, Binary) and ir.type == BinaryType.DIVISION):
                continue
            right = ir.variable_right
            if isinstance(right, Constant) and int(right.value) in _BAD_DIVISORS:
                return right
    return None


class FeeCalcInflationDOS(AbstractDetector):
    """Detect fee calculations with a sub-standard BPS divisor that inflates the fee, causing DoS."""

    ARGUMENT = "fee-calc-inflation-dos"
    HELP = (
        "Fee multiplied by feeBps then divided by 100/1000 instead of 10000 - "
        "inflated fee > totalAssets causes DoS"
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW  # FP risk: percentage-based systems use /100

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Fee Calculation Inflation DoS"
    WIKI_DESCRIPTION = (
        "A fee calculation function multiplies an asset amount by a feeBps state variable "
        "then divides by a small constant (10, 100, or 1000) instead of the standard "
        "basis-points divisor of 10000. When feeBps is set to any double-digit value "
        "(e.g. 100 for 1%), the computed fee becomes equal to or greater than the full "
        "asset amount. Any downstream check such as require(fee <= balance) or a fee "
        "subtraction will revert on every call, permanently DoSing the vault."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
uint256 public feeBps = 100; // intended: 1% in basis points

function _calculateFee(uint256 assets) internal view returns (uint256) {
    return assets * feeBps / 100; // BUG: should be / 10000
}

function deposit(uint256 assets) external {
    uint256 fee = _calculateFee(assets);
    require(fee <= totalAssets, "insufficient"); // always reverts
    totalAssets += assets - fee;
}
```
When feeBps = 100 (1%), `_calculateFee` returns `assets * 100 / 100 = assets`.
Every `deposit` call reverts at the require, permanently DoSing the vault."""
    WIKI_RECOMMENDATION = (
        "Use 10000 as the basis-points divisor: `fee = assets * feeBps / 10000`. "
        "Add a constant `uint256 public constant MAX_FEE_BPS = 10000` to document "
        "the intended scale, and enforce `feeBps <= MAX_FEE_BPS` in the setter."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if any(k in contract.name.lower() for k in SKIP_KEYWORDS):
                continue
            if is_vendored_or_test_contract(contract):
                continue

            for function in contract.functions_and_modifiers_declared:
                # Find a fee-named StateVariable used in a multiplication
                fee_sv = _function_mul_fee_sv(function)
                if fee_sv is None:
                    continue

                # Find a division by a small (sub-standard bps) constant
                bad_div = _function_divides_by_small_constant(function)
                if bad_div is None:
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " multiplies fee variable ",
                    fee_sv,
                    " then divides by ",
                    str(bad_div.value),
                    " (expected 10000 for basis-point math). "
                    "An inflated fee causes require(fee <= balance) to always revert, "
                    "DoSing the vault.\n",
                ]
                results.append(self.generate_result(info))

        return results
