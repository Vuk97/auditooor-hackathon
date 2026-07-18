"""
slippage_calculated_at_execution_time.py - Custom Slither detector.

Pattern (Virtuals M-03/M-06/M-07, slice_ac): a swap function reads
reserves / balances from the pool in the same transaction that then
performs the swap, derives a "minOut" from those same reads, and passes
it to the swap. The slippage check is computed on the same block state
that the swap is about to mutate, so it is tautological - a sandwich
bot can still move the reserves before this tx executes and the bound
will silently follow.

Detection strategy:
    1. For every function declared on a non-vendored contract, walk the
       node IR list in order.
    2. Track whether we have seen a HighLevelCall to one of the "spot
       state" reads (`getReserves`, `reserve0`, `reserve1`, `balanceOf`).
    3. If we then see a HighLevelCall to a swap-style function whose
       arguments are NOT directly any of the function's own parameters
       matching `(?i)minOut|minAmount|amountOutMin`, flag the function.

@author auditooor wave9
@pattern slice_ac Virtuals M-03/M-06/M-07
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
from slither.core.declarations import Function
from slither.slithir.operations import HighLevelCall
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_SPOT_READ_NAMES = frozenset({
    "getReserves",
    "reserve0",
    "reserve1",
    "balanceOf",
})

_SWAP_PREFIXES = ("swap", "exchange", "addLiquidity", "_swap", "_exchange")

_MIN_OUT_RE = re.compile(r"min(out|amount|amountout)|amountoutmin", re.IGNORECASE)


def _ir_callee_name(ir: HighLevelCall) -> str:
    if isinstance(ir.function, Function):
        sig = ir.function.solidity_signature or ""
        return sig.split("(")[0]
    return getattr(ir, "function_name", None) or ""


def _is_spot_read(ir: HighLevelCall) -> bool:
    return _ir_callee_name(ir) in _SPOT_READ_NAMES


def _is_swap_call(ir: HighLevelCall) -> bool:
    name = _ir_callee_name(ir)
    if not name:
        return False
    for p in _SWAP_PREFIXES:
        if name == p or name.startswith(p):
            return True
    return False


def _function_has_min_param(function) -> bool:
    for p in function.parameters:
        nm = (getattr(p, "name", "") or "")
        if _MIN_OUT_RE.search(nm):
            return True
    return False


class SlippageCalculatedAtExecutionTime(AbstractDetector):
    """Swap function derives minOut from spot reserves read in the same tx."""

    ARGUMENT = "slippage-calculated-at-execution-time"
    HELP = (
        "Swap function derives minAmountOut from on-chain reserves read in "
        "the same transaction - slippage check is tautological"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Slippage Computed From Spot State Read In Same Tx"
    WIKI_DESCRIPTION = (
        "A swap function reads `getReserves` / `reserve0` / `balanceOf` from "
        "the pool and then immediately calls the pool's swap function, passing "
        "a `minOut` derived from those reads. Because the read happens in the "
        "same transaction as the swap, an attacker can manipulate the pool "
        "before this transaction executes - the spot read returns the "
        "manipulated value, the derived `minOut` matches it, and the slippage "
        "check passes trivially. The function never receives a real slippage "
        "bound from the user. Confirmed in Virtuals M-03/M-06/M-07."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function swap(uint256 amountIn) external returns (uint256) {
    (uint112 r0, uint112 r1) = pool.getReserves();
    uint256 minOut = (amountIn * r1 * 99) / (r0 * 100);
    return pool.swap(amountIn, minOut); // BUG: minOut tracks manipulation
}
```
1. Attacker sandwiches the user's tx: front-runs by skewing reserves.
2. Inside the user's tx, `getReserves()` returns the skewed values.
3. `minOut` is computed from the skewed values, so the swap's slippage
   check passes even though the user receives a manipulated amount."""
    WIKI_RECOMMENDATION = (
        "Take `minAmountOut` as a function parameter so the user (or their "
        "wallet) can compute and sign it off-chain with full context, or "
        "derive it from a TWAP/oracle that is not manipulable in a single "
        "block."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            for function in contract.functions_declared:
                if function.is_constructor or function.view or function.pure:
                    continue
                if _function_has_min_param(function):
                    continue

                spot_read_node = None
                swap_node = None
                for node in function.nodes:
                    for ir in node.irs:
                        if not isinstance(ir, HighLevelCall):
                            continue
                        if spot_read_node is None and _is_spot_read(ir):
                            spot_read_node = node
                            continue
                        if spot_read_node is not None and _is_swap_call(ir):
                            swap_node = node
                            break
                    if swap_node is not None:
                        break

                if swap_node is None:
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " reads pool spot state at ",
                    spot_read_node,
                    " and uses it to derive the slippage bound passed to the "
                    "swap call at ",
                    swap_node,
                    " - the bound tracks any pre-trade manipulation, so the "
                    "slippage check is tautological. Take minAmountOut as a "
                    "user-supplied parameter instead.\n",
                ]
                results.append(self.generate_result(info))

        return results
