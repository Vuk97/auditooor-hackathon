"""
hardcoded_sqrtpricelimit_univ3.py - Custom Slither detector.

Pattern (Lambo M-05, slice_ab): a Uniswap V3 swap call passes a literal
constant for `sqrtPriceLimitX96` (typically `0`, `MIN_SQRT_RATIO + 1`,
`MAX_SQRT_RATIO - 1`). The pool will then never bound its execution
price - every user receives the worst possible fill, MEV bots get a
free dinner.

Detection strategy:
    1. Walk every HighLevelCall to a function whose name is one of the
       known Uniswap V3 entrypoints
       (`exactInputSingle`, `exactOutputSingle`, `swap`).
    2. Locate the `sqrtPriceLimitX96` parameter on the callee by name
       (case-insensitive). If we cannot find it, fall back to "last
       uint160 parameter".
    3. Read the corresponding argument on the IR; if it is a `Constant`,
       flag the function.

@author auditooor wave9
@pattern slice_ab Lambo M-05
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
from slither.core.declarations import Function
from slither.slithir.operations import HighLevelCall
from slither.slithir.variables import Constant
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_V3_NAMES = frozenset({
    "exactInputSingle",
    "exactOutputSingle",
    "swap",
})


def _ir_callee_name(ir: HighLevelCall) -> str:
    if isinstance(ir.function, Function):
        sig = ir.function.solidity_signature or ""
        return sig.split("(")[0]
    return getattr(ir, "function_name", None) or ""


def _sqrt_param_index(ir: HighLevelCall) -> int:
    """
    Return the index of the sqrtPriceLimitX96 argument in ir.arguments.
    Try (1) by name on the callee Function, (2) fallback: last argument.
    """
    callee = ir.function
    if isinstance(callee, Function):
        for i, p in enumerate(callee.parameters):
            nm = (getattr(p, "name", "") or "").lower()
            if "sqrtpricelimit" in nm:
                return i
    args = getattr(ir, "arguments", None) or []
    return len(args) - 1 if args else -1


class HardcodedSqrtPriceLimitUniv3(AbstractDetector):
    """Uniswap V3 swap call passes a literal constant for sqrtPriceLimitX96."""

    ARGUMENT = "hardcoded-sqrtpricelimit-univ3"
    HELP = (
        "Uniswap V3 swap hardcodes sqrtPriceLimitX96 to a constant - the pool "
        "will never bound execution price (MEV-eligible)"
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Hardcoded sqrtPriceLimitX96 In Uniswap V3 Swap"
    WIKI_DESCRIPTION = (
        "A Uniswap V3 swap call (`exactInputSingle`, `exactOutputSingle`, "
        "`pool.swap`) passes a literal constant for the `sqrtPriceLimitX96` "
        "parameter - typically `0`, `MIN_SQRT_RATIO + 1`, or "
        "`MAX_SQRT_RATIO - 1`. The pool never bounds its execution price. "
        "Combined with a permissive `amountOutMin`, this leaves every user "
        "of the wrapper at the mercy of MEV bots. Confirmed in Lambo M-05."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
router.exactInputSingle(
    tokenIn, tokenOut, fee, msg.sender, amountIn, minOut,
    0  // BUG: no price limit
);
```
A searcher front-runs every call to the wrapper, pushes the pool to
the worst tolerable price, lets the user's swap consume the manipulated
liquidity, then back-runs to capture the spread."""
    WIKI_RECOMMENDATION = (
        "Take `sqrtPriceLimitX96` as a function parameter so the caller can "
        "supply a meaningful execution-price bound, or compute one from a "
        "TWAP."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            for function in contract.functions_declared:
                for node in function.nodes:
                    for ir in node.irs:
                        if not isinstance(ir, HighLevelCall):
                            continue
                        name = _ir_callee_name(ir)
                        if name not in _V3_NAMES:
                            continue
                        # Need a callee Function so we can find the sqrt param.
                        if not isinstance(ir.function, Function):
                            continue
                        idx = _sqrt_param_index(ir)
                        args = getattr(ir, "arguments", None) or []
                        if idx < 0 or idx >= len(args):
                            continue
                        arg = args[idx]
                        if not isinstance(arg, Constant):
                            continue

                        info: DETECTOR_INFO = [
                            function,
                            " calls a Uniswap V3 swap with a hardcoded "
                            "sqrtPriceLimitX96 constant at ",
                            node,
                            " - the pool will not bound execution price, "
                            "leaving the user fully exposed to MEV.\n",
                        ]
                        results.append(self.generate_result(info))
                        break
                    else:
                        continue
                    break

        return results
