"""
partial_fill_exact_out_router_validation_missing.py - Custom Slither detector.

Pattern (Ekubo M-04, slice_ad): a swap router accepts both an
"exact-out" amount and an `allowPartial` flag, but never requires that
the resulting `actualOut` matches the requested `amountOut` when
partial filling is disabled. A user that asked for exactly 100 tokens
can therefore receive 50 - silently - even with `allowPartial=false`.

Detection strategy:
    1. For every function declared on a non-vendored contract, check
       the parameter list for ONE param matching
       `(?i)exactOut|amountOutExact|requestedOut|targetOut|amountOut`
       AND ANOTHER param matching `(?i)partialFill|allowPartial`.
    2. Walk the function body. If we cannot find a require/assert that
       compares any local variable against the exact-out parameter,
       flag the function.

@author auditooor wave9
@pattern slice_ad Ekubo M-04
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
from slither.slithir.operations import Binary, BinaryType, SolidityCall
from slither.core.declarations import SolidityFunction
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_EXACT_OUT_RE = re.compile(
    r"(exactout|amountoutexact|requestedout|targetout|amountout)$",
    re.IGNORECASE,
)
_PARTIAL_RE = re.compile(r"(partialfill|allowpartial)", re.IGNORECASE)

_REQUIRE_FNS = frozenset({
    "require(bool)",
    "require(bool,string)",
    "assert(bool)",
})


def _find_param(function, regex):
    for p in function.parameters:
        nm = (getattr(p, "name", "") or "")
        if regex.search(nm):
            return p
    return None


def _function_has_require_referencing(function, target_param) -> bool:
    """
    Return True if some require/assert in `function` references
    `target_param` directly (read inside the same node as the require).
    """
    for node in function.nodes:
        if not node.contains_require_or_assert():
            continue
        # node.local_variables_read is set; check if our param is in it.
        if target_param in (node.local_variables_read or []):
            return True
        # Also walk binaries for direct reference.
        for ir in node.irs:
            if isinstance(ir, Binary) and ir.type in (
                BinaryType.EQUAL,
                BinaryType.GREATER_EQUAL,
                BinaryType.LESS_EQUAL,
            ):
                left = getattr(ir, "variable_left", None)
                right = getattr(ir, "variable_right", None)
                if left is target_param or right is target_param:
                    return True
    return False


class PartialFillExactOutRouterValidationMissing(AbstractDetector):
    """Exact-out router with allowPartial flag never validates actualOut."""

    ARGUMENT = "partial-fill-exact-out-router-validation-missing"
    HELP = (
        "Exact-out swap router with allowPartial flag never asserts that the "
        "actual output matches the requested amount when partial fill is off"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Exact-Out Router Missing Partial-Fill Validation"
    WIKI_DESCRIPTION = (
        "A swap router takes both an `exactOut` / `amountOut` requested "
        "amount and an `allowPartial` flag, but the body never enforces that "
        "the actual output matches the requested amount when "
        "`allowPartial == false`. A user that asks for exactly N tokens can "
        "silently receive less than N. Confirmed in Ekubo M-04."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function swapExactOut(uint256 amountOut, uint256 maxIn, bool allowPartial)
    external returns (uint256 actualOut, uint256 actualIn)
{
    actualOut = _executeSwap(amountOut, maxIn);
    actualIn  = _getInputUsed();
    // BUG: no check that actualOut == amountOut when !allowPartial
    return (actualOut, actualIn);
}
```
A user signs a meta-tx for `amountOut = 100, allowPartial = false`,
expecting an all-or-nothing fill. Liquidity is thin; the swap returns
50. The router silently accepts the partial fill and the user is short
50 tokens with no recourse."""
    WIKI_RECOMMENDATION = (
        "When `allowPartial` is false, `require(actualOut == amountOut, ...)` "
        "before returning. Better yet, branch the entire code path on the "
        "flag so partial-fill behaviour is a separate function."
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

                exact_out_param = _find_param(function, _EXACT_OUT_RE)
                partial_param = _find_param(function, _PARTIAL_RE)
                if exact_out_param is None or partial_param is None:
                    continue

                if _function_has_require_referencing(function, exact_out_param):
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " accepts an exact-out amount and an allowPartial flag "
                    "but never asserts the actual output equals the requested "
                    "amount when partial fill is disabled - users can be "
                    "silently short-filled.\n",
                ]
                results.append(self.generate_result(info))

        return results
