"""
pool_graduation_preseed_check_missing.py — Custom Slither detector.

Pattern (Zellic slice_ae GTE Launchpad, CRITICAL): a token launchpad / bonding
curve contract graduates to a Uniswap pair by calling `addLiquidity` /
`initializePool` / `initialize` on the external pair. Because the pair might
already be deployed with non-zero reserves (an attacker front-runs the
graduation and donates a skewed ratio), the launchpad MUST check
`getReserves() == (0, 0)` before adding liquidity. Missing this pre-seed check
lets attackers steal the graduation premium.

Detection strategy:
    1. Walk functions that make a HighLevelCall to a function named in
       {`addLiquidity`, `initializePool`, `initialize`}.
    2. In the same function, check whether there is a HighLevelCall to
       `getReserves()` BEFORE (lower node index) the addLiquidity call, AND
       a require/assert that reads local variables populated by the reserves
       call. Approximation: ANY getReserves HighLevelCall + ANY
       require/assert in the function that precedes addLiquidity counts.

@author auditooor wave8
@pattern slice_ae GTE Launchpad
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
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_ADDLIQ_NAMES = frozenset({"addliquidity", "initializepool", "initialize"})


def _first_add_liquidity_call(function):
    for idx, node in enumerate(function.nodes):
        for ir in node.irs:
            if not isinstance(ir, HighLevelCall):
                continue
            callee = ir.function
            if not isinstance(callee, Function):
                continue
            name = (callee.name or "").lower()
            if name in _ADDLIQ_NAMES:
                return idx, node, ir
    return None, None, None


def _has_reserves_check_before(function, addliq_idx: int) -> bool:
    """Look for a getReserves HighLevelCall AND a require/assert both before addliq_idx."""
    saw_reserves = False
    saw_require = False
    for idx in range(addliq_idx):
        node = function.nodes[idx]
        if node.contains_require_or_assert():
            saw_require = True
        for ir in node.irs:
            if isinstance(ir, HighLevelCall):
                callee = ir.function
                if isinstance(callee, Function):
                    if (callee.name or "").lower() == "getreserves":
                        saw_reserves = True
    return saw_reserves and saw_require


class PoolGraduationPreseedCheckMissing(AbstractDetector):
    """Detect launchpad graduation that calls addLiquidity without verifying empty reserves."""

    ARGUMENT = "pool-graduation-preseed-check-missing"
    HELP = (
        "Launchpad graduation calls addLiquidity/initializePool on a pair "
        "without first checking getReserves() == 0 — attacker can pre-seed"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Missing Pair Pre-seed Check on Graduation"
    WIKI_DESCRIPTION = (
        "Token launchpads that graduate to a Uniswap-style pair must verify that "
        "the pair has no existing reserves before calling `addLiquidity` / "
        "`initializePool`. An attacker can front-run the graduation and donate a "
        "skewed ratio of tokens, then arbitrage the mispriced liquidity the moment "
        "the launchpad adds its premium — stealing the launchpad's share of the "
        "graduation reserve. This is the GTE Launchpad CRITICAL class."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function graduate(uint256 a, uint256 b) external {
    pair.addLiquidity(a, b); // BUG: reserves may already be non-zero
}
```
1. Attacker creates / funds the Uniswap pair with a heavily skewed ratio.
2. Launchpad graduates and adds `(a, b)` at the intended 1:1 ratio.
3. The pair now holds attacker-favoured reserves; attacker swaps once and
   drains the graduation premium."""
    WIKI_RECOMMENDATION = (
        "Before calling addLiquidity: `(uint112 r0, uint112 r1, ) = pair.getReserves(); "
        "require(r0 == 0 && r1 == 0, \"preseeded\");` — or use a newly-deployed "
        "pair created inside the graduation function."
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
                idx, node, _ = _first_add_liquidity_call(function)
                if idx is None:
                    continue
                if _has_reserves_check_before(function, idx):
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " calls addLiquidity/initializePool at ",
                    node,
                    " without first verifying that getReserves() is zero. "
                    "An attacker can pre-seed the pair with a skewed ratio and "
                    "steal the graduation premium.\n",
                ]
                results.append(self.generate_result(info))

        return results
