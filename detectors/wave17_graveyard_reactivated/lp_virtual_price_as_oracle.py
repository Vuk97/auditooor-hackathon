"""
lp_virtual_price_as_oracle.py - Custom Slither detector.

Pattern (W8-4 - Makina/Woofi/UwuLend ~$40M+): a function named or behaving as
a price oracle reads directly from `ICurvePool.get_virtual_price()` OR from
`IUniswapV2Pair.getReserves()` / `reserve0()` / `reserve1()` without a TWAP
wrapper, enabling flashloan price manipulation.

Detection strategy:
  1. Walk contract.functions_and_modifiers_declared.
  2. Filter functions whose name matches (?i).*(price|oracle|value|rate).*
  3. Inspect f.high_level_calls tuples; flag if any callee's
     solidity_signature is get_virtual_price(), getReserves(), reserve0(),
     or reserve1().
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
from slither.utils.output import Output


_ORACLE_NAME_RE = re.compile(r"(price|oracle|value|rate|latestAnswer)", re.IGNORECASE)

_DANGEROUS_SIGS = frozenset({
    "get_virtual_price()",
    "getReserves()",
    "reserve0()",
    "reserve1()",
})

SKIP_KEYWORDS = ("test", "mock", "setup", "fixture", "helper", "deploy", "script")


class LpVirtualPriceAsOracle(AbstractDetector):
    """
    Oracle-like function reads get_virtual_price / getReserves directly -
    manipulable via single-block flashloan.
    """

    ARGUMENT = "lp-virtual-price-as-oracle"
    HELP = (
        "Oracle function reads Curve get_virtual_price / Uniswap-V2 getReserves "
        "directly - flashloan-manipulable price source"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "LP Virtual Price Used as Oracle"
    WIKI_DESCRIPTION = (
        "A function whose name suggests it is a price oracle (getPrice, "
        "valueOf, latestAnswer, *Oracle*) reads the price directly from a "
        "Curve pool's `get_virtual_price()` or a Uniswap V2 pair's "
        "`getReserves()`. Both values are mutable within a single block by "
        "an attacker holding a flashloan: depositing imbalanced liquidity or "
        "swapping against the pool moves the spot value, and the oracle "
        "consumer accepts the manipulated number. This was the root cause of "
        "UwuLend ($20M, 2024), Woofi ($8.75M, 2024), Makina and many others."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
contract Oracle {
    ICurvePool public pool;
    function getPrice() external view returns (uint256) {
        return pool.get_virtual_price();
    }
}
```
Attacker flash-borrows a large amount of one pool asset, swaps it into the
pool (skewing reserves), then reads getPrice() - which now reports an
inflated virtual price. The attacker uses this price to borrow or mint against
manipulated collateral, then unwinds the swap and repays the flashloan with
the profit."""
    WIKI_RECOMMENDATION = (
        "Never read spot LP state as a price. Use a time-weighted average "
        "price (Uniswap V3 TWAP, Chainlink feed) or a push-based oracle "
        "updated by a trusted keeper with staleness bounds. For Curve pools, "
        "use the hardcoded `lp_price` view only when combined with Chainlink "
        "underlying prices - never alone."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if any(k in contract.name.lower() for k in SKIP_KEYWORDS):
                continue
            if is_vendored_or_test_contract(contract):
                continue

            for function in contract.functions_and_modifiers_declared:
                if not _ORACLE_NAME_RE.search(function.name or ""):
                    continue

                for _c, ir in function.high_level_calls:
                    callee = getattr(ir, "function", None)
                    if callee is None:
                        continue
                    sig = getattr(callee, "solidity_signature", None)
                    if sig in _DANGEROUS_SIGS:
                        info: DETECTOR_INFO = [
                            function,
                            f" reads `{sig}` directly as an oracle value at ",
                            ir.node,
                            " - spot LP state is flashloan-manipulable. "
                            "Use a TWAP or push-based feed instead.\n",
                        ]
                        results.append(self.generate_result(info))
                        break

        return results
