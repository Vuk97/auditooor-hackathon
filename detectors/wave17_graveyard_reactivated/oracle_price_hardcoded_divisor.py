"""
oracle_price_hardcoded_divisor.py - Custom Slither detector.

Pattern (Zellic slice_ad - Blackhaven OracleDecimalMismatch):
    A contract calls a Chainlink-style oracle (latestAnswer/latestRoundData
    /getPrice) and divides or multiplies the returned integer by a HARDCODED
    10**N constant (e.g. 1e18) WITHOUT calling `.decimals()` on the feed.
    Chainlink ETH/USD feeds return 8 decimals, BTC/USD 8 decimals, some
    custom feeds 18. Hardcoding a single divisor produces ~1e10× NAV errors
    when the feed's real decimals differ.

Detection strategy:
    1. For every function, find HighLevelCalls whose solidity_signature
       matches a known oracle getter (latestAnswer/latestRoundData/getPrice/
       getAnswer).
    2. In the SAME function, look for any Binary DIVISION or MULTIPLICATION
       operation whose rvalue is a Constant with a value that looks like a
       decimal-scale literal (10**N for N in 6..27).
    3. Also require that NO HighLevelCall to `.decimals()` (the canonical
       `function decimals() returns (uint8)`) appears in the function.
    4. If oracle call + hardcoded 10**N constant + no .decimals() call →
       flag the function.

@author auditooor wave11
@pattern slice_ad Blackhaven OracleDecimalMismatch
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
from slither.slithir.operations import HighLevelCall, Binary, BinaryType
from slither.slithir.variables import Constant
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_ORACLE_SIGS = frozenset({
    "latestAnswer()",
    "latestRoundData()",
    "getPrice()",
    "getPrice(address)",
    "getAnswer(uint256)",
})

_DECIMALS_SIGS = frozenset({
    "decimals()",
})

# Exactly 10**N literals that feed scale normalization errors.
# 10**6 (USDC) through 10**27 (Aave ray).
_DECIMAL_SCALE_LITERALS = frozenset(
    10 ** n for n in range(6, 28)
)


def _function_calls_oracle(function) -> bool:
    for _c, ir in function.high_level_calls:
        fn = getattr(ir, "function", None)
        if fn is None:
            continue
        sig = getattr(fn, "solidity_signature", None)
        if sig in _ORACLE_SIGS:
            return True
    return False


def _function_calls_decimals(function) -> bool:
    for _c, ir in function.high_level_calls:
        fn = getattr(ir, "function", None)
        if fn is None:
            continue
        sig = getattr(fn, "solidity_signature", None)
        if sig in _DECIMALS_SIGS:
            return True
    return False


def _find_hardcoded_scale_div(function):
    """
    Return the first (node, constant_value) where a DIVISION or MULT Binary
    uses a Constant whose value is a 10**N literal. None if not found.
    """
    for node in function.nodes:
        for ir in node.irs:
            if not isinstance(ir, Binary):
                continue
            if ir.type not in (BinaryType.DIVISION, BinaryType.MULTIPLICATION):
                continue
            for operand in (ir.variable_left, ir.variable_right):
                if not isinstance(operand, Constant):
                    continue
                val = getattr(operand, "value", None)
                try:
                    v = int(val)
                except (TypeError, ValueError):
                    continue
                if v in _DECIMAL_SCALE_LITERALS:
                    return node, v
    return None


class OraclePriceHardcodedDivisor(AbstractDetector):
    """Detect oracle consumers using a hardcoded 10**N scale without .decimals()."""

    ARGUMENT = "oracle-price-hardcoded-divisor"
    HELP = (
        "Oracle price scaled by hardcoded 10**N literal (no .decimals() call) "
        "- cross-feed decimal mismatch produces ~1e10× NAV errors"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Oracle Price Scaled by Hardcoded 10**N"
    WIKI_DESCRIPTION = (
        "Contracts that consume Chainlink-style oracles must normalize the "
        "returned price by the feed's reported `decimals()` value. When a "
        "contract hardcodes division (or multiplication) by a single 10**N "
        "literal such as 1e18, any feed with a different decimal count produces "
        "orders-of-magnitude errors. Observed in Blackhaven BackingCalculator, "
        "where `getPrice()` results were divided by a hardcoded 1e18 even "
        "though deployed feeds returned 8 decimals."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function singleNAV() external view returns (uint256) {
    uint256 price = oracle.getPrice();          // 8-decimal feed
    return totalBacking * price / 1e18;         // HARDCODED - off by 1e10
}
```
1. Deploy with a 1e18-assumption in all math.
2. Operator switches `oracle` to a legitimate Chainlink 8-decimal feed.
3. NAV / FDV calculation under-reports the true backing by 10^10.
4. Bonds mint below floor, tokens redeem against wrong price, arbitrage drain."""
    WIKI_RECOMMENDATION = (
        "Call `oracle.decimals()` on initialization or at read time and "
        "normalize the returned price dynamically. Never hardcode a single "
        "10**N divisor when the feed address is mutable or protocol-agnostic."
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
                if not _function_calls_oracle(function):
                    continue
                if _function_calls_decimals(function):
                    continue

                hit = _find_hardcoded_scale_div(function)
                if hit is None:
                    continue
                node, scale_value = hit

                info: DETECTOR_INFO = [
                    function,
                    " consumes an oracle price and scales it by a hardcoded "
                    f"10**N literal ({scale_value}) at ",
                    node,
                    " without calling the feed's .decimals() - cross-decimal "
                    "feeds produce orders-of-magnitude errors.\n",
                ]
                results.append(self.generate_result(info))

        return results
