"""
supply_ignores_max_deposit.py - Custom Slither detector.

Pattern (Silo Finance slice_ac MED): An ERC-4626 allocator / router / supply
wrapper calls `market.deposit(assets, receiver)` on a downstream vault without
first consulting `market.maxDeposit(receiver)`. When the downstream vault is
full or paused for deposits, the call reverts or silently caps, breaking the
allocator's accounting.

Detection strategy:
    1. Walk every non-vendored, non-test function.
    2. Find a HighLevelCall whose solidity_signature matches
       `deposit(uint256,address)` (canonical ERC-4626 signature).
    3. Collect ALL HighLevelCall signatures in the same function and verify
       that NONE of them is `maxDeposit(address)`.
    4. If deposit() is called but maxDeposit() is never consulted - flag.

This is an over-approximation: we don't verify that `maxDeposit` is called on
the *same* target. A function that forwards to a curated list where every
market's cap is checked upstream is a false positive; acceptable at MEDIUM
confidence.

@author auditooor wave11
@pattern slice_ac Silo Finance - Supply-Ignores-MaxDeposit (M)
"""

import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract

from slither.core.declarations import Function
from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.slithir.operations import HighLevelCall
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_DEPOSIT_SIGS = frozenset({
    "deposit(uint256,address)",
    "mint(uint256,address)",
})
_MAX_SIGS = frozenset({
    "maxDeposit(address)",
    "maxMint(address)",
})


class SupplyIgnoresMaxDeposit(AbstractDetector):
    """Flag allocator/router functions that call vault.deposit without maxDeposit."""

    ARGUMENT = "supply-ignores-max-deposit"
    HELP = (
        "ERC-4626 allocator calls downstream vault.deposit() without first "
        "consulting maxDeposit() - reverts or silently caps when market is full"
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Supply Ignores maxDeposit"
    WIKI_DESCRIPTION = (
        "An ERC-4626 allocator or router forwards user funds into a downstream "
        "vault via `deposit(assets, receiver)` without querying "
        "`maxDeposit(receiver)` first. When the downstream vault is paused, "
        "capped, or full, `deposit` reverts (DoS) or silently caps (accounting "
        "drift). Reported in Silo Finance."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function supply(IERC4626 market, uint256 assets) external {
    // BUG: no maxDeposit check
    market.deposit(assets, address(this));
}
```
If `market` is at capacity, the deposit reverts and the allocator cannot route
funds into any other market in this tx - a single full market DoSes the whole
supply path."""
    WIKI_RECOMMENDATION = (
        "Call `uint256 cap = market.maxDeposit(receiver);` and cap `assets` to "
        "`cap` (or skip the market) before invoking `deposit`."
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

                deposit_nodes = []
                seen_max = False
                for node in function.nodes:
                    for ir in node.irs:
                        if not isinstance(ir, HighLevelCall):
                            continue
                        if not isinstance(ir.function, Function):
                            continue
                        sig = ir.function.solidity_signature
                        if sig in _DEPOSIT_SIGS:
                            deposit_nodes.append(node)
                        elif sig in _MAX_SIGS:
                            seen_max = True

                if deposit_nodes and not seen_max:
                    info: DETECTOR_INFO = [
                        function,
                        " calls vault.deposit without checking maxDeposit (",
                        deposit_nodes[0],
                        "). Reverts or caps silently when the downstream market is full.\n",
                    ]
                    results.append(self.generate_result(info))

        return results
