"""
twap_cardinality_not_increased.py - Custom Slither detector.

Pattern (Zellic slice_ab JuiceSwap TWAP-Cardinality-One-Manipulation, MEDIUM):
A contract integrates with a Uniswap V3 pool and reads TWAP via `observe(...)`
but never calls `increaseObservationCardinalityNext(...)`. Freshly-created
Uniswap V3 pools default to observation cardinality = 1, meaning the only
observation slot is overwritten every block. TWAP collapses to the *spot*
price at that block, which is trivially sandwich-able: an attacker moves the
spot price in the same block the oracle is queried, and TWAP returns the
manipulated value.

Detection strategy:
    Contract-level scan (simpler and more robust than per-function walks):
    1. Gather every HighLevelCall IR in the contract's functions.
    2. If any call's function `name == "observe"` (UniV3 pool TWAP query) is
       present AND no call's function name matches
       `increaseObservationCardinalityNext` is present → flag the contract.

Confidence: MEDIUM - a large integration may bump cardinality in an off-chain
deploy script rather than the contract itself. False-positive rate acceptable
for triage because the fix is always either (a) a new setter calling
`increaseObservationCardinalityNext` or (b) refusing newly-created pools.

@author auditooor wave10
@pattern slice_ab juiceswap-jan-26 TWAP-Cardinality-One-Manipulation
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
from slither.slithir.operations import HighLevelCall
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")


def _gather_hlc_names(contract):
    names = set()
    observe_fn = None
    for f in contract.functions_and_modifiers_declared:
        for node in f.nodes:
            for ir in node.irs:
                if isinstance(ir, HighLevelCall):
                    callee = ir.function
                    nm = getattr(callee, "name", None)
                    if nm:
                        names.add(nm)
                        if nm == "observe" and observe_fn is None:
                            observe_fn = f
    return names, observe_fn


class TwapCardinalityNotIncreased(AbstractDetector):
    """Detect Uniswap V3 observe() usage without increaseObservationCardinalityNext()."""

    ARGUMENT = "twap-cardinality-not-increased"
    HELP = (
        "Uniswap V3 pool observe() consumed but "
        "increaseObservationCardinalityNext() never called - TWAP defaults to "
        "cardinality=1 and collapses to spot price"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Uniswap V3 TWAP Cardinality Not Increased"
    WIKI_DESCRIPTION = (
        "Newly-created Uniswap V3 pools start with "
        "`slot0.observationCardinality = 1`. The sole observation slot is "
        "overwritten every block, so the `observe()` function returns tick "
        "cumulatives that cover a zero-second window - the oracle degrades to "
        "spot price. A contract that queries TWAP from a pool without first "
        "calling `pool.increaseObservationCardinalityNext(N)` to grow the "
        "buffer is trivially manipulatable: an attacker swaps the pool in the "
        "same block as the oracle read, skewing the cumulative tick exactly "
        "where the lender or AMM integration reads it. JuiceSwap (Zellic Jan "
        "2026) shipped with this gap."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function setupPool(address a, address b, uint24 fee) external {
    pool = factory.createPool(a, b, fee);
    pool.initialize(sqrtP);
    // BUG: no pool.increaseObservationCardinalityNext(N)
}
function getTwap() external view returns (int56 tick) {
    (int56[] memory cums, ) = pool.observe(twoAgos);
    tick = cums[1] - cums[0];              // spot price, not TWAP
}
```
Attacker flash-swaps the pool, reads the oracle through the victim, then
unwinds - the victim priced the attacker's trade against the manipulated
'TWAP'."""
    WIKI_RECOMMENDATION = (
        "After creating or whitelisting a Uniswap V3 pool, immediately call "
        "`pool.increaseObservationCardinalityNext(N)` with N sized to the "
        "TWAP window (e.g. 500 for a 10-minute TWAP at 2-s blocks). Reject "
        "pools whose current cardinality is < N."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            names, observe_fn = _gather_hlc_names(contract)
            if "observe" not in names:
                continue
            if "increaseObservationCardinalityNext" in names:
                continue
            if observe_fn is None:
                continue

            info: DETECTOR_INFO = [
                contract,
                " queries a Uniswap V3 pool via observe() in ",
                observe_fn,
                " but never calls increaseObservationCardinalityNext(). "
                "Default cardinality is 1 - TWAP degrades to spot price and "
                "can be manipulated in a single block.\n",
            ]
            results.append(self.generate_result(info))

        return results
