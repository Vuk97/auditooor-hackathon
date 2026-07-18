"""
oracle_staleness_guard.py - Custom Slither detector.

Pattern: Contract calls a Chainlink-compatible oracle's latestRoundData(),
latestAnswer(), or latestRoundDataByName(string) but does NOT compare the
returned timestamp against block.timestamp in the same function.

Ported from:
    reference/corpus_mined/slice_ah.md - highest cross-protocol frequency
    class (Takara Lend, WOOFi, Yei, ether.fi all had this exact bug).

Exploitation context:
    Chainlink oracles can go stale during network congestion, gas price
    spikes, or a sequencer outage (L2). Without a freshness check, the
    price returned may be minutes or hours old. An attacker who observes
    the on-chain price diverging from the real-world price can:
      - Borrow against over-valued collateral (lending protocol)
      - Swap at a manipulated rate (DEX)
      - Liquidate healthy positions (perps)

Detection strategy:
    1. Walk c.functions_and_modifiers_declared.
    2. For each function, inspect f.high_level_calls (list of
       (Contract, HighLevelCall) tuples - confirmed by IR inspection).
    3. If any HC has .function.solidity_signature in the oracle set:
         {"latestRoundData()", "latestAnswer()", "latestRoundDataByName(string)"}
    4. Scan all nodes in the same function for any node where
       node.solidity_variables_read contains a variable with
       name == "block.timestamp". That read implies a staleness comparison
       exists (require(block.timestamp - updatedAt <= MAX_AGE, ...)).
    5. If oracle call present AND no block.timestamp read anywhere in the
       function → flag.

API notes:
    - f.high_level_calls is a list of (Contract, HighLevelCall) tuples.
      Access the IR via tuple[1]; the function signature via
      tuple[1].function.solidity_signature.
    - node.solidity_variables_read returns SolidityVariable /
      SolidityVariableComposed objects. block.timestamp has .name ==
      "block.timestamp" (canonical Slither spelling).
    - Slither may also represent the legacy `now` alias as "now" in
      older compiled contracts - we check both.
    - generate_result info list: Function + plain strings only;
      no raw IR objects or TemporaryVariable.

Confidence: MEDIUM - the detector catches the absence of any
block.timestamp read in a function that calls an oracle. A small number
of contracts may perform the staleness check in an internal helper called
from the flagged function (callee not inspected - acceptable approximation
for triage). Use HIGH severity because stale oracle prices directly enable
fund extraction.
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract

from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.utils.output import Output


# Chainlink-compatible oracle call signatures we care about.
_ORACLE_SIGS = frozenset({
    "latestRoundData()",
    "latestAnswer()",
    "latestRoundDataByName(string)",
})

# Solidity variable names that represent the current block time.
# "now" was the pre-0.7 alias; block.timestamp is the canonical form.
_TIMESTAMP_NAMES = frozenset({"block.timestamp", "now"})

SKIP_KEYWORDS = ("test", "mock", "setup", "fixture", "helper", "deploy", "script")


def _function_calls_oracle(function) -> bool:
    """
    Return True if the function makes a HighLevelCall to one of the
    known Chainlink-compatible oracle signatures.

    f.high_level_calls is a list of (Contract, HighLevelCall) tuples
    (confirmed by IR inspection - see workflow notes in module docstring).
    """
    for _contract, ir in function.high_level_calls:
        fn = getattr(ir, "function", None)
        if fn is None:
            continue
        sig = getattr(fn, "solidity_signature", None)
        if sig in _ORACLE_SIGS:
            return True
    return False


def _function_has_timestamp_check(function) -> bool:
    """
    Return True if ANY node in the function reads block.timestamp (or the
    legacy `now` alias). Presence of a block.timestamp read implies the
    developer performs a staleness comparison somewhere in the function.
    """
    for node in function.nodes:
        for sv in node.solidity_variables_read:
            if sv.name in _TIMESTAMP_NAMES:
                return True
    return False


class OracleStalenessGuard(AbstractDetector):
    """
    Detect Chainlink oracle calls without a block.timestamp staleness check.
    """

    ARGUMENT = "oracle-staleness-guard"
    HELP = (
        "Chainlink latestRoundData/latestAnswer called without comparing "
        "updatedAt to block.timestamp - stale price accepted silently"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Missing Chainlink Oracle Staleness Check"
    WIKI_DESCRIPTION = (
        "Functions that call Chainlink's latestRoundData(), latestAnswer(), or "
        "latestRoundDataByName() return a price together with an updatedAt "
        "timestamp. If the code consumes the price without verifying that "
        "block.timestamp - updatedAt is within an acceptable freshness window, "
        "the contract silently accepts stale prices. This is especially dangerous "
        "on L2s where the sequencer can be offline, causing the oracle feed to "
        "freeze while the underlying asset price keeps moving. The same bug class "
        "was confirmed in Takara Lend, WOOFi, Yei Finance, and ether.fi audits."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
IChainlinkAggregator oracle;

function getPrice() external view returns (uint256) {
    (, int256 price, , uint256 updatedAt, ) = oracle.latestRoundData();
    // updatedAt is retrieved but never compared to block.timestamp
    return uint256(price);
}
```
1. Chainlink sequencer goes offline on an L2 (e.g. Arbitrum sequencer down).
2. The oracle feed stops updating - updatedAt freezes at the last submission.
3. Real-world asset price drops 30%.
4. Attacker calls a lending protocol that uses getPrice() as collateral value.
5. Protocol still sees the stale (inflated) price → attacker borrows against
   over-valued collateral and withdraws, leaving the protocol with bad debt."""
    WIKI_RECOMMENDATION = (
        "After calling latestRoundData(), add a staleness check: "
        "`require(block.timestamp - updatedAt <= MAX_STALENESS, \"stale price\")`. "
        "Choose MAX_STALENESS based on the feed's heartbeat interval "
        "(e.g. 3600 s for a 1-hour heartbeat). For L2 deployments also check "
        "the Chainlink L2 Sequencer Uptime Feed before consuming any price."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if any(k in contract.name.lower() for k in SKIP_KEYWORDS):
                continue
            if is_vendored_or_test_contract(contract):
                continue

            for function in contract.functions_and_modifiers_declared:
                # Step 1: function must call a Chainlink-compatible oracle
                if not _function_calls_oracle(function):
                    continue

                # Step 2: function must NOT read block.timestamp anywhere
                if _function_has_timestamp_check(function):
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " calls a Chainlink oracle (latestRoundData/latestAnswer/"
                    "latestRoundDataByName) without comparing updatedAt to "
                    "block.timestamp. Stale prices are accepted silently - "
                    "add require(block.timestamp - updatedAt <= MAX_STALENESS).\n",
                ]
                results.append(self.generate_result(info))

        return results
