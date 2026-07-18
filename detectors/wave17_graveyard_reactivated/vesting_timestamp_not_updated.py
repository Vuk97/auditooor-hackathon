"""
vesting_timestamp_not_updated.py - Custom Slither detector.

Pattern (Zellic slice_ac - Apyx Stablecoin VestingDrainLoop, MEDIUM):
    `transferVestedYield()` computes the releasable amount using
        vested = remaining * (block.timestamp - lastDepositTimestamp) / period;
    reduces `vestingAmount` by `vested`, but NEVER updates
    `lastDepositTimestamp`. A caller can invoke the function repeatedly in
    the same block-slot or across blocks: each call extracts a fraction of
    the ever-shrinking remaining balance using the SAME large elapsed
    period, converging to full drain within a polynomial number of calls.

The general class is: any withdrawal / release function that reads a
"last-update" timestamp state var in the payout formula, writes the amount
state var, but does NOT also write the timestamp state var.

Detection strategy:
    1. Walk every non-view function.
    2. Collect the set of StateVariables the function reads that
       (a) have a name hinting at a timestamp (last*, lastUpdate,
           lastDeposit, lastAccrual, checkpoint, etc.)
       (b) and are read in a node that also reads `block.timestamp`.
    3. Require the function to WRITE at least one state variable with an
       "amount"-like name (amount, balance, vesting, remaining, debt).
    4. Require the function NOT to write any of the timestamp state vars
       identified in step 2.
    5. Flag.

@author auditooor wave11
@pattern slice_ac Apyx VestingDrainLoop
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
from slither.core.variables.state_variable import StateVariable
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_TIMESTAMP_VAR_HINTS = (
    "lastupdate",
    "lastdeposit",
    "lastaccrual",
    "lastclaim",
    "lastrelease",
    "lastcheckpoint",
    "lasttimestamp",
    "lastdripped",
    "vestingstart",
    "releaseupdate",
    "updatedat",
    "checkpoint",
)

_AMOUNT_VAR_HINTS = (
    "amount",
    "balance",
    "vesting",
    "remaining",
    "debt",
    "owed",
    "locked",
    "pending",
    "reserve",
)

_TIMESTAMP_NAMES = frozenset({"block.timestamp", "now"})


def _name_has_hint(name, hints):
    if not name:
        return False
    nm = name.lower()
    return any(h in nm for h in hints)


def _timestamp_state_vars_used_in_time_arith(function):
    """
    Return set of StateVariables whose name matches _TIMESTAMP_VAR_HINTS
    AND are read in the same node where block.timestamp is also read.
    """
    result = set()
    for node in function.nodes:
        reads_ts = any(
            sv.name in _TIMESTAMP_NAMES
            for sv in node.solidity_variables_read
        )
        if not reads_ts:
            continue
        for sv in node.state_variables_read:
            if isinstance(sv, StateVariable) and _name_has_hint(sv.name, _TIMESTAMP_VAR_HINTS):
                result.add(sv)
    return result


class VestingTimestampNotUpdated(AbstractDetector):
    """Detect withdrawal/release fns that use a last-* timestamp but never refresh it."""

    ARGUMENT = "vesting-timestamp-not-updated"
    HELP = (
        "Release/withdraw function reads lastUpdate timestamp in payout "
        "formula but never writes it back - repeated drain"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Vesting / Release Timestamp Not Updated After Withdraw"
    WIKI_DESCRIPTION = (
        "Time-based payout functions that compute the releasable amount as "
        "`remaining * (now - lastUpdate) / period` must update `lastUpdate` "
        "on every successful withdrawal, otherwise the same elapsed interval "
        "is multiplied into the calculation across many calls. The caller "
        "can drain the remaining balance with a polynomial number of "
        "repeated withdrawals. Observed in Apyx Stablecoin "
        "`transferVestedYield`."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
uint256 public vestingAmount;
uint256 public lastDepositTimestamp;
uint256 public constant VEST_PERIOD = 30 days;

function transferVestedYield() external {
    uint256 elapsed = block.timestamp - lastDepositTimestamp;
    uint256 vested = vestingAmount * elapsed / VEST_PERIOD;
    vestingAmount -= vested;            // BUG: lastDepositTimestamp never updated
    _payOut(vested);
}
```
1. elapsed = 10 days → vests 1/3 of remaining, remaining drops to 2/3·X.
2. Repeat → 2/3·X * 10/30 = 2/9·X vests, remaining drops to 4/9·X.
3. Polynomial calls converge to zero - full drain before 30 days expire."""
    WIKI_RECOMMENDATION = (
        "Write `lastDepositTimestamp = block.timestamp` (or the appropriate "
        "checkpoint variable) in the same code path that reduces the "
        "remaining balance. Consider a monotonic-released accumulator "
        "instead of a decaying balance for vesting math."
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
                if function.view or function.pure:
                    continue

                ts_vars = _timestamp_state_vars_used_in_time_arith(function)
                if not ts_vars:
                    continue

                # Must write some amount-like state var (otherwise it's a
                # read-only getter).
                writes_amount = False
                for sv in function.state_variables_written:
                    if isinstance(sv, StateVariable) and _name_has_hint(sv.name, _AMOUNT_VAR_HINTS):
                        writes_amount = True
                        break
                if not writes_amount:
                    continue

                # Must NOT write any of the timestamp vars we identified.
                written = set(function.state_variables_written)
                if any(ts in written for ts in ts_vars):
                    continue

                ts_var = next(iter(ts_vars))
                info: DETECTOR_INFO = [
                    function,
                    " computes a payout using ",
                    ts_var,
                    " in the time-elapsed arithmetic but never writes it "
                    "back - repeated calls re-use the same elapsed interval "
                    "and drain the remaining balance.\n",
                ]
                results.append(self.generate_result(info))

        return results
