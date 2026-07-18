"""
settable_past_deadline.py - Custom Slither detector.

Pattern (Phi H-04, TraitForge, BendDAO slice_aa P41):
    A function lets an actor write to a deadline / endTime / expiry state
    variable without requiring `newTime > block.timestamp` AND
    `newTime > previousStoredValue`. This enables retroactive extension
    or premature termination of a live time-window (auction, vesting,
    voting, redemption period).

Detection strategy:
    1. Walk every non-vendored contract.
    2. Find each function (public/external, non-view) that writes to a
       state variable whose name (case-insensitive) matches one of the
       deadline/expiry hints below.
    3. Inspect every IF/require/assert node in the function:
         - Does any Binary comparison reference both the deadline-like
           variable AND `block.timestamp` / the deadline state var?
       The acceptable check is either:
         - newValue compared against block.timestamp (future-only), OR
         - newValue compared against the existing stored value
           (monotonic-only).
       We require BOTH to be present (matching the canonical fix pattern).
    4. If either check is missing → flag the function.

@author auditooor wave9
@pattern slice_aa P41 / Phi H-04 / TraitForge / BendDAO
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
from slither.slithir.operations import Binary, BinaryType
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_DEADLINE_HINTS = (
    "endtime",
    "deadline",
    "expiry",
    "expiration",
    "finishtime",
    "closetime",
    "endat",
    "expireat",
)

_TIMESTAMP_NAMES = frozenset({"block.timestamp", "now"})

_COMPARE_TYPES = frozenset({
    BinaryType.GREATER,
    BinaryType.GREATER_EQUAL,
    BinaryType.LESS,
    BinaryType.LESS_EQUAL,
    BinaryType.NOT_EQUAL,
})


def _looks_like_deadline_var(sv) -> bool:
    nm = (getattr(sv, "name", "") or "").lower()
    return any(h in nm for h in _DEADLINE_HINTS)


def _function_has_temporal_guards(function, deadline_sv) -> tuple[bool, bool]:
    """
    Walk all require/assert/if-condition nodes. Return
    (has_future_check, has_monotonic_check).

    has_future_check: a binary compare references block.timestamp AND
                      either a parameter/local OR the deadline_sv.
    has_monotonic_check: a binary compare references the deadline_sv
                      (the existing stored value) AND a parameter/local.
    """
    has_future = False
    has_monotonic = False

    for node in function.nodes:
        if not (node.contains_require_or_assert() or node.contains_if()):
            continue

        # Was block.timestamp / now read on this node?
        node_reads_ts = any(
            sv.name in _TIMESTAMP_NAMES
            for sv in node.solidity_variables_read
        )
        # Was the deadline state variable read on this node?
        node_reads_deadline = deadline_sv in node.state_variables_read

        if not (node_reads_ts or node_reads_deadline):
            continue

        # Look for at least one Binary compare on this node.
        for ir in node.irs:
            if not isinstance(ir, Binary):
                continue
            if ir.type not in _COMPARE_TYPES:
                continue
            # Any compare on a node that reads block.timestamp counts as
            # a future-check; any compare on a node that reads the existing
            # deadline value counts as a monotonic-check.
            if node_reads_ts:
                has_future = True
            if node_reads_deadline:
                has_monotonic = True
            if has_future and has_monotonic:
                return True, True

    return has_future, has_monotonic


class SettablePastDeadline(AbstractDetector):
    """Detect deadline/expiry setters that miss future-and-monotonic guards."""

    ARGUMENT = "settable-past-deadline"
    HELP = (
        "endTime/deadline/expiry setter missing require(new > block.timestamp) "
        "and require(new > current) - enables retroactive window manipulation"
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Settable Past Deadline"
    WIKI_DESCRIPTION = (
        "A setter function writes to a deadline/endTime/expiry state variable "
        "without requiring the new value to be in the future AND strictly later "
        "than the previously stored value. The owner (or anyone with the gate) "
        "can therefore set the window to a past timestamp, prematurely closing "
        "an auction/vesting/voting period, or extend an already-running window "
        "retroactively. Reported in Phi H-04, TraitForge, and BendDAO."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
uint256 public endTime;

function updateEndTime(uint256 newEnd) external onlyOwner {
    endTime = newEnd;            // no temporal validation
}
```
1. Auction is live with `endTime = T`.
2. Owner calls `updateEndTime(block.timestamp - 1)` → window already over.
3. Last bidder is locked out; griefer with the role decides who wins."""
    WIKI_RECOMMENDATION = (
        "Add `require(newEnd > block.timestamp, \"past\")` and "
        "`require(newEnd > endTime, \"shorten\")` before writing the new value, "
        "so the deadline can only move forward into the future."
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
                if function.visibility not in ("public", "external"):
                    continue

                # Must write at least one deadline-like state variable.
                deadline_writes = [
                    sv for sv in function.state_variables_written
                    if isinstance(sv, StateVariable) and _looks_like_deadline_var(sv)
                ]
                if not deadline_writes:
                    continue

                for deadline_sv in deadline_writes:
                    has_future, has_monotonic = _function_has_temporal_guards(
                        function, deadline_sv,
                    )
                    if has_future and has_monotonic:
                        continue

                    info: DETECTOR_INFO = [
                        function,
                        " writes deadline-like state variable ",
                        deadline_sv,
                        " without requiring (newValue > block.timestamp) AND "
                        "(newValue > current). Owner can retroactively extend "
                        "or prematurely terminate the time window.\n",
                    ]
                    results.append(self.generate_result(info))
                    break  # one finding per function

        return results
