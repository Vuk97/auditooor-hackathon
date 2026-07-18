"""
auction_failed_stalls_protocol.py - Custom Slither detector.

Pattern (P28): A contract has an enum-typed state variable whose enum
declares a member named FAILED / ABORTED / CANCELLED / CANCELED. Functions
exist that write that state variable to the failure member (transitioning
INTO the failure state), but NO function guards on the failure member in a
require/assert and then writes a non-failure member (transitioning OUT of
the failure state). The failure state is therefore terminal: once entered,
epoch progression is permanently blocked.

Source: reference/corpus_mined/slice_ag.md - Plaza Core Protocol.
Bug: "Auction Failure Not Handled: Protocol Permanently Stalled" (HIGH).
In Plaza: FAILED_UNDERSOLD/FAILED_LIQUIDATION leave auctions[currentPeriod]
non-zero; currentPeriod can never increment; new auctions impossible; bidder
funds locked.

Detection strategy (verified against IR probe):

1. Walk state variables of the contract (direct enum type - skip MappingType
   wrappers which are historical records, not the protocol state machine).
2. For each enum SV, find its "failure members" (values containing FAILED,
   ABORTED, CANCELLED, CANCELED case-insensitively).
3. Over ALL functions_and_modifiers_declared, track two sets:
     A. fns_writing_to_fail  - functions that assign the enum SV to a fail member
     B. fns_writing_from_fail - functions that:
          (i)  guard on fail member in a require/assert/Binary check, AND
          (ii) assign the enum SV to a NON-fail member in the same function
4. If A is non-empty and B is empty → flag (no exit path from failure state).

IR shapes (verified):
  currentState = State.Failed;
    Member REF_N(EnumType) -> State.Failed  (variable_right=Constant("Failed"))
    Assignment currentState := REF_N

  require(currentState == State.Failed, ...);
    Member REF_M(EnumType) -> State.Failed
    Binary TMP = currentState == REF_M
    SolidityCall require(TMP, ...)

Confidence: LOW - broad pattern; some protocols intentionally leave
historical slots in FAILED state without providing a state-machine exit.
Operators must confirm the flagged SV is the live-protocol-state variable,
not a per-slot record.

@author auditooor
@pattern wave6 P28 auction-failed-stalls-protocol
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
from slither.slithir.operations import Member as MemberOp, Assignment, Binary
from slither.core.solidity_types import UserDefinedType, MappingType
from slither.core.declarations import Enum
from slither.slithir.variables import ReferenceVariable
from slither.core.variables.state_variable import StateVariable
from slither.utils.output import Output


# Keywords that identify "failure" enum members (case-insensitive)
_FAIL_KEYWORDS = ("FAILED", "ABORTED", "CANCELLED", "CANCELED")

# Function / contract name fragments to skip
_SKIP_KEYWORDS = ("test", "mock", "setup", "fixture", "helper", "deploy", "script")


def _enum_fail_members(enum_decl) -> set:
    """Return the subset of enum values whose names contain a failure keyword."""
    return {
        v for v in enum_decl.values
        if any(kw in v.upper() for kw in _FAIL_KEYWORDS)
    }


def _build_member_ref_map(function) -> dict:
    """
    Walk all nodes of *function* and return a mapping:
        id(MemberOp.lvalue) -> str(member_name)
    for every Member IR op encountered.
    """
    ref_map: dict[int, str] = {}
    for node in function.nodes:
        for ir in node.irs:
            if isinstance(ir, MemberOp):
                mname = getattr(ir.variable_right, "name", None)
                if mname:
                    ref_map[id(ir.lvalue)] = mname
    return ref_map


def _analyse_function(function, sv_name: str, fail_members: set) -> tuple:
    """
    Analyse a single function for transitions to/from the failure state.

    Returns (writes_to_fail: bool, writes_from_fail: bool).

    writes_to_fail  - function assigns sv to a failure member
    writes_from_fail - function guards on failure member in a require/assert
                       AND writes sv to a non-failure member
    """
    ref_map = _build_member_ref_map(function)
    fail_seen_in_guard = False
    write_destinations: list = []

    for node in function.nodes:
        for ir in node.irs:
            if isinstance(ir, Assignment):
                lv = ir.lvalue
                rv = getattr(ir, "rvalue", None)
                # Check if lvalue resolves to our target state variable
                sv_matched = False
                if isinstance(lv, StateVariable) and lv.name == sv_name:
                    sv_matched = True
                # Do NOT chase ReferenceVariable chains here - mapping slots are
                # intentionally excluded (we only want direct SV writes).
                if sv_matched and rv is not None:
                    mname = ref_map.get(id(rv))
                    write_destinations.append(mname)

        # Separate pass: check require/assert nodes for failure-member guards
        if node.contains_require_or_assert():
            for ir in node.irs:
                if isinstance(ir, Binary):
                    for v in ir.read:
                        mname = ref_map.get(id(v))
                        if mname in fail_members:
                            fail_seen_in_guard = True

    writes_to_fail = any(d in fail_members for d in write_destinations)
    writes_from_fail = (
        fail_seen_in_guard
        and any(d is not None and d not in fail_members for d in write_destinations)
    )
    return writes_to_fail, writes_from_fail


class AuctionFailedStallsProtocol(AbstractDetector):
    """
    Detect enum state machines where the FAILED/ABORTED/CANCELLED state has
    no transition function to advance the protocol epoch.
    """

    ARGUMENT = "auction-failed-stalls-protocol"
    HELP = (
        "Enum state machine has no transition out of FAILED/ABORTED/CANCELLED "
        "state - protocol epoch permanently blocked after one failure"
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Auction FAILED State Permanently Stalls Protocol (P28)"
    WIKI_DESCRIPTION = (
        "A structured auction protocol uses an enum state machine with members "
        "like FAILED, ABORTED, or CANCELLED. Functions exist that transition "
        "the state variable into the failure state, but no function transitions "
        "out of it. Once a single auction fails, the protocol's epoch counter "
        "can never advance, all subsequent auctions are blocked, and bidder "
        "funds may be permanently locked. "
        "Observed in Plaza Core Protocol (Zellic audit): FAILED_UNDERSOLD and "
        "FAILED_LIQUIDATION states left auctions[currentPeriod] non-zero forever."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
enum State { Open, Closed, Failed }
State public currentState;

function closeAuction(bool succeeded) external {
    if (succeeded) {
        currentState = State.Closed;
        currentPeriod++;          // epoch advances
    } else {
        currentState = State.Failed; // no exit path
    }
}
// No recover() function exists - currentPeriod never increments.
```
1. Market conditions cause one auction to fail.
2. `currentState` is set to `State.Failed`.
3. Every subsequent `distribute()` / `startAuction()` requires `currentState == Open`,
   which is permanently false.
4. Protocol is bricked; bidder funds locked in the failed auction contract."""
    WIKI_RECOMMENDATION = (
        "Add a recovery function (e.g. `recover()`) that is callable when the state "
        "is in the FAILED member and transitions it to the initial Open/Active state "
        "while advancing the epoch counter. Ensure this function is access-controlled "
        "or callable by governance so that protocol liveness can be restored."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            for sv in contract.state_variables:
                # Only inspect direct enum state vars - skip mapping wrappers
                # (mapping SVs are per-slot historical records, not the live state machine)
                tp = sv.type
                if isinstance(tp, MappingType):
                    continue
                if not isinstance(tp, UserDefinedType):
                    continue
                enum_decl = tp.type
                if not isinstance(enum_decl, Enum):
                    continue

                fail_members = _enum_fail_members(enum_decl)
                if not fail_members:
                    continue

                fns_writing_to_fail: list = []
                fns_writing_from_fail: list = []

                for function in contract.functions_and_modifiers_declared:
                    w_to, w_from = _analyse_function(function, sv.name, fail_members)
                    if w_to:
                        fns_writing_to_fail.append(function)
                    if w_from:
                        fns_writing_from_fail.append(function)

                # Flag only if the failure state can be entered but never exited
                if fns_writing_to_fail and not fns_writing_from_fail:
                    # Use the first function that writes to fail as the anchor
                    anchor_fn = fns_writing_to_fail[0]
                    info: DETECTOR_INFO = [
                        contract,
                        " has enum state variable ",
                        sv,
                        " with failure member(s) [",
                        ", ".join(sorted(fail_members)),
                        "]. Functions [",
                        ", ".join(f.name for f in fns_writing_to_fail),
                        "] transition INTO the failure state but no function "
                        "transitions OUT of it. Protocol epoch permanently "
                        "stalled after one failed auction.\n",
                    ]
                    results.append(self.generate_result(info))

        return results
