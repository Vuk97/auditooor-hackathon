"""
cfi_before_fulfill.py - Custom Slither detector.

Pattern: A function makes a HighLevelCall to an external address and LATER (in
CFG node order) writes to a state variable whose name contains a fulfillment
sentinel keyword (fulfilled, processed, executed, settled, consumed).

This is the CEI (Checks-Effects-Interactions) violation seen in Socket Dec24:
    _executeCalldata(...)       ← external callback fires HERE
    $.fulfilledRequests[hash] = FulfilledRequest(...)  ← WRITTEN AFTER

Exploitation path:
  1. Attacker's contract is the callback target.
  2. Callback fires while fulfilledRequests[hash] is still unset.
  3. Attacker calls cancel() / refund() / re-fulfill() - state says "not yet
     fulfilled" → double-spend or fund drain.
  4. Original transaction completes and THEN sets fulfilledRequests[hash] = true.
     Exploit is complete.

Source:
  reference/corpus_mined/slice_aa.md - "cfi-callback-before-fulfilled-mark",
  Socket Dec24, ranked #1 novel candidate for auditooor target domain.

Dedup:
  - reentrancy-eth, reentrancy-no-eth, reentrancy-balance, reentrancy-benign,
    reentrancy-events, reentrancy-unlimited-gas: Slither's reentrancy detectors
    look for "does a re-entrant call occur?" using static reachability analysis.
    This detector is strictly different - it flags the ORDER of operations
    (call before write) regardless of whether re-entry is possible.  Even an
    onlyOperator function where re-entry is hard-to-execute is flagged because
    the fulfillment mark must be written BEFORE any external interaction,
    unconditionally.  ARGUMENT prefix "cfi-" distinguishes from "reentrancy-*".

Detection strategy:
  1. Walk c.functions_and_modifiers_declared.
  2. For each function, collect:
       call_nodes   - nodes with any HighLevelCall IR
       fulfill_nodes - nodes with an Assignment IR whose lvalue (possibly via
                       ReferenceVariable) resolves to a StateVariable with a
                       fulfillment-sentinel name
  3. If min(call_node_ids) < min(fulfill_node_ids) → flag.
     (Any call precedes any fulfill-write.)

API notes (verified against IR probe on fixture):
  - Node order: function.nodes gives CFG order; node_id is reliable for
    comparing node positions within a linear function.
  - HighLevelCall: isinstance(ir, HighLevelCall) - exact match.
  - Assignment to mapping entry: Slither compiles `m[k] = v` as:
      Index: REF -> m[k]                   (lvalue = ReferenceVariable)
      Assignment: REF := v                 (lvalue = same ReferenceVariable)
    The ReferenceVariable's .points_to_origin (or .points_to) walks to the
    underlying StateVariable.
  - Assignment IR class: slither.slithir.operations.Assignment - confirmed
    present in this Slither version (probe verified).
  - generate_result: only Function, Node, StateVariable, str are source-mapped;
    do NOT pass raw IR or TemporaryVariable.

Confidence: MEDIUM - linear CFG walk; branching functions may generate false
positives if the call and write are on diverging paths.
Impact: HIGH - double-spend / fund drain in cross-chain settlement.

@author auditooor wave5
@pattern cfi-callback-before-fulfill-mark (Socket Dec24)
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
from slither.slithir.operations import Assignment, HighLevelCall
from slither.core.variables.state_variable import StateVariable
from slither.slithir.variables import ReferenceVariable
from slither.utils.output import Output


SKIP_KEYWORDS = ("test", "mock", "setup", "fixture", "helper", "deploy", "script")

# State-variable name substrings indicating a fulfillment sentinel.
_FULFILL_HINTS = (
    "fulfilled",
    "processed",
    "executed",
    "settled",
    "consumed",
)

# Regex: any of the above words as a word-boundary match (case-insensitive).
_FULFILL_RE = re.compile(
    r"(?:fulfilled|processed|executed|settled|consumed)",
    re.IGNORECASE,
)


def _is_fulfill_state_var(var) -> bool:
    """Return True if var is a StateVariable with a fulfillment-hint name."""
    if not isinstance(var, StateVariable):
        return False
    return bool(_FULFILL_RE.search(var.name or ""))


def _resolve_to_state_var(lv):
    """
    Walk a (possibly chained) ReferenceVariable to its root StateVariable.
    Returns the StateVariable if found, else None.
    Depth-limited to 5 hops to guard against cycles.
    """
    cur = lv
    for _ in range(5):
        if isinstance(cur, StateVariable):
            return cur
        if not isinstance(cur, ReferenceVariable):
            return None
        nxt = (
            getattr(cur, "points_to_origin", None)
            or getattr(cur, "points_to", None)
        )
        if nxt is None or nxt is cur:
            return None
        cur = nxt
    return None


def _collect_call_and_fulfill_nodes(function):
    """
    Return (call_nodes, fulfill_nodes):
      call_nodes    - list of nodes containing a HighLevelCall IR
      fulfill_nodes - list of nodes containing an Assignment IR whose lvalue
                      resolves to a fulfillment-sentinel StateVariable
    """
    call_nodes = []
    fulfill_nodes = []

    for node in function.nodes:
        has_call = False
        has_fulfill_write = False

        for ir in node.irs:
            # Check for external call
            if isinstance(ir, HighLevelCall):
                has_call = True

            # Check for assignment to fulfillment state var
            if isinstance(ir, Assignment):
                lv = getattr(ir, "lvalue", None)
                if lv is not None:
                    sv = _resolve_to_state_var(lv)
                    if sv is not None and _is_fulfill_state_var(sv):
                        has_fulfill_write = True

        if has_call:
            call_nodes.append(node)
        if has_fulfill_write:
            fulfill_nodes.append(node)

    return call_nodes, fulfill_nodes


class CfiBeforeFulfill(AbstractDetector):
    """
    Detect external calls that fire before the fulfillment-mark state write
    (CEI violation in cross-chain / callback-based settlement).
    """

    ARGUMENT = "cfi-before-fulfill"
    HELP = (
        "External HighLevelCall fires before fulfilled/processed/executed/"
        "settled/consumed state-variable write - CEI violation"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Callback Before Fulfill-Mark (CEI Violation)"
    WIKI_DESCRIPTION = (
        "A function performs an external call (HighLevelCall) before writing "
        "the fulfillment sentinel to a state variable whose name contains "
        "'fulfilled', 'processed', 'executed', 'settled', or 'consumed'. "
        "When the external call triggers a callback, the callee can observe "
        "the contract in a state where the request is not yet marked as "
        "fulfilled, enabling cancel-and-refund or re-entrancy attacks that "
        "drain additional funds before the sentinel write completes. "
        "This exact pattern was confirmed in the Socket Dec24 audit."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
mapping(bytes32 => bool) public fulfilledRequests;
IExternal public ext;

function executeRequest(bytes32 id) external {
    ext.doThing();                 // callback fires here
    fulfilledRequests[id] = true;  // written AFTER - state says "not fulfilled"
}
```
1. Attacker crafts a contract as `ext` that, inside `doThing()`, calls back
   into the victim contract to invoke `cancelRequest(id)` or a refund path.
2. At re-entry time `fulfilledRequests[id]` is still `false`, so the cancel
   check passes and a refund is issued.
3. The outer `executeRequest` call then resumes and sets
   `fulfilledRequests[id] = true`, making the double-spend permanent."""
    WIKI_RECOMMENDATION = (
        "Follow the Checks-Effects-Interactions pattern: write the fulfillment "
        "sentinel BEFORE any external call. For cross-chain callbacks, use a "
        "nonReentrant guard AND set the state variable as the very first "
        "operation in the execution path."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in SKIP_KEYWORDS):
                continue

            for function in contract.functions_and_modifiers_declared:
                call_nodes, fulfill_nodes = _collect_call_and_fulfill_nodes(function)

                if not call_nodes or not fulfill_nodes:
                    continue

                # Flag if the earliest external call precedes the earliest
                # fulfillment-mark write in CFG node-id order.
                min_call_id = min(n.node_id for n in call_nodes)
                min_fulfill_id = min(n.node_id for n in fulfill_nodes)

                if min_call_id >= min_fulfill_id:
                    # Fulfill write comes first (CEI compliant) - no flag.
                    continue

                # Find the specific nodes for the report.
                earliest_call_node = min(call_nodes, key=lambda n: n.node_id)
                earliest_fulfill_node = min(fulfill_nodes, key=lambda n: n.node_id)

                # Recover the state variable name for the message.
                sv_name = "?"
                for ir in earliest_fulfill_node.irs:
                    if isinstance(ir, Assignment):
                        lv = getattr(ir, "lvalue", None)
                        if lv is not None:
                            sv = _resolve_to_state_var(lv)
                            if sv is not None and _is_fulfill_state_var(sv):
                                sv_name = sv.name
                                break

                info: DETECTOR_INFO = [
                    function,
                    " makes an external call at ",
                    earliest_call_node,
                    " before writing fulfillment sentinel '",
                    sv_name,
                    "' at ",
                    earliest_fulfill_node,
                    " - CEI violation; callback can re-enter before the "
                    "fulfilled/processed/executed/settled/consumed mark is set.\n",
                ]
                results.append(self.generate_result(info))

        return results
