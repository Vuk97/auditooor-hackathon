"""
multisig_executed_before_call.py - Custom Slither detector.

Pattern (slice_ah - eBridge Ethereum Bridge, HIGH):
    A multisig/queue function marks a transaction's `executed` flag to
    `true` BEFORE invoking the external call. If the call reverts (e.g.
    a malicious signer routes to a contract that OOGs), the revert rolls
    back the executed write AND the call - BUT the original Zellic
    finding was that the multisig catches the call result, does not
    revert, and leaves `executed == true` forever, permanently cancelling
    the proposal.

    Even without a try/catch, writing "executed = true" before the call
    is a CEI inversion: reentrancy via the call can observe the flag as
    already-set and bypass re-entry guards.

Detection strategy:
    1. For each function, walk nodes in order. Track the first node index
       at which a ReferenceVariable field assignment writes a Constant
       `True` to a field whose name matches `executed|processed|handled|
       claimed|finalized|fulfilled`.
    2. Track the first node index at which a LowLevelCall or HighLevelCall
       is emitted.
    3. If write_idx < call_idx → flag. The write precedes the external
       call within the same function's linear CFG order.

Confidence: MEDIUM. Ordering by node index approximates CFG order; the
flag-name allowlist narrows the domain. Does not flag when the call is
in a prior node or a different function.
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
from slither.slithir.operations import (
    Assignment,
    LowLevelCall,
    HighLevelCall,
    Member,
)
from slither.slithir.variables import ReferenceVariable, Constant
from slither.utils.output import Output


_EXECUTED_FRAGMENTS = (
    "executed", "processed", "handled", "claimed",
    "finalized", "fulfilled", "settled",
)
_SKIP_KEYWORDS = ("test", "mock", "setup", "fixture", "helper", "deploy", "script")


def _find_executed_flag_write(function) -> int:
    """
    Return the node index of the first write `struct.executed = true`,
    or -1 if none.
    """
    for idx, node in enumerate(function.nodes):
        # Map ReferenceVariable-id → field name from Member ops in this node
        ref_field: dict[int, str] = {}
        for ir in node.irs:
            if isinstance(ir, Member):
                fname = getattr(ir.variable_right, "name", None) or getattr(
                    ir.variable_right, "value", None
                )
                if fname:
                    ref_field[id(ir.lvalue)] = str(fname)
        # Look for Assignment lvalue=ref, rvalue=True
        for ir in node.irs:
            if not isinstance(ir, Assignment):
                continue
            lv = ir.lvalue
            if not isinstance(lv, ReferenceVariable):
                continue
            fname = ref_field.get(id(lv))
            if fname is None:
                continue
            if not any(frag in fname.lower() for frag in _EXECUTED_FRAGMENTS):
                continue
            # Check RHS is True literal
            rv = getattr(ir, "rvalue", None)
            if isinstance(rv, Constant):
                val = getattr(rv, "value", None)
                if val is True or str(val).lower() == "true":
                    return idx
    return -1


def _find_first_external_call(function) -> int:
    for idx, node in enumerate(function.nodes):
        for ir in node.irs:
            if isinstance(ir, (LowLevelCall, HighLevelCall)):
                return idx
    return -1


class MultisigExecutedBeforeCall(AbstractDetector):
    """Detect multisig/queue executed-flag set before the external call."""

    ARGUMENT = "multisig-executed-before-call"
    HELP = (
        "Tx struct's `executed` flag is set to true BEFORE the external call "
        "- on revert/OOG proposal is permanently dead (CEI inversion)"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Multisig Executed Flag Set Before External Call"
    WIKI_DESCRIPTION = (
        "A multisig/queue/governance execute function writes an `executed` "
        "(or `processed`, `fulfilled`, ...) flag to true BEFORE performing "
        "the transaction's external call. If the call reverts, in a try/catch "
        "the flag stays true → proposal permanently cancelled. Even without "
        "try/catch this inverts CEI: reentrancy via the call can observe the "
        "flag as already-set and bypass re-entry checks. Observed in eBridge "
        "Ethereum Bridge (Zellic audit, HIGH)."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function executeTransaction(uint256 id) external {
    Tx storage t = txs[id];
    require(!t.executed);
    t.executed = true;                // BUG: set before call
    (bool ok, ) = t.destination.call(t.data);
    require(ok); // (or silently ignored)
}
```
1. A malicious signer crafts a `destination`/`data` pair whose call reverts
   (OOG, selfdestruct, manually-revert).
2. Inside try/catch the revert does NOT undo `executed = true`.
3. The proposal is permanently marked executed and cannot be retried."""
    WIKI_RECOMMENDATION = (
        "Apply checks-effects-interactions: perform the external call first "
        "and only set `executed = true` in the success branch after the "
        "call returns OK."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            for function in contract.functions_and_modifiers_declared:
                w_idx = _find_executed_flag_write(function)
                if w_idx < 0:
                    continue
                c_idx = _find_first_external_call(function)
                if c_idx < 0:
                    continue
                if w_idx >= c_idx:
                    continue
                info: DETECTOR_INFO = [
                    function,
                    " sets an executed/processed/fulfilled flag to true BEFORE "
                    "its external call - on revert the flag is not rolled back "
                    "if the call is wrapped in try/catch (proposal stuck) and "
                    "reentrancy via the call observes the flag already set. "
                    "Move the flag write to AFTER the call.\n",
                ]
                results.append(self.generate_result(info))

        return results
