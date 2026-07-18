"""
withdraw_hash_stale_delete.py - Custom Slither detector.

ARG: withdraw-hash-stale-delete
SEVERITY: MEDIUM  CONFIDENCE: LOW

Pattern (from reference/corpus_mined/slice_ac.md - UFarm "StaleWithdrawalHash"):

  A withdraw / claim function uses a hash replay gate:
      mapping(bytes32 => bool) public usedHashes;
      require(!usedHashes[h], "replay");
      usedHashes[h] = true;            // unconditional mark
      if (amount > 0) {
          delete usedHashes[h];        // conditional clear - only when amount > 0
          transfer(amount);
      }
      // if amount == 0: hash stays marked, transfer never happens → stale residual

  When `amount == 0` the hash is permanently consumed without any state change
  occurring. An attacker (or a griever) can use the stale entry to replay a
  privileged state transition (e.g., `deactivate()`, `emergencyExit()`) that
  also uses `usedHashes` as its replay gate.

Detection logic:
  1. Find state variables whose name (lowercased) contains any of: used,
     consumed, processed, claimed, spent, hashes, seen. These identify
     hash-replay-gate mappings.

  2. For each function F that writes such a variable:
     a. Find nodes with an Assignment IR where the lvalue is a
        ReferenceVariable pointing to the hash-gate state var and the
        rvalue is Constant(True). This is the unconditional "mark as used" write.
        These nodes must NOT be of NodeType.IF (i.e., they are expression nodes).

     b. Find nodes with a Delete IR where the lvalue is the hash-gate
        state variable directly. This is the "clear / delete" operation.
        These nodes must appear AFTER a NodeType.IF node in CFG order
        (i.e., they are inside a conditional branch body).

     c. If (a) and (b) both exist → flag.

  The "inside conditional" detection:
     Slither's CFG node types include NodeType.IF, NodeType.ENDIF.
     The EXPRESSION nodes inside an if-body appear AFTER the IF node and
     BEFORE (or without) the ENDIF node. We track this by walking function.nodes
     in order and toggling an "in_if_body" flag.
     NOTE: function.nodes returns nodes in approximate CFG order for linear
     functions. For nested ifs this is an approximation (over-approximate).

IR observations (verified against fixture):
  - `usedHashes[h] = true` compiles to:
       Index REF_1(bool) -> usedHashes[h]   (lvalue=REF_1, rv=None)
       Assignment REF_1(bool) (->usedHashes) := True(bool)
       → ir.lvalue is ReferenceVariable, ir.rvalue is Constant(True)
       → node.type == NodeType.EXPRESSION, contains_if=False
  - `delete usedHashes[h]` compiles to:
       Index REF_2(bool) -> usedHashes[h]   (lvalue=REF_2, rv=None)
       Delete usedHashes = delete REF_2
       → ir is type Delete, ir.lvalue is StateVariable("usedHashes")
       → node.type == NodeType.EXPRESSION, contains_if=False
       → but this node appears AFTER a NodeType.IF node in the CFG
  - NodeType.IF has contains_if=True; EXPRESSION child nodes of if-body
    have contains_if=False (they are NOT the condition node themselves)

Gotchas:
  - `Assignment` AND `Delete` are both importable from slither.slithir.operations.
    `delete mapping[k]` compiles to Delete IR, NOT Assignment IR.
  - The Delete.lvalue is the StateVariable directly (not a ReferenceVariable
    pointing to it). This is different from the Assignment pattern.
  - `contains_if()` on a node is True only for the IF/condition node itself,
    NOT for expression nodes inside the if-body.

Dedup: no Slither builtin covers conditional-clear of hash replay gates.
  `slither --list-detectors | grep -iE "hash|replay|withdraw"` → nothing.

Source: reference/corpus_mined/slice_ac.md - UFarm finding "StaleWithdrawalHash"
@author auditooor wave6
@pattern withdraw-hash-stale-delete
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
from slither.slithir.operations import Assignment, Delete
from slither.slithir.variables import Constant, ReferenceVariable
from slither.core.variables.state_variable import StateVariable
from slither.core.cfg.node import NodeType
from slither.utils.output import Output

SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

# State variable name substrings that indicate a hash replay-gate mapping.
_HASH_GATE_HINTS = (
    "used",
    "consumed",
    "processed",
    "claimed",
    "spent",
    "hashes",
    "seen",
)


def _looks_like_hash_gate(sv: StateVariable) -> bool:
    """Return True if the state variable name matches a hash-gate pattern."""
    name = (sv.name or "").lower()
    return any(h in name for h in _HASH_GATE_HINTS)


def _resolve_to_state_var(lvalue):
    """
    Walk a ReferenceVariable chain to find the underlying StateVariable.
    Handles: mapping[key] → ref → StateVariable.
    Same approach as order_status_non_monotonic.py.
    """
    cur = lvalue
    for _ in range(6):
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


def _analyze_function(function, hash_sv: StateVariable):
    """
    Return (unconditional_set_found, conditional_clear_node) for the given
    function and hash-gate state variable.

    Walks function.nodes in order:
    - unconditional_set_found: True if any EXPRESSION node has
      Assignment(ref→hash_sv, True) and is NOT inside an if-body
    - conditional_clear_node: the first node that has Delete(hash_sv)
      and IS inside an if-body (i.e., appears after a NodeType.IF node
      in linear CFG order and before a NodeType.ENDIF)

    Returns (bool, node_or_None).
    """
    unconditional_set_found = False
    conditional_clear_node = None

    # Track whether we're currently inside an if-body.
    # Slither's node order for a simple if-body is:
    #   IF-node → EXPRESSION-node(s) → ENDIF-node (or END_LOOP, etc.)
    # We toggle in_if_depth on IF/ENDIF transitions.
    in_if_depth = 0

    for node in function.nodes:
        # Update if-depth based on node type
        if node.type == NodeType.IF:
            in_if_depth += 1

        # Check this node for relevant IR
        for ir in node.irs:
            # Pattern A: Assignment(ref→hash_sv, True) outside any if-body
            if isinstance(ir, Assignment):
                rv = ir.rvalue
                if isinstance(rv, Constant) and (rv.value is True or rv.value == 1):
                    sv = _resolve_to_state_var(ir.lvalue)
                    if sv is hash_sv and in_if_depth == 0:
                        unconditional_set_found = True

            # Pattern B: Delete(hash_sv) inside an if-body
            if isinstance(ir, Delete):
                lv = ir.lvalue
                # Delete.lvalue is the StateVariable directly
                if isinstance(lv, StateVariable) and lv is hash_sv:
                    if in_if_depth > 0 and conditional_clear_node is None:
                        conditional_clear_node = node

        # ENDIF decrements depth
        if node.type == NodeType.ENDIF:
            in_if_depth = max(0, in_if_depth - 1)

    return unconditional_set_found, conditional_clear_node


class WithdrawHashStaleDelete(AbstractDetector):
    """
    Detect withdraw/claim functions where a hash-gate mapping is set
    unconditionally but cleared (deleted) only conditionally, leaving
    stale entries that consume the hash without executing the guarded effect.
    """

    ARGUMENT = "withdraw-hash-stale-delete"
    HELP = (
        "Hash replay-gate set unconditionally but deleted only inside a "
        "conditional branch - zero-amount path leaves stale consumed hash"
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Stale Withdrawal Hash - Conditional Delete"
    WIKI_DESCRIPTION = (
        "A withdraw or claim function marks a hash as used/consumed "
        "unconditionally (`usedHashes[h] = true`) but only clears it inside a "
        "conditional block (e.g. `if (amount > 0) { delete usedHashes[h]; }`). "
        "When the zero-amount (or otherwise skipped) path executes, the hash is "
        "permanently marked consumed without the corresponding state transition "
        "taking effect. The stale entry can be exploited to replay a separate "
        "privileged function that uses the same hash-gate as a replay guard "
        "(e.g. a `deactivate()` or `emergencyExit()` function), since that "
        "function will find `usedHashes[h] == true` and revert, effectively "
        "DoS-ing it - or, in other designs, it may transition state unexpectedly. "
        "Found in UFarm (Hexens audit, UFARM1-4 StaleWithdrawalHash)."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
mapping(bytes32 => bool) public usedHashes;
bool public active;

function withdraw(bytes32 h, uint256 amt) external {
    require(!usedHashes[h], "replay");
    usedHashes[h] = true;           // unconditional mark
    if (amt > 0) {
        delete usedHashes[h];       // cleared only when amt > 0
        payable(msg.sender).transfer(amt);
    }
    // amt == 0: hash stays permanently consumed, no ETH transferred
}

function deactivate(bytes32 h) external {
    require(!usedHashes[h], "replay");   // same gate reused
    usedHashes[h] = true;
    active = false;
}
```
Attacker calls `withdraw(h, 0)` with a valid hash `h`.
`usedHashes[h]` is set to `true`; the transfer branch is skipped.
Any later call to `deactivate(h)` reverts with "replay" even though
`deactivate` was never actually executed - the hash gate is DoS-ed.
In protocols where deactivation is a time-sensitive emergency measure,
this permanently blocks the escape hatch."""
    WIKI_RECOMMENDATION = (
        "Ensure hash-gate clearing is symmetric with the marking: either "
        "validate the condition (e.g. `require(amt > 0)`) BEFORE marking the "
        "hash, so zero-amount calls revert cleanly before touching `usedHashes`; "
        "or restructure so the hash is only marked after all conditions are "
        "verified and the state transition is guaranteed to execute. "
        "Never mark a hash and then conditionally un-mark it."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if any(k in contract.name.lower() for k in SKIP_KEYWORDS):
                continue
            if is_vendored_or_test_contract(contract):
                continue

            for function in contract.functions_and_modifiers_declared:
                if function.is_constructor or type(function).__name__ == "Modifier":
                    continue
                if function.view or function.pure:
                    continue

                # Quick pre-filter: function must write a hash-gate state var
                hash_svs = [
                    sv for sv in function.state_variables_written
                    if isinstance(sv, StateVariable) and _looks_like_hash_gate(sv)
                ]
                if not hash_svs:
                    continue

                for hash_sv in hash_svs:
                    set_found, clear_node = _analyze_function(function, hash_sv)
                    if set_found and clear_node is not None:
                        info: DETECTOR_INFO = [
                            function,
                            " in ",
                            contract,
                            " marks hash-gate variable ",
                            hash_sv,
                            " as consumed unconditionally but deletes/clears it"
                            " only inside a conditional branch at ",
                            clear_node,
                            ". A zero-amount (or skipped) path leaves a stale"
                            " consumed hash without executing the guarded state"
                            " transition.\n",
                        ]
                        results.append(self.generate_result(info))
                        break  # one result per function

        return results
