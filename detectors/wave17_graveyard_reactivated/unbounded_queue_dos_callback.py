"""
unbounded_queue_dos_callback.py - Custom Slither detector.

Pattern: A callback / process function iterates a state array
(`depositQueue[]` / `requests[]`) via a `for` loop whose upper bound is the
array's `.length`, with no per-call pagination limit. An attacker spams zero-
value entries via an `addToQueue` helper to push the array length past the
block gas limit, permanently bricking `processQueue()`.

Source: Zellic slice_ab ufarm-may-25 (CRITICAL).

Detection:
    1. Iterate functions (non-view, non-constructor).
    2. Find nodes of type STARTLOOP / IFLOOP that reference a state array
       via `.length`. We approximate by looking for a node whose
       solidity_variables_read contains no timestamp but whose
       state_variables_read include a state variable of array type, AND
       whose expression source contains the word `length`.
    3. Verify that the function does NOT contain any comparison using a
       literal / constant upper bound (we accept if the loop condition
       variable comes from a local `limit` / `min` / `cap` binding -
       approximated by presence of a local var whose name contains
       `limit`/`cap`/`max`/`min`).
    4. If an unbounded loop exists over a state array → flag.

Confidence: MEDIUM. We operate on node-level hints: the vulnerable fixture
has no pagination local; the clean fixture has a `limit` local variable
that shadows the array length.
"""

import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract

from slither.core.cfg.node import NodeType
from slither.core.solidity_types.array_type import ArrayType
from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.utils.output import Output


SKIP_KEYWORDS = ("test", "mock", "setup", "fixture", "helper", "deploy", "script")

_PAGINATION_HINTS = ("limit", "cap", "max", "min", "batch", "page")


def _function_has_pagination_local(function) -> bool:
    for lv in function.local_variables:
        name = (lv.name or "").lower()
        if any(h in name for h in _PAGINATION_HINTS):
            return True
    return False


def _state_array_names(contract) -> set:
    names = set()
    for sv in contract.state_variables:
        if isinstance(sv.type, ArrayType):
            if sv.name:
                names.add(sv.name)
    return names


def _find_unbounded_loop_node(function, state_array_names):
    """
    Look for an IF_LOOP node (loop condition) whose expression textually
    references `<state_array>.length`. Return that node, else None.
    """
    for node in function.nodes:
        if node.type != NodeType.IFLOOP:
            continue
        expr = str(node.expression) if node.expression is not None else ""
        if ".length" not in expr:
            continue
        if any(name in expr for name in state_array_names):
            return node
    return None


class UnboundedQueueDosCallback(AbstractDetector):
    """Detect unbounded for-loops over state arrays that can be DoS'd by spamming entries."""

    ARGUMENT = "unbounded-queue-dos-callback"
    HELP = (
        "Unbounded for loop iterates a state array without per-call cap - "
        "attacker can brick the function by spamming queue entries"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Unbounded Queue Iteration - Griefing DoS"
    WIKI_DESCRIPTION = (
        "A process / callback function iterates a state array using "
        "`for (i = 0; i < queue.length; i++)` without a per-call pagination "
        "limit. Any attacker that can push entries to the queue (even zero-"
        "value deposits) can inflate the array past the block gas limit, "
        "permanently bricking the function and anything that depends on it. "
        "Source: Zellic UFarm may-25 (CRITICAL)."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
Deposit[] public depositQueue;

function addToQueue() external {
    depositQueue.push(Deposit(msg.sender, 0));
}

function processQueue() external {
    for (uint256 i = 0; i < depositQueue.length; i++) {
        depositQueue[i].user.call("");
    }
}
```
1. Attacker calls `addToQueue()` tens of thousands of times with zero deposits.
2. `depositQueue.length` grows past the point where iterating it fits in a
   single block.
3. `processQueue()` now permanently out-of-gases - legitimate deposits are
   stuck forever."""
    WIKI_RECOMMENDATION = (
        "Enforce a per-call cap: `uint256 limit = depositQueue.length > 100 "
        "? 100 : depositQueue.length; for (uint256 i = 0; i < limit; i++)` "
        "and pop processed entries off the front (or use a mapping-based "
        "FIFO with head/tail pointers)."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in SKIP_KEYWORDS):
                continue

            array_names = _state_array_names(contract)
            if not array_names:
                continue

            for function in contract.functions_and_modifiers_declared:
                if function.is_constructor:
                    continue
                if function.view or function.pure:
                    continue

                loop_node = _find_unbounded_loop_node(function, array_names)
                if loop_node is None:
                    continue

                # If there's a pagination local, assume the developer capped it.
                if _function_has_pagination_local(function):
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " iterates a state array via ",
                    loop_node,
                    " with no per-call pagination cap. Anyone who can push "
                    "entries to the array can brick this function once the "
                    "array grows past block-gas-limit. Add a per-call limit "
                    "and pop/advance the head pointer.\n",
                ]
                results.append(self.generate_result(info))

        return results
