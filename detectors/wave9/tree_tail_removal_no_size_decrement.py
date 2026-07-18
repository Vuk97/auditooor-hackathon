"""
tree_tail_removal_no_size_decrement.py — Custom Slither detector.

Pattern: A priority-queue / orderbook / sorted-tree contract has an `insert`
function that increments a `size`/`length`/`count` state variable, and a
`remove`/`pop`/`delete` function that pops the element but does NOT decrement
the same counter. Subsequent queries that use `size` as a bound overread or
return phantom entries.

Source: GTE-spot M-03 (slice_ac).

Detection (purely static, name-based per the spec):
    1. Per contract, find every uint state variable whose lowercased name
       matches `(size|length|count|tail|head)`. These are the candidate
       counters.
    2. For each counter, find an "insert-style" function (name matches
       `insert|push|add|enqueue`) that WRITES the counter — confirming
       the protocol uses this counter as a logical length.
    3. Find a "remove-style" function (name matches
       `remove|pop|delete|dequeue`) that does NOT write the counter.
    4. Flag the remove function — it tears down the underlying entry but
       leaves the counter stale.

Confidence: MEDIUM. We only flag if BOTH a counter-incrementing insert
AND a non-counter-touching remove exist in the same contract — this rules
out unrelated counters and unrelated remove helpers.

@author auditooor wave9
"""

import re
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract

from slither.core.solidity_types.elementary_type import ElementaryType
from slither.core.variables.state_variable import StateVariable
from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "deploy", "script", "setup")

_COUNTER_RE = re.compile(r"(size|length|count|tail|head)", re.IGNORECASE)
_INSERT_RE = re.compile(r"(insert|push|add|enqueue)", re.IGNORECASE)
_REMOVE_RE = re.compile(r"(remove|pop|delete|dequeue)", re.IGNORECASE)


def _is_uint_state_var(sv) -> bool:
    if not isinstance(sv, StateVariable):
        return False
    if not isinstance(sv.type, ElementaryType):
        return False
    name = sv.type.name or ""
    return name.startswith("uint") or name.startswith("int")


class TreeTailRemovalNoSizeDecrement(AbstractDetector):
    """Detect remove/pop functions that leave a size counter stale."""

    ARGUMENT = "tree-tail-removal-no-size-decrement"
    HELP = (
        "remove/pop function deletes a queue/tree entry but never decrements "
        "the size/length counter — subsequent reads overread"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Queue/Tree Tail Removal Missing Size Decrement"
    WIKI_DESCRIPTION = (
        "A priority-queue / orderbook / sorted-tree implementation has an "
        "`insert` path that increments a `size`/`length`/`count` state "
        "variable but a corresponding `remove`/`pop` path that pops the "
        "underlying element without decrementing the same counter. Any "
        "downstream loop that uses the counter as an upper bound will "
        "overread, returning stale or phantom entries. Source: GTE-spot M-03."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
mapping(uint256 => Order) public orders;
uint256 public size;

function insert(uint256 id, uint256 price) external {
    orders[id] = Order(price, 0);
    size++;
}

function removeTail(uint256 id) external {
    delete orders[id];          // BUG: size never decremented
}
```
1. Insert N orders → size = N.
2. removeTail(...) several times → underlying entries gone, size still N.
3. Iteration over `for (i = 0; i < size; i++)` reads zeroed slots and
   either reverts on a stale invariant or returns phantom orders."""
    WIKI_RECOMMENDATION = (
        "Always pair `insert`-side counter increments with matching "
        "`remove`-side decrements (`size = size - 1;` or use Solidity's "
        "checked subtract). Better: extract a private `_pop()` helper that "
        "always updates the counter."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            counters = [
                sv for sv in contract.state_variables
                if _is_uint_state_var(sv)
                and sv.name
                and _COUNTER_RE.search(sv.name)
            ]
            if not counters:
                continue

            functions = list(contract.functions_and_modifiers_declared)
            insert_fns = [
                f for f in functions
                if f.name and _INSERT_RE.search(f.name) and not f.is_constructor
            ]
            remove_fns = [
                f for f in functions
                if f.name and _REMOVE_RE.search(f.name) and not f.is_constructor
            ]
            if not insert_fns or not remove_fns:
                continue

            for counter in counters:
                insert_writers = [
                    f for f in insert_fns
                    if counter in f.state_variables_written
                ]
                if not insert_writers:
                    continue
                for rfn in remove_fns:
                    if counter in rfn.state_variables_written:
                        continue  # decrements (or otherwise touches) the counter
                    info: DETECTOR_INFO = [
                        rfn,
                        " in ",
                        contract,
                        " removes an entry without writing the size counter ",
                        counter,
                        ", while ",
                        insert_writers[0],
                        " increments it. Subsequent loops bounded by ",
                        counter,
                        " will overread.\n",
                    ]
                    results.append(self.generate_result(info))

        return results
