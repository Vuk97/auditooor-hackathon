"""
unbounded_while_on_storage_list.py - Custom Slither detector.

Pattern: A function iterates a storage-resident linked list (a struct-in-mapping
whose struct has a `next`/`prev` field) inside a loop whose condition has no
counter / iteration cap. An attacker who can append nodes (any external `add` /
`append` style helper exists in the contract) grows the list arbitrarily;
future calls to the iteration function hit the block gas limit and the function
becomes permanently DoS'd.

Source: LoopFi MFD slice_aa P44 (CRITICAL).

Detection:
    1. For each contract, find state variables of mapping(_ => Struct) type
       where the struct has a field literally named `next` or `prev`.
    2. For each function (non-view OR view both qualify - DoS still applies
       because dependent functions cascade), look for an IFLOOP node that
       reads from one of those mapping state variables (since Slither lowers
       both `for` and `while` to IFLOOP, this captures both).
    3. The function is FLAGGED unless it declares a local variable whose
       name matches a pagination hint (`limit`, `cap`, `max`, `min`,
       `batch`, `page`, `iter`, `bound`).
    4. We require BOTH (a) the linked-list struct shape AND (b) the loop on
       that mapping - minimising false positives from generic mapping reads.

Confidence: MEDIUM. Modeled on wave8/unbounded_queue_dos_callback.py.

@author auditooor wave9
"""

import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract

from slither.core.cfg.node import NodeType
from slither.core.solidity_types.mapping_type import MappingType
from slither.core.solidity_types.user_defined_type import UserDefinedType
from slither.core.declarations.structure import Structure
from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "deploy", "script", "setup")
_LINK_FIELDS = ("next", "prev")
_PAGINATION_HINTS = ("limit", "cap", "max", "min", "batch", "page", "iter", "bound")


def _linked_list_state_vars(contract):
    """Return state variables that are mapping(_ => Struct{...next/prev...})."""
    out = []
    for sv in contract.state_variables:
        t = sv.type
        if not isinstance(t, MappingType):
            continue
        value_t = t.type_to
        if not isinstance(value_t, UserDefinedType):
            continue
        inner = value_t.type
        if not isinstance(inner, Structure):
            continue
        field_names = {(e.name or "").lower() for e in inner.elems_ordered}
        if any(link in field_names for link in _LINK_FIELDS):
            out.append(sv)
    return out


def _function_has_pagination_local(function) -> bool:
    for lv in function.local_variables:
        name = (lv.name or "").lower()
        if any(h in name for h in _PAGINATION_HINTS):
            return True
    return False


def _find_loop_over_linked_list(function, ll_state_vars):
    """
    Find an IFLOOP node inside this function. Slither lowers both `while` and
    `for` to IFLOOP. The function qualifies if anywhere in the function body
    one of the linked-list state variables is read AND there is at least one
    IFLOOP node - i.e. iteration over a linked list. Return the loop node.
    """
    has_loop_node = None
    for node in function.nodes:
        if node.type == NodeType.IFLOOP:
            has_loop_node = node
            break
    if has_loop_node is None:
        return None
    # Require the function to actually read one of the linked-list mappings.
    func_state_reads = set(function.state_variables_read)
    if not any(sv in func_state_reads for sv in ll_state_vars):
        return None
    return has_loop_node


class UnboundedWhileOnStorageList(AbstractDetector):
    """Detect unbounded loops over storage-resident linked lists."""

    ARGUMENT = "unbounded-while-on-storage-list"
    HELP = (
        "Function loops over a storage linked list (mapping → struct with "
        "next/prev) without a counter cap - DoS via list growth"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Unbounded While Loop on Storage Linked List"
    WIKI_DESCRIPTION = (
        "A function walks a storage linked list (mapping(uint => Node) with a "
        "`next` or `prev` pointer) using a `while (cur != 0)` style loop and "
        "has no counter-based cap on iterations. Any actor who can append "
        "nodes can grow the list past the block gas limit; the iteration "
        "function (and anything that depends on it) is then permanently "
        "bricked. Source: LoopFi MFD slice_aa P44 (CRITICAL)."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
struct Node { uint256 value; uint256 next; }
mapping(uint256 => Node) public nodes;
uint256 public head;

function sum() external view returns (uint256 total) {
    uint256 cur = head;
    while (cur != 0) {                       // no counter cap
        total += nodes[cur].value;
        cur = nodes[cur].next;
    }
}
```
1. Attacker calls `append()` thousands of times, paying only base gas.
2. `head → nodes[a].next → ... → 0` chain grows past the block gas limit.
3. Every caller of `sum()` (and any function that downstream-calls it) now
   permanently out-of-gases."""
    WIKI_RECOMMENDATION = (
        "Track an explicit per-call `uint256 i = 0; uint256 cap = MAX_ITER;` "
        "counter in the loop condition (e.g. `while (cur != 0 && i < cap)`) "
        "and resume from a stored cursor between calls. Never iterate an "
        "unbounded user-controllable linked list in a single transaction."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            ll_state_vars = _linked_list_state_vars(contract)
            if not ll_state_vars:
                continue

            for function in contract.functions_and_modifiers_declared:
                if function.is_constructor:
                    continue

                loop_node = _find_loop_over_linked_list(function, ll_state_vars)
                if loop_node is None:
                    continue

                if _function_has_pagination_local(function):
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " walks a storage linked list at ",
                    loop_node,
                    " with no per-call counter cap. An attacker who can "
                    "append nodes can grow the list past the block gas "
                    "limit and permanently DoS this function.\n",
                ]
                results.append(self.generate_result(info))
                break  # one finding per function

        return results
