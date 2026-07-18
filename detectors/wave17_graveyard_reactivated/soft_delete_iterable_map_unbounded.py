"""
soft_delete_iterable_map_unbounded.py - Custom Slither detector.

Pattern (Zellic slice_aa QSWP-4, HIGH): An iterable-mapping pattern uses a
`mapping(key => Item)` plus a companion `keys[]` state array for iteration.
The `remove`/`delete`/`cancel` function sets a deletion flag inside the
mapping's struct (soft delete) but NEVER shrinks the keys array (no
`keys.pop()`, no `keys[i] = keys[last]`, no `delete keys[i]`). Over time the
array grows without bound, making every iterating operation progressively
more expensive until the contract DoS-es itself.

Detection strategy:
    1. Contract must declare at least one `mapping(...)` state var AND at
       least one `<T>[]` dynamic array state var.
    2. Look at functions whose name matches `remove|delete|cancel` (case
       insensitive).
    3. The function must write to the mapping state variable.
    4. The function must NOT write to any dynamic-array state variable.
    5. If both hold, the soft-delete function leaks the companion array.

@author auditooor wave8
@pattern slice_aa QSWP-4
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
from slither.core.solidity_types import MappingType, ArrayType
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")
_REMOVE_HINTS = ("remove", "delete", "cancel", "retire", "revoke")


def _is_dynamic_array(sv) -> bool:
    t = sv.type
    if not isinstance(t, ArrayType):
        return False
    # Dynamic arrays have `length` == None (Slither convention).
    return getattr(t, "length", None) is None


class SoftDeleteIterableMapUnbounded(AbstractDetector):
    """Detect soft-delete functions that leave the iteration array unbounded."""

    ARGUMENT = "soft-delete-iterable-map-unbounded"
    HELP = (
        "remove/delete function flags a struct field but never shrinks the "
        "companion keys[] array - iteration cost grows unboundedly"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Soft-Delete Leaves Iterable-Mapping Array Unbounded"
    WIKI_DESCRIPTION = (
        "Iterable-mapping patterns combine `mapping(key => Item)` with a "
        "companion `keys[]` dynamic array used for iteration. If `remove()` "
        "only sets `items[k].deleted = true` and never pops / swaps / deletes "
        "the key from the companion array, every removed element still incurs "
        "iteration gas, and the array grows forever. Eventually all iteration "
        "functions hit the block gas limit and the contract is DoS-ed."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
struct Item { uint256 v; bool deleted; }
mapping(uint256 => Item) items;
uint256[] keys;

function add(uint256 k, uint256 v) external {
    items[k] = Item(v, false);
    keys.push(k);
}

function remove(uint256 k) external {
    items[k].deleted = true; // BUG: keys never shrinks
}
```
An attacker who can repeatedly call add/remove grows `keys` until every
iterating view (e.g. `sum()`) exceeds the block gas limit, bricking the
contract's core functionality."""
    WIKI_RECOMMENDATION = (
        "Inside the remove function, swap the key into the last slot and call "
        "`keys.pop()` so the array shrinks alongside the logical deletion."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            mapping_svs = [
                sv for sv in contract.state_variables
                if isinstance(sv.type, MappingType)
            ]
            array_svs = [
                sv for sv in contract.state_variables
                if _is_dynamic_array(sv)
            ]
            if not mapping_svs or not array_svs:
                continue

            map_sv_set = set(mapping_svs)
            arr_sv_set = set(array_svs)

            for function in contract.functions_and_modifiers_declared:
                if function.is_constructor:
                    continue
                if function.view or function.pure:
                    continue
                name = (function.name or "").lower()
                if not any(h in name for h in _REMOVE_HINTS):
                    continue

                writes_mapping = False
                writes_array = False
                for node in function.nodes:
                    for sv in node.state_variables_written:
                        if sv in map_sv_set:
                            writes_mapping = True
                        if sv in arr_sv_set:
                            writes_array = True
                # Also scan functions called internally (pop/length is part of
                # the same function body in practice, but be safe):
                if not writes_array:
                    for other in function.all_internal_calls():
                        try:
                            for n in other.nodes:
                                for sv in n.state_variables_written:
                                    if sv in arr_sv_set:
                                        writes_array = True
                        except Exception:
                            pass

                if not writes_mapping:
                    continue
                if writes_array:
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " soft-deletes an entry from mapping state variable(s) on ",
                    contract,
                    " without shrinking the companion dynamic array ",
                    array_svs[0],
                    ". Iteration cost grows unboundedly - swap-and-pop the key.\n",
                ]
                results.append(self.generate_result(info))

        return results
