"""
dirty_flag_not_updated_on_transfer.py - Custom Slither detector.

Pattern: An NFT-like contract stores per-token state as a struct in a mapping.
The struct has a "dirty"-style bool field (`locked`, `staked`, `dirty`,
`occupied`, `reserved`, `active`) that is logically tied to the previous
owner. A transfer hook (`_update`, `_transfer`, `_beforeTokenTransfer`) moves
the owner field but does NOT reset / migrate the dirty flag - so the new
owner inherits stale state.

Source: Munchables dirty-flag (slice_aa P48).

Detection (per contract):
    1. Find every state variable of type mapping(_ => Struct{...}) whose
       struct contains both a non-bool field (owner, holder, user, account)
       AND a "dirty"-style bool field.
    2. For each such mapping, walk every function and identify which struct
       fields it writes (using the Member/Assignment IR pattern from
       partial_struct_write.py).
    3. Flag any function that writes the owner-style field of the struct
       but does NOT write the dirty-style bool field.

Confidence: MEDIUM. We require the struct shape to match exactly so that
unrelated mappings don't false-positive.

@author auditooor wave9
"""

import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract

from slither.core.declarations.structure import Structure
from slither.core.solidity_types.elementary_type import ElementaryType
from slither.core.solidity_types.mapping_type import MappingType
from slither.core.solidity_types.user_defined_type import UserDefinedType
from slither.core.variables.state_variable import StateVariable
from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.slithir.operations import Member, Assignment
from slither.slithir.variables import ReferenceVariable
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "deploy", "script", "setup")

_DIRTY_FIELD_HINTS = (
    "dirty", "staked", "locked", "occupied", "reserved", "active", "frozen",
)
_OWNER_FIELD_HINTS = ("owner", "holder", "user", "account", "operator")


def _struct_of_mapping(sv):
    if not isinstance(sv, StateVariable):
        return None
    t = sv.type
    if not isinstance(t, MappingType):
        return None
    vt = t.type_to
    if not isinstance(vt, UserDefinedType):
        return None
    inner = vt.type
    if not isinstance(inner, Structure):
        return None
    return inner


def _identify_struct_fields(struct):
    """Return (dirty_field_names, owner_field_names) for the struct."""
    dirty = []
    owner = []
    for elem in struct.elems_ordered:
        nm = (elem.name or "").lower()
        # bool fields matching dirty hints
        if isinstance(elem.type, ElementaryType) and elem.type.name == "bool":
            if any(h in nm for h in _DIRTY_FIELD_HINTS):
                dirty.append(elem.name)
        # owner-style fields
        if isinstance(elem.type, ElementaryType) and elem.type.name == "address":
            if any(h in nm for h in _OWNER_FIELD_HINTS):
                owner.append(elem.name)
    return dirty, owner


def _function_field_writes_for_sv(function, target_sv):
    """Return set of struct field names written by this function on target_sv."""
    writes = set()
    member_map = {}
    for node in function.nodes:
        for ir in node.irs:
            if isinstance(ir, Member):
                lv = ir.lvalue
                if not isinstance(lv, ReferenceVariable):
                    continue
                origin = lv.points_to_origin
                if origin is not target_sv:
                    continue
                field_name = ir.variable_right.value
                member_map[id(lv)] = field_name
            elif isinstance(ir, Assignment):
                lv = ir.lvalue
                if not isinstance(lv, ReferenceVariable):
                    continue
                fn = member_map.get(id(lv))
                if fn is not None:
                    writes.add(fn)
    return writes


class DirtyFlagNotUpdatedOnTransfer(AbstractDetector):
    """Detect transfer hooks that move ownership without resetting a per-token dirty flag."""

    ARGUMENT = "dirty-flag-not-updated-on-transfer"
    HELP = (
        "Function writes a per-token owner field but leaves a logically "
        "paired dirty/locked/staked bool field stale - new owner inherits state"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Dirty Flag Not Reset on Transfer"
    WIKI_DESCRIPTION = (
        "An NFT-like contract stores per-token state in a struct mapping with "
        "both an owner field and a `locked`/`staked`/`dirty`/`occupied` bool "
        "flag. A transfer hook moves the owner without resetting the bool, so "
        "the new owner inherits stale state - typically an unintended lock, "
        "stake credit, or reservation. Source: Munchables dirty-flag (slice_aa P48)."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
struct Asset { address owner; bool locked; }
mapping(uint256 => Asset) public assets;

function _update(address from, address to, uint256 id) internal {
    assets[id].owner = to;
    // BUG: assets[id].locked is not reset
}
```
1. Alice locks token #1 - `assets[1].locked = true`.
2. Alice transfers token #1 to Bob.
3. Bob now owns the token, but `locked` is still true → Bob can't unstake/
   transfer/use the token until Alice cooperates."""
    WIKI_RECOMMENDATION = (
        "In the transfer hook, explicitly reset every per-token bool flag "
        "(or migrate the corresponding state to the new owner). Better: "
        "store transient flags keyed by `(tokenId, owner)` so they reset "
        "automatically when ownership changes."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            for sv in contract.state_variables:
                struct = _struct_of_mapping(sv)
                if struct is None:
                    continue
                dirty_fields, owner_fields = _identify_struct_fields(struct)
                if not dirty_fields or not owner_fields:
                    continue
                dirty_set = set(dirty_fields)
                owner_set = set(owner_fields)

                for function in contract.functions_and_modifiers_declared:
                    if function.is_constructor:
                        continue
                    writes = _function_field_writes_for_sv(function, sv)
                    if not writes:
                        continue
                    # Must write at least one owner-style field …
                    if not (writes & owner_set):
                        continue
                    # … and must NOT touch any dirty-style field.
                    if writes & dirty_set:
                        continue

                    info: DETECTOR_INFO = [
                        function,
                        " in ",
                        contract,
                        " writes the owner field of struct mapping ",
                        sv,
                        " but does not reset the dirty/locked field(s) {",
                        ", ".join(sorted(dirty_fields)),
                        "}. New owner inherits stale state.\n",
                    ]
                    results.append(self.generate_result(info))

        return results
