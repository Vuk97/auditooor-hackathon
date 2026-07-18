"""
liquidation_partial_clear.py - Custom Slither detector.

Pattern: a liquidation/close function writes the literal 0 to a struct
field whose name suggests amount/size/value semantics, but does NOT reset
paired flag fields (isLong, isOpen, side, status, direction) on the same
struct to zero/false, and there is no `delete` of the whole struct entry.

Source: reference/corpus_mined/slice_ae.md - GTE Perps perpetuals exchange.
In that codebase, liquidate() zeroed position.amount but left position.isLong
set. The stale flag caused _close() to treat the zero-amount position as an
active long, triggering a revert that blocked every subsequent long position
opening for the same slot key.

Detection strategy (verified against IR probe, see workflow notes):

  1. Match functions whose lowercased name starts with one of:
       "liquidate", "forceclose", "closeposition", "close"
  2. For each such function, inspect f.state_variables_written. Keep only
     state vars whose type (possibly wrapped in MappingType/ArrayType) is a
     UserDefinedType backed by a Structure.
  3. Enumerate the structure's fields (struct.elems_ordered).
     Classify each field by name into AMOUNT set (amount, size, value, …)
     or FLAG set (isLong, isOpen, side, status, …).
  4. Walk every node's IR list:
       - Member IR: ir.variable_right.name gives the field name.
         Record: field_ref_id -> field_name.
       - Assignment IR with Constant(0 or False) rvalue: if lvalue id
         matches a known field_ref_id, record it as "written to zero".
       - Delete IR anywhere in the function: the developer used
         `delete positions[id]`, which clears ALL fields - skip the check.
  5. If:
       - at least one AMOUNT field was zeroed, AND
       - at least one FLAG field was NOT zeroed (missing from written set),
       - AND no Delete IR was found in the function
     → flag.

IR shapes (verified):
  positions[id].amount = 0;
    Index  REF_0(Position) -> positions[id]
    Member REF_1(uint256)  -> REF_0.amount   (variable_right = Constant("amount"))
    Assignment REF_1 := 0

  delete positions[id];
    Index  REF_0(Position) -> positions[id]
    Delete positions = delete REF_0

Gotchas:
  - Member.variable_right is a Constant whose .name is the field name string.
  - Assignment IR DOES exist in Slither (unlike what some older notes say) -
    confirmed by running the IR probe on these exact fixtures.
  - Delete IR is importable from slither.slithir.operations.
  - lvalue identity (id()) is stable within one function's IR walk.
  - State vars written across MULTIPLE nodes within the same function are all
    aggregated: we walk ALL nodes before making a judgment.
  - The "close" prefix is intentionally broad to catch closePosition,
    closeTrade, etc. False positives on e.g. closeVault() with a struct that
    has both size and status fields are possible but acceptable at HIGH/LOW.

Confidence: LOW - broad name prefix matching; operators should review
whether the flagged struct has meaningful state invariants.

@author auditooor
@pattern wave5 liquidation-partial-clear
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
from slither.slithir.operations import Member as MemberOp, Assignment, Delete
from slither.slithir.variables import Constant
from slither.core.solidity_types import UserDefinedType, MappingType, ArrayType
from slither.core.declarations import Structure
from slither.utils.output import Output


SKIP_KEYWORDS = ("test", "mock", "setup", "fixture", "helper", "deploy", "script")

# Function name prefixes that suggest a liquidation/close path.
# Lowercased for comparison.
_LIQUIDATE_PREFIXES = ("liquidate", "forceclose", "closeposition", "close")

# Struct field names (lowercased substrings) that indicate quantity / size.
# If any of these fields gets zeroed, we check whether the paired flags
# are also cleared.
_AMOUNT_HINTS: tuple[str, ...] = (
    "amount",
    "size",
    "value",
    "qty",
    "quantity",
    "balance",
    "notional",
    "principal",
    "collateral",
)

# Struct field names (lowercased substrings / prefixes) that represent
# directional or status flags.  If these are NOT cleared when an AMOUNT
# field is zeroed, we flag.
_FLAG_HINTS: tuple[str, ...] = (
    "islong",
    "isopen",
    "isactive",
    "isliquidat",
    "side",
    "status",
    "direction",
    "state",
    "flag",
    "active",
    "open",
    "long",
    "short",
    "type",
)


def _name_matches_any(name: str, hints: tuple[str, ...]) -> bool:
    """Return True if the field name contains or starts with any hint."""
    low = name.lower()
    return any(h in low for h in hints)


def _get_struct(tp) -> "Structure | None":
    """
    Walk through MappingType/ArrayType wrappers to find an underlying Structure.
    Returns None if the type is not struct-based.
    """
    for _ in range(6):
        if isinstance(tp, UserDefinedType) and isinstance(tp.type, Structure):
            return tp.type
        if isinstance(tp, MappingType):
            tp = tp.type_to
        elif isinstance(tp, ArrayType):
            tp = tp.type
        else:
            break
    return None


def _func_name_is_liquidation(name: str) -> bool:
    """Return True if the function name starts with a liquidation/close prefix."""
    low = name.lower()
    return any(low.startswith(p) for p in _LIQUIDATE_PREFIXES)


def _check_function(function) -> "tuple[bool, str, str] | None":
    """
    Inspect a single function for the partial-clear pattern.

    Returns (struct_var_name, amount_fields_zeroed, missing_flag_fields)
    tuple if a bug is found, else None.
    """
    # Step 1: find struct-typed state vars written by this function
    struct_svs: dict = {}
    for sv in function.state_variables_written:
        struct = _get_struct(sv.type)
        if struct is not None:
            struct_svs[sv] = struct

    if not struct_svs:
        return None

    # Step 2: walk IR across all nodes in the function
    #   Build: member_ref_id -> field_name  (from Member IR)
    #   Track: fields_zeroed (set of field names given Assignment(0/false))
    #   Track: has_delete (Delete IR = full struct clear → safe)
    member_ref_to_field: dict[int, str] = {}
    fields_zeroed: set[str] = set()
    has_delete = False

    for node in function.nodes:
        for ir in node.irs:
            if isinstance(ir, Delete):
                has_delete = True
                break  # no need to keep scanning once we see delete

            if isinstance(ir, MemberOp):
                field_ref = ir.variable_right          # Constant whose .name = field name
                field_name = getattr(field_ref, "name", None)
                if field_name:
                    member_ref_to_field[id(ir.lvalue)] = field_name

            elif isinstance(ir, Assignment):
                lv = ir.lvalue
                rv = getattr(ir, "rvalue", None)
                if isinstance(rv, Constant):
                    val = rv.value
                    if val == 0 or val is False:
                        field_name = member_ref_to_field.get(id(lv))
                        if field_name is not None:
                            fields_zeroed.add(field_name)

        if has_delete:
            break

    if has_delete:
        return None

    # Step 3: for each struct-bearing state var, classify fields and check
    for sv, struct in struct_svs.items():
        all_fields = {e.name for e in struct.elems_ordered}
        amount_fields = {fn for fn in all_fields if _name_matches_any(fn, _AMOUNT_HINTS)}
        flag_fields = {fn for fn in all_fields if _name_matches_any(fn, _FLAG_HINTS)}

        # Ignore structs with no flag fields - nothing to miss
        if not flag_fields:
            continue

        zeroed_amounts = fields_zeroed & amount_fields
        zeroed_flags = fields_zeroed & flag_fields
        missing_flags = flag_fields - zeroed_flags

        if zeroed_amounts and missing_flags:
            return sv, sorted(zeroed_amounts), sorted(missing_flags)

    return None


class LiquidationPartialClear(AbstractDetector):
    """
    Detect liquidation/close functions that zero an amount/size field but
    leave paired flag fields (isLong, isOpen, side, status) unreset.
    """

    ARGUMENT = "liquidation-partial-clear"
    HELP = (
        "Liquidation/close function zeroes amount/size field but leaves "
        "isLong/isOpen/side/status unreset on the same struct"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW   # broad prefix matching

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Partial Struct Clear in Liquidation Path"
    WIKI_DESCRIPTION = (
        "A liquidation or close function zeros the amount/size/value field of "
        "a position struct but leaves directional or status flag fields "
        "(isLong, isOpen, side, status) at their pre-liquidation values. "
        "Any subsequent code that checks the flag before inspecting the amount "
        "will treat the zero-amount entry as an active position, causing "
        "unexpected reverts or re-execution on a ghost position. "
        "This exact pattern was observed in GTE Perps: liquidate() set "
        "position.amount = 0 but left position.isLong, causing _close() to "
        "revert on the zero-amount entry and blocking new long position openings."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
struct Position { uint256 amount; bool isLong; address owner; }
mapping(bytes32 => Position) public positions;

function liquidate(bytes32 id) external {
    positions[id].amount = 0;
    // BUG: isLong is NOT reset
}

function openLong(bytes32 id) external {
    Position storage p = positions[id];
    if (p.isLong) {          // stale true - amount is 0 but flag persists
        _close(p);           // _close sees amount==0, reverts
    }
    // new long is never opened - DoS
}
```
1. Alice's position is liquidated: `positions[id].amount = 0`, `isLong` left as `true`.
2. Bob calls `openLong(id)` for the same slot key.
3. `_close(p)` is invoked on the stale `isLong=true` entry.
4. `_close` reverts because `amount == 0` - zero-size position cannot be closed.
5. Every subsequent `openLong(id)` call reverts, effectively DoS-ing that slot."""
    WIKI_RECOMMENDATION = (
        "Use `delete positions[id]` to atomically reset all struct fields to "
        "their zero values, or explicitly assign every field (amount, isLong, "
        "side, status, owner) to its zero value before returning from the "
        "liquidation path. Never partially clear a struct whose flag fields "
        "affect downstream control flow."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in SKIP_KEYWORDS):
                continue

            for function in contract.functions_and_modifiers_declared:
                if not _func_name_is_liquidation(function.name):
                    continue

                finding = _check_function(function)
                if finding is None:
                    continue

                sv, zeroed_amounts, missing_flags = finding
                info: DETECTOR_INFO = [
                    function,
                    " zeros struct field(s) [",
                    ", ".join(zeroed_amounts),
                    "] on state variable ",
                    sv,
                    " but does NOT reset flag field(s) [",
                    ", ".join(missing_flags),
                    "]. Stale flags on a zero-amount position cause reverts in "
                    "downstream close/open paths - use `delete` or reset all fields.\n",
                ]
                results.append(self.generate_result(info))

        return results
