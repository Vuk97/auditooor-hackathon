"""
library_memory_copy_not_writeback.py — Custom Slither detector (wave18).

ARG: library-memory-copy-not-writeback
IMPACT: HIGH
CONFIDENCE: MEDIUM

Pattern: a Solidity library function takes a struct or array as a `memory`
parameter, mutates fields of that copy in its body (and may return the
mutated value), and the caller passes a state variable into that helper but
neither captures the return value into the same state slot nor uses a
storage-reference variant. Because Solidity copies state into memory at the
call site, the mutations are silently lost.

Source seed:
  reference/solodit_corpus_gaps.json -> wave_8_candidates_top_tier ->
  "library-memory-copy-not-writeback" (slice ad Concrete + slice af Maia DAO,
  HIGH, ★★★).
  reference/corpus_mined/NOVELS_UNPORTED.md (entry #6, HIGH).

Why hand-written / Slither IR instead of DSL (Codex W5 ★★★ call):
  The DSL companion (reference/patterns.dsl/library-memory-copy-not-writeback.yaml,
  status documentation-only) only has source-text regex predicates. To suppress
  false positives we need to reason about:
    1. The library function's parameter data location (`memory` vs `storage`)
       and the IR that mutates a struct/array field of that parameter.
    2. The caller-site IR — specifically a `LibraryCall` whose argument is a
       `StateVariable` AND whose `lvalue` (if any) is not subsequently
       assigned back into a state slot.
  Both items require Slither's IR (Member/Binary/Assignment IRs +
  LibraryCall.arguments + lvalue tracking), which the DSL preconditions cannot
  express. Hand-written IR analysis is the right granularity.

Companion detector:
  detectors/wave17_graveyard_reactivated/library_value_type_no_writeback.py
  flags the *library* side (memory-struct-param mutation). This wave18
  detector flags the *caller* side: places where the bug actually manifests.
  Combining both raises confidence when they fire on the same library.

IR shapes verified against fixtures:

  Vulnerable library MyLib.update(S memory s) returns (S memory):
    function MyLib.update(S):
      Member: REF_0 -> s.field    (s = memory param)
      Assignment: REF_0 := 1      (writes back via the reference)
      Return: s

  Vulnerable caller `MyLib.update(state);` (return discarded):
    LibraryCall: TMP_0(S) = LIBRARY_CALL, dest=MyLib, fn=update(S), args=[state]
      lvalue=TMP_0, but TMP_0 never used as rvalue of an Assignment whose
      lvalue is a StateVariable.

  Vulnerable caller `MyLib.bumpVoid(state);` (returns nothing):
    LibraryCall: lvalue=None.

  Clean caller `state = ReturnLib.update(state);`:
    LibraryCall: TMP_1(S) = LIBRARY_CALL, args=[state]
    Assignment: state := TMP_1   ← write-back; suppresses the flag.

  Clean lib `StorageLib.update(S storage s)`:
    Library function parameter location is "storage", so no memory copy
    happens — the lib is excluded from the muting-libs set entirely.

Detection logic:
  1. First pass — build the set of (library_contract, library_function)
     where the function has at least one `memory` struct/array parameter
     that is mutated inside the body. Mutation = a Member IR pulls a
     ReferenceVariable off that parameter, then a Binary or Assignment IR
     writes through the same ReferenceVariable.
  2. Second pass — for each non-library contract, walk all functions and
     their IRs. For each `LibraryCall` whose target is in the muting-libs
     set AND that passes a `StateVariable` as an argument: check whether
     the lvalue is assigned back to a state slot in the same function.
     If not, flag the call site.

False-positive suppression:
  - Skip vendored/test contracts (is_vendored_or_test_contract).
  - Skip contracts/functions whose names look like mock/test/setup helpers.
  - Skip library functions whose mutated param has location `storage`
     (those are the safe variant).
  - Storage-vs-memory disambiguation at the call site: skip library calls
     whose first argument is a storage reference (LocalVariable with
     `location == "storage"`). Mutations through a storage reference persist
     in place; not the bug class. This is the symmetric call-site check that
     pairs with the lib-function-side filter on parameter location.
  - Flaggable first arguments: StateVariable (state copied to memory at lib
     boundary, mutation lost) OR LocalVariable with `location == "memory"`
     (caller's memory copy mutated by lib and discarded).
  - Skip calls where the lvalue flows into an Assignment whose lvalue is a
     StateVariable. Conservative: we trace one level (TMP -> Assignment to
     state). Re-aliased writes are out of scope (CONFIDENCE MEDIUM).

@author auditooor wave18
@pattern library-memory-copy-not-writeback
"""

import sys as _sys
from pathlib import Path as _Path

_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract  # noqa: E402

from slither.detectors.abstract_detector import (  # noqa: E402
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.slithir.operations import (  # noqa: E402
    Assignment,
    Binary,
    LibraryCall,
    Member,
)
from slither.slithir.variables import (  # noqa: E402
    ReferenceVariable,
    TemporaryVariable,
)
from slither.core.variables.state_variable import StateVariable  # noqa: E402
from slither.core.variables.local_variable import LocalVariable  # noqa: E402
from slither.core.solidity_types import (  # noqa: E402
    UserDefinedType,
    ArrayType,
)
from slither.utils.output import Output  # noqa: E402


SKIP_KEYWORDS = (
    "test",
    "mock",
    "setup",
    "fixture",
    "helper",
    "deploy",
    "script",
)


def _is_struct_or_array_type(t) -> bool:
    """Mutation-prone parameter types: structs (UserDefinedType) and arrays."""
    if t is None:
        return False
    if isinstance(t, UserDefinedType):
        return True
    if isinstance(t, ArrayType):
        return True
    return False


def _library_function_mutates_memory_param(function):
    """Return True iff *function* has a memory struct/array parameter that is
    mutated (member assignment) inside its body.

    Memory copy semantics in Solidity:
      - `memory` location: caller's storage is copied; mutations are local.
      - `storage` location: in-place reference; mutations persist.
      - `calldata` location: read-only; no mutation possible.
    """
    if function is None:
        return False
    # Pure / view functions cannot mutate state, but they can return a mutated
    # memory copy — if the caller ignores the return that's the bug. We do
    # NOT exclude pure/view here.
    memory_struct_or_array_params: dict[str, object] = {}
    for p in function.parameters:
        loc = getattr(p, "location", None)
        if loc != "memory":
            continue
        if not _is_struct_or_array_type(p.type):
            continue
        memory_struct_or_array_params[p.name] = p

    if not memory_struct_or_array_params:
        return False

    for node in function.nodes:
        # Track refs created from a target memory-param in this node.
        param_refs: dict[int, object] = {}
        for ir in node.irs:
            if isinstance(ir, Member):
                lv = ir.lvalue
                if not isinstance(lv, ReferenceVariable):
                    continue
                var_left = ir.variable_left
                if var_left is None:
                    continue
                pname = getattr(var_left, "name", None)
                if pname and pname in memory_struct_or_array_params:
                    param_refs[id(lv)] = memory_struct_or_array_params[pname]
            elif isinstance(ir, (Binary, Assignment)):
                lv = getattr(ir, "lvalue", None)
                if isinstance(lv, ReferenceVariable) and id(lv) in param_refs:
                    return True
    return False


def _build_muting_lib_funcs(slither_contracts) -> set:
    """Return the set of library Function objects whose body mutates a memory
    struct/array parameter. Used as a quick lookup at call sites."""
    muting: set = set()
    for c in slither_contracts:
        if not getattr(c, "is_library", False):
            continue
        if is_vendored_or_test_contract(c):
            continue
        if any(k in c.name.lower() for k in SKIP_KEYWORDS):
            continue
        for f in c.functions_and_modifiers_declared:
            if _library_function_mutates_memory_param(f):
                muting.add(f)
    return muting


def _first_arg_is_storage_bound(call: LibraryCall) -> bool:
    """Return True iff the implicit `self` (first) argument of the library
    call is a storage reference rather than a memory copy.

    The bug class only applies when the lib parameter is `memory` AND the
    caller's value is copied into that parameter. If the call's first arg is
    a `LocalVariable` whose data location is `storage`, then the call is
    bound to a storage reference and any mutations the lib performs through
    that reference persist — NOT the bug class.

    The lib-function side (parameter location `storage` vs `memory`) is
    already filtered in `_library_function_mutates_memory_param`. This helper
    is the symmetric call-site disambiguation: it catches cases where the
    callee's parameter signals memory but the caller's argument is itself a
    storage reference (e.g., `using L for X` invoked through a struct that
    Slither models with `location == "storage"`).
    """
    args = getattr(call, "arguments", []) or []
    if not args:
        return False
    first = args[0]
    # LocalVariable with explicit storage location: a `Foo storage` local
    # reference. Mutations go through the underlying slot — not the bug class.
    if isinstance(first, LocalVariable):
        loc = getattr(first, "location", None)
        if loc == "storage":
            return True
    return False


def _flaggable_first_arg(call: LibraryCall):
    """Return the receiver argument of *call* if it is a candidate for
    flagging, or None.

    Two callable shapes count as candidates:
      1. `StateVariable` of struct/array type — caller passed state directly,
         Solidity copies state→memory at the lib boundary, mutation lost.
      2. `LocalVariable` of struct/array type with data location `memory` —
         caller passed a memory copy that the lib mutates and returns; if the
         caller does not capture/use the return, the mutation is lost.

    Storage-bound first arguments (LocalVariable with `location == "storage"`)
    are NOT flaggable: those are storage references, mutations propagate.
    See `_first_arg_is_storage_bound`.
    """
    args = getattr(call, "arguments", []) or []
    if not args:
        return None
    first = args[0]
    t = getattr(first, "type", None)
    if not _is_struct_or_array_type(t):
        return None
    if isinstance(first, StateVariable):
        return first
    if isinstance(first, LocalVariable):
        loc = getattr(first, "location", None)
        # Only memory-bound locals are candidates; storage-bound locals are
        # storage references (mutations persist) and calldata is read-only.
        if loc == "memory":
            return first
    return None


def _lvalue_written_back_to_state(call: LibraryCall, function) -> bool:
    """Return True if the call's lvalue is later assigned back into a state
    slot inside *function*.

    Conservative — we only trace one level: lvalue (TemporaryVariable) read
    by an Assignment whose lvalue is a StateVariable, or by a Member/Index IR
    that resolves into a StateVariable-rooted reference.
    """
    lv = getattr(call, "lvalue", None)
    if lv is None:
        return False
    if not isinstance(lv, TemporaryVariable):
        return False

    target_id = id(lv)
    for node in function.nodes:
        for ir in node.irs:
            # Direct: state = TMP
            if isinstance(ir, Assignment):
                rv = getattr(ir, "rvalue", None)
                lv2 = getattr(ir, "lvalue", None)
                if rv is None or lv2 is None:
                    continue
                if id(rv) == target_id:
                    # rvalue is our temp; check if the lvalue ultimately
                    # corresponds to a state slot.
                    if isinstance(lv2, StateVariable):
                        return True
                    # It might be a ReferenceVariable rooted in state; trace
                    # via points_to_origin if available.
                    pto = getattr(lv2, "points_to_origin", None)
                    if isinstance(pto, StateVariable):
                        return True
    return False


class LibraryMemoryCopyNotWriteback(AbstractDetector):
    """Caller passes a state variable to a library helper whose `memory`
    parameter gets mutated inside the lib, but the caller never writes the
    helper's result back to storage. Mutations are silently dropped."""

    ARGUMENT = "library-memory-copy-not-writeback"
    HELP = (
        "Library helper mutates a memory copy of a state variable; caller "
        "never writes the result back to storage — mutations are lost."
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = (
        "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/"
        "library-memory-copy-not-writeback.yaml"
    )
    WIKI_TITLE = (
        "Library helper mutates memory copy, caller never writes back"
    )
    WIKI_DESCRIPTION = (
        "Solidity libraries that operate on structs or arrays passed by "
        "`memory` produce a mutated local copy. If the helper returns the "
        "updated value but the caller does not assign the result back to a "
        "state slot, the mutations are silently dropped when the function "
        "returns. The caller's state appears unchanged even though the "
        "library code looks correct in isolation."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "```solidity\n"
        "struct S { uint256 field; }\n"
        "library MyLib {\n"
        "    function update(S memory s) internal pure returns (S memory) {\n"
        "        s.field = 1;\n"
        "        return s;\n"
        "    }\n"
        "}\n"
        "contract C {\n"
        "    S public state;\n"
        "    function bad() external {\n"
        "        // BUG: state is copied to memory, mutated, returned;\n"
        "        // the caller throws the return value away.\n"
        "        MyLib.update(state);\n"
        "    }\n"
        "}\n"
        "```\n"
        "Found in slice ad Concrete (LibraryMemoryCopyNotWriteback) and "
        "slice af Maia DAO (EnumerableMap-style helper)."
    )
    WIKI_RECOMMENDATION = (
        "Either (a) change the library parameter location to `storage` so "
        "mutations persist in place, or (b) capture the helper's return "
        "value at the call site and assign it back to the state slot: "
        "`state = MyLib.update(state);`. Returning a struct/array but "
        "discarding the return value is almost always a mistake; consider "
        "marking the helper `internal returns (...)` and treating an "
        "ignored return as a compile-time warning."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        muting_lib_funcs = _build_muting_lib_funcs(self.contracts)
        if not muting_lib_funcs:
            return results

        for contract in self.contracts:
            if getattr(contract, "is_library", False):
                # We flag the *caller*, not the lib itself. The companion
                # detector library_value_type_no_writeback covers the lib side.
                continue
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in SKIP_KEYWORDS):
                continue

            for function in contract.functions_and_modifiers_declared:
                if any(k in function.name.lower() for k in SKIP_KEYWORDS):
                    continue
                for node in function.nodes:
                    for ir in node.irs:
                        if not isinstance(ir, LibraryCall):
                            continue
                        callee = getattr(ir, "function", None)
                        if callee is None or callee not in muting_lib_funcs:
                            continue
                        # Storage-vs-memory disambiguation at the call site:
                        # if the receiver is a storage reference (LocalVariable
                        # with location='storage'), mutations persist through
                        # that reference — NOT the bug class. Skip.
                        if _first_arg_is_storage_bound(ir):
                            continue
                        flag_arg = _flaggable_first_arg(ir)
                        if flag_arg is None:
                            continue
                        if _lvalue_written_back_to_state(ir, function):
                            continue

                        info: DETECTOR_INFO = [
                            "Library call ",
                            node,
                            " in ",
                            function,
                            " (contract ",
                            contract,
                            ") passes `",
                            flag_arg.name,
                            "` to ",
                            callee,
                            ", whose `memory` parameter is mutated inside "
                            "the library. The return value (if any) is "
                            "discarded, so the mutations are lost. Either "
                            "make the library parameter `storage` or assign "
                            "the return value back to the state slot.\n",
                        ]
                        results.append(self.generate_result(info))

        return results
