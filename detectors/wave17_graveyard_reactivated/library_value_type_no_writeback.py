"""
library_value_type_no_writeback.py - Custom Slither detector.

ARG: library-value-type-no-writeback
IMPACT: MEDIUM
CONFIDENCE: MEDIUM

Pattern (P26): A library function takes a struct as a `memory` (value-type)
parameter instead of a `storage` reference. When the function body assigns to
a field of that struct parameter, the mutation happens on a local copy - it has
no effect on the caller's storage. The caller that invokes the library via
`using LibX for Struct` expects in-place mutation, but the state is unchanged.

Source: reference/corpus_mined/slice_ad.md - Concrete audit,
LibraryMemoryCopyNotWriteback. Variant of Glider
`contract-updates-a-memory-copy.py` but specialized for library function
parameters (not `this`-field copies).

IR patterns verified on fixture:
  - Library contract: `c.is_library == True`
  - Parameter: `p.location == "memory"` AND `isinstance(p.type, UserDefinedType)`
    (UserDefinedType means it's a struct, not a primitive)
  - Body IR: `Member` IR with `lvalue` being a `ReferenceVariable` whose
    `points_to_origin` is that memory parameter → followed by a `Binary` IR
    that writes back to the same `ReferenceVariable` (lvalue is the same ref).
    This represents `d.counter += 1` which in SSA is:
      Member:  REF_0(uint256) -> d.counter
      Binary:  REF_0(-> d) = REF_0 (c)+ 1   ← assignment to the ref (memory local)

  - Clean: `p.location == "storage"` - the same pattern writes to storage.

Detection logic:
  1. Iterate all library contracts (`c.is_library == True`).
  2. For each declared function, find parameters with `location == "memory"`
     that have a `UserDefinedType` (struct).
  3. In the function's nodes/IRs, look for `Member` IRs where the struct being
     accessed (`ir.variable_left`) is one of those memory parameters (or a
     reference derived from them). Then check if the resulting ReferenceVariable
     is subsequently written (appears as lvalue in a Binary or Assignment IR).
  4. If any such write is found → flag the function + parameter.

Approximation notes:
  - We detect write-through-ref-derived-from-memory-param. This reliably catches
    `d.counter += 1` and `d.amount = v` patterns.
  - We do NOT track whether the mutation is eventually returned as a value. A
    function that returns the mutated struct (instead of using storage ref) is a
    valid pattern in some contexts but is still flagged - the `using lib for Type`
    call-site never captures the return value so the mutation is still lost.
    CONFIDENCE MEDIUM accounts for this.
  - Library functions with `calldata` structs are also skipped (location == "calldata"
    is trivially read-only).

@author auditooor wave6
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
from slither.slithir.operations import Member, Binary, Assignment
from slither.slithir.variables import ReferenceVariable
from slither.core.solidity_types import UserDefinedType
from slither.utils.output import Output


SKIP_KEYWORDS = ("test", "mock", "setup", "fixture", "helper", "deploy", "script")


def _function_mutates_memory_struct_param(function):
    """
    Return a list of (parameter, node) pairs where `parameter` is a memory
    UserDefinedType (struct) param and `node` is the node where the mutation
    occurs.

    Strategy:
    1. Collect all memory-struct parameters by name into a set.
    2. Walk IR: for each Member IR, check if `ir.variable_left` is one of
       those parameters (direct match).
    3. Record the resulting ReferenceVariable (lvalue of the Member IR).
    4. For each subsequent IR in the same node: if it's a Binary or generic IR
       whose lvalue is that same ReferenceVariable → mutation confirmed.

    Note: Slither represents `d.counter += 1` as:
      Member:  REF_N(T) -> d.counter        ← creates ref
      Binary:  REF_N(-> d) = REF_N (c)+ 1  ← writes back via same ref

    Both IRs appear in the same node. We detect the Binary write-back to a ref
    that came from a memory-param Member access.
    """
    # Collect memory struct params: name -> param object
    memory_struct_params: dict[str, object] = {}
    for p in function.parameters:
        if p.location != "memory":
            continue
        if not isinstance(p.type, UserDefinedType):
            continue
        memory_struct_params[p.name] = p

    if not memory_struct_params:
        return []

    hits = []

    for node in function.nodes:
        # Within a node, track refs created from memory-param Member accesses.
        # ref_id -> param
        param_refs: dict[int, object] = {}

        for ir in node.irs:
            if isinstance(ir, Member):
                lv = ir.lvalue
                if not isinstance(lv, ReferenceVariable):
                    continue
                # ir.variable_left is the struct being accessed.
                var_left = ir.variable_left
                if var_left is None:
                    continue
                param_name = getattr(var_left, "name", None)
                if param_name and param_name in memory_struct_params:
                    param_refs[id(lv)] = memory_struct_params[param_name]

            elif (isinstance(ir, Binary) or isinstance(ir, Assignment)):
                lv = getattr(ir, "lvalue", None)
                if lv is None:
                    continue
                if not isinstance(lv, ReferenceVariable):
                    continue
                if id(lv) in param_refs:
                    # Found a write to a ref derived from a memory-struct param.
                    param = param_refs[id(lv)]
                    hits.append((param, node))
                    # Don't break - report all occurrences for different params.

    return hits


class LibraryValueTypeNoWriteback(AbstractDetector):
    """
    Detect library functions that take a struct as a value-type (memory) parameter
    and mutate it - the mutation is lost since it operates on a local copy.
    """

    ARGUMENT = "library-value-type-no-writeback"
    HELP = "Library function mutates a memory (value-type) struct param - mutation lost"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Library Value-Type Struct Mutation - No Write-Back"
    WIKI_DESCRIPTION = (
        "A library function that receives a struct as a `memory` (value-type) parameter "
        "and assigns to its fields is mutating a local copy. The caller's storage is never "
        "updated. This pattern is often introduced when a Solidity library function is "
        "written with the incorrect data location keyword: using `memory` instead of "
        "`storage` for a struct that the caller expects to be modified in-place. "
        "Observed in the Concrete audit (LibraryMemoryCopyNotWriteback): "
        "`emergencyRemoveStrategy` passed `protectStrategy` as a value copy to a "
        "library function that cleared it locally - the state variable was unchanged."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
struct Data { uint256 counter; }

library DataLib {
    // BUG: 'memory' means a local copy - d.counter += 1 has no effect on caller
    function bump(Data memory d) internal {
        d.counter += 1;
    }
}

contract Counter {
    using DataLib for Data;
    Data public myData;   // myData.counter stays 0 forever

    function increment() external {
        myData.bump();    // calls DataLib.bump(myData) with a copy - no write-back
    }
}
```
Caller invokes `increment()` expecting `myData.counter` to grow. Because
`bump` receives a `memory` copy, the increment is discarded and
`myData.counter` remains 0 after any number of calls."""
    WIKI_RECOMMENDATION = (
        "Change the struct parameter data location from `memory` to `storage` "
        "in the library function: `function bump(Data storage d) internal { d.counter += 1; }`. "
        "If the function must remain pure/view, have it return the mutated struct and "
        "explicitly assign the return value at the call site: "
        "`myData = DataLib.bump(myData);`."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if not contract.is_library:
                continue
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in SKIP_KEYWORDS):
                continue

            for function in contract.functions_and_modifiers_declared:
                hits = _function_mutates_memory_struct_param(function)
                for param, node in hits:
                    info: DETECTOR_INFO = [
                        "Library function ",
                        function,
                        " in ",
                        contract,
                        " mutates field of struct parameter `",
                        param.name,
                        "` (location: memory) - the caller's storage is not updated. "
                        "Change parameter location to `storage` or return the mutated value.",
                        "\n",
                        node,
                        "\n",
                    ]
                    results.append(self.generate_result(info))

        return results
