"""
interface_function_not_in_impl.py — Custom Slither detector.

Pattern (Zellic slice_aa LID-17, HIGH): A contract makes a HighLevelCall through
an interface (`IFoo(addr).missingFunction()`) where the called function is
declared in the interface but NO non-interface contract in the same compilation
unit implements that signature. At runtime the call always reverts because no
concrete contract exposes the function selector.

Detection strategy:
    1. Collect the set of `solidity_signature` strings declared by every
       non-interface contract in the compilation unit (implementations).
    2. Walk `HighLevelCall` IRs where `ir.function.contract.is_interface == True`.
    3. If the call's `solidity_signature` does not appear in the implementation
       set, flag the call.

This mirrors the approximation mandated by the bug ticket: within the same
source file, a cast to `IFoo` and a method that no concrete contract declares
is almost always a wiring bug.

@author auditooor wave8
@pattern slice_aa LID-17
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
from slither.core.declarations import Function
from slither.core.variables.state_variable import StateVariable
from slither.slithir.operations import HighLevelCall, Assignment, TypeConversion
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")


def _destination_touches_immutable(ir: HighLevelCall, function) -> bool:
    """
    Return True if the call destination variable traces back (in the same
    function) to an `immutable` state variable. This is the SKILL_ISSUE #44
    escape hatch: external integration adapters route calls through an
    immutable constructor-assigned state var, and the local compilation
    unit never sees the concrete impl. Treat those as integration points
    rather than missing-impl bugs.
    """
    dest = getattr(ir, "destination", None)
    if dest is None:
        return False

    # If the destination is itself an immutable state var, done.
    if isinstance(dest, StateVariable) and getattr(dest, "is_immutable", False):
        return True

    # Walk temporaries / locals back through Assignments and TypeConversions
    # within the same function until we either hit an immutable state var or
    # run out of producers.
    seen = set()
    frontier = [dest]
    while frontier:
        cur = frontier.pop()
        cid = id(cur)
        if cid in seen:
            continue
        seen.add(cid)
        if isinstance(cur, StateVariable) and getattr(cur, "is_immutable", False):
            return True
        for node in function.nodes:
            for n_ir in node.irs:
                lv = getattr(n_ir, "lvalue", None)
                if lv is None or id(lv) != cid:
                    continue
                if isinstance(n_ir, Assignment):
                    rv = getattr(n_ir, "rvalue", None)
                    if rv is not None:
                        frontier.append(rv)
                elif isinstance(n_ir, TypeConversion):
                    var = getattr(n_ir, "variable", None)
                    if var is not None:
                        frontier.append(var)
    return False


class InterfaceFunctionNotInImpl(AbstractDetector):
    """Detect interface-typed calls whose signature is implemented by no concrete contract."""

    ARGUMENT = "interface-function-not-in-impl"
    HELP = (
        "HighLevelCall through an interface to a function not implemented "
        "by any concrete contract in the compilation unit — always reverts"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Interface Function Not Implemented by Concrete Contract"
    WIKI_DESCRIPTION = (
        "Calling `IFoo(addr).bar()` requires the concrete contract at `addr` to "
        "expose the selector for `bar()`. When the interface declares a function "
        "that no non-interface contract in the same compilation unit implements, "
        "the call reverts at runtime. This is almost always a copy/paste or "
        "stale-interface bug that bricks the feature the caller is trying to use."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
interface IWQ { function getStatus(uint256) external view returns (uint8); }
contract WQ { /* forgot to implement getStatus */ }
contract Caller {
    IWQ public wq;
    function check(uint256 id) external view returns (uint8) {
        return wq.getStatus(id); // always reverts
    }
}
```
Any call to `Caller.check()` reverts because WQ exposes no `getStatus` selector."""
    WIKI_RECOMMENDATION = (
        "Ensure the concrete contract referenced by the interface declares the "
        "same function. Prefer compiling against the concrete type or adding "
        "an integration test that exercises the call path."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        # Build set of implemented function signatures across all non-interface
        # contracts in the compilation unit.
        implemented: set[str] = set()
        for contract in self.contracts:
            if contract.is_interface:
                continue
            for f in contract.functions:
                sig = getattr(f, "solidity_signature", None)
                if sig:
                    implemented.add(sig)

        for contract in self.contracts:
            if contract.is_interface:
                continue
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            for function in contract.functions_and_modifiers_declared:
                for node in function.nodes:
                    for ir in node.irs:
                        if not isinstance(ir, HighLevelCall):
                            continue
                        callee = ir.function
                        if not isinstance(callee, Function):
                            continue
                        callee_contract = getattr(callee, "contract", None)
                        if callee_contract is None:
                            continue
                        if not getattr(callee_contract, "is_interface", False):
                            continue
                        sig = getattr(callee, "solidity_signature", None)
                        if not sig:
                            continue
                        if sig in implemented:
                            continue

                        # SKILL_ISSUE #44: external integration adapters
                        # route calls through an immutable constructor-
                        # assigned state var. The concrete impl lives in a
                        # different repo and is invisible to the local CU.
                        if _destination_touches_immutable(ir, function):
                            continue

                        info: DETECTOR_INFO = [
                            function,
                            " calls ",
                            callee,
                            " via interface ",
                            callee_contract,
                            " at ",
                            node,
                            " but no non-interface contract in this compilation "
                            "unit implements that signature — call will always revert.\n",
                        ]
                        results.append(self.generate_result(info))

        return results
