"""
permanent_per_user_flag_dos.py - Custom Slither detector.

Pattern: A contract has a `mapping(address => bool) public <flag>` that gates
operations (transfer / claim / withdraw) via a require check. Some function
sets the flag to `true`, but NO function ever sets it back to `false`. Once a
user is flagged they are permanently locked out - there is no recovery path.

Source: Thorwallet M-01 (slice_ac).

Detection:
    1. Per contract, find every `mapping(address => bool)` state variable.
    2. For each such mapping, walk every function and identify constant-true
       and constant-false writes via Index → Assignment(rvalue=Constant(bool)).
    3. Confirm the mapping is used as a gate: at least one function reads it
       inside a require/assert/if condition.
    4. Flag the contract if there is at least one true-write and zero
       false-writes.

Confidence: MEDIUM. Modeled on partial_struct_write.py for the IR walk.

@author auditooor wave9
"""

import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract

from slither.core.solidity_types.elementary_type import ElementaryType
from slither.core.solidity_types.mapping_type import MappingType
from slither.core.variables.state_variable import StateVariable
from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.slithir.operations import Index, Assignment
from slither.slithir.variables import Constant, ReferenceVariable
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "deploy", "script", "setup")


def _is_address_to_bool_mapping(sv) -> bool:
    if not isinstance(sv, StateVariable):
        return False
    t = sv.type
    if not isinstance(t, MappingType):
        return False
    kt = t.type_from
    vt = t.type_to
    if not (isinstance(kt, ElementaryType) and kt.name == "address"):
        return False
    if not (isinstance(vt, ElementaryType) and vt.name == "bool"):
        return False
    return True


def _bool_writes_to_mapping(function, target_sv) -> tuple[bool, bool]:
    """Return (writes_true, writes_false) for the given mapping state var."""
    writes_true = False
    writes_false = False
    # ref_id -> bool (True if the Index IR pointed at target_sv)
    ref_to_target: dict[int, bool] = {}
    for node in function.nodes:
        for ir in node.irs:
            if isinstance(ir, Index):
                lv = ir.lvalue
                if not isinstance(lv, ReferenceVariable):
                    continue
                origin = lv.points_to_origin
                if origin is target_sv:
                    ref_to_target[id(lv)] = True
            elif isinstance(ir, Assignment):
                lv = ir.lvalue
                if not isinstance(lv, ReferenceVariable):
                    continue
                if not ref_to_target.get(id(lv)):
                    continue
                rv = ir.rvalue
                if isinstance(rv, Constant) and isinstance(rv.value, bool):
                    if rv.value:
                        writes_true = True
                    else:
                        writes_false = True
    return writes_true, writes_false


def _function_uses_mapping_as_gate(function, target_sv) -> bool:
    """Return True if the function reads target_sv inside a require/assert/if."""
    for node in function.nodes:
        if not (node.contains_require_or_assert() or node.contains_if()):
            continue
        if target_sv in node.state_variables_read:
            return True
    return False


class PermanentPerUserFlagDos(AbstractDetector):
    """Detect permanent / unrecoverable user-blacklist mappings."""

    ARGUMENT = "permanent-per-user-flag-dos"
    HELP = (
        "mapping(address => bool) gate is set true but never set false - "
        "users can be permanently locked out (no recovery path)"
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Permanent Per-User Flag - DoS"
    WIKI_DESCRIPTION = (
        "A contract gates user operations (transfer, claim, withdraw) on a "
        "`mapping(address => bool)` flag, sets the flag to `true` from at "
        "least one function, but never resets it to `false`. Any user who is "
        "ever flagged is permanently locked out - even if the trigger was "
        "accidental, a UI bug, or a malicious griefer with the gate. "
        "Source: Thorwallet M-01 (slice_ac)."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
mapping(address => bool) public blacklisted;

function flag(address u) external onlyOwner {
    blacklisted[u] = true;
}

function transfer(address to, uint256 a) external {
    require(!blacklisted[msg.sender], "flagged");
    // ... transfer
}
// no unflag()
```
1. Owner (or compromised key) calls `flag(victim)`.
2. `victim` cannot transfer or recover - the flag has no setter.
3. Even legitimate flags become permanent because there is no review path."""
    WIKI_RECOMMENDATION = (
        "Always pair `flag(...)` with `unflag(...)` (or expose a unified "
        "setter `setFlag(addr, bool)`). Consider time-bounded flags that "
        "expire automatically and an explicit recovery mechanism."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            flag_svs = [sv for sv in contract.state_variables if _is_address_to_bool_mapping(sv)]
            if not flag_svs:
                continue

            for flag_sv in flag_svs:
                any_true = False
                any_false = False
                gate_used = False
                true_writer = None
                for function in contract.functions_and_modifiers_declared:
                    if function.is_constructor:
                        continue
                    wt, wf = _bool_writes_to_mapping(function, flag_sv)
                    if wt and not true_writer:
                        true_writer = function
                    any_true = any_true or wt
                    any_false = any_false or wf
                    if _function_uses_mapping_as_gate(function, flag_sv):
                        gate_used = True

                if any_true and not any_false and gate_used:
                    info: DETECTOR_INFO = [
                        contract,
                        " sets ",
                        flag_sv,
                        " to true (e.g. in ",
                        true_writer,
                        ") and gates other functions on it, but no function "
                        "ever sets it back to false. Flagged users are "
                        "permanently locked out.\n",
                    ]
                    results.append(self.generate_result(info))

        return results
