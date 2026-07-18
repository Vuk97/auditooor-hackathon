"""
storage_flag_before_internal_guard.py - Custom Slither detector.

Pattern (slice_ag - Spectral Modelers, CRITICAL):
    `isValRegistered[sender] = true` is written BEFORE calling the
    helper `addValidatorRewardList`. The helper reads
    `isValRegistered[user]` as its guard:
        if (isValRegistered[user]) return;
    Because the flag was just set, the helper early-returns; the
    MAX_VALIDATORS capacity check and `validatorAddresses.push` NEVER
    run. Anyone can register arbitrarily many validators.

Detection strategy:
    1. For each caller function, locate a state-variable write where
       the RHS is the Constant `True` (flag toggled on).
    2. In a later node of the SAME function, locate an InternalCall.
    3. Inside the callee's body, check that the callee reads the same
       state variable AND contains a RETURN node guarded by an IF that
       reads that state variable. (We approximate by asking whether any
       callee node is NodeType.RETURN *and* the function's body
       references the SV in a Condition IR.)
    4. If all three hold → flag.

Confidence: MEDIUM. The state-var identity match plus the callee's
IF+RETURN over that variable is a sharp pattern. We do not check that
the caller's write and the callee's read share the exact mapping index
- this is acceptable because the bug is present whenever the flag's
semantics are "set before guarded callee runs".
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
from slither.core.cfg.node import NodeType
from slither.core.variables.state_variable import StateVariable
from slither.slithir.operations import (
    Assignment,
    InternalCall,
    Condition,
    Index,
)
from slither.slithir.variables import Constant, ReferenceVariable
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "setup", "fixture", "helper", "deploy", "script")


def _find_true_flag_writes(function):
    """
    Return list of (node_index, StateVariable) for every write where
    a state variable (possibly via mapping index) is assigned Constant True.
    """
    out = []
    for idx, node in enumerate(function.nodes):
        # Build REF -> StateVariable map from Index IRs within this node
        ref_to_sv: dict[int, StateVariable] = {}
        for ir in node.irs:
            if isinstance(ir, Index):
                base = getattr(ir, "variable_left", None)
                if isinstance(base, StateVariable):
                    ref_to_sv[id(ir.lvalue)] = base
        # Look for Assignment of True
        for ir in node.irs:
            if not isinstance(ir, Assignment):
                continue
            rv = getattr(ir, "rvalue", None)
            if not isinstance(rv, Constant):
                continue
            val = getattr(rv, "value", None)
            if not (val is True or str(val).lower() == "true"):
                continue
            lv = ir.lvalue
            if isinstance(lv, StateVariable):
                out.append((idx, lv))
            elif isinstance(lv, ReferenceVariable):
                sv = ref_to_sv.get(id(lv))
                if sv is not None:
                    out.append((idx, sv))
    return out


def _callee_early_returns_on_sv(callee, sv: StateVariable) -> bool:
    """
    Return True if `callee` contains a Condition IR that reads `sv`
    AND has at least one NodeType.RETURN reachable from it.
    Approximation: we look for (a) any Condition IR whose read set
    contains a ReferenceVariable derived from `sv`, AND (b) any
    NodeType.RETURN node anywhere in the callee.
    """
    reads_sv_in_cond = False
    has_return = False
    for node in callee.nodes:
        if node.type == NodeType.RETURN:
            has_return = True
        # Map this node's REFs back to state variables
        ref_to_sv: dict[int, StateVariable] = {}
        for ir in node.irs:
            if isinstance(ir, Index):
                base = getattr(ir, "variable_left", None)
                if isinstance(base, StateVariable):
                    ref_to_sv[id(ir.lvalue)] = base
        for ir in node.irs:
            if not isinstance(ir, Condition):
                continue
            for r in ir.read:
                if isinstance(r, StateVariable) and r is sv:
                    reads_sv_in_cond = True
                elif isinstance(r, ReferenceVariable):
                    if ref_to_sv.get(id(r)) is sv:
                        reads_sv_in_cond = True
    return reads_sv_in_cond and has_return


class StorageFlagBeforeInternalGuard(AbstractDetector):
    """Detect flag write preceding an internal call whose guard reads the same flag."""

    ARGUMENT = "storage-flag-before-internal-guard"
    HELP = (
        "State-variable flag is set to true BEFORE calling an internal helper "
        "whose own guard reads the same flag and early-returns - registration "
        "bounds / push never execute"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Storage Flag Set Before Internal Guard Consumes It"
    WIKI_DESCRIPTION = (
        "A function writes a boolean state variable to `true` and then calls "
        "an internal helper whose first action is `if (flag) return;`. Because "
        "the flag has already been set by the caller, the helper short-circuits "
        "every time and the real registration/accounting logic never runs. "
        "First observed in Spectral Modelers (Zellic audit, CRITICAL) where "
        "the MAX_VALIDATORS bound and `validatorAddresses.push` were dead code."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
mapping(address => bool) public isValRegistered;

function registerValidator() external {
    isValRegistered[msg.sender] = true;        // BUG: set before guard runs
    _addValidatorRewardList(msg.sender);
}

function _addValidatorRewardList(address u) internal {
    if (isValRegistered[u]) return;            // early-returns EVERY call
    require(validatorAddresses.length < MAX_VALIDATORS, "full");
    validatorAddresses.push(u);
}
```
1. Caller toggles the flag to true.
2. Internal helper sees the flag set, returns silently.
3. The MAX_VALIDATORS bound is never checked, the array push never runs.
4. Anyone can "register" arbitrarily many times."""
    WIKI_RECOMMENDATION = (
        "Set the flag AFTER the helper succeeds, or move the bound/push logic "
        "to the caller and check the flag before the write. Ensure writes and "
        "guards are not interleaved between caller and callee."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            for function in contract.functions_and_modifiers_declared:
                flag_writes = _find_true_flag_writes(function)
                if not flag_writes:
                    continue

                # Collect (node_idx, callee) internal-call pairs
                internal_calls = []
                for idx, node in enumerate(function.nodes):
                    for ir in node.irs:
                        if isinstance(ir, InternalCall):
                            callee = getattr(ir, "function", None)
                            if callee is not None:
                                internal_calls.append((idx, callee))

                if not internal_calls:
                    continue

                for w_idx, sv in flag_writes:
                    for c_idx, callee in internal_calls:
                        if c_idx <= w_idx:
                            continue
                        if _callee_early_returns_on_sv(callee, sv):
                            info: DETECTOR_INFO = [
                                function,
                                " writes state variable ",
                                sv,
                                " to true and then calls ",
                                callee,
                                ", whose guard reads ",
                                sv,
                                " and early-returns - the capacity check / push "
                                "in the helper never executes. Move the flag write "
                                "to AFTER the helper succeeds.\n",
                            ]
                            results.append(self.generate_result(info))
                            break  # one hit per caller function

        return results
