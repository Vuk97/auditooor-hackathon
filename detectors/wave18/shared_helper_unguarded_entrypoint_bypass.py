"""
shared_helper_unguarded_entrypoint_bypass.py — Custom Slither detector.

Bounded G1-001 slice (logic-error-flow-bypass): flag contracts where two
externally reachable sibling functions invoke the same mutating internal
effect helper, but only one path applies a lifecycle/auth/precondition guard.

This intentionally targets the detector-ready shape from the Subsquid-style
class: a direct external path reaches the same internal withdraw/exit/remove/
decrease helper as a guarded path while skipping the deregistration, cooldown,
pause, role, or status gate. It does NOT claim coverage for broader accounting
or value-flow variants such as the GainsNetwork leverage/accounting family.
"""

from __future__ import annotations

import re
import sys as _sys
from pathlib import Path as _Path

_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract

from slither.detectors.abstract_detector import (
    AbstractDetector,
    DETECTOR_INFO,
    DetectorClassification,
)
from slither.slithir.operations import InternalCall
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")
_EFFECT_NAME_RE = re.compile(
    r"(withdraw|redeem|claim|unstake|exit|release|remove|close|settle|"
    r"burn|decrease|delever|liquidat)",
    re.IGNORECASE,
)
_GUARD_NAME_RE = re.compile(
    r"(assert|check|validate|verify|enforce|guard|only|role|owner|admin|gov|"
    r"pause|cooldown|lock|wait|allow|deny|active|register|deregister|status)",
    re.IGNORECASE,
)
_GUARD_STATE_RE = re.compile(
    r"(pause|cooldown|lock|wait|allow|deny|ban|blacklist|whitelist|active|"
    r"enabled|disabled|frozen|role|owner|admin|gov|auth|permission|status|"
    r"registered|deregister)",
    re.IGNORECASE,
)
_CRITICAL_STATE_RE = re.compile(
    r"(stake|share|deposit|withdraw|claim|reward|collateral|position|"
    r"worker|delegat|amount|balance|debt|escrow)",
    re.IGNORECASE,
)


def _is_external_entry(function) -> bool:
    return (
        not function.is_constructor
        and getattr(function, "visibility", None) in {"public", "external"}
        and not function.is_receive
        and not function.is_fallback
    )


def _internal_callees(function):
    callees = set()
    for node in function.nodes:
        for ir in node.irs:
            if not isinstance(ir, InternalCall):
                continue
            callee = ir.function
            if callee is None:
                continue
            if getattr(callee, "visibility", None) not in {"internal", "private"}:
                continue
            callees.add(callee)
    return callees


def _guard_state_reads(function) -> set[str]:
    reads: set[str] = set()
    for node in function.nodes:
        if not node.contains_require_or_assert():
            continue
        for sv in node.state_variables_read:
            name = getattr(sv, "name", "") or ""
            if _GUARD_STATE_RE.search(name):
                reads.add(name)
    return reads


def _guard_modifier_names(function) -> set[str]:
    names: set[str] = set()
    for mod in getattr(function, "modifiers", []) or []:
        name = getattr(mod, "name", "") or ""
        if _GUARD_NAME_RE.search(name):
            names.add(name.lower())
        for node in mod.nodes:
            if not node.contains_require_or_assert():
                continue
            for sv in node.state_variables_read:
                sv_name = getattr(sv, "name", "") or ""
                if _GUARD_STATE_RE.search(sv_name):
                    names.add(sv_name.lower())
    return names


def _guard_helper_names(function, effect_helper) -> set[str]:
    names: set[str] = set()
    for callee in _internal_callees(function):
        if callee == effect_helper:
            continue
        name = getattr(callee, "name", "") or ""
        if _GUARD_NAME_RE.search(name) or _guard_state_reads(callee):
            names.add(name.lower())
    return names


def _guard_profile(function, effect_helper) -> tuple[set[str], set[str], set[str]]:
    return (
        _guard_state_reads(function),
        _guard_modifier_names(function),
        _guard_helper_names(function, effect_helper),
    )


def _has_meaningful_guard(function, effect_helper) -> bool:
    state_reads, modifier_names, helper_names = _guard_profile(function, effect_helper)
    return bool(state_reads or modifier_names or helper_names)


def _helper_has_critical_effect(helper, callers) -> bool:
    if getattr(helper, "visibility", None) not in {"internal", "private"}:
        return False
    if not helper.state_variables_written and not helper.high_level_calls and not helper.low_level_calls:
        return False
    helper_name = getattr(helper, "name", "") or ""
    if _EFFECT_NAME_RE.search(helper_name):
        return True
    for caller in callers:
        caller_name = getattr(caller, "name", "") or ""
        if _EFFECT_NAME_RE.search(caller_name):
            return True
    for sv in helper.state_variables_written:
        name = getattr(sv, "name", "") or ""
        if _CRITICAL_STATE_RE.search(name):
            return True
    return bool(helper.high_level_calls or helper.low_level_calls)


class SharedHelperUnguardedEntrypointBypass(AbstractDetector):
    """Detect direct external paths that hit a guarded effect helper without the guard."""

    ARGUMENT = "shared-helper-unguarded-entrypoint-bypass"
    HELP = (
        "External sibling reaches the same mutating internal helper as a guarded path "
        "but skips lifecycle/auth preconditions"
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Shared Effect Helper Reachable Through Unguarded External Path"
    WIKI_DESCRIPTION = (
        "A contract exposes two public/external entries that both reach the same "
        "mutating internal helper. One path applies a meaningful lifecycle/auth "
        "guard such as deregistration, cooldown, pause, role, or status checks; "
        "the sibling path reaches the same helper without any comparable guard. "
        "This is the bounded, detector-ready slice of the logic-error-flow-bypass "
        "class. It is suitable for direct internal-call bypasses, but does not "
        "close broader accounting-flow variants."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function withdrawAfterCooldown(uint256 amount) external {
    _assertWithdrawalReady(msg.sender);
    _withdrawStake(msg.sender, amount);
}

function emergencyWithdraw(uint256 amount) external {
    _withdrawStake(msg.sender, amount); // BUG: same effect helper, no guard
}
```
An operator/user follows the direct path and reaches the same storage-changing
withdraw helper without satisfying the cooldown/deregister/authorization flow."""
    WIKI_RECOMMENDATION = (
        "Route every externally reachable path through the same guard helper or "
        "re-apply the lifecycle/auth checks before calling the shared effect helper."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            helper_to_callers: dict = {}
            for function in contract.functions_and_modifiers_declared:
                if not _is_external_entry(function):
                    continue
                for callee in _internal_callees(function):
                    helper_to_callers.setdefault(callee, []).append(function)

            for helper, callers in helper_to_callers.items():
                if len(callers) < 2:
                    continue
                if not _helper_has_critical_effect(helper, callers):
                    continue
                if _has_meaningful_guard(helper, None):
                    continue

                guarded = [f for f in callers if _has_meaningful_guard(f, helper)]
                bypass = [f for f in callers if not _has_meaningful_guard(f, helper)]
                if not guarded or not bypass:
                    continue

                for unguarded_fn in bypass:
                    guarded_fn = next(
                        (candidate for candidate in guarded if candidate != unguarded_fn),
                        None,
                    )
                    if guarded_fn is None:
                        continue

                    info: DETECTOR_INFO = [
                        unguarded_fn,
                        " reaches shared internal effect helper ",
                        helper,
                        " without the lifecycle/auth guard applied by ",
                        guarded_fn,
                        ". This is a bounded logic-flow bypass on ",
                        contract,
                        ".\n",
                    ]
                    results.append(self.generate_result(info))

        return results
