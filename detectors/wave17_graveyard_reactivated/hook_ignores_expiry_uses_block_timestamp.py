"""
hook_ignores_expiry_uses_block_timestamp.py - Custom Slither detector.

Pattern (Wildcat M-05 - slice_aa body finding, hooks-use-block.timestamp-not-expiry):
    A hook / callback function receives an `expiry` (or `deadline`, `validUntil`,
    `maturity`) parameter but never reads it, comparing `block.timestamp`
    against a DIFFERENT source of truth (a cached `block.timestamp` stored
    earlier, or a contract-wide config). Because the passed-in expiry is
    silently dropped, time-bound semantics are wrong: callers think they are
    restricting the window to `expiry` but the hook honors some other value.

Detection strategy:
    1. Walk non-vendored contracts.
    2. For each declared function whose name contains "hook" / "callback" /
       "onAction" / "execute" / "handle" (heuristic for hook-like entry),
       OR any function with a parameter whose name hints at expiry/deadline,
       OR an external/public non-view function with such a parameter.
    3. Collect the expiry-like parameters by name (expiry, deadline,
       validUntil, maturity, expiresAt, timeout, validity).
    4. Check whether the expiry parameter is ever read inside the function
       (function.local_variables_read at any node).
    5. If the function reads `block.timestamp` but NEVER reads the
       expiry-like parameter → flag.

Confidence: MEDIUM. We require at least one `block.timestamp` read and zero
reads of a named expiry-like parameter inside the function body.

@author auditooor wave11
@pattern slice_aa body finding / Wildcat M-05 hooks-use-block.timestamp-not-expiry
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
from slither.core.solidity_types.elementary_type import ElementaryType
from slither.core.variables.local_variable import LocalVariable
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_HOOK_NAME_HINTS = (
    "hook", "callback", "handle", "execute", "onaction", "onorder",
    "ondeposit", "onwithdraw", "onborrow", "onrepay", "onclaim",
    "beforetransfer", "aftertransfer", "beforeswap", "afterswap",
    "ontransfer", "oncall",
)

_EXPIRY_PARAM_HINTS = (
    "expiry", "deadline", "validuntil", "maturity", "expiresat",
    "timeout", "validity", "endtime", "endtimestamp",
)


def _function_looks_hook(function) -> bool:
    n = (function.name or "").lower()
    return any(h in n for h in _HOOK_NAME_HINTS)


def _expiry_params(function) -> list:
    out = []
    for p in function.parameters:
        if not isinstance(p, LocalVariable):
            continue
        t = getattr(p, "type", None)
        if not isinstance(t, ElementaryType):
            continue
        if t.name not in ("uint256", "uint64", "uint40", "uint32", "uint48", "uint128"):
            continue
        nm = (p.name or "").lower()
        if any(h in nm for h in _EXPIRY_PARAM_HINTS):
            out.append(p)
    return out


def _reads_block_timestamp(function) -> bool:
    for node in function.nodes:
        for sv in node.solidity_variables_read:
            if sv.name == "block.timestamp":
                return True
    return False


def _param_is_read(function, param) -> bool:
    for node in function.nodes:
        for lv in node.local_variables_read:
            if lv is param:
                return True
    return False


class HookIgnoresExpiryUsesBlockTimestamp(AbstractDetector):
    """Detect hook/callback funcs that take an expiry param but never use it."""

    ARGUMENT = "hook-ignores-expiry-uses-block-timestamp"
    HELP = (
        "Hook/callback function takes an expiry/deadline parameter but never "
        "reads it while also reading block.timestamp - window is ignored"
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Hook Ignores Expiry Parameter"
    WIKI_DESCRIPTION = (
        "A hook (or callback) function declares a timestamp-shaped parameter "
        "named like `expiry`, `deadline`, `validUntil`, `maturity`, or "
        "`timeout`, but the function body never reads it. Instead it compares "
        "`block.timestamp` against some other source (a stored value, a "
        "constant, or nothing at all). The caller's intent to bound the "
        "action to `expiry` is silently dropped. Reported in Wildcat "
        "(M-05 hooks-use-block.timestamp-not-expiry)."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function onDepositHook(address user, uint256 amount, uint256 expiry) external {
    // BUG: `expiry` is never read - contract uses a global maturity.
    require(block.timestamp <= maturity, "past maturity");
    _credit(user, amount);
}
```
The caller passed `expiry = block.timestamp + 60`, expecting a tight window.
The hook validates against the contract-wide `maturity` instead, so a
stale transaction that sat in the mempool for an hour still executes."""
    WIKI_RECOMMENDATION = (
        "Either compare `block.timestamp` against the passed `expiry` "
        "parameter directly (`require(block.timestamp <= expiry)`), or remove "
        "the unused parameter so callers are not misled about the semantics."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            for function in contract.functions_and_modifiers_declared:
                if function.is_constructor:
                    continue
                if function.view or function.pure:
                    continue

                # Only look at hook-like callees OR public/external entries
                # - avoids every internal helper flagging.
                if not (_function_looks_hook(function)
                        or function.visibility in ("public", "external")):
                    continue

                expiry_ps = _expiry_params(function)
                if not expiry_ps:
                    continue
                if not _reads_block_timestamp(function):
                    continue

                unused = [p for p in expiry_ps if not _param_is_read(function, p)]
                if not unused:
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " has expiry-like parameter(s) {",
                    ", ".join(p.name for p in unused),
                    "} but never reads them, while comparing block.timestamp "
                    "against a different source. Caller's time bound is "
                    "silently dropped.\n",
                ]
                results.append(self.generate_result(info))

        return results
