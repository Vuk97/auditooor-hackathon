"""
rate_provider_allowlist_missing.py - Custom Slither detector.

Pattern (W8-3 - Cork $12M, 2024): a contract calls `IRateProvider(x).rate()`
/ `IExchangeRateProvider(x).getRate()` where `x` is a state variable that
can be written by a permissionless setter (no onlyOwner/onlyRole). Attacker
registers a malicious rate provider and drains the pool.

Detection strategy:
  1. Find all HighLevelCall IRs whose callee solidity_signature is in
     {"rate()", "getRate()", "exchangeRate()"}.
  2. For each, resolve ir.destination; if it is a StateVariable, check
     whether the contract has ANY function that writes to that state
     variable WITHOUT an ACL modifier.
  3. If yes → flag.
"""

import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract

from slither.core.variables.state_variable import StateVariable
from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.utils.output import Output


_RATE_SIGS = frozenset({
    "rate()",
    "getRate()",
    "exchangeRate()",
    "getExchangeRate()",
})

_ACL_MODIFIERS = frozenset({
    "onlyowner",
    "onlyadmin",
    "onlyoperator",
    "onlyroles",
    "onlyrole",
    "hasrole",
    "hasanyrole",
    "requiresauth",
    "authorized",
    "onlymanager",
    "onlygovernance",
    "onlymultisig",
    "restricted",
    "onlyauthorized",
})

SKIP_KEYWORDS = ("test", "mock", "setup", "fixture", "helper", "deploy", "script")


def _has_acl_modifier(function) -> bool:
    for m in function.modifiers:
        if (m.name or "").lower() in _ACL_MODIFIERS:
            return True
    # also check for require(msg.sender == owner/admin) patterns
    for node in function.nodes:
        if not node.contains_require_or_assert():
            continue
        for sv in node.solidity_variables_read:
            if sv.name == "msg.sender":
                return True
    return False


def _state_var_has_permissionless_setter(contract, state_var: StateVariable) -> bool:
    """True if any function in the contract writes state_var WITHOUT an ACL."""
    for f in contract.functions_and_modifiers_declared:
        if f.is_constructor:
            continue
        if f.visibility not in ("external", "public"):
            continue
        if state_var not in f.state_variables_written:
            continue
        if _has_acl_modifier(f):
            continue
        return True
    return False


class RateProviderAllowlistMissing(AbstractDetector):
    """
    Rate provider call where the provider address can be set by anyone.
    """

    ARGUMENT = "rate-provider-allowlist-missing"
    HELP = (
        "Contract calls IRateProvider.rate()/getRate() where the provider "
        "address can be set by a permissionless function"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Rate Provider Allowlist Missing"
    WIKI_DESCRIPTION = (
        "The contract pulls a conversion rate from an external "
        "IRateProvider / IExchangeRateProvider contract whose address is "
        "stored in a state variable, but the setter for that state variable "
        "has no onlyOwner / onlyRole gate. An attacker front-runs a legitimate "
        "operation by registering their own rate provider (returning a "
        "manipulated rate), then executes the operation and profits from the "
        "skewed conversion. Exploited against Cork Protocol in 2024 for $12M."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
address public provider;
function setProvider(address p) external { provider = p; }   // no ACL!
function price() external view returns (uint256) {
    return IRate(provider).rate();
}
```
Attacker: `pool.setProvider(attackerContract); pool.swap(...)` - swap prices
against an attacker-controlled rate, enabling arbitrary extraction."""
    WIKI_RECOMMENDATION = (
        "Add `onlyOwner` (or the project's equivalent admin modifier) to "
        "every setter that updates an address that is later called in a "
        "price/conversion context. Better still, maintain an explicit "
        "allowlist of approved rate-provider contracts and reject any "
        "others at set-time."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if any(k in contract.name.lower() for k in SKIP_KEYWORDS):
                continue
            if is_vendored_or_test_contract(contract):
                continue

            flagged_pairs = set()  # (function, state_var) dedup

            for function in contract.functions_and_modifiers_declared:
                for _c, ir in function.high_level_calls:
                    callee = getattr(ir, "function", None)
                    if callee is None:
                        continue
                    sig = getattr(callee, "solidity_signature", None)
                    if sig not in _RATE_SIGS:
                        continue

                    dest = ir.destination
                    # Resolve destination to underlying state variable if any.
                    # In Slither the destination may already be a StateVariable,
                    # or a temporary ultimately sourced from one. Inspect the
                    # containing node's state_variables_read as a broad check.
                    target_sv = None
                    if isinstance(dest, StateVariable):
                        target_sv = dest
                    else:
                        # Fall back to node-level state var reads
                        for sv in ir.node.state_variables_read:
                            target_sv = sv
                            break

                    if target_sv is None:
                        continue

                    if not _state_var_has_permissionless_setter(contract, target_sv):
                        continue

                    key = (function, target_sv)
                    if key in flagged_pairs:
                        continue
                    flagged_pairs.add(key)

                    info: DETECTOR_INFO = [
                        function,
                        f" calls {sig} through state variable ",
                        target_sv,
                        " which has a permissionless setter - attacker can "
                        "register a malicious rate provider and skew the "
                        "rate returned at ",
                        ir.node,
                        ".\n",
                    ]
                    results.append(self.generate_result(info))

        return results
