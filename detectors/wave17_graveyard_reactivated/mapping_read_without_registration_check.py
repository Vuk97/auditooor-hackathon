"""
mapping_read_without_registration_check.py - Custom Slither detector.

Pattern (LoopFi H-03 zero-rate-new-quoted-token + Munchables M-01
zero-tax-bypass-landlord-pre-deploy - slice_aa body findings):

    A contract exposes a "register this key" entry point (e.g. `addToken`,
    `registerPool`, `configureAsset`) that seeds an `interestRate[token]` /
    `tax[landlord]` / `feeBps[asset]` storage mapping. Other business-logic
    functions then read that mapping with the key controlled by the caller
    but WITHOUT first checking that the key has been registered - so callers
    can pass a never-registered key, get back `0`, and bypass the associated
    economic lever (zero interest, zero tax, zero fee).

Detection strategy:
    1. Find state variables of type `mapping(address => uint*)` or
       `mapping(bytes32 => uint*)` whose names contain rate/interest/fee/tax/
       price/bps hints (i.e. tunables indexed by a registered key).
    2. Collect the set of "register" functions: declared functions whose
       name matches an allow-list (add*, register*, configure*, setup*,
       whitelist*, create*) that WRITE such a mapping.
    3. For every OTHER declared function (non-view, non-pure, public/
       external) that READS one of those mappings, check whether the same
       function also contains a require/assert node that reads either:
         a. the same mapping slot (proxy for "require(rate[k] != 0)"), OR
         b. a companion boolean / uint "isRegistered" / "exists" / "active"
            state variable mapping.
       If no such guard is found → flag.

Confidence: MEDIUM - we only flag when a matching "register" function
exists on the same contract (avoids firing on unrelated setter/reader pairs).

@author auditooor wave11
@pattern slice_aa body findings / LoopFi H-03 / Munchables M-01
"""

import re as _re
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract

from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.core.solidity_types.mapping_type import MappingType
from slither.core.solidity_types.elementary_type import ElementaryType
from slither.core.variables.state_variable import StateVariable
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_TUNABLE_HINTS = (
    "rate", "interest", "fee", "tax", "price", "bps", "apr", "apy",
    "discount", "commission", "reward",
)

_REGISTER_NAME_RE = _re.compile(
    r"^(add|register|configure|setup|whitelist|create|enable|initialize)",
    _re.IGNORECASE,
)

_EXISTENCE_HINTS = (
    "registered", "exists", "active", "enabled", "supported", "isvalid",
    "whitelisted", "iswhitelisted", "allowed", "known",
)


def _is_tunable_mapping(sv) -> bool:
    if not isinstance(sv, StateVariable):
        return False
    t = sv.type
    if not isinstance(t, MappingType):
        return False
    # key must be address / bytes32
    kt = t.type_from
    if not isinstance(kt, ElementaryType) or kt.name not in ("address", "bytes32", "uint256"):
        return False
    vt = t.type_to
    if not isinstance(vt, ElementaryType):
        return False
    if not vt.name.startswith("uint"):
        return False
    nm = (sv.name or "").lower()
    return any(h in nm for h in _TUNABLE_HINTS)


def _contract_has_existence_mapping(contract) -> bool:
    for sv in contract.state_variables:
        if not isinstance(sv, StateVariable):
            continue
        nm = (sv.name or "").lower()
        if any(h in nm for h in _EXISTENCE_HINTS):
            # Make sure it's not the same tunable mapping.
            if not _is_tunable_mapping(sv):
                return True
    return False


def _function_writes(function, sv) -> bool:
    return sv in function.state_variables_written


def _function_reads(function, sv) -> bool:
    return sv in function.state_variables_read


def _function_has_registration_guard(function, tunable_sv, existence_exists) -> bool:
    """
    Return True if any require/assert node in the function reads EITHER
    the same tunable mapping (proxy for "require(rate[k] != 0)") OR an
    existence-style state variable.
    """
    for node in function.nodes:
        if not node.contains_require_or_assert():
            continue
        for sv in node.state_variables_read:
            if sv is tunable_sv:
                return True
            nm = (getattr(sv, "name", "") or "").lower()
            if any(h in nm for h in _EXISTENCE_HINTS):
                return True
    return False


class MappingReadWithoutRegistrationCheck(AbstractDetector):
    """Detect tunable-mapping reads lacking a registration guard."""

    ARGUMENT = "mapping-read-without-registration-check"
    HELP = (
        "Function reads a per-asset rate/fee/tax mapping without first "
        "checking the key was registered - zero default bypasses the lever"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Mapping Read Without Registration Check"
    WIKI_DESCRIPTION = (
        "A contract seeds per-key tunables (interest rates, fees, taxes, "
        "commissions) via a dedicated `register`/`add` function, then reads "
        "the mapping elsewhere without first verifying the key was registered. "
        "Solidity mappings default to zero, so an unregistered key silently "
        "returns a zero rate/fee and lets callers bypass the economic lever. "
        "Reported in LoopFi (H-03 zero-rate-new-quoted-token) and Munchables "
        "(M-01 zero-tax-bypass-landlord-pre-deploy)."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
mapping(address => uint256) public interestRate; // bps
function addToken(address t, uint256 r) external onlyOwner {
    interestRate[t] = r;
}
function accrue(address t, uint256 principal) external returns (uint256) {
    // BUG: no `require(interestRate[t] != 0)` or `require(isToken[t])`.
    return principal * interestRate[t] / 10_000;
}
```
A borrower opens a position with a token the admin never registered;
`interestRate[t]` is `0`, accrual returns `0`, and the loan is free."""
    WIKI_RECOMMENDATION = (
        "Add an explicit `require(isRegistered[k], ...)` guard (or check "
        "`require(rate[k] != 0)`) at the top of every consumer function, or "
        "use a `supportedKey[]` existence mapping that is written by the "
        "register function and checked by the consumers."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            tunables = [sv for sv in contract.state_variables if _is_tunable_mapping(sv)]
            if not tunables:
                continue

            # Must have at least one "register"-style function that WRITES a
            # tunable - otherwise reads are not bypassable via an
            # unregistered key.
            register_funcs = [
                f for f in contract.functions_and_modifiers_declared
                if f.name and _REGISTER_NAME_RE.search(f.name)
                and any(_function_writes(f, sv) for sv in tunables)
            ]
            if not register_funcs:
                continue

            existence_exists = _contract_has_existence_mapping(contract)

            for function in contract.functions_and_modifiers_declared:
                if function.is_constructor:
                    continue
                if function.view or function.pure:
                    continue
                if function.visibility not in ("public", "external"):
                    continue
                # Skip the register functions themselves.
                if function in register_funcs:
                    continue

                for tunable_sv in tunables:
                    if not _function_reads(function, tunable_sv):
                        continue
                    if _function_has_registration_guard(
                        function, tunable_sv, existence_exists
                    ):
                        continue

                    info: DETECTOR_INFO = [
                        function,
                        " reads tunable mapping ",
                        tunable_sv,
                        " without first requiring the key was registered - "
                        "zero default value bypasses the economic lever.\n",
                    ]
                    results.append(self.generate_result(info))
                    break  # one finding per function

        return results
