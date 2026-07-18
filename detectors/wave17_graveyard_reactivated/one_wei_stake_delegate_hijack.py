"""
one_wei_stake_delegate_hijack.py - Custom Slither detector.

Pattern (Virtuals H-02 / slice_ac):
    A `stake(address user, uint256 amount)` (or similar `deposit`/`delegate`
    /`register`) function writes `delegate[user] = msg.sender` (or any
    "owner of position" mapping) WITHOUT either:
      - requiring `msg.sender == user`, OR
      - checking that the slot was previously unset / belongs to caller.
    Attacker stakes 1 wei on behalf of any victim who has not yet
    interacted, claiming the delegate slot. When the victim later self-
    stakes, their delegate is already owned by the attacker.

Detection strategy:
    1. For each non-vendored contract, find functions whose name matches
       (i)stake|deposit|delegate|register|join|enter and which take an
       `address user` (or `to`/`for`/`account`/`recipient`) parameter.
    2. Inside the function, look for a state-variable WRITE to a mapping
       whose name matches `(?i)(delegate|owner|manager|controller|operator)`
       at index `user` with value `msg.sender`. The simplest & most robust
       proxy: the function `state_variables_written` includes such a
       mapping, AND `msg.sender` is read in the function.
    3. Flag if the function does NOT contain a require/assert that reads
       `msg.sender` (i.e. no `require(msg.sender == user)`-style guard) AND
       does NOT also read the mapping itself (i.e. no
       `require(delegate[user] == address(0))`-style check).

@author auditooor wave9
@pattern Virtuals H-02 / slice_ac
"""

import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract

import re

from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.core.solidity_types import MappingType, ElementaryType
from slither.core.variables.state_variable import StateVariable
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_FN_NAME_RE = re.compile(r"(stake|deposit|delegate|register|join|enter|mintfor|lockfor)", re.IGNORECASE)
_OWNERLIKE_RE = re.compile(r"(delegate|owner|manager|controller|operator|proxy)", re.IGNORECASE)
_USER_PARAM_NAMES = {"user", "to", "for", "account", "recipient", "beneficiary", "owner"}


def _is_address_to_address_mapping(sv: StateVariable) -> bool:
    t = getattr(sv, "type", None)
    if not isinstance(t, MappingType):
        return False
    key = t.type_from
    val = t.type_to
    return (
        isinstance(key, ElementaryType) and key.name == "address"
        and isinstance(val, ElementaryType) and val.name == "address"
    )


def _has_address_user_param(function):
    for p in function.parameters:
        nm = (p.name or "").lower()
        t = getattr(p, "type", None)
        if isinstance(t, ElementaryType) and t.name == "address" and nm in _USER_PARAM_NAMES:
            return p
    return None


def _has_msgsender_eq_user_require(function) -> bool:
    """Heuristic: a require/assert node that reads msg.sender."""
    for node in function.nodes:
        if not node.contains_require_or_assert():
            continue
        for sv in node.solidity_variables_read:
            if sv.name == "msg.sender":
                return True
    return False


def _require_reads_mapping(function, mapping_sv) -> bool:
    """Heuristic: any require/assert node reads `mapping_sv`."""
    for node in function.nodes:
        if not node.contains_require_or_assert():
            continue
        if mapping_sv in node.state_variables_read:
            return True
    return False


class OneWeiStakeDelegateHijack(AbstractDetector):
    """Stake-on-behalf hijacks a delegate/owner slot from msg.sender."""

    ARGUMENT = "one-wei-stake-delegate-hijack"
    HELP = (
        "stake(user) function silently sets delegate[user] = msg.sender "
        "without verifying caller is user or slot was unset - anyone can "
        "hijack a victim's delegate"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "One-Wei Stake → Delegate Hijack"
    WIKI_DESCRIPTION = (
        "A `stake`/`deposit`/`delegate` function takes an `address user` "
        "parameter and binds an owner-style mapping (`delegate`, `owner`, "
        "`manager`, `controller`) to `msg.sender` without checking that "
        "the caller is the user, or that the mapping slot was previously "
        "unset. Attacker calls `stake(victim, 1)` on every fresh user, "
        "claiming the delegate slot before they ever interact. Reported "
        "in Virtuals H-02."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
mapping(address => address) public delegate;
mapping(address => uint256) public stakeOf;

function stake(address user, uint256 amount) external {
    stakeOf[user] += amount;
    delegate[user] = msg.sender;  // anyone can stake-on-behalf and claim slot
}
```
1. Attacker calls stake(victim, 1) → delegate[victim] = attacker.
2. Victim later self-stakes; delegate slot is already pinned to attacker."""
    WIKI_RECOMMENDATION = (
        "Either require `msg.sender == user`, or accept stake-on-behalf "
        "ONLY if the existing delegate slot is `address(0)` or already "
        "the caller - never silently overwrite a delegate from a "
        "stake-for-other code path."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            # Candidate owner-like mappings on this contract.
            owner_mappings = [
                sv for sv in contract.state_variables
                if isinstance(sv, StateVariable)
                and _OWNERLIKE_RE.search(sv.name or "")
                and _is_address_to_address_mapping(sv)
            ]
            if not owner_mappings:
                continue

            for function in contract.functions_declared:
                if function.is_constructor:
                    continue
                if function.view or function.pure:
                    continue
                if function.visibility not in ("public", "external"):
                    continue
                if not _FN_NAME_RE.search(function.name or ""):
                    continue
                user_param = _has_address_user_param(function)
                if user_param is None:
                    continue

                writes = set(function.state_variables_written)
                hit_mappings = [m for m in owner_mappings if m in writes]
                if not hit_mappings:
                    continue

                # Skip if function has msg.sender == user style guard
                if _has_msgsender_eq_user_require(function):
                    continue

                # Skip if function reads the owner mapping inside a require
                # (i.e. checks slot is unset or caller is delegate)
                guarded = any(
                    _require_reads_mapping(function, m) for m in hit_mappings
                )
                if guarded:
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " writes owner-style mapping ",
                    hit_mappings[0],
                    f" using `address {user_param.name}` parameter without "
                    "verifying caller == user or slot was unset - attacker "
                    "can hijack the delegate slot of any victim with a "
                    "1-wei stake-on-behalf call.\n",
                ]
                results.append(self.generate_result(info))

        return results
