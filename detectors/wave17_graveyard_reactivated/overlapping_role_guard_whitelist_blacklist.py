"""
overlapping_role_guard_whitelist_blacklist.py - Custom Slither detector.

Pattern (Ethena M-01/02, slice_ab overlapping-role-guard): Contract uses
both `isWhitelisted` and `isBlacklisted` mappings as access guards but
combines them with logical OR (`||`) - `isWhitelisted[u] || !isBlacklisted[u]`
instead of `isWhitelisted[u] && !isBlacklisted[u]`. The OR collapses the
dual-list invariant: a non-blacklisted, non-whitelisted user passes; a
blacklisted-but-whitelisted user also passes.

Detection strategy:
    1. Contract must declare both a whitelist-named and a blacklist-named
       mapping(address => bool) state variable.
    2. Walk every declared function; for each node that contains a
       require / if and reads BOTH state variables, look for a
       Binary IR with BinaryType.OROR (logical OR). If present, flag the
       function.

@author auditooor wave9
@pattern slice_ab Ethena M-01/02
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
from slither.slithir.operations import Binary, BinaryType
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_WHITELIST_SUBSTRINGS = ("whitelist", "allowlist", "allowed")
_BLACKLIST_SUBSTRINGS = ("blacklist", "blocklist", "denied", "denylist")


def _matches(name: str, subs) -> bool:
    nm = (name or "").lower()
    return any(s in nm for s in subs)


def _find_lists(contract):
    """Return (whitelist_var, blacklist_var) state vars or (None, None)."""
    wl = None
    bl = None
    for sv in contract.state_variables:
        type_str = str(getattr(sv, "type", ""))
        if "mapping(address =>" not in type_str.replace(" ", " "):
            continue
        if _matches(sv.name, _WHITELIST_SUBSTRINGS) and wl is None:
            wl = sv
        elif _matches(sv.name, _BLACKLIST_SUBSTRINGS) and bl is None:
            bl = sv
    return wl, bl


class OverlappingRoleGuardWhitelistBlacklist(AbstractDetector):
    """Flag whitelist/blacklist guards combined with || instead of &&."""

    ARGUMENT = "overlapping-role-guard-whitelist-blacklist"
    HELP = (
        "Whitelist and blacklist mappings are combined with || instead of && - "
        "users in neither set (or both sets) silently pass the guard"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Overlapping Whitelist/Blacklist Role Guard"
    WIKI_DESCRIPTION = (
        "When an access guard combines a whitelist and a blacklist mapping with "
        "logical OR (`isWhitelisted[u] || !isBlacklisted[u]`) instead of logical "
        "AND, the dual-list invariant collapses. A user who is neither listed "
        "nor blocked passes the guard, and a user who is whitelisted but later "
        "blacklisted also passes. The same wrong-operator pattern was confirmed "
        "in Ethena's Code4rena M-01/02 findings."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
mapping(address => bool) public isWhitelisted;
mapping(address => bool) public isBlacklisted;
function transfer(address to, uint256 amount) external {
    require(isWhitelisted[msg.sender] || !isBlacklisted[msg.sender], "denied");
    ...
}
```
1. Admin blacklists `attacker` after detecting bad behaviour.
2. Attacker had previously been added to the whitelist for an airdrop event.
3. The OR check returns true (whitelisted) and the blacklist is bypassed -
   attacker continues to transfer freely."""
    WIKI_RECOMMENDATION = (
        "Combine whitelist and blacklist guards with logical AND: "
        "`require(isWhitelisted[u] && !isBlacklisted[u], \"denied\");`."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            wl, bl = _find_lists(contract)
            if wl is None or bl is None:
                continue

            for function in contract.functions_declared:
                # Function body must not be a setter for one of the lists.
                if (function.name or "").lower().startswith("set"):
                    continue
                for node in function.nodes:
                    if not (node.contains_if() or node.contains_require_or_assert()):
                        continue
                    state_reads = {sv.name for sv in node.state_variables_read}
                    if wl.name not in state_reads or bl.name not in state_reads:
                        continue
                    has_or = any(
                        getattr(ir, "type", None) == BinaryType.OROR
                        for ir in node.irs
                        if isinstance(ir, Binary)
                    )
                    if not has_or:
                        continue
                    info: DETECTOR_INFO = [
                        function,
                        " combines ",
                        wl,
                        " and ",
                        bl,
                        " with logical OR at ",
                        node,
                        " - users in neither set (or both sets) silently pass "
                        "the guard. Use AND instead.\n",
                    ]
                    results.append(self.generate_result(info))
                    break

        return results
