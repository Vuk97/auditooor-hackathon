"""
arbitrary_erc20_sweep_unrestricted.py - Custom Slither detector.

Pattern (generic rug class, ~20+ BSC/Arbitrum tokens in 2024-2026):
    A helper function named `sweep*` / `rescue*` / `withdrawToken*` /
    `recoverERC20*` / `skim*` calls `IERC20(token).transfer(to, amount)`
    where EITHER `token` OR `to` is a user-supplied parameter, but the
    function has no access-control modifier and no explicit `msg.sender
    == owner` require. Attacker sweeps any approved ERC20 (including
    vault underlying) to themselves.

This is the STRAIGHT-UP missing-ACL variant; different from
`sweep_token_allows_underlying.py` (which targets the inverted `==`
guard) and from `router_arbitrary_target_call.py` (which targets an
arbitrary `.call(data)` drain path).

Detection strategy:
    1. Iterate external/public functions whose name matches
       `sweep|rescue|recover|skim|withdrawtoken|pullfund|retrieve`.
    2. Skip if any ACL modifier is present.
    3. Skip if the body has an `msg.sender`-vs-owner-var require.
    4. Require the body to contain a `transfer(address,uint256)` or
       `safeTransfer` HighLevelCall where the destination argument is a
       function parameter OR the token target is a function parameter.
    5. Flag.
"""

import re
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
from slither.slithir.operations import HighLevelCall, LibraryCall
from slither.utils.output import Output


_NAME_RE = re.compile(
    r"^(sweep|rescue|recover|skim|withdrawtoken|pullfund|retrieve|claimtoken)",
    re.IGNORECASE,
)

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
    "onlymaintainer",
    "restricted",
    "onlyauthorized",
    "onlykeeper",
    "onlytimelock",
})

_TRANSFER_SIGS = frozenset({
    "transfer(address,uint256)",
    "safeTransfer(address,address,uint256)",
})

SKIP_KEYWORDS = ("test", "mock", "setup", "fixture", "helper", "deploy", "script")


def _has_acl_modifier(function) -> bool:
    for m in function.modifiers:
        if (m.name or "").lower() in _ACL_MODIFIERS:
            return True
    return False


def _has_owner_require(function) -> bool:
    owner_hints = ("owner", "admin", "governor", "governance", "controller")
    for node in function.nodes:
        if not node.contains_require_or_assert():
            continue
        solidity_vars = [v.name for v in node.solidity_variables_read]
        if "msg.sender" not in solidity_vars:
            continue
        for sv in node.state_variables_read:
            if any(h in (sv.name or "").lower() for h in owner_hints):
                return True
    return False


class ArbitraryErc20SweepUnrestricted(AbstractDetector):
    """Detect unrestricted sweep/rescue functions that transfer any ERC20."""

    ARGUMENT = "arbitrary-erc20-sweep-unrestricted"
    HELP = (
        "sweep/rescue/recover helper transfers ERC20 with no ACL - "
        "attacker drains any approved token"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Unrestricted ERC20 Sweep / Rescue"
    WIKI_DESCRIPTION = (
        "`sweepToken` / `rescueERC20` / `withdrawToken` helpers are "
        "intended for an owner to recover mistakenly-transferred funds. "
        "When the function is missing an access-control modifier, any "
        "caller can pull every ERC20 the contract holds (including the "
        "protocol's own underlying asset and user approvals) to an "
        "arbitrary destination. This is a rug class we've seen ~20+ "
        "times in 2024-2026 on BNB/Arbitrum token launches and on "
        "several legitimate protocols that shipped the helper without "
        "the owner guard."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function sweepToken(address token, address to, uint256 amount) external {
    IERC20(token).transfer(to, amount);  // BUG: no onlyOwner
}
```
Attacker calls `sweepToken(USDC, attacker, contractBalance)` to drain
everything the contract holds - including any token users approved to
this router."""
    WIKI_RECOMMENDATION = (
        "Add `onlyOwner` / `onlyRole(SWEEPER_ROLE)` to every sweep helper. "
        "Consider restricting sweep to tokens that are NOT the protocol's "
        "own underlying, and emitting an event for the sweep operation."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in (contract.name or "").lower() for k in SKIP_KEYWORDS):
                continue

            for function in contract.functions_and_modifiers_declared:
                if function.is_constructor:
                    continue
                if function.visibility not in ("external", "public"):
                    continue
                if not _NAME_RE.match(function.name or ""):
                    continue
                if _has_acl_modifier(function):
                    continue
                if _has_owner_require(function):
                    continue

                params = set(function.parameters)
                if not params:
                    continue

                flagged_node = None
                for node in function.nodes:
                    for ir in node.irs:
                        if not isinstance(ir, (HighLevelCall, LibraryCall)):
                            continue
                        callee = getattr(ir, "function", None)
                        if not isinstance(callee, Function):
                            continue
                        sig = getattr(callee, "solidity_signature", None) or ""
                        if sig not in _TRANSFER_SIGS:
                            continue
                        # Check if any argument / destination is a function param.
                        if (
                            ir.destination in params
                            or any(a in params for a in ir.arguments)
                        ):
                            flagged_node = node
                            break
                    if flagged_node is not None:
                        break

                if flagged_node is None:
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " is a permissionless sweep / rescue helper at ",
                    flagged_node,
                    " that transfers an ERC20 using function-parameter "
                    "addresses - any caller can drain every token held by "
                    "(or approved to) this contract. Gate behind "
                    "`onlyOwner`.\n",
                ]
                results.append(self.generate_result(info))

        return results
