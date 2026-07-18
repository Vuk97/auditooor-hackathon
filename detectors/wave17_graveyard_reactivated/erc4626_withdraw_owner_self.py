"""
erc4626_withdraw_owner_self.py - Custom Slither detector.

Pattern (LoopFi M-03, slice_ab): An internal handler forwards a user
withdrawal through an ERC-4626 vault but passes `address(this)` as the
`owner` argument of `withdraw(assets, receiver, owner)` /
`redeem(shares, receiver, owner)`. The vault burns the CONTRACT's own
shares instead of the user's, making the adapter's accounting drift and
potentially draining any shares the contract happens to hold.

Detection strategy:
    1. Walk every function.
    2. Find HighLevelCall IRs whose callee solidity_signature is one of
       the ERC-4626 withdraw/redeem three-arg forms.
    3. The third argument (`owner`) must be a TemporaryVariable produced
       by a TypeConversion IR on the SAME node whose source is the
       SolidityVariable `this`.
    4. Flag.

@author auditooor wave11
@pattern slice_ab LoopFi M-03 _onWithdraw uses address(this)
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
from slither.core.declarations import Function, SolidityVariable
from slither.slithir.operations import HighLevelCall, TypeConversion
from slither.slithir.variables import TemporaryVariable
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_ERC4626_THREE_ARG_SIGS = frozenset({
    "withdraw(uint256,address,address)",
    "redeem(uint256,address,address)",
})


def _is_this_convert(ir) -> bool:
    if not isinstance(ir, TypeConversion):
        return False
    src = getattr(ir, "variable", None)
    if src is None:
        return False
    if isinstance(src, SolidityVariable) and src.name == "this":
        return True
    return False


class Erc4626WithdrawOwnerSelf(AbstractDetector):
    """Call to ERC-4626 withdraw/redeem uses address(this) as `owner`."""

    ARGUMENT = "erc4626-withdraw-owner-self"
    HELP = (
        "call to IERC4626.withdraw/redeem passes address(this) as the "
        "`owner` argument - the adapter burns its own shares, not the user's"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "ERC-4626 withdraw/redeem uses address(this) as owner"
    WIKI_DESCRIPTION = (
        "A withdraw handler forwards a user's request to an ERC-4626 vault "
        "via `vault.withdraw(assets, receiver, address(this))` or "
        "`vault.redeem(shares, receiver, address(this))`. Passing "
        "`address(this)` as the `owner` argument tells the vault to burn "
        "shares owned by the calling contract - not the real user - which "
        "corrupts the adapter's internal share accounting and can drain any "
        "shares the adapter happens to custody. Reported in LoopFi M-03."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function _onWithdraw(address user, uint256 assets) internal {
    vault.withdraw(assets, user, address(this));    // BUG: owner = adapter
}
```
The user gets their assets but the adapter burns its own shares. A
different user (or the adapter's surplus) takes the loss, and the caller
gets away with paying nothing."""
    WIKI_RECOMMENDATION = (
        "Pass the actual beneficiary's address as the `owner` parameter "
        "(typically the user whose entitlement is being redeemed). "
        "`address(this)` is only correct when the adapter itself is the "
        "beneficiary."
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

                for node in function.nodes:
                    # Collect all TypeConversions on this node that convert
                    # `this` - their lvalue temporaries are the "address(this)"
                    # values later fed into the call.
                    this_temps = {
                        ir.lvalue
                        for ir in node.irs
                        if _is_this_convert(ir)
                    }
                    if not this_temps:
                        continue
                    for ir in node.irs:
                        if not isinstance(ir, HighLevelCall):
                            continue
                        callee = getattr(ir, "function", None)
                        if not isinstance(callee, Function):
                            continue
                        sig = getattr(callee, "solidity_signature", None)
                        if sig not in _ERC4626_THREE_ARG_SIGS:
                            continue
                        args = list(getattr(ir, "arguments", []) or [])
                        if len(args) < 3:
                            continue
                        owner_arg = args[2]
                        if not isinstance(owner_arg, TemporaryVariable):
                            continue
                        if owner_arg not in this_temps:
                            continue

                        info: DETECTOR_INFO = [
                            function,
                            " calls ERC-4626 ",
                            sig,
                            " with address(this) as the `owner` argument at ",
                            node,
                            " - the adapter's own shares are burned, not "
                            "the user's.\n",
                        ]
                        results.append(self.generate_result(info))

        return results
