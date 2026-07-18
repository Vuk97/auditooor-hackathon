"""
router_arbitrary_from_pull_tokens_with_permit.py - Custom Slither detector.

Pattern (BakerFi H-05/06/07 - slice_ab):
    A router / aggregator function takes `(address from, address token,
    uint256 amount, ...)` and calls `token.transferFrom(from, ...)` to
    pull tokens, but never verifies that the caller is authorized to
    pull from `from`. Any account that has approved this router to spend
    its tokens can be drained by any attacker.

Detection strategy:
    1. Walk non-vendored contracts. For each declared external/public
       function, look for a parameter named `from` (or `owner` / `payer`
       / `account` / `user` / `sender_` / `src`) of type `address`.
    2. Walk the function body for HighLevelCall IRs whose callee
       solidity_signature is `transferFrom(address,address,uint256)`
       AND whose first argument is that `from` parameter.
    3. Check whether the function body validates that the caller is
       authorized:
         - any require/assert node that reads BOTH the `from` parameter
           AND the `msg.sender` solidity variable, OR
         - any call to a permit / Permit2 / isValidSignature /
           ecrecover / *recover / *verify helper.
       If neither is present → flag.

@author auditooor wave9
@pattern slice_ab / BakerFi H-05 / H-06 / H-07
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
from slither.core.declarations import Function, SolidityFunction
from slither.core.solidity_types.elementary_type import ElementaryType
from slither.slithir.operations import (
    HighLevelCall,
    InternalCall,
    SolidityCall,
)
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_FROM_PARAM_NAMES = frozenset({
    "from", "owner", "payer", "src", "account", "user", "from_",
    "_from", "sender_", "spender_",
})

_AUTH_HELPER_RE = _re.compile(
    r"(?i)(permit|recover|verify|isvalidsignature|signedmessage|checksig)"
)

_TRANSFER_FROM_SIG = "transferFrom(address,address,uint256)"
_ECRECOVER = SolidityFunction("ecrecover(bytes32,uint8,bytes32,bytes32)")


def _from_params(function):
    out = []
    for p in function.parameters:
        nm = (p.name or "").lower()
        if nm not in _FROM_PARAM_NAMES:
            continue
        t = getattr(p, "type", None)
        if isinstance(t, ElementaryType) and t.name == "address":
            out.append(p)
    return out


def _function_has_msgsender_eq_from(function, from_param) -> bool:
    """True if any require/assert node reads BOTH `from_param` and msg.sender."""
    for node in function.nodes:
        if not node.contains_require_or_assert():
            continue
        reads_from = any(lv is from_param for lv in node.local_variables_read)
        if not reads_from:
            continue
        reads_sender = any(
            (sv.name or "") == "msg.sender"
            for sv in node.solidity_variables_read
        )
        if reads_sender:
            return True
    return False


def _function_calls_auth_helper(function) -> bool:
    """True if function calls a permit / recover / verify / isValidSignature
    helper (any internal, high-level, or solidity call)."""
    for node in function.nodes:
        for ir in node.irs:
            if isinstance(ir, SolidityCall) and ir.function == _ECRECOVER:
                return True
            if isinstance(ir, (InternalCall, HighLevelCall)):
                callee = ir.function
                if isinstance(callee, Function) and callee.name:
                    if _AUTH_HELPER_RE.search(callee.name):
                        return True
    return False


class RouterArbitraryFromPullTokensWithPermit(AbstractDetector):
    """Router pulls tokens from a user-supplied `from` without authorization."""

    ARGUMENT = "router-arbitrary-from-pull-tokens-with-permit"
    HELP = (
        "Router takes `address from` and calls transferFrom(from,...) without "
        "msg.sender == from check or signature verification - drains approvals"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Router Arbitrary From Pull"
    WIKI_DESCRIPTION = (
        "A router / aggregator function takes `address from` as a parameter "
        "and calls `token.transferFrom(from, ...)` to pull tokens, but does "
        "not require that `msg.sender == from` and does not verify a signed "
        "intent (ECDSA, EIP-1271 isValidSignature, EIP-2612 permit, Permit2) "
        "from `from`. Any user that has previously approved this router to "
        "spend their tokens can be drained by any attacker who passes their "
        "address as `from`. Reported in BakerFi H-05 / H-06 / H-07."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function pullAndSwap(address from, address token, uint256 amount) external {
    IERC20(token).transferFrom(from, address(this), amount);  // BUG
    // ... swap ...
}
```
1. Victim approves the router for unlimited USDC.
2. Attacker calls `pullAndSwap(victim, USDC, type(uint256).max)`.
3. The router pulls every USDC the victim ever approved and forwards
   it into a swap whose output address the attacker controls."""
    WIKI_RECOMMENDATION = (
        "Either restrict pulls to `msg.sender` (`require(from == msg.sender)`), "
        "OR require a fresh signed intent from `from` (Permit2, EIP-2612 permit, "
        "or an EIP-712 signature verified via ECDSA/isValidSignature) before "
        "invoking transferFrom."
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
                if function.visibility not in ("public", "external"):
                    continue

                from_params = _from_params(function)
                if not from_params:
                    continue

                # Find a transferFrom HighLevelCall whose first arg is `from`.
                vulnerable_param = None
                vulnerable_node = None
                for node in function.nodes:
                    for ir in node.irs:
                        if not isinstance(ir, HighLevelCall):
                            continue
                        callee = ir.function
                        if not isinstance(callee, Function):
                            continue
                        if (
                            getattr(callee, "solidity_signature", "")
                            != _TRANSFER_FROM_SIG
                        ):
                            continue
                        args = list(ir.arguments)
                        if not args:
                            continue
                        first = args[0]
                        for fp in from_params:
                            if first is fp:
                                vulnerable_param = fp
                                vulnerable_node = node
                                break
                        if vulnerable_param is not None:
                            break
                    if vulnerable_param is not None:
                        break
                if vulnerable_param is None:
                    continue

                # Now check authorization guards.
                if _function_has_msgsender_eq_from(function, vulnerable_param):
                    continue
                if _function_calls_auth_helper(function):
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " calls transferFrom on user-supplied parameter `",
                    vulnerable_param,
                    "` at ",
                    vulnerable_node,
                    " without checking msg.sender == from or verifying a "
                    "signed intent - any approval granted to this contract "
                    "can be drained by any caller.\n",
                ]
                results.append(self.generate_result(info))

        return results
