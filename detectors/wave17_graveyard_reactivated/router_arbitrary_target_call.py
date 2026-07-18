"""
router_arbitrary_target_call.py - Custom Slither detector.

Pattern (W8-9 - LiFi/Socket/Gamma ~$65M in 2024): a permissionless external
function accepts a user-supplied `address target` (or similar) parameter AND
invokes `target.call(data)` / `target.delegatecall(data)` on it. Attacker sets
target=USDC, data=transferFrom(victim,attacker,amount) to drain approvals.

Detection strategy (simplified & conservative per instructions):
  1. Walk contract.functions_and_modifiers_declared.
  2. Skip if function has an ACL modifier (onlyOwner/onlyRole/etc) - admin-gated.
  3. Walk nodes; find LowLevelCall IRs.
  4. If the LowLevelCall.destination traces back to a function parameter
     (i.e. param is in ir.node.local_variables_read or destination identity is
     a parameter of the function), flag.

Flags for ANY arbitrary-target `.call()` / `.delegatecall()` on a function
parameter, regardless of approval-holding heuristic (too hard to model).
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
from slither.slithir.operations import LowLevelCall
from slither.utils.output import Output


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
})

_CALL_NAMES = {"call", "delegatecall"}

SKIP_KEYWORDS = ("test", "mock", "setup", "fixture", "helper", "deploy", "script")


def _has_acl_modifier(function) -> bool:
    for m in function.modifiers:
        if (m.name or "").lower() in _ACL_MODIFIERS:
            return True
    return False


def _has_msgsender_require(function) -> bool:
    for node in function.nodes:
        if not node.contains_require_or_assert():
            continue
        for sv in node.solidity_variables_read:
            if sv.name == "msg.sender":
                return True
    return False


class RouterArbitraryTargetCall(AbstractDetector):
    """
    Permissionless function calls .call/.delegatecall on a user-supplied
    address parameter - enables arbitrary-target drain of approvals.
    """

    ARGUMENT = "router-arbitrary-target-call"
    HELP = (
        "Permissionless function invokes .call/.delegatecall on a parameter "
        "address - attacker can drain approvals via USDC.transferFrom"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Router Arbitrary Target Call"
    WIKI_DESCRIPTION = (
        "A permissionless external function takes a `target` address parameter "
        "and invokes `target.call(data)` / `target.delegatecall(data)` where "
        "`data` is also user-supplied. If the contract holds any ERC20 "
        "approvals - which any router/aggregator does - the attacker can set "
        "target to the token contract and data to `transferFrom(victim, attacker, "
        "amount)`, draining every user that has approved the router. This is the "
        "exact class that drained LiFi, Socket, Gamma, and Dexible for ~$65M "
        "in 2024."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
contract Router {
    function execute(address target, bytes calldata data) external {
        (bool ok,) = target.call(data);
        require(ok);
    }
}
```
Attacker calls execute(USDC, abi.encodeWithSelector(IERC20.transferFrom.selector,
victim, attacker, MAX_APPROVAL)). USDC sees msg.sender = Router, which every
victim has approved. USDC transfers victim's full approval to the attacker."""
    WIKI_RECOMMENDATION = (
        "Restrict the function to an admin role, OR maintain an explicit "
        "allowlist of trusted target contracts (e.g. only 1inch router, "
        "0x exchange), OR ensure the data selector is never a transferFrom-like "
        "opcode. Never forward an arbitrary (target, data) pair from an "
        "unrestricted entrypoint."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if any(k in contract.name.lower() for k in SKIP_KEYWORDS):
                continue
            if is_vendored_or_test_contract(contract):
                continue

            for function in contract.functions_and_modifiers_declared:
                if function.visibility not in ("external", "public"):
                    continue
                if function.is_constructor:
                    continue
                # Skip admin-gated functions
                if _has_acl_modifier(function):
                    continue
                # Skip if an explicit msg.sender == X guard is present
                if _has_msgsender_require(function):
                    continue

                params = set(function.parameters)
                if not params:
                    continue

                for node in function.nodes:
                    for ir in node.irs:
                        if not isinstance(ir, LowLevelCall):
                            continue
                        if ir.function_name not in _CALL_NAMES:
                            continue
                        dest = ir.destination
                        # Check if destination is a parameter of this function.
                        if dest in params:
                            info: DETECTOR_INFO = [
                                function,
                                f" invokes low-level .{ir.function_name}() "
                                "on a user-supplied parameter at ",
                                node,
                                " - attacker controls target AND data, "
                                "enabling drain of any ERC20 approval held "
                                "by this contract.\n",
                            ]
                            results.append(self.generate_result(info))
                            break
                    else:
                        continue
                    break

        return results
