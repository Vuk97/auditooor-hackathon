"""
erc1155_received_state_write_no_caller_check.py - Custom Slither detector.

Pattern: ERC1155 receiver callback (onERC1155Received / onERC1155BatchReceived)
that WRITES to a state variable without first verifying msg.sender is a trusted
ERC1155 contract. Any caller can forge the token-transfer context and trigger
the state change with arbitrary data.

This is DISTINCT from wave3 `erc1155-receive-no-origin` which checks whether
the operator/from PARAMETERS are validated in a conditional. This detector
checks for:
  1. State writes exist (f.state_variables_written is non-empty), AND
  2. No node in the function has both contains_require_or_assert() AND
     msg.sender in node.solidity_variables_read.

The correct fix is `require(msg.sender == trustedToken)` - not validating the
operator/from parameters (those are ERC1155 data, not the caller).

Dedup check:
    - erc1155-receive-no-origin (wave3 #13): checks operator/from param
      validation. This detector checks msg.sender. Complementary - both ship.
    - No Slither builtin covers this. NOVEL.

Source: external/glider-query-db/queries/ac-on-erc1155received.py

@author auditooor wave4
@pattern CTF/ERC1155 callback access control
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract

from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.utils.output import Output

# Canonical ERC1155 receiver signatures - per EIP-1155
_ERC1155_RECEIVER_SIGS = frozenset({
    "onERC1155Received(address,address,uint256,uint256,bytes)",
    "onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)",
})

SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "interface")


def _is_erc1155_receiver(function) -> bool:
    """True if the function is one of the two ERC1155 receiver callbacks."""
    return function.solidity_signature in _ERC1155_RECEIVER_SIGS


def _has_state_writes(function) -> bool:
    """True if the function writes to at least one state variable."""
    return bool(function.state_variables_written)


def _has_msg_sender_require(function) -> bool:
    """
    True if ANY node in the function has:
      (a) contains_require_or_assert(), AND
      (b) msg.sender in node.solidity_variables_read.

    This is the canonical guard pattern from tx_origin.py - the caller check
    that makes a receiver safe against unauthorized invocation.
    """
    for node in function.nodes:
        if not node.contains_require_or_assert():
            continue
        if any(v.name == "msg.sender" for v in node.solidity_variables_read):
            return True
    return False


class ERC1155ReceivedStateWriteNoCallerCheck(AbstractDetector):
    """
    Detect ERC1155 receiver callbacks that write state without a msg.sender guard.
    """

    ARGUMENT = "erc1155-received-state-no-caller"
    HELP = (
        "ERC1155 onReceived hook writes state without require(msg.sender == trustedToken)"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "ERC1155 Receiver State Write Without Caller Check"
    WIKI_DESCRIPTION = (
        "An implementation of onERC1155Received or onERC1155BatchReceived performs "
        "state-changing operations (writes to storage) without first verifying "
        "msg.sender against a trusted ERC1155 token contract. Because the callback "
        "is a publicly callable function, any external account can invoke it with "
        "arbitrary operator, from, id, and value arguments - bypassing the assumed "
        "ERC1155 transfer flow and triggering state changes (e.g. deposit credits, "
        "balance increments) with fabricated data."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
contract Vault {
    mapping(address => uint256) public deposits;

    function onERC1155Received(
        address operator, address from,
        uint256 id, uint256 value, bytes calldata data
    ) external returns (bytes4) {
        // BUG: no require(msg.sender == trustedToken)
        deposits[from] += value;      // state write with attacker-controlled `value`
        return 0xf23a6e61;
    }
}
```
Attacker calls `onERC1155Received(attacker, victim, 0, 1e18, "")` directly.
No ERC1155 transfer occurred; `deposits[victim]` is incremented by 1e18.
Attacker can then drain the vault using the inflated credit."""
    WIKI_RECOMMENDATION = (
        "Add `require(msg.sender == trustedERC1155Token, 'Unauthorized caller')` "
        "at the start of every onERC1155Received / onERC1155BatchReceived "
        "implementation that modifies state. Store the trusted token address "
        "in an immutable or owner-set variable. Alternatively, use "
        "OpenZeppelin's ERC1155Holder which only returns the selector and "
        "never modifies state."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if any(k in contract.name.lower() for k in SKIP_KEYWORDS):
                continue
            if is_vendored_or_test_contract(contract):
                continue

            for function in contract.functions_and_modifiers_declared:
                # Only ERC1155 receiver hooks
                if not _is_erc1155_receiver(function):
                    continue

                # Skip pure stubs - no state writes means no risk
                if not _has_state_writes(function):
                    continue

                # Skip if function has a msg.sender require guard
                if _has_msg_sender_require(function):
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " is an ERC1155 receiver hook that writes to state variable(s) "
                    "[",
                    ", ".join(v.name for v in function.state_variables_written),
                    "] without a `require(msg.sender == trustedToken)` guard. "
                    "Any caller can invoke it with forged data.\n",
                ]
                results.append(self.generate_result(info))

        return results
