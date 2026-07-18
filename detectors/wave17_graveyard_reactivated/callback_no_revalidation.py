"""
callback_no_revalidation.py - Custom Slither detector.

Pattern (cross-protocol, P13 - Bloom/EtherFi/Cultured):
    Protocol callback functions that WRITE to state variables WITHOUT any
    require() or assert() guard in the function body. These callbacks are
    invoked by external contracts (ERC721 safeTransfer, Uniswap V3 router,
    Aave flash-loan pool, LayerZero endpoint, etc.) and are expected to
    re-validate constraints that the initiating call would have enforced
    (amount > 0, caller auth, state != paused, address != 0, etc.).

    Without a guard, an adversary can call the callback directly - bypassing
    the initiating protocol entirely - and trigger state mutations with
    attacker-controlled arguments.

Detection strategy:
    1. Walk c.functions_and_modifiers_declared for each contract.
    2. Match function names against the canonical callback set:
           onERC1155Received, onERC1155BatchReceived, onERC721Received,
           uniswapV3SwapCallback, uniswapV3MintCallback,
           uniswapV3FlashCallback, receiveFlashLoan, executeOperation,
           lzReceive, dispatch, fulfillRandomness
    3. Check f.state_variables_written is non-empty.
    4. Check f.nodes for ANY node where contains_require_or_assert() is True.
       If ZERO guard nodes exist → candidate.
    5. Exception: skip if ALL state writes are "trusted-sender bookkeeping" -
       direct StateVariable assignments whose only read operand is msg.sender.
       (Pattern: `lastSender = msg.sender;` - harmless identity tracking.)

Distinction from existing detectors:
    - erc1155-receive-no-origin (wave3): checks if the ERC1155 `operator`/`from`
      PARAMETERS are read in any conditional node. DIFFERENT surface - that
      detector fires when operator/from are not validated in an if/require,
      even if OTHER requires exist. This detector fires when NO require/assert
      exists at all, regardless of which variable is checked.
    - erc1155-received-state-no-caller (wave4): checks for absence of a
      require(msg.sender == X) specifically. DIFFERENT - that detector would
      PASS a function with `require(amount > 0)` even though it has no
      msg.sender check. This detector fires when there are ZERO guards of any
      kind, which is the stronger (and more dangerous) subset.

Dedup check (slither --list-detectors | grep -i 'callback\|reentrancy'):
    reentrancy-* family catches re-entrancy via external call→state write.
    This detector catches the inverse: callback→state write with no guard,
    where no external call precedes the write. NOVEL.

Source: reference/corpus_mined/slice_ad.md - cross-protocol pattern P13.

@author auditooor wave5
@pattern cross-protocol callback revalidation
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
from slither.core.variables.state_variable import StateVariable
from slither.utils.output import Output


# Canonical set of well-known protocol callback function names.
# These are callbacks that external protocols call INTO the implementing
# contract - they must re-validate any constraints the protocol enforced.
_CALLBACK_NAMES = frozenset({
    "onERC1155Received",
    "onERC1155BatchReceived",
    "onERC721Received",
    "uniswapV3SwapCallback",
    "uniswapV3MintCallback",
    "uniswapV3FlashCallback",
    "receiveFlashLoan",
    "executeOperation",
    "lzReceive",
    "dispatch",
    "fulfillRandomness",
})

SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "interface")


def _is_callback(function) -> bool:
    """True if the function name matches a known protocol callback entry-point."""
    return function.name in _CALLBACK_NAMES


def _has_state_writes(function) -> bool:
    """True if the function writes to at least one state variable."""
    return bool(function.state_variables_written)


def _has_any_guard(function) -> bool:
    """
    True if ANY node in the function has a require() or assert().

    Uses the canonical node helper contains_require_or_assert() - same
    approach as tx_origin.py and erc1155_received_state_write_no_caller_check.py.
    """
    return any(n.contains_require_or_assert() for n in function.nodes)


def _all_writes_are_sender_tracking(function) -> bool:
    """
    Exception predicate: return True when the ONLY state writes in the
    function are direct assignments of the form `stateVar = msg.sender`.

    These "trusted-sender bookkeeping" writes (e.g. `lastCaller = msg.sender`)
    record who triggered a callback for logging/reentrancy purposes and do not
    represent a security-relevant state mutation that needs re-validation.

    Detection: walk IR for all Assignment ops where:
      - lvalue is a StateVariable (direct write, not a mapping/array slot)
      - ir.read contains exactly one variable whose name is "msg.sender"

    If EVERY StateVariable-lvalue IR in the function matches this pattern,
    the function is exempt from flagging.
    """
    sender_only_writes = []
    other_writes = []

    for node in function.nodes:
        for ir in node.irs:
            lval = getattr(ir, "lvalue", None)
            if not isinstance(lval, StateVariable):
                continue
            # Check if this write's only operand is msg.sender
            reads = list(ir.read)
            if len(reads) == 1 and reads[0].name == "msg.sender":
                sender_only_writes.append(lval.name)
            else:
                other_writes.append(lval.name)

    # Exempt only if we found at least one sender-tracking write AND
    # zero non-sender writes. (Empty sender_only_writes with empty
    # other_writes means mapping/array writes - still flag.)
    return len(other_writes) == 0 and len(sender_only_writes) > 0


class CallbackNoRevalidation(AbstractDetector):
    """
    Detect protocol callback functions that write state without any guard.
    """

    ARGUMENT = "callback-no-revalidation"
    HELP = (
        "Protocol callback writes state without any require/assert re-validation"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Callback Function Writes State Without Re-Validation Guards"
    WIKI_DESCRIPTION = (
        "Protocol callback entry-points (ERC721/ERC1155 receiver hooks, "
        "Uniswap V3 swap/mint/flash callbacks, Aave executeOperation, "
        "Balancer receiveFlashLoan, LayerZero lzReceive, Chainlink "
        "fulfillRandomness, etc.) are publicly callable functions. "
        "Legitimate invocations arrive from a trusted protocol contract "
        "after the protocol has enforced its own invariants. However, when "
        "the callback writes to state variables with no require() or assert() "
        "guard of any kind, an adversary can call the function directly with "
        "attacker-controlled arguments - bypassing the protocol entirely. "
        "Real-world examples: Bloom Finance (executeOperation credit inflation), "
        "EtherFi (onERC1155Received balance mint), Cultured (lzReceive replay)."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
contract NFTVault {
    mapping(address => uint256) public totalDeposits;

    // BUG: no require(msg.sender == trustedNFT), no require(from != address(0))
    function onERC721Received(
        address, address from, uint256, bytes calldata
    ) external returns (bytes4) {
        totalDeposits[from] += 1;          // state write - no guards
        return this.onERC721Received.selector;
    }
}
```
Attacker calls `onERC721Received(attacker, victim, 0, "")` directly.
No ERC721 transfer occurred; `totalDeposits[victim]` is incremented, granting
the victim (or attacker, choosing `from=attacker`) phantom credit they can
redeem."""
    WIKI_RECOMMENDATION = (
        "Add at minimum `require(msg.sender == trustedProtocolAddress)` at "
        "the top of every callback that modifies state. For callbacks that "
        "receive amounts or addresses as parameters, also re-validate "
        "invariants (e.g. `require(amount > 0)`, `require(from != address(0))`). "
        "For Uniswap V3 callbacks, use `verifyCallback(factory, pool)` from "
        "the Uniswap V3 periphery library. Store trusted addresses as "
        "`immutable` or owner-set state and validate at the start of every "
        "callback body."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            # Skip test/mock/interface contracts - high FP surface
            if any(k in contract.name.lower() for k in SKIP_KEYWORDS):
                continue
            if is_vendored_or_test_contract(contract):
                continue

            for function in contract.functions_and_modifiers_declared:
                # Step 1: must be a known protocol callback
                if not _is_callback(function):
                    continue

                # Step 2: must actually write state (pure stubs are safe)
                if not _has_state_writes(function):
                    continue

                # Step 3: if there is ANY require/assert anywhere, it has some
                # re-validation - not our target (may still be under-validated,
                # but that's a separate, subtler detector)
                if _has_any_guard(function):
                    continue

                # Step 4: exception - skip if only writes are `stateVar = msg.sender`
                # (trusted-sender bookkeeping, not a security-relevant mutation)
                if _all_writes_are_sender_tracking(function):
                    continue

                # Flag: callback writes state, zero guards
                written_names = ", ".join(
                    v.name for v in function.state_variables_written
                )
                info: DETECTOR_INFO = [
                    function,
                    " is a protocol callback that writes state variable(s) ["
                    + written_names
                    + "] without any require() or assert() guard - "
                    "any caller can invoke it with arbitrary arguments.\n",
                ]
                results.append(self.generate_result(info))

        return results
