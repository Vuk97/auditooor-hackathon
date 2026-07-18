"""
swap_callback_reentrancy.py - Custom Slither detector.

Pattern (Cross-function reentrancy without ETH - Valantis):
    A Uniswap V3 swap callback (uniswapV3SwapCallback / pancakeV3SwapCallback)
    WRITES to a state variable (leaving dirty intermediate state) AND then
    makes an external call (HighLevelCall / LowLevelCall) in the SAME function.
    A second function in the same contract READS that same state variable.

    Because the external call can re-enter the second function before the
    callback clears the dirty state, the second function observes inconsistent
    (partial-swap) values.

Dedup check:
    slither --list-detectors | grep -i reentrancy
    → reentrancy-no-eth (#51): catches reentrancy where an external call
      is followed by a state write in the SAME function. This detector is
      DIFFERENT: it specifically targets swap CALLBACKS where the state write
      PRECEDES the external call (the typical callback shape - pay the pool
      first), and the reentrancy risk is cross-function (the dirty state is
      read by a DIFFERENT function that the external call re-enters).
      reentrancy-no-eth would not flag a function where the write comes before
      the call (it looks for write-after-call). NOVEL surface.

Detection strategy:
    1. Find functions named uniswapV3SwapCallback / pancakeV3SwapCallback.
    2. Confirm function WRITES to at least one state variable (dirty state).
    3. Confirm function makes at least one external call (HighLevelCall or
       LowLevelCall) AFTER the state write (any node order where
       state write node index < external call node index in function.nodes).
    4. Confirm that the same state variable is READ by at least one OTHER
       function in the same contract.
    5. Flag: dirty-state write → external call in callback + sibling function
       reads the dirty state.

Impact: HIGH - cross-function reentrancy can corrupt accounting.
Confidence: MEDIUM - swap callbacks are a specific well-known surface.

Source: reference/corpus_mined/slice_ac.md - Valantis HOT.
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
from slither.slithir.operations import HighLevelCall, LowLevelCall
from slither.slithir.variables import Constant
from slither.core.variables.state_variable import StateVariable
from slither.utils.output import Output


_SWAP_CALLBACK_NAMES = frozenset({
    "uniswapV3SwapCallback",
    "pancakeV3SwapCallback",
})

_SKIP_KEYWORDS = ("test", "mock", "setup", "fixture", "helper", "deploy", "script")


def _function_has_body(function) -> bool:
    return any(node.irs for node in function.nodes)


def _state_vars_written_before_external_call(function) -> set:
    """
    Walk function.nodes in order. Track state variables written by any IR.
    Return the set of state variables written before (or at the same node as)
    the first external call in the function.

    Uses the fact that function.nodes is in approximate CFG order for linear
    functions - acceptable for a triage detector.
    """
    written_before_call = set()
    call_seen = False

    for node in function.nodes:
        if call_seen:
            break
        # Detect external call in this node
        node_has_call = any(
            isinstance(ir, (HighLevelCall, LowLevelCall))
            for ir in node.irs
        )
        # Collect state writes in this node first, then check call.
        # Skip writes where the assigned value is a zero Constant (clear ops
        # like `partialAmount = 0` are CEI-safe - they don't leave dirty state).
        for ir in node.irs:
            lval = getattr(ir, "lvalue", None)
            if not isinstance(lval, StateVariable):
                continue
            # Check if the only read operand is Constant(0) - a clear write
            reads = list(ir.read)
            if len(reads) == 1 and isinstance(reads[0], Constant):
                try:
                    if int(reads[0].value) == 0:
                        continue  # skip clear-to-zero writes
                except (TypeError, ValueError):
                    pass
            written_before_call.add(lval)
        if node_has_call:
            call_seen = True

    return written_before_call


def _has_external_call(function) -> bool:
    """True if function contains any HighLevelCall or LowLevelCall."""
    for node in function.nodes:
        for ir in node.irs:
            if isinstance(ir, (HighLevelCall, LowLevelCall)):
                return True
    return False


def _sibling_reads_sv(contract, callback_func, dirty_svs) -> StateVariable:
    """
    Return the first state variable from dirty_svs that is READ by any
    OTHER declared function in the contract. Returns None if none found.
    """
    for fn in contract.functions_and_modifiers_declared:
        if fn is callback_func:
            continue
        fn_reads = set(fn.state_variables_read)
        for sv in dirty_svs:
            if sv in fn_reads:
                return sv
    return None


class SwapCallbackReentrancy(AbstractDetector):
    """
    Detect Uniswap V3 swap callbacks that write state and make external calls,
    leaving dirty state visible to sibling functions via cross-function reentrancy.
    """

    ARGUMENT = "swap-callback-reentrancy"
    HELP = (
        "Uniswap V3 swap callback writes state variable before external call - "
        "sibling function reads dirty state via cross-function reentrancy"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Swap Callback Cross-Function Reentrancy via Dirty Intermediate State"
    WIKI_DESCRIPTION = (
        "Uniswap V3 swap callbacks must pay the pool by transferring tokens to "
        "msg.sender (the pool). If intermediate accounting state is written "
        "before this external transfer, that state is 'dirty' (reflects a "
        "partially-complete swap) during the token transfer. An attacker can "
        "deploy a malicious ERC-20 token whose transfer() re-enters another "
        "function in the same contract that reads the dirty state variable, "
        "observing an inconsistent mid-swap value. This cross-function "
        "reentrancy (without ETH) is not caught by Slither's reentrancy-no-eth "
        "detector because the state write precedes (not follows) the external "
        "call. Observed in the Valantis HOT audit."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
uint256 public partialAmount;   // dirty during swap

function uniswapV3SwapCallback(int256 delta0, int256, bytes calldata) external {
    if (delta0 > 0) {
        partialAmount = uint256(delta0);     // write dirty state
        token0.transfer(msg.sender, uint256(delta0));  // external call - re-entry here
    }
}

function settle() external {
    uint256 amt = partialAmount;  // reads dirty partialAmount during re-entry!
    partialAmount = 0;
    totalSettled += amt;
}
```
Attacker deploys a malicious token0. During token0.transfer(), re-enters settle().
settle() reads partialAmount == delta0 before it is cleared, incrementing
totalSettled by the mid-swap amount. After the callback completes, partialAmount
is written again (=0 by settle), leading to accounting corruption."""
    WIKI_RECOMMENDATION = (
        "Apply the Checks-Effects-Interactions pattern inside the swap callback: "
        "clear or finalize all state variables BEFORE the external token transfer. "
        "Alternatively, protect all functions that read callback-written state with "
        "a nonReentrant modifier. Use OpenZeppelin ReentrancyGuard on both the "
        "callback and sibling functions that read intermediate state."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue
            if is_vendored_or_test_contract(contract):
                continue

            for function in contract.functions_and_modifiers_declared:
                # Step 1: must be a swap callback by name
                if function.name not in _SWAP_CALLBACK_NAMES:
                    continue

                # Step 2: must have a body
                if not _function_has_body(function):
                    continue

                # Step 3: must write state and make an external call
                if not function.state_variables_written:
                    continue
                if not _has_external_call(function):
                    continue

                # Step 4: find state vars written before the external call
                dirty_svs = _state_vars_written_before_external_call(function)
                if not dirty_svs:
                    continue

                # Step 5: a sibling function must read the dirty state var
                dirty_sv = _sibling_reads_sv(contract, function, dirty_svs)
                if dirty_sv is None:
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " in ",
                    contract,
                    " writes state variable ",
                    dirty_sv,
                    " before making an external call. A sibling function reads "
                    "this variable, which is observable as dirty intermediate "
                    "state during cross-function reentrancy through the external "
                    "call (e.g. malicious token transfer hook).\n",
                ]
                results.append(self.generate_result(info))

        return results
