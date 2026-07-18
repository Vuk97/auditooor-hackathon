"""
chain_id_destination_mismatch_unchecked.py - Custom Slither detector.

Pattern (Chakra H-04 - slice_aa P40):
    A cross-chain message handler accepts a `to_chain` / `destChainId` /
    `targetChainId` / `dstChainId` / `destinationChain` parameter (the
    chain the message was *intended for*) but never enforces that it
    equals `block.chainid` (or a stored `myChainId` immutable). Messages
    addressed to an entirely different destination chain are processed by
    this contract anyway.

Detection strategy:
    1. Walk non-vendored contracts. For each declared external/public
       function (skip view/pure, skip constructors).
    2. Find parameters whose name matches a destination-chain regex:
         (?i)(toChain|destChain|targetChain|dstChainId|destinationChain)
    3. The function must have at least one effect - either writes state
       OR emits an event - otherwise it is a pure helper.
    4. Walk every node that is a require/assert. The function is OK if
       any such node reads the destination-chain parameter (i.e. the
       parameter appears in `node.local_variables_read`). Otherwise flag.

@author auditooor wave9
@pattern slice_aa P40 / Chakra H-04
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
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_DESTCHAIN_RE = _re.compile(
    r"(?i)(tochain|destchain|targetchain|dstchain|destinationchain|dstchainid|destchainid)"
)


def _destchain_params(function):
    out = []
    for p in function.parameters:
        nm = p.name or ""
        if _DESTCHAIN_RE.search(nm):
            out.append(p)
    return out


def _function_has_effect(function) -> bool:
    """True if the function writes state OR emits an event."""
    if function.state_variables_written:
        return True
    # Walk for any EventCall IR.
    from slither.slithir.operations import EventCall
    for node in function.nodes:
        for ir in node.irs:
            if isinstance(ir, EventCall):
                return True
    return False


def _param_checked_in_require(function, param) -> bool:
    """True if `param` is read by at least one require/assert node."""
    for node in function.nodes:
        if not node.contains_require_or_assert():
            continue
        for lv in node.local_variables_read:
            if lv is param:
                return True
    return False


class ChainIdDestinationMismatchUnchecked(AbstractDetector):
    """Cross-chain handler accepts destChainId but never validates it."""

    ARGUMENT = "chain-id-destination-mismatch-unchecked"
    HELP = (
        "Cross-chain handler takes a destChainId/toChain parameter but "
        "never requires it equals block.chainid - messages for other "
        "chains are processed locally"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Cross-Chain Destination Chain ID Not Validated"
    WIKI_DESCRIPTION = (
        "A cross-chain bridge / message handler takes the intended "
        "destination chain ID as a parameter (`toChain`, `destChainId`, "
        "`targetChainId`, `dstChainId`, `destinationChain`) and acts on it "
        "without requiring `destChainId == block.chainid` (or an immutable "
        "snapshot thereof). Any message - including one explicitly bound for "
        "a *different* chain - is processed by this contract. Reported in "
        "Chakra H-04 (`receive_cross_chain_callback`)."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function receiveMessage(uint256 destChainId, bytes calldata payload) external {
    // BUG: no `require(destChainId == block.chainid)`.
    _process(payload);
}
```
A relayer / attacker submits a message that was intended for chain B to
the contract deployed on chain A. The handler processes it anyway, e.g.
mints tokens or releases funds that were pegged on a different chain."""
    WIKI_RECOMMENDATION = (
        "Cache `block.chainid` once in an `immutable myChainId` and add "
        "`require(destChainId == myChainId, \"wrong chain\")` at the top of "
        "every cross-chain entrypoint."
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

                params = _destchain_params(function)
                if not params:
                    continue

                if not _function_has_effect(function):
                    continue

                # If the destination-chain param is checked in any
                # require/assert, treat the function as safe.
                if any(_param_checked_in_require(function, p) for p in params):
                    continue

                names = ", ".join(p.name for p in params)
                info: DETECTOR_INFO = [
                    function,
                    " accepts destination-chain parameter(s) [" + names + "] "
                    "but never validates them against block.chainid - messages "
                    "addressed to other chains are processed locally.\n",
                ]
                results.append(self.generate_result(info))

        return results
