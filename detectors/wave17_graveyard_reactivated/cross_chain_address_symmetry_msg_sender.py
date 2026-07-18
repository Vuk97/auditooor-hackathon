"""
cross_chain_address_symmetry_msg_sender.py - Custom Slither detector.

Pattern (Nudge M-03, Thorwallet H-02 - slice_ac):
    A cross-chain composer / OFT adapter / bridge wrapper takes a value
    from a user on the source chain and forwards it through a bridge
    primitive (`send`, `sendFrom`, `bridge`, `compose`, `lzSend`,
    `swap`, ...) - but uses `msg.sender` on the source chain as the
    *recipient* on the destination chain. On any chain that is not
    EVM-equivalent (or simply has a different keystore / smart-wallet
    deployment), the source-chain attacker's address is owned by an
    entirely different entity (or no one) on the destination, and the
    funds land out of reach.

Detection strategy:
    1. Walk non-vendored contracts. For each declared external/public
       function, walk every node and every IR.
    2. Find HighLevelCall IRs whose callee name matches
       (?i)(send|bridge|compose|lz|swap|relay).
    3. Inspect the IR's arguments. If `msg.sender` (a SolidityVariable
       named `msg.sender`) appears at any position OTHER than the first
       argument, flag - the first arg is conventionally the destination
       chain id / endpoint id / domain, but every later positional address
       slot is a recipient candidate.

@author auditooor wave9
@pattern slice_ac / Nudge M-03 / Thorwallet H-02
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
from slither.core.declarations import Function
from slither.core.declarations.solidity_variables import SolidityVariableComposed
from slither.slithir.operations import HighLevelCall
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_BRIDGE_RE = _re.compile(
    r"(?i)(send|bridge|compose|lz|swap|relay)"
)


def _is_bridge_call(ir: HighLevelCall) -> bool:
    callee = ir.function
    if not isinstance(callee, Function):
        return False
    name = callee.name or ""
    if not name:
        return False
    return _BRIDGE_RE.search(name) is not None


def _arg_is_msg_sender(arg) -> bool:
    return (
        isinstance(arg, SolidityVariableComposed)
        and (getattr(arg, "name", "") or "") == "msg.sender"
    )


class CrossChainAddressSymmetryMsgSender(AbstractDetector):
    """Bridge call uses msg.sender as recipient on the destination chain."""

    ARGUMENT = "cross-chain-address-symmetry-msg-sender"
    HELP = (
        "Cross-chain bridge call passes msg.sender as the destination-chain "
        "recipient - assumes EVM-style address symmetry that does not hold"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Cross-Chain Composer Uses msg.sender as Destination Recipient"
    WIKI_DESCRIPTION = (
        "An OFT adapter / cross-chain composer / bridge wrapper invokes a "
        "bridge primitive (`send`, `sendFrom`, `bridge`, `compose`, `lzSend`, "
        "`swap`, ...) and passes `msg.sender` directly as the recipient "
        "address on the destination chain. This silently assumes the same "
        "address is controlled by the same entity on every chain - which is "
        "false on non-EVM-equivalent chains (Cosmos, Solana, Aptos, Tron), "
        "and unreliable even between EVM chains when smart-wallets / "
        "factories differ. Reported in Nudge M-03 and Thorwallet H-02."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function crossChainTransfer(uint32 dst, uint256 amount) external {
    bridge.send(dst, msg.sender, amount);    // BUG: msg.sender on dst chain
}
```
Alice (an EOA on Ethereum) calls `crossChainTransfer(SOLANA_EID, 100e6)`.
Her Ethereum address is meaningless on Solana; the bridge mints / releases
the tokens to a Solana account that no one controls (or that someone else
permissionlessly created at the same address)."""
    WIKI_RECOMMENDATION = (
        "Always require the caller to explicitly name the destination-chain "
        "recipient: `function crossChainTransfer(uint32 dst, address recipient, "
        "uint256 amount)`. Never re-use `msg.sender` across chains."
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

                for node in function.nodes:
                    flagged = False
                    for ir in node.irs:
                        if not isinstance(ir, HighLevelCall):
                            continue
                        if not _is_bridge_call(ir):
                            continue
                        # Walk arguments AFTER the first positional slot.
                        for idx, arg in enumerate(ir.arguments):
                            if idx == 0:
                                continue
                            if _arg_is_msg_sender(arg):
                                info: DETECTOR_INFO = [
                                    function,
                                    " calls bridge primitive ",
                                    ir.function,
                                    " with msg.sender as a destination-chain "
                                    "argument at ",
                                    node,
                                    " - addresses are not symmetric across "
                                    "chains; recipient should be supplied by "
                                    "the caller.\n",
                                ]
                                results.append(self.generate_result(info))
                                flagged = True
                                break
                        if flagged:
                            break
                    if flagged:
                        break

        return results
