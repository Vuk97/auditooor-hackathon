"""
erc1155_receiver_missing_supportsinterface.py — Custom Slither detector.

Pattern (Cantina 3.2.1 — ctf-exchange-v2 ERC1155TokenReceiver.sol):
EIP-1155 requires every `ERC1155TokenReceiver` contract to implement the
ERC-165 `supportsInterface(bytes4)` method so that senders can verify the
receiver before forwarding tokens. A contract that exposes
`onERC1155Received` / `onERC1155BatchReceived` without `supportsInterface`
is non-compliant: some senders will refuse to transfer, and others will
treat the missing-interface as a silent pass.

Detection strategy:
    1. For each non-vendored contract, check whether it declares (or
       inherits) at least one of the two canonical receiver hooks.
    2. If it does, look up every function visible on the contract and
       require at least one whose signature is
       `supportsInterface(bytes4)`.
    3. If missing, flag the first receiver hook node.

@author auditooor wave11
@pattern Cantina 3.2.1
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
from slither.utils.output import Output


SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "interface")

ERC1155_RECEIVER_SIGS = {
    "onERC1155Received(address,address,uint256,uint256,bytes)",
    "onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)",
}

SUPPORTS_INTERFACE_SIG = "supportsInterface(bytes4)"


class Erc1155ReceiverMissingSupportsInterface(AbstractDetector):
    """ERC-1155 receiver contract missing `supportsInterface(bytes4)`."""

    ARGUMENT = "erc1155-receiver-missing-supportsinterface"
    HELP = (
        "Contract implements ERC1155 receiver hooks but does not declare "
        "`supportsInterface(bytes4)` as required by ERC-165 / EIP-1155."
    )
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "ERC1155 receiver missing supportsInterface"
    WIKI_DESCRIPTION = (
        "Every contract intended to receive ERC-1155 tokens must implement "
        "ERC-165 `supportsInterface(bytes4)` so that senders can detect the "
        "receiver and refuse transfers to contracts that cannot handle "
        "1155. Polymarket ctf-exchange-v2 initially shipped its "
        "`ERC1155TokenReceiver` mixin without this method; Cantina filed "
        "this as 3.2.1 and Polymarket fixed it in PR 70."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
contract Vault {
    function onERC1155Received(address,address,uint256,uint256,bytes calldata)
        external returns (bytes4) { return 0xf23a6e61; }
    // <-- no supportsInterface
}
```
A well-behaved ERC-1155 token uses `IERC165(to).supportsInterface(...)`
before calling the hook; this contract either reverts the transfer or, if
the token skips the check, silently passes without the receiver being
validated."""
    WIKI_RECOMMENDATION = (
        "Implement `supportsInterface(bytes4 interfaceId)` returning true "
        "for `type(IERC165).interfaceId` (0x01ffc9a7) and "
        "`type(IERC1155Receiver).interfaceId` (0x4e2312e0)."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []
        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if contract.is_interface or contract.is_library:
                continue
            if any(k in contract.name.lower() for k in SKIP_KEYWORDS):
                continue

            # Collect the contract's visible function signatures (including
            # inherited) — function.solidity_signature is canonical.
            all_sigs = set()
            for f in contract.functions:
                try:
                    all_sigs.add(f.solidity_signature)
                except Exception:
                    pass

            receiver_hits = ERC1155_RECEIVER_SIGS.intersection(all_sigs)
            if not receiver_hits:
                continue
            if SUPPORTS_INTERFACE_SIG in all_sigs:
                continue

            # Locate a receiver hook declaration to anchor the result.
            hook_func = None
            for f in contract.functions_and_modifiers_declared:
                try:
                    if f.solidity_signature in receiver_hits:
                        hook_func = f
                        break
                except Exception:
                    pass
            if hook_func is None:
                # Hook is inherited only — anchor on the contract.
                info: DETECTOR_INFO = [
                    contract,
                    " implements ERC1155 receiver hooks ",
                    ", ".join(sorted(receiver_hits)),
                    " but does not declare `supportsInterface(bytes4)`.\n",
                ]
            else:
                info: DETECTOR_INFO = [
                    hook_func,
                    " implements an ERC1155 receiver hook but the "
                    "enclosing contract ",
                    contract,
                    " does not declare `supportsInterface(bytes4)`.\n",
                ]
            results.append(self.generate_result(info))
        return results
