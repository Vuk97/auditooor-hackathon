"""
bridge_bypasses_transfer_pause.py - Custom Slither detector.

Pattern (slice_ah - d3-doma, MEDIUM):
    An NFT / token contract has a pause flag state variable (named
    `blockAllTransfers`, `transfersPaused`, `paused`, ...) that is read
    in the standard `transfer` / `transferFrom` path. The contract also
    exposes a `bridge` / `crossChainTransfer` / `teleport` function that
    moves the asset out of the chain but DOES NOT consult the pause
    flag. Users bypass the pause by bridging out and back to a fresh
    address.

Detection strategy:
    1. Identify pause-flag state variables: `bool` SVs whose name matches
       `pause|paused|frozen|block|halt`.
    2. For each contract, verify at least one function-declared locally
       reads that SV AND its name matches `transfer|_update|_beforeToken
       Transfer` (the canonical transfer path).
    3. Then, for each function whose name matches `bridge|teleport|
       crossChain`, check that it does NOT read the same SV.
    4. Flag the bridge function.

Confidence: MEDIUM. Narrowed by (a) SV naming, (b) the existence of a
transfer-path function that already consults the flag - ensures we only
flag contracts where the developer's intention was clearly to pause all
outbound movement.
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
from slither.core.solidity_types import ElementaryType
from slither.core.variables.state_variable import StateVariable
from slither.utils.output import Output


_PAUSE_NAME_FRAGMENTS = ("pause", "frozen", "block", "halt", "lockdown")
_TRANSFER_FN_FRAGMENTS = ("transfer", "_update", "beforetokentransfer")
_BRIDGE_FN_FRAGMENTS = ("bridge", "teleport", "crosschain", "sendtochain", "burnandbridge")
_SKIP_KEYWORDS = ("test", "mock", "setup", "fixture", "helper", "deploy", "script")


def _bool_pause_svs(contract):
    out = []
    for sv in contract.state_variables:
        tp = sv.type
        if not isinstance(tp, ElementaryType):
            continue
        if str(tp) != "bool":
            continue
        name = (sv.name or "").lower()
        if any(frag in name for frag in _PAUSE_NAME_FRAGMENTS):
            out.append(sv)
    return out


def _function_reads_sv(function, sv: StateVariable) -> bool:
    for node in function.nodes:
        for read in node.state_variables_read:
            if read is sv:
                return True
    return False


class BridgeBypassesTransferPause(AbstractDetector):
    """Detect bridge/crossChain functions that skip the transfer pause flag."""

    ARGUMENT = "bridge-bypasses-transfer-pause"
    HELP = (
        "bridge/crossChain function does not read the contract's pause flag "
        "even though the transfer/_update path does - pause can be bypassed "
        "by bridging out and back"
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Bridge Function Bypasses Transfer Pause Flag"
    WIKI_DESCRIPTION = (
        "A token contract has a `blockAllTransfers` (or similar) pause flag "
        "that is consulted by the standard transfer path, but the contract's "
        "own `bridge`/`crossChain` function does not read the flag. Users can "
        "bypass the transfer freeze by bridging out and bridging back to a "
        "fresh address on the same chain. Observed in d3-doma NameToken "
        "(Zellic audit, MEDIUM)."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
bool public blockAllTransfers;

function transferFrom(address from, address to, uint256 id) external {
    require(!blockAllTransfers, "paused");
    // ...
}

function bridge(uint256 id, address remote) external {
    // No pause check - bypass.
    ownerOf[id] = address(0);
}
```
1. Admin sets `blockAllTransfers = true`.
2. Holder calls `bridge(tokenId, newAddr)` - succeeds.
3. On the remote chain, bridge-back mints to a different owner.
4. The "paused" transfer has effectively happened."""
    WIKI_RECOMMENDATION = (
        "Add `require(!blockAllTransfers, ...)` (or the equivalent modifier) "
        "to every cross-chain / bridge entrypoint, or factor the pause gate "
        "into a shared `_beforeTransfer` hook that both the standard transfer "
        "path and the bridge path call."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            pause_svs = _bool_pause_svs(contract)
            if not pause_svs:
                continue

            # For each pause SV, check the contract has a transfer-path fn
            # that reads it
            for sv in pause_svs:
                transfer_fn_reads = False
                for f in contract.functions_and_modifiers_declared:
                    fname = (f.name or "").lower()
                    if not any(frag in fname for frag in _TRANSFER_FN_FRAGMENTS):
                        continue
                    if any(frag in fname for frag in _BRIDGE_FN_FRAGMENTS):
                        continue  # skip - same fn would be bridge
                    if _function_reads_sv(f, sv):
                        transfer_fn_reads = True
                        break
                if not transfer_fn_reads:
                    continue

                # Flag every bridge-like fn that does NOT read the SV
                for f in contract.functions_and_modifiers_declared:
                    fname = (f.name or "").lower()
                    if not any(frag in fname for frag in _BRIDGE_FN_FRAGMENTS):
                        continue
                    if _function_reads_sv(f, sv):
                        continue
                    info: DETECTOR_INFO = [
                        f,
                        " is a bridge/crossChain entrypoint that does NOT read "
                        "pause flag ",
                        sv,
                        " even though the transfer path does. Users can bypass "
                        "the pause by bridging out and back.\n",
                    ]
                    results.append(self.generate_result(info))

        return results
