"""
callback_hardcoded_status.py - Custom Slither detector.

Pattern (Chakra H-06, Karak - slice_aa P39):
    A cross-chain / async callback handler writes a status / result state
    variable to a literal success value (e.g. `Status.Settled`) but ignores
    the `bytes`/`bytes32` payload that encodes the actual remote outcome.
    Because the payload is never inspected, an attacker can call the
    callback with arbitrary arguments and have the request marked
    successful even when the remote leg failed (or never happened).

Detection strategy (conservative, fixture-driven):
    1. Walk non-vendored contracts. For each declared function whose name
       matches a callback regex (callback / onReceive / onResult /
       fulfill / handle).
    2. Function must write at least one state variable (otherwise it has
       no effect to weaponize).
    3. Function must declare at least one `bytes`-shaped parameter (the
       remote-result payload).
    4. That payload parameter must NEVER be read in the function body
       (no node has it in `local_variables_read`).
    5. Flag - the callback ignores the payload yet still mutates state.

This is the inverse of `callback-no-revalidation` (wave5): that detector
fires when ANY require/assert is missing; this one fires specifically
when the result-bearing payload itself is unused, regardless of guards.

@author auditooor wave9
@pattern slice_aa P39 / Chakra H-06 / Karak
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

_CALLBACK_RE = _re.compile(
    r"(?i)(callback|onreceive|onresult|onmessage|fulfill|handle)"
)

_PAYLOAD_TYPE_HINTS = ("bytes", "bytes32")


def _is_callback_name(function) -> bool:
    name = function.name or ""
    if not name:
        return False
    return _CALLBACK_RE.search(name) is not None


def _payload_params(function):
    """Return parameters whose declared type is bytes / bytes calldata / bytes32."""
    out = []
    for p in function.parameters:
        t = str(getattr(p, "type", "") or "")
        # Catch "bytes", "bytes calldata", "bytes memory", "bytes32".
        if any(t.startswith(h) for h in _PAYLOAD_TYPE_HINTS):
            out.append(p)
    return out


def _param_is_read(function, param) -> bool:
    """True if `param` appears in any node.local_variables_read."""
    for node in function.nodes:
        for lv in node.local_variables_read:
            if lv is param:
                return True
    return False


class CallbackHardcodedStatus(AbstractDetector):
    """Callback writes a status state variable while ignoring its payload."""

    ARGUMENT = "callback-hardcoded-status"
    HELP = (
        "Cross-chain callback writes status state variable but never reads "
        "its payload parameter - remote outcome is ignored, attacker forces success"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Callback Hard-codes Status, Ignores Payload"
    WIKI_DESCRIPTION = (
        "A cross-chain or async callback (`*Callback`, `onReceive`, "
        "`onResult`, `fulfill*`, `handle*`) accepts a `bytes` payload that "
        "encodes the remote leg's actual outcome but never reads it, and "
        "still writes a status state variable. The handler effectively "
        "marks every request as successful regardless of what happened on "
        "the source chain. Reported in Chakra H-06 (`receive_cross_chain_callback`) "
        "and a similar Karak finding."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
enum Status { Pending, Settled, Failed }
mapping(bytes32 => Status) public status;

function onCrossChainCallback(bytes32 id, bytes calldata data) external {
    status[id] = Status.Settled;          // BUG: ignores `data`
}
```
1. Attacker calls `onCrossChainCallback(victimRequestId, "")` directly.
2. `status[victimRequestId]` flips to `Settled` even though no remote
   message was relayed.
3. The protocol now treats the request as successful and releases funds /
   credits the attacker."""
    WIKI_RECOMMENDATION = (
        "Decode the payload (`abi.decode(data, (...))`) and derive the "
        "status from the actual remote outcome, not from a hard-coded "
        "constant. Validate the relayer / endpoint via `msg.sender` so the "
        "callback cannot be invoked directly by attackers."
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
                if not _is_callback_name(function):
                    continue
                # Must mutate state - pure reporting hooks are safe.
                if not function.state_variables_written:
                    continue

                payloads = _payload_params(function)
                if not payloads:
                    continue

                # Identify payload params that are NEVER read in the body.
                ignored = [p for p in payloads if not _param_is_read(function, p)]
                if not ignored:
                    continue

                ignored_names = ", ".join(p.name for p in ignored)
                written_names = ", ".join(
                    sv.name for sv in function.state_variables_written
                )
                info: DETECTOR_INFO = [
                    function,
                    " is a callback that writes state [" + written_names + "] "
                    "but never reads its payload parameter(s) [" + ignored_names
                    + "] - the remote outcome is ignored and any caller can "
                    "force a successful status.\n",
                ]
                results.append(self.generate_result(info))

        return results
