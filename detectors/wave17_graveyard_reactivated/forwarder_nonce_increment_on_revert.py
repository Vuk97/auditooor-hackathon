"""
forwarder_nonce_increment_on_revert.py - Custom Slither detector.

Pattern (Zellic slice_aa SLSF-21, HIGH): an EIP-2771 forwarder's execute /
forwardRequest / executeMetaTransaction function increments `nonces[req.from]`
BEFORE it makes the forwarded low-level call, and does not revert if that call
fails. Because the nonce is bumped unconditionally, a user's signed request
slot is permanently consumed when the inner call reverts, blocking the
relayer from ever replaying / retrying the same signed message.

Detection strategy:
    1. Walk user functions whose name matches execute / forwardRequest /
       executeMetaTransaction (case-insensitive substring).
    2. Locate the first node that WRITES a state variable whose name contains
       "nonce" (mapping write = StateVariable in node.state_variables_written).
    3. Locate the first node that performs a LowLevelCall.
    4. If the nonce-write node precedes the low-level-call node in
       function.nodes order AND no `require(success)` / `if (!success) revert`
       is present (node.contains_require_or_assert() with a LocalVariable that
       is the LowLevelCall's lvalue) → flag.
    5. Approximation: we look for ANY require/assert node in the function that
       is reached *after* the LowLevelCall and reads the success bool. If there
       is no such check, we flag.

@author auditooor wave8
@pattern slice_aa SLSF-21
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


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_FORWARDER_HINTS = (
    "execute",
    "forwardrequest",
    "forward",
    "executemetatransaction",
    "relay",
)


def _is_forwarder_fn(function) -> bool:
    name = (function.name or "").lower()
    return any(h in name for h in _FORWARDER_HINTS)


def _nonce_write_index(function) -> "tuple[int, object] | tuple[None, None]":
    """Return (idx, node) of the first node that writes a nonce-named state var."""
    for idx, node in enumerate(function.nodes):
        for sv in node.state_variables_written:
            if sv is None:
                continue
            name = (getattr(sv, "name", "") or "").lower()
            if "nonce" in name:
                return idx, node
    return None, None


def _lowlevel_call_index(function) -> "tuple[int, object, object] | tuple[None, None, None]":
    """Return (idx, node, lvalue) of the first LowLevelCall in the function."""
    for idx, node in enumerate(function.nodes):
        for ir in node.irs:
            if isinstance(ir, LowLevelCall):
                lval = getattr(ir, "lvalue", None)
                return idx, node, lval
    return None, None, None


def _success_checked_after(function, call_idx: int, call_lval) -> bool:
    """
    Return True if any node at index >= call_idx contains a require/assert
    or an IF branching on a LocalVariable whose name matches the call's
    success lvalue name. This is an over-approximation: any boolean check
    involving a variable called "success"/"ok" after the low-level call
    counts as a success check.
    """
    target_names = set()
    if call_lval is not None:
        nm = (getattr(call_lval, "name", None) or "").lower()
        if nm:
            target_names.add(nm)
    # Common bool-return variable names in Solidity meta-tx patterns.
    target_names.update({"success", "ok", "result"})

    for idx in range(call_idx, len(function.nodes)):
        node = function.nodes[idx]
        if not (node.contains_require_or_assert() or node.contains_if()):
            continue
        for v in node.local_variables_read:
            vn = (getattr(v, "name", "") or "").lower()
            if vn and vn in target_names:
                return True
    return False


class ForwarderNonceIncrementOnRevert(AbstractDetector):
    """Detect EIP-2771 forwarder that bumps nonce before an unchecked low-level call."""

    ARGUMENT = "forwarder-nonce-increment-on-revert"
    HELP = (
        "Forwarder increments nonces[req.from] before making the forwarded "
        "call and does not require(success) - inner revert consumes the nonce"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Forwarder Nonce Incremented Before Unchecked Forwarded Call"
    WIKI_DESCRIPTION = (
        "EIP-2771 forwarder-style functions (execute, forwardRequest, "
        "executeMetaTransaction) commonly bump `nonces[req.from]` before "
        "relaying the signed call via a low-level `.call`. If the inner call "
        "reverts and the forwarder does not bubble the revert, the user's "
        "nonce is permanently consumed - the same signed request can never "
        "be retried, effectively griefing the user and permanently burning "
        "the meta-transaction slot."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function execute(ForwardRequest calldata req) external {
    require(nonces[req.from] == req.nonce, "bad nonce");
    nonces[req.from]++;                         // BUG: nonce burnt first
    (bool ok,) = req.to.call(req.data);         // revert silently swallowed
}
```
Attacker triggers the relayed target to revert (e.g. transient liquidity,
slippage). The user signed the meta-tx to pay a relayer once; the relayer
collects the fee and the user is left with a burnt nonce and no state change."""
    WIKI_RECOMMENDATION = (
        "Make the call first, `require(ok, 'forwarded call failed')`, then "
        "bump the nonce. Alternatively, bubble up the inner revert so the "
        "whole transaction reverts and the nonce state is rolled back."
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
                if not _is_forwarder_fn(function):
                    continue

                n_idx, n_node = _nonce_write_index(function)
                if n_idx is None:
                    continue

                c_idx, c_node, c_lval = _lowlevel_call_index(function)
                if c_idx is None:
                    continue

                # Nonce write must precede the low-level call
                if not (n_idx < c_idx):
                    continue

                if _success_checked_after(function, c_idx, c_lval):
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " increments a nonce state variable at ",
                    n_node,
                    " before a low-level call at ",
                    c_node,
                    " whose success is never checked. A revert in the "
                    "forwarded call permanently burns the user's nonce. "
                    "Call first, require(success), then bump the nonce.\n",
                ]
                results.append(self.generate_result(info))

        return results
