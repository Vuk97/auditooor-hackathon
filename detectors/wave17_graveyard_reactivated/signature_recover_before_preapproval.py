"""
signature_recover_before_preapproval.py - Custom Slither detector.

Pattern (Cantina 3.2.2 - ctf-exchange-v2 Signatures.validateOrderSignature):
Order validators commonly support two authorization paths - a fresh
ECDSA signature OR a preapproved-order storage flag. A buggy
implementation calls `ecrecover` / `ECDSA.recover` first and then only
consults the preapproval mapping if the signature path did not return the
expected signer. Because the recover path reverts on malformed signature
data (wrong length, low-s, etc.), a user who pre-approved their order
cannot submit a zero-byte signature - the revert happens before the
preapproval fallback runs.

Detection strategy:
    1. For each declared function, find whether it reads a state mapping
       whose name contains /preapprov/ (case-insensitive).
    2. In the same function, find whether it calls ecrecover directly or
       calls an internal helper whose name matches /recover|validateSig/.
    3. For each (preapproval-read-node, recover-call-node) pair, check
       node.node_id ordering: if the recover call happens strictly before
       the preapproval read, flag the function.

@author auditooor wave11
@pattern Cantina 3.2.2
"""

import re
import sys as _sys
from pathlib import Path as _Path

_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract

from slither.core.declarations import SolidityFunction
from slither.core.variables.state_variable import StateVariable
from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.slithir.operations import (
    HighLevelCall,
    InternalCall,
    SolidityCall,
)
from slither.utils.output import Output


SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup")
_PREAPPROVED_RE = re.compile(r"pre.?approv", re.IGNORECASE)
_RECOVER_HELPER_RE = re.compile(r"(recover|validateSignature|verifySig)", re.IGNORECASE)

_ECRECOVER = SolidityFunction("ecrecover(bytes32,uint8,bytes32,bytes32)")


def _find_preapproved_state_var(function):
    for sv in function.state_variables_read:
        if not isinstance(sv, StateVariable):
            continue
        if _PREAPPROVED_RE.search(sv.name or ""):
            return sv
    return None


def _first_node_reading_var(function, state_var):
    for node in function.nodes:
        if state_var in node.state_variables_read:
            return node
    return None


def _first_node_with_recover(function):
    for node in function.nodes:
        for ir in node.irs:
            if isinstance(ir, SolidityCall) and ir.function == _ECRECOVER:
                return node
            if isinstance(ir, HighLevelCall):
                fn = ir.function
                if fn is not None and _RECOVER_HELPER_RE.search(fn.name or ""):
                    return node
            if isinstance(ir, InternalCall):
                fn = ir.function
                if fn is not None and _RECOVER_HELPER_RE.search(fn.name or ""):
                    return node
    return None


class SignatureRecoverBeforePreapproval(AbstractDetector):
    """Signature validator reverts on malformed sigs before checking
    the preapproval fallback."""

    ARGUMENT = "signature-recover-before-preapproval"
    HELP = (
        "validateSignature helper calls ecrecover before consulting the "
        "preapproved mapping - malformed sigs revert before the preapproval "
        "fallback is reached."
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Preapproval checked after ecrecover"
    WIKI_DESCRIPTION = (
        "An order-signature validator that supports both EIP-712 signatures "
        "and a preapproved-order storage flag must consult the storage flag "
        "FIRST. Otherwise, a malformed or zero-byte signature reverts inside "
        "`ecrecover` / `ECDSA.recover` before the preapproval fallback "
        "executes, so a user who pre-approved their order cannot actually "
        "use it. This is Polymarket ctf-exchange-v2 Cantina finding 3.2.2."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function validateOrderSignature(bytes32 h, address signer, bytes calldata sig)
    external view returns (bool)
{
    bool validSig = ECDSA.recover(h, sig) == signer;  // reverts on bad sig
    if (validSig) return true;
    return preapproved[h];                              // unreachable
}
```
A user submits a zero-byte signature for an order they pre-approved.
`ECDSA.recover` reverts, the preapproval lookup is skipped, and a valid
order fails to match."""
    WIKI_RECOMMENDATION = (
        "Check the preapproval mapping first and short-circuit; only call "
        "`ECDSA.recover` if the caller did not rely on preapproval."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []
        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in SKIP_KEYWORDS):
                continue
            for function in contract.functions_and_modifiers_declared:
                if function.is_constructor:
                    continue

                sv = _find_preapproved_state_var(function)
                if sv is None:
                    continue
                preapproved_node = _first_node_reading_var(function, sv)
                if preapproved_node is None:
                    continue
                recover_node = _first_node_with_recover(function)
                if recover_node is None:
                    continue

                # Ordering: recover first
                rn_id = getattr(recover_node, "node_id", None)
                pn_id = getattr(preapproved_node, "node_id", None)
                if rn_id is None or pn_id is None:
                    continue
                if rn_id >= pn_id:
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " calls a signature-recover helper at ",
                    recover_node,
                    " before reading preapproval state ",
                    sv,
                    " at ",
                    preapproved_node,
                    " - malformed sigs revert before the preapproval "
                    "fallback is checked.\n",
                ]
                results.append(self.generate_result(info))
        return results
