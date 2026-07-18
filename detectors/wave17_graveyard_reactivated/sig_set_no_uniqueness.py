"""
sig_set_no_uniqueness.py - Custom Slither detector.

Pattern (Chakra duplicate-validator-signatures - slice_aa P46):
    A multi-signer verification function takes an array of signatures
    (`bytes[]`, `bytes32[]`, `Signature[]`) and iterates them, recovering
    a signer per element via `ecrecover` / a `recover*` / `verify*`
    helper, and increments a counter for each valid validator. It then
    checks `count >= threshold`. If it never tracks WHICH validator
    produced each signature, the same validator can sign N times and
    reach quorum alone.

Detection strategy:
    1. Walk non-vendored contracts.
    2. For each declared function, find one with at least one parameter
       whose type renders as `bytes[]`, `bytes32[]`, or `*Signature[]`.
    3. The function body must contain a STARTLOOP node followed by:
         - an InternalCall (or HighLevelCall, or SolidityCall to ecrecover)
           to a callee whose name matches `(?i).*(recover|verify).*`,
         - a counter `++` increment.
    4. Inside the loop region there must be NO require/assert node - that
       is the signal that the implementer is not sanity-checking the
       recovered signer against any uniqueness invariant.
    5. Flag.

A real fix (sorted-strict-monotonic, mapping-dedupe, bitmap, address[]
tracker) always yields a require/assert inside the loop body. This
heuristic is conservative - it only flags loops with zero in-loop
guards, which is the canonical vulnerable shape.

@author auditooor wave9
@pattern slice_aa P46 / Chakra duplicate-validator-signatures
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
from slither.core.cfg.node import NodeType
from slither.core.declarations import Function, SolidityFunction
from slither.core.solidity_types.elementary_type import ElementaryType
from slither.slithir.operations import (
    InternalCall,
    HighLevelCall,
    SolidityCall,
    Binary,
    BinaryType,
)
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_RECOVER_RE = _re.compile(r"(?i)(recover|verify|ecrecover)")

_ECRECOVER = SolidityFunction("ecrecover(bytes32,uint8,bytes32,bytes32)")


def _has_signature_array_param(function) -> bool:
    for p in function.parameters:
        t = str(getattr(p, "type", "") or "")
        if not t.endswith("[]"):
            continue
        # bytes[], bytes32[], <something>Signature[], Sig[]
        base = t[:-2].strip()
        if base in ("bytes", "bytes32"):
            return True
        if "signature" in base.lower() or base.lower().endswith("sig"):
            return True
    return False


def _ir_is_recover_call(ir) -> bool:
    # Solidity builtin ecrecover.
    if isinstance(ir, SolidityCall) and ir.function == _ECRECOVER:
        return True
    if isinstance(ir, (InternalCall, HighLevelCall)):
        callee = ir.function
        if isinstance(callee, Function) and callee.name:
            if _RECOVER_RE.search(callee.name):
                return True
    return False


def _function_has_loop(function) -> bool:
    return any(n.type == NodeType.STARTLOOP for n in function.nodes)


def _function_has_recover_and_increment(function) -> bool:
    has_recover = False
    has_increment = False
    for n in function.nodes:
        for ir in n.irs:
            if _ir_is_recover_call(ir):
                has_recover = True
            if isinstance(ir, Binary) and ir.type == BinaryType.ADDITION:
                from slither.slithir.variables import Constant
                operands = (ir.variable_left, ir.variable_right)
                if any(
                    isinstance(o, Constant) and str(o.value) == "1"
                    for o in operands
                ):
                    has_increment = True
    return has_recover and has_increment


def _function_has_address_dedup_guard(function) -> bool:
    """A real fix tracks signers across iterations. Heuristic: any
    require/assert node in the function that reads an `address`-typed
    local variable is treated as a dedupe / uniqueness guard."""
    for node in function.nodes:
        if not node.contains_require_or_assert():
            continue
        for lv in node.local_variables_read:
            t = getattr(lv, "type", None)
            if isinstance(t, ElementaryType) and t.name == "address":
                return True
    # Bitmap / mapping-based fixes write a state variable inside the loop;
    # we treat any in-function state write whose name hints dedupe as safe.
    for sv in function.state_variables_written:
        nm = (getattr(sv, "name", "") or "").lower()
        if any(h in nm for h in ("seen", "used", "claimed", "signed", "bitmap")):
            return True
    return False


class SigSetNoUniqueness(AbstractDetector):
    """Multi-sig verifier loop counts signatures without deduping signers."""

    ARGUMENT = "sig-set-no-uniqueness"
    HELP = (
        "Multi-signer verifier loop counts signatures without enforcing "
        "signer uniqueness - same validator can sign N times to reach quorum"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Signature Set Lacks Signer Uniqueness Check"
    WIKI_DESCRIPTION = (
        "A quorum / multi-sig verifier accepts an array of signatures, "
        "iterates them, recovers the signer for each, and increments a "
        "counter when the recovered address is a known validator. Without "
        "tracking *which* signer produced each accepted signature, the same "
        "validator can supply N identical (or distinct but co-signed) "
        "signatures and reach the threshold alone, defeating the multi-party "
        "trust assumption. Reported in Chakra (duplicate validator signatures)."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function verifyQuorum(bytes32 digest, bytes[] calldata sigs) external view returns (bool) {
    uint256 count = 0;
    for (uint256 i = 0; i < sigs.length; i++) {
        address s = recover(digest, sigs[i]);
        if (isValidator[s]) count++;        // BUG: no dedupe
    }
    return count >= threshold;
}
```
A single compromised validator hands the same signature `threshold` times
(or signs the digest `threshold` times with fresh nonces). The counter
trivially reaches quorum and the message is treated as multi-validator
authenticated."""
    WIKI_RECOMMENDATION = (
        "Track the recovered signers across iterations: use a "
        "`mapping(address => bool) seen` reset per call, an `address[] seenList`, "
        "a uint256 bitmap keyed by validator index, OR require the input array "
        "to be sorted strictly-monotonic by signer (`require(s > lastSigner)`). "
        "Each accepted signer must be unique."
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
                if not _has_signature_array_param(function):
                    continue

                if not _function_has_loop(function):
                    continue
                if not _function_has_recover_and_increment(function):
                    continue
                if _function_has_address_dedup_guard(function):
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " iterates a signature array, recovers a signer per "
                    "element, and increments a quorum counter without any "
                    "guard tracking signer uniqueness - the same validator "
                    "can sign multiple slots to reach threshold.\n",
                ]
                results.append(self.generate_result(info))

        return results
