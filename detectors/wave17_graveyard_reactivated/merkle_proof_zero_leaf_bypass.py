"""
merkle_proof_zero_leaf_bypass.py - Custom Slither detector.

ARG: merkle-proof-zero-leaf-bypass
SEVERITY: MEDIUM  CONFIDENCE: LOW

Pattern (from slice_ab - t3rn multi-proof zero-leaf bypass):

  Multi-proof verification (MerkleProof.verify / custom processProof) accepts a
  zero-leaf as valid input, allowing quorum bypass when the attacker crafts a
  proof whose leaf is bytes32(0). Some Merkle tree implementations treat the
  zero-leaf as a valid node value, enabling forged membership proofs.

Detection logic:
  1. Find external/public functions that call a Merkle-proof verification helper:
     - internal calls to a function named verify / processProof / multiProofVerify /
       verifyProof / checkProof
     - OR contain `keccak256` in the same node as the proof verification call
       (typical custom Merkle implementation pattern)
  2. Confirm the function receives a `leaf` / `node` / `hash` parameter of type
     bytes32 (the caller-supplied leaf value to verify).
  3. Check that NO require/assert node in the function reads that leaf parameter
     in a comparison with zero (proxy for `require(leaf != bytes32(0))`).
  4. Flag if (1) and (2) are true and (3) finds no zero-guard.

IR observations (verified against fixture):
  - `require(leaf != bytes32(0))` compiles to:
      TypeConversion TMP_8 = CONVERT 0 to bytes32
      Binary TMP_9(bool) = leaf != TMP_8
      SolidityCall require(bool,string)(TMP_9, ...)
    Node has contains_require_or_assert() == True AND leaf in local_variables_read.
  - Vulnerable claim() has leaf in local_variables_read at the verify call node
    but NOT in any require node.
  - Clean claim() has leaf in a require node before the verify call.

Gotchas:
  - `local_variables_read` on a node returns LocalVariable objects; we compare
    using set membership against function.parameters (same object identity).
  - The zero check may also appear as `require(leaf > 0)` using a Binary >
    comparison - we approximate this as "any require node reading the leaf param".
  - Functions where the leaf is computed internally (not from a parameter) are
    NOT flagged - this is intentional, the risk only exists when the caller
    supplies the leaf directly.

Dedup: no Slither builtin covers merkle-zero-leaf bypass.
  `slither --list-detectors | grep -iE "merkle|leaf|proof"` → nothing.

Source: reference/corpus_mined/slice_ab.md - t3rn multi-proof bypass
@author auditooor wave7
@pattern merkle-proof-zero-leaf-bypass
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
from slither.slithir.operations import InternalCall, SolidityCall, HighLevelCall
from slither.utils.output import Output

SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

# Function name substrings indicating Merkle proof verification.
_VERIFY_HINTS = (
    "verify",
    "processproof",
    "multiproofverify",
    "verifymerkle",
    "verifyleaf",
    "verifyproof",
    "checkproof",
    "proveinclude",
    "verifyinclusion",
)

# Parameter name substrings indicating the caller-supplied leaf value.
_LEAF_PARAM_HINTS = (
    "leaf",
    "node",
    "claim",
    "data",
    "value",
    "hash",
)


def _is_bytes32_like(param_type) -> bool:
    """Return True if the parameter type looks like bytes32."""
    type_str = str(param_type).lower()
    return "bytes32" in type_str


def _find_leaf_param(func):
    """
    Return the first function parameter whose name (lowercased) suggests a
    Merkle leaf value AND whose type is bytes32-like.
    Returns None if no such parameter exists.
    """
    for param in func.parameters:
        name_lower = param.name.lower() if param.name else ""
        if any(h in name_lower for h in _LEAF_PARAM_HINTS):
            if _is_bytes32_like(param.type):
                return param
    return None


def _has_merkle_verify_call(func) -> bool:
    """
    Return True if the function contains an InternalCall or HighLevelCall to
    a verify/processProof-like function, OR contains keccak256 (custom Merkle).

    Detects:
      - InternalCall to internal verify helper (custom implementation)
      - HighLevelCall to MerkleProof.verify (library call)
      - SolidityCall to keccak256 (inside a loop - typical Merkle leaf hashing)
    """
    for node in func.nodes:
        for ir in node.irs:
            if isinstance(ir, InternalCall):
                callee = getattr(ir, "function", None)
                if callee is None:
                    continue
                if callee.__class__.__name__ == "Modifier":
                    continue
                callee_name = getattr(callee, "name", "").lower()
                if any(h in callee_name for h in _VERIFY_HINTS):
                    return True
            elif isinstance(ir, HighLevelCall):
                fn = getattr(ir, "function", None)
                if fn is None:
                    continue
                fn_name = getattr(fn, "name", "").lower()
                if any(h in fn_name for h in _VERIFY_HINTS):
                    return True
            elif isinstance(ir, SolidityCall):
                fn = getattr(ir, "function", None)
                if fn is None:
                    continue
                fn_name = getattr(fn, "name", "")
                if fn_name == "keccak256":
                    return True
    return False


def _has_zero_leaf_guard(func, leaf_param) -> bool:
    """
    Return True if any require/assert node in the function contains both:
      (a) a Binary IR that uses leaf_param as a direct operand, AND
      (b) a Constant(0) anywhere in the same node's IR operands.

    This is the specific proxy for `require(leaf != bytes32(0))`.

    IR pattern (confirmed in clean fixture):
      TypeConversion TMP = CONVERT 0 to bytes32
      Binary TMP2 = leaf != TMP    ← leaf is variable_left or variable_right
      SolidityCall require(bool,string)(TMP2, ...)

    Why NOT just `leaf in local_variables_read AND node.contains_require()`:
    The verify-call node `require(verify(proof, leaf), "invalid proof")`
    also reads leaf in a require node but is NOT a zero guard. The distinction
    is the presence of a Binary with `leaf` as a direct operand PLUS a Constant(0)
    in the same node.
    """
    from slither.slithir.operations import Binary
    from slither.slithir.variables import Constant

    for node in func.nodes:
        if not node.contains_require_or_assert():
            continue

        # Check (a): does any Binary IR have leaf_param as a direct operand?
        leaf_in_binary = False
        for ir in node.irs:
            if not isinstance(ir, Binary):
                continue
            left = getattr(ir, "variable_left", None)
            right = getattr(ir, "variable_right", None)
            if left is leaf_param or right is leaf_param:
                leaf_in_binary = True
                break

        if not leaf_in_binary:
            continue

        # Check (b): does any IR in the node read a Constant(0)?
        for ir in node.irs:
            for operand in getattr(ir, "read", []):
                if isinstance(operand, Constant) and operand.value == 0:
                    return True

    return False


class MerkleProofZeroLeafBypass(AbstractDetector):
    """
    Detect public/external functions that call a Merkle proof verifier with a
    caller-supplied bytes32 leaf but do not guard against a zero-leaf input.
    """

    ARGUMENT = "merkle-proof-zero-leaf-bypass"
    HELP = (
        "Merkle proof verify call uses a caller-supplied bytes32 leaf with no "
        "require(leaf != bytes32(0)) guard - zero-leaf can satisfy degenerate trees"
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Merkle Proof Zero-Leaf Bypass"
    WIKI_DESCRIPTION = (
        "A Merkle proof verification function receives the leaf value as a "
        "caller-supplied parameter (e.g. `bytes32 leaf`) but does not validate "
        "`require(leaf != bytes32(0))`. Some Merkle tree implementations treat "
        "the zero node as a valid intermediate hash, allowing an attacker to "
        "craft a short proof path for the zero-leaf that satisfies the "
        "root check. This enables forged membership proofs and quorum bypass. "
        "Pattern found in t3rn multi-root verification (slice_ab)."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
bytes32 public root;
function claim(bytes32[] calldata proof, bytes32 leaf) external {
    // No require(leaf != bytes32(0))
    require(verify(proof, leaf), "invalid proof");
    // attacker passes leaf = bytes32(0) with a crafted proof path
}
```
Attacker passes `leaf = bytes32(0)` and a carefully crafted `proof` array.
If the Merkle tree was built with default leaf values initialized to zero,
or if the tree allows zero-value nodes, the verifier computes a valid root
from the zero-leaf, passes the `verify` check, and processes the bogus claim."""
    WIKI_RECOMMENDATION = (
        "Add `require(leaf != bytes32(0), \"zero leaf\")` at the start of any "
        "function that accepts a caller-supplied Merkle leaf. For OZ MerkleProof, "
        "also consider using the double-hashing leaf convention: "
        "`leaf = keccak256(bytes.concat(keccak256(abi.encode(addr, amount))))` "
        "to prevent second-preimage and zero-leaf attacks."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if any(k in contract.name.lower() for k in SKIP_KEYWORDS):
                continue
            if is_vendored_or_test_contract(contract):
                continue

            for function in contract.functions_and_modifiers_declared:
                # Only public/external entry-points
                if function.visibility not in ("public", "external"):
                    continue
                if function.is_constructor:
                    continue

                # Step 1: find a caller-supplied bytes32 leaf parameter
                leaf_param = _find_leaf_param(function)
                if leaf_param is None:
                    continue

                # Step 2: function must call a Merkle verifier (or contain keccak256)
                if not _has_merkle_verify_call(function):
                    continue

                # Step 3: flag if no require node reads the leaf param
                if not _has_zero_leaf_guard(function, leaf_param):
                    info: DETECTOR_INFO = [
                        function,
                        " in ",
                        contract,
                        " calls a Merkle proof verifier with caller-supplied "
                        "leaf parameter `" + (leaf_param.name or "leaf") + "` "
                        "(bytes32) but has no require(leaf != bytes32(0)) guard. "
                        "An attacker may pass bytes32(0) to satisfy degenerate "
                        "Merkle tree proofs. Add "
                        "require(leaf != bytes32(0), \"zero leaf\") before verification.\n",
                    ]
                    results.append(self.generate_result(info))

        return results
