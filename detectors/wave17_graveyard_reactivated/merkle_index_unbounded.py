"""
merkle_index_unbounded.py - Custom Slither detector.

Pattern (Zellic slice_aa EIG-10, CRITICAL): a function accepts a user-supplied
`uint256 index` that is used in merkle-proof navigation - array subscript,
bit-shift, or as a parameter to a merkle/verify/proof library call - without
a `require(index < X)` bound check. This lets an attacker traverse past the
declared tree depth and forge proofs for leaves at synthetic indices.

Detection strategy:
    1. Find functions that have a parameter named `index`/`idx`/`_index` of type uint256.
    2. Confirm the parameter is used in (a) an ArraySubscript (indexing into a
       state array), OR (b) as an argument to a HighLevelCall whose function
       name contains `verify`/`proof`/`merkle`.
    3. Scan all require/assert nodes in the function; if none of them read the
       same local variable in a comparison (node.contains_require_or_assert()
       and reads the local variable) → flag.

The bound check is approximated: any require that reads the same local
variable satisfies the bound requirement.

@author auditooor wave8
@pattern slice_aa EIG-10
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
from slither.core.declarations import Function
from slither.slithir.operations import HighLevelCall, Index
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_INDEX_PARAM_NAMES = ("index", "idx", "_index", "_idx", "leafindex")

_MERKLE_KEYWORDS = ("verify", "proof", "merkle")


def _uint_index_params(function):
    out = []
    for p in function.parameters:
        name = (getattr(p, "name", "") or "").lower()
        tp = str(getattr(p, "type", "") or "")
        if name in _INDEX_PARAM_NAMES and "int" in tp:
            out.append(p)
    return out


def _param_used_as_subscript_or_merkle_arg(function, param) -> bool:
    for node in function.nodes:
        # Subscript usage
        for ir in node.irs:
            if isinstance(ir, Index):
                # ir.variable_right is the index operand
                rhs = getattr(ir, "variable_right", None)
                if rhs is param:
                    return True
            if isinstance(ir, HighLevelCall):
                callee = ir.function
                if isinstance(callee, Function):
                    fname = (callee.name or "").lower()
                    if any(k in fname for k in _MERKLE_KEYWORDS):
                        for arg in ir.arguments:
                            if arg is param:
                                return True
    return False


def _param_bounded_in_require(function, param) -> bool:
    """True if any require/assert node reads the parameter."""
    for node in function.nodes:
        if not node.contains_require_or_assert():
            continue
        for v in node.local_variables_read:
            if v is param:
                return True
    return False


class MerkleIndexUnbounded(AbstractDetector):
    """Detect user-supplied merkle-proof index parameters with no bounds check."""

    ARGUMENT = "merkle-index-unbounded"
    HELP = (
        "Function parameter `uint256 index` used in proof/array lookup "
        "without require(index < MAX_DEPTH) - enables out-of-bounds proofs"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Unbounded Merkle Proof Index"
    WIKI_DESCRIPTION = (
        "Merkle-proof verifiers that accept a user-supplied `uint256 index` to "
        "select a leaf or navigate a proof must assert `index < 2**MAX_DEPTH` (or "
        "against an explicit state-variable bound). Without the check, an attacker "
        "can supply an arbitrarily large index and either reach storage past the "
        "intended tree, exploit an integer overflow during bit-shift, or forge a "
        "valid proof for a synthetic leaf. This is the Eigenlayer EIG-10 bug class."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
bytes32[] public proofs;
function verify(uint256 index, bytes32 leaf) external view returns (bool) {
    return proofs[index] == leaf;   // BUG: index has no upper bound
}
```
Attacker passes an arbitrary index outside the declared depth and proves a leaf
that was never committed in the Merkle root."""
    WIKI_RECOMMENDATION = (
        "Add `require(index < MAX_DEPTH, \"oob\")` (or against the declared bound) "
        "at the top of any function that uses the index for proof navigation."
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
                params = _uint_index_params(function)
                if not params:
                    continue
                for p in params:
                    if not _param_used_as_subscript_or_merkle_arg(function, p):
                        continue
                    if _param_bounded_in_require(function, p):
                        continue
                    info: DETECTOR_INFO = [
                        function,
                        " accepts user-supplied index parameter `",
                        p.name or "index",
                        "` and uses it in proof/array lookup without any "
                        "require(index < BOUND) check. Out-of-bounds proofs "
                        "may be accepted.\n",
                    ]
                    results.append(self.generate_result(info))

        return results
