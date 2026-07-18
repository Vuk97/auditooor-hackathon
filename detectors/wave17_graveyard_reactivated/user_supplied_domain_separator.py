"""
user_supplied_domain_separator.py - Custom Slither detector.

Pattern (Next Gen H-01, slice_ab): An EIP-712 verification function takes the
`domainSeparator` as a CALLER-SUPPLIED parameter rather than computing it from
a cached constant or `block.chainid + address(this)`. The user can supply a
crafted domainSeparator that authenticates a signature originally signed for
ANOTHER protocol - cross-contract signature replay.

Detection strategy:
    1. Iterate every declared function in non-vendored contracts.
    2. Identify any function parameter named matching `(domain|separator)` of
       type `bytes32` ("domain-sep param").
    3. Confirm the function uses `ecrecover` (signature verification path).
    4. Confirm a flow from the parameter into the digest: the parameter must
       appear in the source of a node that also references `keccak256` /
       `\\x19\\x01` (EIP-712 envelope). We use source-text inspection because
       Slither lowers the abi.encodePacked to many irreducible IR ops.
    5. Flag the function.

@author auditooor wave9
@pattern slice_ab Next Gen H-01
"""

import re
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract

from slither.core.declarations import SolidityFunction
from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_DOMAIN_PARAM_RE = re.compile(r"domain|separator", re.IGNORECASE)
_KECCAK_RE = re.compile(r"keccak256", re.IGNORECASE)
_ENVELOPE_RE = re.compile(r"1901|0x19|x19\\x01", re.IGNORECASE)


def _is_bytes32(t) -> bool:
    return str(t) == "bytes32"


def _domain_param(function):
    """Return the first bytes32 parameter whose name matches domain/separator."""
    for p in function.parameters or []:
        nm = getattr(p, "name", "") or ""
        if _DOMAIN_PARAM_RE.search(nm) and _is_bytes32(getattr(p, "type", None)):
            return p
    return None


def _calls_ecrecover(function) -> bool:
    target = SolidityFunction("ecrecover(bytes32,uint8,bytes32,bytes32)")
    for ir in function.solidity_calls:
        if ir.function == target:
            return True
    return False


def _param_flows_into_digest(function, param) -> bool:
    """Heuristic: param name appears in the source of a node that also has
    `keccak256` and the EIP-712 0x1901 envelope OR another keccak256 call."""
    pname = param.name
    if not pname:
        return False
    pname_re = re.compile(r"\b" + re.escape(pname) + r"\b")
    for node in function.nodes:
        sm = getattr(node, "source_mapping", None)
        content = getattr(sm, "content", None) if sm else None
        if not content:
            continue
        if not pname_re.search(content):
            continue
        if _KECCAK_RE.search(content) and _ENVELOPE_RE.search(content):
            return True
    return False


class UserSuppliedDomainSeparator(AbstractDetector):
    """Detect EIP-712 verifiers that accept the domain separator as an
    untrusted function parameter."""

    ARGUMENT = "user-supplied-domain-separator"
    HELP = (
        "EIP-712 verifier accepts domainSeparator as a function parameter - "
        "cross-protocol signature replay"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "User-Supplied EIP-712 Domain Separator"
    WIKI_DESCRIPTION = (
        "An EIP-712 verification function that accepts the `domainSeparator` "
        "as a caller-supplied parameter (rather than reading it from a cached "
        "constant or rebuilding it from `block.chainid` and `address(this)`) "
        "lets an attacker authenticate a message signed for a completely "
        "different protocol. A signature originally bound to e.g. protocol A "
        "can be replayed against protocol B by passing protocol A's domain "
        "separator into B's verifier."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function verify(
    bytes32 domainSeparator,            // attacker-controlled
    bytes32 structHash,
    uint8 v, bytes32 r, bytes32 s
) external pure returns (address) {
    bytes32 digest = keccak256(
        abi.encodePacked(bytes2(0x1901), domainSeparator, structHash)
    );
    return ecrecover(digest, v, r, s);
}
```
1. Victim signs a message in protocol A using A's domainSeparator.
2. Attacker calls `verify` on protocol B passing A's domainSeparator and the
   original signature.
3. ecrecover recovers the victim's address - protocol B treats the message as
   authenticated and executes whatever the structHash authorises."""
    WIKI_RECOMMENDATION = (
        "Hard-code the domain separator as an immutable computed in the "
        "constructor from `block.chainid + address(this)` (preferably via "
        "OpenZeppelin's EIP712 base) and never accept it from calldata."
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
                p = _domain_param(function)
                if p is None:
                    continue
                if not _calls_ecrecover(function):
                    continue
                if not _param_flows_into_digest(function, p):
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " in ",
                    contract,
                    " accepts the EIP-712 domain separator as a caller-"
                    "supplied parameter and feeds it into ecrecover - "
                    "cross-protocol signature replay risk.\n",
                ]
                results.append(self.generate_result(info))

        return results
