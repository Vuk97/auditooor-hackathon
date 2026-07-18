"""
ecdsa_low_s_check_missing.py — Custom Slither detector.

Pattern: Contract calls ecrecover(hash, v, r, s) but does NOT validate that
`s <= secp256k1n / 2`. Without the low-s check, a valid signature (r, s, v)
can be transformed to (r, n-s mod n, v^1) — both recover the SAME address.
This is ECDSA signature malleability (SWC-117).

Ported from:
    external/glider-query-db/queries/lack-of-signature-validation-check-against-low-s-v.py

Exploitation context: malleability is exploitable when:
    - The contract uses the raw signature as a unique identifier (e.g. as a nonce).
    - A relayer deduplicates by tx signature hash.
    - The signature is part of a commit-reveal scheme.

Detection strategy:
    1. Find functions that call ecrecover().
    2. Skip functions that use OpenZeppelin ECDSA.recover() via HighLevelCall —
       ECDSA.recover() enforces low-s internally.
    3. Check if the function has a Binary comparison against the HALF_N constant
       `0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0`.
    4. Also check source for the hex constant or symbolic names (*HALF*N* / *MAX*S*).
    5. If no such check → flag.

API notes:
    - Constant values in Slither IR are represented as slithir.variables.Constant.
    - The HALF_N hex value appears as a Python int: 0x7fff...
    - Binary.variable_left / .variable_right are the operands.
    - Compare Constant.value as int or case-insensitive hex string.

Confidence: LOW — malleability is only exploitable in specific contexts.
OpenZeppelin ECDSA.recover() skip reduces FPs on modern contracts.
"""

import re
import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract

from slither.core.declarations import Function, SolidityFunction
from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.slithir.operations import Binary, BinaryType, HighLevelCall, SolidityCall
from slither.slithir.variables import Constant
from slither.utils.output import Output


SKIP_KEYWORDS = ("test", "mock", "setup", "fixture", "helper", "deploy", "script")

# secp256k1 half-order constant
_HALF_N = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
_HALF_N_HEX_LOWER = hex(_HALF_N)  # "0x7fff..."

_ECRECOVER_SIG = SolidityFunction("ecrecover(bytes32,uint8,bytes32,bytes32)")

# Regex for HALF_N hex literal or symbolic constant names in source
_HALF_N_RE = re.compile(
    r'(0x7[Ff]{3}[0-9a-fA-F]+|HALF.?N|MAX.?S\b|secp256k1n)',
    re.IGNORECASE,
)


def _calls_ecrecover(function) -> bool:
    for ir in function.solidity_calls:
        if isinstance(ir, SolidityCall):
            if (ir.function == _ECRECOVER_SIG
                    or (hasattr(ir.function, "name")
                        and ir.function.name.startswith("ecrecover("))):
                return True
    return False


def _uses_ecdsa_recover_library(function) -> bool:
    """
    Return True if the function makes a HighLevelCall to a function named
    'recover' that belongs to a contract/library named 'ECDSA'.
    OZ ECDSA.recover() enforces low-s internally.
    """
    for node in function.nodes:
        for ir in node.irs:
            if not isinstance(ir, HighLevelCall):
                continue
            fn = ir.function
            if not isinstance(fn, Function):
                continue
            if fn.name != "recover":
                continue
            # Check if the library/contract is named ECDSA
            owner = getattr(fn, "contract", None) or getattr(fn, "contract_declarer", None)
            if owner and "ecdsa" in owner.name.lower():
                return True
    return False


def _is_half_n_constant(val) -> bool:
    """Return True if val is the HALF_N constant (as int or hex string)."""
    if isinstance(val, int):
        return val == _HALF_N
    if isinstance(val, str):
        try:
            return int(val, 16) == _HALF_N
        except (ValueError, TypeError):
            return False
    return False


def _has_low_s_check_ir(function) -> bool:
    """
    Return True if the function has a Binary comparison where one side is
    the HALF_N constant (catches require(s <= HALF_N) patterns).
    """
    for node in function.nodes:
        for ir in node.irs:
            if not isinstance(ir, Binary):
                continue
            # We care about LESS_EQUAL / GREATER_EQUAL / LESS / GREATER comparisons
            if ir.type not in (
                BinaryType.LESS_EQUAL,
                BinaryType.GREATER_EQUAL,
                BinaryType.LESS,
                BinaryType.GREATER,
            ):
                continue
            for operand in (ir.variable_left, ir.variable_right):
                if isinstance(operand, Constant) and _is_half_n_constant(operand.value):
                    return True
    return False


def _has_low_s_check_source(function) -> bool:
    """
    Source-level fallback: check node source_mapping.content for HALF_N hex
    or symbolic constant names.
    """
    for node in function.nodes:
        sm = getattr(node, "source_mapping", None)
        if sm and sm.content and _HALF_N_RE.search(sm.content):
            return True
    return False


class EcdsaLowSCheckMissing(AbstractDetector):
    """
    Detect ecrecover usage without ECDSA low-s malleability check.
    """

    ARGUMENT = "ecdsa-low-s-missing"
    HELP = "ecrecover used without low-s check — ECDSA signature malleability (SWC-117)"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW

    WIKI = "https://swcregistry.io/docs/SWC-117"
    WIKI_TITLE = "ECDSA Signature Malleability — Missing Low-S Check"
    WIKI_DESCRIPTION = (
        "A contract calls ecrecover(hash, v, r, s) without verifying that "
        "s <= secp256k1n / 2. For any valid ECDSA signature (r, s, v), a "
        "second valid signature (r, n-s, v^1) exists that recovers the same "
        "address. This malleability allows an attacker to produce a 'different' "
        "signature for the same message, breaking systems that use the raw "
        "signature bytes as a unique key (e.g. replay-protection nonces keyed "
        "by signature hash, off-chain deduplication by signature value). "
        "See SWC-117: https://swcregistry.io/docs/SWC-117"
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
mapping(bytes => bool) usedSigs;

function execute(bytes32 hash, uint8 v, bytes32 r, bytes32 s) external {
    bytes memory sig = abi.encodePacked(r, s, v);
    require(!usedSigs[sig], "replayed");
    usedSigs[sig] = true;
    address signer = ecrecover(hash, v, r, s);
    require(signer == owner);
    _doAction();
}
```
1. Owner signs (hash, v, r, s). Contract processes the action, marks sig used.
2. Attacker computes (r, n-s mod n, v^1) — a valid alternate form of the sig.
3. Attacker calls execute with the malleable sig: different bytes, same signer.
4. usedSigs[altSig] = false → action replayed despite replay protection."""
    WIKI_RECOMMENDATION = (
        "Add `require(uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        "5D576E7357A4501DDFE92F46681B20A0, 'malleable sig')` before "
        "calling ecrecover. Better: use OpenZeppelin ECDSA.recover() which "
        "enforces low-s and reverts on address(0) recovery automatically."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if any(k in contract.name.lower() for k in SKIP_KEYWORDS):
                continue
            if is_vendored_or_test_contract(contract):
                continue

            for function in contract.functions_and_modifiers_declared:
                if not _calls_ecrecover(function):
                    continue

                # OpenZeppelin ECDSA.recover() handles low-s internally — skip
                if _uses_ecdsa_recover_library(function):
                    continue

                # Check for low-s validation
                if _has_low_s_check_ir(function):
                    continue
                if _has_low_s_check_source(function):
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " calls ecrecover() without a low-s check. "
                    "Malleable signatures (r, n-s, v^1) recover the same "
                    "signer — use OpenZeppelin ECDSA.recover() or add "
                    "require(uint256(s) <= HALF_N).\n",
                ]
                results.append(self.generate_result(info))

        return results
