"""
partial_calldata_hash_consent.py - Custom Slither detector.

Pattern (Zellic slice_af Metavest, HIGH): a governance/consent modifier or
function hashes only a partial slice of calldata (e.g. the trailing 32 bytes)
and compares that hash against a stored consent mapping. An authority can
supply arbitrary leading calldata bytes - e.g. a completely different function
selector and arguments - while keeping the hashed tail unchanged. The consent
check passes, but the executed payload is attacker-chosen.

Observed in Metavest `consentCheck`:
    assembly { tail := keccak256(sub(calldatasize(), 0x20), 0x20) }
    require(consented[tail], "no consent");

Detection strategy (assembly source-text + function-name filter):
    1. For every function/modifier declared on a non-vendored contract, whose
       lowercase name contains one of: "consent", "approve", "authoriz",
       "permit", "sign", "verify", "amend".
    2. Walk its nodes; for any NodeType.ASSEMBLY node, read node.source_mapping
       .content - which is the raw Yul block as written by the developer.
    3. In that source text, look for `keccak256(` used together with
       `calldatasize` or `calldataload` - a signal that the hash input is a
       calldata slice rather than a fixed struct.
    4. Additionally require the assembly block NOT to compute keccak256 over
       the full range `keccak256(0, calldatasize())` - that form is equivalent
       to `keccak256(msg.data)` and is safe.
    5. ALSO skip the finding if elsewhere in the same function a node reads the
       SolidityVariable `msg.data` (developer hashes msg.data separately).

This gives a reliable signal on the Metavest pattern (trailing-bytes hash) and
on related variants (leading-bytes hash, fixed-offset slice) without flagging
the safe full-calldata keccak.

Dedup: no Slither builtin or wave1..10 detector covers partial-calldata
consent hashing. Related but distinct: `eip712_type_string_field_omission`
(wave3) targets EIP-712 struct hash builders, not calldata-slice hashing.

@author auditooor wave11
@pattern slice_af Metavest
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
from slither.core.cfg.node import NodeType
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

# Function / modifier name fragments that indicate a governance-consent path.
_CONSENT_FN_HINTS = (
    "consent",
    "approve",
    "authoriz",
    "permit",
    "sign",
    "verify",
    "amend",
)


def _assembly_uses_partial_calldata_hash(src: str) -> bool:
    """
    True if *src* (raw Yul text) hashes a calldata-derived slice that is
    demonstrably NOT the full calldata (i.e. the hash range does not start
    at byte 0 with length calldatasize()).
    """
    s = src.lower()
    if "keccak256(" not in s:
        return False
    # The hash input must reference calldata.
    if ("calldatasize" not in s) and ("calldataload" not in s):
        return False
    # Safe form: `keccak256(0, calldatasize())` or `keccak256(0x0, calldatasize())`
    # hashes the full calldata and is equivalent to `keccak256(msg.data)`.
    safe_patterns = (
        "keccak256(0, calldatasize",
        "keccak256(0x0, calldatasize",
        "keccak256(0x00, calldatasize",
    )
    for p in safe_patterns:
        if p.replace(" ", "") in s.replace(" ", ""):
            return False
    return True


def _function_reads_msg_data(function) -> bool:
    """True if any node in *function* reads the solidity variable `msg.data`."""
    for node in function.nodes:
        for sv in node.solidity_variables_read:
            if getattr(sv, "name", "") == "msg.data":
                return True
    return False


class PartialCalldataHashConsent(AbstractDetector):
    """
    Detect consent/authorization modifiers that hash only a partial slice of
    calldata, enabling authority-controlled payload substitution.
    """

    ARGUMENT = "partial-calldata-hash-consent"
    HELP = (
        "Consent modifier hashes a partial calldata slice rather than the full "
        "msg.data, letting an authority swap the executed payload while "
        "matching the pre-signed consent hash"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Partial Calldata Hash - Consent Check Bypass"
    WIKI_DESCRIPTION = (
        "A governance consent / permit modifier computes `keccak256` over a "
        "calldata slice (e.g. the last 32 bytes) instead of the full "
        "`msg.data`. Because the hash only commits to part of the input, "
        "an authority can submit the same-ish transaction with a different "
        "function selector or different leading argument bytes while keeping "
        "the hashed tail unchanged - passing the consent check but executing "
        "a completely different payload. Observed in Metavest "
        "`proposeMajorityMetavestAmendment` (Zellic slice_af)."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
modifier consentCheck() {
    bytes32 tail;
    assembly { tail := keccak256(sub(calldatasize(), 0x20), 0x20) }
    require(consented[tail], "no consent"); // only last 32 bytes hashed
    _;
}
```
1. DAO pre-signs consent for a specific amendment payload P.
2. Authority computes `tail = keccak256(P[len-32:len])` and stores consented[tail] = true.
3. Attacker-authority then submits `executeAmendment(EVIL, maliciousPayload)` whose
   trailing 32 bytes happen to match the same tail (trivially achieved via padding).
4. The consentCheck modifier passes; the executed call is arbitrary."""
    WIKI_RECOMMENDATION = (
        "Hash the full `msg.data` (`keccak256(msg.data)`) or the entire ABI-"
        "encoded struct including selector and all arguments. Never rely on "
        "a partial calldata slice for consent verification."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            for function in contract.functions_and_modifiers_declared:
                fname = (function.name or "").lower()
                if not any(h in fname for h in _CONSENT_FN_HINTS):
                    continue
                if _function_reads_msg_data(function):
                    continue
                for node in function.nodes:
                    if node.type != NodeType.ASSEMBLY:
                        continue
                    src = None
                    try:
                        if node.source_mapping is not None:
                            src = node.source_mapping.content
                    except Exception:
                        src = None
                    if not src:
                        continue
                    if not _assembly_uses_partial_calldata_hash(src):
                        continue
                    info: DETECTOR_INFO = [
                        function,
                        " uses inline assembly to hash a partial calldata "
                        "slice for consent verification at ",
                        node,
                        " - authority can substitute leading calldata "
                        "bytes (selector/args) while keeping the hashed "
                        "tail, executing arbitrary payloads under a valid "
                        "consent entry. Hash the full `msg.data` instead.\n",
                    ]
                    results.append(self.generate_result(info))
                    break

        return results
