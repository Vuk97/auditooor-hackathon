"""
bridge-proof-domain-bypass-fire22

Detector capability for Solidity bridge settlement functions that accept
source chain, destination chain, receiver, and proof context, but build the
settlement or consume-once key from proof or payload material without binding
those bridge-domain fields.

This is candidate evidence only. It intentionally requires both a proof/root
acceptance path and a consumed/replayed marker so generic bridge message hash
helpers and already-covered BEEFY transcript helpers stay out of scope.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract

from slither.detectors.abstract_detector import (
    DETECTOR_INFO,
    AbstractDetector,
    DetectorClassification,
)
from slither.utils.output import Output


_BRIDGE_CONTEXT_RE = re.compile(
    r"\b(?:bridge|gateway|portal|crossChain|cross[-_ ]?chain|settle|"
    r"finalize|withdraw|relay|message|proof|root|commitment|receipt|"
    r"MerkleProof|consume|consumed|processed)\b",
    re.IGNORECASE,
)
_PROOF_OR_ROOT_RE = re.compile(
    r"\b(?:proof|proofRoot|root|stateRoot|storageRoot|receiptRoot|"
    r"commitment|messageHash|payloadHash|leaf|leafHash|receipt|"
    r"MerkleProof\s*\.\s*(?:verify|process)Proof|verifyProof)\b",
    re.IGNORECASE,
)
_ACCEPTANCE_RE = re.compile(
    r"\b(?:MerkleProof\s*\.\s*verify|MerkleProof\s*\.\s*processProof|"
    r"verifyProof|verifyMessage|verifyRoot|verifyCommitment|"
    r"require\s*\([^;{}]*(?:proof|root|commitment|leaf|messageHash))",
    re.IGNORECASE | re.DOTALL,
)
_CONSUME_RE = re.compile(
    r"\b(?:consumed|processed|used|spent|settled|claimed|finalized|"
    r"executed|receipts?|receiptConsumed)\s*\[[^\]]+\]\s*=\s*true"
    r"|\b(?:consumed|processed|used|spent|settled|claimed|finalized|"
    r"executed|receipt)[A-Za-z0-9_]*\s*\[[^\]]+\]\s*=\s*true"
    r"|\b(?:consumed|processed|used|spent|settled|claimed|finalized|"
    r"executed)\s*\.\s*(?:set|add)\s*\(",
    re.IGNORECASE | re.DOTALL,
)
_KEY_ASSIGN_RE = re.compile(
    r"\b(?:bytes32\s+)?(?P<name>(?:settlement|consume|consumed|receipt|"
    r"message|proof|claim|finalize|replay)[A-Za-z0-9_]*(?:Key|Id|Hash|Digest))"
    r"\s*=\s*(?P<expr>(?:keccak256|sha256)\s*\(\s*(?:abi\.encode"
    r"(?:Packed)?|bytes\.concat)\s*\([^;{}]{0,900}\)\s*\))",
    re.IGNORECASE | re.DOTALL,
)
_HASH_EXPR_RE = re.compile(
    r"(?P<expr>(?:keccak256|sha256)\s*\(\s*(?:abi\.encode(?:Packed)?|"
    r"bytes\.concat)\s*\([^;{}]{0,900}\)\s*\))",
    re.IGNORECASE | re.DOTALL,
)
_SAFE_DOMAIN_GUARD_RE = re.compile(
    r"\b(?:DOMAIN_SEPARATOR|domainSeparator|_domainSeparatorV4|"
    r"InvalidDomain|WrongDomain|WrongDestination|WrongReceiver|"
    r"WrongSource|sourceChainBound|destinationChainBound)\b",
    re.IGNORECASE,
)
_TOKEN_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'|"
    r"//[^\n\r]*|"
    r"/\*.*?\*/",
    re.DOTALL,
)

_DOMAIN_GROUP_PATTERNS = (
    (
        "source_chain",
        re.compile(
            r"\b(?:source|src|origin|remote|from)\w*(?:ChainId|Chain|Domain|"
            r"DomainId|NetworkId)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "destination_chain",
        re.compile(
            r"\b(?:destination|dest|dst|target|local|to)\w*(?:ChainId|Chain|"
            r"Domain|DomainId|NetworkId)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "receiver",
        re.compile(
            r"\b(?:receiver|recipient|to|beneficiary)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "lane",
        re.compile(r"\b(?:lane|channel|route|bridgeId|bridgeID)\w*\b", re.IGNORECASE),
    ),
)


def _source_of(obj) -> str:
    try:
        return obj.source_mapping.content or ""
    except Exception:
        return ""


def _code_only(source: str) -> str:
    def replace_token(match: re.Match[str]) -> str:
        text = match.group(0)
        return "\n" * text.count("\n") if "\n" in text else " "

    return _TOKEN_RE.sub(replace_token, source or "")


def _domain_groups(text: str) -> set[str]:
    return {name for name, pattern in _DOMAIN_GROUP_PATTERNS if pattern.search(text)}


def _hash_exprs(text: str) -> list[str]:
    exprs = [match.group("expr") for match in _KEY_ASSIGN_RE.finditer(text)]
    if exprs:
        return exprs
    return [match.group("expr") for match in _HASH_EXPR_RE.finditer(text)]


def _has_receiver_guard(text: str) -> bool:
    return bool(
        re.search(
            r"\b(?:require|if)\s*\([^;{}]*(?:receiver|recipient|beneficiary)"
            r"[^;{}]*(?:address\(0\)|msg\.sender|expectedReceiver|receiverDomain|"
            r"recipientDomain)",
            text,
            re.IGNORECASE | re.DOTALL,
        )
    )


def _has_domain_bound_consume_key(function) -> bool:
    source = _code_only(_source_of(function))
    if not source:
        return False
    if not _BRIDGE_CONTEXT_RE.search(source):
        return False
    if not _PROOF_OR_ROOT_RE.search(source):
        return False
    if not _ACCEPTANCE_RE.search(source):
        return False
    if not _CONSUME_RE.search(source):
        return False

    visible_domains = _domain_groups(source)
    required_domains = {"source_chain", "destination_chain", "receiver"}
    if not required_domains.issubset(visible_domains):
        return False
    if _SAFE_DOMAIN_GUARD_RE.search(source) and _has_receiver_guard(source):
        return False

    for expr in _hash_exprs(source):
        if not _PROOF_OR_ROOT_RE.search(expr):
            continue
        expr_domains = _domain_groups(expr)
        if required_domains - expr_domains:
            return True
    return False


class BridgeProofDomainBypassFire22(AbstractDetector):
    ARGUMENT = "bridge-proof-domain-bypass-fire22"
    HELP = (
        "Bridge proof settlement consumes a proof or payload key without "
        "binding source chain, destination chain, and receiver into the key"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = (
        "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/"
        "bridge-proof-domain-bypass-fire22.yaml"
    )
    WIKI_TITLE = "Bridge proof consume-once key omits domain context"
    WIKI_DESCRIPTION = (
        "Fixture-smoke/source-shape proof only. A Solidity bridge proof consumer "
        "accepts source-chain, destination-chain, receiver, and proof material, "
        "then marks a hash-derived settlement or consume-once key as used. If "
        "that key is derived only from proof/root/payload material, the same "
        "accepted proof can be replayed across bridge contexts."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A valid receipt proof for source chain A, destination chain B, and "
        "receiver R is settled with consumed[keccak256(root, receipt, amount)]. "
        "Because source chain, destination chain, and receiver are not part of "
        "the consumed key, the same proof tuple can be replayed through another "
        "bridge context that accepts the same root and receipt material."
    )
    WIKI_RECOMMENDATION = (
        "Derive the consumed key from the full bridge domain: source chain, "
        "destination chain, local receiver, bridge or channel id, proof root, "
        "receipt or payload hash, and amount. Also assert the destination "
        "domain is the local chain before settlement."
    )

    SUBMISSION_POSTURE = "NOT_SUBMIT_READY"
    COVERAGE_CLAIM = "detector_fixture_smoke_only"
    PROMOTION_ALLOWED = False

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if not _BRIDGE_CONTEXT_RE.search(_code_only(_source_of(contract))):
                continue

            for function in contract.functions_and_modifiers_declared:
                if not _has_domain_bound_consume_key(function):
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " consumes a bridge proof key while source chain, "
                    "destination chain, and receiver are visible in the "
                    "settlement path but omitted from the hash key.\n",
                ]
                results.append(self.generate_result(info))

        return results
