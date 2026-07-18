"""
bridge-proof-domain-route-binding-fire23

Detector capability for Solidity bridge route or verifier registries where a
weakly guarded route update feeds a later proof consumer, but the verified
proof digest is not bound to the expected source chain, destination chain,
route, and verifier.

This is candidate evidence only. Detector hits are not filing proof.
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


_TOKEN_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'|"
    r"//[^\n\r]*|"
    r"/\*.*?\*/",
    re.DOTALL,
)
_CONTRACT_CONTEXT_RE = re.compile(
    r"\b(?:bridge|cross[-_ ]?chain|gateway|route|router|adapter|messenger|"
    r"selector|verifier|proof|message|commitment|destination|source)\b",
    re.IGNORECASE,
)
_ROUTE_SETTER_NAME_RE = re.compile(
    r"(?i)^(?:set|configure|register|update|migrate|initialize)"
    r"[A-Za-z0-9_]*(?:Route|Adapter|Messenger|Verifier|Peer|Remote|Gateway|"
    r"ChainSelector|Selector)$"
)
_ROUTE_WRITE_RE = re.compile(
    r"(?is)\b(?:routes?|routeBy\w*|adapters?|adapterBy\w*|messengers?|"
    r"messengerBy\w*|verifiers?|verifierBy\w*|chainSelectors?|"
    r"selectorTo\w*)\s*(?:\[[^\]]+\]\s*){0,3}=\s*"
    r"|\b(?:routes?|adapters?|messengers?|verifiers?)\s*\[[^\]]+\]\s*\.",
)
_AUTH_RE = re.compile(
    r"(?is)\b(?:onlyOwner|onlyAdmin|onlyGovernance|onlyGovernor|onlyFactory|"
    r"onlyRole|onlyOperator|onlyManager|onlyConfigurator|onlyTimelock|"
    r"requires?Auth|authorized|isAuthorized|hasRole|_checkOwner|_authorize)\b"
    r"|require\s*\([^;{}]*msg\.sender\s*==\s*"
    r"(?:owner|admin|governance|governor|factory|operator|manager|"
    r"configurator|timelock|controller)"
)
_PROOF_CONSUMER_NAME_RE = re.compile(
    r"(?i)(verify|process|consume|finalize|settle|relay|submit|execute|send)"
    r"[A-Za-z0-9_]*(Proof|Message|Packet|Commitment|Route|Bridge)?"
)
_PROOF_MATERIAL_RE = re.compile(
    r"\b(?:proof|root|stateRoot|storageRoot|receiptRoot|commitment|messageHash|"
    r"payloadHash|packetHash|leaf|digest|signature)\b",
    re.IGNORECASE,
)
_ROUTE_READ_RE = re.compile(
    r"(?is)\b(?:routes?|routeBy\w*|adapters?|adapterBy\w*|messengers?|"
    r"messengerBy\w*|verifiers?|verifierBy\w*|selectorTo\w*)\s*"
    r"(?:\[[^\]]+\]\s*){1,3}"
    r"|\broute\s*\.\s*(?:adapter|messenger|verifier)"
)
_VERIFY_CALL_RE = re.compile(
    r"(?is)\b(?:verify|verifyProof|verifyMessage|verifyCommitment|"
    r"isValidProof)\s*\([^;{}]*(?:proof|digest|root|messageHash|payloadHash)"
)
_HASH_EXPR_RE = re.compile(
    r"(?P<expr>(?:keccak256|sha256)\s*\(\s*(?:abi\.encode(?:Packed)?|"
    r"bytes\.concat)\s*\([^;{}]{0,1000}\)\s*\))",
    re.IGNORECASE | re.DOTALL,
)

_DOMAIN_GROUP_PATTERNS = (
    (
        "source",
        re.compile(
            r"\b(?:source|src|origin|remote|from)\w*(?:ChainId|Chain|Domain|"
            r"DomainId|NetworkId|Eid)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "destination",
        re.compile(
            r"\b(?:destination|dest|dst|target|local|to)\w*(?:ChainId|Chain|"
            r"Domain|DomainId|NetworkId|Eid)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "route",
        re.compile(
            r"\b(?:route|routeId|routeID|routeKey|lane|channel|selector|"
            r"bridgeId|bridgeID)\w*\b",
            re.IGNORECASE,
        ),
    ),
    (
        "verifier",
        re.compile(
            r"\b(?:verifier|proofVerifier|messageVerifier|routeVerifier|"
            r"lightClient)\w*\b",
            re.IGNORECASE,
        ),
    ),
)
_REQUIRED_GROUPS = {"source", "destination", "route", "verifier"}


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


def _visibility(function) -> str:
    return str(getattr(function, "visibility", "") or "").lower()


def _is_public_entry(function) -> bool:
    return _visibility(function) in {"public", "external"}


def _domain_groups(text: str) -> set[str]:
    return {name for name, pattern in _DOMAIN_GROUP_PATTERNS if pattern.search(text)}


def _hash_exprs(text: str) -> list[str]:
    return [match.group("expr") for match in _HASH_EXPR_RE.finditer(text)]


def _has_weak_route_update(function) -> bool:
    if not _is_public_entry(function):
        return False
    source = _code_only(_source_of(function))
    if not source:
        return False
    name = getattr(function, "name", "") or ""
    if not _ROUTE_SETTER_NAME_RE.search(name):
        return False
    if not _ROUTE_WRITE_RE.search(source):
        return False
    if _AUTH_RE.search(source):
        return False
    return bool({"source", "destination", "route"} & _domain_groups(source))


def _hash_has_full_domain_binding(expr: str) -> bool:
    return _REQUIRED_GROUPS.issubset(_domain_groups(expr))


def _has_unbound_route_proof_consumer(function) -> bool:
    if not _is_public_entry(function):
        return False
    source = _code_only(_source_of(function))
    if not source:
        return False
    name = getattr(function, "name", "") or ""
    if not _PROOF_CONSUMER_NAME_RE.search(name):
        return False
    if not _PROOF_MATERIAL_RE.search(source):
        return False
    if not _ROUTE_READ_RE.search(source):
        return False
    if not _VERIFY_CALL_RE.search(source):
        return False
    if not _REQUIRED_GROUPS.issubset(_domain_groups(source)):
        return False

    for expr in _hash_exprs(source):
        if not _PROOF_MATERIAL_RE.search(expr):
            continue
        if not _hash_has_full_domain_binding(expr):
            return True
    return False


class BridgeProofDomainRouteBindingFire23(AbstractDetector):
    ARGUMENT = "bridge-proof-domain-route-binding-fire23"
    HELP = (
        "Weak bridge route update feeds a proof verifier whose digest omits "
        "source chain, destination chain, route, or verifier binding"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = (
        "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/"
        "bridge-proof-domain-route-binding-fire23.yaml"
    )
    WIKI_TITLE = "Bridge proof digest omits mutable route domain binding"
    WIKI_DESCRIPTION = (
        "A bridge route, adapter, messenger, selector, or verifier registry is "
        "weakly guarded and a later proof consumer reads that mutable route. "
        "If the proof digest is built only from message or root material, a "
        "route update can redirect verification without the proof committing "
        "to the expected source chain, destination chain, route, and verifier."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "An attacker front-runs or otherwise changes a bridge route verifier. "
        "The settlement path then looks up the mutable route and asks that "
        "verifier to accept keccak256(messageHash, root, amount). Because the "
        "digest omits the source chain, destination chain, route key, and "
        "verifier identity, a proof valid in one lane can be replayed through "
        "the attacker-controlled route."
    )
    WIKI_RECOMMENDATION = (
        "Gate route, adapter, messenger, selector, and verifier updates behind "
        "the authoritative owner, factory, or governance path. Bind source "
        "chain, destination chain, route key, verifier address, contract "
        "address, proof root, and payload hash into the verified digest."
    )

    SUBMISSION_POSTURE = "NOT_SUBMIT_READY"
    COVERAGE_CLAIM = "detector_fixture_smoke_only"
    PROMOTION_ALLOWED = False

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            contract_source = _code_only(_source_of(contract))
            if not _CONTRACT_CONTEXT_RE.search(contract_source):
                continue

            route_setters = [
                function
                for function in contract.functions_and_modifiers_declared
                if _has_weak_route_update(function)
            ]
            if not route_setters:
                continue

            setter_names = ", ".join(getattr(fn, "name", "<unknown>") for fn in route_setters)
            for function in contract.functions_and_modifiers_declared:
                if not _has_unbound_route_proof_consumer(function):
                    continue
                info: DETECTOR_INFO = [
                    function,
                    " consumes a proof through mutable bridge route state "
                    "while the verified digest omits source, destination, "
                    "route, or verifier binding. Weak route updater(s): ",
                    setter_names,
                    ".\n",
                ]
                results.append(self.generate_result(info))

        return results
