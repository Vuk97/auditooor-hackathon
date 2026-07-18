"""
bridge-external-replay-domain-fire34

Solidity recall-lift detector for bridge proof or message verification paths
that authenticate a digest, then consume or dispatch under external bridge
domain fields that are absent from the authenticated digest preimage. The
targeted shape is Snowbridge-style adaptor and BEEFY-client replay domain
omission: source chain, destination chain, gateway, adapter, light-client id,
message channel, or nonce lane are visible, but the verified digest is scoped
only to proof, root, nonce, payload, or commitment material.

Provenance:
- context_pack_id: auditooor.vault_context_pack.v1:resume:bfadc3c938400bc6
- context_pack_hash: bfadc3c938400bc6618f7f3ae8d500bbc8e5dce19f7f4e6c043195ffc6742129
- source refs:
  - reports/detector_lift_fire33_20260605/post_priorities_all.md
  - reference/patterns.dsl/bridge-proof-domain-bypass-umbrella.yaml
  - reference/patterns.dsl/bridge-proof-domain-bypass-verifier-digest-omits-domain.yaml
  - detectors/wave17/bridge_proof_adapter_domain_fire32.py
  - detectors/wave17/bridge_digest_domain_fire33.py
- attack_class: bridge-proof-domain-bypass
- verification_tier: tier-3-synthetic-taxonomy-anchored

Hits are candidate evidence only. NOT_SUBMIT_READY.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "bridge-external-replay-domain-fire34"
DETECTOR_SEVERITY_DEFAULT = "High"
SUBMISSION_POSTURE = "NOT_SUBMIT_READY"
COVERAGE_CLAIM = "detector_fixture_smoke_only"
PROMOTION_ALLOWED = False
VERIFICATION_TIER = "tier-3-synthetic-taxonomy-anchored"


@dataclass
class Finding:
    detector: str
    file: str
    line: int
    severity: str
    message: str
    function: Optional[str] = None


@dataclass
class FunctionSlice:
    name: str
    header: str
    body: str
    line: int
    body_line: int


_TOKEN_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'|"
    r"//[^\n\r]*|"
    r"/\*.*?\*/",
    re.DOTALL,
)
_FN_HEADER_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_CALLABLE_HEADER_RE = re.compile(r"\b(?:external|public|internal)\b")
_VIEW_HEADER_RE = re.compile(r"\b(?:view|pure)\b")
_IDENT_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")

_BRIDGE_CONTEXT_RE = re.compile(
    r"\b(?:bridge|crossChain|crosschain|cross[-_ ]?chain|snowbridge|"
    r"gateway|portal|messenger|mailbox|endpoint|adapter|adaptor|relay|"
    r"relayer|route|lane|channel|proof|root|commitment|receipt|nonce|"
    r"domain|chain|lightClient|light[-_ ]?client|BEEFY|MMR|validatorSet|"
    r"authoritySet|message|packet|payload|dispatch|processed|consumed)\b",
    re.IGNORECASE,
)
_ENTRY_NAME_RE = re.compile(
    r"(?i)(submit|verify|process|consume|finalize|prove|relay|receive|"
    r"execute|dispatch|accept|apply).*(proof|message|commitment|digest|"
    r"root|header|packet|bridge|beefy|mmr|adapter|adaptor)?"
)
_PROOF_MATERIAL_RE = re.compile(
    r"\b(?:proof|proofRoot|messageRoot|stateRoot|receiptRoot|root|rootHash|"
    r"rootDigest|mmrRoot|MMRRoot|newMMRRoot|commitment|commitmentHash|"
    r"commitmentDigest|leaf|leafHash|payloadHash|payload|messageHash|"
    r"message|messageBody|packet|packetHash|nonce|sequence|seq|header|"
    r"bitFieldHash|validatorSetRoot|authoritySetRoot|signature|sig|"
    r"ballot|transcript)\b",
    re.IGNORECASE,
)
_AUTH_CALL_RE = re.compile(
    r"(?is)(?:"
    r"\b(?:[A-Za-z_][A-Za-z0-9_]*\s*\.\s*)?"
    r"(?:verify|verifyProof|verifyMessage|verifyDigest|verifyRoot|"
    r"verifyCommitment|verifyMMRRoot|verifyFinalityProof|prove|"
    r"isValidProof|checkProof|recover|isValidSignatureNow|processProof)"
    r"\s*\((?P<args>[^;{}]{0,2400})\)|"
    r"\becrecover\s*\((?P<ecrecover_args>[^;{}]{0,2400})\)"
    r")"
)
_SINK_RE = re.compile(
    r"(?is)(?:"
    r"\b(?:processed|consumed|used|seen|executed|delivered|claimed|"
    r"finalized|accepted)[A-Za-z0-9_]*\s*(?:\[[^\]\n;{}]+\]\s*)+"
    r"=\s*(?:true|1)|"
    r"\b(?:acceptedRoots|acceptedCommitments|verifiedRoots|trustedRoots|"
    r"latestMMRRoot|latestBeefyRoot|messageStatus)\s*"
    r"(?:\[[^\]\n;{}]+\]\s*)*=\s*|"
    r"\b(?:dispatch|deliver|execute|handle|route|apply|receiveMessage|"
    r"onMessage|onBridgeMessage|processMessage|settle|release|claim|"
    r"mint|unlock|finalize)\s*\(|"
    r"\bI[A-Za-z0-9_]*(?:Gateway|Bridge|Adapter|Adaptor|Endpoint|Receiver|"
    r"Application|App|Mailbox|Messenger)\s*\([^;{}]*\)\s*\."
    r"(?:dispatch|deliver|execute|handle|route|apply|receiveMessage|"
    r"onBridgeMessage|processMessage)\s*\(|"
    r"\.\s*(?:call|delegatecall|functionCall|safeTransfer|transfer)"
    r"\s*(?:\{|\()"
    r")"
)
_HASH_ASSIGN_RE = re.compile(
    r"\b(?:bytes32\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*"
    r"(?:Digest|Hash|Root|Leaf|Challenge|Transcript|Id|ID|Key)?)\s*=\s*"
    r"(?P<expr>(?:keccak256|sha256)\s*\(\s*(?:abi\.encode(?:Packed)?|"
    r"bytes\.concat)\s*\([^;{}]{0,3600}\)\s*\))",
    re.IGNORECASE | re.DOTALL,
)
_HASH_EXPR_RE = re.compile(
    r"(?P<expr>(?:keccak256|sha256)\s*\(\s*(?:abi\.encode(?:Packed)?|"
    r"bytes\.concat)\s*\([^;{}]{0,3600}\)\s*\))",
    re.IGNORECASE | re.DOTALL,
)
_SAFE_HELPER_RE = re.compile(
    r"\b(?:BRIDGE_EXTERNAL_REPLAY_DOMAIN_FIRE34|BRIDGE_EXTERNAL_REPLAY_DOMAIN|"
    r"EXTERNAL_REPLAY_DOMAIN|SNOWBRIDGE_EXTERNAL_DOMAIN|"
    r"BEEFY_EXTERNAL_REPLAY_DOMAIN|DOMAIN_SEPARATOR|domainSeparator|"
    r"_domainSeparatorV4|domainBoundExternalReplayDigest|"
    r"domainBoundBridgeDigest|domainBoundProofDigest|"
    r"hashExternalBridgeDomain|hashDomainBoundBridgeMessage|"
    r"bindExternalReplayDomain|bindBridgeDomain|verifyDomainBound[A-Za-z0-9_]*)\b",
    re.IGNORECASE,
)
_TRUSTED_CALLER_RE = re.compile(
    r"(?is)\b(?:onlyEndpoint|onlyMailbox|onlyBridge|onlyGateway|"
    r"onlyMessenger|onlyRelayer|onlyRouter|onlyOperator|onlyOwner|"
    r"onlyAdmin|trustedRelayer|authorizedRelayer)\b|"
    r"require\s*\(\s*msg\.sender\s*==\s*\w*(?:Endpoint|Mailbox|Bridge|"
    r"Gateway|Messenger|Relayer|Router|Operator|Admin)\b"
)
_CANONICAL_BASE_RE = re.compile(
    r"\b(?:NonblockingLzApp|CCIPReceiver|AxelarExecutable|"
    r"AbstractMessageIdAuth|CrossDomainOwnable|IMessageRecipient)\b",
    re.IGNORECASE,
)

_DOMAIN_GROUP_PATTERNS = (
    (
        "source_chain",
        re.compile(
            r"\b(?:source|src|origin|remote|from|relay)\w*"
            r"(?:ChainId|ChainID|ChainSelector|Selector|Chain|Domain|"
            r"DomainId|DomainID|NetworkId|Eid|EID)\b|"
            r"\b(?:srcEid|sourceChainSelector)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "destination_chain",
        re.compile(
            r"\b(?:destination|dest|dst|target|local|to)\w*"
            r"(?:ChainId|ChainID|ChainSelector|Selector|Chain|Domain|"
            r"DomainId|DomainID|NetworkId|Eid|EID)\b|"
            r"\b(?:dstEid|localEid|block\s*\.\s*chainid)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "gateway",
        re.compile(
            r"\b(?:source|src|origin|remote|destination|dest|dst|target|"
            r"local|trusted)?\w*(?:Gateway|BridgeGateway|GatewayAddress)"
            r"\w*\b",
            re.IGNORECASE,
        ),
    ),
    (
        "adapter",
        re.compile(
            r"\b(?:source|src|origin|remote|destination|dest|dst|target|"
            r"local)?\w*(?:Adapter|Adaptor|AdapterAddress|AdaptorAddress)"
            r"\w*\b|\baddress\s*\(\s*this\s*\)",
            re.IGNORECASE,
        ),
    ),
    (
        "light_client",
        re.compile(
            r"\b(?:lightClient|lightclient|clientId|clientID|beefyClient|"
            r"beefyClientId|beefyClientID|BEEFY_CLIENT_ID|validatorClient|"
            r"finalityClient|clientName|clientHash)\w*\b",
            re.IGNORECASE,
        ),
    ),
    (
        "message_channel",
        re.compile(
            r"\b(?:messageChannel|channel|channelId|channelID|appChannel|"
            r"applicationChannel|route|routeId|routeID|port|portId|"
            r"paraId|paraID|parachain|topic|topicId)\w*\b",
            re.IGNORECASE,
        ),
    ),
    (
        "nonce_lane",
        re.compile(
            r"\b(?:nonceLane|nonceLaneId|laneNonce|laneNonceId|lane|laneId|"
            r"laneID|sourceLane|destinationLane|inboundLane|outboundLane|"
            r"inboundNonce|outboundNonce|sequenceLane|sequenceChannel)\w*\b",
            re.IGNORECASE,
        ),
    ),
)
_GROUP_LABELS = {
    "source_chain": "source chain",
    "destination_chain": "destination chain",
    "gateway": "gateway",
    "adapter": "adapter",
    "light_client": "light-client id",
    "message_channel": "message channel",
    "nonce_lane": "nonce lane",
}
_EXTERNAL_REQUIRED_ANY = {
    "gateway",
    "adapter",
    "light_client",
    "message_channel",
    "nonce_lane",
}


def _strip_comments_and_strings(source: str) -> str:
    def replace_token(match: re.Match[str]) -> str:
        text = match.group(0)
        return "\n" * text.count("\n") if "\n" in text else " "

    return _TOKEN_RE.sub(replace_token, source or "")


def _extract_balanced_block(source: str, open_brace: int) -> tuple[Optional[str], int]:
    if open_brace < 0 or open_brace >= len(source) or source[open_brace] != "{":
        return None, open_brace
    depth = 1
    i = open_brace + 1
    while i < len(source) and depth > 0:
        char = source[i]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
        i += 1
    if depth != 0:
        return None, open_brace
    return source[open_brace + 1:i - 1], i


def _split_functions(source: str) -> list[FunctionSlice]:
    out: list[FunctionSlice] = []
    pos = 0
    while True:
        match = _FN_HEADER_RE.search(source, pos)
        if match is None:
            break
        name = match.group("name")
        i = match.end()
        depth_paren = 1
        while i < len(source) and depth_paren > 0:
            char = source[i]
            if char == "(":
                depth_paren += 1
            elif char == ")":
                depth_paren -= 1
            i += 1

        body_start = -1
        j = i
        while j < len(source):
            if source[j] == ";":
                break
            if source[j] == "{":
                body_start = j
                break
            j += 1
        if body_start < 0:
            pos = max(i, j)
            continue

        body, end_pos = _extract_balanced_block(source, body_start)
        if body is None:
            pos = body_start + 1
            continue

        header = source[match.start():body_start]
        line = source.count("\n", 0, match.start()) + 1
        body_line = source.count("\n", 0, body_start + 1) + 1
        out.append(FunctionSlice(name=name, header=header, body=body, line=line, body_line=body_line))
        pos = end_pos
    return out


def _context(fn: FunctionSlice) -> str:
    return f"{fn.name}\n{fn.header}\n{fn.body}"


def _line_for(fn: FunctionSlice, match: re.Match[str] | None) -> int:
    if match is None:
        return fn.line
    return fn.body_line + fn.body.count("\n", 0, match.start())


def _domain_groups(text: str) -> set[str]:
    return {name for name, pattern in _DOMAIN_GROUP_PATTERNS if pattern.search(text)}


def _hash_assignments_before(body: str, pos: int) -> dict[str, str]:
    assignments: dict[str, str] = {}
    for match in _HASH_ASSIGN_RE.finditer(body[:pos]):
        assignments[match.group("name")] = match.group("expr")
    return assignments


def _is_callable(fn: FunctionSlice) -> bool:
    return bool(_CALLABLE_HEADER_RE.search(fn.header)) and not _VIEW_HEADER_RE.search(fn.header)


def _visible_external_domain_groups(fn: FunctionSlice) -> set[str]:
    visible = _domain_groups(_context(fn))
    if len(visible) < 3:
        return set()
    if not (visible & _EXTERNAL_REQUIRED_ANY):
        return set()
    return visible


def _has_external_replay_auth_shape(fn: FunctionSlice) -> bool:
    text = _context(fn)
    if not _is_callable(fn):
        return False
    if _CANONICAL_BASE_RE.search(text) or _TRUSTED_CALLER_RE.search(text):
        return False
    if not (_ENTRY_NAME_RE.search(fn.name) or _BRIDGE_CONTEXT_RE.search(text)):
        return False
    if not _BRIDGE_CONTEXT_RE.search(text):
        return False
    if not _visible_external_domain_groups(fn):
        return False
    if _PROOF_MATERIAL_RE.search(text) is None:
        return False
    if _AUTH_CALL_RE.search(fn.body) is None:
        return False
    return _HASH_EXPR_RE.search(fn.body) is not None


def _authenticated_digest_exprs(fn: FunctionSlice, auth: re.Match[str]) -> list[str]:
    args = auth.group("args") or auth.group("ecrecover_args") or ""
    out: list[str] = []
    out.extend(match.group("expr") for match in _HASH_EXPR_RE.finditer(args))

    assignments = _hash_assignments_before(fn.body, auth.start())
    for ident_match in _IDENT_RE.finditer(args):
        expr = assignments.get(ident_match.group(0))
        if expr:
            out.append(expr)
    return out


def _sink_after_auth(fn: FunctionSlice, auth: re.Match[str]) -> bool:
    return _SINK_RE.search(fn.body[auth.end():]) is not None


def _unsafe_authentication(fn: FunctionSlice) -> tuple[list[str], re.Match[str] | None]:
    visible = _visible_external_domain_groups(fn)
    if not visible:
        return [], None

    for auth in _AUTH_CALL_RE.finditer(fn.body):
        if not _sink_after_auth(fn, auth):
            continue
        for expr in _authenticated_digest_exprs(fn, auth):
            if _SAFE_HELPER_RE.search(expr):
                continue
            if _PROOF_MATERIAL_RE.search(expr) is None:
                continue
            bound = _domain_groups(expr)
            missing = sorted(visible - bound)
            if missing:
                return missing, auth
    return [], None


def _finding(file_path: str, fn: FunctionSlice, match: re.Match[str], missing: list[str]) -> Finding:
    labels = ", ".join(_GROUP_LABELS[item] for item in missing)
    return Finding(
        detector=DETECTOR_NAME,
        file=file_path,
        line=_line_for(fn, match),
        severity=DETECTOR_SEVERITY_DEFAULT,
        function=fn.name,
        message=(
            f"Bridge authenticated digest omits external replay domain fields: {labels}. "
            "The function verifies a proof or message digest and then consumes or "
            "dispatches under visible source, destination, gateway, adapter, "
            "light-client, channel, or nonce-lane fields that are not all bound "
            "into the authenticated digest preimage. NOT_SUBMIT_READY: detector "
            "fixture smoke evidence only."
        ),
    )


def scan(source: str, file_path: str = "<memory>") -> list[Finding]:
    code = _strip_comments_and_strings(source)
    findings: list[Finding] = []
    for fn in _split_functions(code):
        if not _has_external_replay_auth_shape(fn):
            continue
        missing, match = _unsafe_authentication(fn)
        if not missing or match is None:
            continue
        findings.append(_finding(file_path, fn, match, missing))
    return findings


__all__ = [
    "scan",
    "Finding",
    "DETECTOR_NAME",
    "DETECTOR_SEVERITY_DEFAULT",
]
