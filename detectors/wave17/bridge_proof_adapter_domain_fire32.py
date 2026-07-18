"""
bridge-proof-adapter-domain-fire32

Solidity recall-lift detector for bridge verifier paths that bind a proof
root and nonce into a proof digest or consumed message id, then apply the
message under adapter, endpoint, chain, lane, or application-domain fields
that are absent from the consumed key namespace.

Provenance:
- context_pack_id: auditooor.vault_context_pack.v1:resume:0f026ac1001e9e9b
- context_pack_hash: 0f026ac1001e9e9b588d5fafc49e8d99e6f347f91a2aaa782107be04d27011d8
- source refs:
  - reports/detector_lift_fire31_20260605/post_priorities_all.md
  - reference/patterns.dsl/bridge-proof-domain-bypass-umbrella.yaml
  - reference/patterns.dsl/bridge-replay-key-omits-chain-domain.yaml
  - reference/patterns.dsl/bridge-receiver-domain-omitted-from-proof-digest.yaml
- attack_class: bridge-proof-domain-bypass
- verification_tier: tier-3-synthetic-taxonomy-anchored

Hits are candidate evidence only. NOT_SUBMIT_READY.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "bridge-proof-adapter-domain-fire32"
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

_BRIDGE_CONTEXT_RE = re.compile(
    r"\b(?:bridge|crossChain|crosschain|cross[-_ ]?chain|gateway|portal|"
    r"messenger|mailbox|endpoint|adapter|adaptor|relayer|relay|router|"
    r"lane|channel|proof|root|commitment|receipt|nonce|domain|chain|"
    r"application|packet|payload|messageId|consumed|processed)\b",
    re.IGNORECASE,
)
_ENTRY_NAME_RE = re.compile(
    r"(?i)(consume|receive|process|execute|deliver|route|claim|finalize|"
    r"settle|relay|apply|verify).*(Adapter|Endpoint|Message|Bridge|Packet|"
    r"Proof|Receipt|Commitment|Root|Transfer)?|^(consumeAdapterProof|"
    r"receiveMessage|executeMessage|processProof|applyMessage)$"
)
_PROOF_MATERIAL_RE = re.compile(
    r"\b(?:proofRoot|messageRoot|stateRoot|receiptRoot|exportRoot|root|"
    r"rootHash|rootDigest|commitment|commitmentHash|leaf|leafHash|"
    r"payloadHash|payload|messageHash|message|receipt)\b",
    re.IGNORECASE,
)
_NONCE_RE = re.compile(r"\b(?:nonce|messageNonce|proofNonce|sequence|seq)\b", re.IGNORECASE)
_VERIFY_RE = re.compile(
    r"(?is)(?:"
    r"\b(?:verify|verifyProof|verifyMessage|verifyRoot|verifyCommitment|"
    r"isValidProof|checkProof|prove)\s*\(|"
    r"\b(?:MerkleProof|SignatureChecker|ECDSA)\s*\.\s*"
    r"(?:verify|processProof|recover|isValidSignatureNow)\s*\(|"
    r"\bverifier\s*\.\s*verify\s*\(|"
    r"\becrecover\s*\("
    r")"
)
_DELIVERY_RE = re.compile(
    r"(?is)(?:"
    r"\.\s*(?:call|delegatecall|functionCall|safeTransfer|transfer)\s*(?:\{|\()|"
    r"\b(?:dispatch|deliver|execute|handle|route|apply|receiveMessage|"
    r"onMessage|onBridgeMessage|processMessage|settle|release|claim|mint)"
    r"\s*\(|"
    r"\bI[A-Za-z0-9_]*(?:Adapter|Adaptor|Endpoint|Receiver|Application|"
    r"App|Gateway|Bridge|Messenger|Mailbox)\s*\([^;{}]*\)\s*\."
    r"(?:dispatch|deliver|execute|handle|route|apply|receiveMessage|"
    r"onBridgeMessage|processMessage)\s*\("
    r")"
)
_CONSUME_WRITE_RE = re.compile(
    r"(?is)(?P<lvalue>\b(?:consumed|processed|used|spent|seen|executed|"
    r"delivered|claimed|finalized|received)[A-Za-z0-9_]*\s*"
    r"(?:\[[^\]\n;{}]+\]\s*)+)\s*=\s*(?:true|1)"
)
_BRACKET_RE = re.compile(r"\[([^\]\n;{}]+)\]")
_HASH_ASSIGN_RE = re.compile(
    r"\b(?:bytes32\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"(?P<expr>(?:keccak256|sha256)\s*\(\s*(?:abi\.encode(?:Packed)?|"
    r"bytes\.concat)\s*\([^;{}]{0,2600}\)\s*\))",
    re.IGNORECASE | re.DOTALL,
)
_HASH_EXPR_RE = re.compile(
    r"(?P<expr>(?:keccak256|sha256)\s*\(\s*(?:abi\.encode(?:Packed)?|"
    r"bytes\.concat)\s*\([^;{}]{0,2600}\)\s*\))",
    re.IGNORECASE | re.DOTALL,
)
_SAFE_HELPER_RE = re.compile(
    r"\b(?:BRIDGE_ADAPTER_DOMAIN_FIRE32|BRIDGE_ADAPTER_DOMAIN|"
    r"ADAPTER_REPLAY_DOMAIN|ENDPOINT_REPLAY_DOMAIN|LANE_REPLAY_DOMAIN|"
    r"APPLICATION_REPLAY_DOMAIN|DOMAIN_SEPARATOR|domainSeparator|"
    r"_domainSeparatorV4|domainBoundAdapterDigest|"
    r"domainBoundConsumedMessageId|bindAdapterDomain|bindEndpointDomain|"
    r"hashDomainBoundAdapterMessage|hashAdapterDomainReplayKey|"
    r"verifyDomainBoundAdapter[A-Za-z0-9_]*)\b",
    re.IGNORECASE,
)
_TRUSTED_CALLER_RE = re.compile(
    r"(?is)\b(?:onlyRelayer|onlyEndpoint|onlyMailbox|onlyBridge|"
    r"onlyMessenger|onlyOperator|onlyBridgeOperator|onlyOwner|onlyAdmin)\b|"
    r"require\s*\(\s*msg\.sender\s*==\s*\w*(?:Endpoint|Mailbox|Bridge|"
    r"Messenger|Relayer|Operator|Admin)\b"
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
            r"\b(?:source|src|origin|remote|from)\w*"
            r"(?:ChainId|ChainID|Chain|Domain|DomainId|DomainID|NetworkId|"
            r"Eid|EID)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "destination_chain",
        re.compile(
            r"\b(?:destination|dest|dst|target|local|to)\w*"
            r"(?:ChainId|ChainID|Chain|Domain|DomainId|DomainID|NetworkId|"
            r"Eid|EID)\b|\b(?:block\s*\.\s*chainid|localEid|dstEid)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "adapter_address",
        re.compile(
            r"\b(?:local|destination|dest|dst|target|remote|source|src)?"
            r"\w*(?:Adapter|Adaptor|AdapterAddress|AdaptorAddress)\w*\b|"
            r"\baddress\s*\(\s*this\s*\)",
            re.IGNORECASE,
        ),
    ),
    (
        "source_endpoint",
        re.compile(
            r"\b(?:source|src|origin|remote|from|trusted)\w*"
            r"(?:BridgeEndpoint|Endpoint|Bridge|Gateway|Messenger|Mailbox)"
            r"\w*\b",
            re.IGNORECASE,
        ),
    ),
    (
        "destination_endpoint",
        re.compile(
            r"\b(?:destination|dest|dst|target|to|local)\w*"
            r"(?:BridgeEndpoint|Endpoint|Bridge|Gateway|Messenger|Mailbox)"
            r"\w*\b",
            re.IGNORECASE,
        ),
    ),
    (
        "lane_or_channel",
        re.compile(
            r"\b(?:channel|channelId|channelID|lane|laneId|laneID|route|"
            r"routeId|routeID|port|portId|paraId|parachain)\w*\b",
            re.IGNORECASE,
        ),
    ),
    (
        "application_domain",
        re.compile(
            r"\b(?:application|app|receiver|export)\w*"
            r"(?:Domain|DomainId|DomainID|Namespace|AppId|AppID|Id)\b",
            re.IGNORECASE,
        ),
    ),
)
_GROUP_LABELS = {
    "source_chain": "source chain domain",
    "destination_chain": "destination chain domain",
    "adapter_address": "adapter address",
    "source_endpoint": "source endpoint",
    "destination_endpoint": "destination endpoint",
    "lane_or_channel": "lane or channel id",
    "application_domain": "application domain",
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


def _last_mapping_key(lvalue: str) -> str:
    parts = _BRACKET_RE.findall(lvalue)
    if not parts:
        return ""
    return parts[-1].strip()


def _key_expr_for_consume(fn: FunctionSlice, consume: re.Match[str]) -> str:
    key = _last_mapping_key(consume.group("lvalue"))
    if not key:
        return ""
    direct_hash = _HASH_EXPR_RE.search(key)
    if direct_hash is not None:
        return direct_hash.group("expr")
    return _hash_assignments_before(fn.body, consume.start()).get(key, key)


def _is_callable(fn: FunctionSlice) -> bool:
    return bool(_CALLABLE_HEADER_RE.search(fn.header)) and not _VIEW_HEADER_RE.search(fn.header)


def _contains_root_and_nonce(text: str) -> bool:
    return bool(_PROOF_MATERIAL_RE.search(text) and _NONCE_RE.search(text))


def _has_bridge_adapter_consume_shape(fn: FunctionSlice) -> bool:
    text = _context(fn)
    if not _is_callable(fn):
        return False
    if _CANONICAL_BASE_RE.search(text) or _TRUSTED_CALLER_RE.search(text):
        return False
    if not (_ENTRY_NAME_RE.search(fn.name) or _BRIDGE_CONTEXT_RE.search(text)):
        return False
    if not _BRIDGE_CONTEXT_RE.search(text):
        return False
    if not _contains_root_and_nonce(text):
        return False
    if len(_domain_groups(text)) < 2:
        return False
    if _VERIFY_RE.search(text) is None:
        return False
    if _DELIVERY_RE.search(text) is None:
        return False
    return _CONSUME_WRITE_RE.search(fn.body) is not None


def _unsafe_consume(fn: FunctionSlice) -> tuple[list[str], re.Match[str] | None]:
    visible = _domain_groups(_context(fn))
    if not visible or _SAFE_HELPER_RE.search(fn.body):
        return [], None

    for consume in _CONSUME_WRITE_RE.finditer(fn.body):
        key_expr = _key_expr_for_consume(fn, consume)
        if not key_expr or not _contains_root_and_nonce(key_expr):
            continue
        bound = _domain_groups(f"{consume.group('lvalue')} {key_expr}")
        missing = sorted(visible - bound)
        if missing:
            return missing, consume
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
            f"Bridge adapter replay key omits {labels}. The verifier binds "
            "a proof root and nonce into the consumed message id, but that id "
            "or mapping namespace does not bind every visible adapter, "
            "endpoint, chain, lane, or application-domain field used after "
            "verification. NOT_SUBMIT_READY: detector fixture smoke evidence only."
        ),
    )


def scan(source: str, file_path: str = "<memory>") -> list[Finding]:
    code = _strip_comments_and_strings(source)
    findings: list[Finding] = []
    for fn in _split_functions(code):
        if not _has_bridge_adapter_consume_shape(fn):
            continue
        missing, match = _unsafe_consume(fn)
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
