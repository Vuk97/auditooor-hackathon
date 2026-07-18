"""
bridge-message-channel-domain-fire31

Solidity recall-lift detector for bridge proof or message consumers that
verify a message root or commitment, mark a replay key consumed, and then
apply the message under a channel, lane, destination chain, or application
domain that is not bound into the consumed key or mapping namespace.

Provenance:
- context_pack_id: auditooor.vault_context_pack.v1:resume:c01d420fe4a1c24a
- context_pack_hash: c01d420fe4a1c24a974c8890b2d40ca3881d87e848d83dc294a1ee396a5753c8
- source refs:
  - reports/detector_lift_fire30_20260605/post_priorities_all.md
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


DETECTOR_NAME = "bridge-message-channel-domain-fire31"
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
    r"messenger|message|receiver|router|mailbox|endpoint|relayer|relay|"
    r"lane|channel|proof|root|commitment|receipt|nonce|domain|chain|"
    r"application|packet|payload)\b",
    re.IGNORECASE,
)
_ENTRY_NAME_RE = re.compile(
    r"(?i)(receive|process|execute|deliver|route|claim|finalize|settle|"
    r"consume|relay|apply|verify).*(Message|Bridge|Packet|Proof|Receipt|"
    r"Commitment|Root|Transfer)?|^(receiveMessage|executeMessage|"
    r"processMessage|applyMessage|deliverMessage)$"
)
_ROOT_OR_COMMITMENT_RE = re.compile(
    r"\b(?:messageRoot|stateRoot|receiptRoot|root|commitment|"
    r"messageCommitment|proofCommitment|leaf|leafHash|payloadHash|"
    r"payload|nonce|message)\b",
    re.IGNORECASE,
)
_VERIFY_RE = re.compile(
    r"(?is)(?:"
    r"\b(?:verify|verifyProof|verifyMessage|verifyRoot|verifyCommitment|"
    r"isValidProof|checkProof|prove)\s*\(|"
    r"\b(?:MerkleProof|SignatureChecker|ECDSA)\s*\.\s*"
    r"(?:verify|processProof|recover|isValidSignatureNow)\s*\(|"
    r"\becrecover\s*\("
    r")"
)
_DELIVERY_RE = re.compile(
    r"(?is)(?:"
    r"\.\s*(?:call|delegatecall|functionCall|safeTransfer|transfer)\s*(?:\{|\()|"
    r"\b(?:dispatch|deliver|execute|handle|route|apply|receiveMessage|"
    r"onMessage|onBridgeMessage|processMessage|settle|release|claim|mint)"
    r"\s*\(|"
    r"\bI[A-Za-z0-9_]*(?:Receiver|Application|App|Endpoint|Gateway|Bridge)"
    r"\s*\([^;{}]*\)\s*\.\s*(?:onBridgeMessage|receiveMessage|execute|"
    r"dispatch|handle|deliver|apply)\s*\("
    r")"
)
_CONSUME_WRITE_RE = re.compile(
    r"(?is)(?P<lvalue>\b(?:consumed|processed|used|spent|seen|executed|"
    r"delivered|claimed|finalized)[A-Za-z0-9_]*\s*(?:\[[^\]\n;{}]+\]\s*)+)"
    r"\s*=\s*(?:true|1)"
)
_BRACKET_RE = re.compile(r"\[([^\]\n;{}]+)\]")
_HASH_ASSIGN_RE = re.compile(
    r"\b(?:bytes32\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"(?P<expr>(?:keccak256|sha256)\s*\(\s*(?:abi\.encode(?:Packed)?|"
    r"bytes\.concat)\s*\([^;{}]{0,2400}\)\s*\))",
    re.IGNORECASE | re.DOTALL,
)
_HASH_EXPR_RE = re.compile(
    r"(?P<expr>(?:keccak256|sha256)\s*\(\s*(?:abi\.encode(?:Packed)?|"
    r"bytes\.concat)\s*\([^;{}]{0,2400}\)\s*\))",
    re.IGNORECASE | re.DOTALL,
)
_SAFE_HELPER_RE = re.compile(
    r"\b(?:BRIDGE_MESSAGE_CHANNEL_DOMAIN|BRIDGE_CHANNEL_DOMAIN|"
    r"CHANNEL_REPLAY_DOMAIN|LANE_REPLAY_DOMAIN|DOMAIN_SEPARATOR|"
    r"domainSeparator|_domainSeparatorV4|domainBoundReplayKey|"
    r"domainBoundMessageKey|bindChannelDomain|bindLaneDomain|"
    r"hashChannelBoundMessage|hashDomainBoundReplayKey)\b",
    re.IGNORECASE,
)
_SPECIALIZED_BRIDGE_PROOF_RE = re.compile(
    r"\b(?:BEEFY|MMR|MMRRoot|Fiat.?Shamir|validatorSet|authoritySet)\b",
    re.IGNORECASE,
)

_DOMAIN_GROUP_PATTERNS = (
    (
        "channel_id",
        re.compile(
            r"\b(?:channelId|channelID|messageChannel|appChannel|"
            r"applicationChannel|routeId|routeID|routeKey|channel)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "lane_id",
        re.compile(
            r"\b(?:laneId|laneID|lane|sourceLane|destinationLane|"
            r"inboundLane|outboundLane|laneKey)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "destination_chain",
        re.compile(
            r"\b(?:destination|dest|dst|target|local|to)\w*"
            r"(?:ChainId|ChainID|Chain|Domain|DomainId|NetworkId|Eid|EID)"
            r"\b|\b(?:dstEid|localEid|block\s*\.\s*chainid)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "application_address",
        re.compile(
            r"\b(?:application|applicationAddress|appAddress|appContract|"
            r"targetApplication|destinationApplication|receiverApplication|"
            r"applicationContract|app)\b",
            re.IGNORECASE,
        ),
    ),
)
_GROUP_LABELS = {
    "channel_id": "channel id",
    "lane_id": "lane id",
    "destination_chain": "destination chain id",
    "application_address": "application address",
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
    lvalue = consume.group("lvalue")
    key = _last_mapping_key(lvalue)
    if not key:
        return ""
    direct_hash = _HASH_EXPR_RE.search(key)
    if direct_hash is not None:
        return direct_hash.group("expr")
    return _hash_assignments_before(fn.body, consume.start()).get(key, key)


def _is_callable(fn: FunctionSlice) -> bool:
    return bool(_CALLABLE_HEADER_RE.search(fn.header)) and not _VIEW_HEADER_RE.search(fn.header)


def _has_bridge_proof_consume_shape(fn: FunctionSlice) -> bool:
    text = _context(fn)
    if not _is_callable(fn):
        return False
    if _SPECIALIZED_BRIDGE_PROOF_RE.search(text):
        return False
    if not (_ENTRY_NAME_RE.search(fn.name) or _BRIDGE_CONTEXT_RE.search(text)):
        return False
    if not _BRIDGE_CONTEXT_RE.search(text):
        return False
    if not _ROOT_OR_COMMITMENT_RE.search(text):
        return False
    if not _VERIFY_RE.search(text):
        return False
    if not _DELIVERY_RE.search(text):
        return False
    return _CONSUME_WRITE_RE.search(fn.body) is not None


def _unsafe_consume(fn: FunctionSlice) -> tuple[list[str], re.Match[str] | None]:
    visible = _domain_groups(_context(fn))
    if not visible:
        return [], None
    if _SAFE_HELPER_RE.search(fn.body):
        return [], None

    for consume in _CONSUME_WRITE_RE.finditer(fn.body):
        lvalue = consume.group("lvalue")
        key_expr = _key_expr_for_consume(fn, consume)
        if not key_expr:
            continue
        if not _ROOT_OR_COMMITMENT_RE.search(key_expr):
            continue
        bound = _domain_groups(f"{lvalue} {key_expr}")
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
            f"Bridge message replay key omits {labels}. The function verifies "
            "a root or commitment and consumes a replay key, but the consumed "
            "key or mapping namespace does not bind every visible channel, "
            "lane, destination chain, or application domain used for delivery. "
            "NOT_SUBMIT_READY: detector fixture smoke evidence only."
        ),
    )


def scan(source: str, file_path: str = "<memory>") -> list[Finding]:
    code = _strip_comments_and_strings(source)
    findings: list[Finding] = []
    for fn in _split_functions(code):
        if not _has_bridge_proof_consume_shape(fn):
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
