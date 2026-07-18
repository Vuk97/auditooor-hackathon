"""
bridge-message-domain-binding-fire28

Solidity recall-lift detector for bridge receiver functions that verify or
consume message payloads without binding the full bridge message domain into
the digest: source chain, destination chain, remote sender, and receiver.

The detector also flags endpoint receive paths where source-chain and remote
sender fields are visible but the function lacks trusted endpoint, source
chain, or trusted remote sender checks before delivery.

Provenance:
- context_pack_id: auditooor.vault_context_pack.v1:resume:86c2076101171056
- context_pack_hash: 86c2076101171056d88e0073a7354a1cf2324d92f13627249a1c5ece0c70b722
- source refs:
  - reference/big_loss_templates/bridge_proof_domain.json
  - reference/patterns.dsl/bridge-proof-domain-bypass-umbrella.yaml
  - reference/patterns.dsl/bridge-receiver-domain-omitted-from-proof-digest.yaml
  - reference/patterns.dsl.r75_mined/firms_chainsec_halborn_hexens_pashov/halborn-crosschain-bridge-message-not-chainscoped.yaml
- attack_class: bridge-proof-domain-bypass

Hits are candidate evidence only. NOT_SUBMIT_READY.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "bridge-message-domain-binding-fire28"
DETECTOR_SEVERITY_DEFAULT = "High"
SUBMISSION_POSTURE = "NOT_SUBMIT_READY"
COVERAGE_CLAIM = "detector_fixture_smoke_only"
PROMOTION_ALLOWED = False


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
    r"\b(?:bridge|gateway|portal|crosschain|crossChain|cross[-_ ]?chain|"
    r"message|messenger|endpoint|mailbox|receiver|relayer|relay|packet|"
    r"payload|proof|root|commitment|receipt|nonce|domain|chain|selector|"
    r"lzReceive|ccipReceive|receiveMessage|executeMessage|processMessage)\b",
    re.IGNORECASE,
)
_ENTRY_NAME_RE = re.compile(
    r"(?i)(receive|process|execute|settle|claim|finalize|relay|deliver|"
    r"handle|consume).*(Message|Bridge|Packet|Proof|Receipt|Payload|Transfer)?"
    r"|^(lzReceive|ccipReceive|_ccipReceive|receiveMessage|executeMessage|"
    r"processMessage|handleMessage)$"
)
_HASH_EXPR_RE = re.compile(
    r"(?P<expr>(?:keccak256|sha256)\s*\(\s*(?:abi\.encode(?:Packed)?|"
    r"bytes\.concat)\s*\([^;{}]{0,1800}\)\s*\))",
    re.IGNORECASE | re.DOTALL,
)
_MESSAGE_MATERIAL_RE = re.compile(
    r"\b(?:message|messageHash|messageDigest|payload|payloadHash|packet|"
    r"packetHash|proof|proofRoot|root|stateRoot|receipt|receiptRoot|leaf|"
    r"leafHash|commitment|nonce|sequence|command|data)\b",
    re.IGNORECASE,
)
_VERIFY_OR_CONSUME_RE = re.compile(
    r"(?is)(?:"
    r"\b(?:verify|verifyProof|verifyMessage|verifyPayload|verifyPacket|"
    r"verifyReceipt|verifyRoot|isValidProof|checkProof)\s*\(|"
    r"\b(?:MerkleProof|SignatureChecker|ECDSA)\s*\.\s*"
    r"(?:verify|processProof|recover|isValidSignatureNow)\s*\(|"
    r"\becrecover\s*\(|"
    r"\b(?:processed|consumed|used|seen|executed|delivered|claimed|"
    r"finalized)[A-Za-z0-9_]*\s*\[[^\]]+\]"
    r")"
)
_SINK_RE = re.compile(
    r"(?is)(?:"
    r"\b(?:processed|consumed|used|seen|executed|delivered|claimed|"
    r"finalized)[A-Za-z0-9_]*\s*\[[^\]]+\]\s*=\s*(?:true|1)|"
    r"\b(?:dispatch|deliver|execute|handle|receiveMessage|onMessage|"
    r"onBridgeMessage|processMessage|settle|release|claim|mint)\s*\(|"
    r"\.\s*(?:call|delegatecall|functionCall|safeTransfer|transfer)\s*(?:\{|\()|"
    r"\bI[A-Za-z0-9_]*(?:Receiver|Endpoint|Gateway|Messenger|Bridge)\s*"
    r"\([^;{}]*\)\s*\.\s*(?:onBridgeMessage|receiveMessage|execute|"
    r"dispatch|handle|deliver)\s*\("
    r")"
)
_SAFE_HELPER_RE = re.compile(
    r"(?is)\b(?:"
    r"domainBoundMessageDigest|domainBoundBridgeDigest|hashDomainBound|"
    r"_hashTypedDataV4|hashCrossChainMessage|verifyDomainBoundMessage|"
    r"bindMessageDomain|bindBridgeDomain|DOMAIN_SEPARATOR|domainSeparator|"
    r"_domainSeparatorV4"
    r")\b"
)

_DOMAIN_PATTERNS = (
    (
        "source_chain",
        re.compile(
            r"\b(?:source|src|origin|remote|from)\w*(?:ChainId|ChainID|"
            r"ChainSelector|Selector|Chain|Domain|DomainId|DomainID|NetworkId|"
            r"Eid|EID)\b|\b(?:srcEid|_srcEid|sourceChainSelector)\b|"
            r"\bmessage\s*\.\s*sourceChainSelector\b",
            re.IGNORECASE,
        ),
    ),
    (
        "destination_chain",
        re.compile(
            r"\b(?:destination|dest|dst|target|local|to)\w*(?:ChainId|"
            r"ChainID|ChainSelector|Selector|Chain|Domain|DomainId|DomainID|"
            r"NetworkId|Eid|EID)\b|\b(?:dstEid|localEid|block\s*\.\s*chainid)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "source_sender",
        re.compile(
            r"\b(?:source|src|origin|remote|from|trusted)\w*(?:Sender|"
            r"Address|Peer|Remote|Endpoint|BridgeEndpoint|Mailbox|Messenger)"
            r"\w*\b|\b(?:senderBytes|srcAddress|srcAddressHash|sourceSender|"
            r"remoteSender|originSender)\b|\bmessage\s*\.\s*sender\b",
            re.IGNORECASE,
        ),
    ),
    (
        "receiver",
        re.compile(
            r"\b(?:receiver|recipient|targetReceiver|targetRecipient|"
            r"destinationReceiver|localReceiver|receiverContract|targetContract|"
            r"destinationContract|beneficiary|to)\b|\baddress\s*\(\s*this\s*\)",
            re.IGNORECASE,
        ),
    ),
)
_REQUIRED_GROUPS = {"source_chain", "destination_chain", "source_sender", "receiver"}
_GROUP_LABELS = {
    "source_chain": "source chain",
    "destination_chain": "destination chain",
    "source_sender": "remote sender",
    "receiver": "receiver",
}

_ENDPOINT_GUARD_RE = re.compile(
    r"(?is)(?:"
    r"\bonly[A-Za-z0-9_]*(?:Endpoint|Router|Bridge|Messenger|Mailbox|Relayer)\b|"
    r"msg\s*\.\s*sender\s*(?:==|!=)[^;{}]*(?:endpoint|Endpoint|router|Router|"
    r"bridge|Bridge|messenger|Messenger|mailbox|Mailbox|relayer|Relayer)|"
    r"(?:endpoint|Endpoint|router|Router|bridge|Bridge|messenger|Messenger|"
    r"mailbox|Mailbox|relayer|Relayer)[^;{}]*(?:==|!=)\s*msg\s*\.\s*sender"
    r")"
)
_SOURCE_CHAIN_GUARD_RE = re.compile(
    r"(?is)(?:"
    r"(?:source|src|origin|remote|from)\w*(?:ChainId|ChainSelector|Domain|"
    r"DomainId|Eid|EID)\s*(?:==|!=)|"
    r"(?:trusted|allowed|approved|valid|supported)[A-Za-z0-9_]*"
    r"(?:Chains?|ChainSelectors?|Domains?|Eids?)\s*\[|"
    r"(?:trusted|allowed|approved|valid|known)[A-Za-z0-9_]*"
    r"(?:Remotes?|Peers?|Sources?|Origins?)\s*\[\s*"
    r"(?:source|src|origin|remote|from)\w*(?:ChainId|ChainSelector|Domain|"
    r"DomainId|Eid|EID)|"
    r"message\s*\.\s*sourceChainSelector\s*(?:==|!=)"
    r")"
)
_TRUSTED_SENDER_GUARD_RE = re.compile(
    r"(?is)(?:"
    r"(?:remoteSender|sourceSender|originSender|srcAddress|sourceAddress|"
    r"senderBytes|message\s*\.\s*sender)\s*(?:==|!=)\s*"
    r"(?:TRUSTED|trusted|allowed|expected|approved|canonical)[A-Za-z0-9_]*|"
    r"(?:TRUSTED|trusted|allowed|expected|approved|canonical)[A-Za-z0-9_]*"
    r"\s*(?:==|!=)\s*(?:remoteSender|sourceSender|originSender|srcAddress|"
    r"sourceAddress|senderBytes|message\s*\.\s*sender)|"
    r"(?:trusted|allowed|approved|valid|known)[A-Za-z0-9_]*"
    r"(?:Senders?|Remotes?|Peers?|Sources?|Origins?)\s*\[|"
    r"keccak256\s*\([^;{}]*(?:remoteSender|sourceSender|originSender|"
    r"srcAddress|sourceAddress|senderBytes|message\s*\.\s*sender)[^;{}]*\)"
    r"\s*(?:==|!=)"
    r")"
)
_DESTINATION_GUARD_RE = re.compile(
    r"(?is)(?:"
    r"(?:destination|dest|dst|target|local|to)\w*(?:ChainId|ChainSelector|"
    r"Domain|DomainId|Eid|EID)\s*(?:==|!=)\s*(?:block\s*\.\s*chainid|"
    r"uint(?:8|16|32|64|128|256)?\s*\(\s*block\s*\.\s*chainid\s*\)|"
    r"LOCAL|local|CURRENT|current|EXPECTED|expected|trusted|allowed|canonical)|"
    r"(?:block\s*\.\s*chainid|uint(?:8|16|32|64|128|256)?\s*\(\s*block\s*\.\s*chainid\s*\)|LOCAL|local|CURRENT|current|EXPECTED|expected|"
    r"trusted|allowed|canonical)[^;{}]*(?:==|!=)\s*(?:destination|dest|dst|"
    r"target|local|to)\w*(?:ChainId|ChainSelector|Domain|DomainId|Eid|EID)|"
    r"(?:trusted|allowed|approved|valid|supported|expected|canonical)"
    r"[A-Za-z0-9_]*(?:Target|Destination|Local)?(?:Chains?|Domains?|Eids?)\s*\["
    r")"
)
_RECEIVER_GUARD_RE = re.compile(
    r"(?is)(?:"
    r"(?:receiver|recipient|targetReceiver|targetRecipient|receiverContract|"
    r"targetContract|destinationReceiver|destinationContract)\s*(?:==|!=)\s*"
    r"(?:address\s*\(\s*this\s*\)|LOCAL|local|EXPECTED|expected|trusted|"
    r"allowed|canonical)|"
    r"(?:address\s*\(\s*this\s*\)|LOCAL|local|EXPECTED|expected|trusted|"
    r"allowed|canonical)[^;{}]*(?:==|!=)\s*(?:receiver|recipient|"
    r"targetReceiver|targetRecipient|receiverContract|targetContract|"
    r"destinationReceiver|destinationContract)|"
    r"(?:trusted|allowed|approved|valid|supported|expected|canonical)"
    r"[A-Za-z0-9_]*(?:Receivers?|Recipients?|Contracts?)\s*\["
    r")"
)


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
    return {name for name, pattern in _DOMAIN_PATTERNS if pattern.search(text)}


def _is_callable(fn: FunctionSlice) -> bool:
    return bool(_CALLABLE_HEADER_RE.search(fn.header)) and not _VIEW_HEADER_RE.search(fn.header)


def _has_bridge_message_signal(fn: FunctionSlice) -> bool:
    text = _context(fn)
    if not _is_callable(fn):
        return False
    if not (_ENTRY_NAME_RE.search(fn.name) or _BRIDGE_CONTEXT_RE.search(text)):
        return False
    if not _BRIDGE_CONTEXT_RE.search(text):
        return False
    if not (_HASH_EXPR_RE.search(text) or _VERIFY_OR_CONSUME_RE.search(text)):
        return False
    return bool(_SINK_RE.search(text))


def _best_domain_digest_groups(fn: FunctionSlice) -> tuple[set[str], re.Match[str] | None]:
    best: set[str] = set()
    best_match: re.Match[str] | None = None
    for match in _HASH_EXPR_RE.finditer(fn.body):
        expr = match.group("expr")
        if not _MESSAGE_MATERIAL_RE.search(expr):
            continue
        groups = _domain_groups(expr)
        if best_match is None or len(groups) > len(best):
            best = groups
            best_match = match
    return best, best_match


def _missing_digest_groups(fn: FunctionSlice) -> tuple[list[str], re.Match[str] | None]:
    text = _context(fn)
    visible = _domain_groups(text)
    if not _REQUIRED_GROUPS.issubset(visible):
        return [], None
    if _SAFE_HELPER_RE.search(fn.body):
        return [], None
    groups, match = _best_domain_digest_groups(fn)
    if match is None:
        return [], None
    missing = sorted(_REQUIRED_GROUPS - groups)
    return missing, match


def _missing_endpoint_checks(fn: FunctionSlice) -> list[str]:
    text = _context(fn)
    groups = _domain_groups(text)
    if not {"source_chain", "source_sender"}.issubset(groups):
        return []
    if not _ENTRY_NAME_RE.search(fn.name):
        return []
    if not (_VERIFY_OR_CONSUME_RE.search(text) or _SINK_RE.search(text)):
        return []

    missing: list[str] = []
    if not _ENDPOINT_GUARD_RE.search(text):
        missing.append("canonical endpoint")
    if not _SOURCE_CHAIN_GUARD_RE.search(text):
        missing.append("source chain check")
    if not _TRUSTED_SENDER_GUARD_RE.search(text):
        missing.append("trusted remote sender")
    if "destination_chain" in groups and not _DESTINATION_GUARD_RE.search(text):
        missing.append("destination chain check")
    if "receiver" in groups and not _RECEIVER_GUARD_RE.search(text):
        missing.append("receiver check")

    endpoint_core_missing = {
        "canonical endpoint",
        "source chain check",
        "trusted remote sender",
    }
    if endpoint_core_missing.isdisjoint(missing):
        return []
    return missing


def _finding(file_path: str, line: int, function: str, reasons: list[str]) -> Finding:
    reason_text = "; ".join(reasons)
    return Finding(
        detector=DETECTOR_NAME,
        file=file_path,
        line=line,
        severity=DETECTOR_SEVERITY_DEFAULT,
        function=function,
        message=(
            f"Bridge receiver message domain binding gap: {reason_text}. "
            "Source chain, destination chain, remote sender, and receiver "
            "must be bound into the verified or replay digest, or enforced "
            "by trusted endpoint plus trusted remote checks before delivery. "
            "NOT_SUBMIT_READY: detector fixture smoke evidence only."
        ),
    )


def scan(source: str, file_path: str = "<memory>") -> list[Finding]:
    code = _strip_comments_and_strings(source)
    findings: list[Finding] = []
    for fn in _split_functions(code):
        if not _has_bridge_message_signal(fn):
            continue

        reasons: list[str] = []
        line_match: re.Match[str] | None = None
        missing_digest, digest_match = _missing_digest_groups(fn)
        if missing_digest:
            labels = ", ".join(_GROUP_LABELS[item] for item in missing_digest)
            reasons.append(f"verified or replay digest omits {labels}")
            line_match = digest_match

        missing_endpoint = _missing_endpoint_checks(fn)
        if missing_endpoint:
            reasons.append("endpoint receive path lacks " + ", ".join(missing_endpoint))
            if line_match is None:
                line_match = _VERIFY_OR_CONSUME_RE.search(fn.body) or _SINK_RE.search(fn.body)

        if not reasons:
            continue
        findings.append(_finding(file_path, _line_for(fn, line_match), fn.name, reasons))
    return findings


__all__ = [
    "scan",
    "Finding",
    "DETECTOR_NAME",
    "DETECTOR_SEVERITY_DEFAULT",
]
