"""
ccip-receiver-chain-source-unvalidated-fire27

Solidity recall-lift detector for CCIP or bridge receiver callbacks that
decode a receiver and target-chain tuple from the inbound payload, then apply
a privileged route or admin mutation without validating the complete receiver
domain first.

Provenance:
- context_pack_id: auditooor.vault_context_pack.v1:resume:5a4dc5fcabec4193
- context_pack_hash: 5a4dc5fcabec419385f40cc3f83d3a24f63a01e0d5c301ab1ef08763094a3fe5
- source refs:
  - reference/patterns.dsl/ccip-receiver-and-chain-unvalidated.yaml
  - reference/patterns.dsl/cross-chain-aa-address-symmetry.yaml
  - reference/patterns.dsl/abi-encode-packed-hash-collision.yaml
- target miss family: ccip-receiver-and-chain-unvalidated
- attack_class: admin-bypass
- related detectors: admin-receiver-chain-unvalidated-fire25,
  admin-receiver-source-domain-fire26

Hits are candidate evidence only. NOT_SUBMIT_READY.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "ccip-receiver-chain-source-unvalidated-fire27"
DETECTOR_SEVERITY_DEFAULT = "High"


@dataclass
class Finding:
    detector: str
    file: str
    line: int
    severity: str
    message: str
    function: Optional[str] = None


_COMMENT_OR_STRING_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'|"
    r"//[^\n\r]*|"
    r"/\*.*?\*/",
    re.DOTALL,
)
_FN_HEADER_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_CALLABLE_HEADER_RE = re.compile(r"\b(?:external|public|internal)\b")
_VIEW_HEADER_RE = re.compile(r"\b(?:view|pure)\b")
_RECEIVER_CONTEXT_RE = re.compile(
    r"(?is)\b(?:"
    r"ccipReceive|_ccipReceive|Any2EVMMessage|Client\s*\.|IRouterClient|"
    r"lzReceive|receiveMessage|handleMessage|receiveCrossChain|onMessage|"
    r"processMessage|executeMessage|sourceChainSelector|sourceChainId|"
    r"sourceDomain|remoteDomain|srcEid|srcChainId|receiverContract|"
    r"targetChainSelector|destinationChainSelector"
    r")\b"
)
_PAYLOAD_DECODE_RE = re.compile(
    r"(?is)abi\s*\.\s*decode\s*\([^;{}]*"
    r"(?:message|msg_|payload|data|encoded|command)[A-Za-z0-9_\.]*"
)
_PAYLOAD_RECEIVER_RE = re.compile(
    r"(?is)\b(?:"
    r"receiver|recipient|targetReceiver|targetRecipient|receiverContract|"
    r"targetContract|remoteReceiver|remoteRecipient|destinationReceiver|"
    r"destinationContract|adminReceiver"
    r")\b"
)
_PAYLOAD_CHAIN_RE = re.compile(
    r"(?is)\b(?:"
    r"targetChainSelector|destinationChainSelector|dstChainSelector|"
    r"targetChainId|destinationChainId|dstChainId|targetDomain|"
    r"destinationDomain|dstDomain|targetEid|dstEid|targetChain|"
    r"destinationChain"
    r")\b"
)
_ADMIN_PAYLOAD_RE = re.compile(
    r"(?is)\b(?:"
    r"SET_ADMIN|GRANT_ADMIN|GRANT_ROLE|REVOKE_ROLE|SET_OWNER|SET_GOVERNANCE|"
    r"SET_GUARDIAN|SET_OPERATOR|SET_MANAGER|SET_EXECUTOR|SET_ROUTER|"
    r"SET_REMOTE|SET_ROUTE|SET_PEER|ADMIN_ROLE|OPERATOR_ROLE|adminAction|"
    r"adminCommand|messageType|commandType|actionType|newAdmin|newOwner|"
    r"newGovernor|newOperator|newManager|newGuardian|remoteAdmin|"
    r"targetAdmin|targetContract|targetChainSelector"
    r")\b"
)
_ROUTER_GUARD_RE = re.compile(
    r"(?is)(?:"
    r"\bonlyRouter\b|"
    r"\bonly[A-Za-z0-9_]*(?:Router|Endpoint|Bridge|Messenger)\b|"
    r"msg\s*\.\s*sender\s*(?:==|!=)[^;{}]*"
    r"(?:router|Router|ccipRouter|i_router|endpoint|Endpoint|bridge|Bridge|"
    r"messenger|Messenger)|"
    r"(?:router|Router|ccipRouter|i_router|endpoint|Endpoint|bridge|Bridge|"
    r"messenger|Messenger)[^;{}]*(?:==|!=)\s*msg\s*\.\s*sender|"
    r"\b(?:_validateRouter|validateRouter|_requireRouter|requireRouter|"
    r"_checkRouter|getRouter)\s*\("
    r")"
)
_SOURCE_CHAIN_GUARD_RE = re.compile(
    r"(?is)(?:"
    r"(?:message|msg_?)\s*\.\s*sourceChainSelector\s*(?:==|!=)|"
    r"(?:origin|src|message|msg_?)\s*\.\s*(?:srcEid|sourceChainId|sourceDomain)"
    r"\s*(?:==|!=)|"
    r"(?:sourceChainSelector|sourceChainId|srcChain|srcChainId|sourceChain|"
    r"remoteChain|originChain|sourceDomain|srcDomain|remoteDomain|originDomain|"
    r"srcEid)\s*(?:==|!=)|"
    r"(?:trusted|allowed|approved|enabled|valid|supported)[A-Za-z0-9_]*"
    r"(?:Chains?|Domains?|Eids?)\s*\["
    r")"
)
_SOURCE_SENDER_GUARD_RE = re.compile(
    r"(?is)(?:"
    r"(?:remoteSender|sourceSender|originSender|decodedSender|senderBytes|"
    r"srcSender|trustedRemote|remoteAddress)\s*(?:==|!=)\s*"
    r"(?:TRUSTED|trusted|allowed|expected|approved)[A-Za-z0-9_]*|"
    r"(?:TRUSTED|trusted|allowed|expected|approved)[A-Za-z0-9_]*"
    r"\s*(?:==|!=)\s*(?:remoteSender|sourceSender|originSender|decodedSender|"
    r"senderBytes|srcSender|trustedRemote|remoteAddress)|"
    r"(?:trusted|allowed|approved|enabled|valid)[A-Za-z0-9_]*"
    r"(?:Senders?|Remotes?|Peers?|Sources?|Origins?)\s*\[|"
    r"keccak256\s*\([^;{}]*(?:message|msg_?)\s*\.\s*sender[^;{}]*\)"
    r"\s*(?:==|!=)|"
    r"keccak256\s*\([^;{}]*(?:remoteSender|sourceSender|originSender|"
    r"decodedSender|srcSender)[^;{}]*\)\s*(?:==|!=)"
    r")"
)
_RECEIVER_GUARD_RE = re.compile(
    r"(?is)(?:"
    r"(?:receiver|recipient|targetReceiver|targetRecipient|receiverContract|"
    r"targetContract|remoteReceiver|remoteRecipient|destinationReceiver|"
    r"destinationContract|adminReceiver)\s*(?:==|!=)\s*"
    r"(?:address\s*\(\s*this\s*\)|expected|trusted|allowed|canonical|local)|"
    r"(?:address\s*\(\s*this\s*\)|expected|trusted|allowed|canonical|local)"
    r"[^;{}]*(?:==|!=)\s*(?:receiver|recipient|targetReceiver|targetRecipient|"
    r"receiverContract|targetContract|remoteReceiver|remoteRecipient|"
    r"destinationReceiver|destinationContract|adminReceiver)|"
    r"(?:expected|allowed|trusted|canonical|valid)[A-Za-z0-9_]*"
    r"(?:Receivers?|Recipients?|Contracts?)\s*\["
    r")"
)
_TARGET_CHAIN_GUARD_RE = re.compile(
    r"(?is)(?:"
    r"(?:targetChainSelector|destinationChainSelector|dstChainSelector|"
    r"targetChainId|destinationChainId|dstChainId|targetDomain|"
    r"destinationDomain|dstDomain|targetEid|dstEid|targetChain|"
    r"destinationChain)\s*(?:==|!=)\s*"
    r"(?:block\s*\.\s*chainid|LOCAL|local|CURRENT|current|EXPECTED|expected|"
    r"trusted|allowed|canonical)|"
    r"(?:block\s*\.\s*chainid|LOCAL|local|CURRENT|current|EXPECTED|expected|"
    r"trusted|allowed|canonical)[^;{}]*(?:==|!=)\s*"
    r"(?:targetChainSelector|destinationChainSelector|dstChainSelector|"
    r"targetChainId|destinationChainId|dstChainId|targetDomain|"
    r"destinationDomain|dstDomain|targetEid|dstEid|targetChain|"
    r"destinationChain)|"
    r"(?:trusted|allowed|approved|enabled|valid|supported|expected|canonical)"
    r"[A-Za-z0-9_]*(?:Target|Destination)?(?:Chains?|Domains?|Eids?)\s*\["
    r")"
)
_PRIVILEGED_EFFECT_RE = re.compile(
    r"(?is)(?:"
    r"\b_grantRole\s*\(|\bgrantRole\s*\(|\b_setupRole\s*\(|"
    r"\b_revokeRole\s*\(|\brevokeRole\s*\(|"
    r"\b(?:roles|roleMembers|admins|remoteAdmins|operators|controllers|keepers|"
    r"managers|routeAdmins|chainAdmins)\s*(?:\[[^;\]]+\]\s*){1,4}"
    r"=\s*(?:true|[A-Za-z_][A-Za-z0-9_]*)|"
    r"\b(?:owner|admin|governance|governor|guardian|controller|manager|operator|"
    r"executor|router|oracle|treasury|feeRecipient|config|implementation|"
    r"adminReceiver|remoteReceiver|targetReceiver|targetContract|remoteRouter)"
    r"\s*=\s*|"
    r"\b(?:trusted|allowed|approved|authorized|whitelist|blacklist|remote|route|"
    r"peer)[A-Za-z0-9_]*\s*(?:\[[^;\]]+\]\s*){1,4}=\s*(?:true|[A-Za-z_][A-Za-z0-9_]*)|"
    r"\b(?:setAdmin|setOwner|setOracle|setRouter|setExecutor|setTrusted|"
    r"setRemote|setRoute|setPeer|executeAdmin|adminCall|upgradeTo|"
    r"upgradeToAndCall)\s*\("
    r")"
)


def _strip_comments_and_strings(source: str) -> str:
    def replace(match: re.Match[str]) -> str:
        text = match.group(0)
        return "\n" * text.count("\n") if "\n" in text else " "

    return _COMMENT_OR_STRING_RE.sub(replace, source or "")


def _split_functions(source: str) -> list[tuple[str, str, str, int]]:
    out: list[tuple[str, str, str, int]] = []
    pos = 0
    while True:
        match = _FN_HEADER_RE.search(source, pos)
        if match is None:
            break
        name = match.group("name")
        i = match.end()
        depth_paren = 1
        while i < len(source) and depth_paren > 0:
            if source[i] == "(":
                depth_paren += 1
            elif source[i] == ")":
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

        depth = 1
        k = body_start + 1
        while k < len(source) and depth > 0:
            if source[k] == "{":
                depth += 1
            elif source[k] == "}":
                depth -= 1
            k += 1

        header = source[match.start():body_start]
        body = source[body_start + 1:k - 1]
        line = source.count("\n", 0, match.start()) + 1
        out.append((name, header, body, line))
        pos = k
    return out


def _is_receiver_entry(header: str) -> bool:
    return bool(_CALLABLE_HEADER_RE.search(header)) and not _VIEW_HEADER_RE.search(header)


def _missing_domain_bindings(name: str, header: str, body: str) -> list[str]:
    text = f"{name}\n{header}\n{body}"
    if not _is_receiver_entry(header):
        return []
    if not _RECEIVER_CONTEXT_RE.search(text):
        return []
    if not _PAYLOAD_DECODE_RE.search(body):
        return []
    if not _PAYLOAD_RECEIVER_RE.search(text):
        return []
    if not _PAYLOAD_CHAIN_RE.search(text):
        return []
    if not _ADMIN_PAYLOAD_RE.search(text):
        return []
    if not _PRIVILEGED_EFFECT_RE.search(body):
        return []

    missing: list[str] = []
    if not _ROUTER_GUARD_RE.search(text):
        missing.append("allowed router")
    if not _SOURCE_CHAIN_GUARD_RE.search(text):
        missing.append("source chain selector")
    if not _SOURCE_SENDER_GUARD_RE.search(text):
        missing.append("trusted sender")
    if not _RECEIVER_GUARD_RE.search(text):
        missing.append("receiver contract")
    if not _TARGET_CHAIN_GUARD_RE.search(text):
        missing.append("target chain")

    if "receiver contract" not in missing or "target chain" not in missing:
        return []
    return missing


def _finding(file_path: str, line: int, function: str, missing: list[str]) -> Finding:
    omitted = ", ".join(missing)
    return Finding(
        detector=DETECTOR_NAME,
        file=file_path,
        line=line,
        severity=DETECTOR_SEVERITY_DEFAULT,
        function=function,
        message=(
            "CCIP or bridge receiver decodes a receiver and target-chain admin "
            f"payload before privileged mutation but lacks {omitted} binding. "
            "The missing receiver-chain pair can let a valid router-delivered "
            "message mutate the wrong local admin or route domain. "
            "NOT_SUBMIT_READY: detector fixture smoke evidence only."
        ),
    )


def scan(source: str, file_path: str = "<memory>") -> list[Finding]:
    code = _strip_comments_and_strings(source)
    findings: list[Finding] = []
    for name, header, body, line in _split_functions(code):
        missing = _missing_domain_bindings(name, header, body)
        if missing:
            findings.append(_finding(file_path, line, name, missing))
    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
