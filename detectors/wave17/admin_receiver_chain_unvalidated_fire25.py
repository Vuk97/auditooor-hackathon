"""
admin-receiver-chain-unvalidated-fire25

Solidity recall-lift detector for privileged cross-chain receiver callbacks
that accept an admin payload after only partial authentication. The target
shape is a CCIP-style receiver that checks the router or payload type, then
executes a privileged mutation without binding the source chain selector,
trusted source sender, receiver contract, or router.

Provenance:
- context_pack_id: auditooor.vault_context_pack.v1:resume:fcf56f9b78035a25
- target miss family: ccip-receiver-and-chain-unvalidated
- attack_class: admin-bypass

Hits are candidate evidence only. NOT_SUBMIT_READY.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "admin-receiver-chain-unvalidated-fire25"
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
_PUBLIC_HEADER_RE = re.compile(r"\b(?:external|public|internal)\b")
_VIEW_HEADER_RE = re.compile(r"\b(?:view|pure)\b")
_RECEIVER_CONTEXT_RE = re.compile(
    r"(?is)\b(?:ccipReceive|_ccipReceive|Any2EVMMessage|sourceChainSelector|"
    r"IRouterClient|Client\s*\.)\b"
)
_MESSAGE_PAYLOAD_RE = re.compile(
    r"(?is)\b(?:message|msg_?)\s*\.\s*(?:data|sender|sourceChainSelector)\b|"
    r"abi\s*\.\s*decode\s*\([^;{}]*(?:message|msg_?)\s*\.\s*data"
)
_PARTIAL_AUTH_RE = re.compile(
    r"(?is)(?:"
    r"\bonlyRouter\b|"
    r"msg\s*\.\s*sender\s*(?:==|!=)[^;{}]*(?:router|Router|ccipRouter)|"
    r"(?:router|Router|ccipRouter)[^;{}]*(?:==|!=)\s*msg\s*\.\s*sender|"
    r"\b(?:messageType|messageKind|commandType|actionType|kind)\s*(?:==|!=)|"
    r"\b(?:trusted|allowed|approved)[A-Za-z0-9_]*Senders?\s*\["
    r")"
)
_PRIVILEGED_EFFECT_RE = re.compile(
    r"(?is)(?:"
    r"\b_grantRole\s*\(|\bgrantRole\s*\(|\b_setupRole\s*\(|"
    r"\b_revokeRole\s*\(|\brevokeRole\s*\(|"
    r"\b(?:roles|roleMembers|admins|operators|controllers|keepers|managers)"
    r"\s*\[[^\]]+\]\s*=\s*(?:true|[A-Za-z_][A-Za-z0-9_]*)|"
    r"\b(?:owner|admin|governance|governor|guardian|controller|manager|operator|"
    r"executor|router|oracle|treasury|feeRecipient|config|implementation|adminReceiver)"
    r"\s*=\s*|"
    r"\b(?:trusted|allowed|approved|authorized|whitelist|blacklist)"
    r"[A-Za-z0-9_]*\s*\[[^\]]+\]\s*=\s*true|"
    r"\b(?:setAdmin|setOwner|setOracle|setRouter|setExecutor|setTrusted|"
    r"executeAdmin|adminCall|upgradeTo|upgradeToAndCall)\s*\("
    r")"
)
_ROUTER_GUARD_RE = re.compile(
    r"(?is)(?:"
    r"\bonlyRouter\b|"
    r"msg\s*\.\s*sender\s*(?:==|!=)[^;{}]*(?:router|Router|ccipRouter)|"
    r"(?:router|Router|ccipRouter)[^;{}]*(?:==|!=)\s*msg\s*\.\s*sender|"
    r"\b(?:_validateRouter|validateRouter|InvalidRouter|getRouter)\s*\("
    r")"
)
_CHAIN_GUARD_RE = re.compile(
    r"(?is)(?:"
    r"(?:message|msg_?)\s*\.\s*sourceChainSelector\s*(?:==|!=)|"
    r"(?:sourceChainSelector|srcChain|sourceChain|remoteChain)\s*(?:==|!=)|"
    r"(?:trusted|allowed|approved|enabled)[A-Za-z0-9_]*Chains?\s*\["
    r"\s*(?:message|msg_?)\s*\.\s*sourceChainSelector\s*\]"
    r")"
)
_SENDER_GUARD_RE = re.compile(
    r"(?is)(?:"
    r"(?:remoteSender|sourceSender|originSender|decodedSender)\s*(?:==|!=)\s*"
    r"(?:TRUSTED|trusted|allowed|expected)[A-Za-z0-9_]*|"
    r"(?:TRUSTED|trusted|allowed|expected)[A-Za-z0-9_]*\s*(?:==|!=)\s*"
    r"(?:remoteSender|sourceSender|originSender|decodedSender)|"
    r"(?:trusted|allowed|approved|enabled)[A-Za-z0-9_]*Senders?\s*\[|"
    r"keccak256\s*\(\s*(?:message|msg_?)\s*\.\s*sender\s*\)\s*(?:==|!=)"
    r")"
)
_RECEIVER_GUARD_RE = re.compile(
    r"(?is)(?:"
    r"(?:receiver|recipient|targetReceiver|receiverContract|targetContract)"
    r"\s*(?:==|!=)\s*address\s*\(\s*this\s*\)|"
    r"address\s*\(\s*this\s*\)\s*(?:==|!=)\s*"
    r"(?:receiver|recipient|targetReceiver|receiverContract|targetContract)|"
    r"(?:expectedReceiver|allowedReceiver|trustedReceiver|canonicalReceiver)"
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


def _is_callable_entry(header: str) -> bool:
    return bool(_PUBLIC_HEADER_RE.search(header)) and not _VIEW_HEADER_RE.search(header)


def _missing_receiver_bindings(name: str, header: str, body: str) -> list[str]:
    text = f"{name}\n{header}\n{body}"
    if not _is_callable_entry(header):
        return []
    if not _RECEIVER_CONTEXT_RE.search(text):
        return []
    if not _MESSAGE_PAYLOAD_RE.search(text):
        return []
    if not _PARTIAL_AUTH_RE.search(text):
        return []
    if not _PRIVILEGED_EFFECT_RE.search(body):
        return []

    missing: list[str] = []
    if not _ROUTER_GUARD_RE.search(text):
        missing.append("router")
    if not _CHAIN_GUARD_RE.search(text):
        missing.append("source chain selector")
    if not _SENDER_GUARD_RE.search(text):
        missing.append("trusted sender")
    if not _RECEIVER_GUARD_RE.search(text):
        missing.append("receiver contract")
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
            "privileged cross-chain receiver executes admin payload without "
            f"binding: {omitted}. The callback has partial router or message-type "
            "authentication, but the receiver domain is incomplete. "
            "NOT_SUBMIT_READY: detector fixture smoke evidence only."
        ),
    )


def scan(source: str, file_path: str = "<memory>") -> list[Finding]:
    code = _strip_comments_and_strings(source)
    findings: list[Finding] = []
    for name, header, body, line in _split_functions(code):
        missing = _missing_receiver_bindings(name, header, body)
        if missing:
            findings.append(_finding(file_path, line, name, missing))
    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
