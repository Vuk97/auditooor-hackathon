"""
admin-receiver-source-domain-fire26

Solidity recall-lift detector for privileged cross-chain receiver callbacks
that validate only the local router before executing an admin payload. The
target shape is a CCIP or bridge receiver that decodes an admin action and
mutates privileged state without binding the remote source chain and remote
source sender or domain.

Provenance:
- context_pack_id: auditooor.vault_context_pack.v1:resume:adfd418d3f6192da
- context_pack_hash: adfd418d3f6192daba631fcbdf76e5215584274de62029de0f3d710f7f613f3b
- target miss family: ccip-receiver-and-chain-unvalidated
- attack_class: admin-bypass
- related detector: admin-receiver-chain-unvalidated-fire25

Hits are candidate evidence only. NOT_SUBMIT_READY.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "admin-receiver-source-domain-fire26"
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
    r"sourceDomain|remoteDomain|srcEid|srcChainId"
    r")\b"
)
_PAYLOAD_DECODE_RE = re.compile(
    r"(?is)abi\s*\.\s*decode\s*\([^;{}]*"
    r"(?:message|msg_|payload|data|encoded|command)[A-Za-z0-9_\.]*"
)
_ADMIN_PAYLOAD_RE = re.compile(
    r"(?is)\b(?:"
    r"SET_ADMIN|GRANT_ADMIN|GRANT_ROLE|REVOKE_ROLE|SET_OWNER|SET_GOVERNANCE|"
    r"SET_GUARDIAN|SET_OPERATOR|SET_MANAGER|SET_EXECUTOR|SET_ROUTER|"
    r"ADMIN_ROLE|OPERATOR_ROLE|adminAction|adminCommand|messageType|"
    r"commandType|actionType|newAdmin|newOwner|newGovernor|newOperator|"
    r"newManager|newGuardian|targetAdmin"
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
_PRIVILEGED_EFFECT_RE = re.compile(
    r"(?is)(?:"
    r"\b_grantRole\s*\(|\bgrantRole\s*\(|\b_setupRole\s*\(|"
    r"\b_revokeRole\s*\(|\brevokeRole\s*\(|"
    r"\b(?:roles|roleMembers|admins|operators|controllers|keepers|managers)"
    r"\s*\[[^;\]]+\]\s*=\s*(?:true|[A-Za-z_][A-Za-z0-9_]*)|"
    r"\b(?:owner|admin|governance|governor|guardian|controller|manager|operator|"
    r"executor|router|oracle|treasury|feeRecipient|config|implementation|"
    r"adminReceiver)\s*=\s*|"
    r"\b(?:trusted|allowed|approved|authorized|whitelist|blacklist)"
    r"[A-Za-z0-9_]*\s*\[[^;\]]+\]\s*=\s*true|"
    r"\b(?:setAdmin|setOwner|setOracle|setRouter|setExecutor|setTrusted|"
    r"executeAdmin|adminCall|upgradeTo|upgradeToAndCall)\s*\("
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
    return bool(_CALLABLE_HEADER_RE.search(header)) and not _VIEW_HEADER_RE.search(header)


def _missing_source_domain_bindings(name: str, header: str, body: str) -> list[str]:
    text = f"{name}\n{header}\n{body}"
    if not _is_callable_entry(header):
        return []
    if not _RECEIVER_CONTEXT_RE.search(text):
        return []
    if not _PAYLOAD_DECODE_RE.search(body):
        return []
    if not _ADMIN_PAYLOAD_RE.search(text):
        return []
    if not _ROUTER_GUARD_RE.search(text):
        return []
    if not _PRIVILEGED_EFFECT_RE.search(body):
        return []

    missing: list[str] = []
    if not _SOURCE_CHAIN_GUARD_RE.search(text):
        missing.append("source chain")
    if not _SOURCE_SENDER_GUARD_RE.search(text):
        missing.append("source sender")
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
            "privileged cross-chain receiver decodes an admin payload after "
            f"only router authentication and lacks {omitted} allowlisting. "
            "A router-only callback can accept a privileged action from an "
            "untrusted remote domain. NOT_SUBMIT_READY: detector fixture "
            "smoke evidence only."
        ),
    )


def scan(source: str, file_path: str = "<memory>") -> list[Finding]:
    code = _strip_comments_and_strings(source)
    findings: list[Finding] = []
    for name, header, body, line in _split_functions(code):
        missing = _missing_source_domain_bindings(name, header, body)
        if missing:
            findings.append(_finding(file_path, line, name, missing))
    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
