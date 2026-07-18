"""
admin-bypass-domain-auth-fire23

Recall-lift detector for Solidity admin-bypass misses where a signature digest
or cross-chain receiver callback authorizes privileged mutation while omitting
load-bearing domain fields.

Source anchors:
- context_pack_id: auditooor.vault_context_pack.v1:resume:9c8dd8c350f93fe7
- measured miss: abi-encode-packed-hash-collision
- measured miss: ccip-receiver-and-chain-unvalidated
- rust analogue: public-servicenft-updateimpact-bypasses-governance-only-intent

Hits are candidate evidence only. NOT_SUBMIT_READY.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "admin-bypass-domain-auth-fire23"
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
_PUBLIC_HEADER_RE = re.compile(r"\b(?:external|public)\b")
_VIEW_HEADER_RE = re.compile(r"\b(?:view|pure)\b")
_PARAM_RE = re.compile(
    r"(?is)(?:^|,)\s*"
    r"(?:[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?|"
    r"bytes(?:[0-9]+)?|uint(?:[0-9]+)?|address|string|bool)"
    r"(?:\s*\[\s*\])?\s+"
    r"(?:(?:calldata|memory|storage)\s+)?"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
)
_HASH_ASSIGN_RE = re.compile(
    r"(?is)(?:bytes32\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"keccak256\s*\(\s*abi\s*\.\s*encode(?P<packed>Packed)?\s*\("
    r"(?P<args>[^;{}]+?)\)\s*\)"
)
_DIGEST_VAR_RE = re.compile(r"(?i)(digest|authHash|adminHash|messageHash|orderHash|structHash)")
_AUTH_VERIFY_RE = re.compile(
    r"(?is)(?:\becrecover\b|ECDSA\s*\.\s*recover|SignatureChecker|"
    r"isValidSignature|signature|signer|digest)"
)
_CALLER_AUTH_GUARD_RE = re.compile(
    r"(?is)(?:"
    r"\b(?:onlyOwner|onlyAdmin|onlyRole|onlyRoles|onlyGovernance|onlyGovernor|"
    r"onlyTimelock|requiresAuth|requireAuth|restricted|auth)\b|"
    r"\b(?:hasRole|_checkRole|_checkOwner|isOwner|isAdmin|isAuthorized)\s*\(|"
    r"\brequire\s*\([^;{}]*(?:msg\.sender|_msgSender\s*\(\s*\))"
    r"[^;{}]*(?:owner|admin|governance|governor|timelock|controller|manager|operator)|"
    r"\brequire\s*\([^;{}]*(?:owner|admin|governance|governor|timelock|"
    r"controller|manager|operator)[^;{}]*(?:msg\.sender|_msgSender\s*\(\s*\))"
    r")"
)
_PRIVILEGED_EFFECT_RE = re.compile(
    r"(?is)(?:"
    r"\b_grantRole\s*\(|\bgrantRole\s*\(|\b_setupRole\s*\(|"
    r"\b_revokeRole\s*\(|\brevokeRole\s*\(|"
    r"\b(?:roles|roleMembers|admins|operators|controllers|keepers|managers)"
    r"\s*\[[^;\]]+\]\s*=\s*true|"
    r"\b(?:owner|admin|governance|governor|guardian|controller|manager|operator|"
    r"executor|router|oracle|treasury|feeRecipient|config)\s*=\s*|"
    r"\b(?:trusted|allowed|approved|authorized|whitelist|blacklist)"
    r"[A-Za-z0-9_]*\s*\[[^;\]]+\]\s*=\s*true|"
    r"\b(?:setAdmin|setOwner|setOracle|setRouter|setExecutor|setTrusted|"
    r"executeAdmin|adminCall|upgradeTo)\s*\("
    r")"
)
_DYNAMIC_ARG_RE = re.compile(
    r"(?is)\b(?:bytes|string|[A-Za-z_][A-Za-z0-9_]*\s*\[\s*\])\s+"
    r"(?:(?:calldata|memory|storage)\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
)
_DOMAIN_FIELD_PATTERNS = {
    "chain selector": re.compile(r"(?i)(sourceChainSelector|chainSelector|srcChain|sourceChain|originChain|remoteChain|chainId)$"),
    "receiver": re.compile(r"(?i)(receiver|recipient)$"),
    "target contract": re.compile(r"(?i)(target|targetContract|receiverContract|implementation|verifyingContract)$"),
    "function selector": re.compile(r"(?i)(selector|functionSelector|callSelector|targetSelector)$"),
    "nonce scope": re.compile(r"(?i)(nonce|nonceScope|scopeNonce|saltedNonce)$"),
    "role": re.compile(r"(?i)(role|roleId|adminRole|operatorRole)$"),
}
_LOCAL_DOMAIN_TOKEN_RE = re.compile(r"(?is)(address\s*\(\s*this\s*\)|block\s*\.\s*chainid|DOMAIN_SEPARATOR|domainSeparator)")

_CCIP_CONTEXT_RE = re.compile(r"(?is)(?:\bccip\b|Any2EVMMessage|sourceChainSelector|Client\s*\.)")
_CCIP_DATA_RE = re.compile(r"(?is)(?:message|msg_?)\s*\.\s*(?:data|sender|sourceChainSelector)")
_CHAIN_GUARD_RE = re.compile(
    r"(?is)(?:"
    r"(?:message|msg_?)\s*\.\s*sourceChainSelector\s*(?:==|!=)|"
    r"(?:trusted|allowed|approved|enabled)[A-Za-z0-9_]*Chains?\s*"
    r"\[\s*(?:message|msg_?)\s*\.\s*sourceChainSelector\s*\]|"
    r"(?:sourceChainSelector|remoteChain|sourceChain)\s*(?:==|!=)"
    r")"
)
_SENDER_GUARD_RE = re.compile(
    r"(?is)(?:"
    r"abi\s*\.\s*decode\s*\(\s*(?:message|msg_?)\s*\.\s*sender|"
    r"(?:remoteSender|sourceSender|trustedSender|allowedSender)\s*(?:==|!=)|"
    r"(?:trusted|allowed|approved|enabled)[A-Za-z0-9_]*Senders?\s*\["
    r")"
)
_RECEIVER_GUARD_RE = re.compile(
    r"(?is)(?:"
    r"(?:receiver|recipient)\s*(?:==|!=)\s*address\s*\(\s*this\s*\)|"
    r"address\s*\(\s*this\s*\)\s*(?:==|!=)\s*(?:receiver|recipient)|"
    r"(?:expectedReceiver|allowedReceiver|trustedReceiver|canonicalReceiver)"
    r")"
)
_TARGET_GUARD_RE = re.compile(
    r"(?is)(?:"
    r"(?:target|targetContract|receiverContract)\s*(?:==|!=)\s*address\s*\(\s*this\s*\)|"
    r"address\s*\(\s*this\s*\)\s*(?:==|!=)\s*(?:target|targetContract|receiverContract)|"
    r"(?:expectedTarget|trustedTarget|allowedTarget)"
    r")"
)
_SELECTOR_GUARD_RE = re.compile(
    r"(?is)(?:"
    r"(?:selector|functionSelector|callSelector)\s*(?:==|!=)\s*(?:this\.|[A-Za-z_][A-Za-z0-9_]*\.)?"
    r"[A-Za-z_][A-Za-z0-9_]*\.selector|"
    r"(?:allowed|trusted|approved)[A-Za-z0-9_]*Selectors?\s*\["
    r")"
)
_ROLE_GUARD_RE = re.compile(
    r"(?is)(?:"
    r"\brole\s*(?:==|!=)\s*[A-Z_][A-Z0-9_]*_ROLE|"
    r"(?:allowed|trusted|approved)[A-Za-z0-9_]*Roles?\s*\["
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


def _is_external_entry(header: str) -> bool:
    return bool(_PUBLIC_HEADER_RE.search(header)) and not _VIEW_HEADER_RE.search(header)


def _parameter_section(header: str) -> str:
    start = header.find("(")
    if start < 0:
        return ""
    depth = 1
    i = start + 1
    while i < len(header) and depth > 0:
        if header[i] == "(":
            depth += 1
        elif header[i] == ")":
            depth -= 1
        i += 1
    if depth != 0:
        return ""
    return header[start + 1:i - 1]


def _param_names(header: str) -> set[str]:
    params = _parameter_section(header)
    return {match.group("name") for match in _PARAM_RE.finditer(params)}


def _domain_param_fields(header: str) -> dict[str, set[str]]:
    fields: dict[str, set[str]] = {}
    for name in _param_names(header):
        for field, pattern in _DOMAIN_FIELD_PATTERNS.items():
            if pattern.search(name):
                fields.setdefault(field, set()).add(name)
    return fields


def _dynamic_param_count(header: str) -> int:
    return len({match.group("name") for match in _DYNAMIC_ARG_RE.finditer(_parameter_section(header))})


def _hash_args_for_digest(body: str) -> list[tuple[bool, str]]:
    out: list[tuple[bool, str]] = []
    for match in _HASH_ASSIGN_RE.finditer(body):
        name = match.group("name") or ""
        if not _DIGEST_VAR_RE.search(name):
            continue
        out.append((bool(match.group("packed")), match.group("args")))
    return out


def _missing_domain_fields(fields: dict[str, set[str]], args: str) -> list[str]:
    missing: list[str] = []
    for field, names in fields.items():
        if not any(re.search(rf"\b{re.escape(name)}\b", args) for name in names):
            missing.append(field)
    return missing


def _signed_digest_domain_gap(header: str, body: str) -> list[str]:
    if not _is_external_entry(header):
        return []
    if _CALLER_AUTH_GUARD_RE.search(f"{header}\n{body}"):
        return []
    if not _AUTH_VERIFY_RE.search(body):
        return []
    if not _PRIVILEGED_EFFECT_RE.search(body):
        return []

    fields = _domain_param_fields(header)
    if len(fields) < 2:
        return []

    for packed, args in _hash_args_for_digest(body):
        missing = _missing_domain_fields(fields, args)
        local_domain_bound = bool(_LOCAL_DOMAIN_TOKEN_RE.search(args))
        dynamic_packed = packed and _dynamic_param_count(header) >= 2
        if missing and (dynamic_packed or not local_domain_bound):
            return missing
    return []


def _ccip_receiver_domain_gap(name: str, header: str, body: str) -> list[str]:
    text = f"{name}\n{header}\n{body}"
    if not _CCIP_CONTEXT_RE.search(text):
        return []
    if not _CCIP_DATA_RE.search(body):
        return []
    if not _PRIVILEGED_EFFECT_RE.search(body):
        return []

    missing: list[str] = []
    if not _CHAIN_GUARD_RE.search(body):
        missing.append("chain selector")
    if not _SENDER_GUARD_RE.search(body):
        missing.append("remote sender")
    if not _RECEIVER_GUARD_RE.search(body):
        missing.append("receiver")
    if not _TARGET_GUARD_RE.search(body):
        missing.append("target contract")
    if not _SELECTOR_GUARD_RE.search(body):
        missing.append("function selector")
    if not _ROLE_GUARD_RE.search(body):
        missing.append("role")
    return missing


def _finding(file_path: str, line: int, function: str, branch: str, missing: list[str]) -> Finding:
    omitted = ", ".join(missing)
    return Finding(
        detector=DETECTOR_NAME,
        file=file_path,
        line=line,
        severity=DETECTOR_SEVERITY_DEFAULT,
        function=function,
        message=(
            f"{branch} authorizes privileged mutation without binding "
            f"load-bearing domain field(s): {omitted}. "
            "NOT_SUBMIT_READY: detector fixture smoke evidence only."
        ),
    )


def scan(source: str, file_path: str = "<memory>") -> list[Finding]:
    code = _strip_comments_and_strings(source)
    findings: list[Finding] = []
    for name, header, body, line in _split_functions(code):
        signed_missing = _signed_digest_domain_gap(header, body)
        if signed_missing:
            findings.append(
                _finding(
                    file_path,
                    line,
                    name,
                    "signed digest domain-auth gap",
                    signed_missing,
                )
            )

        ccip_missing = _ccip_receiver_domain_gap(name, header, body)
        if ccip_missing:
            findings.append(
                _finding(
                    file_path,
                    line,
                    name,
                    "cross-chain receiver domain-auth gap",
                    ccip_missing,
                )
            )
    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
