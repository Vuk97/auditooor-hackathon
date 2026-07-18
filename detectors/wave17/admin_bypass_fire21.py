"""
admin-bypass-fire21

Recall-lift detector for Solidity admin-bypass misses where a privileged or
trust-bound effect is reachable through a caller-controlled packed digest, an
unvalidated CCIP receiver domain, or a transfer-to-pair side effect that is
treated as route authorization. Hits are candidate evidence only.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "admin-bypass-fire21"
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
_DYNAMIC_PARAM_RE = re.compile(
    r"(?is)\b(?:bytes|string|[A-Za-z_][A-Za-z0-9_]*\s*\[\s*\])"
    r"\s+(?:(?:calldata|memory|storage)\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
)
_PACKED_HASH_RE = re.compile(
    r"(?is)keccak256\s*\(\s*abi\s*\.\s*encodePacked\s*\((?P<args>[^;{}]+?)\)\s*\)"
)
_SIGNATURE_AUTH_RE = re.compile(
    r"(?is)\b(?:ecrecover|ECDSA\s*\.\s*recover|SignatureChecker|isValidSignature|"
    r"signature|signer|digest|orderHash|adminHash|authHash)\b"
)
_SAFE_DIGEST_RE = re.compile(
    r"(?is)(?:abi\s*\.\s*encode\s*\(|_hashTypedDataV4|toTypedDataHash|"
    r"TYPEHASH|domainSeparator|DOMAIN_SEPARATOR)"
)
_DIGEST_DOMAIN_TOKEN_RE = re.compile(
    r"(?is)(?:address\s*\(\s*this\s*\)|block\s*\.\s*chainid|chainid|"
    r"DOMAIN|domain|verifyingContract)"
)
_PRIVILEGED_EFFECT_RE = re.compile(
    r"(?is)(?:"
    r"\b_grantRole\s*\(|\bgrantRole\s*\(|\b_setupRole\s*\(|"
    r"\b_revokeRole\s*\(|\brevokeRole\s*\(|"
    r"\b(?:roles|roleMembers|admins|operators|controllers|keepers|managers)"
    r"\s*\[[^;\]]+\]\s*=\s*true|"
    r"\b(?:owner|admin|governance|governor|guardian|controller|manager|"
    r"operator|executor|router|oracle|treasury|feeRecipient|config)"
    r"\s*=\s*|"
    r"\b(?:trusted|allowed|approved|authorized|whitelist|blacklist)"
    r"[A-Za-z0-9_]*\s*\[[^;\]]+\]\s*=\s*true|"
    r"\b(?:trusted|allowed|approved|authorized)[A-Za-z0-9_]*\s*=\s*|"
    r"\b(?:setAdmin|setOwner|setOracle|setRouter|setExecutor|setTrusted|"
    r"executeAdmin|adminCall|upgradeTo)\s*\("
    r")"
)
_AUTH_GUARD_RE = re.compile(
    r"(?is)(?:"
    r"\b(?:onlyOwner|onlyAdmin|onlyRole|onlyRoles|onlyGovernance|onlyGovernor|"
    r"onlyController|onlyManager|onlyOperator|requiresAuth|requireAuth|"
    r"restricted|auth)\b|"
    r"\b(?:hasRole|_checkRole|_checkOwner|isOwner|isAdmin|isAuthorized)\s*\(|"
    r"\brequire\s*\([^;{}]*(?:msg\.sender|_msgSender\s*\(\s*\))"
    r"[^;{}]*(?:owner|admin|governance|governor|controller|manager|operator|"
    r"trusted|authorized|allowed)|"
    r"\brequire\s*\([^;{}]*(?:owner|admin|governance|governor|controller|"
    r"manager|operator|trusted|authorized|allowed)[^;{}]*(?:msg\.sender|"
    r"_msgSender\s*\(\s*\))"
    r")"
)
_CCIP_CONTEXT_RE = re.compile(
    r"(?is)(?:\bccip\b|Any2EVMMessage|sourceChainSelector|Client\s*\.)"
)
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
    r"(?:trusted|allowed|approved|enabled)[A-Za-z0-9_]*Senders?\s*\[|"
    r"(?:remoteSender|sourceSender|trustedSender|allowedSender)\s*(?:==|!=)"
    r")"
)
_RECEIVER_GUARD_RE = re.compile(
    r"(?is)(?:"
    r"(?:receiver|recipient|target)\s*(?:==|!=)\s*address\s*\(\s*this\s*\)|"
    r"address\s*\(\s*this\s*\)\s*(?:==|!=)\s*(?:receiver|recipient|target)|"
    r"(?:expectedReceiver|allowedReceiver|trustedReceiver|canonicalReceiver)"
    r")"
)
_TRANSFER_TO_ROUTE_RE = re.compile(
    r"(?is)(?:safeTransfer|transfer|transferFrom)\s*\(\s*"
    r"(?P<route>pair|pool|route|router|market|recipient|receiver)\s*,"
)
_PAIR_SIDE_EFFECT_RE = re.compile(
    r"(?is)(?:"
    r"\.\s*(?:sync|skim|getReserves)\s*\(|"
    r"\b(?:trusted|allowed|approved|enabled)[A-Za-z0-9_]*\s*\[[^;\]]+\]\s*=\s*true|"
    r"\b(?:adminPrice|trustedPrice|routePrice|price|spotPrice|oraclePrice)"
    r"[A-Za-z0-9_]*\s*\[[^;\]]+\]\s*="
    r")"
)
_ROUTE_GUARD_RE = re.compile(
    r"(?is)(?:"
    r"\b(?:onlyOwner|onlyAdmin|onlyRole|onlyGovernance|onlyGovernor)\b|"
    r"\brequire\s*\([^;{}]*(?:approved|allowed|trusted|registered|canonical)"
    r"[A-Za-z0-9_]*\s*\[\s*(?:pair|pool|route|router|market|recipient|receiver)\s*\]|"
    r"\brequire\s*\([^;{}]*(?:pair|pool|route|router|market|recipient|receiver)"
    r"\s*==\s*(?:canonical|trusted|approved|allowed|registered)[A-Za-z0-9_]*|"
    r"\b(?:approved|allowed|trusted|registered|canonical)[A-Za-z0-9_]*"
    r"\s*(?:==|!=)\s*(?:pair|pool|route|router|market|recipient|receiver)"
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


def _dynamic_param_names(header: str) -> set[str]:
    return {match.group("name") for match in _DYNAMIC_PARAM_RE.finditer(header)}


def _packed_digest_uses_two_dynamic_params(header: str, body: str) -> bool:
    dynamic_names = _dynamic_param_names(header)
    if len(dynamic_names) < 2:
        return False
    for match in _PACKED_HASH_RE.finditer(body):
        args = match.group("args")
        if _DIGEST_DOMAIN_TOKEN_RE.search(args):
            continue
        used = {name for name in dynamic_names if re.search(rf"\b{re.escape(name)}\b", args)}
        if len(used) >= 2:
            return True
    return False


def _packed_digest_admin_bypass(header: str, body: str) -> bool:
    if not _is_external_entry(header):
        return False
    if _AUTH_GUARD_RE.search(header):
        return False
    if _SAFE_DIGEST_RE.search(body):
        return False
    if not _SIGNATURE_AUTH_RE.search(body):
        return False
    if not _PRIVILEGED_EFFECT_RE.search(body):
        return False
    return _packed_digest_uses_two_dynamic_params(header, body)


def _ccip_domain_admin_bypass(name: str, header: str, body: str) -> bool:
    text = f"{name}\n{header}\n{body}"
    if not _CCIP_CONTEXT_RE.search(text):
        return False
    if not _CCIP_DATA_RE.search(body):
        return False
    if not _PRIVILEGED_EFFECT_RE.search(body):
        return False
    return not (
        _CHAIN_GUARD_RE.search(body)
        and _SENDER_GUARD_RE.search(body)
        and _RECEIVER_GUARD_RE.search(body)
    )


def _transfer_side_effect_admin_bypass(header: str, body: str) -> bool:
    if not _is_external_entry(header):
        return False
    if _ROUTE_GUARD_RE.search(f"{header}\n{body}"):
        return False
    if not _TRANSFER_TO_ROUTE_RE.search(body):
        return False
    return bool(_PAIR_SIDE_EFFECT_RE.search(body))


def _finding(file_path: str, line: int, function: str, branch: str) -> Finding:
    return Finding(
        detector=DETECTOR_NAME,
        file=file_path,
        line=line,
        severity=DETECTOR_SEVERITY_DEFAULT,
        function=function,
        message=(
            f"{branch} reaches privileged or trust-bound state. "
            "NOT_SUBMIT_READY: detector fixture smoke evidence only."
        ),
    )


def scan(source: str, file_path: str = "<memory>") -> list[Finding]:
    code = _strip_comments_and_strings(source)
    findings: list[Finding] = []
    for name, header, body, line in _split_functions(code):
        if _packed_digest_admin_bypass(header, body):
            findings.append(
                _finding(
                    file_path,
                    line,
                    name,
                    "caller-controlled abi.encodePacked digest collision",
                )
            )
        if _ccip_domain_admin_bypass(name, header, body):
            findings.append(
                _finding(
                    file_path,
                    line,
                    name,
                    "CCIP receiver missing source chain, sender, or receiver binding",
                )
            )
        if _transfer_side_effect_admin_bypass(header, body):
            findings.append(
                _finding(
                    file_path,
                    line,
                    name,
                    "transfer-to-pair side effect trusted as route authorization",
                )
            )
    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
