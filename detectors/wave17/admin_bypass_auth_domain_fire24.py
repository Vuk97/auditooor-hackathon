"""
admin-bypass-auth-domain-fire24

Solidity recall-lift detector for privileged admin authorization digests that
verify a signature but do not bind the full authorization domain. The domain
must include the source chain or chain selector, source sender, receiver,
target contract, function selector, and privileged role when those fields are
present on the entrypoint.

Provenance:
- context_pack_id: auditooor.vault_context_pack.v1:resume:9625aa6c1a1d4007
- measured miss: abi-encode-packed-hash-collision
- measured miss: ccip-receiver-and-chain-unvalidated
- related Fire23 detector: admin-bypass-domain-auth-fire23

Hits are candidate evidence only. NOT_SUBMIT_READY.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "admin-bypass-auth-domain-fire24"
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
_DIRECT_RECOVER_HASH_RE = re.compile(
    r"(?is)(?:ECDSA\s*\.\s*recover|ecrecover|SignatureChecker|isValidSignature)"
    r"\s*\([^;{}]*keccak256\s*\(\s*abi\s*\.\s*encode(?P<packed>Packed)?\s*\("
    r"(?P<args>[^;{}]+?)\)\s*\)"
)
_DIGEST_VAR_RE = re.compile(
    r"(?i)(digest|authHash|adminHash|messageHash|actionHash|operationHash|structHash|permissionHash)"
)
_SIGNATURE_AUTH_RE = re.compile(
    r"(?is)\b(?:ecrecover|ECDSA\s*\.\s*recover|SignatureChecker|isValidSignature)\b"
)
_SIGNER_GATE_RE = re.compile(
    r"(?is)(?:signers|trustedSigners|authorizedSigners|adminSigners|hasRole\s*\()"
    r"\s*(?:\[|\()"
)
_CALLER_AUTH_GUARD_RE = re.compile(
    r"(?is)(?:"
    r"\b(?:onlyOwner|onlyAdmin|onlyRole|onlyRoles|onlyGovernance|onlyGovernor|"
    r"onlyTimelock|requiresAuth|requireAuth|restricted|auth)\b|"
    r"\b(?:_checkRole|_checkOwner|isOwner|isAdmin|isAuthorized)\s*\(|"
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
    r"executor|router|oracle|treasury|feeRecipient|config|implementation)\s*=\s*|"
    r"\b(?:trusted|allowed|approved|authorized|whitelist|blacklist)"
    r"[A-Za-z0-9_]*\s*\[[^;\]]+\]\s*=\s*true|"
    r"\b(?:setAdmin|setOwner|setOracle|setRouter|setExecutor|setTrusted|"
    r"executeAdmin|adminCall|upgradeTo|upgradeToAndCall)\s*\("
    r")"
)
_LOCAL_DOMAIN_RE = re.compile(
    r"(?is)(address\s*\(\s*this\s*\)|block\s*\.\s*chainid|DOMAIN_SEPARATOR|domainSeparator)"
)
_DOMAIN_FIELD_PATTERNS = {
    "chain": re.compile(
        r"(?i)(sourceChainSelector|chainSelector|srcChain|sourceChain|originChain|"
        r"remoteChain|chainId|domainId)$"
    ),
    "source sender": re.compile(
        r"(?i)(sourceSender|remoteSender|originSender|trustedSender|senderDomain|sender)$"
    ),
    "receiver": re.compile(r"(?i)(receiver|recipient)$"),
    "target contract": re.compile(
        r"(?i)(target|targetContract|receiverContract|verifyingContract|executorContract)$"
    ),
    "function selector": re.compile(
        r"(?i)(selector|functionSelector|callSelector|targetSelector|operationSelector)$"
    ),
    "role": re.compile(r"(?i)(role|roleId|adminRole|operatorRole|privilegedRole)$"),
}
_MIN_DOMAIN_FIELDS = 4


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
    return {match.group("name") for match in _PARAM_RE.finditer(_parameter_section(header))}


def _domain_param_fields(header: str) -> dict[str, set[str]]:
    fields: dict[str, set[str]] = {}
    for name in _param_names(header):
        for field, pattern in _DOMAIN_FIELD_PATTERNS.items():
            if pattern.search(name):
                fields.setdefault(field, set()).add(name)
    return fields


def _hash_args(body: str) -> list[str]:
    out: list[str] = []
    for match in _HASH_ASSIGN_RE.finditer(body):
        name = match.group("name") or ""
        if _DIGEST_VAR_RE.search(name):
            out.append(match.group("args"))
    out.extend(match.group("args") for match in _DIRECT_RECOVER_HASH_RE.finditer(body))
    return out


def _field_bound(args: str, field: str, names: set[str]) -> bool:
    if any(re.search(rf"\b{re.escape(name)}\b", args) for name in names):
        return True
    if field == "chain" and re.search(r"\bblock\s*\.\s*chainid\b", args):
        return True
    if field == "target contract" and re.search(r"\baddress\s*\(\s*this\s*\)", args):
        return True
    return False


def _missing_domain_fields(fields: dict[str, set[str]], args: str) -> list[str]:
    missing: list[str] = []
    for field, names in fields.items():
        if not _field_bound(args, field, names):
            missing.append(field)
    return missing


def _admin_digest_domain_gap(header: str, body: str) -> list[str]:
    text = f"{header}\n{body}"
    if not _is_external_entry(header):
        return []
    if _CALLER_AUTH_GUARD_RE.search(text):
        return []
    if not _SIGNATURE_AUTH_RE.search(body):
        return []
    if not _SIGNER_GATE_RE.search(body):
        return []
    if not _PRIVILEGED_EFFECT_RE.search(body):
        return []

    fields = _domain_param_fields(header)
    if len(fields) < _MIN_DOMAIN_FIELDS:
        return []

    for args in _hash_args(body):
        missing = _missing_domain_fields(fields, args)
        local_binding_present = bool(_LOCAL_DOMAIN_RE.search(args))
        if missing or not local_binding_present:
            return missing or ["local chain or contract"]
    return []


def _finding(file_path: str, line: int, function: str, missing: list[str]) -> Finding:
    omitted = ", ".join(missing)
    return Finding(
        detector=DETECTOR_NAME,
        file=file_path,
        line=line,
        severity=DETECTOR_SEVERITY_DEFAULT,
        function=function,
        message=(
            "signed privileged authorization digest omits admin domain field(s): "
            f"{omitted}. The signature can authorize a different privileged "
            "chain, sender, receiver, target, selector, or role context. "
            "NOT_SUBMIT_READY: detector fixture smoke evidence only."
        ),
    )


def scan(source: str, file_path: str = "<memory>") -> list[Finding]:
    code = _strip_comments_and_strings(source)
    findings: list[Finding] = []
    for name, header, body, line in _split_functions(code):
        missing = _admin_digest_domain_gap(header, body)
        if missing:
            findings.append(_finding(file_path, line, name, missing))
    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
