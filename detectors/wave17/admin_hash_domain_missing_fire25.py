"""
admin-hash-domain-missing-fire25

Solidity recall-lift detector for signed privileged admin or route
authorizations where the recovered digest is built with abi.encodePacked and
does not bind replay-critical domain fields.

Provenance:
- context_pack_id: auditooor.vault_context_pack.v1:resume:fcf56f9b78035a25
- context_pack_hash: fcf56f9b78035a25a56bfd6043af651efdeb29b3bfa3414225c6dd96a8617cbe
- same-class miss: abi-encode-packed-hash-collision
- parent class: admin-bypass
- Fire24 precedent: admin-bypass-auth-domain-fire24

Hits are candidate evidence only. NOT_SUBMIT_READY.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "admin-hash-domain-missing-fire25"
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
_PACKED_HASH_ASSIGN_RE = re.compile(
    r"(?is)(?:bytes32\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"keccak256\s*\(\s*abi\s*\.\s*encodePacked\s*\("
    r"(?P<args>[^;{}]+?)\)\s*\)"
)
_DIRECT_PACKED_RECOVER_RE = re.compile(
    r"(?is)(?:ECDSA\s*\.\s*recover|ecrecover|SignatureChecker|isValidSignature)"
    r"\s*\([^;{}]*keccak256\s*\(\s*abi\s*\.\s*encodePacked\s*\("
    r"(?P<args>[^;{}]+?)\)\s*\)"
)
_DIGEST_VAR_RE = re.compile(
    r"(?i)(digest|authHash|adminHash|messageHash|actionHash|operationHash|routeHash|permissionHash)"
)
_SIGNATURE_AUTH_RE = re.compile(
    r"(?is)\b(?:ecrecover|ECDSA\s*\.\s*recover|SignatureChecker|isValidSignature)\b"
)
_SIGNER_GATE_RE = re.compile(
    r"(?is)(?:"
    r"(?:signers|trustedSigners|authorizedSigners|adminSigners|operatorSigners)"
    r"\s*\[[^\]]+\]|"
    r"hasRole\s*\([^;{}]*(?:signer|recovered|adminSigner)|"
    r"\brequire\s*\([^;{}]*(?:signer|recovered|adminSigner)"
    r"[^;{}]*(?:admin|owner|operator|authorized|trusted|signer)|"
    r"\brequire\s*\([^;{}]*(?:admin|owner|operator|authorized|trusted|signer)"
    r"[^;{}]*(?:signer|recovered|adminSigner)"
    r")"
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
    r"executor|router|oracle|treasury|feeRecipient|config|implementation)"
    r"\s*=\s*|"
    r"\b(?:trusted|allowed|approved|authorized|whitelist|blacklist)"
    r"[A-Za-z0-9_]*\s*\[[^;\]]+\]\s*=\s*true|"
    r"\b(?:setAdmin|setOwner|setOracle|setRouter|setExecutor|setTrusted|"
    r"executeAdmin|adminCall|upgradeTo|upgradeToAndCall)\s*\("
    r")"
)
_FIELD_NAME_PATTERNS = {
    "nonce": re.compile(r"(?i)(nonce|nonceScope|scopeNonce|saltedNonce)$"),
    "role": re.compile(r"(?i)(role|roleId|adminRole|operatorRole|privilegedRole)$"),
    "selector": re.compile(
        r"(?i)(selector|functionSelector|callSelector|targetSelector|operationSelector)$"
    ),
    "target": re.compile(
        r"(?i)(target|targetContract|receiverContract|verifyingContract|executorContract)$"
    ),
}
_REQUIRED_BASE_FIELDS = ("chain id", "contract address")


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


def _domain_params(header: str) -> dict[str, set[str]]:
    fields: dict[str, set[str]] = {}
    for name in _param_names(header):
        for field, pattern in _FIELD_NAME_PATTERNS.items():
            if pattern.search(name):
                fields.setdefault(field, set()).add(name)
    return fields


def _packed_hash_args(body: str) -> list[str]:
    out: list[str] = []
    for match in _PACKED_HASH_ASSIGN_RE.finditer(body):
        name = match.group("name") or ""
        if _DIGEST_VAR_RE.search(name):
            out.append(match.group("args"))
    out.extend(match.group("args") for match in _DIRECT_PACKED_RECOVER_RE.finditer(body))
    return out


def _contains_word(args: str, name: str) -> bool:
    return bool(re.search(rf"\b{re.escape(name)}\b", args))


def _is_field_bound(field: str, names: set[str], args: str) -> bool:
    if any(_contains_word(args, name) for name in names):
        return True
    if field == "chain id":
        return bool(re.search(r"(?is)\bblock\s*\.\s*chainid\b|\bchainId\b|\bchainid\b", args))
    if field == "contract address":
        return bool(
            re.search(
                r"(?is)\baddress\s*\(\s*this\s*\)|\bDOMAIN_SEPARATOR\b|\bdomainSeparator\b",
                args,
            )
        )
    return False


def _missing_fields(fields: dict[str, set[str]], args: str) -> list[str]:
    expected: dict[str, set[str]] = {field: set() for field in _REQUIRED_BASE_FIELDS}
    expected.update(fields)

    missing: list[str] = []
    for field, names in expected.items():
        if not _is_field_bound(field, names, args):
            missing.append(field)
    return missing


def _admin_hash_domain_gap(header: str, body: str) -> list[str]:
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

    fields = _domain_params(header)
    if len(fields) < 2:
        return []

    for args in _packed_hash_args(body):
        missing = _missing_fields(fields, args)
        if missing:
            return missing
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
            "abi.encodePacked signed admin authorization digest omits "
            f"domain field(s): {omitted}. A captured admin signature can be "
            "replayed across another chain, contract, nonce, selector, target, "
            "or role context. NOT_SUBMIT_READY: detector fixture smoke evidence only."
        ),
    )


def scan(source: str, file_path: str = "<memory>") -> list[Finding]:
    code = _strip_comments_and_strings(source)
    findings: list[Finding] = []
    for name, header, body, line in _split_functions(code):
        missing = _admin_hash_domain_gap(header, body)
        if missing:
            findings.append(_finding(file_path, line, name, missing))
    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
