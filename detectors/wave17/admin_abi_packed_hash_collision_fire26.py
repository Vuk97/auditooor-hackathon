"""
admin-abi-packed-hash-collision-fire26

Solidity recall-lift detector for privileged signature authorization paths
where an admin digest uses keccak256(abi.encodePacked(...)) over two or more
caller-controlled dynamic or ambiguous fields, then performs a privileged
mutation without binding replay-critical domain fields.

Provenance:
- context_pack_id: auditooor.vault_context_pack.v1:resume:adfd418d3f6192da
- context_pack_hash: adfd418d3f6192daba631fcbdf76e5215584274de62029de0f3d710f7f613f3b
- same-class miss: abi-encode-packed-hash-collision
- parent class: admin-bypass
- Fire25 overlap: admin-hash-domain-missing-fire25

Hits are candidate evidence only. NOT_SUBMIT_READY.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "admin-abi-packed-hash-collision-fire26"
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
    r"(?P<type>"
    r"(?:[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?|"
    r"bytes(?:[0-9]+)?|uint(?:[0-9]+)?|int(?:[0-9]+)?|address|string|bool)"
    r"(?:\s*\[[^\]]*\])?"
    r")\s+"
    r"(?:(?:calldata|memory|storage)\s+)?"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
)
_PACKED_START_RE = re.compile(r"(?is)keccak256\s*\(\s*abi\s*\.\s*encodePacked\s*\(")
_PACKED_ASSIGN_PREFIX_RE = re.compile(
    r"(?is)(?:bytes32\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*$"
)
_DIGEST_VAR_RE = re.compile(
    r"(?i)(digest|authHash|adminHash|messageHash|actionHash|operationHash|"
    r"routeHash|permissionHash|upgradeHash|grantHash|roleHash)"
)
_SIGNATURE_AUTH_RE = re.compile(
    r"(?is)\b(?:ecrecover|ECDSA\s*\.\s*recover|SignatureChecker|"
    r"isValidSignature|isValidSignatureNow)\b"
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
    r"executor|router|oracle|treasury|feeRecipient|config|implementation|"
    r"upgradeTarget|pendingAdmin)\s*=\s*|"
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
        r"(?i)(target|targetContract|receiverContract|verifyingContract|"
        r"executorContract|upgradeTarget)$"
    ),
}
_AMBIGUOUS_NAME_RE = re.compile(
    r"(?i)(data|payload|calldata|callData|extraData|memo|metadata|uri|path|route|"
    r"message|reason|commands|params|description|adminPath|actionName)$"
)
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


def _param_types(header: str) -> dict[str, str]:
    return {
        match.group("name"): re.sub(r"\s+", "", match.group("type"))
        for match in _PARAM_RE.finditer(_parameter_section(header))
    }


def _is_dynamic_or_ambiguous(param_type: str, name: str) -> bool:
    clean_type = param_type.lower().replace(" ", "")
    return (
        clean_type == "string"
        or clean_type == "bytes"
        or "[" in clean_type
        or bool(_AMBIGUOUS_NAME_RE.search(name))
    )


def _find_matching_paren(text: str, open_index: int) -> int:
    depth = 1
    i = open_index + 1
    while i < len(text) and depth > 0:
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
        i += 1
    return i - 1 if depth == 0 else -1


def _packed_hash_sites(body: str) -> list[tuple[str, str, str]]:
    sites: list[tuple[str, str, str]] = []
    for match in _PACKED_START_RE.finditer(body):
        args_start = match.end()
        args_end = _find_matching_paren(body, args_start - 1)
        if args_end < 0:
            continue
        prefix = body[max(0, match.start() - 96):match.start()]
        suffix = body[args_end:min(len(body), args_end + 160)]
        sites.append((body[args_start:args_end], prefix, suffix))
    return sites


def _is_signature_digest_site(prefix: str, suffix: str) -> bool:
    assign = _PACKED_ASSIGN_PREFIX_RE.search(prefix)
    if assign and _DIGEST_VAR_RE.search(assign.group("name")):
        return True
    return bool(re.search(r"(?is)(recover|ecrecover|isValidSignature|signature|sig)", suffix))


def _split_top_level_args(args: str) -> list[str]:
    out: list[str] = []
    start = 0
    depth = 0
    for i, ch in enumerate(args):
        if ch == "(":
            depth += 1
        elif ch == ")" and depth > 0:
            depth -= 1
        elif ch == "," and depth == 0:
            out.append(args[start:i].strip())
            start = i + 1
    out.append(args[start:].strip())
    return [arg for arg in out if arg]


def _contains_word(text: str, name: str) -> bool:
    return bool(re.search(rf"\b{re.escape(name)}\b", text))


def _ambiguous_args_used(header: str, args: str) -> set[str]:
    params = _param_types(header)
    ambiguous = {
        name
        for name, param_type in params.items()
        if _is_dynamic_or_ambiguous(param_type, name)
    }
    used: set[str] = set()
    for arg in _split_top_level_args(args):
        if re.search(r"(?is)\bkeccak256\s*\(", arg):
            continue
        for name in ambiguous:
            if _contains_word(arg, name):
                used.add(name)
    return used


def _domain_params(header: str) -> dict[str, set[str]]:
    fields: dict[str, set[str]] = {}
    for name in _param_types(header):
        for field, pattern in _FIELD_NAME_PATTERNS.items():
            if pattern.search(name):
                fields.setdefault(field, set()).add(name)
    return fields


def _body_implies_binding_field(field: str, body: str) -> bool:
    if field == "nonce":
        return bool(re.search(r"(?is)\b(?:usedNonce|usedNonces|nonceUsed|nonces)\b", body))
    if field == "role":
        return bool(re.search(r"(?is)\b(?:grantRole|_grantRole|roles?\s*\[|ROLE)\b", body))
    if field == "selector":
        return bool(re.search(r"(?is)\b(?:selector|msg\.sig|\.selector)\b", body))
    if field == "target":
        return bool(
            re.search(
                r"(?is)\b(?:target|targetContract|executorContract|upgradeTarget)\b",
                body,
            )
        )
    return False


def _expected_bindings(header: str, body: str) -> dict[str, set[str]]:
    expected: dict[str, set[str]] = {field: set() for field in _REQUIRED_BASE_FIELDS}
    field_params = _domain_params(header)
    for field in ("nonce", "role", "selector", "target"):
        if field in field_params or _body_implies_binding_field(field, body):
            expected[field] = field_params.get(field, set())
    return expected


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
    if field == "selector":
        return bool(re.search(r"(?is)\bmsg\s*\.\s*sig\b|\.\s*selector\b|\bselector\b", args))
    if field == "role":
        return bool(re.search(r"(?is)\brole\b|\b[A-Z0-9_]*ROLE[A-Z0-9_]*\b", args))
    if field == "nonce":
        return bool(re.search(r"(?is)\bnonce\b", args))
    if field == "target":
        return bool(
            re.search(
                r"(?is)\btarget\b|\btargetContract\b|\bverifyingContract\b|"
                r"\bexecutorContract\b|\bupgradeTarget\b",
                args,
            )
        )
    return False


def _missing_bindings(header: str, body: str, args: str) -> list[str]:
    missing: list[str] = []
    for field, names in _expected_bindings(header, body).items():
        if not _is_field_bound(field, names, args):
            missing.append(field)
    return missing


def _collision_admin_gap(header: str, body: str) -> tuple[list[str], set[str]]:
    text = f"{header}\n{body}"
    if not _is_external_entry(header):
        return [], set()
    if _CALLER_AUTH_GUARD_RE.search(text):
        return [], set()
    if not _SIGNATURE_AUTH_RE.search(body):
        return [], set()
    if not _SIGNER_GATE_RE.search(body):
        return [], set()
    if not _PRIVILEGED_EFFECT_RE.search(body):
        return [], set()

    for args, prefix, suffix in _packed_hash_sites(body):
        if not _is_signature_digest_site(prefix, suffix):
            continue
        ambiguous_used = _ambiguous_args_used(header, args)
        if len(ambiguous_used) < 2:
            continue
        missing = _missing_bindings(header, body, args)
        if missing:
            return missing, ambiguous_used
    return [], set()


def _finding(
    file_path: str,
    line: int,
    function: str,
    missing: list[str],
    ambiguous_used: set[str],
) -> Finding:
    omitted = ", ".join(missing)
    ambiguous = ", ".join(sorted(ambiguous_used))
    return Finding(
        detector=DETECTOR_NAME,
        file=file_path,
        line=line,
        severity=DETECTOR_SEVERITY_DEFAULT,
        function=function,
        message=(
            "privileged signature digest hashes abi.encodePacked with multiple "
            f"ambiguous field(s): {ambiguous}; omitted binding field(s): {omitted}. "
            "A colliding packed preimage can authorize a different admin mutation "
            "context. NOT_SUBMIT_READY: detector fixture smoke evidence only."
        ),
    )


def scan(source: str, file_path: str = "<memory>") -> list[Finding]:
    code = _strip_comments_and_strings(source)
    findings: list[Finding] = []
    for name, header, body, line in _split_functions(code):
        missing, ambiguous_used = _collision_admin_gap(header, body)
        if missing:
            findings.append(_finding(file_path, line, name, missing, ambiguous_used))
    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
