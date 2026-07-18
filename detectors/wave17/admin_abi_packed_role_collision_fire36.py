"""
admin-abi-packed-role-collision-fire36

Solidity recall-lift detector for privileged role or signature gates that
authorize an admin operation from a collision-prone abi.encodePacked transcript
while omitting role id, target, chain id, nonce, or dynamic-type boundaries.

This is not a broad abi.encodePacked detector. It requires:
1. public or external mutating function;
2. a keccak256(abi.encodePacked(...)) transcript used near role or signature
   authorization;
3. privileged execution, role mutation, upgrade, or config mutation sink;
4. missing transcript binding or dynamic boundary evidence.

Provenance:
- context_pack_id: auditooor.vault_context_pack.v1:resume:a14a00fe6ae82f40
- context_pack_hash: a14a00fe6ae82f4042f8fce336676e437af06060e1f44425bad63447335cb2d7
- source ref: reports/detector_lift_fire35_20260605/post_priorities_all.md
- source ref: reference/patterns.dsl/admin-bypass-umbrella.yaml
- source ref: reference/patterns.dsl/admin-bypass-wrong-domain-or-missing-guard.yaml
- source ref: reference/patterns.dsl/abi-encode-packed-hash-collision.yaml
- source ref: detectors/wave17/admin_external_authority_fire34.py
- source ref: detectors/wave17/admin_zero_only_guard_fire35.py
- attack_class: admin-bypass

Hits are candidate evidence only. NOT_SUBMIT_READY.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "admin-abi-packed-role-collision-fire36"
DETECTOR_SEVERITY_DEFAULT = "High"


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


_COMMENT_RE = re.compile(r"//[^\n\r]*|/\*.*?\*/", re.DOTALL)
_FN_HEADER_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_PUBLIC_HEADER_RE = re.compile(r"\b(?:external|public)\b", re.IGNORECASE)
_VIEW_HEADER_RE = re.compile(r"\b(?:view|pure)\b", re.IGNORECASE)
_PARAM_RE = re.compile(
    r"(?is)(?:^|,)\s*"
    r"(?P<type>"
    r"(?:[A-Za-z_][A-Za-z0-9_]*\s*\.\s*)?[A-Za-z_][A-Za-z0-9_]*|"
    r"address|bytes(?:[0-9]+)?|uint(?:[0-9]+)?|int(?:[0-9]+)?|bool|string"
    r")"
    r"(?P<array>(?:\s*\[[^\]]*\])*)\s+"
    r"(?:(?:calldata|memory|storage)\s+)?"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
)
_STRONG_AUTH_HEADER_RE = re.compile(
    r"(?i)\bonly(?:Owner|Admin|Governance|Governor|Gov|DAO|Dao|Timelock|"
    r"Controller|Manager|Operator|Guardian|Pauser|Executor|Validator|"
    r"Factory|Authorized|Authority|AccessManager|AccessControl)"
    r"[A-Za-z0-9_]*\b|"
    r"\b(?:requiresAuth|requireAuth|restricted|onlyAuthorized)\b"
)
_STRONG_AUTH_BODY_RE = re.compile(
    r"(?is)(?:"
    r"\b(?:_checkOwner|_onlyOwner|enforceIsOwner|enforceIsGovernance|"
    r"enforceIsContractOwner)\s*\(|"
    r"\b(?:require|assert)\s*\([^;{}]*(?:"
    r"(?:msg\s*\.\s*sender|_msgSender\s*\(\s*\))[^;{}]*(?:owner|_owner|admin|"
    r"_admin|governance|governor|gov|dao|timelock)|"
    r"(?:owner|_owner|admin|_admin|governance|governor|gov|dao|timelock)"
    r"[^;{}]*(?:msg\s*\.\s*sender|_msgSender\s*\(\s*\))"
    r")[^;{}]*\)"
    r")"
)
_ROLE_OR_SIGNATURE_AUTH_RE = re.compile(
    r"(?is)\b(?:hasRole|_checkRole|checkRole|roles?\s*\[|permissions?\s*\[|"
    r"ecrecover|ECDSA\s*\.\s*recover|\.recover\s*\(|SignatureChecker|"
    r"isValidSignature|isValidSignatureNow)\b"
)
_PRIVILEGED_SINK_RE = re.compile(
    r"(?is)(?:"
    r"\b(?:_grantRole|grantRole|_revokeRole|revokeRole|_setRoleAdmin|"
    r"upgradeTo|upgradeToAndCall|authorizeUpgrade|diamondCut|executeAdmin|"
    r"adminCall|privilegedCall|executePrivileged|_executePrivileged|"
    r"_executeAdmin|setAdmin|setOwner|transferOwnership)\s*\(|"
    r"\.\s*(?:call|delegatecall)\s*\(|"
    r"\b(?:owner|_owner|admin|_admin|governance|governor|timelock|operator|"
    r"manager|controller|guardian|pauser|router|routers|adapter|adapters|"
    r"oracle|oracles|implementation|registry|config|configs|feeRecipient|treasury|roles|role|permissions|"
    r"whitelist|blacklist|paused|frozen)\s*(?:\[[^;\n]+\])?"
    r"(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*)?\s*="
    r")"
)
_PACKED_HASH_RE = re.compile(r"keccak256\s*\(\s*abi\.encodePacked\s*\(", re.IGNORECASE)
_ENCODE_PACKED_RE = re.compile(r"abi\.encodePacked\s*\(", re.IGNORECASE)
_TYPED_SAFE_RE = re.compile(
    r"(?is)\b(?:_hashTypedDataV4|toTypedDataHash|hashTypedData|EIP712|"
    r"TYPEHASH|TYPE_HASH|DOMAIN_SEPARATOR|_domainSeparatorV4)\b"
)
_ROLE_BINDING_RE = re.compile(
    r"(?is)\b(?:role|permission|capability|selector|functionSelector|"
    r"functionSig|operation|operationId|action|typehash|typeHash)\b|"
    r"\b[A-Z0-9_]*_ROLE\b"
)
_TARGET_BINDING_RE = re.compile(
    r"(?is)\b(?:target|to|callee|destination|recipient|account|user|"
    r"operator|contract|module|facet|implementation|adapter|router|route|"
    r"routeId|vault|pool|market|verifyingContract)\b|address\s*\(\s*this\s*\)"
)
_CHAIN_BINDING_RE = re.compile(
    r"(?is)\b(?:block\s*\.\s*chainid|chainid\s*\(\s*\)|chainId|chain_id|"
    r"domain|domainSeparator|DOMAIN_SEPARATOR|verifyingContract)\b"
)
_NONCE_BINDING_RE = re.compile(
    r"(?is)\b(?:nonce|nonces|salt|deadline|expiry|expires|expiration|"
    r"validUntil|used|consumed|nullifier|sequence|seq|replay)\b"
)
_DYNAMIC_NAME_HINT_RE = re.compile(
    r"(?i)\b(?:data|payload|message|messages|calldata|params|extraData|"
    r"callData|commands|actions|targets|values|signatures|proof|proofs)\b"
)
_HASHED_DYNAMIC_RE = re.compile(r"(?is)\bkeccak256\s*\(|\bsha256\s*\(")
_EXPLICIT_LENGTH_RE = re.compile(r"(?is)\.length\b|bytes\s*\([^)]*\)\s*\.length")
_EXAMPLE_SOURCE_RE = re.compile(r"(?i)\b(?:mock|example|demo)\b")


def _strip_comments(source: str) -> str:
    def replace(match: re.Match[str]) -> str:
        text = match.group(0)
        return "\n" * text.count("\n") if "\n" in text else " "

    return _COMMENT_RE.sub(replace, source or "")


def _extract_balanced_block(source: str, open_brace: int) -> tuple[Optional[str], int]:
    if open_brace < 0 or open_brace >= len(source) or source[open_brace] != "{":
        return None, open_brace
    depth = 1
    i = open_brace + 1
    while i < len(source) and depth > 0:
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
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

        body, end_pos = _extract_balanced_block(source, body_start)
        if body is None:
            pos = body_start + 1
            continue

        header = source[match.start():body_start]
        line = source.count("\n", 0, match.start()) + 1
        out.append(FunctionSlice(name=name, header=header, body=body, line=line))
        pos = end_pos
    return out


def _is_external_mutator(fn: FunctionSlice) -> bool:
    return bool(_PUBLIC_HEADER_RE.search(fn.header)) and not _VIEW_HEADER_RE.search(fn.header)


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


def _dynamic_params(header: str) -> set[str]:
    out: set[str] = set()
    for match in _PARAM_RE.finditer(_parameter_section(header)):
        typ = re.sub(r"\s+", "", match.group("type") or "").lower()
        array = match.group("array") or ""
        name = match.group("name")
        if typ == "string" or typ == "bytes" or array:
            out.add(name)
    return out


def _extract_parenthesized(source: str, open_paren: int) -> tuple[Optional[str], int]:
    if open_paren < 0 or open_paren >= len(source) or source[open_paren] != "(":
        return None, open_paren
    depth = 1
    i = open_paren + 1
    while i < len(source) and depth > 0:
        if source[i] == "(":
            depth += 1
        elif source[i] == ")":
            depth -= 1
        i += 1
    if depth != 0:
        return None, open_paren
    return source[open_paren + 1:i - 1], i


def _split_args(args: str) -> list[str]:
    out: list[str] = []
    start = 0
    depth = 0
    for i, char in enumerate(args):
        if char in "([{":
            depth += 1
        elif char in ")]}" and depth > 0:
            depth -= 1
        elif char == "," and depth == 0:
            out.append(args[start:i].strip())
            start = i + 1
    tail = args[start:].strip()
    if tail:
        out.append(tail)
    return out


def _packed_arg_sets(body: str) -> list[str]:
    out: list[str] = []
    for match in _ENCODE_PACKED_RE.finditer(body):
        open_paren = body.find("(", match.start())
        args, _end = _extract_parenthesized(body, open_paren)
        if args:
            out.append(args)
    return out


def _arg_is_dynamic(arg: str, dynamic_params: set[str]) -> bool:
    if _HASHED_DYNAMIC_RE.search(arg):
        return False
    if _EXPLICIT_LENGTH_RE.search(arg):
        return False
    if _DYNAMIC_NAME_HINT_RE.search(arg):
        return True
    for name in dynamic_params:
        if re.search(rf"\b{re.escape(name)}\b", arg):
            return True
    return False


def _dynamic_boundary_gap(args: str, dynamic_params: set[str]) -> bool:
    dynamic_count = sum(1 for arg in _split_args(args) if _arg_is_dynamic(arg, dynamic_params))
    return dynamic_count >= 2


def _missing_bindings(args: str, dynamic_params: set[str]) -> list[str]:
    missing: list[str] = []
    if not _ROLE_BINDING_RE.search(args):
        missing.append("role id or action discriminator")
    if not _TARGET_BINDING_RE.search(args):
        missing.append("target or account binding")
    if not _CHAIN_BINDING_RE.search(args):
        missing.append("chain id or domain binding")
    if not _NONCE_BINDING_RE.search(args):
        missing.append("nonce or replay guard")
    if _dynamic_boundary_gap(args, dynamic_params):
        missing.append("typed length boundaries for dynamic fields")
    return missing


def _has_strong_independent_auth(fn: FunctionSlice) -> bool:
    text = f"{fn.header}\n{fn.body}"
    return bool(_STRONG_AUTH_HEADER_RE.search(fn.header) or _STRONG_AUTH_BODY_RE.search(text))


def _role_collision_gap(fn: FunctionSlice) -> tuple[list[str], list[str]]:
    if not _is_external_mutator(fn):
        return [], []
    if _has_strong_independent_auth(fn):
        return [], []
    text = f"{fn.header}\n{fn.body}"
    if not _PACKED_HASH_RE.search(text):
        return [], []
    if not _ROLE_OR_SIGNATURE_AUTH_RE.search(text):
        return [], []
    if not _PRIVILEGED_SINK_RE.search(text):
        return [], []
    if _TYPED_SAFE_RE.search(text) and "abi.encodePacked" not in text:
        return [], []

    dynamic_params = _dynamic_params(fn.header)
    missing_union: list[str] = []
    transcript_summaries: list[str] = []
    for args in _packed_arg_sets(text):
        missing = _missing_bindings(args, dynamic_params)
        if not missing:
            continue
        if _TYPED_SAFE_RE.search(args) and "typed length boundaries for dynamic fields" not in missing:
            continue
        missing_union.extend(missing)
        compact = re.sub(r"\s+", " ", args).strip()
        if len(compact) > 120:
            compact = compact[:117] + "..."
        transcript_summaries.append(compact)

    return sorted(set(missing_union)), transcript_summaries


def _finding(
    file_path: str,
    line: int,
    function: str,
    missing: list[str],
    transcripts: list[str],
) -> Finding:
    return Finding(
        detector=DETECTOR_NAME,
        file=file_path,
        line=line,
        severity=DETECTOR_SEVERITY_DEFAULT,
        function=function,
        message=(
            "privileged role or signature gate derives authorization from "
            "keccak256(abi.encodePacked(...)) before an admin sink, but the "
            f"transcript omits {', '.join(missing)}. "
            f"Packed transcript(s): {' | '.join(transcripts)}. "
            "Bind role/action, target, chain/domain, and nonce, and use "
            "abi.encode or EIP-712 typed data for dynamic fields. "
            "NOT_SUBMIT_READY: detector fixture smoke evidence only."
        ),
    )


def scan(source: str, file_path: str = "<memory>") -> list[Finding]:
    if _EXAMPLE_SOURCE_RE.search(file_path):
        return []
    code = _strip_comments(source)
    findings: list[Finding] = []
    for fn in _split_functions(code):
        missing, transcripts = _role_collision_gap(fn)
        if missing:
            findings.append(_finding(file_path, fn.line, fn.name, missing, transcripts))
    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
