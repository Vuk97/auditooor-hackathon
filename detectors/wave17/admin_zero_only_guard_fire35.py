"""
admin-zero-only-guard-fire35

Solidity recall-lift detector for privileged configuration setters that
perform only weak input validation, such as a zero-address check, array length
check, or numeric bounds check, while missing an effective owner, role,
governance, factory, timelock, or equivalent authorization guard.

This is not a broad "public setter" detector. It requires:
1. public or external mutating function;
2. setter-like privileged configuration, oracle, router, adapter, market, or
   fee-recipient write;
3. weak input validation evidence;
4. no effective authorization guard.

Provenance:
- context_pack_id: auditooor.vault_context_pack.v1:resume:5a29d91bbce92794
- context_pack_hash: 5a29d91bbce92794762a8ed09f2250a9242a49986ce3809863c10a012720379d
- source ref: reports/detector_lift_fire34_20260605/post_priorities_all.md
- source ref: reference/patterns.dsl/admin-bypass-wrong-domain-or-missing-guard.yaml
- source ref: detectors/wave17/admin_external_authority_fire34.py
- source ref: detectors/wave17/input_missing_zero_address_check.py
- attack_class: admin-bypass

Hits are candidate evidence only. NOT_SUBMIT_READY.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "admin-zero-only-guard-fire35"
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


_COMMENT_OR_STRING_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'|"
    r"//[^\n\r]*|"
    r"/\*.*?\*/",
    re.DOTALL,
)
_FN_HEADER_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_PUBLIC_HEADER_RE = re.compile(r"\b(?:external|public)\b", re.IGNORECASE)
_VIEW_HEADER_RE = re.compile(r"\b(?:view|pure)\b", re.IGNORECASE)
_SENDER_RE = r"(?:msg\s*\.\s*sender|_msgSender\s*\(\s*\))"
_SENDER_SEARCH_RE = re.compile(_SENDER_RE, re.IGNORECASE)
_SETTER_NAME_RE = re.compile(
    r"(?i)^(?:set|update|change|configure|register|add|remove|enable|disable)"
    r"(?:[A-Z_].*)?$"
)
_PRIVILEGED_WORD_RE = re.compile(
    r"(?i)(oracle|router|adapter|market|feeRecipient|feeReceiver|"
    r"protocolFeeRecipient|feeCollector|feeSink|config|configuration|registry|"
    r"gateway|controller|manager|operator|factory|keeper|guardian|pauser|"
    r"implementation|proxy|admin|governance|governor|treasury|risk|reserve)"
)
_PRIVILEGED_WRITE_RE = re.compile(
    r"(?is)\b(?P<lhs>[A-Za-z_][A-Za-z0-9_]*"
    r"(?:\s*\[[^;=]+\])*"
    r"(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*)?)\s*"
    r"(?:=|\+=|-=|\*=|/=)\s*"
)
_ZERO_ADDRESS_CHECK_RE = re.compile(
    r"(?is)(?:"
    r"\b(?:require|assert)\s*\([^;{}]*(?:"
    r"!=\s*address\s*\(\s*0x?0*\s*\)|"
    r"address\s*\(\s*0x?0*\s*\)\s*!="
    r")[^;{}]*\)|"
    r"\bif\s*\([^;{}]*(?:"
    r"==\s*address\s*\(\s*0x?0*\s*\)|"
    r"address\s*\(\s*0x?0*\s*\)\s*=="
    r")[^;{}]*\)\s*(?:revert|throw)|"
    r"\b(?:ZeroAddress|AddressZero|InvalidAddress)\s*\("
    r")"
)
_LENGTH_CHECK_RE = re.compile(
    r"(?is)\b(?:require|assert|if)\s*\([^;{}]*"
    r"\.length\s*(?:==|!=|<=|>=|<|>)\s*[^;{}]*\)"
)
_BOUNDS_WORD_RE = (
    r"(?:fee|fees|bps|rate|limit|limits|max|min|threshold|cap|slippage|delay|"
    r"duration|ratio|spread|weight|bound|amount|size|count)"
)
_BOUNDS_CHECK_RE = re.compile(
    rf"(?is)\b(?:require|assert|if)\s*\([^;{{}}]*"
    rf"\b[A-Za-z_][A-Za-z0-9_]*{_BOUNDS_WORD_RE}[A-Za-z0-9_]*\b"
    rf"\s*(?:<=|<|>=|>|!=|==)\s*[^;{{}}]*\)"
)
_AUTH_MODIFIER_RE = re.compile(
    r"(?i)\bonly(?:Owner|Admin|Role|Roles|Governance|Governor|Gov|DAO|Dao|"
    r"Timelock|Factory|Controller|Manager|Operator|Guardian|Keeper|Pauser|"
    r"Executor|Validator|Authorized|Authority|AccessManager|AccessControl)"
    r"[A-Za-z0-9_]*\b|"
    r"\b(?:requiresAuth|requireAuth|auth|restricted|onlyAuthorized)\b"
)
_AUTH_BODY_RE = re.compile(
    rf"(?is)(?:"
    rf"\b(?:_checkOwner|_onlyOwner|_checkRole|_checkRoles|_requireAuth|"
    rf"enforceIsOwner|enforceIsGovernance|enforceIsContractOwner)\s*\(|"
    rf"\b(?:hasRole|isAdmin|isOwner|isAuthorized|authorized|canCall|"
    rf"isAllowed|isTrusted|isFactory|isGovernor|isTimelock)\s*\([^;{{}}]*"
    rf"{_SENDER_RE}[^;{{}}]*\)|"
    rf"\b(?:require|assert)\s*\([^;{{}}]*(?:"
    rf"{_SENDER_RE}[^;{{}}]*(?:owner|_owner|admin|_admin|governance|"
    rf"governor|gov|dao|timelock|factory|controller|manager|operator|"
    rf"guardian|keeper|pauser|executor|validator|role|authority|access)|"
    rf"(?:owner|_owner|admin|_admin|governance|governor|gov|dao|timelock|"
    rf"factory|controller|manager|operator|guardian|keeper|pauser|executor|"
    rf"validator|role|authority|access)[^;{{}}]*{_SENDER_RE}|"
    rf"(?:authorized|allowed|approved|trusted|permission|permissions|"
    rf"operators|admins|roles|factories)\s*\[[^\]]*{_SENDER_RE}[^\]]*\]"
    rf")[^;{{}}]*\)"
    rf")"
)
_INITIALIZER_HEADER_RE = re.compile(r"(?i)\b(?:initializer|reinitializer)\b")
_TEST_SOURCE_RE = re.compile(r"(?i)\b(?:mock|fixture|example|demo)\b")


def _strip_comments_and_strings(source: str) -> str:
    def replace(match: re.Match[str]) -> str:
        text = match.group(0)
        return "\n" * text.count("\n") if "\n" in text else " "

    return _COMMENT_OR_STRING_RE.sub(replace, source or "")


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


def _has_effective_authorization(fn: FunctionSlice) -> bool:
    text = f"{fn.header}\n{fn.body}"
    return bool(_AUTH_MODIFIER_RE.search(fn.header) or _AUTH_BODY_RE.search(text))


def _weak_validation_reasons(fn: FunctionSlice) -> list[str]:
    reasons: list[str] = []
    if _ZERO_ADDRESS_CHECK_RE.search(fn.body):
        reasons.append("zero-address validation")
    if _LENGTH_CHECK_RE.search(fn.body):
        reasons.append("array length validation")
    if _BOUNDS_CHECK_RE.search(fn.body):
        reasons.append("numeric bounds validation")
    return reasons


def _privileged_writes(fn: FunctionSlice) -> list[str]:
    writes: list[str] = []
    for match in _PRIVILEGED_WRITE_RE.finditer(fn.body):
        lhs = re.sub(r"\s+", "", match.group("lhs"))
        if _PRIVILEGED_WORD_RE.search(lhs):
            writes.append(lhs)
    return sorted(set(writes))


def _is_setter_like(fn: FunctionSlice, writes: list[str]) -> bool:
    if _SETTER_NAME_RE.search(fn.name) and _PRIVILEGED_WORD_RE.search(fn.name):
        return True
    if _SETTER_NAME_RE.search(fn.name) and writes:
        return True
    return False


def _zero_only_guard_gap(fn: FunctionSlice) -> tuple[list[str], list[str]]:
    if not _is_external_mutator(fn):
        return [], []
    if _INITIALIZER_HEADER_RE.search(fn.header):
        return [], []
    if _has_effective_authorization(fn):
        return [], []

    writes = _privileged_writes(fn)
    if not writes:
        return [], []
    if not _is_setter_like(fn, writes):
        return [], []

    reasons = _weak_validation_reasons(fn)
    if not reasons:
        return [], []
    return reasons, writes


def _finding(
    file_path: str,
    line: int,
    function: str,
    weak_checks: list[str],
    writes: list[str],
) -> Finding:
    return Finding(
        detector=DETECTOR_NAME,
        file=file_path,
        line=line,
        severity=DETECTOR_SEVERITY_DEFAULT,
        function=function,
        message=(
            "privileged setter performs only weak input validation without an "
            f"effective owner, role, governance, factory, or timelock guard "
            f"({', '.join(weak_checks)}; writes {', '.join(writes)}). "
            "Zero-address, length, and bounds checks do not authorize "
            "configuration, oracle, router, adapter, market, or fee-recipient "
            "changes. NOT_SUBMIT_READY: detector fixture smoke evidence only."
        ),
    )


def scan(source: str, file_path: str = "<memory>") -> list[Finding]:
    if _TEST_SOURCE_RE.search(file_path):
        return []
    code = _strip_comments_and_strings(source)
    findings: list[Finding] = []
    for fn in _split_functions(code):
        weak_checks, writes = _zero_only_guard_gap(fn)
        if weak_checks:
            findings.append(_finding(file_path, fn.line, fn.name, weak_checks, writes))
    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
