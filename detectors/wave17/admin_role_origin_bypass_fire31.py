"""
admin-role-origin-bypass-fire31

Solidity recall-lift detector for privileged setters, role grants, sweep
paths, and emergency configuration mutations that authorize from tx.origin
or from caller-supplied owner, admin, governance, role, or operator fields
instead of a real sender-bound owner, admin, governance, or role guard.

Provenance:
- context_pack_id: auditooor.vault_context_pack.v1:resume:c01d420fe4a1c24a
- context_pack_hash: c01d420fe4a1c24a974c8890b2d40ca3881d87e848d83dc294a1ee396a5753c8
- source ref: reports/detector_lift_fire30_20260605/post_priorities_all.md
- source ref: detectors/wave17/operator_management_missing_access_control_fire29.py
- source ref: reference/patterns.dsl/role_grant_divergence.yaml
- attack_class: admin-bypass

Hits are candidate evidence only. NOT_SUBMIT_READY.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "admin-role-origin-bypass-fire31"
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
_PARAM_RE = re.compile(
    r"(?is)(?:^|,)\s*"
    r"(?:"
    r"(?:[A-Za-z_][A-Za-z0-9_]*\s*\.\s*)?[A-Za-z_][A-Za-z0-9_]*|"
    r"address|bytes(?:[0-9]+)?|uint(?:[0-9]+)?|int(?:[0-9]+)?|bool|string"
    r")"
    r"(?:\s*\[\s*\])?\s+"
    r"(?:(?:calldata|memory|storage)\s+)?"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
)
_SENDER_RE = r"(?:msg\s*\.\s*sender|_msgSender\s*\(\s*\))"
_SENDER_SEARCH_RE = re.compile(_SENDER_RE, re.IGNORECASE)
_TX_ORIGIN_AUTH_RE = re.compile(
    r"(?is)(?:"
    r"\b(?:require|assert)\s*\([^;{}]*\btx\s*\.\s*origin\b[^;{}]*\)|"
    r"\bif\s*\([^;{}]*\btx\s*\.\s*origin\b[^;{}]*\)"
    r"\s*(?:\{[^{}]*(?:revert|throw|return)|(?:revert|throw|return))|"
    r"\bonly[A-Za-z0-9_]*Origin[A-Za-z0-9_]*\b|"
    r"\bonly[A-Za-z0-9_]*TxOrigin[A-Za-z0-9_]*\b"
    r")"
)
_FIXED_HEADER_GUARD_RE = re.compile(
    r"(?is)\b(?:"
    r"onlyOwner|onlyAdmin|onlyGovernance|onlyGovernor|onlyGov|onlyDAO|"
    r"onlyDao|onlyTimelock|onlyController|onlyManager|onlyOperator|"
    r"onlyGuardian|onlyExecutor|onlyRelayer|onlySigner|onlyKeeper|"
    r"onlyValidator|requiresAuth|requireAuth|restricted|auth"
    r")\b(?!\s*\()"
)
_ROLE_HEADER_GUARD_RE = re.compile(
    r"(?is)\b(?:onlyRole|onlyRoles|hasRole|hasAnyRole)\s*\((?P<args>[^)]*)\)"
)
_BODY_ROLE_GUARD_RE = re.compile(
    r"(?is)\b(?:hasRole|_checkRole)\s*\([^;{}]*(?:msg\s*\.\s*sender|_msgSender\s*\(\s*\))"
)
_BODY_OWNER_GUARD_RE = re.compile(r"(?is)\b(?:_checkOwner|_onlyOwner)\s*\(\s*\)")
_MAPPING_SENDER_GUARD_RE = re.compile(
    r"(?is)\b(?:admins|isAdmin|operators|isOperator|guardians|isGuardian|"
    r"managers|isManager|controllers|isController|governors|isGovernor|"
    r"executors|isExecutor|relayers|isRelayer|signers|isSigner|keepers|"
    r"isKeeper|validators|isValidator|authorized|isAuthorized|trusted|"
    r"isTrusted)\s*\[\s*(?:msg\s*\.\s*sender|_msgSender\s*\(\s*\))\s*\]"
)
_AUTHORITY_STATE_RE = re.compile(
    r"(?is)^(?:"
    r"address\s*\(\s*)?"
    r"(?:owner|_owner|owner\s*\(\s*\)|admin|_admin|admin\s*\(\s*\)|"
    r"governance|governor|gov|dao|timelock|controller|manager|operator|"
    r"guardian|executor|relayer|signer|keeper|validator|authority|"
    r"authorized|roleAdmin)"
    r"(?:\s*\))?$"
)
_AUTHORITY_WORD_RE = re.compile(
    r"(?i)(owner|admin|govern|gov|dao|role|authority|controller|manager|"
    r"operator|guardian|executor|relayer|signer|keeper|validator|pauser|timelock)"
)
_PARAM_MEMBER_AUTHORITY_RE = re.compile(
    r"(?i)^(owner|admin|governance|governor|gov|role|roleAdmin|authority|"
    r"controller|manager|operator|guardian|executor|relayer|signer|keeper|"
    r"validator|pauser|timelock)$"
)
_PRIVILEGED_NAME_RE = re.compile(
    r"(?i)(?:"
    r"set|update|configure|grant|revoke|sweep|rescue|recover|emergency|"
    r"pause|unpause|upgrade|withdraw|drain|rotate|add|remove|enable|disable"
    r").*(?:owner|admin|role|operator|guardian|treasury|oracle|router|"
    r"config|fee|limit|cap|param|emergency|implementation|executor|signer|"
    r"pauser|controller|manager|relayer|keeper|validator)"
)
_PRIVILEGED_ASSIGN_RE = re.compile(
    r"(?is)\b(?:"
    r"owner|_owner|pendingOwner|admin|_admin|governance|governor|gov|dao|"
    r"timelock|controller|manager|operator|guardian|executor|relayer|"
    r"signer|keeper|validator|pauser|authority|treasury|feeRecipient|feeTo|"
    r"oracle|priceOracle|router|bridge|endpoint|implementation|config|"
    r"emergency[A-Za-z0-9_]*|paused|isPaused|halted|frozen|disabled|"
    r"limit|cap|max[A-Za-z0-9_]*|min[A-Za-z0-9_]*|protocolFee|feeBps|"
    r"roleAdmin"
    r")(?:\s*\[[^\]]+\])?\s*(?:=|\+=|-=|\*=|/=|\+\+|--)"
)
_PRIVILEGED_MAPPING_WRITE_RE = re.compile(
    r"(?is)\b(?:"
    r"roles|roleMembers|admins|isAdmin|operators|isOperator|guardians|"
    r"isGuardian|managers|isManager|controllers|isController|executors|"
    r"isExecutor|relayers|isRelayer|signers|isSigner|keepers|isKeeper|"
    r"validators|isValidator|pausers|isPauser|authorized|isAuthorized|"
    r"trusted|isTrusted|whitelist|blacklist|allowlist|blocklist"
    r")\s*\[[^\]]+\]\s*="
)
_ROLE_MANAGEMENT_CALL_RE = re.compile(
    r"(?is)\b(?:_grantRole|grantRole|_setupRole|setupRole|_revokeRole|"
    r"revokeRole|_setRoleAdmin|setRoleAdmin)\s*\("
)
_SWEEP_EFFECT_RE = re.compile(
    r"(?is)(?:"
    r"\b(?:safeTransfer|transfer|sendValue|send)\s*\([^;{}]*(?:balanceOf\s*\("
    r"\s*address\s*\(\s*this\s*\)|address\s*\(\s*this\s*\)\s*\.\s*balance|"
    r"\bthis\s*\.\s*balance)|"
    r"\.call\s*\{\s*value\s*:\s*(?:address\s*\(\s*this\s*\)\s*\.\s*balance|"
    r"\bthis\s*\.\s*balance)"
    r")"
)


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


def _authority_param_terms(header: str) -> list[str]:
    names = sorted(_param_names(header), key=len, reverse=True)
    terms: list[str] = []
    for name in names:
        if _AUTHORITY_WORD_RE.search(name):
            terms.append(re.escape(name))
        for member in (
            "owner",
            "admin",
            "governance",
            "governor",
            "gov",
            "role",
            "roleAdmin",
            "authority",
            "controller",
            "manager",
            "operator",
            "guardian",
            "executor",
            "relayer",
            "signer",
            "keeper",
            "validator",
            "pauser",
            "timelock",
        ):
            if _PARAM_MEMBER_AUTHORITY_RE.search(member):
                terms.append(rf"{re.escape(name)}\s*\.\s*{member}")
    return terms


def _contains_authority_param(text: str, terms: list[str]) -> bool:
    return any(re.search(rf"\b{term}\b", text) for term in terms)


def _expr_is_authority_param(expr: str, terms: list[str]) -> bool:
    cleaned = re.sub(r"\s+", "", expr)
    for term in terms:
        term_clean = re.sub(r"\\s\*|\\\.", ".", term).replace("\\", "")
        if cleaned == term_clean:
            return True
    return False


def _primary_condition_arg(expr: str) -> str:
    return expr.split(",", 1)[0].strip()


def _require_sender_equals_param(text: str, terms: list[str]) -> bool:
    for term in terms:
        term_re = rf"\b{term}\b"
        if re.search(
            rf"(?is)\b(?:require|assert)\s*\([^;{{}}]*(?:"
            rf"{_SENDER_RE}\s*==\s*{term_re}|{term_re}\s*==\s*{_SENDER_RE})"
            rf"[^;{{}}]*\)",
            text,
        ):
            return True
        if re.search(
            rf"(?is)\bif\s*\([^;{{}}]*(?:"
            rf"{_SENDER_RE}\s*!=\s*{term_re}|{term_re}\s*!=\s*{_SENDER_RE})"
            rf"[^;{{}}]*\)\s*(?:\{{[^{{}}]*(?:revert|throw|return)|"
            rf"(?:revert|throw|return))",
            text,
        ):
            return True
    return False


def _require_param_equals_state_authority(text: str, terms: list[str]) -> bool:
    for term in terms:
        term_re = rf"\b{term}\b"
        require_re = re.compile(
            rf"(?is)\b(?:require|assert)\s*\((?P<expr>[^;{{}}]*)\)"
        )
        for match in require_re.finditer(text):
            expr = _primary_condition_arg(match.group("expr"))
            if "==" not in expr:
                continue
            left, right = [part.strip() for part in expr.split("==", 1)]
            if re.search(term_re, left) and _AUTHORITY_STATE_RE.search(right):
                return True
            if re.search(term_re, right) and _AUTHORITY_STATE_RE.search(left):
                return True
    return False


def _role_checks_caller_supplied_authority(text: str, terms: list[str]) -> bool:
    for match in re.finditer(r"(?is)\b(?:hasRole|_checkRole)\s*\((?P<args>[^;{}]+)\)", text):
        args = match.group("args")
        if _SENDER_SEARCH_RE.search(args):
            continue
        if _contains_authority_param(args, terms):
            return True
    return False


def _modifier_checks_caller_supplied_authority(header: str, terms: list[str]) -> bool:
    for match in re.finditer(
        r"(?is)\b(?:onlyOwner|onlyAdmin|onlyRole|onlyRoles|onlyGovernance|"
        r"onlyGovernor|onlyOperator|onlyGuardian|onlyManager|onlyController|"
        r"onlyExecutor|onlyPauser|onlyRoleAdmin|auth|requiresAuth)\s*"
        r"\((?P<args>[^)]*)\)",
        header,
    ):
        if _contains_authority_param(match.group("args"), terms):
            return True
    return False


def _bad_auth_reasons(fn: FunctionSlice) -> list[str]:
    text = f"{fn.header}\n{fn.body}"
    terms = _authority_param_terms(fn.header)
    reasons: list[str] = []
    if _TX_ORIGIN_AUTH_RE.search(text):
        reasons.append("tx.origin authorization")
    if terms and _require_sender_equals_param(text, terms):
        reasons.append("msg.sender compared to caller-supplied authority")
    if terms and _require_param_equals_state_authority(text, terms):
        reasons.append("caller-supplied authority compared to authority state")
    if terms and _role_checks_caller_supplied_authority(text, terms):
        reasons.append("role check applied to caller-supplied authority")
    if terms and _modifier_checks_caller_supplied_authority(fn.header, terms):
        reasons.append("modifier receives caller-supplied authority")
    return reasons


def _has_real_header_guard(header: str, terms: list[str]) -> bool:
    if _FIXED_HEADER_GUARD_RE.search(header):
        return True
    for match in _ROLE_HEADER_GUARD_RE.finditer(header):
        args = match.group("args")
        if _contains_authority_param(args, terms):
            continue
        if re.search(r"\b[A-Z0-9_]*ROLE\b|\bDEFAULT_ADMIN_ROLE\b", args):
            return True
    return False


def _has_real_sender_equality_guard(body: str, terms: list[str]) -> bool:
    for match in re.finditer(r"(?is)\b(?:require|assert)\s*\((?P<expr>[^;{}]*)\)", body):
        expr = _primary_condition_arg(match.group("expr"))
        if "==" not in expr or not _SENDER_SEARCH_RE.search(expr):
            continue
        left, right = [part.strip() for part in expr.split("==", 1)]
        other = right if _SENDER_SEARCH_RE.search(left) else left
        if _expr_is_authority_param(other, terms):
            continue
        if _AUTHORITY_STATE_RE.search(other):
            return True
    for match in re.finditer(r"(?is)\bif\s*\((?P<expr>[^;{}]*)\)\s*(?:\{[^{}]*(?:revert|throw|return)|(?:revert|throw|return))", body):
        expr = match.group("expr")
        if "!=" not in expr or not _SENDER_SEARCH_RE.search(expr):
            continue
        left, right = [part.strip() for part in expr.split("!=", 1)]
        other = right if _SENDER_SEARCH_RE.search(left) else left
        if _expr_is_authority_param(other, terms):
            continue
        if _AUTHORITY_STATE_RE.search(other):
            return True
    return False


def _has_real_auth_guard(fn: FunctionSlice) -> bool:
    terms = _authority_param_terms(fn.header)
    text = f"{fn.header}\n{fn.body}"
    return (
        _has_real_header_guard(fn.header, terms)
        or bool(_BODY_ROLE_GUARD_RE.search(text))
        or bool(_BODY_OWNER_GUARD_RE.search(text))
        or bool(_MAPPING_SENDER_GUARD_RE.search(text))
        or _has_real_sender_equality_guard(fn.body, terms)
    )


def _is_external_mutator(fn: FunctionSlice) -> bool:
    return bool(_PUBLIC_HEADER_RE.search(fn.header)) and not _VIEW_HEADER_RE.search(fn.header)


def _has_privileged_effect(fn: FunctionSlice) -> bool:
    text = f"{fn.name}\n{fn.body}"
    if _ROLE_MANAGEMENT_CALL_RE.search(fn.body):
        return True
    if _PRIVILEGED_MAPPING_WRITE_RE.search(fn.body):
        return True
    if _PRIVILEGED_ASSIGN_RE.search(fn.body):
        return True
    if _SWEEP_EFFECT_RE.search(fn.body):
        return True
    if _PRIVILEGED_NAME_RE.search(fn.name) and re.search(r"(?is)(?:=|transfer\s*\(|safeTransfer\s*\(|\.call\s*\{)", fn.body):
        return True
    return bool(_PRIVILEGED_NAME_RE.search(text) and _ROLE_MANAGEMENT_CALL_RE.search(text))


def _admin_role_origin_bypass(fn: FunctionSlice) -> list[str]:
    if not _is_external_mutator(fn):
        return []
    if not _has_privileged_effect(fn):
        return []
    reasons = _bad_auth_reasons(fn)
    if not reasons:
        return []
    if _has_real_auth_guard(fn):
        return []
    return reasons


def _finding(file_path: str, line: int, function: str, reasons: list[str]) -> Finding:
    reason_text = ", ".join(sorted(set(reasons)))
    return Finding(
        detector=DETECTOR_NAME,
        file=file_path,
        line=line,
        severity=DETECTOR_SEVERITY_DEFAULT,
        function=function,
        message=(
            "privileged admin or role mutation uses a non-sender-bound "
            f"authorization shape ({reason_text}) instead of a real owner, "
            "admin, governance, or role guard. NOT_SUBMIT_READY: detector "
            "fixture smoke evidence only."
        ),
    )


def scan(source: str, file_path: str = "<memory>") -> list[Finding]:
    code = _strip_comments_and_strings(source)
    findings: list[Finding] = []
    for fn in _split_functions(code):
        reasons = _admin_role_origin_bypass(fn)
        if reasons:
            findings.append(_finding(file_path, fn.line, fn.name, reasons))
    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
