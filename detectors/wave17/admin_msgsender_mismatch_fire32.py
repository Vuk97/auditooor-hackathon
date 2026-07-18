"""
admin-msgsender-mismatch-fire32

Solidity recall-lift detector for privileged setters, role grants, sweeps,
pause paths, and config writes that validate a caller-supplied user, signer,
owner, admin, or struct field while the caller receives or triggers the
privileged effect through msg.sender.

Provenance:
- context_pack_id: auditooor.vault_context_pack.v1:resume:0f026ac1001e9e9b
- context_pack_hash: 0f026ac1001e9e9b588d5fafc49e8d99e6f347f91a2aaa782107be04d27011d8
- source ref: reports/detector_lift_fire31_20260605/post_priorities_all.md
- source ref: detectors/wave17/admin_role_origin_bypass_fire31.py
- source ref: reference/patterns.dsl/role_grant_divergence.yaml
- source ref: reference/patterns.dsl/admin-malicious-contract-injection.yaml
- attack_class: admin-bypass

Hits are candidate evidence only. NOT_SUBMIT_READY.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "admin-msgsender-mismatch-fire32"
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


@dataclass(frozen=True)
class AuthorityTerm:
    display: str
    pattern: str


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
_AUTHORITY_WORD_RE = re.compile(
    r"(?i)(owner|admin|govern|gov|dao|role|authority|controller|manager|"
    r"operator|guardian|executor|relayer|signer|keeper|validator|pauser|"
    r"timelock|user|account|member)"
)
_AUTHORITY_FIELDS = (
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
    "user",
    "account",
    "member",
)
_AUTHORITY_STATE_RE = re.compile(
    r"(?is)^(?:"
    r"address\s*\(\s*)?"
    r"(?:owner|_owner|owner\s*\(\s*\)|admin|_admin|admin\s*\(\s*\)|"
    r"governance|governor|gov|dao|timelock|controller|manager|operator|"
    r"guardian|executor|relayer|signer|trustedSigner|keeper|validator|"
    r"pauser|authority|authorized|roleAdmin|defaultAdmin)"
    r"(?:\s*\))?$"
)
_FIXED_HEADER_GUARD_RE = re.compile(
    r"(?is)\b(?:"
    r"onlyOwner|onlyAdmin|onlyGovernance|onlyGovernor|onlyGov|onlyDAO|"
    r"onlyDao|onlyTimelock|onlyController|onlyManager|onlyOperator|"
    r"onlyGuardian|onlyExecutor|onlyRelayer|onlySigner|onlyKeeper|"
    r"onlyValidator|onlyPauser|onlyRoleAdmin|requiresAuth|requireAuth|"
    r"restricted|auth"
    r")\b(?!\s*\()"
)
_ROLE_HEADER_GUARD_RE = re.compile(
    r"(?is)\b(?:onlyRole|onlyRoles|hasRole|hasAnyRole)\s*\((?P<args>[^)]*)\)"
)
_BODY_ROLE_GUARD_RE = re.compile(
    rf"(?is)\b(?:hasRole|_checkRole)\s*\([^;{{}}]*{_SENDER_RE}"
)
_BODY_OWNER_GUARD_RE = re.compile(r"(?is)\b(?:_checkOwner|_onlyOwner)\s*\(\s*\)")
_MAPPING_SENDER_GUARD_RE = re.compile(
    rf"(?is)\b(?:require|assert)\s*\([^;{{}}]*"
    rf"\b(?:admins|isAdmin|operators|isOperator|guardians|isGuardian|"
    rf"managers|isManager|controllers|isController|governors|isGovernor|"
    rf"executors|isExecutor|relayers|isRelayer|signers|isSigner|keepers|"
    rf"isKeeper|validators|isValidator|pausers|isPauser|authorized|"
    rf"isAuthorized|trusted|isTrusted|roles)\s*\[[^\]]*{_SENDER_RE}[^\]]*\]"
    rf"[^;{{}}]*\)"
)
_ROLE_CHECK_RE = re.compile(
    r"(?is)\b(?:hasRole|_checkRole)\s*\((?P<args>[^;{}]+)\)"
)
_AUTH_MAPPING_NAME_RE = (
    r"owners|isOwner|admins|isAdmin|operators|isOperator|guardians|"
    r"isGuardian|managers|isManager|controllers|isController|governors|"
    r"isGovernor|executors|isExecutor|relayers|isRelayer|signers|isSigner|"
    r"trustedSigners|isTrustedSigner|keepers|isKeeper|validators|isValidator|"
    r"pausers|isPauser|authorized|isAuthorized|trusted|isTrusted|roles"
)
_MODIFIER_INPUT_AUTH_RE = re.compile(
    r"(?is)\b(?:onlyOwner|onlyAdmin|onlyRole|onlyRoles|onlyGovernance|"
    r"onlyGovernor|onlyOperator|onlyGuardian|onlyManager|onlyController|"
    r"onlyExecutor|onlyPauser|onlySigner|onlyRoleAdmin|auth|requiresAuth)"
    r"\s*\((?P<args>[^)]*)\)"
)
_ROLE_MSGSENDER_EFFECT_RE = re.compile(
    rf"(?is)\b(?:_grantRole|grantRole|_setupRole|setupRole)\s*"
    rf"\([^;{{}}]*{_SENDER_RE}"
)
_PRIVILEGED_MSGSENDER_MAPPING_WRITE_RE = re.compile(
    rf"(?is)\b(?:"
    rf"roles|roleMembers|admins|isAdmin|operators|isOperator|guardians|"
    rf"isGuardian|managers|isManager|controllers|isController|executors|"
    rf"isExecutor|relayers|isRelayer|signers|isSigner|keepers|isKeeper|"
    rf"validators|isValidator|pausers|isPauser|authorized|isAuthorized|"
    rf"trusted|isTrusted|whitelist|allowlist|config|configs|settings|"
    rf"limits|caps|quotas"
    rf")\s*\[[^\]]*{_SENDER_RE}[^\]]*\]"
    rf"(?:\s*\[[^\]]+\])?\s*="
)
_PRIVILEGED_MSGSENDER_SCALAR_ASSIGN_RE = re.compile(
    rf"(?is)\b(?:owner|_owner|admin|_admin|governance|governor|gov|dao|"
    rf"timelock|controller|manager|operator|guardian|executor|relayer|"
    rf"signer|keeper|validator|pauser|authority|treasury|feeRecipient|"
    rf"feeTo)\s*=\s*{_SENDER_RE}"
)
_ROLE_MANAGEMENT_CALL_RE = re.compile(
    r"(?is)\b(?:_grantRole|grantRole|_setupRole|setupRole|_revokeRole|"
    r"revokeRole|_setRoleAdmin|setRoleAdmin)\s*\("
)
_PRIVILEGED_ASSIGN_RE = re.compile(
    r"(?is)\b(?:"
    r"owner|_owner|pendingOwner|admin|_admin|governance|governor|gov|dao|"
    r"timelock|controller|manager|operator|guardian|executor|relayer|"
    r"signer|keeper|validator|pauser|authority|treasury|feeRecipient|feeTo|"
    r"oracle|priceOracle|router|bridge|endpoint|implementation|config|"
    r"settings|paused|isPaused|halted|frozen|disabled|limit|cap|"
    r"max[A-Za-z0-9_]*|min[A-Za-z0-9_]*|protocolFee|feeBps|roleAdmin"
    r")(?:\s*\[[^\]]+\])?\s*(?:=|\+=|-=|\*=|/=|\+\+|--)"
)
_PRIVILEGED_MAPPING_WRITE_RE = re.compile(
    r"(?is)\b(?:"
    r"roles|roleMembers|admins|isAdmin|operators|isOperator|guardians|"
    r"isGuardian|managers|isManager|controllers|isController|executors|"
    r"isExecutor|relayers|isRelayer|signers|isSigner|keepers|isKeeper|"
    r"validators|isValidator|pausers|isPauser|authorized|isAuthorized|"
    r"trusted|isTrusted|whitelist|blacklist|allowlist|blocklist|config|"
    r"configs|settings|limits|caps|quotas"
    r")\s*\[[^\]]+\]\s*="
)
_PRIVILEGED_NAME_RE = re.compile(
    r"(?i)(?:"
    r"set|update|configure|grant|revoke|sweep|rescue|recover|emergency|"
    r"pause|unpause|upgrade|withdraw|drain|rotate|add|remove|enable|disable"
    r").*(?:owner|admin|role|operator|guardian|treasury|oracle|router|"
    r"config|fee|limit|cap|param|emergency|implementation|executor|signer|"
    r"pauser|controller|manager|relayer|keeper|validator)"
)
_SWEEP_NAME_RE = re.compile(r"(?i)(sweep|rescue|recover|withdraw|drain)")
_SWEEP_TO_MSGSENDER_RE = re.compile(
    rf"(?is)(?:"
    rf"\b(?:safeTransfer|transfer|sendValue|send)\s*\(\s*{_SENDER_RE}\s*,|"
    rf"{_SENDER_RE}\s*\.\s*call\s*\{{\s*value\s*:"
    rf")"
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


def _param_names(header: str) -> list[str]:
    return [match.group("name") for match in _PARAM_RE.finditer(_parameter_section(header))]


def _authority_terms(header: str) -> list[AuthorityTerm]:
    out: list[AuthorityTerm] = []
    seen: set[str] = set()
    for name in sorted(set(_param_names(header)), key=len, reverse=True):
        if _AUTHORITY_WORD_RE.search(name):
            display = name
            if display not in seen:
                out.append(AuthorityTerm(display=display, pattern=rf"\b{re.escape(name)}\b"))
                seen.add(display)
        for field in _AUTHORITY_FIELDS:
            display = f"{name}.{field}"
            if display in seen:
                continue
            out.append(
                AuthorityTerm(
                    display=display,
                    pattern=rf"\b{re.escape(name)}\s*\.\s*{field}\b",
                )
            )
            seen.add(display)
    return out


def _contains_term(text: str, term: AuthorityTerm) -> bool:
    return bool(re.search(term.pattern, text))


def _contains_any_term(text: str, terms: list[AuthorityTerm]) -> bool:
    return any(_contains_term(text, term) for term in terms)


def _primary_condition_arg(expr: str) -> str:
    return expr.split(",", 1)[0].strip()


def _expr_side_is_authority_state(expr: str) -> bool:
    expr = re.sub(r"\s+", "", expr)
    return bool(_AUTHORITY_STATE_RE.search(expr))


def _input_checked_against_state_authority(text: str, terms: list[AuthorityTerm]) -> bool:
    require_re = re.compile(r"(?is)\b(?:require|assert)\s*\((?P<expr>[^;{}]*)\)")
    for match in require_re.finditer(text):
        expr = _primary_condition_arg(match.group("expr"))
        if "==" not in expr:
            continue
        left, right = [part.strip() for part in expr.split("==", 1)]
        for term in terms:
            if _contains_term(left, term) and _expr_side_is_authority_state(right):
                return True
            if _contains_term(right, term) and _expr_side_is_authority_state(left):
                return True
    return False


def _role_checks_input_authority(text: str, terms: list[AuthorityTerm]) -> bool:
    for match in _ROLE_CHECK_RE.finditer(text):
        args = match.group("args")
        if _SENDER_SEARCH_RE.search(args):
            continue
        if _contains_any_term(args, terms):
            return True
    return False


def _mapping_checks_input_authority(text: str, terms: list[AuthorityTerm]) -> bool:
    for term in terms:
        if re.search(
            rf"(?is)\b(?:{_AUTH_MAPPING_NAME_RE})\s*\[[^\]]*{term.pattern}[^\]]*\]",
            text,
        ):
            return True
        if re.search(
            rf"(?is)\broles\s*\[[^\]]+\]\s*\[[^\]]*{term.pattern}[^\]]*\]",
            text,
        ):
            return True
    return False


def _modifier_checks_input_authority(header: str, terms: list[AuthorityTerm]) -> bool:
    for match in _MODIFIER_INPUT_AUTH_RE.finditer(header):
        args = match.group("args")
        if _contains_any_term(args, terms):
            return True
    return False


def _mismatched_auth_reasons(fn: FunctionSlice) -> list[str]:
    terms = _authority_terms(fn.header)
    if not terms:
        return []
    text = f"{fn.header}\n{fn.body}"
    reasons: list[str] = []
    if _input_checked_against_state_authority(text, terms):
        reasons.append("caller-supplied authority compared to authority state")
    if _role_checks_input_authority(text, terms):
        reasons.append("role check applied to caller-supplied authority")
    if _mapping_checks_input_authority(text, terms):
        reasons.append("authority mapping checked for caller-supplied authority")
    if _modifier_checks_input_authority(fn.header, terms):
        reasons.append("modifier receives caller-supplied authority")
    return reasons


def _has_real_header_guard(header: str, terms: list[AuthorityTerm]) -> bool:
    if _FIXED_HEADER_GUARD_RE.search(header):
        return True
    for match in _ROLE_HEADER_GUARD_RE.finditer(header):
        args = match.group("args")
        if _contains_any_term(args, terms):
            continue
        if re.search(r"\b[A-Z0-9_]*ROLE\b|\bDEFAULT_ADMIN_ROLE\b", args):
            return True
    return False


def _has_real_sender_equality_guard(body: str) -> bool:
    for match in re.finditer(r"(?is)\b(?:require|assert)\s*\((?P<expr>[^;{}]*)\)", body):
        expr = _primary_condition_arg(match.group("expr"))
        if "==" not in expr or not _SENDER_SEARCH_RE.search(expr):
            continue
        left, right = [part.strip() for part in expr.split("==", 1)]
        other = right if _SENDER_SEARCH_RE.search(left) else left
        if _expr_side_is_authority_state(other):
            return True
    for match in re.finditer(
        r"(?is)\bif\s*\((?P<expr>[^;{}]*)\)\s*(?:\{[^{}]*(?:revert|throw|return)|"
        r"(?:revert|throw|return))",
        body,
    ):
        expr = match.group("expr")
        if "!=" not in expr or not _SENDER_SEARCH_RE.search(expr):
            continue
        left, right = [part.strip() for part in expr.split("!=", 1)]
        other = right if _SENDER_SEARCH_RE.search(left) else left
        if _expr_side_is_authority_state(other):
            return True
    return False


def _has_real_sender_bound_guard(fn: FunctionSlice) -> bool:
    terms = _authority_terms(fn.header)
    text = f"{fn.header}\n{fn.body}"
    return (
        _has_real_header_guard(fn.header, terms)
        or bool(_BODY_ROLE_GUARD_RE.search(text))
        or bool(_BODY_OWNER_GUARD_RE.search(text))
        or bool(_MAPPING_SENDER_GUARD_RE.search(text))
        or _has_real_sender_equality_guard(fn.body)
    )


def _is_external_mutator(fn: FunctionSlice) -> bool:
    return bool(_PUBLIC_HEADER_RE.search(fn.header)) and not _VIEW_HEADER_RE.search(fn.header)


def _effect_reasons(fn: FunctionSlice) -> list[str]:
    text = f"{fn.name}\n{fn.body}"
    reasons: list[str] = []
    if _ROLE_MSGSENDER_EFFECT_RE.search(fn.body):
        reasons.append("role granted to msg.sender")
    if _PRIVILEGED_MSGSENDER_MAPPING_WRITE_RE.search(fn.body):
        reasons.append("privileged mapping write keyed by msg.sender")
    if _PRIVILEGED_MSGSENDER_SCALAR_ASSIGN_RE.search(fn.body):
        reasons.append("privileged authority assigned to msg.sender")
    if _SWEEP_TO_MSGSENDER_RE.search(fn.body) and _SWEEP_NAME_RE.search(fn.name):
        reasons.append("privileged sweep transfers to msg.sender")
    if _ROLE_MANAGEMENT_CALL_RE.search(fn.body) and _PRIVILEGED_NAME_RE.search(text):
        reasons.append("privileged role management triggered by caller")
    if _PRIVILEGED_MAPPING_WRITE_RE.search(fn.body) and _PRIVILEGED_NAME_RE.search(text):
        reasons.append("privileged membership or config write triggered by caller")
    if _PRIVILEGED_ASSIGN_RE.search(fn.body) and _PRIVILEGED_NAME_RE.search(text):
        reasons.append("privileged setter, pause, or config write triggered by caller")
    return reasons


def _admin_msgsender_mismatch(fn: FunctionSlice) -> tuple[list[str], list[str]]:
    if not _is_external_mutator(fn):
        return [], []
    auth_reasons = _mismatched_auth_reasons(fn)
    if not auth_reasons:
        return [], []
    effect_reasons = _effect_reasons(fn)
    if not effect_reasons:
        return [], []
    if _has_real_sender_bound_guard(fn):
        return [], []
    return auth_reasons, effect_reasons


def _finding(
    file_path: str,
    line: int,
    function: str,
    auth_reasons: list[str],
    effect_reasons: list[str],
) -> Finding:
    auth_text = ", ".join(sorted(set(auth_reasons)))
    effect_text = ", ".join(sorted(set(effect_reasons)))
    return Finding(
        detector=DETECTOR_NAME,
        file=file_path,
        line=line,
        severity=DETECTOR_SEVERITY_DEFAULT,
        function=function,
        message=(
            "privileged admin effect validates a caller-supplied authority "
            f"({auth_text}) while msg.sender receives or triggers the effect "
            f"({effect_text}) without a real sender-bound owner, admin, "
            "governance, or role guard. NOT_SUBMIT_READY: detector fixture "
            "smoke evidence only."
        ),
    )


def scan(source: str, file_path: str = "<memory>") -> list[Finding]:
    code = _strip_comments_and_strings(source)
    findings: list[Finding] = []
    for fn in _split_functions(code):
        auth_reasons, effect_reasons = _admin_msgsender_mismatch(fn)
        if auth_reasons:
            findings.append(_finding(file_path, fn.line, fn.name, auth_reasons, effect_reasons))
    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
