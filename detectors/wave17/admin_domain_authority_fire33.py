"""
admin-domain-authority-fire33

Solidity recall-lift detector for admin-only mutations that authorize the
wrong authority domain: caller-supplied authority contracts, router-only guards
that are not bound to the controlled resource, unguarded self-admin
grants, and sibling admin mutations where one path is guarded but the
equivalent same-sink mutation is public.

Provenance:
- context_pack_id: auditooor.vault_context_pack.v1:resume:57361adac683c0c7
- context_pack_hash: 57361adac683c0c7f40a2f345b94c4172fe41a09373a05ca2cf8fae67d1b1dab
- source ref: reports/detector_lift_fire32_20260605/post_priorities_all.md
- source ref: reference/patterns.dsl/admin-bypass-wrong-domain-or-missing-guard.yaml
- source ref: reference/patterns.dsl/admin-bypass-umbrella.yaml
- source ref: reference/patterns.dsl/self-admin-grant-privilege-escalation.yaml
- attack_class: admin-bypass

Hits are candidate evidence only. NOT_SUBMIT_READY.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "admin-domain-authority-fire33"
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
    r"timelock|router|factory|settings|policy)"
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
    "router",
    "factory",
)
_AUTHORITY_STATE_RE = re.compile(
    r"(?is)^(?:"
    r"address\s*\(\s*)?"
    r"(?:owner|_owner|owner\s*\(\s*\)|admin|_admin|admin\s*\(\s*\)|"
    r"governance|governor|gov|dao|timelock|controller|manager|operator|"
    r"guardian|executor|relayer|signer|keeper|validator|pauser|authority|"
    r"authorized|roleAdmin|defaultAdmin|factory)"
    r"(?:\s*\))?$"
)
_FIXED_HEADER_GUARD_RE = re.compile(
    r"(?is)\b(?:"
    r"onlyOwner|onlyAdmin|onlyGovernance|onlyGovernor|onlyGov|onlyDAO|"
    r"onlyDao|onlyTimelock|onlyController|onlyManager|onlyOperator|"
    r"onlyGuardian|onlyExecutor|onlyRelayer|onlySigner|onlyKeeper|"
    r"onlyValidator|onlyPauser|onlyFactory|onlyRoleAdmin|requiresAuth|"
    r"requireAuth|restricted|auth"
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
)
_AUTHORITY_CONTRACT_SENDER_CALL_RE = re.compile(
    rf"(?is)(?P<receiver>"
    rf"\b[A-Za-z_][A-Za-z0-9_]*\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*\)|"
    rf"\b[A-Za-z_][A-Za-z0-9_]*"
    rf")\s*\.\s*(?:hasRole|isAdmin|canCall|isAuthorized|authorized|"
    rf"isOperator|isGovernor|isOwner|owner)\s*\([^;{{}}]*{_SENDER_RE}"
)
_ROLE_CHECK_RE = re.compile(r"(?is)\b(?:hasRole|_checkRole)\s*\((?P<args>[^;{}]+)\)")
_TX_ORIGIN_AUTH_RE = re.compile(
    r"(?is)(?:"
    r"\b(?:require|assert)\s*\([^;{}]*\btx\s*\.\s*origin\b[^;{}]*\)|"
    r"\bif\s*\([^;{}]*\btx\s*\.\s*origin\b[^;{}]*\)"
    r"\s*(?:\{[^{}]*(?:revert|throw|return)|(?:revert|throw|return))|"
    r"\bonly[A-Za-z0-9_]*(?:Origin|TxOrigin)[A-Za-z0-9_]*\b"
    r")"
)
_ROUTER_GUARD_RE = re.compile(
    rf"(?is)(?:"
    rf"\bonlyRouter\b|"
    rf"\b(?:require|assert)\s*\([^;{{}}]*(?:"
    rf"{_SENDER_RE}\s*==\s*(?:router|trustedRouter|_router)|"
    rf"(?:router|trustedRouter|_router)\s*==\s*{_SENDER_RE})"
    rf"[^;{{}}]*\)"
    rf")"
)
_RESOURCE_BINDING_RE = re.compile(
    rf"(?is)(?:"
    rf"(?:routerPermission|routerPermissions|authorizedRouters|isRouterFor|"
    rf"resourceRouter|routerFor|accountRouter|marketRouter)\s*\[[^\]]*"
    rf"(?:account|user|market|resource|vault|pool|id)[^\]]*\][^;{{}}]*"
    rf"(?:{_SENDER_RE}|router|trustedRouter)|"
    rf"(?:ownerOf|controllerOf|managerOf)\s*\([^)]*(?:account|user|market|"
    rf"resource|vault|pool|id)[^)]*\)\s*==\s*{_SENDER_RE}|"
    rf"{_SENDER_RE}\s*==\s*(?:ownerOf|controllerOf|managerOf)\s*\([^)]*"
    rf"(?:account|user|market|resource|vault|pool|id)[^)]*\)"
    rf")"
)
_SELF_ADMIN_EFFECT_RE = re.compile(
    rf"(?is)(?:"
    rf"\b(?:_grantRole|grantRole|_setupRole|setupRole)\s*\([^;{{}}]*"
    rf"(?:DEFAULT_ADMIN_ROLE|ADMIN_ROLE|OWNER_ROLE|GOVERNANCE_ROLE)[^;{{}}]*"
    rf"{_SENDER_RE}|"
    rf"\b(?:admins|isAdmin|owners|isOwner|governors|isGovernor)"
    rf"\s*\[[^\]]*{_SENDER_RE}[^\]]*\]\s*=\s*true|"
    rf"\broles\s*\[[^\]]*{_SENDER_RE}[^\]]*\]\s*\[[^\]]+\]\s*=\s*true|"
    rf"\broles\s*\[[^\]]+\]\s*\[[^\]]*{_SENDER_RE}[^\]]*\]\s*=\s*true|"
    rf"\b(?:owner|_owner|admin|_admin|governance|governor|defaultAdmin)"
    rf"\s*=\s*{_SENDER_RE}"
    rf")"
)
_ROLE_MANAGEMENT_CALL_RE = re.compile(
    r"(?is)\b(?:_grantRole|grantRole|_setupRole|setupRole|_revokeRole|"
    r"revokeRole|_setRoleAdmin|setRoleAdmin)\s*\("
)
_PRIVILEGED_NAME_RE = re.compile(
    r"(?i)(?:"
    r"set|update|configure|grant|revoke|sweep|rescue|recover|emergency|"
    r"pause|unpause|upgrade|withdraw|drain|rotate|add|remove|enable|disable|"
    r"register|route|forward|dispatch|install|assign|promote"
    r").*(?:owner|admin|role|operator|guardian|treasury|oracle|router|"
    r"adapter|gateway|registry|settings|config|fee|limit|cap|param|"
    r"market|emergency|implementation|executor|signer|pauser|controller|"
    r"manager|relayer|keeper|validator)"
)
_SINK_ASSIGN_RE = re.compile(
    r"(?is)\b(?P<name>"
    r"owner|_owner|pendingOwner|admin|_admin|governance|governor|gov|dao|"
    r"timelock|controller|controllers|manager|managers|operator|operators|"
    r"guardian|guardians|executor|executors|relayer|relayers|signer|signers|"
    r"keeper|keepers|validator|validators|pauser|pausers|authority|treasury|"
    r"feeRecipient|feeTo|oracle|oracles|priceOracle|router|routers|adapter|"
    r"adapters|gateway|gateways|registry|registries|bridge|endpoint|"
    r"implementation|config|configs|settings|marketConfig|marketOracles|markets|paused|"
    r"isPaused|halted|frozen|disabled|limit|limits|cap|caps|max[A-Za-z0-9_]*|"
    r"min[A-Za-z0-9_]*|protocolFee|feeBps|roles|roleMembers|admins|isAdmin|"
    r"owners|isOwner|authorized|isAuthorized|trusted|isTrusted|whitelist|"
    r"blacklist|allowlist|blocklist"
    r")\s*(?:\[[^\]]+\])?\s*(?:=|\+=|-=|\*=|/=|\+\+|--)"
)
_MAPPING_WRITE_RE = re.compile(
    r"(?is)\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\[(?P<key>[^\]]+)\]\s*="
)
_TOKEN_SWEEP_RE = re.compile(
    r"(?is)\b(?:safeTransfer|transfer|sendValue|send)\s*\(|\.call\s*\{\s*value\s*:"
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
    for match in re.finditer(r"(?is)\b(?:require|assert)\s*\((?P<expr>[^;{}]*)\)", text):
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


def _authority_contract_checks_sender(text: str, terms: list[AuthorityTerm]) -> bool:
    for term in terms:
        if re.search(
            rf"(?is)(?:"
            rf"\b[A-Za-z_][A-Za-z0-9_]*\s*\(\s*{term.pattern}\s*\)|"
            rf"{term.pattern}"
            rf")\s*\.\s*(?:hasRole|isAdmin|canCall|isAuthorized|authorized|"
            rf"isOperator|isGovernor|isOwner|owner)\s*\([^;{{}}]*{_SENDER_RE}",
            text,
        ):
            return True
    return False


def _stored_authority_contract_checks_sender(text: str, terms: list[AuthorityTerm]) -> bool:
    for match in _AUTHORITY_CONTRACT_SENDER_CALL_RE.finditer(text):
        receiver = match.group("receiver")
        if _contains_any_term(receiver, terms):
            continue
        if re.search(r"(?i)(admin|authority|access|govern|controller|manager|operator)", receiver):
            return True
    return False


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
        or _stored_authority_contract_checks_sender(text, terms)
        or bool(_BODY_ROLE_GUARD_RE.search(text))
        or bool(_BODY_OWNER_GUARD_RE.search(text))
        or bool(_MAPPING_SENDER_GUARD_RE.search(text))
        or _has_real_sender_equality_guard(fn.body)
    )


def _is_external_mutator(fn: FunctionSlice) -> bool:
    return bool(_PUBLIC_HEADER_RE.search(fn.header)) and not _VIEW_HEADER_RE.search(fn.header)


def _sink_names(fn: FunctionSlice) -> set[str]:
    sinks = {match.group("name").lower() for match in _SINK_ASSIGN_RE.finditer(fn.body)}
    for match in _ROLE_MANAGEMENT_CALL_RE.finditer(fn.body):
        sinks.add("roles")
    return sinks


def _mapping_writes(fn: FunctionSlice) -> list[re.Match[str]]:
    return list(_MAPPING_WRITE_RE.finditer(fn.body))


def _has_non_sender_resource_write(fn: FunctionSlice) -> bool:
    for match in _mapping_writes(fn):
        key = match.group("key")
        name = match.group("name")
        if _SENDER_SEARCH_RE.search(key):
            continue
        if re.search(r"(?i)(limit|cap|quota|config|setting|oracle|adapter|router|market|role|admin)", name):
            return True
    return False


def _is_self_service_only(fn: FunctionSlice) -> bool:
    writes = _mapping_writes(fn)
    if not writes:
        return False
    if _SELF_ADMIN_EFFECT_RE.search(fn.body):
        return False
    if _ROLE_MANAGEMENT_CALL_RE.search(fn.body):
        return False
    return all(_SENDER_SEARCH_RE.search(match.group("key")) for match in writes)


def _has_privileged_effect(fn: FunctionSlice) -> bool:
    text = f"{fn.name}\n{fn.body}"
    if _SELF_ADMIN_EFFECT_RE.search(fn.body):
        return True
    if _ROLE_MANAGEMENT_CALL_RE.search(fn.body):
        return True
    if _sink_names(fn):
        return not _is_self_service_only(fn)
    if _TOKEN_SWEEP_RE.search(fn.body) and re.search(r"(?i)(sweep|rescue|recover|withdraw|drain)", fn.name):
        return True
    return bool(_PRIVILEGED_NAME_RE.search(text) and re.search(r"(?is)(?:=|\.call\s*\(|delegatecall\s*\()", fn.body))


def _has_router_domain_gap(fn: FunctionSlice) -> bool:
    text = f"{fn.header}\n{fn.body}"
    if not _ROUTER_GUARD_RE.search(text):
        return False
    if _RESOURCE_BINDING_RE.search(text):
        return False
    return _has_non_sender_resource_write(fn)


def _bad_authority_reasons(fn: FunctionSlice) -> list[str]:
    text = f"{fn.header}\n{fn.body}"
    terms = _authority_terms(fn.header)
    reasons: list[str] = []
    if _TX_ORIGIN_AUTH_RE.search(text):
        reasons.append("tx.origin authority domain")
    if terms and _input_checked_against_state_authority(text, terms):
        reasons.append("caller-supplied authority compared to authority state")
    if terms and _role_checks_input_authority(text, terms):
        reasons.append("role check applied to caller-supplied authority")
    if terms and _authority_contract_checks_sender(text, terms):
        reasons.append("caller-supplied authority contract checks msg.sender")
    if _has_router_domain_gap(fn):
        reasons.append("router-only guard not bound to controlled resource")
    if _SELF_ADMIN_EFFECT_RE.search(fn.body):
        reasons.append("self-admin grant or self-ownership effect")
    return reasons


def _sibling_asymmetry_reasons(fn: FunctionSlice, guarded_sinks: set[str]) -> list[str]:
    if _has_real_sender_bound_guard(fn):
        return []
    overlap = sorted(_sink_names(fn) & guarded_sinks)
    if not overlap:
        return []
    return [f"unguarded sibling mutates guarded authority sink {', '.join(overlap)}"]


def _admin_domain_authority_gap(
    fn: FunctionSlice,
    guarded_sinks: set[str],
) -> list[str]:
    if not _is_external_mutator(fn):
        return []
    if not _has_privileged_effect(fn):
        return []

    reasons = _bad_authority_reasons(fn)
    reasons.extend(_sibling_asymmetry_reasons(fn, guarded_sinks))
    if not reasons:
        return []

    if _has_real_sender_bound_guard(fn) and not _has_router_domain_gap(fn):
        return []
    return sorted(set(reasons))


def _guarded_authority_sinks(functions: list[FunctionSlice]) -> set[str]:
    sinks: set[str] = set()
    for fn in functions:
        if not _is_external_mutator(fn):
            continue
        if not _has_privileged_effect(fn):
            continue
        if _has_real_sender_bound_guard(fn):
            sinks.update(_sink_names(fn))
    return sinks


def _finding(file_path: str, line: int, function: str, reasons: list[str]) -> Finding:
    reason_text = ", ".join(reasons)
    return Finding(
        detector=DETECTOR_NAME,
        file=file_path,
        line=line,
        severity=DETECTOR_SEVERITY_DEFAULT,
        function=function,
        message=(
            "admin-only mutation uses the wrong authority domain "
            f"({reason_text}) instead of binding msg.sender to the owner, "
            "admin, role, governance, factory, or controlled resource. "
            "NOT_SUBMIT_READY: detector fixture smoke evidence only."
        ),
    )


def scan(source: str, file_path: str = "<memory>") -> list[Finding]:
    code = _strip_comments_and_strings(source)
    functions = _split_functions(code)
    guarded_sinks = _guarded_authority_sinks(functions)
    findings: list[Finding] = []
    for fn in functions:
        reasons = _admin_domain_authority_gap(fn, guarded_sinks)
        if reasons:
            findings.append(_finding(file_path, fn.line, fn.name, reasons))
    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
