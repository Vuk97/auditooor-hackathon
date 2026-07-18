"""
admin-external-authority-fire34

Solidity recall-lift detector for admin mutations where an external router,
factory, bridge, gateway, or authority contract is authenticated as caller,
but the authorized caller is not bound to the account, pool, market, route,
chain, vault, or other resource being modified.

This is not a generic missing-onlyOwner detector. It requires an apparent
external-authority guard plus a non-self resource mutation, then suppresses
cases with a resource-specific caller binding.

Provenance:
- context_pack_id: auditooor.vault_context_pack.v1:resume:bfadc3c938400bc6
- context_pack_hash: bfadc3c938400bc6618f7f3ae8d500bbc8e5dce19f7f4e6c043195ffc6742129
- source ref: reports/detector_lift_fire33_20260605/post_priorities_all.md
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


DETECTOR_NAME = "admin-external-authority-fire34"
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
_EXTERNAL_AUTH_WORD_RE = re.compile(
    r"(?i)(router|routers|factory|factories|bridge|bridges|gateway|gateways|"
    r"adapter|adapters|authority|authorities|accessManager|accessControl|"
    r"endpoint|messenger|relayer|forwarder|dispatcher|hub|spoke)"
)
_EXTERNAL_AUTH_HEADER_RE = re.compile(
    r"(?is)\bonly[A-Za-z0-9_]*(?:Router|Factory|Bridge|Gateway|Adapter|"
    r"Authority|AccessManager|AccessControl|Endpoint|Messenger|Relayer|"
    r"Forwarder|Dispatcher|Hub|Spoke)[A-Za-z0-9_]*\b"
)
_ADMIN_GUARD_RE = re.compile(
    rf"(?is)(?:"
    rf"\bonly(?:Owner|Admin|Governance|Governor|Gov|DAO|Dao|Timelock|"
    rf"Controller|Manager|Operator|Guardian|Executor|Keeper|Validator|"
    rf"Pauser|Role|Roles|RoleAdmin)\b|"
    rf"\b(?:_checkOwner|_onlyOwner|_checkRole)\s*\(|"
    rf"\b(?:hasRole|isAdmin|isOwner)\s*\([^;{{}}]*{_SENDER_RE}|"
    rf"\b(?:require|assert)\s*\([^;{{}}]*(?:"
    rf"{_SENDER_RE}\s*==\s*(?:owner|_owner|admin|_admin|governance|"
    rf"governor|gov|dao|timelock)|"
    rf"(?:owner|_owner|admin|_admin|governance|governor|gov|dao|timelock)"
    rf"\s*==\s*{_SENDER_RE})"
    rf"[^;{{}}]*\)"
    rf")"
)
_EXTERNAL_AUTH_EQUALITY_RE = re.compile(
    rf"(?is)\b(?:require|assert)\s*\([^;{{}}]*(?:"
    rf"{_SENDER_RE}\s*==\s*(?P<rhs>[A-Za-z_][A-Za-z0-9_\.]*)|"
    rf"(?P<lhs>[A-Za-z_][A-Za-z0-9_\.]*)\s*==\s*{_SENDER_RE}"
    rf")[^;{{}}]*\)"
)
_EXTERNAL_AUTH_MAPPING_RE = re.compile(
    rf"(?is)\b(?:require|assert)\s*\([^;{{}}]*"
    rf"\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\[[^\]]*{_SENDER_RE}[^\]]*\]"
    rf"[^;{{}}]*\)"
)
_EXTERNAL_AUTH_CALL_RE = re.compile(
    rf"(?is)\b(?P<receiver>"
    rf"[A-Za-z_][A-Za-z0-9_]*\s*\([^;{{}}]*\)|"
    rf"[A-Za-z_][A-Za-z0-9_]*"
    rf")\s*\.\s*(?:canCall|isAuthorized|authorized|isAllowed|isTrusted|"
    rf"isRouter|isFactory|isBridge|isRelayer|isOperator|hasRole)"
    rf"\s*\([^;{{}}]*{_SENDER_RE}"
)
_RESOURCE_NAME_RE = re.compile(
    r"(?i)(account|user|member|recipient|beneficiary|owner|market|pool|vault|"
    r"asset|token|route|lane|chain|domain|adapter|gateway|bridge|request|"
    r"position|loan|order|campaign|collection|pair|proposal|epoch|id|key)"
)
_RESOURCE_MAPPING_WRITE_RE = re.compile(
    r"(?is)\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*"
    r"\[(?P<key>[^\]]+)\]"
    r"(?:\s*\[[^\]]+\])?"
    r"(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*)?"
    r"\s*(?:=|\+=|-=|\*=|/=|\+\+|--)"
)
_RESOURCE_BINDING_WORD_RE = re.compile(
    r"(?i)(permission|permitted|allow|allowed|authorize|authorized|auth|"
    r"trusted|router|factory|bridge|gateway|adapter|authority|access|owner|"
    r"controller|manager|operator|for|of|belongs|route|resource|market|pool|vault)"
)
_CONDITION_RE = re.compile(r"(?is)\b(?:require|assert|if)\s*\((?P<expr>[^;{}]+)\)")


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


def _resource_params(header: str) -> list[str]:
    out: list[str] = []
    for name in _param_names(header):
        if _RESOURCE_NAME_RE.search(name):
            out.append(name)
    return sorted(set(out), key=len, reverse=True)


def _is_external_mutator(fn: FunctionSlice) -> bool:
    return bool(_PUBLIC_HEADER_RE.search(fn.header)) and not _VIEW_HEADER_RE.search(fn.header)


def _has_admin_guard(fn: FunctionSlice) -> bool:
    return bool(_ADMIN_GUARD_RE.search(f"{fn.header}\n{fn.body}"))


def _external_authority_reasons(fn: FunctionSlice) -> list[str]:
    text = f"{fn.header}\n{fn.body}"
    reasons: list[str] = []
    if _EXTERNAL_AUTH_HEADER_RE.search(fn.header):
        reasons.append("external authority modifier")
    for match in _EXTERNAL_AUTH_EQUALITY_RE.finditer(fn.body):
        target = match.group("rhs") or match.group("lhs") or ""
        if _EXTERNAL_AUTH_WORD_RE.search(target):
            reasons.append(f"caller equals external {target}")
    for match in _EXTERNAL_AUTH_MAPPING_RE.finditer(fn.body):
        name = match.group("name") or ""
        if _EXTERNAL_AUTH_WORD_RE.search(name):
            reasons.append(f"caller is listed in external authority mapping {name}")
    for match in _EXTERNAL_AUTH_CALL_RE.finditer(fn.body):
        receiver = match.group("receiver") or ""
        if _EXTERNAL_AUTH_WORD_RE.search(receiver) or _EXTERNAL_AUTH_WORD_RE.search(text):
            reasons.append("external authority contract authenticates msg.sender")
    return sorted(set(reasons))


def _resource_write_params(fn: FunctionSlice) -> dict[str, set[str]]:
    params = _resource_params(fn.header)
    out: dict[str, set[str]] = {}
    for match in _RESOURCE_MAPPING_WRITE_RE.finditer(fn.body):
        key = match.group("key")
        if _SENDER_SEARCH_RE.search(key):
            continue
        for param in params:
            if re.search(rf"\b{re.escape(param)}\b", key):
                out.setdefault(param, set()).add(f"{match.group('name')}[{param}]")
    return out


def _condition_binds_resource(expr: str, param: str) -> bool:
    if not _SENDER_SEARCH_RE.search(expr):
        return False
    if not re.search(rf"\b{re.escape(param)}\b", expr):
        return False
    return bool(_RESOURCE_BINDING_WORD_RE.search(expr))


def _resource_binding_present(fn: FunctionSlice, resource_params: set[str]) -> bool:
    text = f"{fn.header}\n{fn.body}"
    for param in resource_params:
        for match in _CONDITION_RE.finditer(text):
            if _condition_binds_resource(match.group("expr"), param):
                return True
        if re.search(
            rf"(?is)\b(?:canCall|isAuthorized|authorized|isAllowed|isTrusted|"
            rf"isRouterFor|isFactoryFor|isBridgeFor|ownerOf|controllerOf|managerOf)"
            rf"\s*\([^;{{}}]*{_SENDER_RE}[^;{{}}]*\b{re.escape(param)}\b",
            text,
        ):
            return True
        if re.search(
            rf"(?is)\b(?:canCall|isAuthorized|authorized|isAllowed|isTrusted|"
            rf"isRouterFor|isFactoryFor|isBridgeFor|ownerOf|controllerOf|managerOf)"
            rf"\s*\([^;{{}}]*\b{re.escape(param)}\b[^;{{}}]*{_SENDER_RE}",
            text,
        ):
            return True
    return False


def _authority_resource_gap(fn: FunctionSlice) -> tuple[list[str], dict[str, set[str]]]:
    if not _is_external_mutator(fn):
        return [], {}
    if _has_admin_guard(fn):
        return [], {}

    auth_reasons = _external_authority_reasons(fn)
    if not auth_reasons:
        return [], {}

    writes = _resource_write_params(fn)
    if not writes:
        return [], {}

    if _resource_binding_present(fn, set(writes)):
        return [], {}

    return auth_reasons, writes


def _finding(
    file_path: str,
    line: int,
    function: str,
    auth_reasons: list[str],
    writes: dict[str, set[str]],
) -> Finding:
    auth_text = ", ".join(auth_reasons)
    write_text = ", ".join(
        f"{param}: {', '.join(sorted(sinks))}" for param, sinks in sorted(writes.items())
    )
    return Finding(
        detector=DETECTOR_NAME,
        file=file_path,
        line=line,
        severity=DETECTOR_SEVERITY_DEFAULT,
        function=function,
        message=(
            "external authority guard authenticates msg.sender but does not bind "
            f"that caller to the modified resource ({auth_text}; writes {write_text}). "
            "Trusted router, factory, bridge, or authority callers must be scoped "
            "per account, route, pool, market, chain, vault, or equivalent resource. "
            "NOT_SUBMIT_READY: detector fixture smoke evidence only."
        ),
    )


def scan(source: str, file_path: str = "<memory>") -> list[Finding]:
    code = _strip_comments_and_strings(source)
    findings: list[Finding] = []
    for fn in _split_functions(code):
        auth_reasons, writes = _authority_resource_gap(fn)
        if auth_reasons:
            findings.append(_finding(file_path, fn.line, fn.name, auth_reasons, writes))
    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
