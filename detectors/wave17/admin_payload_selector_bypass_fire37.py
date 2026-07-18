"""
admin-payload-selector-bypass-fire37

Solidity recall-lift detector for admin wrappers where authorization checks a
generic executor, relayer, router, operator, or keeper but does not bind the
requested privileged selector, target, role id, route id, or payload domain.

This is not a broad missing-onlyOwner detector. It requires:
1. public or external mutating function;
2. generic executor-style authorization;
3. user-controlled admin route material such as target, selector, payload,
   role id, or route id;
4. low-level call, proxy route, role mutation, or upgrade/admin sink;
5. missing binding for at least one requested privileged domain.

Provenance:
- context_pack_id: auditooor.vault_context_pack.v1:resume:f4d2e1d5cdce68c4
- context_pack_hash: f4d2e1d5cdce68c48442ecdcc7a8f029fcf9efb0e11511c8f00371f9c304e88f
- source ref: reports/detector_lift_fire36_20260605/post_priorities_solidity.md
- source ref: reference/patterns.dsl/admin-bypass-umbrella.yaml
- source ref: reference/patterns.dsl/admin-bypass-wrong-domain-or-missing-guard.yaml
- source ref: detectors/wave17/admin_abi_packed_role_collision_fire36.py
- source ref: detectors/wave17/admin_zero_only_guard_fire35.py
- attack_class: admin-bypass

Hits are candidate evidence only. NOT_SUBMIT_READY.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "admin-payload-selector-bypass-fire37"
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


@dataclass
class Param:
    typ: str
    name: str


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
    r"(?P<type>"
    r"(?:[A-Za-z_][A-Za-z0-9_]*\s*\.\s*)?[A-Za-z_][A-Za-z0-9_]*|"
    r"address|bytes(?:[0-9]+)?|uint(?:[0-9]+)?|int(?:[0-9]+)?|bool|string"
    r")"
    r"(?P<array>(?:\s*\[[^\]]*\])*)\s+"
    r"(?:(?:calldata|memory|storage)\s+)?"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
)
_SENDER_RE = r"(?:msg\s*\.\s*sender|_msgSender\s*\(\s*\))"
_SENDER_SEARCH_RE = re.compile(_SENDER_RE, re.IGNORECASE)
_GENERIC_EXECUTOR_WORD_RE = re.compile(
    r"(?i)(executor|executors|operator|operators|relayer|relayers|router|"
    r"routers|bridge|bridges|gateway|gateways|dispatcher|dispatchers|"
    r"forwarder|forwarders|keeper|keepers|delegate|delegates)"
)
_GENERIC_ROLE_WORD_RE = re.compile(
    r"(?i)(EXECUTOR|OPERATOR|RELAYER|ROUTER|BRIDGE|GATEWAY|DISPATCHER|"
    r"FORWARDER|KEEPER|CALLER|CALLER_ROLE|AUTHORIZED_CALLER)"
)
_GENERIC_EXECUTOR_HEADER_RE = re.compile(
    r"(?is)\bonly(?:Executor|Operator|Relayer|Router|Bridge|Gateway|"
    r"Dispatcher|Forwarder|Keeper|AuthorizedCaller|Delegate)"
    r"[A-Za-z0-9_]*\b|"
    r"\bonlyRole\s*\([^)]*(?:EXECUTOR|OPERATOR|RELAYER|ROUTER|BRIDGE|"
    r"GATEWAY|DISPATCHER|FORWARDER|KEEPER|CALLER)[^)]*\)"
)
_GENERIC_ROLE_CHECK_RE = re.compile(
    rf"(?is)\b(?:hasRole|_checkRole|checkRole)\s*\([^;{{}}]*"
    rf"(?:EXECUTOR|OPERATOR|RELAYER|ROUTER|BRIDGE|GATEWAY|DISPATCHER|"
    rf"FORWARDER|KEEPER|CALLER)[^;{{}}]*{_SENDER_RE}"
)
_GENERIC_MAPPING_CHECK_RE = re.compile(
    rf"(?is)\b(?:require|assert|if)\s*\([^;{{}}]*"
    rf"\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\[[^\]]*{_SENDER_RE}[^\]]*\]"
    rf"[^;{{}}]*\)"
)
_GENERIC_AUTH_CALL_RE = re.compile(
    rf"(?is)\b(?P<receiver>[A-Za-z_][A-Za-z0-9_]*)\s*\.\s*"
    rf"(?:canCall|isAuthorized|authorized|isAllowed|isTrusted|isExecutor|"
    rf"isOperator|isRelayer|isRouter|isKeeper)\s*\([^;{{}}]*{_SENDER_RE}"
)
_STRONG_ADMIN_GUARD_RE = re.compile(
    rf"(?is)(?:"
    rf"\bonly(?:Owner|Admin|Governance|Governor|Gov|DAO|Dao|Timelock|"
    rf"RoleAdmin|EmergencyAdmin|ProtocolAdmin|GuardianAdmin)\b|"
    rf"\bonlyRole\s*\([^)]*(?:DEFAULT_ADMIN_ROLE|ADMIN_ROLE|GOVERNANCE_ROLE|"
    rf"GOVERNOR_ROLE|TIMELOCK_ROLE|OWNER_ROLE|PROTOCOL_ADMIN_ROLE)[^)]*\)|"
    rf"\b(?:_checkOwner|_onlyOwner|enforceIsOwner|enforceIsGovernance|"
    rf"enforceIsContractOwner)\s*\(|"
    rf"\b(?:require|assert)\s*\([^;{{}}]*(?:"
    rf"{_SENDER_RE}[^;{{}}]*(?:owner|_owner|admin|_admin|governance|"
    rf"governor|gov|dao|timelock)|"
    rf"(?:owner|_owner|admin|_admin|governance|governor|gov|dao|timelock)"
    rf"[^;{{}}]*{_SENDER_RE}|"
    rf"(?:hasRole|_checkRole)\s*\([^;{{}}]*(?:DEFAULT_ADMIN_ROLE|"
    rf"ADMIN_ROLE|GOVERNANCE_ROLE|GOVERNOR_ROLE|TIMELOCK_ROLE)[^;{{}}]*"
    rf"{_SENDER_RE}"
    rf")[^;{{}}]*\)"
    rf")"
)
_LOW_LEVEL_CALL_RE = re.compile(
    r"(?is)(?:"
    r"\.\s*(?:call|delegatecall)\s*\(|"
    r"\.\s*functionCall(?:WithValue)?\s*\(|"
    r"\bAddress\s*\.\s*functionCall(?:WithValue)?\s*\(|"
    r"\b(?:executeCall|_executeCall|executeAdmin|adminCall|privilegedCall|"
    r"routeAdmin|forwardAdmin|dispatchAdmin|proxyCall|_proxyCall)\s*\("
    r")"
)
_ADMIN_SINK_RE = re.compile(
    r"(?is)\b(?:_grantRole|grantRole|_revokeRole|revokeRole|_setRoleAdmin|"
    r"upgradeTo|upgradeToAndCall|authorizeUpgrade|diamondCut|setImplementation|"
    r"setAdmin|transferOwnership)\s*\(|"
    r"\b(?:implementation|admin|_admin|owner|_owner|governance|governor|"
    r"facet|facets|selectorToFacet|routeTarget|routeTargets)\s*(?:\[[^;\n]+\])?"
    r"\s*="
)
_ADMIN_ROUTE_WORD_RE = re.compile(
    r"(?i)(admin|privileged|execute|executor|operator|route|router|proxy|"
    r"forward|dispatch|target|selector|payload|calldata|callData|role|grant|"
    r"revoke|upgrade|implementation|facet|diamond|governance)"
)
_TARGET_NAME_RE = re.compile(
    r"(?i)\b(?:target|targets|to|callee|destination|dest|implementation|"
    r"module|facet|adapter|router|routeTarget|adminTarget|proxy|contract)\b"
)
_SELECTOR_NAME_RE = re.compile(
    r"(?i)\b(?:selector|selectors|functionSelector|functionSig|functionId|"
    r"sig|method|methodId|action|operation|operationId)\b"
)
_PAYLOAD_NAME_RE = re.compile(
    r"(?i)\b(?:data|payload|callData|calldata|params|paramData|adminPayload|"
    r"executeData|execData|commands|actions|message|messages)\b"
)
_ROLE_NAME_RE = re.compile(
    r"(?i)\b(?:role|roleId|roleKey|permission|permissionId|capability|"
    r"capabilityId)\b"
)
_ROUTE_NAME_RE = re.compile(
    r"(?i)\b(?:route|routeId|routeKey|lane|laneId|domain|domainId|chainId|"
    r"dstChainId|srcChainId|path|pathId|proxyRoute|endpoint|channel)\b"
)
_BINDING_WORD_RE = re.compile(
    r"(?i)(allow|allowed|approved|authorized|permission|permissions|policy|"
    r"canCall|capability|trusted|enabled|supported|whitelist|whitelisted|"
    r"selector|target|route|role|domain|scope|binding)"
)
_SELECTOR_BINDING_WORD_RE = re.compile(
    r"(?i)(selector|selectors|functionSelector|method|operation|action|"
    r"calldata|callData|payload|dataHash|payloadHash|keccak256|allowed|"
    r"approved|permission|policy|canCall|capability|whitelist)"
)
_EXAMPLE_SOURCE_RE = re.compile(r"(?i)\b(?:mock|example|demo)\b")
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


def _params(header: str) -> list[Param]:
    out: list[Param] = []
    for match in _PARAM_RE.finditer(_parameter_section(header)):
        typ = re.sub(r"\s+", "", match.group("type") or "").lower()
        array = re.sub(r"\s+", "", match.group("array") or "")
        if array:
            typ = f"{typ}{array}"
        out.append(Param(typ=typ, name=match.group("name")))
    return out


def _is_external_mutator(fn: FunctionSlice) -> bool:
    return bool(_PUBLIC_HEADER_RE.search(fn.header)) and not _VIEW_HEADER_RE.search(fn.header)


def _has_strong_admin_guard(fn: FunctionSlice) -> bool:
    return bool(_STRONG_ADMIN_GUARD_RE.search(f"{fn.header}\n{fn.body}"))


def _generic_executor_reasons(fn: FunctionSlice) -> list[str]:
    text = f"{fn.header}\n{fn.body}"
    reasons: list[str] = []
    if _GENERIC_EXECUTOR_HEADER_RE.search(fn.header):
        reasons.append("generic executor modifier")
    if _GENERIC_ROLE_CHECK_RE.search(fn.body):
        reasons.append("generic executor role check")
    for match in _GENERIC_MAPPING_CHECK_RE.finditer(fn.body):
        name = match.group("name") or ""
        if _GENERIC_EXECUTOR_WORD_RE.search(name):
            reasons.append(f"generic executor mapping {name}")
    for match in _GENERIC_AUTH_CALL_RE.finditer(fn.body):
        receiver = match.group("receiver") or ""
        expr = match.group(0)
        if _GENERIC_EXECUTOR_WORD_RE.search(receiver) or _GENERIC_EXECUTOR_WORD_RE.search(text):
            if "," not in expr:
                reasons.append("generic executor authority call")
            else:
                # A call with only msg.sender and generic policy arguments is
                # still generic. Calls with explicit target or selector are
                # handled by the binding suppression logic.
                if not re.search(r"(?i)(target|selector|route|role|payload|calldata|callData)", expr):
                    reasons.append("generic executor authority call")
    return sorted(set(reasons))


def _request_material(fn: FunctionSlice) -> dict[str, list[str]]:
    material: dict[str, list[str]] = {
        "target domain": [],
        "selector or payload": [],
        "role id": [],
        "route domain": [],
    }
    for param in _params(fn.header):
        name = param.name
        typ = param.typ
        if _TARGET_NAME_RE.search(name) and (typ.startswith("address") or "contract" in typ):
            material["target domain"].append(name)
        if _SELECTOR_NAME_RE.search(name) or typ.startswith("bytes4"):
            material["selector or payload"].append(name)
        elif _PAYLOAD_NAME_RE.search(name) and not re.search(r"(?i)\bsignature\b", name):
            material["selector or payload"].append(name)
        if _ROLE_NAME_RE.search(name):
            material["role id"].append(name)
        if _ROUTE_NAME_RE.search(name):
            material["route domain"].append(name)
    return {key: sorted(set(values)) for key, values in material.items() if values}


def _condition_expressions(body: str) -> list[str]:
    return [match.group("expr") for match in _CONDITION_RE.finditer(body)]


def _contains_name(text: str, name: str) -> bool:
    return bool(re.search(rf"\b{re.escape(name)}\b", text))


def _is_bound_by_condition(body: str, names: list[str], *, selector_domain: bool = False) -> bool:
    if not names:
        return True
    binding_word_re = _SELECTOR_BINDING_WORD_RE if selector_domain else _BINDING_WORD_RE
    for expr in _condition_expressions(body):
        if not any(_contains_name(expr, name) for name in names):
            continue
        if _SENDER_SEARCH_RE.search(expr):
            return True
        if binding_word_re.search(expr):
            return True
    return False


def _payload_hash_or_selector_bound(body: str, names: list[str]) -> bool:
    if not names:
        return True
    for expr in _condition_expressions(body):
        if not any(_contains_name(expr, name) for name in names):
            continue
        if re.search(r"(?is)(keccak256|bytes4|selector|allowed|approved|permission|canCall|policy)", expr):
            return True
    return False


def _selector_aliases_for_payload(body: str, names: list[str]) -> list[str]:
    aliases: list[str] = []
    for name in names:
        alias_re = re.compile(
            rf"(?is)\b(?:bytes4\s+)?(?P<alias>[A-Za-z_][A-Za-z0-9_]*)"
            rf"\s*=\s*bytes4\s*\(\s*{re.escape(name)}\b[^;)]{{0,120}}\)"
        )
        for match in alias_re.finditer(body):
            aliases.append(match.group("alias"))
    return sorted(set(aliases))


def _missing_bindings(fn: FunctionSlice, material: dict[str, list[str]]) -> list[str]:
    missing: list[str] = []
    if "target domain" in material and not _is_bound_by_condition(fn.body, material["target domain"]):
        missing.append("target domain")
    if "selector or payload" in material:
        selector_names = material["selector or payload"]
        selector_names = sorted(
            set(selector_names + _selector_aliases_for_payload(fn.body, selector_names))
        )
        if not (
            _is_bound_by_condition(fn.body, selector_names, selector_domain=True)
            or _payload_hash_or_selector_bound(fn.body, selector_names)
        ):
            missing.append("selector or payload")
    if "role id" in material and not _is_bound_by_condition(fn.body, material["role id"]):
        missing.append("role id")
    if "route domain" in material and not _is_bound_by_condition(fn.body, material["route domain"]):
        missing.append("route domain")
    return missing


def _has_admin_route_sink(fn: FunctionSlice) -> bool:
    text = f"{fn.header}\n{fn.body}"
    if not _ADMIN_ROUTE_WORD_RE.search(text):
        return False
    return bool(_LOW_LEVEL_CALL_RE.search(fn.body) or _ADMIN_SINK_RE.search(fn.body))


def _payload_selector_gap(fn: FunctionSlice) -> tuple[list[str], list[str], list[str]]:
    if not _is_external_mutator(fn):
        return [], [], []
    if _has_strong_admin_guard(fn):
        return [], [], []

    executor_reasons = _generic_executor_reasons(fn)
    if not executor_reasons:
        return [], [], []

    material = _request_material(fn)
    if not material:
        return [], [], []
    if not _has_admin_route_sink(fn):
        return [], [], []

    missing = _missing_bindings(fn, material)
    if not missing:
        return [], [], []

    material_summary = [
        f"{domain}: {', '.join(names)}" for domain, names in sorted(material.items())
    ]
    return missing, executor_reasons, material_summary


def _finding(
    file_path: str,
    line: int,
    function: str,
    missing: list[str],
    executor_reasons: list[str],
    material_summary: list[str],
) -> Finding:
    return Finding(
        detector=DETECTOR_NAME,
        file=file_path,
        line=line,
        severity=DETECTOR_SEVERITY_DEFAULT,
        function=function,
        message=(
            "generic executor authorization reaches an admin payload, selector, "
            "target, role, or proxy route sink without binding the requested "
            f"{', '.join(missing)}. "
            f"Executor evidence: {', '.join(executor_reasons)}. "
            f"User-controlled route material: {'; '.join(material_summary)}. "
            "Bind executor permission to target, selector, role, route, and "
            "payload hash before low-level or privileged dispatch. "
            "NOT_SUBMIT_READY: detector fixture smoke evidence only."
        ),
    )


def scan(source: str, file_path: str = "<memory>") -> list[Finding]:
    if _EXAMPLE_SOURCE_RE.search(file_path):
        return []
    code = _strip_comments_and_strings(source)
    findings: list[Finding] = []
    for fn in _split_functions(code):
        missing, executor_reasons, material_summary = _payload_selector_gap(fn)
        if missing:
            findings.append(
                _finding(file_path, fn.line, fn.name, missing, executor_reasons, material_summary)
            )
    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
