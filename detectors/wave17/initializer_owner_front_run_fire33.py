"""
initializer-owner-front-run-fire33

Solidity recall-lift detector for externally callable initializer, configure,
setter, and clone setup paths that can bind owner, admin, router, fee
recipient, dispatcher, implementation, or role authority before the intended
deployer or factory binds ownership.

Provenance:
- context_pack_id: auditooor.vault_context_pack.v1:resume:57361adac683c0c7
- context_pack_hash: 57361adac683c0c7f40a2f345b94c4172fe41a09373a05ca2cf8fae67d1b1dab
- source ref: reports/detector_lift_fire32_20260605/post_priorities_all.md
- source ref: reference/patterns.dsl/r94-loop-init-race-admin-takeover.yaml
- source ref: reference/patterns.dsl/clone-fee-recipient-init-permissionless-frontrun.yaml
- source ref: reference/patterns.dsl/fx-pendle-initializer-owner-order.yaml
- attack_class: initializer-front-run

Hits are candidate evidence only. NOT_SUBMIT_READY.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "initializer-owner-front-run-fire33"
DETECTOR_SEVERITY_DEFAULT = "High"
SUBMISSION_POSTURE = "NOT_SUBMIT_READY"
COVERAGE_CLAIM = "detector_fixture_smoke_only"


@dataclass(frozen=True)
class Finding:
    detector: str
    file: str
    line: int
    severity: str
    message: str
    function: Optional[str] = None
    branch: Optional[str] = None


@dataclass(frozen=True)
class FunctionSlice:
    name: str
    header: str
    body: str
    function_line: int
    body_line: int


@dataclass(frozen=True)
class CriticalWrite:
    lhs: str
    rhs: str
    line: int
    kind: str


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
_ENTRYPOINT_NAME_RE = re.compile(
    r"(?i)^(?:"
    r"initialize|init|setup|bootstrap|configure|initRecipient|initializeClone|"
    r"initializeProxy|setupClone|setupProxy|setOwner|setAdmin|setFeeRecipient|"
    r"setRouter|setDispatcher|setFactory|setRecipient|setImplementation|"
    r"setBeacon|setRegistry|setGateway"
    r")(?:[A-Za-z0-9_]*)$"
)
_SETTER_SETUP_NAME_RE = re.compile(
    r"(?i)^(?:setOwner|setAdmin|setFeeRecipient|setRouter|setDispatcher|"
    r"setFactory|setRecipient|setImplementation|setBeacon|setRegistry|"
    r"setGateway)(?:[A-Za-z0-9_]*)$"
)
_PARAM_RE = re.compile(
    r"(?is)(?:^|,)\s*"
    r"(?:"
    r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?|"
    r"bytes(?:[0-9]+)?|uint(?:[0-9]+)?|int(?:[0-9]+)?|address|string|bool"
    r")"
    r"(?:\s*\[[^\]]*\])?\s+"
    r"(?:(?:calldata|memory|storage)\s+)?"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
)
_FIRST_CALL_GATE_RE = re.compile(
    r"(?is)(?:"
    r"\b(?:initializer|reinitializer)\b|"
    r"\brequire\s*\([^;{}]*(?:!\s*_?initialized|_?initialized\s*==\s*false|"
    r"_?initialized\s*!=\s*true)[^;{}]*\)|"
    r"\bif\s*\([^;{}]*_?initialized[^;{}]*\)\s*revert|"
    r"\bAlreadyInitialized\b|"
    r"\b(?:initialized|_initialized|isInitialized)\s*=\s*true\b|"
    r"\brequire\s*\([^;{}]*(?:owner|admin|router|feeRecipient|dispatcher|"
    r"factory|implementation|beacon|recipient)[^;{}]*(?:==|!=)\s*"
    r"(?:address\s*\(\s*0\s*\)|0|false)[^;{}]*\)|"
    r"\bif\s*\([^;{}]*(?:owner|admin|router|feeRecipient|dispatcher|"
    r"factory|implementation|beacon|recipient)[^;{}]*(?:==|!=)\s*"
    r"(?:address\s*\(\s*0\s*\)|0|false)[^;{}]*\)"
    r")"
)
_AUTH_GUARD_RE = re.compile(
    r"(?is)(?:"
    r"\b(?:onlyOwner|onlyAdmin|onlyGovernance|onlyGovernor|onlyFactory|"
    r"onlyDeployer|onlyRole|onlyRoles|onlyProxyAdmin|onlyConfigurator|"
    r"initializerOnlyFactory|requiresAuth|requireAuth|restricted|auth)\b|"
    r"\b(?:_checkOwner|_checkRole|hasRole|isOwner|isAdmin|_authorize)\s*\(|"
    r"\brequire\s*\([^;{}]*(?:msg\.sender|_msgSender\s*\(\s*\))"
    r"[^;{}]*(?:owner|admin|governance|governor|deployer|factory|"
    r"trustedFactory|expectedFactory|creator|parent|stakingContract|"
    r"proxyAdmin|authority|controller|manager|operator)|"
    r"\brequire\s*\([^;{}]*(?:owner|admin|governance|governor|deployer|"
    r"factory|trustedFactory|expectedFactory|creator|parent|stakingContract|"
    r"proxyAdmin|authority|controller|manager|operator)[^;{}]*"
    r"(?:msg\.sender|_msgSender\s*\(\s*\))|"
    r"\bif\s*\([^;{}]*(?:msg\.sender|_msgSender\s*\(\s*\))\s*!=\s*"
    r"(?:owner|admin|governance|governor|deployer|factory|trustedFactory|"
    r"expectedFactory|creator|parent|stakingContract|proxyAdmin|authority|"
    r"controller|manager|operator)[^;{}]*\)\s*revert|"
    r"\bif\s*\([^;{}]*(?:owner|admin|governance|governor|deployer|factory|"
    r"trustedFactory|expectedFactory|creator|parent|stakingContract|"
    r"proxyAdmin|authority|controller|manager|operator)[^;{}]*!=\s*"
    r"(?:msg\.sender|_msgSender\s*\(\s*\))[^;{}]*\)\s*revert"
    r")"
)
_SAFE_PARENT_BIND_RE = re.compile(
    r"(?is)\b(?:factory|deployer|parent|stakingContract|trustedParent|"
    r"trustedFactory|creator)\s*=\s*(?:msg\.sender|_msgSender\s*\(\s*\))"
)
_MSG_SENDER_OWNABLE_INIT_RE = re.compile(
    r"(?is)\b(?:__?[A-Za-z0-9_]*Ownable[A-Za-z0-9_]*_init|OwnableInit)"
    r"\s*\(\s*(?:msg\.sender|_msgSender\s*\(\s*\))\s*\)"
)
_OWNERSHIP_HANDOFF_RE = re.compile(
    r"(?is)\b(?:transferOwnership|_transferOwnership|setOwner)\s*\("
)
_OWNABLE_INIT_DIRECT_RE = re.compile(
    r"(?is)\b(?:__?[A-Za-z0-9_]*Ownable[A-Za-z0-9_]*_init|OwnableInit)"
    r"\s*\(\s*(?P<arg>[^)]*?(?:owner|admin)[^)]*?)\s*\)"
)
_ROLE_GRANT_RE = re.compile(
    r"(?is)\b(?:_setupRole|_grantRole|grantRole)\s*\("
    r"(?P<args>[^;{}]+?)\)\s*;"
)
_ASSIGN_RE = re.compile(
    r"(?is)(?P<lhs>[A-Za-z_][A-Za-z0-9_]*(?:\s*\[[^;\n]+\])?"
    r"(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*)?)\s*=\s*(?P<rhs>[^;\n]+);"
)
_AUTHORITY_LHS_RE = re.compile(
    r"(?i)(owner|admin|governance|governor|guardian|authority|controller|"
    r"manager|operator|minter|pauser|upgrader|proxyAdmin)"
)
_DESTINATION_LHS_RE = re.compile(
    r"(?i)(feeRecipient|recipient|receiver|dispatcher|router|registry|"
    r"factory|vault|target|aggregator|distributor|gateway|bridge|peer|"
    r"remote|endpoint)"
)
_IMPLEMENTATION_LHS_RE = re.compile(r"(?i)(implementation|impl|beacon|logic)")
_CALLER_VALUE_RE = re.compile(r"(?is)\b(?:msg\.sender|_msgSender\s*\(\s*\)|tx\.origin)\b")
_ZERO_VALUE_RE = re.compile(
    r"(?is)^(?:address\s*\(\s*0\s*\)|0|false|bytes32\s*\(\s*0\s*\))$"
)
_IMPLEMENTATION_CONTEXT_RE = re.compile(
    r"(?is)\b(?:Initializable|UUPSUpgradeable|ERC1967|TransparentUpgradeableProxy|"
    r"BeaconProxy|upgradeTo|upgradeToAndCall|_authorizeUpgrade|implementation|"
    r"logic contract)\b"
)
_DISABLE_INITIALIZERS_RE = re.compile(r"(?is)\b_disableInitializers\s*\(")
_LOCAL_DECL_PREFIX_RE = re.compile(
    r"(?is)(?:address|bool|bytes(?:[0-9]+)?|uint(?:8|16|32|64|128|256)?|"
    r"int(?:8|16|32|64|128|256)?|string)\s+$"
)


def _strip_comments_and_strings(source: str) -> str:
    def replace(match: re.Match[str]) -> str:
        text = match.group(0)
        return "\n" * text.count("\n") if "\n" in text else " "

    return _COMMENT_OR_STRING_RE.sub(replace, source or "")


def _find_matching(source: str, open_pos: int, open_char: str, close_char: str) -> int:
    if open_pos < 0 or open_pos >= len(source) or source[open_pos] != open_char:
        return -1
    depth = 1
    pos = open_pos + 1
    while pos < len(source) and depth > 0:
        if source[pos] == open_char:
            depth += 1
        elif source[pos] == close_char:
            depth -= 1
        pos += 1
    return pos - 1 if depth == 0 else -1


def _split_functions(source: str) -> list[FunctionSlice]:
    out: list[FunctionSlice] = []
    pos = 0
    while True:
        match = _FN_HEADER_RE.search(source, pos)
        if match is None:
            break

        name = match.group("name")
        open_paren = source.find("(", match.end() - 1)
        close_paren = _find_matching(source, open_paren, "(", ")")
        if close_paren < 0:
            pos = match.end()
            continue

        body_start = -1
        scan_pos = close_paren + 1
        while scan_pos < len(source):
            if source[scan_pos] == ";":
                break
            if source[scan_pos] == "{":
                body_start = scan_pos
                break
            scan_pos += 1
        if body_start < 0:
            pos = max(scan_pos, close_paren + 1)
            continue

        body_end = _find_matching(source, body_start, "{", "}")
        if body_end < 0:
            pos = body_start + 1
            continue

        out.append(
            FunctionSlice(
                name=name,
                header=source[match.start():body_start],
                body=source[body_start + 1:body_end],
                function_line=source.count("\n", 0, match.start()) + 1,
                body_line=source.count("\n", 0, body_start + 1) + 1,
            )
        )
        pos = body_end + 1
    return out


def _is_external_entry(fn: FunctionSlice) -> bool:
    return bool(_PUBLIC_HEADER_RE.search(fn.header)) and not _VIEW_HEADER_RE.search(fn.header)


def _parameter_section(header: str) -> str:
    start = header.find("(")
    if start < 0:
        return ""
    end = _find_matching(header, start, "(", ")")
    if end < 0:
        return ""
    return header[start + 1:end]


def _param_names(header: str) -> set[str]:
    return {match.group("name") for match in _PARAM_RE.finditer(_parameter_section(header))}


def _contains_param_or_caller(text: str, params: set[str]) -> bool:
    if _CALLER_VALUE_RE.search(text):
        return True
    return any(re.search(rf"(?<![A-Za-z0-9_]){re.escape(param)}(?![A-Za-z0-9_])", text) for param in params)


def _line_for_body(fn: FunctionSlice, offset: int) -> int:
    return fn.body_line + fn.body.count("\n", 0, max(offset, 0))


def _is_local_declaration(body: str, start: int) -> bool:
    prefix = body[max(0, start - 100):start]
    prefix = prefix.rsplit(";", 1)[-1]
    prefix = prefix.rsplit("{", 1)[-1]
    return bool(_LOCAL_DECL_PREFIX_RE.search(prefix))


def _write_kind(lhs: str) -> str | None:
    if _AUTHORITY_LHS_RE.search(lhs):
        return "authority"
    if _IMPLEMENTATION_LHS_RE.search(lhs):
        return "implementation"
    if _DESTINATION_LHS_RE.search(lhs):
        return "destination"
    return None


def _critical_writes(fn: FunctionSlice, params: set[str]) -> list[CriticalWrite]:
    writes: list[CriticalWrite] = []
    for match in _ASSIGN_RE.finditer(fn.body):
        if _is_local_declaration(fn.body, match.start()):
            continue
        lhs = re.sub(r"\s+", "", match.group("lhs"))
        rhs = match.group("rhs").strip()
        if _ZERO_VALUE_RE.match(rhs):
            continue
        kind = _write_kind(lhs)
        if kind is None:
            continue
        if not _contains_param_or_caller(rhs, params):
            continue
        writes.append(
            CriticalWrite(
                lhs=lhs,
                rhs=re.sub(r"\s+", " ", rhs)[:120],
                line=_line_for_body(fn, match.start()),
                kind=kind,
            )
        )
    return writes


def _role_grants(fn: FunctionSlice, params: set[str]) -> list[CriticalWrite]:
    grants: list[CriticalWrite] = []
    for match in _ROLE_GRANT_RE.finditer(fn.body):
        args = match.group("args").strip()
        if not _contains_param_or_caller(args, params):
            continue
        grants.append(
            CriticalWrite(
                lhs="role grant",
                rhs=re.sub(r"\s+", " ", args)[:120],
                line=_line_for_body(fn, match.start()),
                kind="authority",
            )
        )
    return grants


def _unsafe_ownable_init(fn: FunctionSlice) -> CriticalWrite | None:
    match = _OWNABLE_INIT_DIRECT_RE.search(fn.body)
    if match is None:
        return None
    arg = re.sub(r"\s+", " ", match.group("arg")).strip()
    if re.search(r"(?i)\bmsg\.sender\b|_msgSender\s*\(", arg):
        return None
    return CriticalWrite(
        lhs="ownable initializer",
        rhs=arg[:120],
        line=_line_for_body(fn, match.start()),
        kind="authority",
    )


def _has_safe_caller_binding(fn: FunctionSlice) -> bool:
    return bool(_AUTH_GUARD_RE.search(f"{fn.header}\n{fn.body}"))


def _has_safe_owner_order(fn: FunctionSlice) -> bool:
    body = fn.body
    return bool(_MSG_SENDER_OWNABLE_INIT_RE.search(body) and _OWNERSHIP_HANDOFF_RE.search(body))


def _parent_binding_makes_destination_safe(fn: FunctionSlice, writes: list[CriticalWrite]) -> bool:
    if not writes:
        return False
    if any(write.kind != "destination" for write in writes):
        return False
    return bool(_SAFE_PARENT_BIND_RE.search(fn.body))


def _reasons(
    fn: FunctionSlice,
    source_has_implementation_context: bool,
    implementation_locked: bool,
    writes: list[CriticalWrite],
    role_grants: list[CriticalWrite],
    ownable_init: CriticalWrite | None,
) -> list[str]:
    text = f"{fn.header}\n{fn.body}"
    first_call_gate = bool(_FIRST_CALL_GATE_RE.search(text))
    setter_setup = bool(_SETTER_SETUP_NAME_RE.search(fn.name))
    authority_material = any(write.kind == "authority" for write in writes + role_grants) or ownable_init is not None
    implementation_material = any(write.kind == "implementation" for write in writes)
    destination_material = any(write.kind == "destination" for write in writes)

    reasons: list[str] = []
    if first_call_gate and authority_material:
        reasons.append("first-call owner or role binding")
    if first_call_gate and destination_material:
        reasons.append("first-call router, fee recipient, dispatcher, or clone destination binding")
    if setter_setup and (authority_material or destination_material or implementation_material):
        reasons.append("unguarded setup setter")
    if ownable_init is not None:
        reasons.append("owner passed directly to Ownable init instead of msg.sender setup handoff")
    if source_has_implementation_context and not implementation_locked and (first_call_gate or implementation_material):
        reasons.append("implementation initializer remains callable without _disableInitializers")
    return reasons


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    stripped = _strip_comments_and_strings(source)
    source_has_implementation_context = bool(_IMPLEMENTATION_CONTEXT_RE.search(stripped))
    implementation_locked = bool(_DISABLE_INITIALIZERS_RE.search(stripped))
    findings: list[Finding] = []

    for fn in _split_functions(stripped):
        if not _is_external_entry(fn):
            continue
        if not _ENTRYPOINT_NAME_RE.search(fn.name):
            continue
        if _has_safe_caller_binding(fn):
            continue
        if _has_safe_owner_order(fn):
            continue

        params = _param_names(fn.header)
        writes = _critical_writes(fn, params)
        role_grants = _role_grants(fn, params)
        ownable_init = _unsafe_ownable_init(fn)
        if not writes and not role_grants and ownable_init is None:
            continue
        if ownable_init is None and not role_grants and _parent_binding_makes_destination_safe(fn, writes):
            continue

        reasons = _reasons(
            fn,
            source_has_implementation_context,
            implementation_locked,
            writes,
            role_grants,
            ownable_init,
        )
        if not reasons:
            continue

        evidence = ownable_init or (role_grants[0] if role_grants else writes[0])
        write_desc = f"{evidence.lhs} from {evidence.rhs}"
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=evidence.line,
                severity=DETECTOR_SEVERITY_DEFAULT,
                function=fn.name,
                branch=", ".join(reasons),
                message=(
                    f"`{fn.name}` exposes {', '.join(reasons)}: {write_desc}. "
                    "The path is external or public, lacks owner, factory, deployer, "
                    "role, or parent caller binding, and can let a wrong first caller "
                    "bind privileged setup state. Candidate evidence only. "
                    "NOT_SUBMIT_READY."
                ),
            )
        )

    return findings


__all__ = [
    "scan",
    "Finding",
    "DETECTOR_NAME",
    "DETECTOR_SEVERITY_DEFAULT",
    "SUBMISSION_POSTURE",
]
