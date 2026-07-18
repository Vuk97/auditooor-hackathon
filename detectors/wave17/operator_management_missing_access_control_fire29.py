"""
operator-management-missing-access-control-fire29

Solidity recall-lift detector for public or external operator, guardian,
manager, relayer, signer, executor, keeper, validator, admin, or role-admin
management functions that mutate privileged membership state without a
same-function owner, admin, governance, role, or equivalent sender-bound guard.

Provenance:
- context_pack_id: auditooor.vault_context_pack.v1:resume:1fbd7a4998da1f42
- context_pack_hash: 1fbd7a4998da1f424cce0858c69a5dd246edb458f1cb9f1927dd25e36d73cb98
- source ref: reference/patterns.dsl/admin-bypass-umbrella.yaml
- source ref: reference/patterns.dsl/admin-bypass-wrong-domain-or-missing-guard.yaml
- source ref: reference/patterns.dsl.r94_solodit_accesscontrol/onlyowneroradministrator-allows-either-role-to-override-the-other-s-config.yaml
- attack_class: admin-bypass

Hits are candidate evidence only. NOT_SUBMIT_READY.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "operator-management-missing-access-control-fire29"
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
_PUBLIC_HEADER_RE = re.compile(r"\b(?:external|public)\b")
_VIEW_HEADER_RE = re.compile(r"\b(?:view|pure)\b")

_MANAGEMENT_VERBS = (
    "add",
    "remove",
    "delete",
    "set",
    "update",
    "change",
    "replace",
    "rotate",
    "register",
    "unregister",
    "grant",
    "revoke",
    "assign",
    "appoint",
    "promote",
    "demote",
    "enable",
    "disable",
)
_MANAGEMENT_NOUNS = (
    "operator",
    "guardian",
    "manager",
    "relayer",
    "signer",
    "executor",
    "roleadmin",
    "admin",
    "keeper",
    "validator",
)
_ACTOR_WORD_RE = re.compile(
    r"(?i)(operator|guardian|manager|relayer|signer|executor|roleAdmin|admin|keeper|validator)"
)
_STATE_MAP_RE = re.compile(
    r"(?is)\b(?P<prefix>delete\s+)?"
    r"(?P<name>"
    r"operators|operatorSet|isOperator|guardians|guardianSet|isGuardian|"
    r"managers|managerSet|isManager|relayers|relayerSet|isRelayer|"
    r"signers|signerSet|isSigner|executors|executorSet|isExecutor|"
    r"keepers|keeperSet|isKeeper|validators|validatorSet|isValidator|"
    r"admins|adminSet|isAdmin|roleAdmins|roleAdmin|roles|roleMembers"
    r")\s*\[\s*(?P<key>[^\]]+)\]\s*(?P<op>=|;)"
)
_STATE_ARRAY_RE = re.compile(
    r"(?is)\b(?P<name>"
    r"operators|guardians|managers|relayers|signers|executors|keepers|validators|admins"
    r")\s*\.\s*(?:push|pop)\s*\("
)
_SCALAR_ASSIGN_RE = re.compile(
    r"(?is)\b(?P<name>"
    r"(?:operator|guardian|manager|relayer|signer|executor|roleAdmin|admin|keeper|validator)"
    r"(?:Address|Account|Wallet|Signer|Admin|Manager|Role)?"
    r")\s*="
)
_ROLE_CALL_RE = re.compile(
    r"(?is)\b(?P<call>_grantRole|grantRole|_revokeRole|revokeRole|_setRoleAdmin|setRoleAdmin)"
    r"\s*\((?P<args>[^;{}]+)\)"
)
_ROLE_ACTOR_ARG_RE = re.compile(
    r"(?i)(DEFAULT_ADMIN_ROLE|ADMIN_ROLE|OPERATOR_ROLE|GUARDIAN_ROLE|MANAGER_ROLE|"
    r"RELAYER_ROLE|SIGNER_ROLE|EXECUTOR_ROLE|KEEPER_ROLE|VALIDATOR_ROLE|roleAdmin|adminRole)"
)
_NON_AUTH_INPUT_CHECK_RE = re.compile(
    r"(?is)\brequire\s*\([^;{}]*(?:!=\s*address\s*\(\s*0\s*\)|address\s*\(\s*0\s*\)\s*!=|"
    r"length\s*[!<>=]|enabled|paused|whenNotPaused|notPaused)"
)
_AUTH_GUARD_RE = re.compile(
    r"(?is)(?:"
    r"\b(?:onlyOwner|onlyAdmin|onlyRole|onlyRoles|onlyGovernance|onlyGovernor|"
    r"onlyGov|onlyDAO|onlyDao|onlyTimelock|onlyFactory|onlyController|"
    r"onlyManager|onlyOperator|onlyGuardian|onlyExecutor|onlyRelayer|onlySigner|"
    r"onlyKeeper|onlyValidator|onlyRoleAdmin|onlyOwnerOrAdministrator|"
    r"requiresAuth|requireAuth|restricted|auth)\b|"
    r"\b(?:_checkRole|_checkOwner|_onlyOwner|isOwner|isAdmin|isAuthorized|"
    r"enforceIsOwner|enforceIsContractOwner|enforceIsGovernance)\s*\(|"
    r"\bhasRole\s*\([^;{}]*(?:msg\.sender|_msgSender\s*\(\s*\))|"
    r"\brequire\s*\([^;{}]*(?:msg\.sender|_msgSender\s*\(\s*\))"
    r"[^;{}]*(?:owner|_owner|admin|_admin|governance|governor|gov|dao|timelock|"
    r"factory|controller|manager|operator|guardian|executor|relayer|signer|keeper|"
    r"validator|authorized)|"
    r"\brequire\s*\([^;{}]*(?:owner|_owner|admin|_admin|governance|governor|gov|dao|"
    r"timelock|factory|controller|manager|operator|guardian|executor|relayer|signer|"
    r"keeper|validator|authorized)"
    r"[^;{}]*(?:msg\.sender|_msgSender\s*\(\s*\))|"
    r"\bif\s*\([^;{}]*(?:msg\.sender|_msgSender\s*\(\s*\))"
    r"[^;{}]*(?:!=|==)[^;{}]*(?:owner|_owner|admin|_admin|governance|governor|"
    r"factory|controller|manager|operator|guardian|executor|relayer|signer|keeper|"
    r"validator)[^;{}]*(?:revert|throw)|"
    r"\b(?:authorized|isAuthorized|admins|operators|guardians|managers|relayers|"
    r"signers|executors|keepers|validators)\s*\[\s*(?:msg\.sender|_msgSender\s*\(\s*\))\s*\]"
    r")"
)
_BAD_AUTH_ONLY_RE = re.compile(r"(?is)\btx\s*\.\s*origin\b")
_SELF_SENDER_RE = re.compile(r"(?is)\b(?:msg\.sender|_msgSender\s*\(\s*\))\b")
_LOCAL_DECL_PREFIX_RE = re.compile(
    r"(?is)\b(?:address|bool|uint(?:256|128|64|32|16|8)?|bytes32|string)\s+$"
)
_SKIP_NAME_RE = re.compile(r"(?i)(approval|allowance|delegate|delegation)")


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


def _normalized_name(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def _has_management_name(name: str) -> bool:
    normalized = _normalized_name(name)
    return (
        any(verb in normalized for verb in _MANAGEMENT_VERBS)
        and any(noun in normalized for noun in _MANAGEMENT_NOUNS)
    )


def _is_local_scalar_declaration(body: str, start: int) -> bool:
    prefix = body[max(0, start - 32):start]
    return bool(_LOCAL_DECL_PREFIX_RE.search(prefix))


def _mapping_writes(body: str) -> list[tuple[str, str]]:
    writes: list[tuple[str, str]] = []
    for match in _STATE_MAP_RE.finditer(body):
        name = match.group("name")
        if _SKIP_NAME_RE.search(name):
            continue
        writes.append((name, match.group("key")))
    return writes


def _scalar_writes(body: str) -> list[str]:
    writes: list[str] = []
    for match in _SCALAR_ASSIGN_RE.finditer(body):
        if _is_local_scalar_declaration(body, match.start()):
            continue
        name = match.group("name")
        if _SKIP_NAME_RE.search(name):
            continue
        writes.append(name)
    return writes


def _role_management_calls(body: str) -> list[str]:
    calls: list[str] = []
    for match in _ROLE_CALL_RE.finditer(body):
        args = match.group("args")
        if _ROLE_ACTOR_ARG_RE.search(args):
            calls.append(match.group("call"))
    return calls


def _array_management_calls(body: str) -> list[str]:
    return [match.group("name") for match in _STATE_ARRAY_RE.finditer(body)]


def _management_write_kinds(body: str) -> list[str]:
    kinds: list[str] = []
    kinds.extend(f"mapping:{name}" for name, _key in _mapping_writes(body))
    kinds.extend(f"scalar:{name}" for name in _scalar_writes(body))
    kinds.extend(f"role:{call}" for call in _role_management_calls(body))
    kinds.extend(f"array:{name}" for name in _array_management_calls(body))
    return kinds


def _self_service_only(body: str) -> bool:
    mappings = _mapping_writes(body)
    if not mappings:
        return False
    if _scalar_writes(body) or _role_management_calls(body) or _array_management_calls(body):
        return False
    return all(_SELF_SENDER_RE.search(key) for _name, key in mappings)


def _has_effective_auth_guard(header: str, body: str) -> bool:
    text = f"{header}\n{body}"
    if not _AUTH_GUARD_RE.search(text):
        return False
    if _BAD_AUTH_ONLY_RE.search(text) and not re.search(r"(?is)\bmsg\s*\.\s*sender\b", text):
        return False
    return True


def _operator_management_gap(fn: FunctionSlice) -> bool:
    if not _is_external_mutator(fn):
        return False
    if not _has_management_name(fn.name):
        return False
    if _has_effective_auth_guard(fn.header, fn.body):
        return False
    if _self_service_only(fn.body):
        return False
    return bool(_management_write_kinds(fn.body))


def _finding(file_path: str, line: int, function: str, body: str) -> Finding:
    kinds = ", ".join(sorted(set(_management_write_kinds(body)))) or "privileged membership state"
    input_check_note = (
        " A zero-address or input-validation check is present, but it is not an "
        "authority guard."
        if _NON_AUTH_INPUT_CHECK_RE.search(body)
        else ""
    )
    return Finding(
        detector=DETECTOR_NAME,
        file=file_path,
        line=line,
        severity=DETECTOR_SEVERITY_DEFAULT,
        function=function,
        message=(
            "operator management function mutates privileged membership state "
            f"({kinds}) with missing owner/admin/role guard."
            f"{input_check_note} NOT_SUBMIT_READY: detector fixture smoke evidence only."
        ),
    )


def scan(source: str, file_path: str = "<memory>") -> list[Finding]:
    code = _strip_comments_and_strings(source)
    findings: list[Finding] = []
    for fn in _split_functions(code):
        if _operator_management_gap(fn):
            findings.append(_finding(file_path, fn.line, fn.name, fn.body))
    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
