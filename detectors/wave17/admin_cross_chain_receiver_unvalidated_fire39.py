"""
admin-cross-chain-receiver-unvalidated-fire39

Solidity recall-lift detector for cross-chain receiver callbacks that
authenticate a remote source and then execute an admin payload without binding
the decoded receiver or local destination to the current contract.

This is not a generic missing-onlyOwner rule. It requires a cross-chain
receiver context, router or endpoint authentication, remote source chain and
sender validation, decoded receiver-like payload material, and a privileged
state mutation. It suppresses functions that explicitly bind the decoded
receiver to address(this), an expected receiver, an allowlist, or a receiver
domain digest before the admin mutation.

Provenance:
- verification_tier: tier-3-synthetic-taxonomy-anchored
- attack_class: admin-bypass
- context_pack_id: auditooor.vault_context_pack.v1:resume:cbdd9eeb5255863c
- context_pack_hash: cbdd9eeb5255863c4870d83e88642e9c4a3eef8e7cdfb8b5fb9a8ee7ac5a25d8
- MCP receipt: .auditooor/memory_context_receipt.json
- source ref: reports/detector_lift_fire38_20260605/post_priorities_solidity.md
- source ref: reference/patterns.dsl/ccip-receiver-and-chain-unvalidated.yaml
- seed miss examples: ccip-receiver-and-chain-unvalidated,
  abi-encode-packed-hash-collision, burn-on-transfer-to-pair-inflates-price
- related detector: admin-receiver-chain-unvalidated-fire25
- related detector: admin-receiver-source-domain-fire26

NOT_SUBMIT_READY. R40/R76/R80 caveat: detector hits are source-review
candidates only, not proof. A hit needs source review, in-scope proof, and a
real non-vacuous PoC before any filing use.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "admin-cross-chain-receiver-unvalidated-fire39"
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
_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_SENDER_RE = r"(?:msg\s*\.\s*sender|_msgSender\s*\(\s*\))"
_RECEIVER_NAME_RE = re.compile(
    r"(?i)(receiver|recipient|destination|dest|targetreceiver|targetcontract|"
    r"receivercontract|localreceiver|adminreceiver|destinationcontract)"
)
_CROSS_CHAIN_CONTEXT_RE = re.compile(
    r"(?is)\b(?:"
    r"ccipReceive|_ccipReceive|Any2EVMMessage|sourceChainSelector|"
    r"lzReceive|_lzReceive|receiveMessage|receiveCrossChain|handleMessage|"
    r"processMessage|executeMessage|onMessage|sourceChainId|sourceDomain|"
    r"srcEid|srcChainId|remoteDomain|endpoint|Endpoint|messenger|Messenger|"
    r"mailbox|Mailbox|bridge|Bridge|gateway|Gateway|router|Router"
    r")\b"
)
_PAYLOAD_DECODE_RE = re.compile(
    r"(?is)abi\s*\.\s*decode\s*\([^;{}]*(?:message|msg_|payload|data|encoded|command)"
)
_DECODE_LHS_RE = re.compile(
    r"(?is)(?P<lhs>\([^;{}]+?\)|(?:[A-Za-z_][A-Za-z0-9_]*\s+){0,4}"
    r"[A-Za-z_][A-Za-z0-9_]*)\s*=\s*abi\s*\.\s*decode\s*\("
)
_ROUTER_OR_ENDPOINT_GUARD_RE = re.compile(
    rf"(?is)(?:"
    rf"\bonly[A-Za-z0-9_]*(?:Router|Endpoint|Bridge|Gateway|Messenger|Mailbox)\b|"
    rf"{_SENDER_RE}\s*(?:==|!=)[^;{{}}]*(?:router|Router|ccipRouter|endpoint|"
    rf"Endpoint|bridge|Bridge|gateway|Gateway|messenger|Messenger|mailbox|Mailbox)|"
    rf"(?:router|Router|ccipRouter|endpoint|Endpoint|bridge|Bridge|gateway|Gateway|"
    rf"messenger|Messenger|mailbox|Mailbox)[^;{{}}]*(?:==|!=)\s*{_SENDER_RE}|"
    rf"\b(?:_validateRouter|validateRouter|_requireRouter|requireRouter|"
    rf"_validateEndpoint|validateEndpoint|_requireEndpoint|requireEndpoint)\s*\("
    rf")"
)
_SOURCE_CHAIN_GUARD_RE = re.compile(
    r"(?is)(?:"
    r"(?:message|msg_?)\s*\.\s*sourceChainSelector\s*(?:==|!=)|"
    r"(?:origin|src|message|msg_?)\s*\.\s*(?:srcEid|sourceChainId|sourceDomain)"
    r"\s*(?:==|!=)|"
    r"(?:sourceChainSelector|sourceChainId|srcChain|srcChainId|sourceChain|"
    r"remoteChain|originChain|sourceDomain|srcDomain|remoteDomain|originDomain|"
    r"srcEid)\s*(?:==|!=)|"
    r"(?:trusted|allowed|approved|enabled|valid|supported)[A-Za-z0-9_]*"
    r"(?:Chains?|Domains?|Eids?)\s*\["
    r")"
)
_SOURCE_SENDER_GUARD_RE = re.compile(
    r"(?is)(?:"
    r"(?:remoteSender|sourceSender|originSender|decodedSender|senderBytes|"
    r"srcSender|trustedRemote|remoteAddress)\s*(?:==|!=)\s*"
    r"(?:TRUSTED|trusted|allowed|expected|approved)[A-Za-z0-9_]*|"
    r"(?:TRUSTED|trusted|allowed|expected|approved)[A-Za-z0-9_]*"
    r"\s*(?:==|!=)\s*(?:remoteSender|sourceSender|originSender|decodedSender|"
    r"senderBytes|srcSender|trustedRemote|remoteAddress)|"
    r"(?:trusted|allowed|approved|enabled|valid)[A-Za-z0-9_]*"
    r"(?:Senders?|Remotes?|Peers?|Sources?|Origins?)\s*\[|"
    r"keccak256\s*\([^;{}]*(?:message|msg_?)\s*\.\s*sender[^;{}]*\)"
    r"\s*(?:==|!=)|"
    r"keccak256\s*\([^;{}]*(?:remoteSender|sourceSender|originSender|"
    r"decodedSender|srcSender)[^;{}]*\)\s*(?:==|!=)"
    r")"
)
_ADMIN_PAYLOAD_RE = re.compile(
    r"(?is)\b(?:"
    r"SET_ADMIN|GRANT_ADMIN|GRANT_ROLE|REVOKE_ROLE|SET_OWNER|SET_GOVERNANCE|"
    r"SET_GUARDIAN|SET_OPERATOR|SET_MANAGER|SET_EXECUTOR|SET_ROUTER|"
    r"ADMIN_ROLE|OPERATOR_ROLE|DEFAULT_ADMIN_ROLE|adminAction|adminCommand|"
    r"messageType|commandType|actionType|newAdmin|newOwner|newGovernor|"
    r"newOperator|newManager|newGuardian|targetAdmin"
    r")\b"
)
_PRIVILEGED_EFFECT_RE = re.compile(
    r"(?is)(?:"
    r"\b_grantRole\s*\(|\bgrantRole\s*\(|\b_setupRole\s*\(|"
    r"\b_revokeRole\s*\(|\brevokeRole\s*\(|"
    r"\b(?:roles|roleMembers|admins|operators|controllers|keepers|managers)"
    r"\s*\[[^;\]]+\]\s*=\s*(?:true|[A-Za-z_][A-Za-z0-9_]*)|"
    r"\b(?:owner|admin|governance|governor|guardian|controller|manager|operator|"
    r"executor|router|oracle|treasury|feeRecipient|config|implementation|"
    r"adminReceiver)\s*=\s*|"
    r"\b(?:trusted|allowed|approved|authorized|whitelist|blacklist)"
    r"[A-Za-z0-9_]*\s*\[[^;\]]+\]\s*=\s*true|"
    r"\b(?:setAdmin|setOwner|setOracle|setRouter|setExecutor|setTrusted|"
    r"executeAdmin|adminCall|upgradeTo|upgradeToAndCall)\s*\("
    r")"
)
_STRONG_LOCAL_ADMIN_RE = re.compile(
    rf"(?is)(?:"
    rf"\bonly(?:Owner|Admin|Governance|Governor|Gov|DAO|Dao|Timelock|"
    rf"RoleAdmin|EmergencyAdmin|ProtocolAdmin|GuardianAdmin)\b|"
    rf"\bonlyRole\s*\([^)]*(?:DEFAULT_ADMIN_ROLE|ADMIN_ROLE|GOVERNANCE_ROLE|"
    rf"GOVERNOR_ROLE|TIMELOCK_ROLE|OWNER_ROLE|PROTOCOL_ADMIN_ROLE)[^)]*\)|"
    rf"\b(?:_checkOwner|_onlyOwner|enforceIsOwner|enforceIsGovernance)\s*\(|"
    rf"\b(?:require|assert)\s*\([^;{{}}]*(?:owner|_owner|admin|_admin|"
    rf"governance|governor|gov|dao|timelock)[^;{{}}]*{_SENDER_RE}[^;{{}}]*\)"
    rf")"
)
_CONDITION_RE = re.compile(r"(?is)\b(?:require|assert|if)\s*\((?P<expr>[^;{}]+)\)")
_RECEIVER_BINDING_WORD_RE = re.compile(
    r"(?i)(expected|trusted|allowed|approved|canonical|local|registered|"
    r"supported|receiver|destination|domain|this|address\s*\(\s*this\s*\)|"
    r"allowlist|whitelist|isReceiver|validReceiver)"
)
_RECEIVER_DIGEST_WORD_RE = re.compile(
    r"(?i)(digest|hash|messageId|messageHash|domain|approved|authorized|valid|"
    r"processed|consumed|seen|checkpoint)"
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


def _has_strong_local_admin(fn: FunctionSlice) -> bool:
    return bool(_STRONG_LOCAL_ADMIN_RE.search(f"{fn.header}\n{fn.body}"))


def _names_from_decode_lhs(lhs: str) -> list[str]:
    text = lhs.strip()
    if text.startswith("(") and text.endswith(")"):
        text = text[1:-1]
    names: list[str] = []
    for part in text.split(","):
        words = _IDENT_RE.findall(part)
        if words:
            names.append(words[-1])
    return names


def _receiver_material(fn: FunctionSlice) -> list[str]:
    names: set[str] = set()
    for param in _params(fn.header):
        if _RECEIVER_NAME_RE.search(param.name):
            names.add(param.name)

    for match in _DECODE_LHS_RE.finditer(fn.body):
        for name in _names_from_decode_lhs(match.group("lhs")):
            if _RECEIVER_NAME_RE.search(name):
                names.add(name)

    for match in re.finditer(
        r"(?is)\b([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*"
        r"(receiver|recipient|destination|targetReceiver|receiverContract|localReceiver)",
        fn.body,
    ):
        names.add(f"{match.group(1)}.{match.group(2)}")

    return sorted(names)


def _contains_name(expr: str, name: str) -> bool:
    if "." in name:
        left, right = name.split(".", 1)
        return bool(re.search(rf"\b{re.escape(left)}\s*\.\s*{re.escape(right)}\b", expr))
    return bool(re.search(rf"\b{re.escape(name)}\b", expr))


def _condition_binds_receiver(expr: str, name: str) -> bool:
    if not _contains_name(expr, name):
        return False
    if re.search(r"(?is)address\s*\(\s*this\s*\)", expr):
        return True
    if _RECEIVER_BINDING_WORD_RE.search(expr) and re.search(r"(?is)(==|!=|\[|\bis[A-Z]|\brequire)", expr):
        return True
    if re.search(r"(?is)(keccak256|abi\s*\.\s*encode)", expr) and _RECEIVER_DIGEST_WORD_RE.search(expr):
        return True
    return False


def _receiver_bound_by_digest(body: str, names: list[str]) -> bool:
    for name in names:
        if not re.search(
            rf"(?is)keccak256\s*\((?=[^;{{}}]*address\s*\(\s*this\s*\))"
            rf"(?=[^;{{}}]*\b{re.escape(name)}\b)[^;{{}}]*\)",
            body,
        ):
            continue
        if re.search(r"(?is)\b(?:require|assert)\s*\([^;{}]*(?:digest|messageHash|messageId|approved|authorized|valid|processed|consumed)", body):
            return True
    return False


def _receiver_binding_present(fn: FunctionSlice, names: list[str]) -> bool:
    if _receiver_bound_by_digest(fn.body, names):
        return True
    text = f"{fn.header}\n{fn.body}"
    for name in names:
        for match in _CONDITION_RE.finditer(text):
            if _condition_binds_receiver(match.group("expr"), name):
                return True
    return False


def _has_required_cross_chain_guards(fn: FunctionSlice) -> bool:
    text = f"{fn.header}\n{fn.body}"
    return (
        bool(_ROUTER_OR_ENDPOINT_GUARD_RE.search(text))
        and bool(_SOURCE_CHAIN_GUARD_RE.search(text))
        and bool(_SOURCE_SENDER_GUARD_RE.search(text))
    )


def _receiver_validation_gap(fn: FunctionSlice) -> tuple[list[str], list[str]]:
    text = f"{fn.name}\n{fn.header}\n{fn.body}"
    if not _is_external_mutator(fn):
        return [], []
    if _has_strong_local_admin(fn):
        return [], []
    if not _CROSS_CHAIN_CONTEXT_RE.search(text):
        return [], []
    if not _PAYLOAD_DECODE_RE.search(fn.body):
        return [], []
    if not _ADMIN_PAYLOAD_RE.search(text):
        return [], []
    if not _PRIVILEGED_EFFECT_RE.search(fn.body):
        return [], []
    if not _has_required_cross_chain_guards(fn):
        return [], []

    receiver_names = _receiver_material(fn)
    if not receiver_names:
        return [], []
    if _receiver_binding_present(fn, receiver_names):
        return [], []

    guards = ["router or endpoint", "source chain", "source sender"]
    return receiver_names, guards


def _finding(file_path: str, line: int, function: str, names: list[str], guards: list[str]) -> Finding:
    return Finding(
        detector=DETECTOR_NAME,
        file=file_path,
        line=line,
        severity=DETECTOR_SEVERITY_DEFAULT,
        function=function,
        message=(
            "cross-chain admin receiver validates "
            f"{', '.join(guards)} but does not bind decoded receiver material "
            f"({', '.join(names)}) to address(this), an expected receiver, or a "
            "receiver-domain digest before a privileged mutation. "
            "NOT_SUBMIT_READY: detector hit is a source-review candidate only."
        ),
    )


def scan(source: str, file_path: str = "<memory>") -> list[Finding]:
    code = _strip_comments_and_strings(source)
    findings: list[Finding] = []
    for fn in _split_functions(code):
        names, guards = _receiver_validation_gap(fn)
        if names:
            findings.append(_finding(file_path, fn.line, fn.name, names, guards))
    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
