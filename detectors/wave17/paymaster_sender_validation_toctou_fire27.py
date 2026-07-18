"""
paymaster-sender-validation-toctou-fire27

Regex API detector for ERC-4337 paymaster validation paths where sender
policy is checked in validatePaymasterUserOp but the checked sender is not
carried into the later postOp, charge, mutation, or EntryPoint-facing use.

Source refs:
- reference/patterns.dsl/erc4337-paymaster-no-sender-validation.yaml
- reference/patterns.dsl/fx-v4core-swap-fee-equality-check.yaml
- reference/patterns.dsl/lido-deposit-blocked-by-attacker.yaml

This is candidate evidence only. It is not a generic sender-validation
detector: it requires ERC-4337 paymaster vocabulary and a validation-to-use
boundary before reporting.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "paymaster-sender-validation-toctou-fire27"
DETECTOR_SEVERITY_DEFAULT = "Medium"


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
_CALLABLE_RE = re.compile(r"\b(?:external|public|internal)\b")
_VALIDATE_NAME_RE = re.compile(r"(?i)^_?validatePaymasterUserOp$")
_POSTOP_OR_CHARGE_RE = re.compile(
    r"(?i)^(?:_?postOp|_?charge[A-Za-z0-9_]*|_?record[A-Za-z0-9_]*|"
    r"_?consume[A-Za-z0-9_]*|_?debit[A-Za-z0-9_]*|_?spend[A-Za-z0-9_]*)$"
)
_ERC4337_VOCAB_RE = re.compile(
    r"(?is)\b(validatePaymasterUserOp|postOp|UserOperation|PackedUserOperation|"
    r"sender|paymaster|EntryPoint)\b"
)
_USEROP_PARAM_RE = re.compile(
    r"\b(?P<type>[A-Za-z_][A-Za-z0-9_]*(?:UserOperation|UserOp)[A-Za-z0-9_]*)\s+"
    r"(?:calldata|memory|storage)?\s*"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b"
)
_ADDRESS_PARAM_RE = re.compile(
    r"\baddress(?:\s+payable)?\s+(?P<name>sender|account|wallet|user|userAccount)\b",
    re.IGNORECASE,
)
_ALIAS_ASSIGN_RE = re.compile(
    r"(?is)\b(?:address(?:\s+payable)?\s+)?"
    r"(?P<alias>sender|account|wallet|user|userAccount|senderAccount)\s*=\s*"
    r"(?P<src>[A-Za-z_][A-Za-z0-9_]*\s*\.\s*sender)\b"
)
_CHECK_RE = re.compile(r"(?is)\b(?P<kind>require|assert|if)\s*\((?P<expr>[^;{}]*)\)")
_POLICY_RE = re.compile(
    r"(?i)\b(sponsor|sponsored|sponsorship|quota|allow|whitelist|whiteList|"
    r"approved|authorized|eligible|class|tier|balance|deposit|credit|budget|"
    r"limit|policy|sender)\b"
)
_SUCCESS_RE = re.compile(
    r"(?is)\b(SIG_VALIDATION_SUCCESS|validationData|_packValidationData|"
    r"return\s*\([^;]*(?:0|bytes32\s*\(\s*0\s*\)))"
)
_ABI_ENCODE_RE = re.compile(r"(?is)\babi\.encode(?:Packed)?\s*\((?P<args>[^;{}]*)\)")
_ABI_DECODE_ADDRESS_RE = re.compile(
    r"(?is)\babi\.decode\s*\([^;{}]*context[^;{}]*,\s*\([^)]*\baddress\b"
)
_STATE_NAME_RE = (
    r"(?:"
    r"[A-Za-z_][A-Za-z0-9_]*(?:Quota|quota|Budget|budget|Balance|balance|"
    r"Spent|spent|Charged|charged|Deposit|deposit|Sponsor|sponsor|Gas|gas)"
    r"[A-Za-z0-9_]*|"
    r"quota|budget|balance|spent|charged|deposit|sponsor|sponsored|gas|gasUsed"
    r")"
)
_CHARGE_OR_MUTATION_RE = re.compile(
    r"(?is)\b(actualGasCost|maxCost|gasCost|quota|sponsor|sponsored|spent|"
    r"charged|charge|budget|balance|deposit|EntryPoint|entryPoint)\b"
)
_UNBOUND_MUTATION_RE = re.compile(
    r"(?is)"
    r"(?:"
    rf"\b{_STATE_NAME_RE}"
    r"\s*(?:=|\+=|-=|\+\+|--)|"
    rf"\b{_STATE_NAME_RE}"
    r"\s*\[\s*(?:msg\.sender|entryPoint|paymaster|address\s*\(\s*this\s*\))\s*\]"
    r"\s*(?:=|\+=|-=|\+\+|--)|"
    r"\b(?:charge|debit|consume|spend|record)[A-Za-z0-9_]*\s*\("
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
        char = source[i]
        if char == "{":
            depth += 1
        elif char == "}":
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
            char = source[i]
            if char == "(":
                depth_paren += 1
            elif char == ")":
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
            pos = max(j, i)
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


def _normalise_expr(expr: str) -> str:
    return re.sub(r"\s+", "", expr or "")


def _expr_regex(expr: str) -> str:
    return r"\s*\.\s*".join(re.escape(part) for part in _normalise_expr(expr).split("."))


def _identity_re(identity: str) -> re.Pattern[str]:
    norm = _normalise_expr(identity)
    if "." in norm:
        return re.compile(_expr_regex(norm))
    return re.compile(rf"\b{re.escape(norm)}\b")


def _contains_identity(text: str, identities: list[str]) -> bool:
    return any(_identity_re(identity).search(text) for identity in identities)


def _sender_aliases(fn: FunctionSlice) -> list[str]:
    aliases: list[str] = []
    for match in _USEROP_PARAM_RE.finditer(fn.header):
        alias = f"{match.group('name')}.sender"
        if alias not in aliases:
            aliases.append(alias)

    if "userOp.sender" in _normalise_expr(fn.header + fn.body) and "userOp.sender" not in aliases:
        aliases.append("userOp.sender")

    for match in _ADDRESS_PARAM_RE.finditer(fn.header):
        name = match.group("name")
        if name not in aliases:
            aliases.append(name)

    for match in _ALIAS_ASSIGN_RE.finditer(fn.body):
        src = _normalise_expr(match.group("src"))
        if src in [_normalise_expr(alias) for alias in aliases]:
            alias = match.group("alias")
            if alias not in aliases:
                aliases.append(alias)
    return aliases


def _line_for_body_match(fn: FunctionSlice, match: re.Match[str]) -> int:
    return fn.line + fn.body.count("\n", 0, match.start())


def _policy_checks(fn: FunctionSlice, aliases: list[str]) -> list[re.Match[str]]:
    checks: list[re.Match[str]] = []
    for match in _CHECK_RE.finditer(fn.body):
        expr = match.group("expr")
        tail = fn.body[match.end():match.end() + 160]
        if not _POLICY_RE.search(expr + tail):
            continue
        if _contains_identity(expr, aliases) or re.search(r"\b[A-Za-z_][A-Za-z0-9_]*\s*\.\s*sender\b", expr):
            checks.append(match)
    return checks


def _function_call_binds_sender(fn: FunctionSlice, aliases: list[str]) -> bool:
    if not aliases:
        return False
    for match in re.finditer(
        r"(?is)\b(?:verify|validate|check|authorize|approve|bind|consume|charge)"
        r"[A-Za-z0-9_]*(?:Sender|Account|Sponsor|Quota|Policy|Intent)?\s*"
        r"\((?P<args>[^;{}]*)\)",
        fn.body,
    ):
        if _contains_identity(match.group("args"), aliases):
            return True
    return False


def _has_sender_binding_guard(fn: FunctionSlice, aliases: list[str]) -> bool:
    return bool(_policy_checks(fn, aliases)) or _function_call_binds_sender(fn, aliases)


def _context_binds_sender(fn: FunctionSlice, aliases: list[str]) -> bool:
    for match in _ABI_ENCODE_RE.finditer(fn.body):
        if _contains_identity(match.group("args"), aliases):
            return True
    return False


def _sender_keyed_use_re(identity: str) -> re.Pattern[str]:
    ident = _expr_regex(identity)
    return re.compile(
        rf"(?is)"
        rf"(?:"
        rf"\b{_STATE_NAME_RE}\s*\[\s*{ident}\s*\]\s*(?:=|\+=|-=|\+\+|--)|"
        rf"\b(?:charge|debit|consume|spend|record)[A-Za-z0-9_]*\s*\([^;{{}}]*{ident}"
        rf")"
    )


def _has_sender_keyed_use(text: str, aliases: list[str]) -> bool:
    return any(_sender_keyed_use_re(alias).search(text) for alias in aliases)


def _direct_sender_keyed_use_after(fn: FunctionSlice, aliases: list[str], offset: int) -> bool:
    return _has_sender_keyed_use(fn.body[offset:], aliases)


def _postop_binds_sender(fn: FunctionSlice) -> bool:
    if not _ABI_DECODE_ADDRESS_RE.search(fn.body):
        return False
    return _has_sender_keyed_use(fn.body, ["sender", "account", "wallet", "user", "userAccount"])


def _postop_has_charge(fn: FunctionSlice) -> bool:
    return bool(_CHARGE_OR_MUTATION_RE.search(fn.body) and _UNBOUND_MUTATION_RE.search(fn.body))


def _postop_has_unbound_charge(fn: FunctionSlice) -> bool:
    return _postop_has_charge(fn) and not _postop_binds_sender(fn)


def _validation_has_unbound_mutation(fn: FunctionSlice, aliases: list[str], offset: int) -> bool:
    tail = fn.body[offset:]
    if _direct_sender_keyed_use_after(fn, aliases, offset):
        return False
    return bool(_UNBOUND_MUTATION_RE.search(tail))


def _returns_success_without_sender_binding(fn: FunctionSlice, aliases: list[str]) -> tuple[bool, int]:
    if _has_sender_binding_guard(fn, aliases):
        return False, fn.line
    match = _SUCCESS_RE.search(fn.body)
    if match is None:
        return False, fn.line
    if not aliases:
        return False, fn.line
    return True, _line_for_body_match(fn, match)


def _match_validation(
    fn: FunctionSlice,
    post_ops: list[FunctionSlice],
) -> tuple[int, str] | None:
    if not _CALLABLE_RE.search(fn.header):
        return None
    aliases = _sender_aliases(fn)
    if not aliases:
        return None

    open_paymaster, open_line = _returns_success_without_sender_binding(fn, aliases)
    if open_paymaster:
        return (
            open_line,
            "returns paymaster validation success without binding UserOperation.sender "
            "to an allowlist, intent, quota, or account policy",
        )

    checks = _policy_checks(fn, aliases)
    if not checks:
        return None

    first_check = checks[0]
    check_line = _line_for_body_match(fn, first_check)
    check_end = first_check.end()

    direct_use = _direct_sender_keyed_use_after(fn, aliases, check_end)
    context_binds = _context_binds_sender(fn, aliases)
    postop_bound = any(_postop_binds_sender(post_op) for post_op in post_ops)
    postop_charge = any(_postop_has_charge(post_op) for post_op in post_ops)
    postop_unbound = any(_postop_has_unbound_charge(post_op) for post_op in post_ops)
    unbound_mutation = _validation_has_unbound_mutation(fn, aliases, check_end)

    if direct_use:
        return None
    if context_binds and postop_bound and not postop_unbound:
        return None
    if not postop_charge and not unbound_mutation:
        return None
    if postop_unbound or unbound_mutation or not context_binds:
        return (
            check_line,
            "checks sender sponsorship, quota, class, or balance before validation "
            "success, but the later postOp or charge path does not carry that "
            "checked sender into a sender-keyed mutation",
        )
    return None


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    findings: list[Finding] = []
    if not _ERC4337_VOCAB_RE.search(source or ""):
        return findings

    clean_source = _strip_comments_and_strings(source)
    if not _ERC4337_VOCAB_RE.search(clean_source):
        return findings

    functions = _split_functions(clean_source)
    post_ops = [fn for fn in functions if _POSTOP_OR_CHARGE_RE.search(fn.name)]

    for fn in functions:
        if not _VALIDATE_NAME_RE.search(fn.name):
            continue
        matched = _match_validation(fn, post_ops)
        if matched is None:
            continue
        line, reason = matched
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=line,
                severity=DETECTOR_SEVERITY_DEFAULT,
                function=fn.name,
                message=(
                    f"`{fn.name}` has an ERC-4337 paymaster sender validation "
                    f"check-use boundary: {reason}. Bind userOp.sender in the "
                    "paymaster context and charge or mutate sender-keyed state "
                    "from that bound account."
                ),
            )
        )
    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
