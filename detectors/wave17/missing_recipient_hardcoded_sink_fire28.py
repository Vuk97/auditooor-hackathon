"""
missing-recipient-hardcoded-sink-fire28

Regex API detector for withdraw, claim, exchange, and bridge paths that take a
recipient-like address but route the value transfer to msg.sender, owner,
vault, router, or another hardcoded sink.

This is candidate evidence only. It intentionally does not treat a zero-address
check as a binding guard. It suppresses functions that forward the recipient to
the transfer edge, bind the recipient to the hardcoded sink with an equality
guard, or assign a local payout alias from the recipient before transfer.

Source refs:
- reference/patterns.dsl/withdraw-claim-recipient-ignored-hardcoded-sink.yaml
- reference/patterns.dsl/dh-odos-exchange-unset-toReceiver.yaml
- reference/patterns.dsl.r94_solodit_r97_incremental/h-02-missing-recipient-validation-in-process-transaction-function.yaml
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "missing-recipient-hardcoded-sink-fire28"
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
    body_line: int


_COMMENT_RE = re.compile(r"//[^\n\r]*|/\*.*?\*/", re.DOTALL)
_FN_HEADER_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_STRUCT_HEADER_RE = re.compile(r"\bstruct\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\{")
_CALLABLE_HEADER_RE = re.compile(r"\b(?:external|public)\b")
_ADDRESS_PARAM_RE = re.compile(
    r"\baddress(?:\s+payable)?\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
)
_STRUCT_PARAM_RE = re.compile(
    r"\b(?P<type>[A-Z][A-Za-z0-9_]*)\s+"
    r"(?:calldata|memory|storage)?\s*"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b"
)
_RECIPIENT_NAME_RE = re.compile(
    r"(?i)(^_?to$|recipient|receiver|payee|beneficiary|payout|refund|"
    r"toReceiver|dstReceiver|destination|recipientAddress|receiverAddress)"
)
_RECIPIENT_FIELD_RE = re.compile(
    r"(?i)\baddress(?:\s+payable)?\s+"
    r"(?P<field>_?to|recipient|receiver|payee|beneficiary|payoutTo|"
    r"refundTo|toReceiver|dstReceiver|destination|recipientAddress|receiverAddress)\b"
)
_RECIPIENT_REF_RE = re.compile(
    r"(?i)\b(?P<root>[A-Za-z_][A-Za-z0-9_]*)\s*\.\s*"
    r"(?P<field>_?to|recipient|receiver|payee|beneficiary|payoutTo|"
    r"refundTo|toReceiver|dstReceiver|destination|recipientAddress|receiverAddress)\b"
)
_FLOW_NAME_RE = re.compile(
    r"(?i)^(withdraw|redeem|claim|claimFees|claimReward|refund|release|exit|"
    r"bridge|bridgeExit|payout|payOut|swap|exchange|process|settle|fill|"
    r"execute)[A-Za-z0-9_]*$"
)
_FLOW_CONTEXT_RE = re.compile(
    r"(?i)\b(withdraw|redeem|claim|refund|release|exit|bridge|swap|exchange|"
    r"settle|payout|payee|recipient|receiver|vault|escrow|router|odos|"
    r"amountOut|proceeds|assets|shares|claimable)\b"
)
_VALUE_CONTEXT_RE = re.compile(
    r"(?i)\b(safeTransfer|transfer\s*\(|sendValue|call\s*\{|_transfer|"
    r"amount|assets|shares|claimable|proceeds|amountOut|refund|payout)\b"
)
_SINK_EXPR = (
    r"(?:payable\s*\(\s*)?"
    r"(?:msg\.sender|_msgSender\s*\(\s*\)|tx\.origin|owner\s*\(\s*\)|"
    r"address\s*\(\s*this\s*\)|[A-Za-z_][A-Za-z0-9_]*"
    r"(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*(?:\s*\(\s*\))?)*"
    r"(?:\s*\(\s*\))?)"
    r"(?:\s*\))?"
)
_TRANSFER_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "transfers token value to hardcoded sink",
        re.compile(
            rf"\b(?:safeTransfer|transfer|sendValue)\s*\(\s*(?P<sink>{_SINK_EXPR})\s*,",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "transfers token value to hardcoded sink",
        re.compile(
            rf"\b(?:safeTransfer|safeTransferETH)\s*\(\s*[^,;{{}}]+,\s*"
            rf"(?P<sink>{_SINK_EXPR})\s*,",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "moves internal balance to hardcoded sink",
        re.compile(
            rf"\b(?:_transfer|_safeTransfer)\s*\(\s*[^,;{{}}]+,\s*"
            rf"(?P<sink>{_SINK_EXPR})\s*,",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "routes native value to hardcoded sink",
        re.compile(
            rf"\bpayable\s*\(\s*(?P<sink>{_SINK_EXPR})\s*\)\s*"
            rf"\.\s*(?:call|transfer|send)\b",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "routes native value to hardcoded sink",
        re.compile(
            rf"\b(?P<sink>{_SINK_EXPR})\s*\.\s*call\s*\{{\s*value\s*:",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
]
_HARDCODED_DIRECT_RE = re.compile(
    r"(?i)^(msg\.sender|_msgSender\(\)|tx\.origin|owner\(\)|owner|"
    r"address\(this\)|this|vault|router|escrow|treasury|protocol|"
    r"feeReceiver|feeCollector|account|payer|operator|executor|relayer|"
    r"maker|taker|order\.maker|order\.owner|request\.account|"
    r"withdrawal\.account|claim\.owner|position\.owner)$"
)
_ASSIGNMENT_RE = re.compile(
    r"(?is)\b(?:address(?:\s+payable)?\s+)?"
    r"(?P<left>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<right>[^;]+);"
)
_REVERT_WORD_RE = re.compile(
    r"(?i)(revert|RecipientMismatch|InvalidRecipient|InvalidReceiver|"
    r"BadRecipient|BadReceiver|NotRecipient|Unauthorized)"
)


def _strip_comments(source: str) -> str:
    def replace(match: re.Match[str]) -> str:
        text = match.group(0)
        return "\n" * text.count("\n") if "\n" in text else " "

    return _COMMENT_RE.sub(replace, source or "")


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
        if not match:
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
        body_line = source.count("\n", 0, body_start + 1) + 1
        out.append(FunctionSlice(name=name, header=header, body=body, body_line=body_line))
        pos = end_pos
    return out


def _struct_recipient_fields(source: str) -> dict[str, list[str]]:
    fields_by_type: dict[str, list[str]] = {}
    pos = 0
    while True:
        match = _STRUCT_HEADER_RE.search(source, pos)
        if not match:
            break
        open_brace = source.find("{", match.end() - 1)
        body, end_pos = _extract_balanced_block(source, open_brace)
        if body is None:
            pos = match.end()
            continue
        fields: list[str] = []
        for field_match in _RECIPIENT_FIELD_RE.finditer(body):
            field = field_match.group("field")
            if field not in fields:
                fields.append(field)
        if fields:
            fields_by_type[match.group("name")] = fields
        pos = end_pos
    return fields_by_type


def _line_for(fn: FunctionSlice, match: re.Match[str]) -> int:
    return fn.body_line + fn.body.count("\n", 0, match.start())


def _normalise_expr(expr: str) -> str:
    norm = re.sub(r"\s+", "", expr or "")
    while norm.startswith("payable(") and norm.endswith(")"):
        norm = norm[len("payable("):-1]
    return norm


def _expr_regex(expr: str) -> str:
    return r"\s*\.\s*".join(re.escape(part) for part in _normalise_expr(expr).split("."))


def _recipient_sources(fn: FunctionSlice, struct_fields: dict[str, list[str]]) -> list[str]:
    sources: list[str] = []
    for match in _ADDRESS_PARAM_RE.finditer(fn.header):
        name = match.group("name")
        if _RECIPIENT_NAME_RE.search(name):
            sources.append(_normalise_expr(name))

    for match in _STRUCT_PARAM_RE.finditer(fn.header):
        type_name = match.group("type")
        param_name = match.group("name")
        for field in struct_fields.get(type_name, []):
            sources.append(_normalise_expr(f"{param_name}.{field}"))

    for match in _RECIPIENT_REF_RE.finditer(fn.header + fn.body):
        sources.append(_normalise_expr(f"{match.group('root')}.{match.group('field')}"))

    deduped: list[str] = []
    for source in sources:
        if source and source not in deduped:
            deduped.append(source)
    return deduped


def _value_sinks(body: str) -> list[tuple[str, str, re.Match[str]]]:
    sinks: list[tuple[str, str, re.Match[str]]] = []
    for reason, pattern in _TRANSFER_PATTERNS:
        for match in pattern.finditer(body):
            sinks.append((reason, _normalise_expr(match.group("sink")), match))
    return sinks


def _assignment_facts(
    body: str,
    sources: list[str],
) -> tuple[set[str], set[str], set[str]]:
    source_aliases = set(sources)
    hardcoded_aliases: set[str] = set()
    overwritten_sources: set[str] = set()

    changed = True
    while changed:
        changed = False
        for match in _ASSIGNMENT_RE.finditer(body):
            left = _normalise_expr(match.group("left"))
            right = _normalise_expr(match.group("right"))
            if not left or not right:
                continue
            if right in source_aliases and left not in source_aliases:
                source_aliases.add(left)
                changed = True
            if right in hardcoded_aliases or _is_hardcoded_direct(right):
                if left not in hardcoded_aliases:
                    hardcoded_aliases.add(left)
                    changed = True
                if left in sources:
                    overwritten_sources.add(left)

    return source_aliases, hardcoded_aliases, overwritten_sources


def _is_hardcoded_direct(expr: str) -> bool:
    return bool(_HARDCODED_DIRECT_RE.search(_normalise_expr(expr)))


def _is_hardcoded_sink(expr: str, hardcoded_aliases: set[str]) -> bool:
    norm = _normalise_expr(expr)
    return norm in hardcoded_aliases or _is_hardcoded_direct(norm)


def _condition_binds_source_to_sink(condition: str, source: str, sink: str) -> bool:
    norm_condition = _normalise_expr(condition)
    norm_source = _normalise_expr(source)
    norm_sink = _normalise_expr(sink)
    if norm_source not in norm_condition or norm_sink not in norm_condition:
        return False
    without_zero = re.sub(r"address\(0\)", "", norm_condition)
    if norm_source not in without_zero or norm_sink not in without_zero:
        return False
    return "==" in without_zero or "!=" in without_zero


def _has_binding_guard(body: str, source: str, sink: str) -> bool:
    for match in re.finditer(r"\b(?:require|assert)\s*\((?P<expr>[^;{}]*)\)", body):
        if _condition_binds_source_to_sink(match.group("expr"), source, sink):
            return True

    for match in re.finditer(r"\bif\s*\((?P<expr>[^;{}]*)\)", body):
        expr = match.group("expr")
        tail = body[match.end():match.end() + 180]
        if _condition_binds_source_to_sink(expr, source, sink) and _REVERT_WORD_RE.search(expr + tail):
            return True

    return False


def _has_forwarded_recipient_transfer(
    sinks: list[tuple[str, str, re.Match[str]]],
    source_aliases: set[str],
    overwritten_sources: set[str],
) -> bool:
    for _reason, sink, _anchor in sinks:
        norm_sink = _normalise_expr(sink)
        if norm_sink in source_aliases and norm_sink not in overwritten_sources:
            return True
    return False


def _match_function(
    fn: FunctionSlice,
    struct_fields: dict[str, list[str]],
) -> tuple[str, str, str, re.Match[str]] | None:
    if not _CALLABLE_HEADER_RE.search(fn.header):
        return None
    if not _FLOW_NAME_RE.search(fn.name) and not _FLOW_CONTEXT_RE.search(fn.header + fn.body):
        return None
    if not _VALUE_CONTEXT_RE.search(fn.body):
        return None

    sources = _recipient_sources(fn, struct_fields)
    if not sources:
        return None

    sinks = _value_sinks(fn.body)
    if not sinks:
        return None

    source_aliases, hardcoded_aliases, overwritten_sources = _assignment_facts(fn.body, sources)
    if _has_forwarded_recipient_transfer(sinks, source_aliases, overwritten_sources):
        return None

    for reason, sink, anchor in sinks:
        norm_sink = _normalise_expr(sink)
        if norm_sink in overwritten_sources:
            return norm_sink, norm_sink, "overwrites recipient with a hardcoded sink before transfer", anchor
        if not _is_hardcoded_sink(norm_sink, hardcoded_aliases):
            continue
        for source in sources:
            if _has_binding_guard(fn.body, source, norm_sink):
                return None
        return sources[0], norm_sink, reason, anchor

    return None


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    clean_source = _strip_comments(source)
    struct_fields = _struct_recipient_fields(clean_source)
    findings: list[Finding] = []

    for fn in _split_functions(clean_source):
        matched = _match_function(fn, struct_fields)
        if matched is None:
            continue
        source, sink, reason, anchor = matched
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=_line_for(fn, anchor),
                severity=DETECTOR_SEVERITY_DEFAULT,
                function=fn.name,
                message=(
                    f"`{fn.name}` accepts recipient-like value `{source}` but {reason} "
                    f"`{sink}`. Bind the value-moving edge to the supplied recipient, "
                    "or reject mismatches before payout."
                ),
            )
        )

    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
