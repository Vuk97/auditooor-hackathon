"""
missing-recipient-trading-settlement-fire25

Regex API detector for trading settlement paths where a fill recipient is
supplied outside the signed order digest, or where a signed order recipient is
observed but settlement pays a caller, operator, maker, or taker sink instead.

This is candidate evidence only. It is scoped to order, fill, match, settle,
trade, payout, and transfer functions with value movement. A zero address check
alone is not a binding guard.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "missing-recipient-trading-settlement-fire25"
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
_CALLABLE_HEADER_RE = re.compile(r"\b(?:external|public|internal)\b")
_ORDER_PARAM_RE = re.compile(
    r"\b(?P<type>[A-Za-z_][A-Za-z0-9_]*Order|Order)\s+"
    r"(?:calldata|memory|storage)?\s*"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b"
)
_ADDRESS_PARAM_RE = re.compile(
    r"\baddress(?:\s+payable)?\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
)
_RECIPIENT_PARAM_RE = re.compile(
    r"(?i)^(to|recipient|receiver|beneficiary|payoutTo|refundTo|settlementRecipient|"
    r"claimRecipient|fillRecipient|tradeRecipient|makerRecipient|takerRecipient)$"
)
_RECIPIENT_FIELD_RE = re.compile(
    r"(?i)\baddress(?:\s+payable)?\s+"
    r"(?P<field>recipient|receiver|beneficiary|payoutTo|refundTo|settlementRecipient|"
    r"claimRecipient|fillRecipient|tradeRecipient|makerRecipient|takerRecipient)\b"
)
_RECIPIENT_REF_RE = re.compile(
    r"(?i)\b(?P<root>[A-Za-z_][A-Za-z0-9_]*)\s*\.\s*"
    r"(?P<field>recipient|receiver|beneficiary|payoutTo|refundTo|settlementRecipient|"
    r"claimRecipient|fillRecipient|tradeRecipient|makerRecipient|takerRecipient)\b"
)
_TRADING_CONTEXT_RE = re.compile(
    r"(?i)\b(order|orders|fill|filled|match|matched|trade|trading|settle|settlement|"
    r"payout|claim|proof|maker|taker|conditional|ctf|token|collateral|proceeds)\b"
)
_VALUE_CONTEXT_RE = re.compile(
    r"(?i)\b(_transfer|safeTransfer|safeTransferFrom|transferFrom|transfer|sendValue|"
    r"call\s*\{|mint|_mint|safeTransferFrom|proceeds|amount|fee|refund|payout)\b"
)
_HASH_OR_VERIFY_RE = re.compile(
    r"(?i)\b(hashOrder|_createStructHash|_hashTypedData|validateOrderSignature|"
    r"validateOrder|_validateOrder|_performOrderChecks|verifyOrder|_verifyOrder|"
    r"SignatureChecker|ECDSA|recover)\b"
)
_COMPARISON_RE = re.compile(
    r"(?is)(?P<a>[A-Za-z_][A-Za-z0-9_]*(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*)?)"
    r"\s*(?:==|!=)\s*"
    r"(?P<b>[A-Za-z_][A-Za-z0-9_]*(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*)?)"
)
_SIGNATURE_BOUND_CALL_RE = re.compile(
    r"(?is)\b(?:hashOrder|hashOrderWithRecipient|_hashOrderWithRecipient|"
    r"_createStructHash|verifyOrder|_verifyOrder|validateOrderSignature|"
    r"validateSettlementRecipient|checkSettlementRecipient|bindRecipient)"
    r"\s*\((?P<args>[^;{}]*)\)"
)
_ABI_HASH_RE = re.compile(
    r"(?is)\b(?:keccak256|_hashTypedData|toTypedDataHash|hashTypedDataV4)\s*"
    r"\([^;{}]*(?P<name>[A-Za-z_][A-Za-z0-9_]*)[^;{}]*\)"
)
_ORDER_BOUND_FIELD_RE = re.compile(r"(?i)\b(maker|taker|recipient|receiver|beneficiary|payoutTo|refundTo)\b")
_HARDCODED_SINK_RE = re.compile(
    r"(?i)^(msg\.sender|_msgSender\s*\(\s*\)|tx\.origin|operator|relayer|executor|"
    r"feeReceiver|getFeeReceiver\s*\(\s*\)|"
    r"[A-Za-z_][A-Za-z0-9_]*\.(maker|taker|owner|operator|relayer))$"
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
    out: dict[str, list[str]] = {}
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
            out[match.group("name")] = fields
        pos = end_pos
    return out


def _line_for(fn: FunctionSlice, match: re.Match[str]) -> int:
    return fn.body_line + fn.body.count("\n", 0, match.start())


def _normalise_expr(expr: str) -> str:
    return re.sub(r"\s+", "", expr or "")


def _expr_regex(expr: str) -> str:
    return r"\s*\.\s*".join(re.escape(part) for part in _normalise_expr(expr).split("."))


def _recipient_params(header: str) -> list[str]:
    params: list[str] = []
    for match in _ADDRESS_PARAM_RE.finditer(header):
        name = match.group("name")
        if _RECIPIENT_PARAM_RE.search(name) and name not in params:
            params.append(name)
    return params


def _order_params(header: str) -> dict[str, str]:
    return {match.group("name"): match.group("type") for match in _ORDER_PARAM_RE.finditer(header)}


def _recipient_refs(fn: FunctionSlice, struct_fields: dict[str, list[str]]) -> list[str]:
    refs: list[str] = []
    for match in _RECIPIENT_REF_RE.finditer(fn.header + fn.body):
        ref = _normalise_expr(f"{match.group('root')}.{match.group('field')}")
        if ref not in refs:
            refs.append(ref)

    for param_name, type_name in _order_params(fn.header).items():
        for field in struct_fields.get(type_name, []):
            ref = _normalise_expr(f"{param_name}.{field}")
            if ref not in refs:
                refs.append(ref)
    return refs


def _value_sinks(body: str) -> list[tuple[str, str, re.Match[str]]]:
    patterns: list[tuple[str, str]] = [
        (
            "routes trading settlement to an unbound recipient",
            r"\b(?:safeTransfer|transfer|sendValue|mint|_mint)\s*"
            r"\(\s*(?P<sink>[A-Za-z_][A-Za-z0-9_]*(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*)?|msg\.sender|_msgSender\s*\(\s*\))\s*,",
        ),
        (
            "routes trading settlement to an unbound recipient",
            r"\b(?:_transfer|safeTransferFrom|transferFrom)\s*\([^;{}]*?,\s*"
            r"(?P<sink>[A-Za-z_][A-Za-z0-9_]*(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*)?|msg\.sender|_msgSender\s*\(\s*\))\s*,",
        ),
        (
            "routes native trading settlement to an unbound recipient",
            r"\bpayable\s*\(\s*(?P<sink>[A-Za-z_][A-Za-z0-9_]*(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*)?|msg\.sender|_msgSender\s*\(\s*\))\s*\)"
            r"\s*\.\s*(?:transfer|send|call)\b",
        ),
        (
            "routes native trading settlement to an unbound recipient",
            r"\b(?P<sink>[A-Za-z_][A-Za-z0-9_]*(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*)?|msg\.sender|_msgSender\s*\(\s*\))"
            r"\s*\.\s*call\s*\{\s*value\s*:",
        ),
    ]
    out: list[tuple[str, str, re.Match[str]]] = []
    for reason, pattern in patterns:
        for match in re.finditer(pattern, body, flags=re.IGNORECASE | re.DOTALL):
            out.append((reason, _normalise_expr(match.group("sink")), match))
    return out


def _condition_binds_sink(condition: str, sink: str, refs: list[str], order_params: dict[str, str]) -> bool:
    norm_condition = _normalise_expr(condition)
    norm_sink = _normalise_expr(sink)
    if norm_sink not in norm_condition:
        return False
    relation = norm_condition.replace(norm_sink, "")
    relation = relation.replace("address(0)", "")
    if any(ref in relation for ref in refs):
        return True
    for order_name in order_params:
        field_match = re.search(rf"{re.escape(order_name)}\.(maker|taker|recipient|receiver|beneficiary)\b", relation)
        if field_match is not None:
            return True
    return False


def _signature_binds_sink(body: str, sink: str) -> bool:
    norm_sink = _normalise_expr(sink)
    for match in _SIGNATURE_BOUND_CALL_RE.finditer(body):
        if norm_sink in _normalise_expr(match.group("args")):
            return True
    for match in _ABI_HASH_RE.finditer(body):
        if _normalise_expr(match.group("name")) == norm_sink:
            return True
    return False


def _sink_assigned_from_ref(body: str, sink: str, refs: list[str]) -> bool:
    sink_pattern = _expr_regex(sink)
    for ref in refs:
        pattern = (
            rf"(?is)\b(?:address(?:\s+payable)?\s+)?{sink_pattern}\s*="
            rf"\s*{_expr_regex(ref)}\b"
        )
        if re.search(pattern, body):
            return True
    return False


def _has_binding_guard(fn: FunctionSlice, sink: str, refs: list[str], order_params: dict[str, str]) -> bool:
    if _signature_binds_sink(fn.body, sink):
        return True
    if _sink_assigned_from_ref(fn.body, sink, refs):
        return True
    for match in re.finditer(r"\b(?:require|assert)\s*\((?P<expr>[^;{}]*)\)", fn.body):
        if _condition_binds_sink(match.group("expr"), sink, refs, order_params):
            return True
    for match in re.finditer(r"\bif\s*\((?P<expr>[^;{}]*)\)", fn.body):
        expr = match.group("expr")
        tail = fn.body[match.end():match.end() + 180]
        if _condition_binds_sink(expr, sink, refs, order_params) and re.search(
            r"(?i)(revert|RecipientMismatch|InvalidRecipient|NotRecipient|BadRecipient|Unauthorized)",
            expr + tail,
        ):
            return True
    return False


def _hardcoded_sink_is_unsafe(sink: str, refs: list[str]) -> bool:
    if not refs:
        return False
    if any(_normalise_expr(sink) == ref for ref in refs):
        return False
    return bool(_HARDCODED_SINK_RE.search(_normalise_expr(sink)))


def _match_function(
    fn: FunctionSlice,
    struct_fields: dict[str, list[str]],
) -> tuple[str, str, re.Match[str]] | None:
    if not _CALLABLE_HEADER_RE.search(fn.header):
        return None
    if not _TRADING_CONTEXT_RE.search(fn.name) and not _TRADING_CONTEXT_RE.search(fn.header + fn.body):
        return None
    if not _VALUE_CONTEXT_RE.search(fn.body):
        return None

    order_params = _order_params(fn.header)
    if not order_params:
        return None
    if not _HASH_OR_VERIFY_RE.search(fn.body):
        return None

    recipient_params = _recipient_params(fn.header)
    refs = _recipient_refs(fn, struct_fields)
    sinks = _value_sinks(fn.body)

    for reason, sink, anchor in sinks:
        if sink in recipient_params:
            if _has_binding_guard(fn, sink, refs, order_params):
                continue
            return sink, reason, anchor

        if _hardcoded_sink_is_unsafe(sink, refs):
            if _has_binding_guard(fn, sink, refs, order_params):
                continue
            return refs[0], f"ignores signed recipient and pays `{sink}`", anchor

    return None


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    clean_source = _strip_comments(source)
    struct_fields = _struct_recipient_fields(clean_source)
    findings: list[Finding] = []

    for fn in _split_functions(clean_source):
        matched = _match_function(fn, struct_fields)
        if matched is None:
            continue
        sink, reason, anchor = matched
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=_line_for(fn, anchor),
                severity=DETECTOR_SEVERITY_DEFAULT,
                function=fn.name,
                message=(
                    f"`{fn.name}` {reason} `{sink}` in an order settlement path "
                    "without binding that recipient to the signed order digest or "
                    "proof recipient. Bind the recipient in the order hash or reject "
                    "recipient mismatches before value movement."
                ),
            )
        )

    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
