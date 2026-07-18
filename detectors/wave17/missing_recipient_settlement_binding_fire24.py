"""
missing-recipient-settlement-binding-fire24

Regex API detector for order, proof, claim, payout, withdrawal, and hook
settlement paths where a signed or proof recipient exists but the settlement
edge pays a different hardcoded sink, or where independent recipient fields are
not compared before payout.

This is candidate evidence only. It is intentionally narrower than generic
zero-address recipient validation: it looks for recipient-bearing order or
proof state and a settlement value edge that is not bound to that recipient.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "missing-recipient-settlement-binding-fire24"
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
_CONTEXT_RE = re.compile(
    r"(?i)\b(order|orders|fill|match|settle|settlement|claim|payout|"
    r"withdraw|redeem|proof|permit|voucher|intent|receipt|hook|callback|"
    r"pool|swap|maker|taker|escrow)\b"
)
_VALUE_CONTEXT_RE = re.compile(
    r"(?i)\b(transfer|safeTransfer|sendValue|call\s*\{|mint|_mint|pay|"
    r"payout|refund|claim|proceeds|amount|amountOut|shares|assets|"
    r"tokens|currency|settlement)\b"
)
_RECIPIENT_FIELD_RE = re.compile(
    r"(?i)\b(?P<root>[A-Za-z_][A-Za-z0-9_]*)\s*\.\s*"
    r"(?P<field>recipient|receiver|beneficiary|payoutRecipient|"
    r"claimRecipient|settlementRecipient|refundRecipient|withdrawRecipient|"
    r"payoutTo|refundTo|to)\b"
)
_ADDRESS_FIELD_RE = re.compile(
    r"(?i)\baddress(?:\s+payable)?\s+"
    r"(?P<field>recipient|receiver|beneficiary|payoutRecipient|"
    r"claimRecipient|settlementRecipient|refundRecipient|withdrawRecipient|"
    r"payoutTo|refundTo|to)\b"
)
_STRUCT_PARAM_RE = re.compile(
    r"\b(?P<type>[A-Za-z_][A-Za-z0-9_]*)\s+"
    r"(?:calldata|memory|storage)?\s*"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b"
)
_RECIPIENT_NAME_RE = re.compile(
    r"(?i)(recipient|receiver|beneficiary|payoutTo|refundTo|payoutRecipient|"
    r"claimRecipient|settlementRecipient|refundRecipient|withdrawRecipient)"
)
_SOURCE_ROOT_RE = re.compile(
    r"(?i)^(order|signedOrder|makerOrder|takerOrder|proof|claim|payout|"
    r"withdrawal|request|intent|permit|voucher|receipt|message|attestation|"
    r"settlement|ticket)$"
)
_SINK_EXPR = (
    r"(?:msg\.sender|_msgSender\s*\(\s*\)|tx\.origin|"
    r"[A-Za-z_][A-Za-z0-9_]*(?:\s*\[[^\]]+\])?"
    r"(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*)?)"
)
_HARDCODED_SINK_RE = re.compile(
    r"(?i)(^msg\.sender$|^_msgSender\s*\(\s*\)$|^tx\.origin$|"
    r"\.(maker|owner|pool|vault)\b|"
    r"\b(maker|caller|pool|poolVault|vault|router|storedSink|defaultSink|"
    r"defaultRecipient|payoutSink|settlementSink|escrowSink|treasury)\b)"
)
_VALIDATOR_RE = re.compile(
    r"(?is)\b(validate|check|assert|bind|verify)[A-Za-z0-9_]*"
    r"(Recipient|Receiver|Beneficiary|Payout|Settlement|Sink|Proof)"
    r"[A-Za-z0-9_]*\s*\([^;{}]*(recipient|receiver|beneficiary|payout)"
)
_COMPARISON_RE = re.compile(
    r"(?is)(?P<a>[A-Za-z_][A-Za-z0-9_]*(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*)?)"
    r"\s*(?:==|!=)\s*"
    r"(?P<b>[A-Za-z_][A-Za-z0-9_]*(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*)?)"
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
        for field_match in _ADDRESS_FIELD_RE.finditer(body):
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


def _recipient_refs(text: str) -> list[str]:
    refs: list[str] = []
    for match in _RECIPIENT_FIELD_RE.finditer(text):
        root = match.group("root")
        field = match.group("field")
        ref = _normalise_expr(f"{root}.{field}")
        if _SOURCE_ROOT_RE.search(root) and ref not in refs:
            refs.append(ref)
    return refs


def _header_struct_recipient_refs(
    fn: FunctionSlice,
    struct_fields: dict[str, list[str]],
) -> list[str]:
    refs: list[str] = []
    for match in _STRUCT_PARAM_RE.finditer(fn.header):
        type_name = match.group("type")
        param_name = match.group("name")
        if type_name not in struct_fields:
            continue
        if not re.search(rf"\b{re.escape(param_name)}\b", fn.body):
            continue
        for field in struct_fields[type_name]:
            ref = _normalise_expr(f"{param_name}.{field}")
            if ref not in refs:
                refs.append(ref)
    return refs


def _all_recipient_refs(fn: FunctionSlice, struct_fields: dict[str, list[str]]) -> list[str]:
    refs = _recipient_refs(fn.header + fn.body)
    for ref in _header_struct_recipient_refs(fn, struct_fields):
        if ref not in refs:
            refs.append(ref)
    return refs


def _expr_mentions_recipient(expr: str, refs: list[str]) -> bool:
    norm = _normalise_expr(expr)
    if _RECIPIENT_NAME_RE.search(norm):
        return True
    return any(norm == ref or norm.endswith(f".{ref}") for ref in refs)


def _sink_is_hardcoded(expr: str) -> bool:
    return bool(_HARDCODED_SINK_RE.search(_normalise_expr(expr)))


def _value_sinks(body: str) -> list[tuple[str, str, re.Match[str]]]:
    patterns: list[tuple[str, str]] = [
        (
            "routes token settlement to a non-recipient sink",
            rf"\b(?:safeTransfer|transfer|sendValue|mint|_mint)\s*"
            rf"\(\s*(?P<sink>{_SINK_EXPR})\s*,",
        ),
        (
            "routes escrowed settlement to a non-recipient sink",
            rf"\b_transfer\s*\(\s*(?:address\s*\(\s*this\s*\)|[^,]+?)\s*,"
            rf"\s*(?P<sink>{_SINK_EXPR})\s*,",
        ),
        (
            "routes native settlement to a non-recipient sink",
            rf"\bpayable\s*\(\s*(?P<sink>{_SINK_EXPR})\s*\)\s*"
            rf"\.\s*(?:transfer|send|call)\b",
        ),
        (
            "routes native settlement to a non-recipient sink",
            rf"\b(?P<sink>{_SINK_EXPR})\s*\.\s*call\s*\{{\s*value\s*:",
        ),
        (
            "routes hook or callback settlement to a non-recipient sink",
            rf"\bI[A-Za-z0-9_]*(?:Hook|Callback|Receiver|Target)[A-Za-z0-9_]*"
            rf"\s*\(\s*(?P<sink>{_SINK_EXPR})\s*\)\s*\.",
        ),
        (
            "routes pool-manager settlement to a non-recipient sink",
            rf"\b(?:take|settleTake|takeCurrency|settleOutput|sendTo|pay)\s*"
            rf"\([^;{{}}]*,\s*(?P<sink>{_SINK_EXPR})\s*,",
        ),
    ]
    out: list[tuple[str, str, re.Match[str]]] = []
    for reason, pattern in patterns:
        for match in re.finditer(pattern, body, flags=re.IGNORECASE | re.DOTALL):
            out.append((reason, match.group("sink"), match))
    return out


def _has_assignment_from_recipient(body: str, sink: str, refs: list[str]) -> bool:
    sink_pattern = _expr_regex(sink)
    for ref in refs:
        pattern = (
            rf"(?is)\b(?:address(?:\s+payable)?\s+)?{sink_pattern}\s*="
            rf"\s*{_expr_regex(ref)}\b"
        )
        if re.search(pattern, body):
            return True
    return False


def _has_recipient_comparison(body: str, refs: list[str], sink: str | None = None) -> bool:
    atoms = set(refs)
    if sink:
        atoms.add(_normalise_expr(sink))

    for match in _COMPARISON_RE.finditer(body):
        a = _normalise_expr(match.group("a"))
        b = _normalise_expr(match.group("b"))
        a_is_ref = a in atoms or any(a.endswith(f".{ref}") for ref in refs)
        b_is_ref = b in atoms or any(b.endswith(f".{ref}") for ref in refs)
        if a_is_ref and b_is_ref and a != b:
            return True
        if sink and ((a == _normalise_expr(sink) and b_is_ref) or (b == _normalise_expr(sink) and a_is_ref)):
            return True

    if _VALIDATOR_RE.search(body):
        refs_seen = sum(1 for ref in refs if ref in _normalise_expr(body))
        if refs_seen >= 1:
            return True
    return False


def _match_function(
    fn: FunctionSlice,
    struct_fields: dict[str, list[str]],
) -> tuple[str, str, re.Match[str]] | None:
    if not _CALLABLE_HEADER_RE.search(fn.header):
        return None
    if not _CONTEXT_RE.search(fn.name) and not _CONTEXT_RE.search(fn.header + fn.body):
        return None
    if not _VALUE_CONTEXT_RE.search(fn.body):
        return None

    refs = _all_recipient_refs(fn, struct_fields)
    if not refs:
        return None

    sinks = _value_sinks(fn.body)
    for reason, sink, anchor in sinks:
        if _expr_mentions_recipient(sink, refs):
            continue
        if not _sink_is_hardcoded(sink):
            continue
        if _has_assignment_from_recipient(fn.body, sink, refs):
            continue
        if _has_recipient_comparison(fn.body, refs, sink):
            continue
        return refs[0], f"{reason} `{sink}`", anchor

    distinct_roots = {ref.split(".", 1)[0] for ref in refs}
    if len(distinct_roots) >= 2 and sinks and not _has_recipient_comparison(fn.body, refs):
        reason, sink, anchor = sinks[0]
        return refs[0], f"does not compare independent recipient fields before settlement to `{sink}`", anchor

    return None


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    clean_source = _strip_comments(source)
    struct_fields = _struct_recipient_fields(clean_source)
    findings: list[Finding] = []

    for fn in _split_functions(clean_source):
        matched = _match_function(fn, struct_fields)
        if matched is None:
            continue
        ref, reason, anchor = matched
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=_line_for(fn, anchor),
                severity=DETECTOR_SEVERITY_DEFAULT,
                function=fn.name,
                message=(
                    f"`{fn.name}` observes signed or proof recipient `{ref}` but {reason}. "
                    "Bind the settlement sink to the signed recipient or reject order, proof, "
                    "and payout recipient mismatches before value movement."
                ),
            )
        )

    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
