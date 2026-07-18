"""
missing-recipient-validation-settlement-fire23

Regex API detector for settlement, order-match, hook, and swap flows that pay
or callback to a caller-supplied recipient-like address without binding that
address to the order, position, pool, or expected user.

This is candidate evidence only. It intentionally does not flag generic
zero-address validation gaps: a zero-recipient check is not treated as a
binding guard, and a finding requires value or callback routing to the same
recipient-like parameter inside a settlement-context function.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "missing-recipient-validation-settlement-fire23"
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
_CALLABLE_HEADER_RE = re.compile(r"\b(?:external|public|internal)\b")
_ADDRESS_PARAM_RE = re.compile(
    r"\baddress(?:\s+payable)?\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
)
_RECIPIENT_PARAM_RE = re.compile(
    r"(?i)(recipient|receiver|beneficiary|payout|settlement.*sink|"
    r"settlement.*target|token.*out.*sink|callback.*target|callback|target|"
    r"to)$"
)
_CONTEXT_RE = re.compile(
    r"(?i)\b(order|orders|match|fill|settle|settlement|swap|hook|pool|"
    r"position|maker|taker|callback|tokenOut|amountOut|surplus|refund|"
    r"proceeds)\b"
)
_VALUE_CONTEXT_RE = re.compile(
    r"(?i)\b(token|asset|collateral|currency|amount|amountOut|tokenOut|"
    r"proceeds|surplus|refund|fee|payout|settle|settlement|take|mint)\b"
)
_BINDING_WORD_RE = re.compile(
    r"(?i)(order|orders|signedOrder|makerOrder|takerOrder|position|"
    r"pool|poolKey|expected|committed|account|owner|user|maker|taker|"
    r"msg\.sender|params|permit|signature|"
    r"quote)"
)
_VALIDATOR_RE = re.compile(
    r"(?i)\b(validate|check|assert|bind|verify)[A-Za-z0-9_]*"
    r"(Recipient|Receiver|Beneficiary|Payout|SettlementSink|Target)"
    r"[A-Za-z0-9_]*\s*\("
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


def _line_for(fn: FunctionSlice, match: re.Match[str]) -> int:
    return fn.body_line + fn.body.count("\n", 0, match.start())


def _recipient_params(header: str) -> list[str]:
    params: list[str] = []
    for match in _ADDRESS_PARAM_RE.finditer(header):
        name = match.group("name")
        if _RECIPIENT_PARAM_RE.search(name) and name not in params:
            params.append(name)
    return params


def _routes_to_param(body: str, param: str) -> tuple[str, re.Match[str]] | None:
    sink = re.escape(param)
    patterns: list[tuple[str, str]] = [
        (
            "transfers settlement value to caller supplied recipient",
            rf"\b(?:safeTransfer|transfer|sendValue|mint|_mint)\s*\(\s*{sink}\s*,",
        ),
        (
            "transfers escrowed value from the contract to caller supplied recipient",
            rf"\b_transfer\s*\(\s*(?:address\s*\(\s*this\s*\)|"
            rf"maker|taker|order\.maker|order\.taker|msg\.sender)\s*,\s*{sink}\s*,",
        ),
        (
            "routes native settlement value to caller supplied recipient",
            rf"\bpayable\s*\(\s*{sink}\s*\)\s*\.\s*(?:transfer|send)\s*\(",
        ),
        (
            "routes native settlement value to caller supplied recipient",
            rf"\b(?:payable\s*\(\s*{sink}\s*\)|{sink})\s*\.\s*call\s*\{{\s*value\s*:",
        ),
        (
            "takes swap or hook output to caller supplied recipient",
            rf"\b(?:take|settleTake|takeCurrency|settleOutput|sendTo|pay)\s*"
            rf"\([^;{{}}]*\b{sink}\b",
        ),
        (
            "calls a caller supplied settlement or hook target",
            rf"\bI[A-Za-z0-9_]*(?:Hook|Callback|Receiver|Target)[A-Za-z0-9_]*"
            rf"\s*\(\s*{sink}\s*\)\s*\.",
        ),
        (
            "calls a caller supplied settlement or hook target",
            rf"\b{sink}\s*\.\s*call\s*\(",
        ),
    ]
    for reason, pattern in patterns:
        match = re.search(pattern, body, flags=re.IGNORECASE | re.DOTALL)
        if match is not None:
            return reason, match
    return None


def _condition_has_binding(condition: str, param: str) -> bool:
    if not re.search(rf"\b{re.escape(param)}\b", condition):
        return False
    relation = re.sub(rf"\b{re.escape(param)}\b", "", condition)
    relation = re.sub(r"address\s*\(\s*0\s*\)", "", relation)
    return bool(_BINDING_WORD_RE.search(relation))


def _has_binding_guard(body: str, param: str) -> bool:
    if _VALIDATOR_RE.search(body):
        return True

    for match in re.finditer(r"\b(?:require|assert)\s*\((?P<expr>[^;{}]*)\)", body):
        if _condition_has_binding(match.group("expr"), param):
            return True

    for match in re.finditer(r"\bif\s*\((?P<expr>[^;{}]*)\)", body):
        expr = match.group("expr")
        if _condition_has_binding(expr, param) and re.search(
            r"(?i)(revert|InvalidRecipient|RecipientMismatch|BadReceiver|Unauthorized)",
            expr + body[match.end():match.end() + 160],
        ):
            return True

    signature_pattern = (
        rf"(?is)\b(?:keccak256|hashTypedData|toTypedDataHash)\s*"
        rf"\([^;{{}}]*\b{re.escape(param)}\b[^;{{}}]*\).*?"
        rf"\b(?:recover|ECDSA|SignatureChecker|isValidSignature)"
    )
    if re.search(signature_pattern, body):
        return True

    return False


def _match_function(fn: FunctionSlice) -> tuple[str, str, re.Match[str]] | None:
    if not _CALLABLE_HEADER_RE.search(fn.header):
        return None
    if not _CONTEXT_RE.search(fn.name) and not _CONTEXT_RE.search(fn.body):
        return None
    if not _VALUE_CONTEXT_RE.search(fn.body):
        return None

    for param in _recipient_params(fn.header):
        routed = _routes_to_param(fn.body, param)
        if routed is None:
            continue
        if _has_binding_guard(fn.body, param):
            continue
        reason, anchor = routed
        return param, reason, anchor
    return None


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    clean_source = _strip_comments(source)
    findings: list[Finding] = []

    for fn in _split_functions(clean_source):
        matched = _match_function(fn)
        if matched is None:
            continue
        param, reason, anchor = matched
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=_line_for(fn, anchor),
                severity=DETECTOR_SEVERITY_DEFAULT,
                function=fn.name,
                message=(
                    f"`{fn.name}` {reason} `{param}` without binding it to "
                    "the order, position, pool, or expected user. Add an "
                    "order or state recipient equality check before routing "
                    "settlement value."
                ),
            )
        )

    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
