"""
state-check-then-external-or-mutating-use-fire17

Regex API detector for a narrow state-change-between-check-and-use shape:
a function checks a fee, sender policy, balance, mode, or state token, then
crosses a hook/callback/external effect or same-token mutation boundary, then
uses the pre-boundary token without a post-boundary revalidation.

This is candidate evidence only. It is deliberately not a generic CEI detector:
it requires a concrete checked token, an effect boundary after the check, and a
later use of that same token or sender-context before any matching recheck.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "state-check-then-external-or-mutating-use-fire17"
DETECTOR_SEVERITY_DEFAULT = "Medium"


@dataclass
class Finding:
    detector: str
    file: str
    line: int
    severity: str
    message: str
    function: Optional[str] = None


_COMMENT_OR_STRING_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'|"
    r"//[^\n\r]*|"
    r"/\*.*?\*/",
    re.DOTALL,
)
_FN_HEADER_RE = re.compile(
    r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(",
)
_PUBLIC_OR_EXTERNAL_RE = re.compile(r"\b(?:external|public)\b")
_CHECK_RE = re.compile(r"\b(?:require|if)\s*\((?P<expr>[^;{}]*)\)")
_EXTERNAL_BOUNDARY_RE = re.compile(
    r"(?is)"
    r"(?:"
    r"\b(?:hook|hooks|callback|callbacks|policy|sponsorPolicy|validator|"
    r"manager|poolManager|adapter|router|oracle)\s*\.\s*"
    r"[A-Za-z_][A-Za-z0-9_]*\s*\(|"
    r"\bI[A-Za-z0-9_]*(?:Hook|Hooks|Callback|Policy|Manager|Validator|"
    r"Oracle|Adapter|Router)[A-Za-z0-9_]*\s*\([^;)]*\)\s*\.\s*"
    r"[A-Za-z_][A-Za-z0-9_]*\s*\(|"
    r"\b(?:safeTransferFrom|transferFrom|safeTransfer|transfer)\s*\(|"
    r"\b(?:call|delegatecall|functionCall)\s*\("
    r")"
)
_SUCCESS_OR_SPEND_USE_RE = re.compile(
    r"(?is)"
    r"(?:"
    r"\breturn\s*\([^;]*(?:SIG_VALIDATION_SUCCESS|validationData|bytes32\s*\(\s*0\s*\))|"
    r"\b(?:spent|used|quota|budget|sponsored|gasUsed|deposit)\s*"
    r"\[[^;\]]*userOp\.sender[^;\]]*\]\s*(?:=|\+=|-=|\+\+|--)|"
    r"\b(?:spent|used|quota|budget|sponsored|gasUsed|deposit)\s*"
    r"\[[^;\]]*sender[^;\]]*\]\s*(?:=|\+=|-=|\+\+|--)"
    r")"
)
_TOKEN_DELTA_FRESH_RE = re.compile(
    r"(?is)\b(?:actualReceived|receivedDelta|deltaIn|balanceDelta|"
    r"netReceived|balanceAfter|balanceBefore|revalidated|validateAfter|"
    r"postEffect|freshFee|feeAfter|quotaAfter|policyAfter|senderAfter)\b"
)
_AMOUNT_IN_RE = re.compile(r"(?i)\bamount[01]?In\b")
_RESERVE_RE = re.compile(r"(?i)\b(?:reserve[01]?|getReserves|kInvariant|constantProduct)\b")
_SELF_BALANCE_RE = re.compile(
    r"(?i)\bbalanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)"
)
_TOKEN_TRANSFER_RE = re.compile(
    r"(?i)\b(?:safeTransferFrom|transferFrom|safeTransfer|transfer)\s*\("
)
_NOMINAL_AMOUNT_MATH_RE = re.compile(
    r"(?is)"
    r"(?:"
    r"\b(?:amount[01]?Out[A-Za-z0-9_]*|quoted[A-Za-z0-9_]*|output[A-Za-z0-9_]*)"
    r"\s*=\s*[^;]*\bamount[01]?In\b[^;]*(?:reserve|balance)|"
    r"\bamount[01]?In\b\s*[*\/]\s*[^;]*(?:reserve|balance)|"
    r"\b(?:reserve|balance)[A-Za-z0-9_]*\b\s*[*\/]\s*\bamount[01]?In\b"
    r")"
)
_POST_BALANCE_USE_RE = re.compile(
    r"(?is)"
    r"(?:"
    r"\brequire\s*\([^;]*(?:newBal[01]?|balance[01]?)[^;]*"
    r"(?:reserve[01]?|kInvariant|constantProduct)[^;]*\)|"
    r"\b(?:reserve[01]?|_reserve[01]?)\s*=\s*[^;]*(?:newBal[01]?|balance[01]?)"
    r")"
)

_STOPWORDS = {
    "address",
    "bool",
    "bytes",
    "bytes32",
    "calldata",
    "else",
    "external",
    "false",
    "function",
    "if",
    "internal",
    "memory",
    "msg",
    "public",
    "pure",
    "require",
    "return",
    "returns",
    "storage",
    "string",
    "this",
    "true",
    "uint",
    "uint8",
    "uint16",
    "uint24",
    "uint32",
    "uint64",
    "uint128",
    "uint160",
    "uint256",
    "view",
}
_INTERESTING_FRAGMENTS = (
    "allowed",
    "balance",
    "cap",
    "config",
    "enabled",
    "fee",
    "limit",
    "mode",
    "policy",
    "quota",
    "reserve",
    "sender",
    "sponsor",
    "state",
    "status",
    "token",
)


def _strip_comments_and_strings(source: str) -> str:
    def replace(match: re.Match[str]) -> str:
        text = match.group(0)
        return "\n" * text.count("\n") if "\n" in text else " "

    return _COMMENT_OR_STRING_RE.sub(replace, source or "")


def _split_functions(source: str) -> list[tuple[str, str, str, int]]:
    out: list[tuple[str, str, str, int]] = []
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

        depth = 1
        k = body_start + 1
        while k < len(source) and depth > 0:
            char = source[k]
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
            k += 1
        header = source[match.start():body_start]
        body = source[body_start + 1:k - 1]
        function_line = source.count("\n", 0, match.start()) + 1
        out.append((name, header, body, function_line))
        pos = k
    return out


def _is_constant_like(token: str) -> bool:
    return token.upper() == token and any(char.isalpha() for char in token)


def _interesting_token(token: str) -> bool:
    lower = token.lower()
    if lower in _STOPWORDS:
        return False
    if _is_constant_like(token):
        return False
    if token in {"msg.sender", "tx.origin"}:
        return False
    if token == "userOp.sender":
        return True
    return any(fragment in lower for fragment in _INTERESTING_FRAGMENTS)


def _extract_checked_tokens(expr: str) -> list[str]:
    tokens: list[str] = []
    dotted_parts: set[str] = set()
    for dotted in re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*\b", expr):
        if _interesting_token(dotted) and dotted not in tokens:
            tokens.append(dotted)
            dotted_parts.update(dotted.split("."))
    for ident in re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", expr):
        if ident in dotted_parts:
            continue
        if _interesting_token(ident) and ident not in tokens:
            tokens.append(ident)
    return tokens


def _token_re(token: str) -> re.Pattern[str]:
    if "." in token:
        return re.compile(re.escape(token))
    return re.compile(rf"\b{re.escape(token)}\b")


def _assignment_boundary_re(token: str) -> re.Pattern[str] | None:
    if "." in token:
        return None
    return re.compile(
        rf"\b{re.escape(token)}\b\s*(?:=|\+=|-=|\*=|/=|\+\+|--)",
        re.IGNORECASE,
    )


def _stale_use_re(token: str) -> re.Pattern[str]:
    escaped = re.escape(token)
    word = escaped if "." in token else rf"\b{escaped}\b"
    return re.compile(
        rf"(?is)"
        rf"(?:"
        rf"\breturn\b[^;]*{word}|"
        rf"\b[A-Za-z_][A-Za-z0-9_]*\s*=\s*[^;]*{word}[^;]*;|"
        rf"\b[A-Za-z_][A-Za-z0-9_]*\s*(?:\+=|-=|\*=|/=)\s*[^;]*{word}[^;]*;|"
        rf"\b(?:transfer|safeTransfer|_mint|mint|burn|settle|charge|spend)"
        rf"[A-Za-z0-9_]*\s*\([^;]*{word}[^;]*\)|"
        rf"{word}\s*(?:[+\-*/%]|<<|>>)|"
        rf"(?:[+\-*/%]|<<|>>)\s*{word}"
        rf")"
    )


def _has_post_boundary_revalidation(segment: str, tokens: list[str]) -> bool:
    for check in _CHECK_RE.finditer(segment):
        expr = check.group("expr")
        if any(_token_re(token).search(expr) for token in tokens):
            return True
    if _TOKEN_DELTA_FRESH_RE.search(segment):
        return True
    return False


def _first_boundary_after(body: str, token: str, start: int) -> tuple[re.Match[str] | None, str]:
    external = _EXTERNAL_BOUNDARY_RE.search(body, start)
    assign_re = _assignment_boundary_re(token)
    assignment = assign_re.search(body, start) if assign_re else None

    candidates: list[tuple[int, re.Match[str], str]] = []
    if external is not None:
        candidates.append((external.start(), external, "external effect"))
    if assignment is not None:
        candidates.append((assignment.start(), assignment, "same-token mutation"))
    if not candidates:
        return None, ""
    _, match, label = min(candidates, key=lambda item: item[0])
    return match, label


def _stale_use_after_boundary(
    body: str,
    tokens: list[str],
    boundary: re.Match[str],
) -> tuple[str, re.Match[str]] | None:
    after_boundary = body[boundary.end():]
    for token in tokens:
        if token in {"userOp.sender", "sender"}:
            sender_use = _SUCCESS_OR_SPEND_USE_RE.search(after_boundary)
            if sender_use is not None:
                before_use = after_boundary[:sender_use.start()]
                if not _has_post_boundary_revalidation(before_use, tokens):
                    return token, sender_use

        use = _stale_use_re(token).search(after_boundary)
        if use is None:
            continue
        before_use = after_boundary[:use.start()]
        if _has_post_boundary_revalidation(before_use, tokens):
            continue
        return token, use
    return None


def _match_function(body: str) -> tuple[list[str], str, int] | None:
    stripped = _strip_comments_and_strings(body)
    amount_boundary = _token_amount_boundary_match(stripped)
    if amount_boundary is not None:
        match, reason = amount_boundary
        return ["amountIn"], reason, stripped.count("\n", 0, match.start())

    for check in _CHECK_RE.finditer(stripped):
        tokens = _extract_checked_tokens(check.group("expr"))
        if not tokens:
            continue
        for token in tokens:
            boundary, boundary_label = _first_boundary_after(stripped, token, check.end())
            if boundary is None:
                continue
            stale = _stale_use_after_boundary(stripped, tokens, boundary)
            if stale is None:
                continue
            stale_token, stale_use = stale
            line_offset = stripped.count("\n", 0, check.start())
            reason = (
                f"checked {', '.join(tokens)} before {boundary_label}, then "
                f"used {stale_token} after that boundary without revalidation"
            )
            # If the only use is a token transfer itself, keep this out of
            # generic CEI territory by requiring a later balance or policy use.
            if stale_use.start() == 0 and "transfer" in stale_use.group(0):
                continue
            return tokens, reason, line_offset
    return None


def _token_amount_boundary_match(body: str) -> tuple[re.Match[str], str] | None:
    if not _AMOUNT_IN_RE.search(body):
        return None
    if not _RESERVE_RE.search(body):
        return None
    if not _SELF_BALANCE_RE.search(body):
        return None
    if not _TOKEN_TRANSFER_RE.search(body):
        return None
    if _TOKEN_DELTA_FRESH_RE.search(body):
        return None

    nominal = _NOMINAL_AMOUNT_MATH_RE.search(body)
    if nominal is None:
        return None
    later = body[nominal.end():]
    if _SELF_BALANCE_RE.search(later) is None:
        return None
    if _POST_BALANCE_USE_RE.search(later) is None:
        return None
    return (
        nominal,
        "used nominal amountIn reserve math across a token transfer and "
        "post-transfer balance use without deriving actual received delta",
    )


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    findings: list[Finding] = []
    if "require" not in source and "if" not in source:
        return findings
    if not any(marker in source for marker in ("hook", "Hook", "policy", "Policy", "callback", "transfer", "balanceOf", "call")):
        return findings

    for function_name, header, body, function_line in _split_functions(source):
        if not _PUBLIC_OR_EXTERNAL_RE.search(header):
            continue
        matched = _match_function(body)
        if matched is None:
            continue
        _tokens, reason, line_offset = matched
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=function_line + line_offset,
                severity=DETECTOR_SEVERITY_DEFAULT,
                function=function_name,
                message=(
                    f"`{function_name}` has a state-change-between-check-and-use "
                    f"boundary: {reason}. Bind or revalidate the value after "
                    "the hook, callback, or mutation before using it."
                ),
            )
        )
    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
