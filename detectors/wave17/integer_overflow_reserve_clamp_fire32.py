"""
integer-overflow-reserve-clamp-fire32

Detects Solidity reserve, supply, fee, ratio, limit, cap, and threshold
values narrowed to uint112, uint96, uint64, or smaller before a wide-value
bound check, then stored or used for pricing, caps, or payouts.

This lifts the Go Fire31 config-clamp shape into Solidity accounting paths
and incorporates the ChainSecurity balance-overflow lesson where unsafe
casts to compact balance types corrupt protocol accounting.

This is detector evidence only. A finding still needs a real protocol path,
negative control, and R40/R76/R80 proof before filing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "integer-overflow-reserve-clamp-fire32"
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
    function_line: int


_SMALL_WIDTHS = (8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112)
_SMALL_UINT = r"uint(?:" + "|".join(str(width) for width in _SMALL_WIDTHS) + r")"

_FN_HEADER_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_STRING_RE = re.compile(r'`[^`]*`|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')

_CAST_ASSIGN_RE = re.compile(
    r"(?is)\b(?P<lhs>(?:"
    + _SMALL_UINT
    + r"\s+)?[A-Za-z_][A-Za-z0-9_]*(?:\s*(?:\[[^\]]+\]|\.[A-Za-z_][A-Za-z0-9_]*))*)"
    r"\s*=\s*(?P<cast>"
    + _SMALL_UINT
    + r")\s*\(\s*(?P<expr>[^;\n{}]+?)\s*\)"
)
_INLINE_CAST_RE = re.compile(
    r"(?is)\b(?P<cast>" + _SMALL_UINT + r")\s*\(\s*(?P<expr>[^;\n{}]+?)\s*\)"
)

_ACCOUNTING_TERM_RE = re.compile(
    r"(?i)(reserve|supply|principal|balance|fee|ratio|limit|threshold|cap|"
    r"payout|reward|rate|price|quote|liquidity|borrow|collateral|debt|"
    r"index|max|min)"
)
_SINK_NAME_RE = re.compile(
    r"(?i)(reserve|supply|principal|fee|ratio|limit|threshold|cap|payout|"
    r"reward|rate|price|quote|liquidity|borrow|collateral|debt|index|max|min)"
)
_PRICING_CONTEXT_RE = re.compile(
    r"(?i)(quote|price|rate|ratio|reserve|liquidity|swap|mint|burn|redeem|"
    r"borrow|lend|payout|reward|fee|cap|limit|threshold|kLast|lastK)"
)
_POST_CAST_VALIDATION_RE = re.compile(
    r"(?is)\b(?:require|assert|if)\s*\([^;{}]*(?:<=|<|>=|>|==|!=)[^;{}]*\)"
)
_REJECT_WORD_RE = re.compile(r"(?i)(revert|return|throw|Invalid|Overflow|too large|exceed)")
_SAFE_CAST_RE = re.compile(
    r"(?is)(?:SafeCast|SafeCastLib|CastLib)\s*\.\s*toUint(?:8|16|24|32|40|48|56|64|72|80|88|96|104|112)\s*\(|"
    r"\.\s*toUint(?:8|16|24|32|40|48|56|64|72|80|88|96|104|112)\s*\("
)


def _blank(match: re.Match[str]) -> str:
    return "".join("\n" if ch == "\n" else " " for ch in match.group(0))


def _strip_comments_and_strings(source: str) -> str:
    source = re.sub(r"//[^\n]*", _blank, source)
    source = re.sub(r"/\*.*?\*/", _blank, source, flags=re.S)
    return _STRING_RE.sub(_blank, source)


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
            pos = max(j, i)
            continue

        depth = 1
        k = body_start + 1
        while k < len(source) and depth > 0:
            if source[k] == "{":
                depth += 1
            elif source[k] == "}":
                depth -= 1
            k += 1
        if depth != 0:
            pos = body_start + 1
            continue

        header = source[match.start():body_start]
        body = source[body_start + 1:k - 1]
        line = source.count("\n", 0, match.start()) + 1
        out.append(FunctionSlice(name=name, header=header, body=body, function_line=line))
        pos = k
    return out


def _line_for(function_line: int, text: str, match: re.Match[str]) -> int:
    return function_line + text.count("\n", 0, match.start())


def _cast_width(cast: str) -> int:
    match = re.search(r"\d+", cast)
    return int(match.group(0)) if match else 256


def _lhs_name(lhs: str) -> str:
    lhs = lhs.strip()
    lhs = re.sub(r"^" + _SMALL_UINT + r"\s+", "", lhs)
    lhs = lhs.split("[", 1)[0].split(".")[-1].strip()
    return lhs


def _is_local_declaration(lhs: str) -> bool:
    return bool(re.match(r"\s*" + _SMALL_UINT + r"\s+", lhs))


def _identifiers(expr: str) -> set[str]:
    return {
        token
        for token in re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", expr)
        if token not in {"uint256", "uint128", "uint112", "uint96", "uint64", "type"}
    }


def _bound_patterns(width: int) -> list[str]:
    return [
        r"type\s*\(\s*uint" + str(width) + r"\s*\)\s*\.\s*max",
        r"MAX_UINT" + str(width),
        r"MAX_U" + str(width),
        r"2\s*\*\*\s*" + str(width),
        r"1\s*<<\s*" + str(width),
    ]


def _has_pre_cast_bound(prefix: str, identifiers: set[str], cast: str) -> bool:
    if not identifiers:
        return False
    width = _cast_width(cast)
    window = prefix[-1600:]
    if _SAFE_CAST_RE.search(window[-420:]):
        return True

    for ident in identifiers:
        ident_re = r"\b" + re.escape(ident) + r"\b"
        for bound in _bound_patterns(width):
            patterns = [
                ident_re + r"[^;\n{}]{0,180}(?:<=|<)[^;\n{}]{0,80}" + bound,
                bound + r"[^;\n{}]{0,180}(?:>=|>)[^;\n{}]{0,80}" + ident_re,
                ident_re + r"[^;\n{}]{0,180}(?:>|>=)[^;\n{}]{0,80}" + bound,
            ]
            for pattern in patterns:
                match = re.search(pattern, window, flags=re.I | re.S)
                if not match:
                    continue
                local = window[max(0, match.start() - 160): match.end() + 220]
                if re.search(r"\b(?:require|assert|if)\b", local) and (
                    _REJECT_WORD_RE.search(local) or "require" in local or "assert" in local
                ):
                    return True
    return False


def _post_cast_validation(tail: str, alias: str) -> bool:
    alias_re = re.compile(r"\b" + re.escape(alias) + r"\b")
    for match in _POST_CAST_VALIDATION_RE.finditer(tail[:700]):
        text = match.group(0)
        if alias_re.search(text):
            return True
    return False


def _alias_sink_reason(tail: str, alias: str) -> str | None:
    alias_pat = r"(?:uint256\s*\(\s*)?\b" + re.escape(alias) + r"\b\s*\)?"
    storage_re = re.compile(
        r"(?is)\b(?P<lhs>[A-Za-z_][A-Za-z0-9_]*(?:\s*(?:\[[^\]]+\]|\.[A-Za-z_][A-Za-z0-9_]*))*)"
        r"\s*(?:=|\+=|-=)\s*[^;\n{}]*"
        + alias_pat
    )
    call_re = re.compile(
        r"(?is)\b(?:safeTransfer|transfer|transferFrom|_pay|pay|payout|claim|"
        r"settle|redeem|_mint|mint|burn|_burn|collect|distribute)\w*\s*"
        r"\([^;{}]*"
        + alias_pat
    )
    pricing_re = re.compile(
        r"(?is)(?:"
        r"\b(?:price|quote|rate|ratio|lastK|kLast|cap|limit|threshold)[A-Za-z0-9_]*"
        r"\s*(?:=|\+=|-=)\s*[^;{}]*(?:\*|/|\+|-)[^;{}]*"
        + alias_pat
        + r"|"
        r"\breturn\b[^;{}]*(?:\*|/|\+|-)[^;{}]*"
        + alias_pat
        + r")"
    )
    cap_re = re.compile(
        r"(?is)\brequire\s*\([^;{}]*(?:amount|value|borrow|mint|redeem|deposit|withdraw)"
        r"[^;{}]*(?:<=|<|>=|>)[^;{}]*"
        + alias_pat
    )

    scoped = tail[:1400]
    for storage_match in storage_re.finditer(scoped):
        if _SINK_NAME_RE.search(storage_match.group("lhs")):
            return "stored in an accounting sink"
    if call_re.search(scoped):
        return "used in a payout or mint/burn sink"
    if pricing_re.search(scoped):
        return "used in pricing, cap, or quote arithmetic"
    if cap_re.search(scoped):
        return "used as a cap or threshold after narrowing"
    return None


def _direct_assignment_reason(lhs: str) -> str | None:
    if _SINK_NAME_RE.search(_lhs_name(lhs)):
        return "stored directly in an accounting sink"
    return None


def _statement_bounds(text: str, start: int, end: int) -> tuple[int, int]:
    left = max(text.rfind(";", 0, start), text.rfind("{", 0, start), text.rfind("\n", 0, start))
    right_candidates = [idx for idx in (text.find(";", end), text.find("\n", end), text.find("}", end)) if idx >= 0]
    right = min(right_candidates) if right_candidates else len(text)
    return left + 1, right


def _statement_sink_reason(statement: str) -> str | None:
    if not _PRICING_CONTEXT_RE.search(statement):
        return None
    if re.search(r"(?is)\b(?:return|require|if|transfer|safeTransfer|_mint|mint|payout|pay|settle|claim)\b", statement):
        return "used directly in pricing, cap, or payout logic"
    if re.search(r"(?is)\b(?:price|quote|rate|ratio|cap|limit|threshold|payout|reward)[A-Za-z0-9_]*\s*=", statement):
        return "used directly in pricing, cap, or payout logic"
    return None


def _context_has_accounting_term(*parts: str) -> bool:
    return any(_ACCOUNTING_TERM_RE.search(part or "") for part in parts)


def _assignment_hazard(fn: FunctionSlice, text: str) -> tuple[re.Match[str], str] | None:
    for match in _CAST_ASSIGN_RE.finditer(text):
        lhs = match.group("lhs")
        alias = _lhs_name(lhs)
        expr = match.group("expr").strip()
        cast = match.group("cast")
        statement_start, statement_end = _statement_bounds(text, match.start(), match.end())
        statement = text[statement_start:statement_end]

        ids = _identifiers(expr)
        if _has_pre_cast_bound(text[: match.start()], ids, cast):
            continue

        direct_reason = None if _is_local_declaration(lhs) else _direct_assignment_reason(lhs)
        sink_reason = direct_reason or _alias_sink_reason(text[match.end():], alias)
        if sink_reason is None:
            continue

        if not _context_has_accounting_term(fn.name, lhs, expr, statement, text[match.end(): match.end() + 500]):
            continue

        validation = " after only post-cast validation" if _post_cast_validation(text[match.end():], alias) else ""
        return match, f"{alias} narrows {expr} to {cast}{validation} and is {sink_reason}"
    return None


def _inline_hazard(fn: FunctionSlice, text: str) -> tuple[re.Match[str], str] | None:
    for match in _INLINE_CAST_RE.finditer(text):
        expr = match.group("expr").strip()
        cast = match.group("cast")
        ids = _identifiers(expr)
        if _has_pre_cast_bound(text[: match.start()], ids, cast):
            continue

        statement_start, statement_end = _statement_bounds(text, match.start(), match.end())
        statement = text[statement_start:statement_end]
        sink_reason = _statement_sink_reason(statement)
        if sink_reason is None:
            continue
        if not _context_has_accounting_term(fn.name, expr, statement):
            continue
        return match, f"{expr} is narrowed to {cast} and {sink_reason}"
    return None


def _hazard(fn: FunctionSlice) -> tuple[re.Match[str], str] | None:
    text = f"{fn.header}\n{fn.body}"
    return _assignment_hazard(fn, text) or _inline_hazard(fn, text)


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    stripped = _strip_comments_and_strings(source)
    findings: list[Finding] = []
    for fn in _split_functions(stripped):
        text = f"{fn.header}\n{fn.body}"
        result = _hazard(fn)
        if result is None:
            continue
        match, reason = result
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=_line_for(fn.function_line, text, match),
                severity=DETECTOR_SEVERITY_DEFAULT,
                function=fn.name,
                message=(
                    f"`{fn.name}` narrows an accounting value before a wide "
                    f"bound check: {reason}. Validate against the target "
                    "integer width before casting. (class: integer-overflow-clamp)"
                ),
            )
        )
    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
