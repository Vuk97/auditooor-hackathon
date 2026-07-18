"""
integer-clamp-fee-scale-fire34

Detects Solidity fee, reserve, and scale math where a value is narrowed to a
small unsigned integer before the cap or clamp is applied. This lifts the
integer-overflow-clamp Fire31/Fire32 shape into basis-point fee math, compact
reserve caps, and scale-limit setters.

Provenance:
- context_pack_id: auditooor.vault_context_pack.v1:resume:bfadc3c938400bc6
- context_pack_hash: bfadc3c938400bc6618f7f3ae8d500bbc8e5dce19f7f4e6c043195ffc6742129
- source ref: reports/detector_lift_fire33_20260605/post_priorities_all.md
- source ref: reference/patterns.dsl/integer-overflow-clamp-arithmetic-loss.yaml
- source ref: detectors/go_wave1/go-integer-overflow-config-clamp-fire31.py
- source ref: detectors/wave17/integer_overflow_reserve_clamp_fire32.py
- attack_class: integer-overflow-clamp

Hits are candidate evidence only. NOT_SUBMIT_READY. A finding still needs a
real source path, negative control, and R40/R76/R80 proof before filing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "integer-clamp-fee-scale-fire34"
DETECTOR_SEVERITY_DEFAULT = "Medium"
SUBMISSION_POSTURE = "NOT_SUBMIT_READY"


@dataclass(frozen=True)
class Finding:
    detector: str
    file: str
    line: int
    severity: str
    message: str
    function: Optional[str] = None


@dataclass(frozen=True)
class FunctionSlice:
    name: str
    header: str
    body: str
    function_line: int


_SMALL_WIDTHS = (8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 120, 128)
_SMALL_UINT = r"uint(?:" + "|".join(str(width) for width in _SMALL_WIDTHS) + r")"

_COMMENT_OR_STRING_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'|"
    r"//[^\n\r]*|"
    r"/\*.*?\*/",
    re.DOTALL,
)
_FN_HEADER_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_VISIBLE_RE = re.compile(r"\b(?:external|public|internal)\b")
_VIEW_OR_PURE_RE = re.compile(r"\b(?:view|pure)\b")

_CAST_ASSIGN_RE = re.compile(
    r"(?is)\b(?:(?P<decl>" + _SMALL_UINT + r")\s+)?"
    r"(?P<lhs>[A-Za-z_][A-Za-z0-9_]*(?:\s*(?:\[[^\]]+\]|\.[A-Za-z_][A-Za-z0-9_]*))*)"
    r"\s*=\s*(?P<cast>" + _SMALL_UINT + r")\s*\(\s*(?P<expr>[^;{}]+?)\s*\)\s*;"
)

_FEE_SCALE_CONTEXT_RE = re.compile(
    r"(?i)(fee|fees|feeBps|bps|basis|BPS|BASIS_POINTS|premium|protocolFee|"
    r"reserve|reserves|cap|caps|limit|threshold|max|min|scale|scaled|scalar|"
    r"ratio|rate|precision|liquidity|borrow|collateral|debt)"
)
_CAP_NAME_RE = re.compile(
    r"(?i)(cap|limit|max|min|threshold|ceil|floor|bound|reserve|fee|scale|ratio|rate)"
)
_SINK_NAME_RE = re.compile(
    r"(?i)(fee|fees|premium|protocolFee|reserve|reserves|cap|limit|threshold|"
    r"scale|ratio|rate|liquidity|borrow|collateral|debt|payout|reward|accrued)"
)
_SAFE_EXPR_RE = re.compile(
    r"(?is)(?:SafeCast|SafeCastLib|CastLib|FullMath|FixedPointMathLib|"
    r"Math\s*\.\s*mulDiv|mulDiv|toUint(?:8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128)"
    r"\s*\(|checked|bounded|capped|clamped)"
)
_POST_CAST_VALIDATE_RE = re.compile(r"(?is)\b(?:require|assert|if)\s*\([^;{}]*(?:<=|<|>=|>)[^;{}]*\)")


def _strip_comments_and_strings(source: str) -> str:
    def replace(match: re.Match[str]) -> str:
        text = match.group(0)
        return "\n" * text.count("\n") if "\n" in text else " "

    return _COMMENT_OR_STRING_RE.sub(replace, source or "")


def _find_matching_delimiter(source: str, open_pos: int, open_char: str, close_char: str) -> int:
    if open_pos < 0 or open_pos >= len(source) or source[open_pos] != open_char:
        return -1
    depth = 1
    index = open_pos + 1
    while index < len(source) and depth > 0:
        if source[index] == open_char:
            depth += 1
        elif source[index] == close_char:
            depth -= 1
        index += 1
    return index - 1 if depth == 0 else -1


def _split_functions(source: str) -> list[FunctionSlice]:
    out: list[FunctionSlice] = []
    pos = 0
    while True:
        match = _FN_HEADER_RE.search(source, pos)
        if match is None:
            break
        name = match.group("name")
        open_paren = source.find("(", match.end() - 1)
        close_paren = _find_matching_delimiter(source, open_paren, "(", ")")
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

        body_end = _find_matching_delimiter(source, body_start, "{", "}")
        if body_end < 0:
            pos = body_start + 1
            continue

        out.append(
            FunctionSlice(
                name=name,
                header=source[match.start():body_start],
                body=source[body_start + 1:body_end],
                function_line=source.count("\n", 0, match.start()) + 1,
            )
        )
        pos = body_end + 1
    return out


def _line_for(function_line: int, text: str, match: re.Match[str]) -> int:
    return function_line + text.count("\n", 0, match.start())


def _cast_width(cast: str) -> int:
    match = re.search(r"\d+", cast)
    return int(match.group(0)) if match else 256


def _identifiers(expr: str) -> set[str]:
    ignored = {
        "uint",
        "uint8",
        "uint16",
        "uint24",
        "uint32",
        "uint40",
        "uint48",
        "uint56",
        "uint64",
        "uint72",
        "uint80",
        "uint88",
        "uint96",
        "uint104",
        "uint112",
        "uint120",
        "uint128",
        "uint256",
        "type",
    }
    return {
        token
        for token in re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", expr)
        if token not in ignored
    }


def _has_context(*parts: str) -> bool:
    return any(_FEE_SCALE_CONTEXT_RE.search(part or "") for part in parts)


def _is_unsafe_expr(expr: str) -> bool:
    if _SAFE_EXPR_RE.search(expr):
        return False
    if "*" in expr or "-" in expr:
        return True
    return bool(_FEE_SCALE_CONTEXT_RE.search(expr))


def _target_max_patterns(width: int) -> list[str]:
    return [
        r"type\s*\(\s*uint" + str(width) + r"\s*\)\s*\.\s*max",
        r"MAX_UINT" + str(width),
        r"MAX_U" + str(width),
        r"2\s*\*\*\s*" + str(width),
        r"1\s*<<\s*" + str(width),
    ]


def _guard_local_window(window: str, start: int, end: int) -> str:
    return window[max(0, start - 180): min(len(window), end + 260)]


def _has_pre_cast_bound(prefix: str, identifiers: set[str], cast: str) -> bool:
    if not identifiers:
        return False
    width = _cast_width(cast)
    window = prefix[-1800:]

    for ident in identifiers:
        ident_re = r"\b" + re.escape(ident) + r"\b"
        for bound in _target_max_patterns(width):
            bound_re = r"(?:" + bound + r")"
            patterns = (
                ident_re + r"[^;{}]{0,220}(?:<=|<)[^;{}]{0,140}" + bound_re,
                bound_re + r"[^;{}]{0,220}(?:>=|>)[^;{}]{0,140}" + ident_re,
                ident_re + r"[^;{}]{0,220}(?:>|>=)[^;{}]{0,140}" + bound_re,
                ident_re + r"[^;{}]{0,220}(?:<=|<)[^;{}]{0,140}" + bound_re + r"\s*/",
            )
            for pattern in patterns:
                match = re.search(pattern, window, flags=re.I | re.S)
                if not match:
                    continue
                local = _guard_local_window(window, match.start(), match.end())
                if re.search(r"\b(?:require|assert|if)\b", local) and re.search(
                    r"\b(?:revert|return|Overflow|overflow|too large|require|assert)\b",
                    local,
                    re.I,
                ):
                    return True

        business_cap = re.compile(
            ident_re
            + r"[^;{}]{0,180}(?:<=|<|>|>=)[^;{}]{0,100}"
            + r"[A-Za-z_][A-Za-z0-9_]*(?:Cap|Limit|Max|Threshold|Ceil|Floor)"
            r"|"
            r"[A-Za-z_][A-Za-z0-9_]*(?:Cap|Limit|Max|Threshold|Ceil|Floor)"
            + r"[^;{}]{0,180}(?:>=|>|<=|<)[^;{}]{0,100}"
            + ident_re,
            re.I | re.S,
        )
        for match in business_cap.finditer(window):
            local = _guard_local_window(window, match.start(), match.end())
            if re.search(r"\b(?:require|assert|if)\b", local) and re.search(
                r"\b(?:revert|return|require|assert)\b|[A-Za-z_][A-Za-z0-9_]*\s*=",
                local,
                re.I,
            ):
                return True
    return False


def _post_cast_cap_reason(tail: str, alias: str) -> str | None:
    alias_re = r"\b" + re.escape(alias) + r"\b"
    cap_re = r"[A-Za-z_][A-Za-z0-9_]*(?:Cap|Limit|Max|Threshold|Ceil|Floor|Reserve|Fee|Scale|Ratio|Rate)[A-Za-z0-9_]*"
    scoped = tail[:1000]

    math_min = re.compile(
        alias_re + r"\s*=\s*(?:Math\s*\.\s*)?min\s*\([^;{}]*" + alias_re + r"[^;{}]*" + cap_re,
        re.I | re.S,
    )
    if math_min.search(scoped):
        return "clamped with min after the narrow cast"

    ternary = re.compile(
        alias_re
        + r"\s*=\s*[^;{}]*"
        + alias_re
        + r"[^;{}]*(?:>|>=|<|<=)[^;{}]*"
        + cap_re
        + r"[^;{}]*\?[^;{}]*;",
        re.I | re.S,
    )
    if ternary.search(scoped):
        return "capped by a ternary after the narrow cast"

    for match in _POST_CAST_VALIDATE_RE.finditer(scoped):
        text = match.group(0)
        if not re.search(alias_re, text):
            continue
        if _CAP_NAME_RE.search(text):
            if text.lower().lstrip().startswith("if"):
                block = scoped[match.end(): match.end() + 220]
                if re.search(alias_re + r"\s*=", block):
                    return "clamped in an if block after the narrow cast"
            return "validated against a cap after the narrow cast"
    return None


def _has_sink_after_cap(tail: str, alias: str) -> bool:
    alias_re = r"\b" + re.escape(alias) + r"\b"
    scoped = tail[:1400]

    storage_write = re.compile(
        r"(?is)\b(?P<lhs>[A-Za-z_][A-Za-z0-9_]*(?:\s*(?:\[[^\]]+\]|\.[A-Za-z_][A-Za-z0-9_]*))*)"
        r"\s*(?:=|\+=|-=)\s*(?:uint256\s*\(\s*)?"
        + alias_re
    )
    for match in storage_write.finditer(scoped):
        if _SINK_NAME_RE.search(match.group("lhs")):
            return True

    call_sink = re.compile(
        r"(?is)\b(?:safeTransfer|transfer|transferFrom|_mint|mint|_burn|burn|"
        r"pay|payout|collect|settle|account|record|credit|debit|update|set)"
        r"[A-Za-z0-9_]*\s*\([^;{}]*"
        + alias_re
    )
    if call_sink.search(scoped):
        return True

    return bool(re.search(r"(?is)\breturn\b[^;{}]*" + alias_re, scoped))


def _cast_hazard(fn: FunctionSlice, text: str) -> tuple[re.Match[str], str] | None:
    if not _VISIBLE_RE.search(fn.header):
        return None
    for match in _CAST_ASSIGN_RE.finditer(text):
        lhs = match.group("lhs").strip()
        alias = lhs.split("[", 1)[0].split(".")[-1].strip()
        cast = match.group("cast")
        expr = match.group("expr").strip()
        tail = text[match.end():]

        if not _has_context(fn.name, fn.header, lhs, expr, text):
            continue
        if not _is_unsafe_expr(expr):
            continue
        if _has_pre_cast_bound(text[: match.start()], _identifiers(expr), cast):
            continue
        cap_reason = _post_cast_cap_reason(tail, alias)
        if cap_reason is None:
            continue
        if not _has_sink_after_cap(tail, alias) and not _VIEW_OR_PURE_RE.search(fn.header):
            continue

        reason = f"{alias} narrows {expr} to {cast}, then is {cap_reason}"
        return match, reason
    return None


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    stripped = _strip_comments_and_strings(source)
    findings: list[Finding] = []
    for fn in _split_functions(stripped):
        text = f"{fn.header}\n{fn.body}"
        result = _cast_hazard(fn, text)
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
                    f"`{fn.name}` applies fee/reserve/scale caps after a small "
                    f"integer cast: {reason}. Apply the cap and target-width "
                    "bound to the wide value before casting. "
                    "(class: integer-overflow-clamp, posture: NOT_SUBMIT_READY)"
                ),
            )
        )
    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT", "SUBMISSION_POSTURE"]
