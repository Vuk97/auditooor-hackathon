"""
integer-clamp-underflow-fire38

Solidity recall-lift detector for fee, flashloan, surge, and IRM math where
arithmetic is performed before the bound that was meant to protect it:

* subtracting a fee, premium, surge-fee, kink, or rate value before checking
  that the minuend is large enough;
* multiplying or adding fee/rate terms before applying a cap or clamp;
* narrowing fee/rate values to a small uint before validating the source
  value, allowing a nonzero value to truncate to zero.

The detector is intentionally domain-scoped. A finding needs fee, flashloan,
surge, IRM, borrow-rate, kink, or swap math context plus a later clamp, sink,
or cast use. Hits are candidate evidence only.

Provenance:
- context_pack_id: auditooor.vault_context_pack.v1:resume:d13bd9d230bee9a9
- context_pack_hash: d13bd9d230bee9a9be7b0163da353a019de15118dc6e4d3986c543a54d28abff
- MCP receipt: .auditooor/memory_context_receipt.json
- source ref: reports/detector_lift_fire37_20260605/post_priorities_solidity.md
- source ref: detectors/wave17/fund_loss_external_transfer_math_fire36.py
- source ref: reference/patterns.dsl/unsafe-downcast-uint-truncation.yaml
- seed: flashloan-fee-underflow-or-missing
- seed: fx-balancer-surge-fee-underflow
- attack_class: integer-overflow-clamp

R37: provenance is declared at emit time in this module docstring.
R40/R76/R80: detector hits are NOT proof of exploitability or source
existence. Promote only after source-grep, real-path PoC, negative control,
and non-vacuous evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "integer-clamp-underflow-fire38"
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
    branch: Optional[str] = None


@dataclass(frozen=True)
class FunctionSlice:
    name: str
    header: str
    body: str
    function_line: int


_SMALL_WIDTHS = (8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 120, 128)
_SMALL_UINT = r"uint(?:" + "|".join(str(width) for width in _SMALL_WIDTHS) + r")"

_TOKEN_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'|"
    r"//[^\n\r]*|"
    r"/\*.*?\*/",
    re.DOTALL,
)
_FN_HEADER_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_VISIBLE_RE = re.compile(r"\b(?:external|public|internal)\b")

_DOMAIN_RE = re.compile(
    r"(?is)(?:amount|apr|borrow|borrowRate|bps|cap|charge|debt|fee|fees|"
    r"flash|flashLoan|flashloan|irm|kink|liquidat|loan|max|min|output|"
    r"premium|protocolFee|rate|repay|repayment|slope|spread|staticFee|"
    r"surge|swap|utilization|value)"
)
_ENTRY_RE = re.compile(
    r"(?i)(?:borrow|charge|fee|flash|irm|liquidat|premium|quote|rate|repay|"
    r"slope|spread|surge|swap)"
)
_BOUND_WORD_RE = (
    r"amount|basis|Basis|bps|BPS|cap|Cap|ceil|Ceil|fee|Fee|floor|Floor|"
    r"kink|Kink|limit|Limit|max|Max|min|Min|rate|Rate|threshold|Threshold|"
    r"utilization|Utilization"
)
_FEE_OR_KINK_STEM = (
    r"fee|Fee|premium|Premium|charge|Charge|spread|Spread|surge|Surge|"
    r"staticFee|StaticFee|protocolFee|ProtocolFee|liquidationFee|"
    r"LiquidationFee|penalty|Penalty|rate|Rate|kink|Kink|slope|Slope"
)
_FEE_OR_KINK_NAME_RE = (
    rf"(?:[A-Za-z_][A-Za-z0-9_]*(?:{_FEE_OR_KINK_STEM})[A-Za-z0-9_]*|"
    rf"(?:{_FEE_OR_KINK_STEM})[A-Za-z0-9_]*)"
)
_RESULT_NAME_RE = (
    r"(?:"
    r"[A-Za-z_][A-Za-z0-9_]*(?:Amount|amount|Apr|APR|Bps|bps|Delta|delta|"
    r"Due|due|Fee|fee|Kink|kink|Net|net|Out|out|Output|output|Payout|"
    r"payout|Premium|premium|Proceeds|proceeds|Range|range|Rate|rate|"
    r"Repay|repay|Slope|slope|Spread|spread|Surge|surge|Value|value)"
    r"[A-Za-z0-9_]*|"
    r"amountAfterFee|borrowApr|borrowRate|borrowerProceeds|effectivePremium|"
    r"feeDelta|netAmount|netOut|owed|payout|premium|range|rateDelta|"
    r"surgeRange)"
)

_SUB_ASSIGN_RE = re.compile(
    rf"(?is)\b(?:uint(?:256|128|64|32|16|8)?\s+)?"
    rf"(?P<out>{_RESULT_NAME_RE})\s*=\s*"
    rf"(?P<left>[^;{{}}]{{1,260}}?)\s*-\s*(?P<right>{_FEE_OR_KINK_NAME_RE})"
    rf"(?P<trail>[^;{{}}]{{0,120}})\s*;"
)
_ARITH_ASSIGN_RE = re.compile(
    rf"(?is)\b(?:uint(?:256|128|64|32|16|8)?\s+)?"
    rf"(?P<out>{_RESULT_NAME_RE})\s*=\s*(?P<expr>[^;{{}}]{{1,360}}(?:\*|\+)"
    rf"[^;{{}}]{{1,260}})\s*;"
)
_CAST_ASSIGN_RE = re.compile(
    rf"(?is)\b(?:(?P<decl>{_SMALL_UINT})\s+)?"
    rf"(?P<out>{_RESULT_NAME_RE})\s*=\s*(?P<cast>{_SMALL_UINT})\s*"
    rf"\(\s*(?P<expr>[^;{{}}]+?)\s*\)\s*;"
)

_SAFE_ARITH_RE = re.compile(
    r"(?is)\b(?:SafeMath|checkedSub|trySub|subOrZero|saturat|mulDiv|"
    r"FullMath|FixedPointMathLib|Math\s*\.\s*mulDiv|Math\s*\.\s*min|"
    r"Math\s*\.\s*max|ceilDiv|Rounding\s*\.\s*(?:Up|Ceil))\b"
)
_SAFE_CAST_RE = re.compile(
    r"(?is)\b(?:SafeCast|SafeCastLib|CastLib|toUint(?:8|16|24|32|40|48|56|"
    r"64|72|80|88|96|104|112|120|128)\s*\()"
)
_SINK_RE = re.compile(
    r"(?is)\b(?:return|transfer|safeTransfer|transferFrom|_mint|mint|_burn|"
    r"burn|pay|payout|settle|collect|repay|charge|credit|debit|update|set)"
)

_IGNORED_IDENTIFIERS = {
    "Math",
    "SafeCast",
    "SafeMath",
    "assert",
    "if",
    "max",
    "min",
    "require",
    "return",
    "type",
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
}


def _strip_comments_and_strings(source: str) -> str:
    def replace_token(match: re.Match[str]) -> str:
        text = match.group(0)
        return "\n" * text.count("\n") if "\n" in text else " "

    return _TOKEN_RE.sub(replace_token, source or "")


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


def _identifiers(expr: str) -> set[str]:
    return {
        token
        for token in re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", expr or "")
        if token not in _IGNORED_IDENTIFIERS
    }


def _has_domain_context(fn: FunctionSlice, text: str, expr: str) -> bool:
    return bool((_ENTRY_RE.search(fn.name) or _DOMAIN_RE.search(text)) and _DOMAIN_RE.search(expr))


def _window(text: str, start: int, end: int, before: int = 900, after: int = 700) -> str:
    return text[max(0, start - before): min(len(text), end + after)]


def _cast_width(cast: str) -> int:
    match = re.search(r"\d+", cast or "")
    return int(match.group(0)) if match else 256


def _type_max_patterns(width: int) -> list[str]:
    return [
        rf"type\s*\(\s*uint{width}\s*\)\s*\.\s*max",
        rf"MAX_UINT{width}",
        rf"MAX_U{width}",
        rf"2\s*\*\*\s*{width}",
        rf"1\s*<<\s*{width}",
    ]


def _has_pre_subtraction_guard(text: str, left_expr: str, right_name: str, start: int) -> bool:
    before = text[:start][-1800:]
    right = re.escape(right_name)
    left_ids = _identifiers(left_expr)

    if re.search(rf"(?is)\b{right}\b\s*=\s*(?:Math\s*\.\s*)?min\s*\(", before):
        return True

    for left_name in left_ids:
        left = re.escape(left_name)
        guard_patterns = [
            rf"require\s*\([^;{{}}]*(?:\b{right}\b[^;{{}}]*(?:<=|<)[^;{{}}]*\b{left}\b|"
            rf"\b{left}\b[^;{{}}]*(?:>=|>)[^;{{}}]*\b{right}\b)",
            rf"if\s*\([^;{{}}]*(?:\b{right}\b[^;{{}}]*(?:>|>=)[^;{{}}]*\b{left}\b|"
            rf"\b{left}\b[^;{{}}]*(?:<|<=)[^;{{}}]*\b{right}\b)[^;{{}}]*\)\s*"
            rf"(?:\{{[^{{}}]{{0,260}}(?:revert|return|{right}\s*=)|(?:revert|return|{right}\s*=))",
            rf"if\s*\([^;{{}}]*\b{left}\b[^;{{}}]*(?:<=|<)[^;{{}}]*\b{right}\b[^;{{}}]*\)"
            rf"\s*(?:\{{[^{{}}]{{0,260}}(?:revert|return)|(?:revert|return))",
        ]
        if any(re.search(pattern, before, re.I | re.S) for pattern in guard_patterns):
            return True
    return False


def _has_post_clamp_or_bound(text: str, out_name: str, start: int) -> bool:
    tail = text[start:start + 1300]
    out = re.escape(out_name)
    if re.search(
        rf"(?is)if\s*\([^;{{}}]*\b{out}\b[^;{{}}]*(?:<|>|<=|>=)[^;{{}}]*(?:{_BOUND_WORD_RE})"
        rf"[^;{{}}]*\)\s*(?:\{{[^{{}}]{{0,320}}\b{out}\b\s*=|\b{out}\b\s*=)",
        tail,
    ):
        return True
    if re.search(
        rf"(?is)\b{out}\b\s*=\s*(?:(?:Math\s*\.\s*)?(?:min|max)\s*\(|"
        rf"\b{out}\b[^;{{}}?]*(?:>|<|>=|<=)[^;{{}}?]*(?:{_BOUND_WORD_RE})[^;{{}}?]*\?)",
        tail,
    ):
        return True
    return False


def _has_sink_after(text: str, out_name: str, start: int) -> bool:
    tail = text[start:start + 1200]
    out = re.escape(out_name)
    return bool(_SINK_RE.search(tail) and re.search(rf"\b{out}\b", tail))


def _has_pre_mul_or_add_bound(text: str, expr: str, start: int) -> bool:
    before = text[:start][-1800:]
    ids = sorted(_identifiers(expr), key=len, reverse=True)
    if _SAFE_ARITH_RE.search(_window(text, start, start, before=650, after=350)):
        return True
    for left in ids:
        for right in ids:
            if left == right:
                continue
            left_re = re.escape(left)
            right_re = re.escape(right)
            if re.search(
                rf"(?is)require\s*\([^;{{}}]*(?:\b{left_re}\b[^;{{}}]*(?:<=|<)[^;{{}}]*(?:max|Max|type)"
                rf"[^;{{}}]*/[^;{{}}]*\b{right_re}\b|\b{right_re}\b[^;{{}}]*(?:<=|<)[^;{{}}]*(?:max|Max|type)"
                rf"[^;{{}}]*/[^;{{}}]*\b{left_re}\b)",
                before,
            ):
                return True
    return False


def _has_pre_cast_bound(text: str, expr: str, cast: str, start: int) -> bool:
    before = text[:start][-1800:]
    ids = _identifiers(expr)
    width = _cast_width(cast)
    if _SAFE_CAST_RE.search(_window(text, start, start, before=650, after=120)):
        return True
    for ident in ids:
        ident_re = re.escape(ident)
        for bound in _type_max_patterns(width):
            patterns = [
                rf"require\s*\([^;{{}}]*\b{ident_re}\b[^;{{}}]*(?:<=|<)[^;{{}}]*(?:{bound})",
                rf"if\s*\([^;{{}}]*\b{ident_re}\b[^;{{}}]*(?:>|>=)[^;{{}}]*(?:{bound})[^;{{}}]*\)"
                rf"\s*(?:\{{[^{{}}]{{0,260}}(?:revert|return)|(?:revert|return))",
            ]
            if any(re.search(pattern, before, re.I | re.S) for pattern in patterns):
                return True
    return False


def _subtraction_before_bound_match(fn: FunctionSlice, text: str) -> tuple[re.Match[str], str] | None:
    for match in _SUB_ASSIGN_RE.finditer(text):
        out_name = match.group("out")
        left = match.group("left").strip()
        right = match.group("right").strip()
        expr = f"{left} - {right}{match.group('trail') or ''}"

        if not _has_domain_context(fn, text, f"{out_name} {expr}"):
            continue
        if _SAFE_ARITH_RE.search(_window(text, match.start(), match.end())):
            continue
        if _has_pre_subtraction_guard(text, left, right, match.start()):
            continue
        if not _has_post_clamp_or_bound(text, out_name, match.end()):
            continue
        if not _has_sink_after(text, out_name, match.end()):
            continue

        return match, f"{out_name} subtracts {right} before checking the lower bound"
    return None


def _overflow_before_clamp_match(fn: FunctionSlice, text: str) -> tuple[re.Match[str], str] | None:
    for match in _ARITH_ASSIGN_RE.finditer(text):
        out_name = match.group("out")
        expr = match.group("expr").strip()
        if "-" in expr:
            continue
        if not _has_domain_context(fn, text, f"{out_name} {expr}"):
            continue
        if not re.search(r"(?is)(fee|premium|surge|rate|kink|bps|slope|utilization)", expr):
            continue
        if _has_pre_mul_or_add_bound(text, expr, match.start()):
            continue
        if not _has_post_clamp_or_bound(text, out_name, match.end()):
            continue
        if not _has_sink_after(text, out_name, match.end()):
            continue

        return match, f"{out_name} computes fee or rate arithmetic before applying the cap"
    return None


def _unsafe_cast_zero_match(fn: FunctionSlice, text: str) -> tuple[re.Match[str], str] | None:
    for match in _CAST_ASSIGN_RE.finditer(text):
        out_name = match.group("out")
        expr = match.group("expr").strip()
        cast = match.group("cast")
        if _cast_width(cast) > 128:
            continue
        if not _has_domain_context(fn, text, f"{out_name} {expr} {cast}"):
            continue
        if not re.search(r"(?is)(fee|premium|rate|kink|bps|slope|surge|utilization)", f"{out_name} {expr}"):
            continue
        if _has_pre_cast_bound(text, expr, cast, match.start()):
            continue
        if not _has_sink_after(text, out_name, match.end()):
            continue

        return match, f"{out_name} narrows {expr} to {cast} before range validation"
    return None


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    stripped = _strip_comments_and_strings(source)
    findings: list[Finding] = []

    for fn in _split_functions(stripped):
        if not _VISIBLE_RE.search(fn.header):
            continue
        text = f"{fn.header}\n{fn.body}"
        candidates = (
            ("subtract-before-bound", _subtraction_before_bound_match(fn, text)),
            ("overflow-before-clamp", _overflow_before_clamp_match(fn, text)),
            ("unsafe-cast-zero", _unsafe_cast_zero_match(fn, text)),
        )
        match_with_reason = next(((branch, item) for branch, item in candidates if item is not None), None)
        if match_with_reason is None:
            continue

        branch, (match, reason) = match_with_reason
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=_line_for(fn.function_line, text, match),
                severity=DETECTOR_SEVERITY_DEFAULT,
                function=fn.name,
                branch=branch,
                message=(
                    f"`{fn.name}` performs fee, surge, flashloan, or IRM math "
                    f"before the protective bound: {reason}. Validate or "
                    "saturate the source value before arithmetic or narrowing, "
                    "then clamp the already-safe wide value. (class: "
                    "integer-overflow-clamp, posture: NOT_SUBMIT_READY)"
                ),
            )
        )

    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT", "SUBMISSION_POSTURE"]
