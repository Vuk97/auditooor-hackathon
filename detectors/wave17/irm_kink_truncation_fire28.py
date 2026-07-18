"""
irm-kink-truncation-fire28

Solidity recall-lift detector for interest-rate-model, utilization, and quote
math where kink, threshold, scale, rate, or quote values are downcast,
divided before fixed-point scaling, or compared across incompatible units.

Provenance:
- context_pack_id: auditooor.vault_context_pack.v1:resume:86c2076101171056
- context_pack_hash: 86c2076101171056d88e0073a7354a1cf2324d92f13627249a1c5ece0c70b722
- source ref: reference/patterns.dsl.zellic_k2_mined/amm-quote-overflow-can-disable-swaps-and-liquidations.yaml
- source ref: reference/patterns.dsl.r75_mined/firms_zellic_ottersec_nethermind/scaled-vs-unscaled-threshold-comparison.yaml
- attack_class: integer-overflow-clamp

Hits are candidate evidence only. NOT_SUBMIT_READY.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "irm-kink-truncation-fire28"
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


_COMMENT_OR_STRING_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'|"
    r"//[^\n\r]*|"
    r"/\*.*?\*/",
    re.DOTALL,
)
_FN_HEADER_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_VISIBILITY_RE = re.compile(r"\b(?:external|public|internal|private)\b")

_RATE_CONTEXT_RE = re.compile(
    r"(?is)(?:"
    r"\b(?:irm|interest|borrowRate|supplyRate|ratePer|baseRate|rateSlope|"
    r"slope1|slope2|maxRate|minRate|utilization|utilisation|utilRate|"
    r"kink|targetUtilization|threshold|ltv|healthFactor|quote|amountOut|"
    r"amountIn|reserveIn|reserveOut|liquidat|collateral|debt)\b|"
    r"\b(?:WAD|RAY|BPS|BASE|SCALE|PIPS|DENOMINATOR|ONE|PRECISION)\b|"
    r"\b(?:1e6|1e8|1e12|1e18|1e27|10\s*\*\*\s*(?:6|8|12|18|27))\b"
    r")"
)
_FUNCTION_NAME_CONTEXT_RE = re.compile(
    r"(?i)(?:irm|interest|borrow|supply|rate|utili[sz]ation|quote|amountout|"
    r"swap|liquidat|collateral|health|ltv)"
)

_SCALE_MARKER_RE = re.compile(
    r"(?is)(?:"
    r"\b(?:WAD|RAY|BPS|BASE|SCALE|PIPS|DENOMINATOR|PRECISION|ONE)\b|"
    r"\b(?:1e6|1e8|1e12|1e18|1e27|10\s*\*\*\s*(?:6|8|12|18|27))\b|"
    r"(?:Wad|Ray|Bps|Scaled|Scale|Precision|Fixed)"
    r")"
)
_FP_MATH_RE = re.compile(
    r"(?is)(?:"
    r"\b(?:mulDiv|fullMulDiv|mulWad|divWad|mulWadDown|divWadDown|"
    r"wadDiv|rayDiv|wadMul|rayMul|toWad|toRay|toBps|scaleTo|normalize|"
    r"normalized|FixedPoint|FixedPointMathLib|PRBMath|ABDKMath|Math)\b|"
    r"\.\s*(?:mulDiv|toUint8|toUint16|toUint32|toUint64|toUint96|"
    r"toUint128|toUint160|toUint224)\s*\("
    r")"
)
_SAFE_CAST_CONTEXT_RE = re.compile(
    r"(?is)(?:"
    r"\bSafeCast\b|"
    r"\.\s*toUint(?:8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|160)\s*\(|"
    r"\btoUint(?:8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|160)\s*\("
    r")"
)
_TYPE_BOUND_RE = re.compile(
    r"(?is)\brequire\s*\([^;{}]*<=\s*type\s*\(\s*uint(?:8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|160)\s*\)\s*\.\s*max"
)

_CAST_RE = re.compile(
    r"(?is)\buint(?P<bits>8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|160)\s*"
    r"\(\s*(?P<expr>[^(){};]{1,180})\s*\)"
)
_DANGEROUS_VALUE_RE = re.compile(
    r"(?is)\b(?:kink|threshold|target|utili[sz]ation|rate|maxRate|minRate|"
    r"baseRate|slope|borrow|supply|quote|amountOut|amountIn|reserve|scale|"
    r"collateral|healthFactor|ltv|ratio)\b"
)
_LOCAL_DECL_RE = re.compile(
    r"(?is)\b(?:uint(?:256|224|192|160|128|96|64|32|16|8)?|int(?:256|128|64|32)?)\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<expr>[^;{}]+);"
)
_DIV_BEFORE_SCALE_RE = re.compile(
    r"(?is)=\s*(?:\([^;{}]*\)|[^;{}=]{0,220})/"
    r"[^;{}=]{1,220}\*\s*(?:[A-Za-z_][A-Za-z0-9_]*|1e\d+|10\s*\*\*\s*\d+)"
)
_DIV_BEFORE_SCALE_INLINE_RE = re.compile(
    r"(?is)(?:return|,|\()\s*(?:\([^;{}]*\)|[^;{}=]{0,220})/"
    r"[^;{}=]{1,220}\*\s*(?:[A-Za-z_][A-Za-z0-9_]*|1e\d+|10\s*\*\*\s*\d+)"
)
_QUOTE_DIV_BEFORE_MULTIPLY_RE = re.compile(
    r"(?is)(?:return|=)\s*[^;{}]*(?:amount|reserve|quote)[A-Za-z0-9_]*"
    r"[^;{}]*/\s*[^;{}]*(?:reserve|amount|quote)[A-Za-z0-9_]*"
    r"[^;{}]*\*\s*[^;{}]*(?:reserve|amount|quote)[A-Za-z0-9_]*"
)

_IF_CONDITION_RE = re.compile(r"(?is)\bif\s*\(\s*(?P<cond>[^{};]{1,260})\)")
_COMPARISON_RE = re.compile(
    r"(?is)(?P<left>[A-Za-z_][A-Za-z0-9_.()]*|\d+(?:e\d+)?)\s*"
    r"(?P<op><=|>=|<|>)\s*"
    r"(?P<right>[A-Za-z_][A-Za-z0-9_.()]*|\d+(?:e\d+)?)"
)
_SMALL_THRESHOLD_RE = re.compile(r"^(?:[1-9]\d{0,2}|1000|10_?000)$")
_THRESHOLD_NAME_RE = re.compile(
    r"(?i)(?:kink|threshold|target|minimum|maximum|min|max|limit|ltv|ratio|health)"
)
_SCALED_NAME_RE = re.compile(r"(?i)(?:wad|ray|bps|scaled|scale|precision)")


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


def _function_has_rate_context(fn: FunctionSlice) -> bool:
    text = f"{fn.name}\n{fn.header}\n{fn.body}"
    return bool(
        _VISIBILITY_RE.search(fn.header)
        and (_FUNCTION_NAME_CONTEXT_RE.search(fn.name) or _RATE_CONTEXT_RE.search(text))
    )


def _has_safe_cast_guard(body: str) -> bool:
    return bool(_SAFE_CAST_CONTEXT_RE.search(body) or _TYPE_BOUND_RE.search(body))


def _has_fixed_point_normalization(text: str) -> bool:
    return bool(_FP_MATH_RE.search(text))


def _collect_scaled_vars(body: str) -> set[str]:
    scaled: set[str] = set()
    for match in _LOCAL_DECL_RE.finditer(body):
        name = match.group("name")
        expr = match.group("expr")
        if _SCALED_NAME_RE.search(name) or _SCALE_MARKER_RE.search(expr):
            scaled.add(name)
    return scaled


def _collect_small_thresholds(source: str, body: str) -> set[str]:
    thresholds: set[str] = set()
    for text in (source, body):
        for match in _LOCAL_DECL_RE.finditer(text):
            name = match.group("name")
            expr = re.sub(r"\s+", "", match.group("expr"))
            if _THRESHOLD_NAME_RE.search(name) and _SMALL_THRESHOLD_RE.match(expr):
                thresholds.add(name)
    return thresholds


def _is_scaled_term(term: str, scaled_vars: set[str]) -> bool:
    clean = term.strip()
    if clean in scaled_vars:
        return True
    return bool(_SCALE_MARKER_RE.search(clean) or _SCALED_NAME_RE.search(clean))


def _is_unscaled_threshold(term: str, thresholds: set[str]) -> bool:
    clean = term.strip()
    if clean in thresholds:
        return True
    if _SMALL_THRESHOLD_RE.match(clean):
        return True
    return bool(_THRESHOLD_NAME_RE.search(clean) and not _SCALE_MARKER_RE.search(clean))


def _has_unsafe_downcast(fn: FunctionSlice) -> bool:
    if _has_safe_cast_guard(fn.body):
        return False
    for match in _CAST_RE.finditer(fn.body):
        expr = match.group("expr")
        window = fn.body[max(0, match.start() - 120):match.end() + 120]
        if _has_fixed_point_normalization(window):
            continue
        if _DANGEROUS_VALUE_RE.search(expr) or _DANGEROUS_VALUE_RE.search(window):
            return True
    return False


def _has_division_before_scaling(fn: FunctionSlice) -> bool:
    body = fn.body
    if _has_fixed_point_normalization(body):
        return False
    for match in list(_DIV_BEFORE_SCALE_RE.finditer(body)) + list(_DIV_BEFORE_SCALE_INLINE_RE.finditer(body)):
        expr = match.group(0)
        if not _SCALE_MARKER_RE.search(expr):
            continue
        if _DANGEROUS_VALUE_RE.search(expr) or _RATE_CONTEXT_RE.search(fn.name):
            return True
    for match in _QUOTE_DIV_BEFORE_MULTIPLY_RE.finditer(body):
        expr = match.group(0)
        if _DANGEROUS_VALUE_RE.search(expr) or _FUNCTION_NAME_CONTEXT_RE.search(fn.name):
            return True
    return False


def _has_scaled_unscaled_comparison(source: str, fn: FunctionSlice) -> bool:
    if _has_fixed_point_normalization(f"{fn.header}\n{fn.body}"):
        return False
    scaled_vars = _collect_scaled_vars(fn.body)
    thresholds = _collect_small_thresholds(source, fn.body)
    for condition in _IF_CONDITION_RE.finditer(fn.body):
        cond = condition.group("cond")
        for comparison in _COMPARISON_RE.finditer(cond):
            left = comparison.group("left")
            right = comparison.group("right")
            if _is_scaled_term(left, scaled_vars) and _is_unscaled_threshold(right, thresholds):
                return True
            if _is_scaled_term(right, scaled_vars) and _is_unscaled_threshold(left, thresholds):
                return True
    return False


def _classify(source: str, fn: FunctionSlice) -> str | None:
    if not _function_has_rate_context(fn):
        return None
    if _has_unsafe_downcast(fn):
        return "unsafe downcast of kink, utilization, rate, scale, or quote value"
    if _has_division_before_scaling(fn):
        return "division before fixed-point scaling in rate or quote math"
    if _has_scaled_unscaled_comparison(source, fn):
        return "scaled and unscaled kink or threshold comparison"
    return None


def _finding(file_path: str, fn: FunctionSlice, reason: str) -> Finding:
    return Finding(
        detector=DETECTOR_NAME,
        file=file_path,
        line=fn.line,
        severity=DETECTOR_SEVERITY_DEFAULT,
        function=fn.name,
        message=(
            f"{reason} near IRM, utilization, quote, kink, or max-rate logic. "
            "Suppresses explicit SafeCast and fixed-point normalization helpers. "
            "NOT_SUBMIT_READY: detector fixture smoke evidence only."
        ),
    )


def scan(source: str, file_path: str = "<memory>") -> list[Finding]:
    code = _strip_comments_and_strings(source)
    findings: list[Finding] = []
    for fn in _split_functions(code):
        reason = _classify(code, fn)
        if reason is not None:
            findings.append(_finding(file_path, fn, reason))
    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
