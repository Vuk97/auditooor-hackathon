"""
arithmetic-conversion-order-fire33

Flags Solidity value-moving functions where asset conversion, fee, share,
reward, or oracle math loses precision before the computed output is consumed
by a transfer, mint, burn, or accounting write.

Provenance:
- context_pack_id: auditooor.vault_context_pack.v1:resume:57361adac683c0c7
- context_pack_hash: 57361adac683c0c7f40a2f345b94c4172fe41a09373a05ca2cf8fae67d1b1dab
- source ref: reports/detector_lift_fire32_20260605/post_priorities_all.md
- source ref: reference/patterns.dsl/fund-loss-via-arithmetic-value-math.yaml
- source ref: reference/patterns.dsl/fund-loss-via-arithmetic-conversion-output-zero.yaml
- source ref: reference/patterns.dsl/oracle-decimal-mis-scaling-hardcoded-scale-without-feed-decimals.yaml
- attack_class: fund-loss-via-arithmetic

Hits are candidate evidence only. NOT_SUBMIT_READY.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "arithmetic-conversion-order-fire33"
DETECTOR_SEVERITY_DEFAULT = "Medium"
SUBMISSION_POSTURE = "NOT_SUBMIT_READY"


try:
    from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
except Exception:  # pragma: no cover - regex scan remains usable without Slither.
    class AbstractDetector:  # type: ignore[no-redef]
        pass

    class DetectorClassification:  # type: ignore[no-redef]
        MEDIUM = "Medium"


@dataclass(frozen=True)
class Finding:
    detector: str
    file: str
    line: int
    severity: str
    message: str
    function: Optional[str] = None
    amount_var: Optional[str] = None
    branch: Optional[str] = None


@dataclass(frozen=True)
class FunctionSlice:
    name: str
    header: str
    body: str
    function_line: int
    body_line: int


@dataclass(frozen=True)
class SuspiciousConversion:
    name: str
    expr: str
    line: int
    branch: str


_COMMENT_OR_STRING_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'|"
    r"//[^\n\r]*|"
    r"/\*.*?\*/",
    re.DOTALL,
)
_FN_HEADER_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_EXTERNAL_OR_PUBLIC_RE = re.compile(r"\b(?:external|public)\b")
_VIEW_OR_PURE_RE = re.compile(r"\b(?:view|pure)\b")
_ASSIGNMENT_RE = re.compile(
    r"(?is)(?:\b(?:u?int(?:8|16|32|64|128|256)?|uint|int)\s+)?"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<expr>[^;{}]+)\s*;"
)
_VALUE_NAME_RE = re.compile(
    r"(?i)(?:amount|asset|assets|share|shares|mint|minted|burn|burned|"
    r"out|output|payout|proceeds|fee|reward|claim|credit|debit|value|"
    r"collateral|debt|repay|owed|net|gross|token|tokens|receipt|liquidity)"
)
_VALUE_EXPR_RE = re.compile(
    r"(?i)\b(?:amount|asset|assets|share|shares|supply|totalSupply|"
    r"totalAssets|balance|reserve|liquidity|price|oraclePrice|rawPrice|"
    r"answer|rate|ratio|index|scale|precision|fee|reward|payout|claim|"
    r"credit|debit|collateral|debt|exchangeRate|bps|basis|decimals?)\w*\b"
)
_SAFE_MATH_RE = re.compile(
    r"(?is)\b(?:mulDiv|mulDivUp|FullMath|FixedPointMathLib|PRBMath|"
    r"Math\s*\.\s*mulDiv|wadMul|wadDiv|mulWad|divWad|mulWadDown|"
    r"divWadDown|mulWadUp|divWadUp|ceilDiv|roundUp|roundingUp|"
    r"Rounding\s*\.\s*(?:Up|Ceil)|normalizeDecimals|normaliseDecimals|"
    r"convertDecimals|scaleByDecimals)\b"
)
_DYNAMIC_DECIMALS_RE = re.compile(
    r"(?is)(?:\.\s*decimals\s*\(|IERC20Metadata|tokenDecimals|"
    r"assetDecimals|feedDecimals|priceDecimals|oracleDecimals|"
    r"10\s*\*\*\s*uint256\s*\(\s*(?:feed|price|oracle|asset|token)?Decimals\s*\))"
)
_HARD_CODED_SCALE_RE = re.compile(
    r"(?is)\b(?:1e6|1e8|1e18|1e27|10\s*\*\*\s*(?:6|8|18|27)|"
    r"1000000|100000000|1000000000000000000|WAD|RAY|BPS|BASIS_POINTS|"
    r"PRECISION|SCALE|SCALAR|DECIMALS)\b"
)
_ORACLE_READ_RE = re.compile(
    r"(?is)\b(?:latestRoundData|latestAnswer|getPrice|getAnswer)\s*\("
)
_ORACLE_VALUE_RE = re.compile(
    r"(?is)\b(?:answer|price|oraclePrice|rawPrice|latestPrice)\b"
)
_TOTAL_DENOM_RE = re.compile(
    r"(?is)/(?:\s*)(?:totalAssets\s*\(\s*\)|totalSupply\s*\(\s*\)|"
    r"[A-Za-z_][A-Za-z0-9_]*(?:Supply|Assets|Shares|Balance|Reserve|"
    r"Liquidity|Denominator|DENOMINATOR|Scale|SCALE|Precision|PRECISION|"
    r"Wad|WAD|Ray|RAY|Bps|BPS|Basis|BASIS_POINTS)|1e\d{1,2}|"
    r"10\s*\*\*\s*\d{1,2})"
)
_STATE_DEBIT_RE = re.compile(
    r"(?is)\b(?:balance|balances|share|shares|credit|credits|claim|"
    r"claimable|reward|rewards|debt|debts|collateral|principal|position|"
    r"positions|ledger|accounting|pending|owed|vault|reserve|reserves)"
    r"[A-Za-z0-9_]*(?:\s*\[[^\]]+\]\s*)?(?:\.\s*[A-Za-z_][A-Za-z0-9_]*)?"
    r"\s*(?:-=|\+=|=\s*0\b|=(?!=)[^;{}]*(?:-|\+)\s*)"
)
_TRANSFER_SINK_RE = re.compile(
    r"(?is)\b(?:safeTransferFrom|safeTransfer|transferFrom|transfer|"
    r"_mint|_burn|mint|burn)\s*\([^;{}]*\b{var}\b[^;{}]*\)\s*;"
)
_ACCOUNTING_WRITE_RE = re.compile(
    r"(?is)\b(?:balance|balances|share|shares|totalShares|totalAssets|"
    r"totalSupply|asset|assets|claimable|pending|reward|rewards|credit|"
    r"credits|debt|debts|reserve|reserves|owed|withdrawable|vault|"
    r"accounting|ledger|position|positions|collateral|principal|liability|"
    r"fee|fees|treasury)[A-Za-z0-9_]*(?:\s*\[[^\]]+\]\s*)?"
    r"(?:\.\s*[A-Za-z_][A-Za-z0-9_]*)?\s*(?:\+=|-=|=(?!=))[^;{}]*"
    r"\b{var}\b[^;{}]*;"
)
_ACCOUNTING_CALL_RE = re.compile(
    r"(?is)\b(?:post|credit|debit|account|record|settle|book|repay|"
    r"withdraw|redeem|claim|liquidate|collect|distribute|allocate)\w*"
    r"\s*\([^;{}]*\b{var}\b[^;{}]*\)\s*;"
)


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
                body_line=source.count("\n", 0, body_start + 1) + 1,
            )
        )
        pos = body_end + 1
    return out


def _line_for_body(fn: FunctionSlice, offset: int) -> int:
    return fn.body_line + fn.body.count("\n", 0, max(offset, 0))


def _is_public_mutating(fn: FunctionSlice) -> bool:
    return bool(_EXTERNAL_OR_PUBLIC_RE.search(fn.header)) and not _VIEW_OR_PURE_RE.search(fn.header)


def _looks_value_amount(name: str, expr: str) -> bool:
    return bool(_VALUE_NAME_RE.search(name) or _VALUE_EXPR_RE.search(expr))


def _has_division_before_multiplication(expr: str) -> bool:
    div_pos = expr.find("/")
    mul_pos = expr.find("*")
    return div_pos >= 0 and mul_pos >= 0 and div_pos < mul_pos


def _scale_denominator_before_multiplier(expr: str) -> bool:
    if not _has_division_before_multiplication(expr):
        return False
    div_pos = expr.find("/")
    mul_pos = expr.find("*")
    denominator_text = expr[div_pos:mul_pos]
    return bool(_TOTAL_DENOM_RE.search(denominator_text + " ") or _HARD_CODED_SCALE_RE.search(denominator_text))


def _hardcoded_oracle_scale_without_decimals(fn: FunctionSlice, expr: str) -> bool:
    if not _ORACLE_READ_RE.search(fn.body):
        return False
    if _DYNAMIC_DECIMALS_RE.search(fn.body):
        return False
    return bool(_ORACLE_VALUE_RE.search(expr) and _HARD_CODED_SCALE_RE.search(expr))


def _wrong_conversion_order_branch(fn: FunctionSlice, expr: str, prefix: str) -> str | None:
    if _SAFE_MATH_RE.search(expr):
        return None
    if _hardcoded_oracle_scale_without_decimals(fn, expr):
        return "hardcoded-oracle-scale-without-feed-decimals"
    if _scale_denominator_before_multiplier(expr):
        if re.search(r"(?is)\b(?:fee|bps|basis|reward|share|asset|amount|rate|price|ratio)\w*\b", expr):
            return "scale-or-denominator-divided-before-multiply"
    if _has_division_before_multiplication(expr) and _VALUE_EXPR_RE.search(expr):
        return "conversion-divides-before-multiply"
    if _HARD_CODED_SCALE_RE.search(expr) and "/" in expr and _VALUE_EXPR_RE.search(expr):
        if _STATE_DEBIT_RE.search(prefix):
            return "truncated-output-after-state-debit"
        return "hardcoded-scale-truncates-output"
    return None


def _has_output_guard(body: str, amount_var: str) -> bool:
    escaped = re.escape(amount_var)
    patterns = (
        rf"(?is)\brequire\s*\([^;{{}}]*\b{escaped}\b\s*(?:>|>=|!=)\s*(?:0|1|min[A-Za-z0-9_]*|expected[A-Za-z0-9_]*)",
        rf"(?is)\brequire\s*\([^;{{}}]*(?:min[A-Za-z0-9_]*|expected[A-Za-z0-9_]*)\s*<=\s*\b{escaped}\b",
        rf"(?is)\bif\s*\([^;{{}}]*\b{escaped}\b\s*==\s*0[^;{{}}]*\)\s*(?:revert|return)",
        rf"(?is)\bif\s*\([^;{{}}]*0\s*==\s*\b{escaped}\b[^;{{}}]*\)\s*(?:revert|return)",
        rf"(?is)\bif\s*\([^;{{}}]*\b{escaped}\b\s*<\s*(?:min[A-Za-z0-9_]*|expected[A-Za-z0-9_]*|1)[^;{{}}]*\)\s*revert",
        rf"(?is)\b(?:ZeroAmount|ZeroAssets|ZeroShares|ZeroPayout|Slippage|MinAmount|AmountTooSmall|InsufficientOutput)\b",
    )
    return any(re.search(pattern, body) for pattern in patterns)


def _var_sink_pattern(template: re.Pattern[str], amount_var: str) -> re.Pattern[str]:
    return re.compile(template.pattern.replace("{var}", re.escape(amount_var)), template.flags)


def _uses_amount_in_sink(body: str, amount_var: str) -> str | None:
    if _var_sink_pattern(_TRANSFER_SINK_RE, amount_var).search(body):
        return "external-token-movement"
    if _var_sink_pattern(_ACCOUNTING_WRITE_RE, amount_var).search(body):
        return "accounting-write"
    if _var_sink_pattern(_ACCOUNTING_CALL_RE, amount_var).search(body):
        return "accounting-call"
    return None


def _suspicious_conversions(fn: FunctionSlice) -> list[SuspiciousConversion]:
    out: list[SuspiciousConversion] = []
    seen: set[tuple[str, str]] = set()

    for match in _ASSIGNMENT_RE.finditer(fn.body):
        name = match.group("name")
        expr = (match.group("expr") or "").strip()
        prefix = fn.body[:match.start()]
        suffix = fn.body[match.end():]

        if not _looks_value_amount(name, expr):
            continue
        branch = _wrong_conversion_order_branch(fn, expr, prefix)
        if branch is None:
            continue
        if _has_output_guard(suffix, name):
            continue
        sink = _uses_amount_in_sink(suffix, name)
        if sink is None:
            continue
        key = (name, branch)
        if key in seen:
            continue
        seen.add(key)
        out.append(
            SuspiciousConversion(
                name=name,
                expr=expr,
                line=_line_for_body(fn, match.start()),
                branch=f"{branch}:{sink}",
            )
        )
    return out


def scan(source: str, file_path: str = "<memory>") -> list[Finding]:
    """Regex scanner used by tests and recall tooling."""
    text = _strip_comments_and_strings(source)
    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    for fn in _split_functions(text):
        if not _is_public_mutating(fn):
            continue
        for conversion in _suspicious_conversions(fn):
            key = (fn.name, conversion.name, conversion.branch)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    detector=DETECTOR_NAME,
                    file=file_path,
                    line=conversion.line,
                    severity=DETECTOR_SEVERITY_DEFAULT,
                    function=fn.name,
                    amount_var=conversion.name,
                    branch=conversion.branch,
                    message=(
                        f"{DETECTOR_NAME}: {conversion.branch} in `{fn.name}` "
                        f"computes `{conversion.name}` from `{conversion.expr}` and then "
                        "moves value or writes asset, share, fee, reward, debt, "
                        "collateral, or oracle-priced accounting without full-precision "
                        "ordering, dynamic decimals, round-up, zero-output, or "
                        "min-output guard. NOT_SUBMIT_READY: detector fixture smoke "
                        "evidence only."
                    ),
                )
            )
    return findings


def _source_text(obj) -> str:
    try:
        return obj.source_mapping.content or ""
    except Exception:
        return ""


def _source_file(obj) -> str:
    try:
        filename = obj.source_mapping.filename
        for attr in ("absolute", "relative", "short"):
            value = getattr(filename, attr, None)
            if value:
                return str(value)
    except Exception:
        pass
    return "<unknown>"


class ArithmeticConversionOrderFire33(AbstractDetector):
    ARGUMENT = DETECTOR_NAME
    HELP = (
        "Value-moving conversion math divides before multiplying, uses a "
        "hardcoded oracle scale without feed decimals, or truncates an output "
        "before transfer, mint, burn, or accounting consumption."
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor"
    WIKI_TITLE = "Arithmetic conversion order can truncate value before movement"
    WIKI_DESCRIPTION = (
        "Asset, share, fee, reward, and oracle-priced paths can lose precision "
        "when they divide by supply, scale, or feed precision before multiplying "
        "or when they hardcode oracle decimals. If the rounded output is later "
        "transferred, minted, burned, or booked, users or protocol accounting "
        "can lose value."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A deposit calculates `mintedShares = assets / totalAssets * totalShares`, "
        "pulls assets from the user, and mints the rounded `mintedShares`. For a "
        "small deposit the division floors to zero before multiplication, so the "
        "user moves assets and receives no shares."
    )
    WIKI_RECOMMENDATION = (
        "Use full-precision multiply-before-divide helpers, feed-specific decimal "
        "normalization, explicit rounding direction, and non-zero or caller-minimum "
        "output checks before moving value or writing accounting state."
    )

    SUBMISSION_POSTURE = SUBMISSION_POSTURE
    COVERAGE_CLAIM = "detector_fixture_smoke_only"
    PROMOTION_ALLOWED = False

    def _detect(self):
        results = []
        for contract in getattr(self, "contracts", []):
            contract_source = _source_text(contract)
            if not contract_source:
                continue
            functions_by_name = {
                str(getattr(function, "name", "") or ""): function
                for function in getattr(contract, "functions_and_modifiers_declared", [])
            }
            for finding in scan(contract_source, _source_file(contract)):
                anchor = functions_by_name.get(finding.function or "") or contract
                info = [anchor, f" - {finding.message} (line {finding.line})"]
                results.append(self.generate_result(info))
        return results


__all__ = [
    "DETECTOR_NAME",
    "DETECTOR_SEVERITY_DEFAULT",
    "Finding",
    "ArithmeticConversionOrderFire33",
    "scan",
]
