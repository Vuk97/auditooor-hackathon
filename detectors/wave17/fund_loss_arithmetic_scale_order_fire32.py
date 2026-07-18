"""
fund-loss-arithmetic-scale-order-fire32

Flags Solidity value-moving functions where arithmetic loses precision before
fund movement or debt, collateral, withdrawal, or payout accounting. The lift
targets three related shapes:

- division before multiplication in a value amount,
- scale dropped before transfer or accounting movement,
- cached or stale ratio used to compute a withdrawal, debt, collateral, or
  payout amount.

Provenance:
- context_pack_id: auditooor.vault_context_pack.v1:resume:0f026ac1001e9e9b
- context_pack_hash: 0f026ac1001e9e9b588d5fafc49e8d99e6f347f91a2aaa782107be04d27011d8
- source ref: reports/detector_lift_fire31_20260605/post_priorities_all.md
- source ref: detectors/wave17/value_math_transfer_rounding_fire31.py
- source ref: reference/patterns.dsl/fund-loss-value-math-external-transfer-fire10.yaml
- source ref: reference/patterns.dsl.r74_mined_cs/bad-debt-rounding-can-be-exploited-to-pay.yaml
- attack_class: fund-loss-via-arithmetic

Hits are candidate evidence only. NOT_SUBMIT_READY.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "fund-loss-arithmetic-scale-order-fire32"
DETECTOR_SEVERITY_DEFAULT = "Medium"
SUBMISSION_POSTURE = "NOT_SUBMIT_READY"


try:
    from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
except Exception:  # pragma: no cover - regex scan remains usable without Slither.
    class AbstractDetector:  # type: ignore[no-redef]
        pass

    class DetectorClassification:  # type: ignore[no-redef]
        HIGH = "High"
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
class SuspiciousAmount:
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
    r"(?i)(?:amount|asset|assets|share|shares|value|payout|out|fee|claim|"
    r"credit|debit|mint|burn|redeem|withdraw|transfer|owed|net|gross|"
    r"debt|collateral|principal|liability|cash|token|tokens)"
)
_VALUE_EXPR_RE = re.compile(
    r"(?i)\b(?:amount|asset|assets|share|shares|value|price|rate|ratio|"
    r"index|scale|precision|fee|claim|payout|credit|debit|totalSupply|"
    r"totalShares|totalAssets|balance|balances|reserve|liquidity|"
    r"collateral|debt|principal|liability|cash|token|tokens)\w*\b"
)
_SAFE_MATH_RE = re.compile(
    r"(?is)\b(?:mulDiv|FullMath|FixedPointMathLib|PRBMath|wadMul|wadDiv|"
    r"rayMul|rayDiv|mulWad|divWad|mulWadDown|divWadDown|normalizeDecimals|"
    r"normaliseDecimals|convertDecimals|scaleByDecimals|Math\s*\.\s*mulDiv)\b"
)
_ROUND_UP_RE = re.compile(
    r"(?is)\b(?:mulDivUp|divWadUp|mulWadUp|ceilDiv|roundUp|roundingUp|"
    r"Rounding\s*\.\s*(?:Up|Ceil))\b"
)
_SCALE_DENOM_RE = re.compile(
    r"(?is)/\s*(?:1e\d+|10\s*\*\*\s*\d+|WAD|RAY|BPS|BASIS_POINTS|"
    r"basisPoints|PRECISION|SCALE|SCALAR|DECIMALS)\b"
)
_STALE_RATIO_SOURCE_RE = re.compile(
    r"(?is)\b(?:cached|cache|stale|old|last|previous|prev|snapshot|stored|"
    r"checkpoint|saved)[A-Za-z0-9_]*(?:rate|ratio|index|price|exchangeRate|"
    r"scale|conversion)|(?:rate|ratio|index|price|exchangeRate|scale|conversion)"
    r"[A-Za-z0-9_]*(?:cached|stale|old|last|previous|prev|snapshot|stored|"
    r"checkpoint|saved)\b"
)
_RATIO_NAME_RE = re.compile(r"(?i)(?:rate|ratio|index|price|exchangeRate|scale|conversion)")
_PRIOR_DEBIT_RE = re.compile(
    r"(?is)\b(?:balance|balances|share|shares|credit|credits|claim|claimable|"
    r"debt|debts|collateral|principal|position|positions|ledger|accounting)"
    r"[A-Za-z0-9_]*(?:\s*\[[^\]]+\]\s*)?(?:\.\s*[A-Za-z_][A-Za-z0-9_]*)?"
    r"\s*(?:-=|=\s*0\b|=(?!=)[^;{}]*-\s*)"
)
_TRANSFER_SINK_RE = re.compile(
    r"(?is)\b(?:safeTransferFrom|safeTransfer|transferFrom|transfer|"
    r"_mint|_burn|mint|burn)\s*\([^;{}]*\b{var}\b[^;{}]*\)\s*;"
)
_ACCOUNTING_WRITE_RE = re.compile(
    r"(?is)\b(?:balance|balances|share|shares|totalShares|totalAssets|"
    r"totalSupply|asset|assets|claimable|pending|credit|credits|debt|"
    r"debts|reserve|reserves|owed|withdrawable|vault|accounting|ledger|"
    r"position|positions|collateral|principal|liability)[A-Za-z0-9_]*"
    r"(?:\s*\[[^\]]+\]\s*)?(?:\.\s*[A-Za-z_][A-Za-z0-9_]*)?"
    r"\s*(?:\+=|-=|=(?!=))[^;{}]*\b{var}\b[^;{}]*;"
)
_ACCOUNTING_CALL_RE = re.compile(
    r"(?is)\b(?:post|credit|debit|account|record|settle|book|repay|withdraw|"
    r"redeem|claim|liquidate)\w*\s*\([^;{}]*\b{var}\b[^;{}]*\)\s*;"
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


def _references_any_identifier(expr: str, identifiers: set[str]) -> bool:
    return any(re.search(rf"(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])", expr) for name in identifiers)


def _branch_for_expr(expr: str, stale_ratio_vars: set[str], prefix: str) -> str | None:
    if _SAFE_MATH_RE.search(expr) or _ROUND_UP_RE.search(expr):
        return None
    if _has_division_before_multiplication(expr) and _VALUE_EXPR_RE.search(expr):
        return "division-before-multiplication-value-math"
    if _STALE_RATIO_SOURCE_RE.search(expr) or _references_any_identifier(expr, stale_ratio_vars):
        if "/" in expr or "*" in expr:
            return "stale-ratio-value-math"
    if _SCALE_DENOM_RE.search(expr) and _VALUE_EXPR_RE.search(expr):
        if _PRIOR_DEBIT_RE.search(prefix):
            return "scale-dropped-after-accounting-debit"
        return "scale-dropped-before-value-movement"
    return None


def _has_output_guard(body: str, amount_var: str) -> bool:
    escaped = re.escape(amount_var)
    patterns = (
        rf"(?is)\brequire\s*\([^;{{}}]*\b{escaped}\b\s*(?:>|>=|!=)\s*(?:0|1|min[A-Za-z0-9_]*|expected[A-Za-z0-9_]*)",
        rf"(?is)\brequire\s*\([^;{{}}]*(?:min[A-Za-z0-9_]*|expected[A-Za-z0-9_]*)\s*<=\s*\b{escaped}\b",
        rf"(?is)\bif\s*\([^;{{}}]*\b{escaped}\b\s*==\s*0[^;{{}}]*\)\s*revert",
        rf"(?is)\bif\s*\([^;{{}}]*0\s*==\s*\b{escaped}\b[^;{{}}]*\)\s*revert",
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
        return "debt-collateral-or-vault-write"
    if _var_sink_pattern(_ACCOUNTING_CALL_RE, amount_var).search(body):
        return "accounting-call"
    return None


def _suspicious_amounts(fn: FunctionSlice) -> list[SuspiciousAmount]:
    out: list[SuspiciousAmount] = []
    seen: set[tuple[str, str]] = set()
    stale_ratio_vars: set[str] = set()

    for match in _ASSIGNMENT_RE.finditer(fn.body):
        name = match.group("name")
        expr = (match.group("expr") or "").strip()
        prefix = fn.body[:match.start()]
        suffix = fn.body[match.end():]

        if _RATIO_NAME_RE.search(name) and _STALE_RATIO_SOURCE_RE.search(expr):
            stale_ratio_vars.add(name)

        if not _looks_value_amount(name, expr):
            continue
        branch = _branch_for_expr(expr, stale_ratio_vars, prefix)
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
            SuspiciousAmount(
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
        for amount in _suspicious_amounts(fn):
            key = (fn.name, amount.name, amount.branch)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    detector=DETECTOR_NAME,
                    file=file_path,
                    line=amount.line,
                    severity=DETECTOR_SEVERITY_DEFAULT,
                    function=fn.name,
                    amount_var=amount.name,
                    branch=amount.branch,
                    message=(
                        f"{DETECTOR_NAME}: {amount.branch} in `{fn.name}` "
                        f"computes `{amount.name}` from `{amount.expr}` and then "
                        "moves value or updates debt, collateral, withdrawal, or "
                        "payout accounting without a full-precision, fresh-ratio, "
                        "round-up, zero-output, or min-output guard. "
                        "NOT_SUBMIT_READY: detector fixture smoke evidence only."
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


class FundLossArithmeticScaleOrderFire32(AbstractDetector):
    ARGUMENT = DETECTOR_NAME
    HELP = (
        "Value-moving arithmetic divides before multiplying, drops scale, or "
        "uses a stale ratio before token movement or debt, collateral, "
        "withdrawal, or payout accounting."
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor"
    WIKI_TITLE = "Arithmetic scale order can move less or more value than accounting intends"
    WIKI_DESCRIPTION = (
        "A withdrawal, debt, collateral, or payout path can compute its moved "
        "amount after truncating precision or by using a cached ratio. If the "
        "rounded value is transferred or booked without a guard, users or the "
        "protocol can lose funds."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A vault calculates `assetsOut = shares / totalShares * totalAssets`, "
        "burns the user's shares, and transfers `assetsOut`. For small share "
        "amounts the first division floors to zero before the multiplication, "
        "so the user loses shares without receiving the proportional assets."
    )
    WIKI_RECOMMENDATION = (
        "Use full-precision multiply-then-divide math with an explicit rounding "
        "direction, refresh ratios at the same accounting point as the movement, "
        "and require non-zero or caller-specified minimum outputs before state "
        "is debited or external value is moved."
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
    "FundLossArithmeticScaleOrderFire32",
    "scan",
]
