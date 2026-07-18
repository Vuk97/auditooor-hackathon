"""
value-math-transfer-rounding-fire31

Flags Solidity value-moving functions that compute a transfer or vault
accounting amount with division-heavy value math, then use that rounded amount
in an external token transfer, mint, burn, or accounting write without an
explicit output guard.

Provenance:
- context_pack_id: auditooor.vault_context_pack.v1:resume:c01d420fe4a1c24a
- context_pack_hash: c01d420fe4a1c24a974c8890b2d40ca3881d87e848d83dc294a1ee396a5753c8
- source ref: reports/detector_lift_fire30_20260605/post_priorities_all.md
- source ref: reference/patterns.dsl/fund-loss-value-math-external-transfer-fire10.yaml
- source ref: detectors/wave17/value_math_constructor_scale_fire29.py
- attack_class: fund-loss-via-arithmetic

Hits are candidate evidence only. NOT_SUBMIT_READY.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "value-math-transfer-rounding-fire31"
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
class RoundedAmount:
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
    r"credit|debit|mint|burn|redeem|withdraw|transfer|owed|net|gross)"
)
_VALUE_EXPR_RE = re.compile(
    r"(?i)\b(?:amount|asset|assets|share|shares|value|price|rate|ratio|"
    r"scale|precision|fee|claim|payout|credit|debit|totalSupply|"
    r"totalAssets|balance|balances|reserve|liquidity|collateral|debt)\w*\b"
)
_SAFE_MATH_RE = re.compile(
    r"(?is)\b(?:mulDiv|FullMath|FixedPointMathLib|PRBMath|wadMul|wadDiv|"
    r"rayMul|rayDiv|mulWad|divWad|mulWadDown|divWadDown|normalizeDecimals|"
    r"convertDecimals|scaleByDecimals|Math\s*\.\s*mulDiv)\b"
)
_ROUND_UP_RE = re.compile(
    r"(?is)\b(?:mulDivUp|divWadUp|mulWadUp|ceilDiv|roundUp|roundingUp|"
    r"Rounding\s*\.\s*(?:Up|Ceil))\b"
)
_HARDCODED_SCALE_RE = re.compile(
    r"(?is)\b(?:1e\d+|10\s*\*\*\s*\d+|WAD|RAY|BPS|BASIS_POINTS|"
    r"basisPoints|PRECISION|SCALE|SCALAR)\b"
)
_DECIMAL_SOURCE_RE = re.compile(
    r"(?is)\b(?:decimals\s*\(|tokenDecimals|assetDecimals|shareDecimals|"
    r"oracleDecimals|feedDecimals|normalize|normalise|convertDecimals)\b"
)
_TRANSFER_SINK_RE = re.compile(
    r"(?is)\b(?:safeTransferFrom|safeTransfer|transferFrom|transfer|"
    r"_mint|_burn|mint|burn)\s*\([^;{}]*\b{var}\b[^;{}]*\)\s*;"
)
_ACCOUNTING_WRITE_RE = re.compile(
    r"(?is)\b(?:balance|balances|share|shares|totalShares|totalAssets|"
    r"totalSupply|asset|assets|claimable|pending|credit|credits|debt|"
    r"debts|reserve|reserves|owed|withdrawable|vault|accounting|ledger|"
    r"position|positions)[A-Za-z0-9_]*(?:\s*\[[^\]]+\]\s*)?"
    r"(?:\.\s*[A-Za-z_][A-Za-z0-9_]*)?\s*(?:\+=|-=|=(?!=))"
    r"[^;{}]*\b{var}\b[^;{}]*;"
)
_ACCOUNTING_CALL_RE = re.compile(
    r"(?is)\b(?:post|credit|debit|account|record|settle|book)\w*"
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


def _branch_for_expr(expr: str) -> str | None:
    if "/" not in expr:
        return None
    if _SAFE_MATH_RE.search(expr) or _ROUND_UP_RE.search(expr):
        return None
    if _has_division_before_multiplication(expr):
        return "division-before-multiplication-transfer-rounding"
    if _HARDCODED_SCALE_RE.search(expr) and not _DECIMAL_SOURCE_RE.search(expr):
        return "hardcoded-scale-transfer-conversion"
    if _VALUE_EXPR_RE.search(expr):
        return "unchecked-division-rounded-transfer-amount"
    return None


def _has_output_guard(body: str, amount_var: str) -> bool:
    escaped = re.escape(amount_var)
    patterns = (
        rf"(?is)\brequire\s*\([^;{{}}]*\b{escaped}\b\s*(?:>|>=|!=)\s*(?:0|1|min[A-Za-z0-9_]*|expected[A-Za-z0-9_]*)",
        rf"(?is)\brequire\s*\([^;{{}}]*(?:min[A-Za-z0-9_]*|expected[A-Za-z0-9_]*)\s*<=\s*\b{escaped}\b",
        rf"(?is)\bif\s*\([^;{{}}]*\b{escaped}\b\s*==\s*0[^;{{}}]*\)\s*revert",
        rf"(?is)\bif\s*\([^;{{}}]*0\s*==\s*\b{escaped}\b[^;{{}}]*\)\s*revert",
        rf"(?is)\bif\s*\([^;{{}}]*\b{escaped}\b\s*<\s*(?:min[A-Za-z0-9_]*|expected[A-Za-z0-9_]*|1)[^;{{}}]*\)\s*revert",
        rf"(?is)\b(?:ZeroAmount|ZeroAssets|ZeroShares|Slippage|MinAmount|AmountTooSmall)\b",
    )
    return any(re.search(pattern, body) for pattern in patterns)


def _var_sink_pattern(template: re.Pattern[str], amount_var: str) -> re.Pattern[str]:
    return re.compile(template.pattern.replace("{var}", re.escape(amount_var)), template.flags)


def _uses_amount_in_sink(body: str, amount_var: str) -> str | None:
    if _var_sink_pattern(_TRANSFER_SINK_RE, amount_var).search(body):
        return "external-token-transfer"
    if _var_sink_pattern(_ACCOUNTING_WRITE_RE, amount_var).search(body):
        return "vault-accounting-write"
    if _var_sink_pattern(_ACCOUNTING_CALL_RE, amount_var).search(body):
        return "external-accounting-call"
    return None


def _rounded_amounts(fn: FunctionSlice) -> list[RoundedAmount]:
    out: list[RoundedAmount] = []
    seen: set[str] = set()
    for match in _ASSIGNMENT_RE.finditer(fn.body):
        name = match.group("name")
        expr = (match.group("expr") or "").strip()
        if name in seen:
            continue
        if not _looks_value_amount(name, expr):
            continue
        branch = _branch_for_expr(expr)
        if branch is None:
            continue
        if _has_output_guard(fn.body[match.end():], name):
            continue
        sink = _uses_amount_in_sink(fn.body[match.end():], name)
        if sink is None:
            continue
        seen.add(name)
        out.append(
            RoundedAmount(
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
        for rounded in _rounded_amounts(fn):
            key = (fn.name, rounded.name, rounded.branch)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    detector=DETECTOR_NAME,
                    file=file_path,
                    line=rounded.line,
                    severity=DETECTOR_SEVERITY_DEFAULT,
                    function=fn.name,
                    amount_var=rounded.name,
                    branch=rounded.branch,
                    message=(
                        f"{DETECTOR_NAME}: {rounded.branch} in `{fn.name}` "
                        f"computes `{rounded.name}` from `{rounded.expr}` and then "
                        "uses the rounded amount in a value-moving sink without "
                        "a zero, min-output, or round-up guard. NOT_SUBMIT_READY: "
                        "detector fixture smoke evidence only."
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


class ValueMathTransferRoundingFire31(AbstractDetector):
    ARGUMENT = DETECTOR_NAME
    HELP = (
        "Value conversion rounds by division, hardcoded scale factors, or "
        "unchecked division before a token transfer or vault accounting write."
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor"
    WIKI_TITLE = "Rounded value math feeds transfer or accounting amount"
    WIKI_DESCRIPTION = (
        "A value-moving function may compute the amount sent or booked with "
        "division before multiplication, fixed scale factors, or plain integer "
        "division. If that rounded result is transferred or written to vault "
        "accounting without a guard, users can lose value or mint too few "
        "shares."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A vault calculates shares as `assets / index * 1e18`. For deposits "
        "smaller than the index, the division truncates before scaling, yet "
        "the vault still transfers tokens and writes zero shares."
    )
    WIKI_RECOMMENDATION = (
        "Use full-precision `mulDiv` style math with the intended rounding "
        "direction, source token decimals dynamically, and require the final "
        "transfer or accounting amount to satisfy zero and min-output bounds."
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
    "ValueMathTransferRoundingFire31",
    "scan",
]
