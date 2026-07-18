"""
integer-fee-underflow-clamp-fire35

Focused Solidity recall lift for integer-overflow-clamp misses where fee,
premium, surge-fee, borrow-rate, swap-output, flashloan, or liquidation math
subtracts a fee-like value before applying a cap or floor. The downstream
clamp does not protect Solidity 0.8 paths from reverting when the fee exceeds
the amount, and unchecked or legacy paths can wrap before the clamp.

Provenance:
- context_pack_id: auditooor.vault_context_pack.v1:resume:5a29d91bbce92794
- context_pack_hash: 5a29d91bbce92794762a8ed09f2250a9242a49986ce3809863c10a012720379d
- source ref: reports/detector_lift_fire34_20260605/post_priorities_all.md
- source ref: reference/patterns.dsl/integer-clamp-fee-or-debt-underflow-boundary.yaml
- source ref: reference/patterns.dsl/integer-overflow-clamp-arithmetic-loss.yaml
- source ref: reference/patterns.dsl/fx-balancer-surge-fee-underflow.yaml
- source ref: detectors/wave17/integer_clamp_fee_scale_fire34.py
- source ref: detectors/wave17/flashloan_fee_underflow_or_missing.py
- attack_class: integer-overflow-clamp

Hits are candidate evidence only. NOT_SUBMIT_READY. A finding still needs a
real source path, source existence, negative control, and R40/R76/R80 proof.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "integer-fee-underflow-clamp-fire35"
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
    r"(?is)(?:amount|amountIn|amountOut|borrow|borrowRate|bps|BPS|cap|"
    r"charge|collateral|debt|fee|fees|flash|flashLoan|flashloan|floor|"
    r"liquidat|loan|max|min|notional|output|owed|payout|premium|principal|"
    r"proceeds|protocolFee|rate|repay|repayment|settle|spread|staticFee|"
    r"surge|swap|value)"
)
_ENTRY_NAME_RE = re.compile(
    r"(?i)(?:borrow|charge|fee|flash|liquidat|premium|quote|repay|settle|"
    r"spread|surge|swap)"
)
_FEE_STEM = (
    r"fee|Fee|premium|Premium|charge|Charge|spread|Spread|surge|Surge|"
    r"staticFee|StaticFee|protocolFee|ProtocolFee|liquidationFee|"
    r"LiquidationFee|penalty|Penalty|rate|Rate"
)
_FEE_NAME_RE = (
    rf"(?:[A-Za-z_][A-Za-z0-9_]*(?:{_FEE_STEM})[A-Za-z0-9_]*|"
    rf"(?:{_FEE_STEM})[A-Za-z0-9_]*)"
)
_OUT_NAME_RE = (
    r"(?:"
    r"[A-Za-z_][A-Za-z0-9_]*(?:Amount|amount|Due|due|Fee|fee|Net|net|Out|"
    r"out|Output|output|Payout|payout|Premium|premium|Proceeds|proceeds|"
    r"Range|range|Repay|repay|Spread|spread|Surge|surge|Value|value)"
    r"[A-Za-z0-9_]*|"
    r"amountAfterFee|borrowerProceeds|effectivePremium|feeDelta|netAmount|"
    r"netOut|owed|payout|premium|range|surgeRange)"
)

_SUBTRACT_ASSIGN_RE = re.compile(
    rf"(?is)\b(?:uint(?:256|128|64)?|int(?:256|128|64)?|var)?\s*"
    rf"(?P<out>{_OUT_NAME_RE})\s*=\s*"
    rf"(?P<left>[^;{{}}]{{1,300}}?)\s*-\s*(?P<fee>{_FEE_NAME_RE})"
    rf"(?P<right>[^;{{}}]{{0,160}})\s*;"
)
_POSITIVE_BRANCH_RE = re.compile(
    rf"(?is)\b(?:uint(?:256|128|64)?|int(?:256|128|64)?|var)?\s*"
    rf"(?P<out>{_OUT_NAME_RE})\s*=\s*"
    rf"(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s*(?:>|>=)\s*(?P<fee>{_FEE_NAME_RE})"
    rf"\s*\?\s*(?P=base)\s*-\s*(?P=fee)\s*:\s*"
    rf"(?P<else>0|(?P=base)|[A-Za-z_][A-Za-z0-9_]*(?:Floor|floor|Min|min)[A-Za-z0-9_]*)\s*;"
)

_SAFE_ARITH_RE = re.compile(
    r"(?is)\b(?:SafeMath|saturat|uncheckedSafe|checkedSub|subOrZero|"
    r"trySub|Math\s*\.\s*min\s*\(|Math\s*\.\s*max\s*\(|"
    r"FullMath\s*\.\s*mulDiv|FixedPointMathLib\s*\.\s*mulDiv|mulDiv)\b"
)
_CAP_WORD_RE = r"(?:cap|Cap|ceil|Ceil|floor|Floor|limit|Limit|max|Max|min|Min|threshold|Threshold)"
_SINK_RE = re.compile(
    r"(?is)\b(?:return|transfer|safeTransfer|transferFrom|_mint|mint|_burn|"
    r"burn|pay|payout|settle|collect|repay|charge|credit|debit|update|set)"
)

_IGNORED_IDENTIFIERS = {
    "uint",
    "uint64",
    "uint128",
    "uint256",
    "int",
    "int64",
    "int128",
    "int256",
    "var",
    "if",
    "require",
    "return",
    "Math",
    "min",
    "max",
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
        for token in re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", expr)
        if token not in _IGNORED_IDENTIFIERS
    }


def _has_domain_context(fn: FunctionSlice, text: str, expr: str) -> bool:
    return bool(
        (_ENTRY_NAME_RE.search(fn.name) or _DOMAIN_RE.search(text))
        and _DOMAIN_RE.search(expr)
        and _DOMAIN_RE.search(text)
    )


def _has_pre_subtraction_guard(text: str, base_expr: str, fee_name: str, start: int) -> bool:
    before = text[:start]
    fee = re.escape(fee_name)
    base_tokens = _identifiers(base_expr)

    clamp_assignment = re.search(
        rf"(?is)\b{fee}\b\s*=\s*(?:Math\s*\.\s*)?min\s*\(|"
        rf"\b{fee}\b\s*=[^;{{}}]{{0,220}}\?[^;{{}}]{{0,220}}:\s*[^;{{}}]{{0,220}}",
        before,
    )
    if clamp_assignment:
        return True

    for base_name in base_tokens:
        base = re.escape(base_name)
        safe_require = re.search(
            rf"(?is)require\s*\([^;{{}}]*(?:\b{fee}\b[^;{{}}]*(?:<=|<)"
            rf"[^;{{}}]*\b{base}\b|\b{base}\b[^;{{}}]*(?:>=|>)"
            rf"[^;{{}}]*\b{fee}\b)",
            before,
        )
        safe_revert = re.search(
            rf"(?is)if\s*\([^;{{}}]*(?:\b{fee}\b[^;{{}}]*(?:>|>=)"
            rf"[^;{{}}]*\b{base}\b|\b{base}\b[^;{{}}]*(?:<|<=)"
            rf"[^;{{}}]*\b{fee}\b)[^;{{}}]*\)\s*"
            rf"(?:\{{[^{{}}]{{0,220}}(?:revert|return|{fee}\s*=)|"
            rf"(?:revert|return|{fee}\s*=))",
            before,
        )
        direct_min = re.search(
            rf"(?is)\b{fee}\b\s*=\s*(?:Math\s*\.\s*)?min\s*\([^;{{}}]*"
            rf"\b{base}\b[^;{{}}]*\)",
            before,
        )
        ternary_cap = re.search(
            rf"(?is)\b{fee}\b\s*=\s*\b{fee}\b\s*>\s*\b{base}\b\s*\?"
            rf"\s*\b{base}\b\s*:\s*\b{fee}\b",
            before,
        )
        if safe_require or safe_revert or direct_min or ternary_cap:
            return True
    return False


def _has_post_cap_or_floor(text: str, out_name: str, start: int) -> bool:
    tail = text[start:start + 1100]
    out = re.escape(out_name)
    if re.search(
        rf"(?is)if\s*\([^;{{}}]*\b{out}\b[^;{{}}]*(?:<|>|<=|>=)"
        rf"[^;{{}}]*(?:{_CAP_WORD_RE}|amount|principal|output|proceeds)"
        rf"[^;{{}}]*\)\s*(?:\{{[^{{}}]{{0,260}}\b{out}\b\s*=|\b{out}\b\s*=)",
        tail,
    ):
        return True
    if re.search(
        rf"(?is)\b{out}\b\s*=\s*(?:\b{out}\b[^;{{}}?]*(?:>|<|>=|<=)"
        rf"[^;{{}}?]*(?:{_CAP_WORD_RE}|amount|principal|output|proceeds)"
        rf"[^;{{}}?]*\?[^;{{}}]*:|(?:Math\s*\.\s*)?(?:min|max)\s*\()",
        tail,
    ):
        return True
    return False


def _has_sink_after(text: str, out_name: str, start: int) -> bool:
    tail = text[start:start + 1000]
    out = re.escape(out_name)
    return bool(_SINK_RE.search(tail) and re.search(rf"\b{out}\b", tail))


def _is_safe_window(text: str, start: int, end: int) -> bool:
    window = text[max(0, start - 700):min(len(text), end + 500)]
    return bool(_SAFE_ARITH_RE.search(window))


def _subtract_before_cap_match(fn: FunctionSlice, text: str) -> tuple[re.Match[str], str] | None:
    for match in _SUBTRACT_ASSIGN_RE.finditer(text):
        out_name = match.group("out")
        left = match.group("left").strip()
        fee_name = match.group("fee").strip()
        expr = f"{left} - {fee_name}{match.group('right') or ''}"

        if not _has_domain_context(fn, text, expr):
            continue
        if _is_safe_window(text, match.start(), match.end()):
            continue
        if _has_pre_subtraction_guard(text, left, fee_name, match.start()):
            continue
        if not _has_post_cap_or_floor(text, out_name, match.end()):
            continue
        if not _has_sink_after(text, out_name, match.end()):
            continue

        return match, f"{out_name} subtracts {fee_name} before the cap or floor"
    return None


def _positive_branch_only_match(fn: FunctionSlice, text: str) -> tuple[re.Match[str], str] | None:
    for match in _POSITIVE_BRANCH_RE.finditer(text):
        out_name = match.group("out")
        base_name = match.group("base")
        fee_name = match.group("fee")
        expr = f"{base_name} - {fee_name}"

        if not _has_domain_context(fn, text, expr):
            continue
        if _is_safe_window(text, match.start(), match.end()):
            continue
        if _has_pre_subtraction_guard(text, base_name, fee_name, match.start()):
            continue
        if not _has_sink_after(text, out_name, match.end()):
            continue
        return match, f"{out_name} only subtracts {fee_name} on the positive branch"
    return None


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    stripped = _strip_comments_and_strings(source)
    findings: list[Finding] = []

    for fn in _split_functions(stripped):
        if not _VISIBLE_RE.search(fn.header):
            continue
        text = f"{fn.header}\n{fn.body}"
        match_with_reason = _positive_branch_only_match(fn, text)
        if match_with_reason is None:
            match_with_reason = _subtract_before_cap_match(fn, text)
        if match_with_reason is None:
            continue

        match, reason = match_with_reason
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=_line_for(fn.function_line, text, match),
                severity=DETECTOR_SEVERITY_DEFAULT,
                function=fn.name,
                message=(
                    f"`{fn.name}` performs fee or premium subtraction before "
                    f"a safe bound: {reason}. Guard fee <= amount or saturate "
                    "the fee before subtracting, then apply caps to the wide "
                    "value. (class: integer-overflow-clamp, posture: "
                    "NOT_SUBMIT_READY)"
                ),
            )
        )

    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT", "SUBMISSION_POSTURE"]
