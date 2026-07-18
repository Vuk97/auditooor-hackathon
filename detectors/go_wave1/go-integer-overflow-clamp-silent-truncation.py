"""
go-integer-overflow-clamp-silent-truncation.py

Detects Go accounting paths that overflow, truncate, or clamp arithmetic before
updating fee, debt, share, reserve, or balance state.

Confirmed anchors:
- AMM protocol fee share is computed with integer division and written to a
  protocol fee reserve without the zero-LP-fee special case.
- Bond debt decay is subtracted or saturated into debt accounting instead of
  rejecting the unsafe decay amount.

This detector is intentionally narrow. It requires both arithmetic-risk shape
and an accounting write, and it suppresses paths that reject the unsafe value
before applying the accounting update.
"""

from __future__ import annotations

import re

DETECTOR_ID = "go_wave1.go-integer-overflow-clamp-silent-truncation"

_ACCOUNTING_NAME_RE = re.compile(
    r"(fee|fees|debt|share|shares|reserve|reserves|balance|balances|"
    r"liquidity|collateral|reward|rewards|owed|outstanding|supply|assets)",
    re.IGNORECASE,
)

_ACCOUNTING_WRITE_RE = re.compile(
    r"\b(?P<lhs>(?:[A-Za-z_]\w*\.)*(?=[A-Za-z_]\w*"
    r"(?:Fee|Fees|Debt|Share|Shares|Reserve|Reserves|Balance|Balances|"
    r"Liquidity|Collateral|Reward|Rewards|Owed|Outstanding|Supply|Assets)"
    r")[A-Za-z_]\w*)\s*(?:\+=|-=|=)",
    re.IGNORECASE,
)

_ACCOUNTING_SETTER_RE = re.compile(
    r"\bSet[A-Za-z_]\w*(?:Fee|Fees|Debt|Share|Shares|Reserve|Reserves|"
    r"Balance|Balances|Liquidity|Collateral|Reward|Rewards|Owed|Outstanding|"
    r"Supply|Assets)[A-Za-z_]\w*\s*\(",
    re.IGNORECASE,
)

_NARROW_CAST_ASSIGN_RE = re.compile(
    r"\b(?P<lhs>[A-Za-z_]\w*)\s*(?::=|=)\s*"
    r"(?P<cast>u?int(?:8|16|32))\s*\((?P<expr>[^)\n]+)\)",
)

_NARROW_CAST_RE = re.compile(r"\bu?int(?:8|16|32)\s*\(")

_REJECTING_BOUND_RE = re.compile(
    r"if\s+(?:[^{}]|\n){0,260}"
    r"(?:>|<|>=|<=|overflow|underflow|fits|math\.Max|MaxUint|MaxInt)"
    r"(?:[^{}]|\n){0,260}\{(?:[^{}]|\n){0,260}\breturn\b",
    re.IGNORECASE,
)

_SPECIAL_CASE_FEE_RE = re.compile(
    r"(?:lpFee\s*==\s*0|swapFee\s*==\s*protocolFee|"
    r"protocolFee\s*==\s*swapFee|allFeeToProtocol|fullProtocolFee)",
    re.IGNORECASE,
)

_PROTOCOL_FEE_DIV_RE = re.compile(
    r"\b(?P<lhs>[A-Za-z_]\w*(?:Fee|Share|Protocol|Reserve)[A-Za-z_]\w*)"
    r"\s*(?::=|=)\s*[^;\n]*(?:protocolFee|feePips|feeBps|lpFee|swapFee)"
    r"[^;\n]*/\s*(?:PIPS|BPS|Bps|Pips|1_?000_?000|10_?000)",
    re.IGNORECASE,
)

_CLAMP_IF_RE = re.compile(
    r"if\s+(?P<value>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*>\s*"
    r"(?P<limit>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*\{\s*"
    r"(?P=value)\s*=\s*(?P=limit)\s*\}",
    re.DOTALL,
)

_MIN_CLAMP_RE = re.compile(
    r"\b(?P<lhs>[A-Za-z_]\w*)\s*(?::=|=)\s*"
    r"(?:min|math\.Min|Min[A-Za-z_]\w*|Clamp[A-Za-z_]\w*)\s*\("
    r"[^)]*(?:fee|debt|share|reserve|balance|liquidity|collateral|reward|assets)",
    re.IGNORECASE,
)

_SUB_COMPOUND_RE = re.compile(
    r"\b(?P<lhs>(?:[A-Za-z_]\w*\.)*[A-Za-z_]\w*)"
    r"\s*-=\s*(?P<rhs>[^;\n]+)",
    re.IGNORECASE,
)

_SUB_ASSIGN_RE = re.compile(
    r"\b(?P<lhs>(?:[A-Za-z_]\w*\.)*[A-Za-z_]\w*)\s*=\s*"
    r"(?P=lhs)\s*-\s*(?P<rhs>[^;\n]+)",
    re.IGNORECASE,
)

_STRING_RE = re.compile(r'`[^`]*`|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')


def _blank_comment(match: re.Match[str]) -> str:
    return "".join("\n" if ch == "\n" else " " for ch in match.group(0))


def _strip_comments(src: str) -> str:
    src = re.sub(r"//.*", _blank_comment, src)
    return re.sub(r"/\*.*?\*/", _blank_comment, src, flags=re.S)


def _strip_comments_and_strings(src: str) -> str:
    src = _strip_comments(src)
    return _STRING_RE.sub(_blank_comment, src)


def _has_prior_reject_guard(body_text: str, index: int) -> bool:
    return bool(_REJECTING_BOUND_RE.search(body_text[: max(index, 0)]))


def _has_accounting_context(text: str) -> bool:
    return bool(_ACCOUNTING_NAME_RE.search(text))


def _tail_has_accounting_write(tail: str) -> bool:
    return bool(_ACCOUNTING_WRITE_RE.search(tail) or _ACCOUNTING_SETTER_RE.search(tail))


def _alias_flows_to_accounting(tail: str, alias: str) -> bool:
    alias_re = re.escape(alias)
    write_with_alias = re.compile(
        r"\b(?:[A-Za-z_]\w*\.)*(?=[A-Za-z_]\w*"
        r"(?:Fee|Fees|Debt|Share|Shares|Reserve|Reserves|Balance|Balances|"
        r"Liquidity|Collateral|Reward|Rewards|Owed|Outstanding|Supply|Assets)"
        r")[A-Za-z_]\w*\s*(?:\+=|-=|=)\s*[^;\n]*\b"
        + alias_re
        + r"\b",
        re.IGNORECASE,
    )
    setter_with_alias = re.compile(
        r"\bSet[A-Za-z_]\w*(?:Fee|Fees|Debt|Share|Shares|Reserve|Reserves|"
        r"Balance|Balances|Liquidity|Collateral|Reward|Rewards|Owed|"
        r"Outstanding|Supply|Assets)[A-Za-z_]\w*\s*\([^)]*\b"
        + alias_re
        + r"\b",
        re.IGNORECASE | re.DOTALL,
    )
    return bool(write_with_alias.search(tail) or setter_with_alias.search(tail))


def _is_rejected_before_write(body_text: str, match: re.Match[str]) -> bool:
    write = _ACCOUNTING_WRITE_RE.search(body_text, match.end())
    if write is None:
        return False
    return _has_prior_reject_guard(body_text, write.start())


def _narrowing_cast_reason(body_text: str) -> str | None:
    for match in _NARROW_CAST_ASSIGN_RE.finditer(body_text):
        if not _has_accounting_context(match.group(0) + body_text):
            continue
        tail = body_text[match.end():]
        if not _alias_flows_to_accounting(tail, match.group("lhs")):
            continue
        if _has_prior_reject_guard(body_text, match.start()):
            continue
        return (
            f"{match.group('lhs')} narrows {match.group('expr').strip()} with "
            f"{match.group('cast')} before an accounting write"
        )

    for match in _NARROW_CAST_RE.finditer(body_text):
        if _has_prior_reject_guard(body_text, match.start()):
            continue
        window = body_text[max(0, match.start() - 120): match.end() + 180]
        if _has_accounting_context(window) and _tail_has_accounting_write(window):
            return "a native narrow integer cast feeds an accounting update"
    return None


def _fee_truncation_reason(body_text: str) -> str | None:
    if _SPECIAL_CASE_FEE_RE.search(body_text):
        return None
    for match in _PROTOCOL_FEE_DIV_RE.finditer(body_text):
        if _has_prior_reject_guard(body_text, match.start()):
            continue
        tail = body_text[match.end():]
        if _alias_flows_to_accounting(tail, match.group("lhs")) or _tail_has_accounting_write(tail):
            return (
                f"{match.group('lhs')} computes a rounded protocol fee share "
                f"before a fee or reserve update"
            )
    return None


def _clamp_reason(body_text: str) -> str | None:
    for match in _CLAMP_IF_RE.finditer(body_text):
        if _has_prior_reject_guard(body_text, match.start()):
            continue
        value = match.group("value").split(".")[-1]
        tail = body_text[match.end():]
        if _alias_flows_to_accounting(tail, value) or _tail_has_accounting_write(tail):
            return (
                f"{match.group('value')} is clamped to {match.group('limit')} "
                f"before an accounting write instead of rejected"
            )

    for match in _MIN_CLAMP_RE.finditer(body_text):
        if _has_prior_reject_guard(body_text, match.start()):
            continue
        tail = body_text[match.end():]
        if _alias_flows_to_accounting(tail, match.group("lhs")) or _tail_has_accounting_write(tail):
            return (
                f"{match.group('lhs')} is saturated with min/Clamp before an "
                f"accounting write instead of rejected"
            )
    return None


def _unchecked_subtraction_reason(body_text: str) -> str | None:
    for pattern in (_SUB_COMPOUND_RE, _SUB_ASSIGN_RE):
        for match in pattern.finditer(body_text):
            if _has_prior_reject_guard(body_text, match.start()):
                continue
            rhs = match.group("rhs").strip()
            if not _has_accounting_context(match.group("lhs")):
                continue
            return (
                f"{match.group('lhs')} subtracts {rhs} without a prior "
                f"rejecting bounds check"
            )
    return None


def _risk_reason(body_text: str) -> str | None:
    return (
        _narrowing_cast_reason(body_text)
        or _fee_truncation_reason(body_text)
        or _clamp_reason(body_text)
        or _unchecked_subtraction_reason(body_text)
    )


def run(engine, filepath: str):
    hits = []
    for fn in engine.functions():
        name = engine.fn_name(fn)
        if not name or name == "?":
            continue
        body = engine.fn_body(fn)
        if body is None:
            continue

        fn_text = engine.text(fn)
        body_text = _strip_comments_and_strings(engine.text(body))
        if not _has_accounting_context(fn_text):
            continue

        reason = _risk_reason(body_text)
        if reason is None:
            continue

        hits.append(
            {
                "severity": "medium",
                "line": engine.line(fn),
                "col": engine.col(fn),
                "snippet": fn_text.splitlines()[0][:160],
                "message": (
                    f"`{name}` silently hides unsafe arithmetic before an "
                    f"accounting update: {reason}. Reject overflow, "
                    f"underflow, or lossy fee/share values before mutating "
                    f"fee, debt, share, reserve, or balance state. "
                    f"(class: integer-overflow-clamp)"
                ),
            }
        )

    return hits
