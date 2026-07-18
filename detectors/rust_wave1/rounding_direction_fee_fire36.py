"""
rounding_direction_fee_fire36.py

Rust Fire36 lift for rounding-direction-attack in fee, share, collateral,
and reward math.

Rule 37 provenance:
- verification_tier: tier-3-synthetic-taxonomy-anchored
- context_pack_id: auditooor.vault_context_pack.v1:resume:a14a00fe6ae82f40
- context_pack_hash: a14a00fe6ae82f4042f8fce336676e437af06060e1f44425bad63447335cb2d7
- source ref: reports/detector_lift_fire35_20260605/post_priorities_rust.md
- source ref: reference/patterns.dsl/fx-aave-liquidation-fee-rounding-direction.yaml
- source ref: reference/patterns.dsl/rd-rounding-direction-zero-payout-after-balance-debit.yaml
- source ref: detectors/rust_wave1/rounding_residual_fire35.py
- source ref: detectors/go_wave1/go-rounding-fee-direction-fire33.py
- attack_class: rounding-direction-attack

Flags public Rust value math where floor, ceil, or truncating cast math feeds
a value-moving sink before exactness checks, before state writeback or external
settlement. The detector is intentionally narrow: it requires a fee, share,
collateral, reward, debt, or settlement context plus a nearby value sink.
Boundary: state writeback or external settlement is required.

Detector hits are source-review candidates only. R40 and R80 proof still
require a real in-scope PoC before any finding can cite the result.
"""

from __future__ import annotations

import re

from _util import (
    body_text_nocomment,
    fn_body,
    fn_name,
    function_items,
    in_test_cfg,
    is_pub,
    line_col,
    snippet_of,
)


DETECTOR_ID = "rust_wave1.rounding_direction_fee_fire36"

_VALUE_CONTEXT_RE = re.compile(
    r"(?i)(fee|fees|share|shares|asset|assets|reward|rewards|rebate|"
    r"refund|liquidat|penalty|haircut|discount|debt|borrow|repay|"
    r"repayment|collateral|margin|health|solv|fund|reserve|vault|pool|"
    r"payout|claim|withdraw|redeem|deposit|mint|burn|credit|owed|"
    r"required|seize|seized|settle|settlement|notional|bps|rate|amount|"
    r"balance|liability|protocol|treasury|collector)"
)

_ACTOR_CONTEXT_RE = re.compile(
    r"(?i)(user|account|owner|sender|caller|payer|borrower|trader|"
    r"liquidator|withdrawer|recipient|beneficiary|delegator|operator|"
    r"position|payer|protocol|treasury|collector|vault)"
)

_ASSIGN_RE = re.compile(
    r"\blet\s+(?:mut\s+)?(?P<alias>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s*:\s*[^=;]+)?\s*=\s*(?P<expr>[^;{}]+)\s*;",
    re.MULTILINE,
)

_CEIL_RE = re.compile(
    r"(?i)(?:\bdiv_ceil\s*\(|\bceil_div\s*\(|\bceildiv\s*\(|"
    r"\bround_up\s*\(|\broundup\s*\(|\bmul_div_up\s*\(|"
    r"\bmuldivup\s*\(|\bchecked_mul_div_up\s*\(|"
    r"\bchecked_ceil_div\s*\(|\+\s*[^;\n()]{1,90}\s*-\s*1\s*\)\s*/)"
)

_FLOOR_RE = re.compile(
    r"(?i)(?:/|\.\s*(?:checked_div|saturating_div|wrapping_div|div_euclid)"
    r"\s*\(|\b(?:floor_div|floordiv|round_down|rounddown|mul_div_down|"
    r"muldivdown|mul_div_floor|muldivfloor|checked_mul_div_down|"
    r"checked_floor_div)\s*\()"
)

_TRUNC_CAST_RE = re.compile(
    r"\bas\s+(?:u8|u16|u32|u64|usize|i8|i16|i32|i64|isize)\b"
)

_NEUTRAL_PRECISION_RE = re.compile(
    r"(?i)(?:\bmul_div\s*\(|\bmuldiv\s*\(|\bchecked_mul_div\s*\(|"
    r"\bmultiply_ratio\s*\(|\bfull_?precision\b|\bfixedu?128\b|"
    r"\bfixedi?128\b|\bfixed_?point\b|\bdecimal\b|\bperbill\b|"
    r"\bpermill\b|\bratio::|\bRoundingMode\b|\bchecked_ratio\b)"
)

_REMAINDER_REJECT_RE = re.compile(
    r"(?is)(?:if|ensure!|require!|assert!)\s*(?=[^{};]{0,460}"
    r"(?:%|checked_rem|rem_euclid))(?=[^{};]{0,460}"
    r"(?:!=\s*0|>\s*0|<\s*0|non_exact|exact))[^{};]{0,460}"
    r"(?:\{[^{}]{0,280}\b(?:return\s+Err|Err\s*\(|panic!|None|false)\b|;)"
)

_SAFE_REMAINDER_HANDLING_RE = re.compile(
    r"(?is)\blet\s+(?:mut\s+)?(?:[A-Za-z_][A-Za-z0-9_]*_)?"
    r"(?:remainder|residual|dust|leftover)[A-Za-z0-9_]*"
    r"(?:\s*:\s*[^=;]+)?\s*=\s*[^;]{0,260}"
    r"(?:%|checked_rem|rem_euclid)[^;]{0,260};"
    r"[^{};]{0,900}\b(?:refund|refunds|carry|rounding_carry|"
    r"carry_forward|pending|rounding_buffer|remainder_pool|"
    r"residual_pool)\b"
)

_ALIAS_GUARD_RE = re.compile(
    r"(?is)(?:if|ensure!|require!|assert!)\s*(?=[^{};]{0,360}\b{alias}\b)"
    r"(?=[^{};]{0,360}(?:==\s*0|<=\s*0|<\s*(?:min|MIN|one|1)|"
    r"<=\s*max|<=\s*MAX|non_zero|minimum|exact))[^{};]{0,360}"
    r"(?:\{[^{}]{0,260}\b(?:return\s+Err|Err\s*\(|panic!|None|false)\b|;)"
)

_SAFE_LINE_RE = re.compile(
    r"(?i)(carry|carry_forward|carryforward|rollover|pending|unallocated|"
    r"rounding_buffer|rounding_reserve|remainder_pool|residual_pool|"
    r"refund|refunds|return_to|return_residual|return_remainder|"
    r"bounded|bound_dust|max_dust|dust_limit|rounding_limit|preview|"
    r"quote|view_only)"
)

_TRANSFER_IN_RE = re.compile(
    r"(?is)\b[A-Za-z_][A-Za-z0-9_:\.]*"
    r"(?:collect|charge|debit|pull|pull_from|repay|burn|take|pay_fee|"
    r"settle_fee|transfer_from)[A-Za-z0-9_:\.]*\s*\("
    r"(?=[^;{}]{0,560}\b{alias}\b)[^;{}]{0,560}\)"
)

_TRANSFER_OUT_RE = re.compile(
    r"(?is)\b[A-Za-z_][A-Za-z0-9_:\.]*"
    r"(?:transfer|send|credit|pay|payout|withdraw|claim|mint|release|"
    r"settle|distribute|award)[A-Za-z0-9_:\.]*\s*\("
    r"(?=[^;{}]{0,560}\b{alias}\b)[^;{}]{0,560}\)"
)

_VALUE_FIELD = (
    r"(?:fee|fees|revenue|treasury|reserve|reserves|insurance|fund|funds|"
    r"share|shares|asset|assets|reward|rewards|reward_debt|debt|debts|"
    r"liability|liabilities|penalty|collateral|margin|health|credit|"
    r"credits|balance|balances|payout|settlement)"
)

_STATE_WRITE_RE = re.compile(
    r"(?is)\b(?:self|state|ledger|pool|vault|market|book|position|account)"
    r"\.[A-Za-z0-9_\.]*"
    r"(?P<field>[A-Za-z0-9_]*" + _VALUE_FIELD + r"[A-Za-z0-9_]*)"
    r"\s*(?P<op>\+=|-=|=)\s*[^;{}]{0,360}\b{alias}\b"
)

_MAP_INSERT_RE = re.compile(
    r"(?is)\b(?:self|state|ledger|pool|vault|market|book|position|account)"
    r"\.[A-Za-z0-9_\.]*"
    r"(?P<field>[A-Za-z0-9_]*" + _VALUE_FIELD + r"[A-Za-z0-9_]*)"
    r"\.insert\s*\((?=[^;{}]{0,560}\b{alias}\b)[^;{}]{0,560}\)"
)

_SETTER_RE = re.compile(
    r"(?is)\b[A-Za-z_][A-Za-z0-9_:\.]*"
    r"(?:set|update|record|accrue|credit|debit|book|apply|write|add|sub)"
    r"[A-Za-z0-9_]*(?:fee|share|reward|debt|liability|penalty|collateral|"
    r"margin|health|solvency|credit|asset|balance)[A-Za-z0-9_]*\s*\("
    r"(?=[^;{}]{0,560}\b{alias}\b)[^;{}]{0,560}\)"
)

_SOLVENCY_RE = re.compile(
    r"(?is)\b(?:if|ensure!|require!)\s*(?=[^{}]{0,560}\b{alias}\b)"
    r"(?=[^{}]{0,560}(?:health|solv|margin|collateral|debt|required|"
    r"threshold|ltv|liquidat))[^{}]{0,560}\{[^{}]{0,360}"
    r"\b(?:withdraw|borrow|liquidate|release|seize|settle|transfer)"
)


def _compile_alias(pattern: re.Pattern[str], alias: str) -> re.Pattern[str]:
    return re.compile(pattern.pattern.replace("{alias}", re.escape(alias)), pattern.flags)


def _expr_kind(expr: str) -> tuple[str, str] | None:
    compact = " ".join(expr.split())
    if _NEUTRAL_PRECISION_RE.search(compact):
        return None
    if _CEIL_RE.search(compact):
        return ("ceil", "ceil rounding")
    if _FLOOR_RE.search(compact):
        if _TRUNC_CAST_RE.search(compact):
            return ("floor", "floor division followed by a truncating cast")
        return ("floor", "floor or truncating division")
    if _TRUNC_CAST_RE.search(compact) and _VALUE_CONTEXT_RE.search(compact):
        return ("floor", "truncating cast in value math")
    return None


def _has_remainder_reject(prefix: str, tail: str, expr: str) -> bool:
    window = prefix[-900:] + "\n" + expr + "\n" + tail[:900]
    return bool(_REMAINDER_REJECT_RE.search(window))


def _has_safe_remainder_handling(tail: str) -> bool:
    return bool(_SAFE_REMAINDER_HANDLING_RE.search(tail[:1300]))


def _has_alias_guard(tail: str, alias: str) -> bool:
    return bool(_compile_alias(_ALIAS_GUARD_RE, alias).search(tail[:1000]))


def _safe_match(match_text: str) -> bool:
    return bool(_SAFE_LINE_RE.search(match_text))


def _first_match(pattern: re.Pattern[str], tail: str, alias: str) -> re.Match[str] | None:
    match = _compile_alias(pattern, alias).search(tail[:1700])
    if match is None or _safe_match(match.group(0)):
        return None
    return match


def _state_sink(tail: str, alias: str) -> tuple[str, str] | None:
    write = _first_match(_STATE_WRITE_RE, tail, alias)
    if write is not None:
        field = write.group("field")
        op = write.group("op")
        return field, f"rounded amount is written to `{field}` with `{op}`"

    inserted = _first_match(_MAP_INSERT_RE, tail, alias)
    if inserted is not None:
        field = inserted.group("field")
        return field, f"rounded amount is inserted into `{field}` accounting"

    setter = _first_match(_SETTER_RE, tail, alias)
    if setter is not None:
        return "setter", "rounded amount is passed to a value-accounting setter"

    return None


def _sink_reason(kind: str, tail: str, alias: str) -> str | None:
    if kind == "floor":
        transfer_in = _first_match(_TRANSFER_IN_RE, tail, alias)
        if transfer_in is not None:
            return "floor-rounded amount is pulled, charged, debited, repaid, or burned"

        state = _state_sink(tail, alias)
        if state is not None:
            _field, reason = state
            return reason

        solvency = _first_match(_SOLVENCY_RE, tail, alias)
        if solvency is not None:
            return "floor-rounded amount gates a health, debt, margin, or collateral decision"

        transfer_out = _first_match(_TRANSFER_OUT_RE, tail, alias)
        if transfer_out is not None:
            return "floor-rounded amount reaches an external payout or settlement path"

        return None

    transfer_out = _first_match(_TRANSFER_OUT_RE, tail, alias)
    if transfer_out is not None:
        return "ceil-rounded amount leaves protocol custody as payout, reward, claim, mint, or settlement"

    state = _state_sink(tail, alias)
    if state is not None:
        field, reason = state
        if re.search(r"(?i)(reward|credit|share|asset|balance|collateral|debt|liabilit)", field):
            return reason

    return None


def _rounding_direction_reason(body_text: str) -> str | None:
    for match in _ASSIGN_RE.finditer(body_text):
        alias = match.group("alias")
        expr = " ".join(match.group("expr").split())
        expr_info = _expr_kind(expr)
        if expr_info is None:
            continue

        if not (_VALUE_CONTEXT_RE.search(alias) or _VALUE_CONTEXT_RE.search(expr)):
            continue
        if not (_ACTOR_CONTEXT_RE.search(body_text) or _ACTOR_CONTEXT_RE.search(expr)):
            continue

        prefix = body_text[: match.start()]
        tail = body_text[match.end():]
        if _has_alias_guard(tail, alias):
            continue
        if _has_remainder_reject(prefix, tail, expr):
            continue
        if _has_safe_remainder_handling(tail):
            continue

        kind, rounding_source = expr_info
        sink = _sink_reason(kind, tail, alias)
        if sink is None:
            continue

        return f"{alias} uses {rounding_source} from `{expr}` and {sink}"
    return None


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source) or not is_pub(fn, source):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        name = fn_name(fn, source)
        body_nc = body_text_nocomment(body, source)
        if not (_VALUE_CONTEXT_RE.search(name) or _VALUE_CONTEXT_RE.search(body_nc)):
            continue

        reason = _rounding_direction_reason(body_nc)
        if reason is None:
            continue

        line, col = line_col(fn)
        hits.append(
            {
                "severity": "medium",
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source, max_len=220),
                "message": (
                    f"`{name}` applies rounding on the attacker-favorable "
                    f"side of fee, share, collateral, reward, or settlement "
                    f"math: {reason}. Use full precision math, put ceil or "
                    f"floor on the value-protecting side, and reject "
                    f"non-exact or below-minimum results before state "
                    f"writeback or external settlement. (class: "
                    f"rounding-direction-attack; posture: NOT_SUBMIT_READY)"
                ),
            }
        )
    return hits
