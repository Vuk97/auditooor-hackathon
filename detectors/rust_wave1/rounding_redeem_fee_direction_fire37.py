"""
rounding_redeem_fee_direction_fire37.py

Rust Fire37 lift for rounding-direction-attack in redeem, withdraw, burn,
fee, and share conversion paths.

Rule 37 provenance:
- verification_tier: tier-3-synthetic-taxonomy-anchored
- context_pack_id: auditooor.vault_context_pack.v1:resume:f4d2e1d5cdce68c4
- context_pack_hash: f4d2e1d5cdce68c48442ecdcc7a8f029fcf9efb0e11511c8f00371f9c304e88f
- source ref: reports/detector_lift_fire36_20260605/post_priorities_rust.md
- source ref: reference/patterns.dsl/rounding-direction-attack.yaml (requested ref absent in this worktree)
- source ref: reference/patterns.dsl/erc4626-redeem-rounding-favors-caller.yaml
- source ref: reference/patterns.dsl/ec-rounding-withdraw-favors-user.yaml
- source ref: reference/patterns.dsl.r75_mined/firms_spearbit_oz_consensys/spearbit-pendle-sy-wrap-rounding-down-on-deposit-up-on-redeem.yaml
- source ref: detectors/rust_wave1/rounding_direction_fee_fire36.py
- source ref: detectors/rust_wave1/rounding_residual_fire35.py
- attack_class: rounding-direction-attack

Flags public Rust redeem, withdraw, burn, fee, or share-conversion logic where
rounded division feeds a value-moving sink on the caller-favorable side. The
detector intentionally requires a concrete sink: shares burned/debited, assets
paid/released, reserves reduced, or a min-out check against the wrong rounded
quantity before net assets move.

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


DETECTOR_ID = "rust_wave1.rounding_redeem_fee_direction_fire37"

_ENTRY_CONTEXT_RE = re.compile(
    r"(?i)(redeem|withdraw|burn|fee|fees|share|shares|asset|assets|vault|"
    r"pool|reserve|reserves|supply|mint|payout|claim|refund|preview|"
    r"min_out|min_assets|min_shares)"
)

_ALIAS_VALUE_RE = re.compile(
    r"(?i)(share|shares|asset|assets|amount|payout|out|withdraw|redeem|"
    r"burn|fee|fees|net|gross|reserve|reserves|min|preview)"
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
    r"(?is)(?:if|ensure!|require!|assert!)\s*(?=[^{};]{0,520}"
    r"(?:%|checked_rem|rem_euclid))(?=[^{};]{0,520}"
    r"(?:!=\s*0|>\s*0|<\s*0|non_exact|exact|remainder))[^{};]{0,520}"
    r"(?:\{[^{}]{0,320}\b(?:return\s+Err|Err\s*\(|panic!|None|false)\b|;)"
)

_ALIAS_SAFE_GUARD_RE = re.compile(
    r"(?is)(?:if|ensure!|require!|assert!)\s*(?=[^{};]{0,420}\b{alias}\b)"
    r"(?=[^{};]{0,420}(?:==\s*0|!=\s*0|>\s*0|<\s*(?:min|MIN|one|1)|"
    r"<=\s*max|<=\s*MAX|non_zero|minimum|exact|dust_limit|rounding_limit))"
    r"[^{};]{0,420}(?:\{[^{}]{0,320}\b(?:return\s+Err|Err\s*\(|panic!|None|false)\b|;)"
)

_SAFE_LINE_RE = re.compile(
    r"(?i)(carry|carry_forward|carryforward|rollover|pending|unallocated|"
    r"rounding_buffer|rounding_reserve|remainder_pool|residual_pool|refund|"
    r"refunds|return_to|return_residual|return_remainder|bounded|bound_dust|"
    r"max_dust|dust_limit|rounding_limit|preview|quote|view_only|simulate)"
)

_SHARE_ALIAS_RE = re.compile(r"(?i)(share|shares|burn)")
_ASSET_ALIAS_RE = re.compile(
    r"(?i)(asset|assets|amount|payout|out|withdraw|redeem|claim|release|net|gross)"
)
_FEE_ALIAS_RE = re.compile(r"(?i)(fee|fees|commission|surcharge)")
_MIN_ALIAS_RE = re.compile(r"(?i)(min|min_out|min_assets|min_shares|minimum)")

_TRANSFER_OUT_RE = re.compile(
    r"(?is)\b[A-Za-z_][A-Za-z0-9_:\.]*"
    r"(?:transfer|send|credit|pay|payout|withdraw|claim|release|settle|"
    r"redeem|distribute)[A-Za-z0-9_:\.]*\s*\("
    r"(?=[^;{}]{0,620}\b{alias}\b)[^;{}]{0,620}\)"
)

_BURN_OR_DEBIT_RE = re.compile(
    r"(?is)\b[A-Za-z_][A-Za-z0-9_:\.]*"
    r"(?:burn|debit|deduct|take|pull|sub|remove|charge)"
    r"[A-Za-z0-9_:\.]*\s*\("
    r"(?=[^;{}]{0,620}\b{alias}\b)[^;{}]{0,620}\)"
)

_RESERVE_DEBIT_RE = re.compile(
    r"(?is)\b(?:self|state|vault|pool|market|reserve|reserves)"
    r"\.[A-Za-z0-9_\.]*(?:asset|assets|reserve|reserves|balance|balances|"
    r"liquidity|cash|funds)[A-Za-z0-9_\.]*\s*(?:-=|=)\s*"
    r"[^;{}]{0,420}\b{alias}\b"
)

_LATER_ASSET_MOVE_RE = re.compile(
    r"(?is)\b[A-Za-z_][A-Za-z0-9_:\.]*"
    r"(?:transfer|send|credit|pay|payout|withdraw|claim|release|settle|"
    r"redeem|distribute)[A-Za-z0-9_:\.]*\s*\("
    r"(?=[^;{}]{0,620}(?:asset|assets|amount|requested|withdraw|redeem|"
    r"payout|out))[^;{}]{0,620}\)"
)

_FEE_SUB_ASSIGN_RE = re.compile(
    r"(?is)\blet\s+(?:mut\s+)?(?P<net>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s*:\s*[^=;]+)?\s*=\s*(?P<expr>[^;{}]*(?:"
    r"checked_sub\s*\(\s*{fee}\s*\)|-\s*{fee}\b)[^;{}]*)\s*;"
)

_MIN_GUARD_FOR_ALIAS_RE = re.compile(
    r"(?is)(?:if|ensure!|require!|assert!)\s*(?=[^{};]{0,460}\b{guarded}\b)"
    r"(?=[^{};]{0,460}\b{minimum}\b)(?=[^{};]{0,460}(?:<|>|<=|>=))"
    r"[^{};]{0,460}(?:\{[^{}]{0,320}\b(?:return\s+Err|Err\s*\(|panic!|None|false)\b|;)"
)


class Assignment:
    def __init__(self, alias: str, expr: str, kind: str, start: int, end: int):
        self.alias = alias
        self.expr = expr
        self.kind = kind
        self.start = start
        self.end = end


def _compile_alias(pattern: re.Pattern[str], **aliases: str) -> re.Pattern[str]:
    text = pattern.pattern
    for key, value in aliases.items():
        text = text.replace("{" + key + "}", re.escape(value))
    return re.compile(text, pattern.flags)


def _expr_kind(expr: str) -> str | None:
    compact = " ".join(expr.split())
    if _NEUTRAL_PRECISION_RE.search(compact):
        return None
    if _CEIL_RE.search(compact):
        return "ceil"
    if _FLOOR_RE.search(compact):
        return "floor"
    if _TRUNC_CAST_RE.search(compact) and _ALIAS_VALUE_RE.search(compact):
        return "floor"
    return None


def _assignments(body_text: str) -> list[Assignment]:
    out = []
    for match in _ASSIGN_RE.finditer(body_text):
        alias = match.group("alias")
        expr = " ".join(match.group("expr").split())
        kind = _expr_kind(expr)
        if kind is None:
            continue
        if not (_ALIAS_VALUE_RE.search(alias) or _ALIAS_VALUE_RE.search(expr)):
            continue
        out.append(Assignment(alias, expr, kind, match.start(), match.end()))
    return out


def _has_remainder_reject(prefix: str, tail: str, expr: str) -> bool:
    window = prefix[-1000:] + "\n" + expr + "\n" + tail[:1100]
    return bool(_REMAINDER_REJECT_RE.search(window))


def _has_alias_safe_guard(tail: str, alias: str) -> bool:
    return bool(_compile_alias(_ALIAS_SAFE_GUARD_RE, alias=alias).search(tail[:1200]))


def _safe_match(match_text: str) -> bool:
    return bool(_SAFE_LINE_RE.search(match_text))


def _first_alias_match(
    pattern: re.Pattern[str],
    tail: str,
    alias: str,
    *,
    limit: int = 1900,
) -> re.Match[str] | None:
    match = _compile_alias(pattern, alias=alias).search(tail[:limit])
    if match is None or _safe_match(match.group(0)):
        return None
    return match


def _has_outgoing_asset_sink(tail: str, alias: str) -> bool:
    return (
        _first_alias_match(_TRANSFER_OUT_RE, tail, alias) is not None
        or _first_alias_match(_RESERVE_DEBIT_RE, tail, alias) is not None
    )


def _has_burn_or_debit_sink(tail: str, alias: str) -> bool:
    return _first_alias_match(_BURN_OR_DEBIT_RE, tail, alias) is not None


def _later_outgoing_sink_for_any_value(tail: str) -> bool:
    value_aliases = re.findall(
        r"\b(?:net_assets|assets_out|asset_out|payout|withdraw_amount|redeem_amount|amount_out)\b",
        tail,
        flags=re.IGNORECASE,
    )
    return (
        any(_has_outgoing_asset_sink(tail, alias) for alias in value_aliases)
        or bool(_LATER_ASSET_MOVE_RE.search(tail[:1900]))
    )


def _fee_subtraction_after_truncation(
    assignment: Assignment,
    prefix: str,
    tail: str,
) -> str | None:
    if assignment.kind != "floor" or not _FEE_ALIAS_RE.search(assignment.alias):
        return None
    if _has_remainder_reject(prefix, tail, assignment.expr):
        return None

    match = _compile_alias(_FEE_SUB_ASSIGN_RE, fee=assignment.alias).search(tail[:1700])
    if match is None:
        return None

    net_alias = match.group("net")
    after_net = tail[match.end():]
    if not _has_outgoing_asset_sink(after_net, net_alias):
        return None

    return (
        f"{assignment.alias} is floor-rounded from `{assignment.expr}`, "
        f"subtracted into `{net_alias}`, and `{net_alias}` is paid out"
    )


def _wrong_min_out_after_net_subtraction(assignments: list[Assignment], body_text: str) -> str | None:
    rounded_by_alias = {item.alias: item for item in assignments}
    for fee_item in assignments:
        if not _FEE_ALIAS_RE.search(fee_item.alias):
            continue
        fee_tail = body_text[fee_item.end:]
        net_match = _compile_alias(_FEE_SUB_ASSIGN_RE, fee=fee_item.alias).search(fee_tail[:1700])
        if net_match is None:
            continue
        net_alias = net_match.group("net")
        net_expr = net_match.group("expr")
        gross_alias = None
        for candidate in rounded_by_alias:
            if re.search(r"\b" + re.escape(candidate) + r"\b", net_expr):
                gross_alias = candidate
                break
        if gross_alias is None:
            continue
        if _SAFE_LINE_RE.search(net_expr):
            continue

        after_net = fee_tail[net_match.end():]
        if not _has_outgoing_asset_sink(after_net, net_alias):
            continue

        min_names = re.findall(
            r"\b(min(?:imum)?_[A-Za-z0-9_]*|min_out|min_assets|min_shares)\b",
            body_text,
            flags=re.IGNORECASE,
        )
        for min_alias in min_names:
            guard_on_gross = _compile_alias(
                _MIN_GUARD_FOR_ALIAS_RE,
                guarded=gross_alias,
                minimum=min_alias,
            ).search(after_net[:1200])
            guard_on_net = _compile_alias(
                _MIN_GUARD_FOR_ALIAS_RE,
                guarded=net_alias,
                minimum=min_alias,
            ).search(after_net[:1200])
            if guard_on_gross is not None and guard_on_net is None:
                gross_item = rounded_by_alias[gross_alias]
                return (
                    f"`{min_alias}` is checked against rounded gross `{gross_alias}` "
                    f"from `{gross_item.expr}` while net `{net_alias}` is transferred"
                )
    return None


def _rounding_redeem_fee_reason(body_text: str) -> str | None:
    assignments = _assignments(body_text)

    min_reason = _wrong_min_out_after_net_subtraction(assignments, body_text)
    if min_reason is not None:
        return min_reason

    for item in assignments:
        prefix = body_text[: item.start]
        tail = body_text[item.end:]
        if _has_alias_safe_guard(tail, item.alias):
            continue
        if _has_remainder_reject(prefix, tail, item.expr):
            continue

        fee_reason = _fee_subtraction_after_truncation(item, prefix, tail)
        if fee_reason is not None:
            return fee_reason

        if item.kind == "floor" and _SHARE_ALIAS_RE.search(item.alias):
            if _has_burn_or_debit_sink(tail, item.alias) and _later_outgoing_sink_for_any_value(tail):
                return (
                    f"{item.alias} is floor-rounded from `{item.expr}` before "
                    "caller shares are burned or debited and assets leave reserves"
                )

        if item.kind == "ceil" and _ASSET_ALIAS_RE.search(item.alias):
            if _has_outgoing_asset_sink(tail, item.alias):
                return (
                    f"{item.alias} is ceil-rounded from `{item.expr}` and then "
                    "paid, released, or deducted from reserves"
                )

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
        if not (_ENTRY_CONTEXT_RE.search(name) or _ENTRY_CONTEXT_RE.search(body_nc)):
            continue

        reason = _rounding_redeem_fee_reason(body_nc)
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
                    f"`{name}` applies redeem, withdraw, burn, fee, or share "
                    f"rounding on the caller-favorable side: {reason}. Round "
                    f"shares-to-burn and protocol fees in the value-protecting "
                    f"direction, check min-out against the final net amount, "
                    f"and reject non-exact dust before moving reserves. (class: "
                    f"rounding-direction-attack; posture: NOT_SUBMIT_READY)"
                ),
            }
        )
    return hits
