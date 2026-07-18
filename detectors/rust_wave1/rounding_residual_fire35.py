"""
rounding_residual_fire35.py

Rust Fire35 lift for rounding-direction-attack residual handling.

Rule 37 provenance:
- verification_tier: tier-3-synthetic-taxonomy-anchored
- context_pack_id: auditooor.vault_context_pack.v1:resume:5a29d91bbce92794
- context_pack_hash: 5a29d91bbce92794762a8ed09f2250a9242a49986ce3809863c10a012720379d
- source ref: reports/detector_lift_fire34_20260605/post_priorities_rust.md
- source ref: reference/patterns.dsl/rounding-direction-attack.yaml
- source ref: reference/patterns.dsl/r94-loop-royalty-distribution-rounding-dust-siphon.yaml
- source ref: detectors/rust_wave1/rounding_div_before_mul_fire34.py
- source ref: detectors/go_wave1/go-rounding-residual-fire34.py
- attack_class: rounding-direction-attack

Flags public Rust value math that computes a remainder, residual, dust,
leftover, or surplus after truncating division and then assigns that residual
to index zero, the last participant, a module/protocol bucket, or an
attacker-controlled payout sink. Safe handling is explicit reject, carry,
refund, or bounded dust handling before any sink.

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


DETECTOR_ID = "rust_wave1.rounding_residual_fire35"

_VALUE_CONTEXT_RE = re.compile(
    r"(?i)(fee|fees|share|shares|reward|rewards|royalt|payout|claim|"
    r"commission|rebate|refund|distribution|distribute|split|participant|"
    r"receiver|recipient|account|attacker|module|treasury|protocol|dust|"
    r"remainder|residual|leftover|surplus|decimal|balance|balances|pool|"
    r"vault|reserve|settle|settlement|withdraw|redeem|deposit|mint|burn)"
)

_RESIDUAL_ALIAS_RE = re.compile(
    r"(?i)(remainder|residual|dust|leftover|surplus|excess|fractional|"
    r"rounding_delta|rounding_loss|rounding)"
)

_ASSIGN_RE = re.compile(
    r"\blet\s+(?:mut\s+)?(?P<alias>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s*:\s*[^=;]+)?\s*=\s*(?P<expr>[^;{}]+)\s*;",
    re.MULTILINE,
)

_TRUNCATING_EXPR_RE = re.compile(
    r"%|"
    r"\.\s*(?:checked_rem|rem_euclid|wrapping_rem|saturating_rem)\s*\(|"
    r"\.\s*(?:checked_sub|saturating_sub|wrapping_sub)\s*\(|"
    r"\bSub\s*\(",
    re.IGNORECASE,
)

_SUBTRACTED_PRODUCT_RE = re.compile(
    r"(?is)(?:-\s*[^;\n]*(?:\*|checked_mul\s*\(|len\s*\(\))|"
    r"(?:checked_sub|saturating_sub|wrapping_sub)\s*\([^;]*(?:checked_mul|len\s*\(|\*))"
)

_DIVISION_CONTEXT_RE = re.compile(
    r"(?i)(?:/|\.\s*(?:checked_div|saturating_div|wrapping_div|div_euclid)\s*\(|"
    r"\b(?:share|split|per_user|per_receiver|per_recipient|quota|quotient)\b|"
    r"len\s*\(\)\s+as\s+(?:u64|u128|usize))"
)

_REJECT_OR_BOUND_GUARD_RE = re.compile(
    r"(?is)(?:if|ensure!|require!|assert!)\s*(?=[^{};]{0,420}\b{alias}\b)"
    r"(?=[^{};]{0,420}(?:!=\s*0|>\s*0|<\s*0|<=\s*max|<=\s*MAX|"
    r"max_dust|MAX_DUST|dust_limit|rounding_limit|bound|exact))"
    r"[^{};]{0,420}(?:\{[^{}]{0,280}\b(?:return\s+Err|Err\s*\(|panic!|None|false)\b|;)"
)

_SAFE_LINE_RE = re.compile(
    r"(?i)(carry|carry_forward|carryforward|rollover|accumulat|pending|"
    r"unallocated|rounding_buffer|rounding_reserve|remainder_pool|"
    r"residual_pool|next_epoch|next_period|refund|refunds|return_to|"
    r"return_residual|return_remainder|bounded|bound_dust|max_dust|MAX_DUST|"
    r"dust_limit|rounding_limit)"
)

_FIRST_INDEX_WRITE_RE = re.compile(
    r"(?is)(?:\[\s*(?:0|first_idx|first_index)\s*\]|"
    r"\.first_mut\s*\(\)|\.front_mut\s*\(\)|\bfirst_[A-Za-z0-9_]*\b)"
    r"[^;{}]{0,180}(?:\+=|=|insert\s*\(|push\s*\()[^;{}]*\b{alias}\b"
)

_LAST_INDEX_WRITE_RE = re.compile(
    r"(?is)(?:\[\s*[^;\]]*len\s*\([^;\]]+\)\s*-\s*1\s*\]|"
    r"\.last_mut\s*\(\)|\.back_mut\s*\(\)|\blast_[A-Za-z0-9_]*\b)"
    r"[^;{}]{0,180}(?:\+=|=|insert\s*\(|push\s*\()[^;{}]*\b{alias}\b"
)

_MODULE_STATE_WRITE_RE = re.compile(
    r"(?is)\b(?:self|state|ledger|pool|vault|market|module|protocol|treasury|"
    r"collector|fee_collector|fee_collector_account|module_account|"
    r"protocol_account)\s*(?:\.|::)?[A-Za-z0-9_\.]*"
    r"(?:module|protocol|treasury|collector|dust|remainder|residual|surplus|fee)"
    r"[A-Za-z0-9_\.]*\s*(?:\+=|=|insert\s*\(|push\s*\()[^;{}]*\b{alias}\b"
)

_MODULE_CALL_RE = re.compile(
    r"(?is)\b[A-Za-z_][A-Za-z0-9_:]*(?:module|protocol|treasury|collector|"
    r"dust|remainder|residual|surplus|fee)[A-Za-z0-9_:]*\s*\("
    r"(?=[^;{}]{0,460}\b{alias}\b)[^;{}]{0,460}\)"
)

_ATTACKER_CALL_RE = re.compile(
    r"(?is)\b[A-Za-z_][A-Za-z0-9_:\.]*"
    r"(?:credit|transfer|send|pay|payout|mint|withdraw|settle|release|insert)"
    r"[A-Za-z0-9_:\.]*\s*\("
    r"(?=[^;{}]{0,520}\b{alias}\b)"
    r"(?=[^;{}]{0,520}(?:attacker|caller|sender|payer|msg_sender|origin|"
    r"beneficiary|recipient|withdrawer|liquidator|operator))"
    r"[^;{}]{0,520}\)"
)


def _compile_alias(pattern: re.Pattern[str], alias: str) -> re.Pattern[str]:
    return re.compile(pattern.pattern.replace("{alias}", re.escape(alias)), pattern.flags)


def _creates_residual(alias: str, expr: str, prefix: str) -> bool:
    if not _RESIDUAL_ALIAS_RE.search(alias):
        return False
    if _TRUNCATING_EXPR_RE.search(expr) and (
        "%" in expr
        or "rem" in expr.lower()
        or _SUBTRACTED_PRODUCT_RE.search(expr)
        or _DIVISION_CONTEXT_RE.search(prefix[-900:] + "\n" + expr)
    ):
        return True
    if _SUBTRACTED_PRODUCT_RE.search(expr):
        return bool(_DIVISION_CONTEXT_RE.search(prefix[-1100:] + "\n" + expr))
    return False


def _has_reject_or_bound_guard(tail: str, alias: str) -> bool:
    return bool(_compile_alias(_REJECT_OR_BOUND_GUARD_RE, alias).search(tail[:1200]))


def _has_safe_residual_handling(tail: str, alias: str) -> bool:
    window = tail[:1300]
    if _has_reject_or_bound_guard(window, alias):
        return True
    for line in window.splitlines()[:22]:
        if re.search(r"\b" + re.escape(alias) + r"\b", line) and _SAFE_LINE_RE.search(line):
            return True
    return False


def _sink_reason(tail: str, alias: str) -> str | None:
    patterns = (
        (_FIRST_INDEX_WRITE_RE, "residual is credited to index zero or a first-participant path"),
        (_LAST_INDEX_WRITE_RE, "residual is credited to the last participant path"),
        (_ATTACKER_CALL_RE, "residual is passed to an attacker-controlled payout path"),
        (_MODULE_STATE_WRITE_RE, "residual is written to module, protocol, treasury, collector, or dust state"),
        (_MODULE_CALL_RE, "residual is passed to a module, protocol, collector, or dust handler"),
    )
    for pattern, reason in patterns:
        match = _compile_alias(pattern, alias).search(tail[:1700])
        if match is None:
            continue
        if _SAFE_LINE_RE.search(match.group(0)):
            continue
        return reason
    return None


def _rounding_residual_reason(body_text: str) -> str | None:
    for match in _ASSIGN_RE.finditer(body_text):
        alias = match.group("alias")
        expr = " ".join(match.group("expr").split())
        prefix = body_text[: match.start()]
        if not _creates_residual(alias, expr, prefix):
            continue

        tail = body_text[match.end():]
        if _has_safe_residual_handling(tail, alias):
            continue

        sink = _sink_reason(tail, alias)
        if sink is None:
            continue

        return (
            f"{alias} is derived from truncating residual math `{expr}` and "
            f"{sink}"
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
        fn_text = snippet_of(fn, source, max_len=220)
        if not (_VALUE_CONTEXT_RE.search(name) or _VALUE_CONTEXT_RE.search(body_nc)):
            continue

        reason = _rounding_residual_reason(body_nc)
        if reason is None:
            continue

        line, col = line_col(fn)
        hits.append(
            {
                "severity": "medium",
                "line": line,
                "col": col,
                "snippet": fn_text,
                "message": (
                    f"`{name}` assigns truncation residual value on an "
                    f"attacker-favorable side: {reason}. Reject non-exact "
                    f"division, carry residuals forward, refund the payer, "
                    f"or bound dust before crediting any participant or module "
                    f"account. (class: rounding-direction-attack; posture: "
                    f"NOT_SUBMIT_READY)"
                ),
            }
        )
    return hits
