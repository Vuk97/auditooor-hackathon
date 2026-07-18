"""
go-rounding-fee-direction-fire33.py

Fire33 Go lift for rounding-direction-attack recall.

Detects fee, share, liquidation, reward, debt, and collateral math where
integer rounding is applied on the attacker-favorable side of a value
movement or accounting write. The covered shapes are intentionally compact:

- floor division or divide-before-multiply feeding protocol-receive,
  share/accounting, liquidation, collateral, debt, or solvency paths,
- ceil-style helpers feeding user payouts, refunds, rewards, withdrawals, or
  debt reductions,
- lossy truncation helpers feeding the same value-moving sinks.

Rule 37 provenance:
- verification_tier: tier-3-synthetic-taxonomy-anchored
- context_pack_id: auditooor.vault_context_pack.v1:resume:57361adac683c0c7
- context_pack_hash: 57361adac683c0c7f40a2f345b94c4172fe41a09373a05ca2cf8fae67d1b1dab
- source ref: reports/detector_lift_fire32_20260605/post_priorities_go.md
- source ref: detectors/go_wave1/go-rounding-direction-fee-fire32.py
- source ref: detectors/go_wave1/test_fixtures/go-rounding-direction-fee-fire32_positive.go
- source ref: reference/patterns.dsl/fund-loss-via-arithmetic-conversion-output-zero.yaml
- attack_class: rounding-direction-attack

Detector hits are source-review candidates only. R40 and R80 proof still
require a real in-scope PoC before any finding can cite the result.
"""

from __future__ import annotations

import re


DETECTOR_ID = "go_wave1.go-rounding-fee-direction-fire33"

_VALUE_MATH_RE = re.compile(
    r"(fee|fees|share|shares|asset|assets|reward|rewards|rebate|refund|"
    r"liquidat|penalty|haircut|discount|debt|borrow|repay|repayment|"
    r"collateral|margin|solv|health|fund|reserve|payout|claim|withdraw|"
    r"credit|owed|required|seize|seized)",
    re.IGNORECASE,
)

_USER_CONTEXT_RE = re.compile(
    r"(user|account|owner|sender|payer|borrower|trader|liquidator|"
    r"withdrawer|recipient|delegator|operator|position|pos|msg\.[A-Za-z_]\w*)",
    re.IGNORECASE,
)

_ASSIGN_RE = re.compile(
    r"\b(?P<alias>[A-Za-z_]\w*)\s*(?::=|=)\s*(?P<expr>[^\n;{}]+)"
)

_DIVISION_RE = re.compile(r"/|\.\s*(?:Quo|QuoRaw|DivRaw|Div)\s*\(")

_DIVIDE_BEFORE_MUL_RE = re.compile(
    r"(?:/|\.\s*(?:Quo|QuoRaw|DivRaw|Div)\s*\()[^\n;{}]{0,120}"
    r"(?:\*|\.\s*(?:Mul|MulRaw)\s*\()",
    re.IGNORECASE,
)

_CEIL_RE = re.compile(
    r"(ceil|Ceil|roundUp|RoundUp|mulDivUp|MulDivUp|QuoRoundUp|DivRoundUp|"
    r"CeilDiv|ceilDiv|RoundUpDivision|roundUpDivision)",
)

_FLOOR_OR_TRUNC_RE = re.compile(
    r"(floor|Floor|roundDown|RoundDown|mulDivDown|MulDivDown|QuoRoundDown|"
    r"DivRoundDown|FloorDiv|floorDiv|Truncate|TruncateInt|TruncateDec|"
    r"ToInt|ToUint)",
)

_SAFE_PRECISION_RE = re.compile(
    r"(mulDiv|MulDiv|FullMath|FixedPointMathLib|LegacyDec|DecCoin|NewDec|"
    r"MustNewDec|BigRat|big\.Rat|math\.Ceil|decimal)",
)

_CEIL_FORMULA_RE = re.compile(
    r"\+\s*(?:[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?)\s*-\s*1\s*\)"
)

_COMMENT_RE = re.compile(r"//[^\n\r]*|/\*.*?\*/", re.DOTALL)
_STRING_RE = re.compile(r'`[^`]*`|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')

_SAFE_SINK_RE = re.compile(
    r"(debug|metric|metrics|log|logger|telemetry|stat|stats|trace|test|preview)",
    re.IGNORECASE,
)

_TRANSFER_IN_RE = re.compile(
    r"\b(?:SendCoinsFromAccountToModule|TransferFrom|Collect|Charge|Pull|"
    r"PullFrom|Debit|DebitAccount|Repay|ApplyRepayment|PayFee|SettleFee|"
    r"Burn)\w*\s*\([^;\n]*\b{alias}\b",
    re.IGNORECASE | re.DOTALL,
)

_TRANSFER_OUT_RE = re.compile(
    r"\b(?:SendCoinsFromModuleToAccount|SendCoinsFromModuleToAddress|"
    r"TransferToAccount|TransferTo|Credit|CreditAccount|Refund|PayReward|"
    r"Payout|Withdraw|Claim|SendCoins)\w*\s*\([^;\n]*\b{alias}\b",
    re.IGNORECASE | re.DOTALL,
)

_VALUE_FIELD = (
    r"(?:Fee|Fees|Revenue|Treasury|Reserve|Reserves|Insurance|Fund|Funds|"
    r"Share|Shares|Asset|Assets|Reward|Rewards|RewardDebt|Debt|Debts|"
    r"Liability|Liabilities|Penalty|Collateral|Margin|Health|Credit|Credits)"
)

_STATE_WRITE_RE = re.compile(
    r"\b(?:[A-Za-z_]\w*(?:\[[^\]\n]+\])?\.)*"
    r"(?P<field>(?:[A-Za-z_]\w*)?" + _VALUE_FIELD + r"[A-Za-z0-9_]*)"
    r"(?:\[[^\]\n]+\])?\s*(?P<op>\+=|-=|=)\s*[^;\n{}]*\b{alias}\b",
    re.IGNORECASE,
)

_MAP_STATE_WRITE_RE = re.compile(
    r"\b(?:[A-Za-z_]\w*\.)?"
    r"(?P<field>(?:[A-Za-z_]\w*)?" + _VALUE_FIELD + r"[A-Za-z0-9_]*)"
    r"\s*\[[^\]\n]+\]\s*"
    r"(?P<op>\+=|-=|=)\s*[^;\n{}]*\b{alias}\b",
    re.IGNORECASE,
)

_STATE_SETTER_RE = re.compile(
    r"\b(?:Set|Update|Record|Accrue|Credit|Debit|Book|Apply|Write|Add|Sub)"
    r"[A-Za-z_]\w*(?:Fee|Share|Reward|Debt|Liability|Penalty|Collateral|"
    r"Margin|Health|Solvency|Credit|Asset)[A-Za-z_]\w*\s*"
    r"\([^;\n{}]*\b{alias}\b",
    re.IGNORECASE | re.DOTALL,
)

_SOLVENCY_CHECK_RE = re.compile(
    r"if\s+(?=[^{}]{0,380}\b{alias}\b)"
    r"(?=[^{}]{0,380}(?:solv|health|margin|collateral|debt|required|limit|threshold))"
    r"[^{}]{0,380}\{[^{}]{0,280}\b(?:return\s+(?:nil|true)|Withdraw|"
    r"Borrow|Transfer|SendCoins|Settle)",
    re.IGNORECASE | re.DOTALL,
)

_ALIAS_GUARD_RE = re.compile(
    r"if\s+[^{}]{0,280}\b{alias}\b[^{}]{0,280}"
    r"(?:==\s*0|<=\s*0|<\s*(?:min|Min|required|Required|1)|"
    r"remainder|Remainder)[^{}]{0,280}\{[^{}]{0,240}\b(?:return|panic)\b",
    re.IGNORECASE | re.DOTALL,
)

_REMAINDER_REJECT_RE = re.compile(
    r"if\s+[^{}]{0,360}(?:%|Mod\s*\()[^{}]{0,360}"
    r"\{[^{}]{0,260}\b(?:return|panic)\b",
    re.IGNORECASE | re.DOTALL,
)


def _blank(match: re.Match[str]) -> str:
    return "".join("\n" if ch == "\n" else " " for ch in match.group(0))


def _strip_comments_and_strings(src: str) -> str:
    src = _COMMENT_RE.sub(_blank, src)
    return _STRING_RE.sub(_blank, src)


def _compile_alias(pattern: re.Pattern[str], alias: str) -> re.Pattern[str]:
    return re.compile(pattern.pattern.replace("{alias}", re.escape(alias)), pattern.flags)


def _expr_kind(expr: str) -> tuple[str, str] | None:
    if _SAFE_PRECISION_RE.search(expr):
        return None
    if _CEIL_RE.search(expr):
        return ("ceil", "ceil-style helper")
    if _CEIL_FORMULA_RE.search(expr):
        return ("ceil", "manual ceil division formula")
    if _FLOOR_OR_TRUNC_RE.search(expr):
        return ("floor", "floor or truncation helper")
    if _DIVIDE_BEFORE_MUL_RE.search(expr):
        return ("floor", "division before multiplication")
    if _DIVISION_RE.search(expr):
        return ("floor", "integer floor division")
    return None


def _value_terms(expr: str) -> set[str]:
    terms: set[str] = set()
    for term in re.findall(r"\b[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?\b", expr):
        if _VALUE_MATH_RE.search(term):
            terms.add(term)
    return terms


def _has_alias_guard(tail: str, alias: str) -> bool:
    return bool(_compile_alias(_ALIAS_GUARD_RE, alias).search(tail[:1000]))


def _has_remainder_reject(prefix: str, tail: str, expr: str) -> bool:
    window = prefix[-1000:] + "\n" + tail[:1000]
    if not _REMAINDER_REJECT_RE.search(window):
        return False
    terms = _value_terms(expr)
    if not terms:
        return bool(_VALUE_MATH_RE.search(window))
    return any(re.search(r"\b" + re.escape(term) + r"\b", window) for term in terms)


def _transfer_in_sink(tail: str, alias: str) -> str | None:
    match = _compile_alias(_TRANSFER_IN_RE, alias).search(tail[:1400])
    if match is None or _SAFE_SINK_RE.search(match.group(0)):
        return None
    return "rounded amount is pulled, charged, repaid, burned, or otherwise received by the protocol"


def _transfer_out_sink(tail: str, alias: str) -> str | None:
    match = _compile_alias(_TRANSFER_OUT_RE, alias).search(tail[:1400])
    if match is None or _SAFE_SINK_RE.search(match.group(0)):
        return None
    return "rounded amount leaves protocol custody as a payout, refund, reward, claim, or withdrawal"


def _state_sink(tail: str, alias: str) -> tuple[str, str, str] | None:
    for pattern in (_STATE_WRITE_RE, _MAP_STATE_WRITE_RE):
        match = _compile_alias(pattern, alias).search(tail[:1400])
        if match is None:
            continue
        if _SAFE_SINK_RE.search(match.group(0)):
            continue
        field = match.group("field")
        op = match.group("op")
        return (field, op, f"rounded amount is written to {field} with `{op}`")

    setter = _compile_alias(_STATE_SETTER_RE, alias).search(tail[:1400])
    if setter is not None and not _SAFE_SINK_RE.search(setter.group(0)):
        return (
            "setter",
            "call",
            "rounded amount is passed to a fee, share, reward, debt, collateral, or margin setter",
        )
    return None


def _solvency_sink(tail: str, alias: str) -> str | None:
    match = _compile_alias(_SOLVENCY_CHECK_RE, alias).search(tail[:1400])
    if match is None or _SAFE_SINK_RE.search(match.group(0)):
        return None
    return "rounded amount influences a solvency, health, margin, collateral, or debt check"


def _sink_reason(kind: str, tail: str, alias: str) -> str | None:
    transfer_in = _transfer_in_sink(tail, alias)
    transfer_out = _transfer_out_sink(tail, alias)
    state = _state_sink(tail, alias)
    solvency = _solvency_sink(tail, alias)

    if kind == "ceil":
        if transfer_out is not None:
            return transfer_out
        if state is not None:
            field, _op, reason = state
            if re.search(r"(debt|liabilit|collateral|reward|credit|asset|share)", field, re.IGNORECASE):
                return reason
        return None

    if transfer_in is not None:
        return transfer_in
    if state is not None:
        field, op, reason = state
        if op == "-=" and re.search(r"(debt|liabilit)", field, re.IGNORECASE):
            return None
        return reason
    if solvency is not None:
        return solvency
    return None


def _rounding_reason(body_text: str) -> str | None:
    for match in _ASSIGN_RE.finditer(body_text):
        alias = match.group("alias")
        expr = match.group("expr").strip()
        expr_info = _expr_kind(expr)
        if expr_info is None:
            continue

        kind, rounding_source = expr_info
        if not (_VALUE_MATH_RE.search(alias) or _VALUE_MATH_RE.search(expr)):
            continue
        if not (_USER_CONTEXT_RE.search(body_text) or _USER_CONTEXT_RE.search(expr)):
            continue

        prefix = body_text[: match.start()]
        tail = body_text[match.end():]
        if _has_alias_guard(tail, alias):
            continue
        if _has_remainder_reject(prefix, tail, expr):
            continue

        sink = _sink_reason(kind, tail, alias)
        if sink is None:
            continue

        return (
            f"{alias} is computed with {rounding_source} from `{expr}` and "
            f"{sink}"
        )
    return None


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
        if not _VALUE_MATH_RE.search(fn_text):
            continue

        body_text = _strip_comments_and_strings(engine.text(body))
        reason = _rounding_reason(body_text)
        if reason is None:
            continue

        hits.append(
            {
                "detector_id": DETECTOR_ID,
                "severity": "medium",
                "line": engine.line(fn),
                "col": engine.col(fn),
                "snippet": fn_text.splitlines()[0][:160],
                "message": (
                    f"`{name}` applies rounding on the attacker-favorable "
                    f"side of fee, share, liquidation, reward, debt, or "
                    f"collateral math: {reason}. Use full precision math, "
                    f"put ceil or floor on the side that protects protocol "
                    f"and victim value, and reject zero, below-minimum, or "
                    f"non-exact results where the transfer requires exactness. "
                    f"(class: rounding-direction-attack; posture: "
                    f"NOT_SUBMIT_READY)"
                ),
            }
        )
    return hits
