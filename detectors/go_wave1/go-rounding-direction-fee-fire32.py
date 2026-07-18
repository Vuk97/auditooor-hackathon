"""
go-rounding-direction-fee-fire32.py

Detects Go fee, share, reward, liquidation, and debt calculations that use
flooring integer division before a user-favorable transfer, accounting write,
or solvency check.

Provenance:
- context_pack_id: auditooor.vault_context_pack.v1:resume:0f026ac1001e9e9b
- context_pack_hash: 0f026ac1001e9e9b588d5fafc49e8d99e6f347f91a2aaa782107be04d27011d8
- source ref: reports/detector_lift_fire31_20260605/post_priorities_go.md
- source ref: detectors/wave17/value_math_transfer_rounding_fire31.py
- source ref: reference/patterns.dsl.r73_perps/perp-rounding-down-favors-user-on-fund-pull.yaml
- source ref: reference/patterns.dsl.r73_c4_seeds/basis-point-truncation-favoring-treasury-vs-operator.yaml
- attack_class: rounding-direction-attack

Hits are candidate evidence only. NOT_SUBMIT_READY.
"""

from __future__ import annotations

import re


DETECTOR_ID = "go_wave1.go-rounding-direction-fee-fire32"

_VALUE_MATH_RE = re.compile(
    r"(fee|fees|share|shares|reward|rewards|liquidat|penalty|haircut|"
    r"debt|borrow|repay|repayment|collateral|margin|solv|health|fund|"
    r"pull|required|owed|payout|claim)",
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

_DIVISION_RE = re.compile(r"/|\.\s*(?:Quo|QuoRaw|DivRaw)\s*\(")

_ROUND_UP_RE = re.compile(
    r"(ceil|Ceil|roundUp|RoundUp|mulDivUp|MulDivUp|QuoRoundUp|DivRoundUp|"
    r"CeilDiv|ceilDiv|RoundUpDivision|roundUpDivision)",
)

_CEIL_FORMULA_RE = re.compile(
    r"\+\s*(?:[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?)\s*-\s*1\s*\)",
)

_DECIMAL_MATH_RE = re.compile(
    r"(LegacyDec|DecCoin|NewDec|MustNewDec|BigRat|big\.Rat|math\.Ceil)",
)

_REJECT_OR_MIN_GUARD_RE = re.compile(
    r"if\s+[^{}]{0,260}\b{alias}\b[^{}]{0,260}"
    r"(?:==\s*0|<\s*(?:min|Min|required|Required|1)|<=\s*0|remainder|Remainder)"
    r"[^{}]{0,260}\{[^{}]{0,220}\b(?:return|panic)\b",
    re.DOTALL,
)

_REMAINDER_REJECT_RE = re.compile(
    r"if\s+[^{}]{0,320}(?:%|Mod\s*\()[^{}]{0,320}"
    r"\{[^{}]{0,240}\b(?:return|panic)\b",
    re.DOTALL,
)

_TRANSFER_OR_PULL_RE = re.compile(
    r"\b(?:SendCoinsFromAccountToModule|SendCoins|TransferFrom|Transfer|"
    r"Debit|DebitAccount|Charge|Collect|Pull|PullFrom|Withdraw|Repay|"
    r"ApplyRepayment|PayFee|SettleFee|Burn)\w*\s*\([^;\n{}]*\b{alias}\b",
    re.IGNORECASE | re.DOTALL,
)

_STATE_WRITE_RE = re.compile(
    r"\b(?:[A-Za-z_]\w*(?:\[[^\]\n]+\])?\.)*"
    r"(?:[A-Za-z_]\w*)?(?:Fee|Fees|Revenue|Treasury|Reserve|Reserves|Insurance|"
    r"Fund|Funds|Share|Shares|RewardDebt|RewardsDebt|Debt|Debts|Liability|"
    r"Liabilities|Penalty|Collateral|Margin|Health)[A-Za-z0-9_]*"
    r"(?:\[[^\]\n]+\])?\s*(?:\+=|-=|=)\s*[^;\n{}]*\b{alias}\b",
    re.IGNORECASE,
)

_STATE_SETTER_RE = re.compile(
    r"\b(?:Set|Update|Record|Accrue|Credit|Debit|Book|Apply|Write)"
    r"[A-Za-z_]\w*(?:Fee|Share|Reward|Debt|Liability|Penalty|Collateral|"
    r"Margin|Health|Solvency)[A-Za-z_]\w*\s*\([^;\n{}]*\b{alias}\b",
    re.IGNORECASE | re.DOTALL,
)

_SOLVENCY_CHECK_RE = re.compile(
    r"if\s+(?=[^{}]{0,360}\b{alias}\b)"
    r"(?=[^{}]{0,360}(?:solv|health|margin|collateral|debt|required|limit|threshold))"
    r"[^{}]{0,360}\{[^{}]{0,260}\b(?:return\s+(?:nil|true)|Withdraw|Borrow|"
    r"Transfer|SendCoins|Settle)",
    re.IGNORECASE | re.DOTALL,
)

_SAFE_SINK_RE = re.compile(
    r"(debug|metric|metrics|log|logger|telemetry|stat|stats|trace|test)",
    re.IGNORECASE,
)

_COMMENT_RE = re.compile(r"//[^\n\r]*|/\*.*?\*/", re.DOTALL)
_STRING_RE = re.compile(r'`[^`]*`|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'' )


def _blank(match: re.Match[str]) -> str:
    return "".join("\n" if ch == "\n" else " " for ch in match.group(0))


def _strip_comments_and_strings(src: str) -> str:
    src = _COMMENT_RE.sub(_blank, src)
    return _STRING_RE.sub(_blank, src)


def _is_rounding_down_expr(expr: str) -> bool:
    if not _DIVISION_RE.search(expr):
        return False
    if _ROUND_UP_RE.search(expr) or _CEIL_FORMULA_RE.search(expr):
        return False
    if _DECIMAL_MATH_RE.search(expr):
        return False
    return True


def _has_alias_guard(tail: str, alias: str) -> bool:
    guarded = _REJECT_OR_MIN_GUARD_RE.pattern.replace("{alias}", re.escape(alias))
    return bool(re.search(guarded, tail[:900], re.IGNORECASE | re.DOTALL))


def _has_remainder_reject(prefix: str, tail: str, expr: str) -> bool:
    window = prefix[-900:] + "\n" + tail[:900]
    if not _REMAINDER_REJECT_RE.search(window):
        return False
    expr_terms = set(re.findall(r"\b[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?\b", expr))
    for term in expr_terms:
        if term and _VALUE_MATH_RE.search(term) and re.search(r"\b" + re.escape(term) + r"\b", window):
            return True
    return False


def _sink_reason(tail: str, alias: str) -> str | None:
    patterns = (
        (_TRANSFER_OR_PULL_RE, "rounded amount feeds a user payment, pull, repayment, or burn path"),
        (_STATE_WRITE_RE, "rounded amount is written to fee, share, reward, liquidation, or debt state"),
        (_STATE_SETTER_RE, "rounded amount is passed to an accounting setter"),
        (_SOLVENCY_CHECK_RE, "rounded amount influences a solvency or margin check"),
    )
    for pattern, reason in patterns:
        compiled = re.compile(pattern.pattern.replace("{alias}", re.escape(alias)), pattern.flags)
        match = compiled.search(tail[:1300])
        if match is None:
            continue
        if _SAFE_SINK_RE.search(match.group(0)):
            continue
        return reason
    return None


def _rounding_reason(body_text: str) -> str | None:
    for match in _ASSIGN_RE.finditer(body_text):
        alias = match.group("alias")
        expr = match.group("expr").strip()
        if not _is_rounding_down_expr(expr):
            continue
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

        sink_reason = _sink_reason(tail, alias)
        if sink_reason is None:
            continue

        return (
            f"{alias} is computed with floor division from `{expr}` and "
            f"{sink_reason}"
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
                "severity": "medium",
                "line": engine.line(fn),
                "col": engine.col(fn),
                "snippet": fn_text.splitlines()[0][:160],
                "message": (
                    f"`{name}` has user-favorable rounding direction in value "
                    f"math: {reason}. Use explicit ceil division for amounts "
                    f"the protocol must receive, reject non-zero remainders "
                    f"where exactness is required, and guard zero or "
                    f"below-minimum rounded outputs. "
                    f"(class: rounding-direction-attack)"
                ),
            }
        )
    return hits
