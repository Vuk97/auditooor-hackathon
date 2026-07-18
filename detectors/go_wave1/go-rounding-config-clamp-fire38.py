"""
go-rounding-config-clamp-fire38.py

Fire38 Go lift for rounding-direction-attack recall.

Detects config clamp and fee math where unsigned conversion, subtraction,
multiplication, or integer division happens before min, max, clamp, or
range enforcement. The dangerous shape is validating or clamping the rounded
or overflowed intermediate instead of the original wide inputs.

Rule 37 provenance:
- verification_tier: tier-3-synthetic-taxonomy-anchored
- context_pack_id: auditooor.vault_context_pack.v1:resume:44caec64336606d0
- context_pack_hash: 44caec64336606d05c23f8b0680c7d3eb9c383aa6e9009bbeb2361b776b793c2
- source ref: reports/detector_lift_fire37_20260605/post_priorities_go.md
- source ref: detectors/go_wave1/go-integer-overflow-config-clamp-fire31.py
- source ref: reference/patterns.dsl/ec-fee-rounding-truncates-to-zero.yaml
- attack_class: rounding-direction-attack

Detector hits are source-review candidates only. R40 and R80 proof still
require a real in-scope PoC before any finding can cite the result.
"""

from __future__ import annotations

import re


DETECTOR_ID = "go_wave1.go-rounding-config-clamp-fire38"

_CONFIG_CONTEXT_RE = re.compile(
    r"(cfg|config|params|settings|fee|fees|bps|rate|ratio|factor|"
    r"threshold|limit|cap|max|min|clamp|scale|multiplier|price|risk|"
    r"margin|collateral|notional|amount|rebate|discount)",
    re.IGNORECASE,
)

_CONFIG_EXPR_RE = re.compile(
    r"(cfg|config|params|settings|fee|fees|bps|rate|ratio|factor|"
    r"threshold|limit|cap|max|min|scale|multiplier|price|risk|"
    r"margin|collateral|notional|amount|rebate|discount)",
    re.IGNORECASE,
)

_BOUND_CONTEXT_RE = re.compile(
    r"(max|min|limit|cap|threshold|clamp|ceil|floor|round|exact|"
    r"overflow|underflow|MaxUint|MaxInt)",
    re.IGNORECASE,
)

_ASSIGN_RE = re.compile(
    r"\b(?P<alias>[A-Za-z_]\w*)\s*(?::=|=)\s*(?P<expr>[^\n;{}]+)"
)

_CAST_RE = re.compile(r"\bu?int(?:8|16|32|64)?\s*\(")
_NARROW_CAST_RE = re.compile(r"\bu?int(?:8|16|32)\s*\(")
_MUL_RE = re.compile(r"\*|\.\s*(?:Mul|MulRaw)\s*\(", re.IGNORECASE)
_DIV_RE = re.compile(r"/|\.\s*(?:Quo|QuoRaw|Div|DivRaw)\s*\(", re.IGNORECASE)
_SUB_RE = re.compile(r"-|\.\s*Sub\s*\(", re.IGNORECASE)

_SAFE_MATH_RE = re.compile(
    r"(SafeMul|CheckedMul|MulDiv|FullMath|bits\.Mul|big\.Int|big\.Rat|"
    r"LegacyDec|sdk\.Dec|NewDec|MustNewDec|math\.Ceil|ceilDiv|CeilDiv|"
    r"RoundUp|roundUp)",
    re.IGNORECASE,
)

_COMMENT_RE = re.compile(r"//[^\n\r]*|/\*.*?\*/", re.DOTALL)
_STRING_RE = re.compile(r'`[^`]*`|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')

_RETURN_OR_PANIC_RE = re.compile(r"\b(return|panic)\b")
_PRE_GUARD_RE = re.compile(
    r"if\s+(?P<cond>[^{}]{0,460})\{(?P<body>[^{}]{0,360})\}",
    re.DOTALL,
)

_GENERIC_PRE_GUARD_SIGNAL_RE = re.compile(
    r"(MaxUint|MaxInt|overflow|underflow|fits|safe|checked|exact|"
    r"remainder|non[- ]?exact|%|/|<|>)",
    re.IGNORECASE,
)

_POST_IF_RE = re.compile(
    r"if\s+(?P<cond>[^{}]{0,420})\{(?P<body>[^{}]{0,360})\}",
    re.DOTALL,
)

_MIN_MAX_CALL_RE = re.compile(
    r"\b(?:min|max|Min|Max|clamp|Clamp)[A-Za-z_]*\s*\(",
)


def _blank(match: re.Match[str]) -> str:
    return "".join("\n" if ch == "\n" else " " for ch in match.group(0))


def _strip_comments_and_strings(src: str) -> str:
    src = _COMMENT_RE.sub(_blank, src)
    return _STRING_RE.sub(_blank, src)


def _source_terms(expr: str) -> set[str]:
    terms = set(re.findall(r"\b[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?\b", expr))
    return {term for term in terms if not re.fullmatch(r"u?int(?:8|16|32|64)?", term)}


def _mentions_any(text: str, terms: set[str]) -> bool:
    return any(re.search(r"\b" + re.escape(term) + r"\b", text) for term in terms)


def _risk_reason(expr: str) -> str | None:
    if _SAFE_MATH_RE.search(expr):
        return None

    has_cast = _CAST_RE.search(expr) is not None
    has_narrow_cast = _NARROW_CAST_RE.search(expr) is not None
    has_mul = _MUL_RE.search(expr) is not None
    has_div = _DIV_RE.search(expr) is not None
    has_sub = _SUB_RE.search(expr) is not None

    if has_narrow_cast and (has_mul or has_div or has_sub):
        return "narrow uint conversion wraps an already lossy config expression"
    if has_narrow_cast:
        return "narrow uint conversion happens before range enforcement"
    if has_cast and (has_mul or has_div or has_sub):
        return "uint conversion wraps arithmetic before range enforcement"
    if has_mul and has_div:
        return "multiplication can overflow and integer division can round before clamp enforcement"
    if has_mul:
        return "multiplication can overflow before clamp enforcement"
    if has_sub:
        return "unsigned subtraction can underflow before clamp enforcement"
    if has_div:
        return "integer division can round before clamp enforcement"
    return None


def _has_pre_math_guard(prefix: str, terms: set[str]) -> bool:
    if not terms:
        return False
    for match in _PRE_GUARD_RE.finditer(prefix[-1800:]):
        block = match.group(0)
        if not _mentions_any(block, terms):
            continue
        if not _RETURN_OR_PANIC_RE.search(match.group("body")):
            continue
        if _GENERIC_PRE_GUARD_SIGNAL_RE.search(match.group("cond")):
            return True
    return False


def _has_post_bound_enforcement(tail: str, alias: str) -> str | None:
    alias_re = re.compile(r"\b" + re.escape(alias) + r"\b")
    window = tail[:1300]

    for match in _POST_IF_RE.finditer(window):
        cond = match.group("cond")
        body = match.group("body")
        block = match.group(0)
        if not alias_re.search(block):
            continue
        if not _BOUND_CONTEXT_RE.search(block):
            continue
        if re.search(r"(?:>|<|>=|<=|==|!=)", cond) and (
            _RETURN_OR_PANIC_RE.search(body)
            or re.search(r"\b" + re.escape(alias) + r"\b\s*=", body)
        ):
            return "post-math if statement validates or clamps the rounded intermediate"

    for line in window.splitlines()[:24]:
        if not alias_re.search(line):
            continue
        if not _MIN_MAX_CALL_RE.search(line):
            continue
        if re.search(r"(?::=|=|return)\s*", line):
            return "post-math min, max, or clamp helper uses the rounded intermediate"

    return None


def _config_clamp_reason(body_text: str) -> str | None:
    for match in _ASSIGN_RE.finditer(body_text):
        alias = match.group("alias")
        expr = match.group("expr").strip()
        if not (_CONFIG_EXPR_RE.search(expr) or _CONFIG_EXPR_RE.search(alias)):
            continue

        risk = _risk_reason(expr)
        if risk is None:
            continue

        terms = _source_terms(expr)
        prefix = body_text[: match.start()]
        if _has_pre_math_guard(prefix, terms):
            continue

        tail = body_text[match.end():]
        enforcement = _has_post_bound_enforcement(tail, alias)
        if enforcement is None:
            continue

        return f"{alias} is computed as `{expr}`; {risk}; {enforcement}"
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
        if not _CONFIG_CONTEXT_RE.search(fn_text):
            continue

        body_text = _strip_comments_and_strings(engine.text(body))
        reason = _config_clamp_reason(body_text)
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
                    f"`{name}` computes a config or fee clamp input with "
                    f"lossy integer math before enforcing min or max bounds: "
                    f"{reason}. Check overflow, underflow, and non-exact "
                    f"division on the original wide values before casting, "
                    f"rounding, or clamping the result. "
                    f"(class: rounding-direction-attack; posture: "
                    f"NOT_SUBMIT_READY)"
                ),
            }
        )
    return hits
