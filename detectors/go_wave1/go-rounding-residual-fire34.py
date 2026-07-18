"""
go-rounding-residual-fire34.py

Fire34 Go lift for residual ownership in rounding-direction-attack cases.

Detects value math that computes a truncation remainder, residual, dust, or
leftover via integer division, sdk.Int-style truncation, or legacy decimal
conversion, then assigns that residual to an attacker, module account, protocol
dust bucket, or first participant instead of rejecting, carrying, or explicitly
bounding it.

Rule 37 provenance:
- verification_tier: tier-3-synthetic-taxonomy-anchored
- context_pack_id: auditooor.vault_context_pack.v1:resume:bfadc3c938400bc6
- context_pack_hash: bfadc3c938400bc6618f7f3ae8d500bbc8e5dce19f7f4e6c043195ffc6742129
- source ref: reports/detector_lift_fire33_20260605/post_priorities_go.md
- source ref: detectors/go_wave1/go-rounding-direction-fee-fire32.py
- source ref: detectors/go_wave1/go-rounding-fee-direction-fire33.py
- source ref: reference/patterns.dsl/r94-loop-royalty-distribution-rounding-dust-siphon.yaml
- source ref: reference/patterns.dsl/ec-fee-rounding-truncates-to-zero.yaml
- attack_class: rounding-direction-attack

Detector hits are source-review candidates only. R40 and R80 proof still
require a real in-scope PoC before any finding can cite the result.
"""

from __future__ import annotations

import re


DETECTOR_ID = "go_wave1.go-rounding-residual-fire34"

_VALUE_CONTEXT_RE = re.compile(
    r"(fee|fees|share|shares|reward|rewards|royalt|payout|claim|"
    r"commission|rebate|refund|distribution|distribute|split|participant|"
    r"receiver|recipient|account|attacker|module|treasury|protocol|dust|"
    r"remainder|residual|leftover|surplus|decimal|sdk\.Int|LegacyDec)",
    re.IGNORECASE,
)

_RESIDUAL_ALIAS_RE = re.compile(
    r"(remainder|residual|dust|leftover|surplus|excess|fractional|rounding)",
    re.IGNORECASE,
)

_ASSIGN_RE = re.compile(
    r"\b(?P<alias>[A-Za-z_]\w*)\s*(?::=|=)\s*(?P<expr>[^\n;{}]+)"
)

_TRUNCATING_EXPR_RE = re.compile(
    r"%|"
    r"\.\s*(?:Mod|Rem|Quo|QuoRaw|Div|DivRaw|TruncateInt|TruncateDec|ToInt|ToUint)\s*\(|"
    r"\b(?:LegacyDec|NewLegacyDec|MustNewDec|NewDec|sdk\.NewDec|sdk\.LegacyDec)\b|"
    r"\bSub\s*\([^;\n]*(?:Mul|Quo|Div|Truncate)|"
    r"-\s*[^;\n]*(?:\*|\.\s*(?:Mul|MulRaw)\s*\()",
    re.IGNORECASE,
)

_DIVISION_CONTEXT_RE = re.compile(
    r"(?:/|\.\s*(?:Quo|QuoRaw|Div|DivRaw)\s*\(|uint64\s*\(\s*len\s*\(|int64\s*\(\s*len\s*\()",
    re.IGNORECASE,
)

_COMMENT_RE = re.compile(r"//[^\n\r]*|/\*.*?\*/", re.DOTALL)
_STRING_RE = re.compile(r'`[^`]*`|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'' )

_RETURN_OR_PANIC_RE = re.compile(r"\b(return|panic)\b")

_REJECT_OR_BOUND_GUARD_RE = re.compile(
    r"if\s+(?=[^{}]{0,360}\b{alias}\b)"
    r"(?=[^{}]{0,360}(?:!=\s*0|>\s*0|<\s*0|IsZero|Sign\s*\(|"
    r"GT\s*\(|LT\s*\(|maxDust|MaxDust|bound|Bound|exact|Exact|"
    r"remainder|Remainder|dust|Dust))"
    r"[^{}]{0,360}\{[^{}]{0,260}\b(?:return|panic)\b",
    re.IGNORECASE | re.DOTALL,
)

_SAFE_CARRY_RE = re.compile(
    r"(carry|carryForward|rollover|accumulat|pending|unallocated|"
    r"remainderPool|residualPool|roundingBuffer|nextEpoch|nextPeriod|"
    r"distributeToLast|lastRecipient|lastParticipant|metric|metrics|"
    r"debug|telemetry|logger|trace|stat|stats|preview)",
    re.IGNORECASE,
)

_LAST_PARTICIPANT_RE = re.compile(
    r"\[[^\n;\]]*len\s*\([^\n;\]]+\)\s*-\s*1[^\n;\]]*\]"
    r"\s*(?:\+=|=)\s*[^;\n]*\b{alias}\b",
    re.IGNORECASE,
)

_FIRST_INDEX_WRITE_RE = re.compile(
    r"\[[^\n;]{0,90}(?:\[\s*0\s*\]|\b0\b|first[A-Za-z_]\w*)[^\n;]{0,60}\]"
    r"\s*(?:\+=|=)\s*[^;\n]*\b{alias}\b",
    re.IGNORECASE,
)

_ATTACKER_OR_FIRST_CALL_RE = re.compile(
    r"\b[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*\s*\("
    r"(?=[^;\n]{0,420}\b{alias}\b)"
    r"(?=[^;\n]{0,420}(?:attacker|first[A-Za-z_]\w*|sender|payer|"
    r"msg\.Sender\s*\(\)|participants\s*\[\s*0\s*\]|receivers\s*\[\s*0\s*\]|"
    r"recipients\s*\[\s*0\s*\]|accounts\s*\[\s*0\s*\]))"
    r"[^;\n]{0,420}\)",
    re.IGNORECASE | re.DOTALL,
)

_MODULE_STATE_WRITE_RE = re.compile(
    r"\b(?:[A-Za-z_]\w*\.)*"
    r"(?:[A-Za-z_]\w*)?(?:Module|Protocol|Treasury|FeeCollector|"
    r"Collector|Dust|Remainder|Residual|Surplus)[A-Za-z0-9_]*"
    r"(?:\[[^\]\n]+\])?\s*(?:\+=|=)\s*[^;\n{}]*\b{alias}\b",
    re.IGNORECASE,
)

_MODULE_CALL_RE = re.compile(
    r"\b[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*"
    r"(?:Module|Treasury|Protocol|Collector|Fee|Dust|Remainder|Residual)"
    r"[A-Za-z_]\w*\s*\((?=[^;\n]{0,420}\b{alias}\b)[^;\n]{0,420}\)",
    re.IGNORECASE | re.DOTALL,
)


def _blank(match: re.Match[str]) -> str:
    return "".join("\n" if ch == "\n" else " " for ch in match.group(0))


def _strip_comments_and_strings(src: str) -> str:
    src = _COMMENT_RE.sub(_blank, src)
    return _STRING_RE.sub(_blank, src)


def _compile_alias(pattern: re.Pattern[str], alias: str) -> re.Pattern[str]:
    return re.compile(pattern.pattern.replace("{alias}", re.escape(alias)), pattern.flags)


def _creates_residual(alias: str, expr: str, prefix: str) -> bool:
    if not _RESIDUAL_ALIAS_RE.search(alias):
        return False
    if _TRUNCATING_EXPR_RE.search(expr):
        return True
    window = prefix[-500:] + "\n" + expr
    return bool(_DIVISION_CONTEXT_RE.search(window) and re.search(r"\b(len|share|split|participant|receiver|recipient)\b", window, re.IGNORECASE))


def _has_reject_or_bound_guard(tail: str, alias: str) -> bool:
    return bool(_compile_alias(_REJECT_OR_BOUND_GUARD_RE, alias).search(tail[:1100]))


def _has_safe_residual_handling(tail: str, alias: str) -> bool:
    window = tail[:1300]
    last_participant = _compile_alias(_LAST_PARTICIPANT_RE, alias).search(window)
    if last_participant is not None:
        return True
    for line in window.splitlines()[:18]:
        if re.search(r"\b" + re.escape(alias) + r"\b", line) and _SAFE_CARRY_RE.search(line):
            return True
    return False


def _sink_reason(tail: str, alias: str) -> str | None:
    patterns = (
        (_FIRST_INDEX_WRITE_RE, "residual is credited to index zero or the first participant"),
        (_ATTACKER_OR_FIRST_CALL_RE, "residual is passed to an attacker, sender, or first-participant payout path"),
        (_MODULE_STATE_WRITE_RE, "residual is written to module, protocol, treasury, or dust state"),
        (_MODULE_CALL_RE, "residual is passed to a module, protocol, collector, or dust handler"),
    )
    for pattern, reason in patterns:
        match = _compile_alias(pattern, alias).search(tail[:1600])
        if match is None:
            continue
        if _SAFE_CARRY_RE.search(match.group(0)):
            continue
        return reason
    return None


def _rounding_residual_reason(body_text: str) -> str | None:
    for match in _ASSIGN_RE.finditer(body_text):
        alias = match.group("alias")
        expr = match.group("expr").strip()
        prefix = body_text[: match.start()]
        if not _creates_residual(alias, expr, prefix):
            continue

        tail = body_text[match.end():]
        if _has_reject_or_bound_guard(tail, alias):
            continue
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
        if not _VALUE_CONTEXT_RE.search(fn_text):
            continue

        body_text = _strip_comments_and_strings(engine.text(body))
        reason = _rounding_residual_reason(body_text)
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
                    f"`{name}` assigns truncation residual value on an "
                    f"attacker-favorable side: {reason}. Reject non-exact "
                    f"division when exactness is required, carry residuals "
                    f"forward in an explicit accumulator, allocate them to a "
                    f"documented last-recipient path, or bound dust before "
                    f"crediting it. (class: rounding-direction-attack; "
                    f"posture: NOT_SUBMIT_READY)"
                ),
            }
        )
    return hits
