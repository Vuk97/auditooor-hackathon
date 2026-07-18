"""
rewards-failed-dispatch-payment-fire25

Solidity same-class recall detector for rewards-distribution-skew misses where
a relayer, keeper, or caller reward is credited after downstream dispatch
success is known to be false or is not enforced.

Confirmed sources:
- bridge-relayer-reward-paid-on-failed-dispatch
- rewards-distribution-failed-dispatch-stale-supply-fire23
- rewards-branch-asymmetry-fire24

Detector hits are candidate evidence only. They do not prove exploitability or
filing readiness without a real protocol path, impact proof, and negative
control.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "rewards-failed-dispatch-payment-fire25"
DETECTOR_SEVERITY_DEFAULT = "Medium"


@dataclass
class Finding:
    detector: str
    file: str
    line: int
    severity: str
    message: str
    function: Optional[str] = None


@dataclass
class FunctionSlice:
    name: str
    header: str
    body: str
    body_line: int


@dataclass
class DispatchSignal:
    flag: str
    end: int
    source: str


_FN_HEADER_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_PUBLIC_HEADER_RE = re.compile(r"\b(?:external|public)\b")
_TOKEN_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'|"
    r"//[^\n\r]*|"
    r"/\*.*?\*/",
    re.DOTALL,
)

_CONTEXT_RE = re.compile(
    r"\b(?:reward\w*|relayer\w*|keeper\w*|caller\w*|refund\w*|"
    r"bounty\w*|rebate\w*|dispatch\w*|deliver\w*|message\w*|"
    r"bridge\w*|relay\w*|handler\w*|execute\w*)\b",
    re.IGNORECASE,
)
_FAILURE_HINT_RE = re.compile(
    r"\b(?:fail\w*|revert\w*|unsuccessful|undelivered|notDelivered|"
    r"recordFailed|DispatchFailed|MessageFailed)\b",
    re.IGNORECASE,
)

_TRY_CATCH_FALSE_RE = re.compile(
    r"\btry\b[\s\S]{0,3600}?\bcatch\b(?:\s*\([^)]*\))?\s*\{"
    r"[\s\S]{0,1000}?\b(?P<flag>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*false\b",
    re.IGNORECASE,
)
_BOOL_CALL_RE = re.compile(
    r"\bbool\s+(?P<flag>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"[^;{}]{0,320}?\b(?:dispatch|deliver|execute|handle|relay|route|send)"
    r"[A-Za-z0-9_]*\s*\(",
    re.IGNORECASE | re.DOTALL,
)
_TUPLE_LOW_LEVEL_CALL_RE = re.compile(
    r"\(\s*bool\s+(?P<flag>[A-Za-z_][A-Za-z0-9_]*)\s*,[^)]*\)\s*=\s*"
    r"[^;{}]{0,360}?\.(?:call|delegatecall|staticcall)\s*(?:\{|\()",
    re.IGNORECASE | re.DOTALL,
)
_ASSIGN_CALL_RE = re.compile(
    r"\b(?P<flag>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"[^;{}]{0,320}?\b(?:dispatch|deliver|execute|handle|relay|route|send)"
    r"[A-Za-z0-9_]*\s*\(",
    re.IGNORECASE | re.DOTALL,
)

_ACTOR_RE = (
    r"(?:msg\.sender|relayer|_relayer|keeper|_keeper|caller|_caller|"
    r"executor|_executor|submitter|_submitter)"
)
_REWARD_CREDIT_RE = re.compile(
    rf"\b[A-Za-z_][A-Za-z0-9_]*(?:Reward|Rewards|Credit|Credits|Refund|"
    rf"Refunds|Bounty|Bounties|Rebate|Rebates)[A-Za-z0-9_]*\s*"
    rf"(?:\[[^\]]+\]\s*)*(?:\[\s*{_ACTOR_RE}\s*\]\s*)"
    rf"(?:=|\+=)\s*[^;]*(?:reward|refund|bounty|rebate|gas|fee|amount)|"
    rf"\b(?:safeNativeTransfer|safeTransferETH|sendValue)\s*\([^;{{}}]*"
    rf"{_ACTOR_RE}[^;{{}}]*(?:reward|refund|bounty|rebate|gas|fee|amount)|"
    rf"\bpayable\s*\(\s*{_ACTOR_RE}\s*\)\s*\.\s*(?:transfer|send)\s*\(|"
    rf"\bpayable\s*\(\s*{_ACTOR_RE}\s*\)\s*\.\s*call\s*\{{\s*value\s*:",
    re.IGNORECASE | re.DOTALL,
)


def _strip_comments_and_strings(source: str) -> str:
    def replace_token(match: re.Match[str]) -> str:
        text = match.group(0)
        return "\n" * text.count("\n") if "\n" in text else " "

    return _TOKEN_RE.sub(replace_token, source or "")


def _find_matching_delimiter(source: str, open_pos: int, open_char: str, close_char: str) -> int:
    if open_pos < 0 or open_pos >= len(source) or source[open_pos] != open_char:
        return -1
    depth = 1
    i = open_pos + 1
    while i < len(source) and depth > 0:
        char = source[i]
        if char == open_char:
            depth += 1
        elif char == close_char:
            depth -= 1
        i += 1
    return i - 1 if depth == 0 else -1


def _extract_balanced_block(source: str, open_brace: int) -> tuple[Optional[str], int]:
    close_brace = _find_matching_delimiter(source, open_brace, "{", "}")
    if close_brace < 0:
        return None, open_brace
    return source[open_brace + 1:close_brace], close_brace + 1


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
        j = close_paren + 1
        while j < len(source):
            if source[j] == ";":
                break
            if source[j] == "{":
                body_start = j
                break
            j += 1
        if body_start < 0:
            pos = max(j, close_paren + 1)
            continue

        body, end_pos = _extract_balanced_block(source, body_start)
        if body is None:
            pos = body_start + 1
            continue

        header = source[match.start():body_start]
        body_line = source.count("\n", 0, body_start + 1) + 1
        out.append(FunctionSlice(name=name, header=header, body=body, body_line=body_line))
        pos = end_pos
    return out


def _line_for_offset(fn: FunctionSlice, offset: int) -> int:
    return fn.body_line + fn.body.count("\n", 0, max(0, offset))


def _extract_if_blocks(body: str, condition_re: re.Pattern[str]) -> list[tuple[int, int]]:
    blocks: list[tuple[int, int]] = []
    for match in condition_re.finditer(body):
        brace = body.find("{", match.end() - 1)
        if brace < 0:
            continue
        _block, end_pos = _extract_balanced_block(body, brace)
        if end_pos > brace:
            blocks.append((brace, end_pos))
    return blocks


def _inside_blocks(offset: int, blocks: list[tuple[int, int]]) -> bool:
    return any(start < offset < end for start, end in blocks)


def _requires_success_before(body: str, offset: int, flag_name: str) -> bool:
    prefix = body[:offset]
    escaped = re.escape(flag_name)
    guard_re = re.compile(
        rf"\brequire\s*\(\s*{escaped}\b|"
        rf"\bif\s*\(\s*!\s*{escaped}\s*\)\s*"
        rf"(?:\{{[^{{}}]*(?:revert|return)[^{{}}]*\}}|(?:revert|return)\b)|"
        rf"\bif\s*\(\s*{escaped}\s*==\s*false\s*\)\s*"
        rf"(?:\{{[^{{}}]*(?:revert|return)[^{{}}]*\}}|(?:revert|return)\b)|"
        rf"\bif\s*\(\s*false\s*==\s*{escaped}\s*\)\s*"
        rf"(?:\{{[^{{}}]*(?:revert|return)[^{{}}]*\}}|(?:revert|return)\b)",
        re.IGNORECASE | re.DOTALL,
    )
    return bool(guard_re.search(prefix))


def _is_success_gated(body: str, offset: int, flag_name: str) -> bool:
    escaped = re.escape(flag_name)
    success_gate_re = re.compile(
        rf"\bif\s*\(\s*(?:{escaped}|{escaped}\s*==\s*true|true\s*==\s*{escaped})"
        rf"\s*\)\s*\{{",
        re.IGNORECASE,
    )
    return _inside_blocks(offset, _extract_if_blocks(body, success_gate_re))


def _dispatch_signals(fn: FunctionSlice) -> list[DispatchSignal]:
    signals: list[DispatchSignal] = []
    seen: set[tuple[str, int]] = set()

    for match in _TRY_CATCH_FALSE_RE.finditer(fn.body):
        signal = DispatchSignal(flag=match.group("flag"), end=match.end(), source="try-catch")
        key = (signal.flag, signal.end)
        if key not in seen:
            seen.add(key)
            signals.append(signal)

    for regex, source in (
        (_BOOL_CALL_RE, "bool-dispatch-return"),
        (_TUPLE_LOW_LEVEL_CALL_RE, "low-level-call-return"),
        (_ASSIGN_CALL_RE, "assigned-dispatch-return"),
    ):
        for match in regex.finditer(fn.body):
            flag = match.group("flag")
            if flag.lower() in {"reward", "refund", "amount", "bounty"}:
                continue
            signal = DispatchSignal(flag=flag, end=match.end(), source=source)
            key = (signal.flag, signal.end)
            if key not in seen:
                seen.add(key)
                signals.append(signal)

    return signals


def _failure_is_observable(body: str, signal: DispatchSignal) -> bool:
    if signal.source == "try-catch":
        return True
    flag = re.escape(signal.flag)
    failure_branch_re = re.compile(
        rf"\bif\s*\(\s*(?:!\s*{flag}|{flag}\s*==\s*false|false\s*==\s*{flag})"
        rf"\s*\)|\b(?:emit\s+)?[A-Za-z_][A-Za-z0-9_]*Failed\b",
        re.IGNORECASE,
    )
    return bool(failure_branch_re.search(body[signal.end:]) or _FAILURE_HINT_RE.search(body))


def _failed_dispatch_payment(fn: FunctionSlice) -> tuple[int, str] | None:
    if not _PUBLIC_HEADER_RE.search(fn.header):
        return None
    if not (_CONTEXT_RE.search(fn.name) or _CONTEXT_RE.search(fn.body)):
        return None

    for signal in _dispatch_signals(fn):
        if not _failure_is_observable(fn.body, signal):
            continue
        payout = _REWARD_CREDIT_RE.search(fn.body, signal.end)
        if payout is None:
            continue
        if _is_success_gated(fn.body, payout.start(), signal.flag):
            continue
        if _requires_success_before(fn.body, payout.start(), signal.flag):
            continue
        return (
            payout.start(),
            f"{signal.source} sets or returns `{signal.flag}` but reward payment is not gated on it",
        )
    return None


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    clean = _strip_comments_and_strings(source)
    if not _CONTEXT_RE.search(clean):
        return []

    findings: list[Finding] = []
    for fn in _split_functions(clean):
        result = _failed_dispatch_payment(fn)
        if result is None:
            continue
        offset, reason = result
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=_line_for_offset(fn, offset),
                severity=DETECTOR_SEVERITY_DEFAULT,
                function=fn.name,
                message=(
                    f"`{fn.name}` pays a relayer, keeper, or caller reward after failed dispatch: "
                    f"{reason}. Reward or refund credit must require delivery success, "
                    "or the failure branch must revert or return before value moves."
                ),
            )
        )
    return findings


__all__ = [
    "DETECTOR_NAME",
    "DETECTOR_SEVERITY_DEFAULT",
    "Finding",
    "scan",
]
