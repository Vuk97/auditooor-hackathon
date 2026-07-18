"""
rewards-distribution-failed-dispatch-stale-supply-fire23

Solidity same-class recall detector for rewards-distribution-skew misses where
a bridge or inbound dispatcher credits the relayer after a caught dispatch
failure, or reward math divides by a supply snapshot taken before a burn,
withdraw, redeem, or mint state change.

Detector hits are candidate evidence only. They do not prove exploitability or
filing readiness without a real protocol path, impact proof, and negative
control.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "rewards-distribution-failed-dispatch-stale-supply-fire23"
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
    r"\b(?:reward\w*|relayer\w*|dispatch\w*|bridge\w*|refund\w*|"
    r"bounty\w*|burn\w*|redeem\w*|withdraw\w*|mint\w*|totalSupply|"
    r"_totalSupply|checkpoint\w*)\b",
    re.IGNORECASE,
)

_DISPATCH_FAILURE_RE = re.compile(
    r"\btry\b[\s\S]{0,2600}?\bcatch\b(?:\s*\([^)]*\))?\s*\{"
    r"[\s\S]{0,700}?\b(?P<flag>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*false\b",
    re.IGNORECASE,
)
_CATCH_REVERT_RE = re.compile(
    r"\bcatch\b(?:\s*\([^)]*\))?\s*\{[^{}]*(?:revert\s*\(|"
    r"require\s*\(\s*false\b)",
    re.IGNORECASE | re.DOTALL,
)
_RELAYER_PAYOUT_RE = re.compile(
    r"\b(?:relayerRewards?|relayerCredits?|rewardCredits?|gasRefunds?)"
    r"\s*\[\s*(?:msg\.sender|relayer|_relayer)\s*\]\s*\+=|"
    r"\b(?:safeNativeTransfer|safeTransferETH|sendValue|transfer)\s*\("
    r"[^;{}]*(?:msg\.sender|relayer|_relayer)|"
    r"\bpayable\s*\(\s*(?:msg\.sender|relayer|_relayer)\s*\)\s*\."
    r"(?:transfer|send)\s*\(|"
    r"\.\s*call\s*\{\s*value\s*:\s*[^}]*\}\s*\([^;{}]*"
    r"(?:msg\.sender|relayer|_relayer)",
    re.IGNORECASE | re.DOTALL,
)

_SUPPLY_SNAPSHOT_RE = re.compile(
    r"\b(?:uint(?:256)?\s+)?(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"(?:totalSupply\s*\(\s*\)|totalSupply|_totalSupply)\b",
    re.IGNORECASE,
)
_POST_CHANGE_VAR_RE = re.compile(r"(?:after|post|remaining|new)", re.IGNORECASE)
_REWARD_DENOMINATOR_PREFIX_RE = (
    r"\b(?:reward\w*|pendingReward\w*|claimable\w*|payout\w*|"
    r"relayerReward\w*|bounty\w*|rebate\w*)\b\s*(?:\[[^\]]+\]\s*)?"
    r"(?:=|\+=)\s*[^;]*\/\s*"
)
_SUPPLY_MUTATION_RE = re.compile(
    r"\b(?:_burn|burn|_mint|mint|withdraw|redeem)\s*\(|"
    r"\b(?:totalSupply|_totalSupply)\s*(?:-=|\+=|=\s*(?:totalSupply|_totalSupply)\s*[-+])",
    re.IGNORECASE,
)
_SUPPLY_RECOMPUTE_OR_CHECKPOINT_RE = re.compile(
    r"\b(?:checkpointTotalSupply|_checkpointTotalSupply|checkpointSupply|"
    r"_checkpointSupply|syncSupply|_syncSupply|recomputeSupply|"
    r"_recomputeSupply|postBurnSupply|supplyAfterBurn|afterBurnSupply|"
    r"remainingSupply|supplyAfter|totalSupplyAfter|supplyAfterMint)\b",
    re.IGNORECASE,
)


def _strip_comments_and_strings(source: str) -> str:
    def replace_token(match: re.Match[str]) -> str:
        text = match.group(0)
        return "\n" * text.count("\n") if "\n" in text else " "

    return _TOKEN_RE.sub(replace_token, source or "")


def _extract_balanced_block(source: str, open_brace: int) -> tuple[Optional[str], int]:
    if open_brace < 0 or open_brace >= len(source) or source[open_brace] != "{":
        return None, open_brace
    depth = 1
    i = open_brace + 1
    while i < len(source) and depth > 0:
        char = source[i]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
        i += 1
    if depth != 0:
        return None, open_brace
    return source[open_brace + 1:i - 1], i


def _split_functions(source: str) -> list[FunctionSlice]:
    out: list[FunctionSlice] = []
    pos = 0
    while True:
        match = _FN_HEADER_RE.search(source, pos)
        if match is None:
            break
        name = match.group("name")
        i = match.end()
        depth_paren = 1
        while i < len(source) and depth_paren > 0:
            char = source[i]
            if char == "(":
                depth_paren += 1
            elif char == ")":
                depth_paren -= 1
            i += 1

        body_start = -1
        j = i
        while j < len(source):
            if source[j] == ";":
                break
            if source[j] == "{":
                body_start = j
                break
            j += 1
        if body_start < 0:
            pos = max(j, i)
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


def _line_for(fn: FunctionSlice, match: re.Match[str] | None) -> int:
    if match is None:
        return fn.body_line
    return fn.body_line + fn.body.count("\n", 0, match.start())


def _inside_success_gate(body: str, offset: int, flag_name: str) -> bool:
    gate_re = re.compile(
        rf"\bif\s*\(\s*{re.escape(flag_name)}\s*\)\s*\{{",
        re.IGNORECASE,
    )
    for match in gate_re.finditer(body):
        brace = body.find("{", match.end() - 1)
        _block, end_pos = _extract_balanced_block(body, brace)
        if brace < offset < end_pos:
            return True
    return False


def _requires_success_before(body: str, offset: int, flag_name: str) -> bool:
    prefix = body[:offset]
    escaped = re.escape(flag_name)
    guard_re = re.compile(
        rf"\brequire\s*\(\s*{escaped}\b|"
        rf"\bif\s*\(\s*!\s*{escaped}\s*\)\s*(?:\{{[^{{}}]*(?:revert|return)"
        rf"[^{{}}]*\}}|(?:revert|return)\b)",
        re.IGNORECASE | re.DOTALL,
    )
    return bool(guard_re.search(prefix))


def _failed_dispatch_credits_relayer(fn: FunctionSlice) -> tuple[str, re.Match[str]] | None:
    failure = _DISPATCH_FAILURE_RE.search(fn.body)
    if failure is None or _CATCH_REVERT_RE.search(fn.body):
        return None

    payout = _RELAYER_PAYOUT_RE.search(fn.body)
    if payout is None:
        return None

    flag_name = failure.group("flag")
    if _inside_success_gate(fn.body, payout.start(), flag_name):
        return None
    if _requires_success_before(fn.body, payout.start(), flag_name):
        return None

    return (
        "credits relayer reward or refund after a catch path marks dispatch unsuccessful",
        payout,
    )


def _stale_supply_reward_denominator(fn: FunctionSlice) -> tuple[str, re.Match[str]] | None:
    if _SUPPLY_RECOMPUTE_OR_CHECKPOINT_RE.search(fn.body):
        return None
    if not re.search(r"\b(reward\w*|claimable\w*|payout\w*|pendingReward\w*)\b", fn.body, re.IGNORECASE):
        return None

    for snapshot in _SUPPLY_SNAPSHOT_RE.finditer(fn.body):
        var_name = snapshot.group("var")
        if _POST_CHANGE_VAR_RE.search(var_name):
            continue
        denom_re = re.compile(
            _REWARD_DENOMINATOR_PREFIX_RE + re.escape(var_name) + r"\b",
            re.IGNORECASE | re.DOTALL,
        )
        reward_calc = denom_re.search(fn.body, snapshot.end())
        if reward_calc is None:
            continue
        mutation = _SUPPLY_MUTATION_RE.search(fn.body, reward_calc.end())
        if mutation is None:
            continue
        return (
            "calculates reward denominator from a supply snapshot before supply changes",
            snapshot,
        )
    return None


def _first_reason(fn: FunctionSlice) -> tuple[str, re.Match[str]] | None:
    for check in (
        lambda: _failed_dispatch_credits_relayer(fn),
        lambda: _stale_supply_reward_denominator(fn),
    ):
        result = check()
        if result is not None:
            return result
    return None


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    clean = _strip_comments_and_strings(source)
    if not _CONTEXT_RE.search(clean):
        return []

    findings: list[Finding] = []
    for fn in _split_functions(clean):
        if not _PUBLIC_HEADER_RE.search(fn.header):
            continue
        reason = _first_reason(fn)
        if reason is None:
            continue
        message, anchor = reason
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=_line_for(fn, anchor),
                severity=DETECTOR_SEVERITY_DEFAULT,
                function=fn.name,
                message=(
                    f"`{fn.name}` {message}. Reward distribution must require "
                    "dispatch success before relayer credit and must recompute "
                    "or checkpoint supply before reward denominator math."
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
