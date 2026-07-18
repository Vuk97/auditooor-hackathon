"""
branch-idempotency-flag-asymmetry-fire28

Solidity same-class recall detector for rewards-distribution-skew misses where
an if/else settlement, claim, bridge release, or profit/loss branch writes a
processed, claimed, settled, checkpoint, lastUpdate, yield, or reward-index
state marker in only one meaningful arm.

Confirmed sources:
- reference/patterns.dsl.r75_mined/firms_zellic_ottersec_nethermind/queued-bridge-message-stale-yield-overwrite.yaml
- reference/patterns.dsl.r75_mined/c4_lending/profit-loss-else-if-drops-one-branch.yaml
- reference/patterns.dsl.r75_mined/firms_chainsec_halborn_hexens_pashov/pashov-erc20-checkpoint-not-updated-on-transfer.yaml

Detector hits are candidate evidence only. They do not prove exploitability or
filing readiness without a real protocol path, impact proof, and negative
control.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "branch-idempotency-flag-asymmetry-fire28"
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
class BranchPair:
    if_condition: str
    if_body: str
    if_start: int
    else_condition: str
    else_body: str
    else_start: int
    end: int


_FN_HEADER_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_TOKEN_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'|"
    r"//[^\n\r]*|"
    r"/\*.*?\*/",
    re.DOTALL,
)

_FUNCTION_CONTEXT_RE = re.compile(
    r"\b(?:reward\w*|claim\w*|settle\w*|release\w*|redeem\w*|"
    r"withdraw\w*|bridge\w*|message\w*|payload\w*|queue\w*|"
    r"process\w*|complete\w*|checkpoint\w*|last\w*update|"
    r"yield\w*|rate\w*|index\w*|profit\w*|loss\w*|share\w*)\b",
    re.IGNORECASE,
)
_BRANCH_CONTEXT_RE = re.compile(
    r"\b(?:queued?|direct|deferred|immediate|success|fail\w*|profit|loss|"
    r"bridge|message|payload|claim|settle|release|reward|checkpoint|"
    r"yield|rate|index|shares?|mint|burn|credit|debit|payout)\b",
    re.IGNORECASE,
)
_VALUE_OR_SETTLEMENT_EFFECT_RE = re.compile(
    r"\b(?:safeTransfer|safeTransferFrom|safeTransferETH|safeNativeTransfer|"
    r"transfer|send|sendValue|mint|_mint|burn|_burn|claimReward|"
    r"payReward|creditReward|releaseReward|unlockReward|distributeReward|"
    r"_credit\w*|_debit\w*|_queue\w*|_release\w*|_settle\w*|"
    r"_complete\w*|_process\w*|_apply\w*)\s*\(|"
    r"\.\s*call\s*\{\s*value\s*:|"
    r"\b[A-Za-z_][A-Za-z0-9_]*\s*(?:\[[^\]]+\]\s*)+"
    r"(?:=|\+=|-=)\s*[^;]*(?:amount|reward|shares?|claim|loss|profit|"
    r"payload|message|rate|yield|index)",
    re.IGNORECASE | re.DOTALL,
)
_STATE_WORD_RE = (
    r"processed|claimed|settled|checkpoint|last[A-Za-z0-9_]*update|"
    r"reward[A-Za-z0-9_]*index|index[A-Za-z0-9_]*reward|"
    r"acc[A-Za-z0-9_]*reward|reward[A-Za-z0-9_]*per[A-Za-z0-9_]*token|"
    r"yield[A-Za-z0-9_]*factor|share[A-Za-z0-9_]*rate|"
    r"exchange[A-Za-z0-9_]*rate|index[A-Za-z0-9_]*rate"
)
_STATE_WRITE_RE = re.compile(
    rf"(?:\b[A-Za-z_][A-Za-z0-9_]*\s*(?:\[[^\]]+\]\s*)*\.\s*)?"
    rf"\b(?=[A-Za-z_][A-Za-z0-9_]*\b)(?=[A-Za-z0-9_]*"
    rf"(?:{_STATE_WORD_RE}))[A-Za-z_][A-Za-z0-9_]*\b"
    r"\s*(?:\[[^\]]+\]\s*)*(?:\.\s*(?:balance|index|value|timestamp)\s*)?"
    r"(?:=|\+=|-=)\s*[^;]+;|"
    r"\bcheckpoint\s*\.\s*(?:balance|index|value|timestamp)\s*(?:=|\+=|-=)\s*[^;]+;|"
    r"\b_?(?:mark|set|record|update|checkpoint|settle|finalize|consume|complete)"
    r"[A-Za-z0-9_]*(?:Processed|Claim|Claimed|Settled|Checkpoint|Reward|"
    r"Rewards|Index|Update|Yield|Rate|Message)[A-Za-z0-9_]*\s*\(",
    re.IGNORECASE | re.DOTALL,
)
_COMMON_FINALIZER_CALL_RE = re.compile(
    r"\b(?P<name>_?(?:finalize|complete|finish|settle|checkpoint|record|"
    r"mark|consume|close)[A-Za-z0-9_]*|"
    r"_?update[A-Za-z0-9_]*(?:Reward|Rewards|Index|Checkpoint|Rate|Yield)"
    r"[A-Za-z0-9_]*)\s*\(",
    re.IGNORECASE,
)
_SYMMETRIC_HINT_RE = re.compile(
    r"\b(?:markAllBranchesProcessed|checkpointBothBranches|"
    r"settleBothRewardBranches|commonRewardFinalize|finalizeBothBranches|"
    r"_commonSettlementFinalizer)\s*\(",
    re.IGNORECASE,
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


def _skip_ws(source: str, pos: int) -> int:
    while pos < len(source) and source[pos].isspace():
        pos += 1
    return pos


def _read_condition(source: str, pos: int) -> tuple[Optional[str], int]:
    pos = _skip_ws(source, pos)
    if pos >= len(source) or source[pos] != "(":
        return None, pos
    close = _find_matching_delimiter(source, pos, "(", ")")
    if close < 0:
        return None, pos
    return source[pos + 1:close], close + 1


def _branch_pairs(body: str) -> list[BranchPair]:
    pairs: list[BranchPair] = []
    pos = 0
    while True:
        if_match = re.search(r"\bif\s*\(", body[pos:])
        if if_match is None:
            break
        if_start = pos + if_match.start()
        cond_start = body.find("(", if_start)
        if_condition, after_condition = _read_condition(body, cond_start)
        if if_condition is None:
            pos = if_start + 2
            continue

        if_block_start = _skip_ws(body, after_condition)
        if if_block_start >= len(body) or body[if_block_start] != "{":
            pos = if_start + 2
            continue
        if_body, after_if = _extract_balanced_block(body, if_block_start)
        if if_body is None:
            pos = if_start + 2
            continue

        else_pos = _skip_ws(body, after_if)
        if not body.startswith("else", else_pos):
            pos = after_if
            continue

        else_condition = "else"
        after_else = _skip_ws(body, else_pos + len("else"))
        if body.startswith("if", after_else) and (
            after_else + 2 == len(body) or not body[after_else + 2].isalnum()
        ):
            else_condition, after_else = _read_condition(body, after_else + 2)
            if else_condition is None:
                pos = after_if
                continue

        else_block_start = _skip_ws(body, after_else)
        if else_block_start >= len(body) or body[else_block_start] != "{":
            pos = after_if
            continue
        else_body, after_else_block = _extract_balanced_block(body, else_block_start)
        if else_body is None:
            pos = after_if
            continue

        pairs.append(
            BranchPair(
                if_condition=if_condition,
                if_body=if_body,
                if_start=if_start,
                else_condition=else_condition,
                else_body=else_body,
                else_start=else_pos,
                end=after_else_block,
            )
        )
        pos = after_if
    return pairs


def _line_for_offset(fn: FunctionSlice, offset: int) -> int:
    return fn.body_line + fn.body.count("\n", 0, max(0, offset))


def _branch_is_meaningful(condition: str, body: str) -> bool:
    branch_text = f"{condition}\n{body}"
    return bool(
        _BRANCH_CONTEXT_RE.search(branch_text)
        or _VALUE_OR_SETTLEMENT_EFFECT_RE.search(body)
        or _STATE_WRITE_RE.search(body)
    )


def _common_finalizer_names(left: str, right: str) -> set[str]:
    left_names = {match.group("name").lower() for match in _COMMON_FINALIZER_CALL_RE.finditer(left)}
    right_names = {match.group("name").lower() for match in _COMMON_FINALIZER_CALL_RE.finditer(right)}
    return left_names & right_names


def _has_common_post_branch_state(fn: FunctionSlice, pair: BranchPair) -> bool:
    tail = fn.body[pair.end:pair.end + 1200]
    return bool(_STATE_WRITE_RE.search(tail) or _COMMON_FINALIZER_CALL_RE.search(tail))


def _has_branch_flag_asymmetry(fn: FunctionSlice) -> tuple[int, str] | None:
    if _SYMMETRIC_HINT_RE.search(fn.body):
        return None
    if not (_FUNCTION_CONTEXT_RE.search(fn.name) or _FUNCTION_CONTEXT_RE.search(fn.body)):
        return None

    for pair in _branch_pairs(fn.body):
        if not _branch_is_meaningful(pair.if_condition, pair.if_body):
            continue
        if not _branch_is_meaningful(pair.else_condition, pair.else_body):
            continue
        if _common_finalizer_names(pair.if_body, pair.else_body):
            continue
        if _has_common_post_branch_state(fn, pair):
            continue

        if_state = _STATE_WRITE_RE.search(pair.if_body)
        else_state = _STATE_WRITE_RE.search(pair.else_body)
        if bool(if_state) == bool(else_state):
            continue

        if if_state is None:
            return (
                pair.if_start,
                "if branch reaches reward or settlement work without the "
                "terminal flag, checkpoint, or index update present in the "
                "sibling branch",
            )
        return (
            pair.else_start,
            "else branch reaches reward or settlement work without the "
            "terminal flag, checkpoint, or index update present in the "
            "sibling branch",
        )
    return None


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    clean = _strip_comments_and_strings(source)
    if not _FUNCTION_CONTEXT_RE.search(clean):
        return []

    findings: list[Finding] = []
    for fn in _split_functions(clean):
        result = _has_branch_flag_asymmetry(fn)
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
                    f"`{fn.name}` has branch idempotency flag asymmetry: "
                    f"{reason}. Branch-heavy reward, claim, bridge-settle, "
                    "or profit/loss paths must update processed, claimed, "
                    "settled, checkpoint, lastUpdate, yield, and reward-index "
                    "state symmetrically, or call a shared finalizer."
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
