"""
delegate-unbounded-reward-recipients-fire27

Solidity same-class recall detector for rewards-distribution-skew misses where
a public delegate, referral, or reward-distributor path iterates over a
caller-controlled dynamic recipient list and updates reward or checkpoint
accounting for every element without a small fixed cap.

Confirmed sources:
- reference/patterns.dsl/delegate-grief-unbounded-recipients.yaml
- reference/patterns.dsl/checkpoints-cleared-on-nft-transfer.yaml
- reference/patterns.dsl/branch-asymmetric-idempotency-flag-toggled-in-only-one-arm.yaml

Detector hits are candidate evidence only. They do not prove exploitability or
filing readiness without a real protocol path, impact proof, and negative
control.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "delegate-unbounded-reward-recipients-fire27"
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
class LoopSlice:
    header: str
    body: str
    start: int
    end: int


@dataclass
class LoopTarget:
    loop_expr: str
    canonical_expr: str
    base: str
    index_var: str


_FN_HEADER_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_PUBLIC_HEADER_RE = re.compile(r"\b(?:external|public)\b")
_TOKEN_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'|"
    r"//[^\n\r]*|"
    r"/\*.*?\*/",
    re.DOTALL,
)

_REWARD_CONTEXT_RE = re.compile(
    r"\b(?:reward\w*|rewards?|distribut\w*|emission\w*|incentive\w*|"
    r"claimable\w*|accrued\w*|earned\w*|pending\w*|rewardDebt|"
    r"rewardIndex|rewardCheckpoint\w*|rewardPerToken|accRewardPerShare)\b",
    re.IGNORECASE,
)
_RECIPIENT_CONTEXT_RE = re.compile(
    r"\b(?:delegat\w*|referr\w*|referral\w*|referee\w*|recipient\w*|"
    r"beneficiar\w*|payee\w*|affiliate\w*|checkpoint\w*)\b",
    re.IGNORECASE,
)
_SURFACE_NAME_RE = re.compile(
    r"(?:delegat|referr|referral|referee|recipient|beneficiar|payee|"
    r"reward|distribut|checkpoint|allocate|register)",
    re.IGNORECASE,
)
_LIST_NAME_RE = re.compile(
    r"(?:reward|delegat|referr|referral|referee|recipient|beneficiar|"
    r"payee|affiliate|receiver|claimer|staker|holder|users?|accounts?)",
    re.IGNORECASE,
)
_ADMIN_GUARD_RE = re.compile(
    r"\b(?:onlyOwner|onlyAdmin|onlyGovernance|onlyGovernor|onlyRole|"
    r"onlyKeeper|onlyDistributor|requiresAuth|adminOnly|governanceOnly)\b|"
    r"\bhasRole\s*\(",
    re.IGNORECASE,
)

_ARRAY_PARAM_RE = re.compile(
    r"\b(?:address(?:\s+payable)?|[A-Za-z_][A-Za-z0-9_]*)\s*\[\]\s*"
    r"(?:calldata|memory|storage)?\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b",
    re.IGNORECASE,
)
_STORAGE_ALIAS_RE = re.compile(
    r"\b(?:address(?:\s+payable)?|[A-Za-z_][A-Za-z0-9_]*)\s*\[\]\s+"
    r"storage\s+(?P<alias>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"(?P<expr>[A-Za-z_][A-Za-z0-9_]*(?:\s*\[[^\]]+\]\s*)*)\s*;",
    re.IGNORECASE | re.DOTALL,
)
_LENGTH_EXPR_RE = re.compile(
    r"(?P<expr>[A-Za-z_][A-Za-z0-9_]*(?:\s*\[[^\]]+\]\s*)*)\s*\.\s*length\b",
    re.IGNORECASE,
)
_LENGTH_ALIAS_RE = re.compile(
    r"\b(?:uint(?:256)?|int(?:256)?|var)?\s*"
    r"(?P<alias>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"(?P<expr>[A-Za-z_][A-Za-z0-9_]*(?:\s*\[[^\]]+\]\s*)*)"
    r"\s*\.\s*length\s*;",
    re.IGNORECASE | re.DOTALL,
)
_LOOP_RE = re.compile(r"\b(?:for|while)\s*\(", re.IGNORECASE)
_FOR_INDEX_RE = re.compile(
    r"^\s*(?:uint(?:256)?|int(?:256)?)?\s*(?P<idx>[A-Za-z_][A-Za-z0-9_]*)\s*=",
    re.IGNORECASE,
)
_COMPARE_INDEX_RE = re.compile(
    r"\b(?P<idx>[A-Za-z_][A-Za-z0-9_]*)\s*(?:<|<=)\s*"
    r"(?:[A-Za-z_][A-Za-z0-9_]*(?:\s*\[[^\]]+\]\s*)*\.length|"
    r"[A-Za-z_][A-Za-z0-9_]*)",
    re.IGNORECASE,
)

_ACCOUNTING_SLOT = (
    r"(?:pendingRewards?|claimableRewards?|accruedRewards?|earnedRewards?|"
    r"unclaimedRewards?|rewardDebt|rewardDebts|rewardBalances?|"
    r"rewardShares?|rewardWeight|rewardWeights|rewardCheckpoints?|"
    r"rewardIndexPaid|userRewardPerTokenPaid|referralRewards?|"
    r"referrerRewards?|delegateReward\w*|delegatedReward\w*|"
    r"checkpoint\w*|delegateCheckpoints?|weightOf|pointsOf)"
)
_ACCOUNTING_CALL_RE = re.compile(
    r"\b(?:_?(?:checkpoint|writeCheckpoint|updateReward|accrueReward|"
    r"creditReward|recordReward|distributeReward|moveDelegates?|"
    r"checkpointDelegate|updateDelegate|creditReferral|recordReferral)"
    r"[A-Za-z0-9_]*)\s*\(",
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


def _loops(body: str) -> list[LoopSlice]:
    out: list[LoopSlice] = []
    pos = 0
    while True:
        match = _LOOP_RE.search(body, pos)
        if match is None:
            break
        open_paren = body.find("(", match.start())
        close_paren = _find_matching_delimiter(body, open_paren, "(", ")")
        if close_paren < 0:
            pos = match.end()
            continue
        block_start = close_paren + 1
        while block_start < len(body) and body[block_start].isspace():
            block_start += 1
        if block_start >= len(body) or body[block_start] != "{":
            pos = close_paren + 1
            continue
        loop_body, end_pos = _extract_balanced_block(body, block_start)
        if loop_body is None:
            pos = block_start + 1
            continue
        out.append(
            LoopSlice(
                header=body[open_paren + 1:close_paren],
                body=loop_body,
                start=match.start(),
                end=end_pos,
            )
        )
        pos = end_pos
    return out


def _line_for_body_pos(fn: FunctionSlice, pos: int) -> int:
    return fn.body_line + fn.body.count("\n", 0, pos)


def _compact(text: str) -> str:
    return re.sub(r"\s+", "", text)


def _base_identifier(expr: str) -> str:
    match = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)", expr)
    return match.group(1) if match else expr.strip()


def _dynamic_array_params(header: str) -> set[str]:
    return {
        match.group("name")
        for match in _ARRAY_PARAM_RE.finditer(header)
        if _LIST_NAME_RE.search(match.group("name"))
    }


def _storage_aliases(body: str) -> dict[str, str]:
    return {
        match.group("alias"): match.group("expr").strip()
        for match in _STORAGE_ALIAS_RE.finditer(body)
    }


def _length_aliases(body: str) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for match in _LENGTH_ALIAS_RE.finditer(body):
        alias = match.group("alias")
        expr = match.group("expr").strip()
        if alias not in {"uint", "uint256", "int", "int256"}:
            aliases[alias] = expr
    return aliases


def _index_var(header: str) -> str:
    for_part = header.split(";", 1)[0]
    match = _FOR_INDEX_RE.search(for_part)
    if match is not None:
        return match.group("idx")
    match = _COMPARE_INDEX_RE.search(header)
    return match.group("idx") if match is not None else "i"


def _loop_targets(loop: LoopSlice, aliases: dict[str, str], lengths: dict[str, str]) -> list[LoopTarget]:
    targets: list[LoopTarget] = []
    idx = _index_var(loop.header)

    for match in _LENGTH_EXPR_RE.finditer(loop.header):
        expr = match.group("expr").strip()
        canonical = aliases.get(expr, expr)
        base = _base_identifier(canonical)
        targets.append(LoopTarget(loop_expr=expr, canonical_expr=canonical, base=base, index_var=idx))

    for alias, expr in lengths.items():
        if re.search(rf"\b{re.escape(alias)}\b", loop.header):
            canonical = aliases.get(expr, expr)
            base = _base_identifier(canonical)
            targets.append(LoopTarget(loop_expr=expr, canonical_expr=canonical, base=base, index_var=idx))

    deduped: list[LoopTarget] = []
    seen: set[tuple[str, str, str]] = set()
    for target in targets:
        key = (target.loop_expr, target.canonical_expr, target.index_var)
        if key not in seen:
            deduped.append(target)
            seen.add(key)
    return deduped


def _is_fixed_array_declared(source: str, base: str) -> bool:
    if not base or not _LIST_NAME_RE.search(base):
        return False
    return bool(
        re.search(
            rf"\b(?:address(?:\s+payable)?|[A-Za-z_][A-Za-z0-9_]*)\s*"
            rf"\[\s*\d+\s*\]\s*(?:public|private|internal|external)?\s*"
            rf"{re.escape(base)}\b",
            source,
            re.IGNORECASE,
        )
    )


def _has_cap_guard(fn: FunctionSlice, loop: LoopSlice, target: LoopTarget) -> bool:
    prefix = fn.body[:loop.start]
    checked = _compact(f"{fn.header}\n{prefix}\n{loop.header}")
    exprs = {
        _compact(target.loop_expr),
        _compact(target.canonical_expr),
        target.base,
    }
    length_aliases = _length_aliases(prefix)

    for expr in exprs:
        if not expr:
            continue
        length = rf"{re.escape(expr)}\.length"
        if re.search(rf"require\({length}(?:<=|<)[^)]+\)", checked, re.IGNORECASE):
            return True
        if re.search(rf"if\({length}(?:>|>=)[^)]+\)(?:\{{)?revert", checked, re.IGNORECASE):
            return True
        if re.search(rf"revert[A-Za-z0-9_]*\([^;]*{length}", checked, re.IGNORECASE):
            return True
        if re.search(rf"(?:min|Math\.min)\({length},[^)]+\)", checked, re.IGNORECASE):
            return True
        if re.search(rf"(?:min|Math\.min)\([^)]+,{length}\)", checked, re.IGNORECASE):
            return True
        if re.search(rf"{length}&&[A-Za-z_][A-Za-z0-9_]*<(?:MAX|Max|max|CAP|Cap)", checked):
            return True
        if re.search(rf"(?:MAX|Max|max|CAP|Cap)[A-Za-z0-9_]*&&[A-Za-z_][A-Za-z0-9_]*<{length}", checked):
            return True

    for alias in length_aliases:
        if re.search(rf"require\({re.escape(alias)}(?:<=|<)[^)]+\)", checked, re.IGNORECASE):
            return True
        if re.search(rf"if\({re.escape(alias)}(?:>|>=)[^)]+\)(?:\{{)?revert", checked, re.IGNORECASE):
            return True
    return False


def _is_user_controlled(target: LoopTarget, dynamic_params: set[str]) -> bool:
    loop_base = _base_identifier(target.loop_expr)
    if loop_base in dynamic_params or target.base in dynamic_params:
        return True
    if "msg.sender" in _compact(target.canonical_expr):
        return True
    return False


def _element_names(loop: LoopSlice, target: LoopTarget) -> set[str]:
    names: set[str] = set()
    index = re.escape(target.index_var)
    exprs = {_compact(target.loop_expr), _compact(target.canonical_expr)}
    compact_body = _compact(loop.body)

    for expr in exprs:
        if not expr:
            continue
        indexed = rf"{re.escape(expr)}\[{index}\]"
        assign_re = re.compile(
            rf"\b(?:address(?:payable)?|[A-Za-z_][A-Za-z0-9_]*)"
            rf"(?P<name>[A-Za-z_][A-Za-z0-9_]*)={indexed}",
            re.IGNORECASE,
        )
        for match in assign_re.finditer(compact_body):
            names.add(match.group("name"))
        if re.search(indexed, compact_body):
            names.add(f"{expr}[{target.index_var}]")
    return names


def _accounting_targets(loop: LoopSlice, target: LoopTarget) -> bool:
    if not _REWARD_CONTEXT_RE.search(loop.body):
        return False

    candidate_names = _element_names(loop, target)
    if not candidate_names:
        return False

    for name in candidate_names:
        if "[" in name:
            target_pat = re.escape(_compact(name))
            compact_body = _compact(loop.body)
            if re.search(rf"{_ACCOUNTING_SLOT}\[{target_pat}\](?:=|\+=|-=|\.|\[)", compact_body, re.IGNORECASE):
                return True
            continue

        name_pat = rf"\b{re.escape(name)}\b"
        slot_re = re.compile(
            rf"\b{_ACCOUNTING_SLOT}\s*\[\s*{name_pat}\s*\]\s*(?:=|\+=|-=|\.|\[)",
            re.IGNORECASE | re.DOTALL,
        )
        call_re = re.compile(
            rf"{_ACCOUNTING_CALL_RE.pattern}[^;{{}}]*{name_pat}",
            re.IGNORECASE | re.DOTALL,
        )
        if slot_re.search(loop.body) or call_re.search(loop.body):
            return True
    return False


def _unbounded_reward_recipient_loop(
    source: str,
    fn: FunctionSlice,
) -> tuple[LoopSlice, LoopTarget, str] | None:
    if not _PUBLIC_HEADER_RE.search(fn.header):
        return None
    if _ADMIN_GUARD_RE.search(fn.header):
        return None
    text = f"{fn.name}\n{fn.header}\n{fn.body}"
    if not (_REWARD_CONTEXT_RE.search(text) and _RECIPIENT_CONTEXT_RE.search(text)):
        return None
    if not _SURFACE_NAME_RE.search(text[:1600]):
        return None

    dynamic_params = _dynamic_array_params(fn.header)
    aliases = _storage_aliases(fn.body)
    lengths = _length_aliases(fn.body)

    for loop in _loops(fn.body):
        for target in _loop_targets(loop, aliases, lengths):
            if not _LIST_NAME_RE.search(target.base):
                continue
            if _is_fixed_array_declared(source, target.base):
                continue
            if not _is_user_controlled(target, dynamic_params):
                continue
            if _has_cap_guard(fn, loop, target):
                continue
            if not _accounting_targets(loop, target):
                continue
            reason = (
                f"iterates caller-controlled `{target.canonical_expr}` without a fixed cap "
                "while updating reward, delegate, referral, or checkpoint accounting "
                "for each recipient"
            )
            return loop, target, reason
    return None


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    clean = _strip_comments_and_strings(source)
    if not (_REWARD_CONTEXT_RE.search(clean) and _RECIPIENT_CONTEXT_RE.search(clean)):
        return []

    findings: list[Finding] = []
    for fn in _split_functions(clean):
        result = _unbounded_reward_recipient_loop(clean, fn)
        if result is None:
            continue
        loop, _target, reason = result
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=_line_for_body_pos(fn, loop.start),
                severity=DETECTOR_SEVERITY_DEFAULT,
                function=fn.name,
                message=(
                    f"`{fn.name}` has unbounded reward recipient iteration: "
                    f"{reason}. Delegate, referral, and reward-distributor paths "
                    "should cap user-controlled recipient arrays or use checkpointed "
                    "accounting that does not iterate over attacker-padded lists."
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
