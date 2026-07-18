"""
governance-snapshot-impossible-quorum-fire39

Solidity detector for governance-snapshot-mismatch cases where quorum or
quorum-reached logic computes the required threshold from live total supply or
live voting power while votes are otherwise bound to a proposal snapshot.

Source refs inspected:
- reports/detector_lift_fire38_20260605/post_priorities_solidity.md
- reference/patterns.dsl/glider-impossible-quorum.yaml
- detectors/wave17/glider_impossible_quorum.py

verification_tier: tier-3-synthetic-taxonomy-anchored
attack_class: governance-snapshot-mismatch
context_pack_id: auditooor.vault_context_pack.v1:resume:cbdd9eeb5255863c
context_pack_hash: cbdd9eeb5255863c4870d83e88642e9c4a3eef8e7cdfb8b5fb9a8ee7ac5a25d8
MCP receipt: .auditooor/memory_context_receipt.json
NOT_SUBMIT_READY
R40/R76/R80 caveat: detector hits are source-review candidates only, not
proof. They do not establish exploitability, configured impact, source
existence beyond the scanned file, or honest harness evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "governance-snapshot-impossible-quorum-fire39"
DETECTOR_SEVERITY_DEFAULT = "High"
SUBMISSION_POSTURE = "NOT_SUBMIT_READY"
COVERAGE_CLAIM = "detector_fixture_smoke_only"
PROMOTION_ALLOWED = False
VERIFICATION_TIER = "tier-3-synthetic-taxonomy-anchored"
ATTACK_CLASS = "governance-snapshot-mismatch"


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
_TOKEN_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'|"
    r"//[^\n\r]*|"
    r"/\*.*?\*/",
    re.DOTALL,
)

_GOVERNANCE_CONTEXT_RE = re.compile(
    r"\b(?:governor|governance|proposal|proposals|quorum|vote|votes|"
    r"voting|delegate|delegation|checkpoint|snapshot)\b",
    re.IGNORECASE,
)
_SNAPSHOT_VOTE_CONTEXT_RE = re.compile(
    r"\b(?:getPastVotes|getPriorVotes|balanceOfAt|getVotesAt|votesAt|"
    r"votingPowerAt|votePowerAt|snapshotBlock|proposalSnapshot|"
    r"voteSnapshot|startBlock|checkpoint|checkpoints|getPastTotalSupply|"
    r"totalSupplyAt)\b",
    re.IGNORECASE,
)
_QUORUM_NAME_RE = re.compile(
    r"^(?:quorum|_quorum|quorumVotes|quorumThreshold|computeQuorum|"
    r"_quorumReached|quorumReached|isQuorumReached|hasQuorum|"
    r"checkQuorum|proposalSucceeded|hasReachedQuorum)$",
    re.IGNORECASE,
)
_QUORUM_BODY_RE = re.compile(
    r"\b(?:quorum|threshold|proposalSucceeded|hasReachedQuorum)\b",
    re.IGNORECASE,
)
_THRESHOLD_MATH_RE = re.compile(
    r"\b(?:quorum|threshold|bps|basisPoints|percent|percentage|"
    r"numerator|denominator|fraction|votesRequired|requiredVotes)\b|"
    r"/\s*(?:100|10_000|10000|BPS|BASIS_POINTS|PERCENT_DENOMINATOR)\b|"
    r"\bmulDiv\s*\(",
    re.IGNORECASE,
)
_LIVE_SUPPLY_RE = re.compile(
    r"(?P<source>"
    r"(?:[A-Za-z_][A-Za-z0-9_]*\s*\.\s*)?"
    r"(?:totalSupply|currentTotalSupply|liveTotalSupply|"
    r"getTotalVoteWeight|getTotalVotingPower|getCurrentVotes|"
    r"getVotes|getVotingPower|currentVotes|votingPowerOf|votePowerOf)"
    r"\s*\([^(){};]{0,180}\)|"
    r"\b(?:currentTotalSupply|liveTotalSupply|liveSupply|"
    r"totalVotingPower|totalVoteWeight|currentVoteWeight|"
    r"totalPowerInTokens|liveVotingPower)\b"
    r")",
    re.IGNORECASE | re.DOTALL,
)
_SAFE_QUORUM_DENOMINATOR_RE = re.compile(
    r"\b(?:getPastTotalSupply|totalSupplyAt|pastTotalSupply|"
    r"priorTotalSupply|snapshotSupply|supplySnapshot|totalSupplySnapshot|"
    r"proposalSupplySnapshot|proposalTotalSupply|checkpointSupply|"
    r"checkpointedSupply|quorumSupply|supplyAt|votingSupplyAt|"
    r"_checkpointSupply|_checkpointQuorum|snapshot\s*\(|_snapshot\s*\()\b",
    re.IGNORECASE,
)
_SAFE_LOCAL_NAME_RE = re.compile(
    r"(?:snapshot|checkpoint|past|prior|proposal|quorumSupply|supplyAt|atBlock)",
    re.IGNORECASE,
)
_ASSIGNMENT_RE = re.compile(
    r"\b(?:uint(?:256|128|96|64)?|int(?:256|128|96|64)?)\s+"
    r"(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<expr>[^;]{0,600});",
    re.IGNORECASE | re.DOTALL,
)


def _strip_comments_and_strings(source: str) -> str:
    def replace_token(match: re.Match[str]) -> str:
        text = match.group(0)
        return "\n" * text.count("\n") if "\n" in text else " "

    return _TOKEN_RE.sub(replace_token, source or "")


def _find_matching_delimiter(
    source: str,
    open_pos: int,
    open_char: str,
    close_char: str,
) -> int:
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
    return source[open_brace + 1 : close_brace], close_brace + 1


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

        header = source[match.start() : body_start]
        body_line = source.count("\n", 0, body_start + 1) + 1
        out.append(FunctionSlice(name=name, header=header, body=body, body_line=body_line))
        pos = end_pos
    return out


def _line_for_match(fn: FunctionSlice, match: re.Match[str]) -> int:
    return fn.body_line + fn.body.count("\n", 0, match.start())


def _is_quorum_function(fn: FunctionSlice) -> bool:
    text = f"{fn.header}\n{fn.body}"
    if _QUORUM_NAME_RE.search(fn.name):
        return True
    return bool(_QUORUM_BODY_RE.search(text) and _THRESHOLD_MATH_RE.search(text))


def _has_safe_quorum_denominator(fn: FunctionSlice) -> bool:
    text = f"{fn.header}\n{fn.body}"
    if _SAFE_QUORUM_DENOMINATOR_RE.search(text):
        return True
    for assignment in _ASSIGNMENT_RE.finditer(fn.body):
        var_name = assignment.group("var")
        expr = assignment.group("expr")
        if _SAFE_LOCAL_NAME_RE.search(var_name) and _LIVE_SUPPLY_RE.search(expr):
            return True
    return False


def _live_supply_source(fn: FunctionSlice) -> tuple[re.Match[str], str] | None:
    for match in _LIVE_SUPPLY_RE.finditer(fn.body):
        source = re.sub(r"\s+", " ", match.group("source")).strip()
        if _SAFE_QUORUM_DENOMINATOR_RE.search(source):
            continue
        return match, source
    return None


def _has_threshold_math(fn: FunctionSlice) -> bool:
    if _QUORUM_NAME_RE.search(fn.name):
        return True
    return bool(_THRESHOLD_MATH_RE.search(fn.body))


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    clean = _strip_comments_and_strings(source)
    if not _GOVERNANCE_CONTEXT_RE.search(clean):
        return []

    has_snapshot_vote_context = bool(_SNAPSHOT_VOTE_CONTEXT_RE.search(clean))
    functions = _split_functions(clean)
    findings: list[Finding] = []

    for fn in functions:
        if not _is_quorum_function(fn):
            continue
        if not _has_threshold_math(fn):
            continue
        if _has_safe_quorum_denominator(fn):
            continue
        live_supply = _live_supply_source(fn)
        if live_supply is None:
            continue
        if not has_snapshot_vote_context:
            continue

        match, source_expr = live_supply
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=_line_for_match(fn, match),
                severity=DETECTOR_SEVERITY_DEFAULT,
                function=fn.name,
                message=(
                    f"`{fn.name}` computes quorum from live denominator "
                    f"`{source_expr}` while governance vote weight is "
                    "snapshot-aware elsewhere in the contract. Bind quorum "
                    "to getPastTotalSupply, totalSupplyAt, or a proposal "
                    "supply checkpoint taken at proposal creation."
                ),
            )
        )

    return findings


__all__ = [
    "ATTACK_CLASS",
    "DETECTOR_NAME",
    "DETECTOR_SEVERITY_DEFAULT",
    "Finding",
    "VERIFICATION_TIER",
    "scan",
]
