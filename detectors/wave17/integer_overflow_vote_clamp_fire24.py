"""
integer-overflow-vote-clamp-fire24

Detects the Solidity integer-overflow-clamp recall gap where governance vote,
checkpoint, quorum, or delegation arithmetic is computed at full width and then
narrowed into uint96, uint128, or a smaller unsigned type without SafeCast or an
explicit type(uintN).max bound before the cast.

Confirmed source:
- reports/realworld_recall_drilldown_integer-overflow-clamp.md
- audit/corpus_tags/tags/dsl_pattern_delegated-votes-overflow-uint96.yaml
- patterns/fixtures/delegated-votes-overflow-uint96_vuln.sol

This detector is candidate evidence only. A finding still needs a real source
path, negative control, and R40/R76/R80 proof before filing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "integer-overflow-vote-clamp-fire24"
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
    function_line: int


_SMALL_UINT = (
    r"uint(?:8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128)"
)
_SMALL_UINT_GROUP = (
    r"(uint(?:8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128))"
)

_FN_HEADER_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_VISIBLE_RE = re.compile(r"\b(?:external|public|internal)\b")

_VOTE_FUNCTION_RE = re.compile(
    r"(?i)(?:delegate|delegat|vote|votes|voting|checkpoint|quorum|proposal|"
    r"governor|ballot|cast|power|weight)"
)
_VOTE_CONTEXT_RE = re.compile(
    r"(?is)\b(?:delegate|delegates|delegated|delegatedVotes|vote|votes|"
    r"votePower|votingPower|votingUnits|checkpoints?|numCheckpoints|"
    r"proposalVotes|quorum|forVotes|againstVotes|abstainVotes|weight|"
    r"governancePower|ballot)\b"
)
_VOTE_EFFECT_RE = re.compile(
    r"(?is)(?:"
    r"(?:delegatedVotes|votePower|votingPower|votingUnits|votes|"
    r"forVotes|againstVotes|abstainVotes|quorum|quorumVotes|"
    r"proposalVotes|governancePower|totalVotes|totalVotingPower)"
    r"\s*(?:\[|=|\+=|-=)|"
    r"checkpoints\s*(?:\[|\.push)|"
    r"\bCheckpoint\s*(?:\(|\{)|"
    r"\b_writeCheckpoint\s*\(|"
    r"\b_pushCheckpoint\s*\("
    r")"
)
_ARITHMETIC_RE = re.compile(
    r"(?is)(?:[+*]|-\s*[A-Za-z_][A-Za-z0-9_\[\]\.]*|/\s*(?:BPS|"
    r"BASIS_POINTS|10000|quorumDenominator|denominator)|balanceOf|"
    r"totalSupply|getVotes|votingUnits|amount|multiplier|weight|quorumBps)"
)

_DECL_CAST_RE = re.compile(
    r"(?is)\b" + _SMALL_UINT_GROUP
    + r"\s+[A-Za-z_][A-Za-z0-9_]*\s*=\s*"
    + _SMALL_UINT_GROUP + r"\s*\([^;{}]+\)"
)
_DECL_ARITH_RE = re.compile(
    r"(?is)\b" + _SMALL_UINT_GROUP
    + r"\s+[A-Za-z_][A-Za-z0-9_]*\s*=\s*[^;{}]*(?:[+*]|/"
    r"\s*(?:BPS|BASIS_POINTS|10000|quorumDenominator|denominator))[^;{}]*;"
)
_DIRECT_CAST_RE = re.compile(r"(?is)\b" + _SMALL_UINT_GROUP + r"\s*\([^;{}]+\)")
_STORAGE_CAST_RE = re.compile(
    r"(?is)(?:delegatedVotes|votePower|votingPower|votingUnits|votes|"
    r"forVotes|againstVotes|abstainVotes|quorum|quorumVotes|"
    r"proposalVotes|governancePower|totalVotes|totalVotingPower|checkpoints)"
    r"\s*(?:\[[^\]]+\]){0,3}\s*(?:=|\+=|-=)\s*"
    + _SMALL_UINT_GROUP + r"\s*\([^;{}]+\)"
)
_CHECKPOINT_CAST_RE = re.compile(
    r"(?is)(?:Checkpoint\s*(?:\(|\{)[^;{}]*(?:votes|weight|quorum)\s*:"
    r"\s*" + _SMALL_UINT_GROUP + r"\s*\([^;{}]+\)|"
    r"_writeCheckpoint\s*\([^;{}]*" + _SMALL_UINT_GROUP + r"\s*\([^;{}]+\)|"
    r"_pushCheckpoint\s*\([^;{}]*" + _SMALL_UINT_GROUP + r"\s*\([^;{}]+\))"
)

_SAFETY_RE = re.compile(
    r"(?is)(?:"
    r"\bSafeCast\b|"
    r"\bsafeCast\b|"
    r"\btoUint(?:8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128)"
    r"\s*\(|"
    r"\bMAX_UINT(?:8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128)\b|"
    r"\bmax(?:Votes|VotePower|VotingPower|Quorum|Supply|TotalSupply)\b|"
    r"\b_checkMaxSupply\s*\(|"
    r"\b_checkVoteBounds\s*\(|"
    r"\b_checkQuorumBounds\s*\(|"
    r"\brequire\s*\([^;{}]*(?:<=|<)\s*type\s*\(\s*" + _SMALL_UINT
    + r"\s*\)\s*\.\s*max|"
    r"\brequire\s*\([^;{}]*type\s*\(\s*" + _SMALL_UINT
    + r"\s*\)\s*\.\s*max\s*(?:>=|>)|"
    r"\bif\s*\([^;{}]*>\s*type\s*\(\s*" + _SMALL_UINT
    + r"\s*\)\s*\.\s*max\s*\)\s*(?:revert|return)|"
    r"\bif\s*\([^;{}]*type\s*\(\s*" + _SMALL_UINT
    + r"\s*\)\s*\.\s*max\s*<[^;{}]*\)\s*(?:revert|return)"
    r")"
)


def _strip_comments(source: str) -> str:
    without_line = re.sub(r"//[^\n]*", "", source)
    return re.sub(
        r"/\*.*?\*/",
        lambda match: "\n" * match.group(0).count("\n"),
        without_line,
        flags=re.S,
    )


def _split_functions(source: str) -> list[FunctionSlice]:
    out: list[FunctionSlice] = []
    pos = 0
    while True:
        match = _FN_HEADER_RE.search(source, pos)
        if not match:
            break

        name = match.group("name")
        i = match.end()
        depth_paren = 1
        while i < len(source) and depth_paren > 0:
            if source[i] == "(":
                depth_paren += 1
            elif source[i] == ")":
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

        depth = 1
        k = body_start + 1
        while k < len(source) and depth > 0:
            if source[k] == "{":
                depth += 1
            elif source[k] == "}":
                depth -= 1
            k += 1
        if depth != 0:
            pos = body_start + 1
            continue

        header = source[match.start():body_start]
        body = source[body_start + 1:k - 1]
        line = source.count("\n", 0, match.start()) + 1
        out.append(FunctionSlice(name=name, header=header, body=body, function_line=line))
        pos = k
    return out


def _line_for(function_line: int, text: str, match: re.Match[str]) -> int:
    return function_line + text.count("\n", 0, match.start())


def _vote_cast_match(fn: FunctionSlice, text: str) -> re.Match[str] | None:
    if not _VISIBLE_RE.search(fn.header):
        return None
    has_vote_name = _VOTE_FUNCTION_RE.search(fn.name) is not None
    has_vote_context = _VOTE_CONTEXT_RE.search(text) is not None
    if not has_vote_name and not has_vote_context:
        return None
    if not _VOTE_EFFECT_RE.search(text):
        return None
    if _SAFETY_RE.search(text):
        return None

    for pattern in (
        _STORAGE_CAST_RE,
        _CHECKPOINT_CAST_RE,
        _DECL_CAST_RE,
        _DECL_ARITH_RE,
        _DIRECT_CAST_RE,
    ):
        match = pattern.search(text)
        if match and (_ARITHMETIC_RE.search(match.group(0)) or _ARITHMETIC_RE.search(text)):
            return match
    return None


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    stripped = _strip_comments(source)
    findings: list[Finding] = []
    for fn in _split_functions(stripped):
        text = f"{fn.header}\n{fn.body}"
        match = _vote_cast_match(fn, text)
        if not match:
            continue
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=_line_for(fn.function_line, text, match),
                severity=DETECTOR_SEVERITY_DEFAULT,
                function=fn.name,
                message=(
                    f"`{fn.name}` narrows computed governance voting power "
                    "into a small uint without SafeCast or an explicit "
                    "type(uintN).max bound."
                ),
            )
        )
    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
