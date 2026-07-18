"""
go-consensus-param-validate-after-setparam.py

Sibling detector for consensus-param-corruption cases where code appears to
validate consensus params, but the validation is not load-bearing:

1. Whole-object validation runs after the SetParam or ParamStore write.
2. Only a local consensus field is checked before committing the full params
   object.

This is intentionally narrower than go-consensus-param-corruption-write-before-
validate. A plain write with no validation signal is left to that detector.
This detector focuses on false assurance from late or partial validation.
"""

from __future__ import annotations

import re

DETECTOR_ID = "go_wave1.go-consensus-param-validate-after-setparam"

_CONSENSUS_MARKER_RE = re.compile(
    r"(\bConsensusParams\b"
    r"|\bBlockParams\b"
    r"|\bEvidenceParams\b"
    r"|\bValidatorParams\b"
    r"|\bVersionParams\b"
    r"|\bVoteExtensionsEnableHeight\b"
    r"|\bMaxBytes\b"
    r"|\bMaxGas\b"
    r"|\bctx\.ConsensusParams\b"
    r"|\bConsensusParamsKeeper\b"
    r"|\bParamStore\b"
    r"|\bParamsStore\b)",
    re.IGNORECASE,
)

_WRITE_SINK_RE = re.compile(
    r"(\bSetConsensusParams\s*\("
    r"|\bWithConsensusParams\s*\("
    r"|\bSetParam\s*\("
    r"|\bSetParams\s*\("
    r"|\bParamStore\b[\s\S]{0,160}\.\s*Set\s*\("
    r"|\bParamsStore\b[\s\S]{0,160}\.\s*Set\s*\("
    r"|\bparamStore\s*\.\s*Set\s*\("
    r"|\bparamsStore\s*\.\s*Set\s*\("
    r"|\.\s*Set\s*\(\s*(?:ctx|sdk\.UnwrapSDKContext\s*\([^)]*\))\s*,\s*"
    r"(?:params|consensusParams|newParams|candidateParams)\b)",
    re.IGNORECASE,
)

_WHOLE_VALIDATE_RE = re.compile(
    r"(\bValidateUpdateConsensusParams\s*\("
    r"|\bValidateConsensusParams\s*\("
    r"|\bValidateUpdate\s*\("
    r"|\bValidateParams\s*\("
    r"|\bValidateBasic\s*\("
    r"|\.Validate\s*\(\s*\))",
    re.IGNORECASE,
)

_PARTIAL_FIELD_RE = re.compile(
    r"(\bValidate(?:Block|Evidence|Validator|Version|VoteExtension|MaxBytes|MaxGas)"
    r"\w*\s*\([^)]*(?:\.Block|\.Evidence|\.Validator|\.Version|"
    r"VoteExtensionsEnableHeight|MaxBytes|MaxGas)[^)]*\)"
    r"|\bif\s+[^{}\n]*(?:\.Block|\.Evidence|\.Validator|\.Version|"
    r"VoteExtensionsEnableHeight|MaxBytes|MaxGas)[^{}\n]*\{[\s\S]{0,220}"
    r"\breturn\b)",
    re.IGNORECASE,
)

_SETTER_NAME_RE = re.compile(
    r"^(SetConsensusParams|SetParams|SetParam|WithConsensusParams)$"
)


def _blank_comment(match: re.Match[str]) -> str:
    return "".join("\n" if ch == "\n" else " " for ch in match.group(0))


def _strip_comments(src: str) -> str:
    src = re.sub(r"//.*", _blank_comment, src)
    return re.sub(r"/\*.*?\*/", _blank_comment, src, flags=re.S)


def _first_match_index(pattern: re.Pattern[str], text: str) -> int:
    match = pattern.search(text)
    return match.start() if match else -1


def _has_whole_validate_before_write(body_text: str, write_idx: int) -> bool:
    validate_idx = _first_match_index(_WHOLE_VALIDATE_RE, body_text)
    return 0 <= validate_idx < write_idx


def _late_validate_reason(body_text: str, write_idx: int) -> str | None:
    validate_match = _WHOLE_VALIDATE_RE.search(body_text, write_idx)
    if validate_match:
        return "whole-object validation occurs after the params write"
    return None


def _partial_validate_reason(body_text: str, write_idx: int) -> str | None:
    prefix = body_text[:write_idx]
    if _PARTIAL_FIELD_RE.search(prefix):
        return "only a local consensus field is checked before the full params write"
    return None


def run(engine, filepath: str):
    hits = []
    path_text = filepath.replace("\\", "/").lower()
    for fn in engine.functions():
        name = engine.fn_name(fn)
        if not name or name == "?":
            continue
        if _SETTER_NAME_RE.match(name):
            continue
        body = engine.fn_body(fn)
        if body is None:
            continue

        fn_text = engine.text(fn)
        body_text = _strip_comments(engine.text(body))
        if "consensus" not in path_text and not _CONSENSUS_MARKER_RE.search(fn_text):
            continue

        write_idx = _first_match_index(_WRITE_SINK_RE, body_text)
        if write_idx < 0:
            continue
        if _has_whole_validate_before_write(body_text, write_idx):
            continue

        reason = (
            _late_validate_reason(body_text, write_idx)
            or _partial_validate_reason(body_text, write_idx)
        )
        if reason is None:
            continue

        hits.append({
            "severity": "high",
            "line": engine.line(fn),
            "col": engine.col(fn),
            "snippet": fn_text.splitlines()[0][:160],
            "message": (
                f"`{name}` writes consensus params before load-bearing "
                f"whole-object validation: {reason}. Malformed consensus "
                f"params can be committed even though the function appears "
                f"to validate them. Validate the full candidate object before "
                f"the first SetParam or ParamStore write. "
                f"(class: consensus-param-corruption)"
            ),
        })
    return hits
