"""
cosmos_consensus_params_missing_validateupdate.py

Detects Cosmos-style handlers that update consensus parameters without
validating the new value first.

Consensus-parameter updates are high-risk because a malformed height,
gas, or vote-extension parameter can halt the chain or corrupt the
consensus transition. The safe pattern validates the candidate params
before any write:

    if err := params.Validate(); err != nil { return err }
    k.SetConsensusParams(ctx, params)

Bug class: HIGH/CRITICAL (consensus-param-corruption -> chain halt).
Attack-class anchor: zero-coverage class `consensus-param-corruption`
("ConsensusParams update accepted with invalid value").
Platform: cosmos-sdk app-chains.
"""

from __future__ import annotations

import re

DETECTOR_ID = "go_wave1.cosmos_consensus_params_missing_validateupdate"

# Functions that likely mutate consensus params or their update path.
_UPDATE_FN_RE = re.compile(
    r"(UpdateConsensusParams|SetConsensusParams|ApplyConsensusParams|"
    r"UpdateParams|SetParams)"
)

# Paths and bodies that actually touch consensus-parameter state.
_CONSENSUS_PATH_RE = re.compile(r"(^|/)(x/consensus|consensus)(/|$)", re.IGNORECASE)

_CONSENSUS_PARAMS_RE = re.compile(
    r"(\bConsensusParams\b"
    r"|\bVoteExtensionsEnableHeight\b"
    r"|\bBlockParams\b"
    r"|\bEvidenceParams\b"
    r"|\bValidatorParams\b"
    r"|\bBlock\.MaxBytes\b"
    r"|\bAbci\b"
    r"|\bConsensusParamsKeeper\b"
    r"|\bSetConsensusParams\s*\("
    r"|\bWithConsensusParams\s*\("
    r"|\bctx\.ConsensusParams\b)",
    re.IGNORECASE,
)

# Write sinks that persist candidate params into consensus state.
_WRITE_SINK_RE = re.compile(
    r"(\bSetConsensusParams\s*\("
    r"|\bWithConsensusParams\s*\("
    r"|\bConsensusParamsKeeper\b[\s\S]{0,120}\bSet\s*\("
    r"|\bParamsStore\s*\.\s*Set\s*\("
    r"|\bSetParams\s*\()",
    re.IGNORECASE,
)

# Evidence the new params were validated before being written.
_VALIDATE_RE = re.compile(
    r"(\bValidateUpdateConsensusParams\b"
    r"|\bValidateConsensusParams\b"
    r"|\bValidateUpdate\s*\("
    r"|\bValidateParams\s*\("
    r"|\bValidateGenesis\b"
    r"|\bValidateBasic\b"
    r"|\.Validate\s*\(\s*\))",
    re.IGNORECASE,
)


def _first_match_index(pattern: re.Pattern[str], text: str) -> int:
    match = pattern.search(text)
    return match.start() if match else -1


def _has_validate_before_write(body_text: str) -> bool:
    write_idx = _first_match_index(_WRITE_SINK_RE, body_text)
    validate_idx = _first_match_index(_VALIDATE_RE, body_text)
    return validate_idx >= 0 and (write_idx < 0 or validate_idx < write_idx)


def run(engine, filepath: str):
    hits = []
    for fn in engine.functions():
        name = engine.fn_name(fn)
        if not name or name == "?":
            continue
        if not _UPDATE_FN_RE.search(name):
            continue
        body = engine.fn_body(fn)
        if body is None:
            continue
        body_text = engine.text(body)

        path_text = filepath.replace("\\", "/")
        if not (_CONSENSUS_PARAMS_RE.search(body_text) or _CONSENSUS_PATH_RE.search(path_text)):
            continue
        if not _WRITE_SINK_RE.search(body_text):
            continue
        if _has_validate_before_write(body_text):
            continue

        hits.append({
            "severity": "high",
            "line": engine.line(fn),
            "col": engine.col(fn),
            "snippet": engine.text(fn).splitlines()[0][:160],
            "message": (
                f"Cosmos handler `{name}` updates consensus params "
                f"without validating the new value first. A malformed "
                f"ConsensusParams payload can corrupt consensus or halt "
                f"the chain. Validate before writing. "
                f"(class: consensus-param-corruption)"),
        })
    return hits
