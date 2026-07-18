"""
go-consensus-param-corruption-write-before-validate.py

Independent Go/Cosmos sibling for the consensus-param-corruption class.

This detector does not rely on the origin detector's function-name allowlist.
It looks for a narrower and more structural shape instead:

1. A function persists consensus parameters through a known write sink.
2. The same function body carries consensus-parameter markers.
3. No validation happens before the first write, or validation happens only
   after the write.

That catches the held-out W68 shape directly: write consensus params first,
validate never or validate too late.
"""

from __future__ import annotations

import re

DETECTOR_ID = "go_wave1.go-consensus-param-corruption-write-before-validate"

_CONSENSUS_MARKER_RE = re.compile(
    r"(\bConsensusParams\b"
    r"|\bBlockParams\b"
    r"|\bEvidenceParams\b"
    r"|\bValidatorParams\b"
    r"|\bVersionParams\b"
    r"|\bVoteExtensionsEnableHeight\b"
    r"|\bBlock\.MaxBytes\b"
    r"|\bctx\.ConsensusParams\b"
    r"|\bWithConsensusParams\s*\()",
    re.IGNORECASE,
)

_WRITE_SINK_RE = re.compile(
    r"(\bSetConsensusParams\s*\("
    r"|\bWithConsensusParams\s*\("
    r"|\bConsensusParamsKeeper\b[\s\S]{0,120}\bSet\s*\("
    r"|\bParamsStore\s*\.\s*Set\s*\()",
    re.IGNORECASE,
)

_VALIDATE_RE = re.compile(
    r"(\bValidateUpdateConsensusParams\b"
    r"|\bValidateConsensusParams\b"
    r"|\bValidateUpdate\s*\("
    r"|\bValidateParams\s*\("
    r"|\bValidateBasic\b"
    r"|\.Validate\s*\(\s*\))",
    re.IGNORECASE,
)

_SETTER_NAME_RE = re.compile(r"^(SetConsensusParams|WithConsensusParams)$")


def _blank_comment(match: re.Match[str]) -> str:
    return "".join("\n" if ch == "\n" else " " for ch in match.group(0))


def _strip_comments(src: str) -> str:
    src = re.sub(r"//.*", _blank_comment, src)
    return re.sub(r"/\*.*?\*/", _blank_comment, src, flags=re.S)


def _first_match_index(pattern: re.Pattern[str], text: str) -> int:
    match = pattern.search(text)
    return match.start() if match else -1


def _write_before_validate(body_text: str) -> bool:
    write_idx = _first_match_index(_WRITE_SINK_RE, body_text)
    validate_idx = _first_match_index(_VALIDATE_RE, body_text)
    return write_idx >= 0 and (validate_idx < 0 or write_idx < validate_idx)


def run(engine, filepath: str):
    hits = []
    path_text = filepath.replace("\\", "/")
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

        if "consensus" not in path_text.lower() and not _CONSENSUS_MARKER_RE.search(fn_text):
            continue
        if not _WRITE_SINK_RE.search(body_text):
            continue
        if not _write_before_validate(body_text):
            continue

        hits.append({
            "severity": "high",
            "line": engine.line(fn),
            "col": engine.col(fn),
            "snippet": fn_text.splitlines()[0][:160],
            "message": (
                f"`{name}` persists consensus parameters before validation. "
                f"Malformed consensus params can be accepted into state and "
                f"halt or corrupt consensus. Validate the candidate payload "
                f"before the first write. "
                f"(class: consensus-param-corruption)"
            ),
        })
    return hits
