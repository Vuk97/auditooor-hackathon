"""
go-consensus-param-authority-validation-gap.py

Sibling detector for consensus-param-corruption cases where a Cosmos handler or
exported mutator accepts consensus parameters without proving the caller is the
module authority.

This is not a duplicate of the write-before-validate detectors. It allows the
params object to be validated before the write. The bug shape is:

Branch A:
1. A Msg-shaped handler consumes `msg.Params` or `msg.ConsensusParams`.
2. The handler persists those params through a consensus-param write sink.
3. No authority check compares `msg.Authority` / `msg.GetAuthority()` to the
   module authority before the write.

Branch B:
1. An exported Update/Apply/Configure consensus-param mutator writes candidate
   params.
2. No authority check runs before the write.
3. Whole-object validation is absent, late, or only partial before the write.

Attack class: consensus-param-corruption.
"""

from __future__ import annotations

import re

DETECTOR_ID = "go_wave1.go-consensus-param-authority-validation-gap"

_CONSENSUS_MARKER_RE = re.compile(
    r"(\bConsensusParams\b"
    r"|\bBlockParams\b"
    r"|\bEvidenceParams\b"
    r"|\bValidatorParams\b"
    r"|\bVersionParams\b"
    r"|\bVoteExtensionsEnableHeight\b"
    r"|\bBlock\.MaxBytes\b"
    r"|\bMaxGas\b"
    r"|\bctx\.ConsensusParams\b"
    r"|\bConsensusParamsKeeper\b"
    r"|\bParamStore\b"
    r"|\bParamsStore\b)",
    re.IGNORECASE,
)

_MSG_HANDLER_RE = re.compile(
    r"func\s*\([^)]*\)\s*"
    r"(Update|Set|Apply|Configure)(ConsensusParams|Params|Param)\s*"
    r"\([^)]*\bmsg\s+\*?Msg[A-Za-z0-9_]*",
    re.IGNORECASE,
)

_EXPORTED_MUTATOR_RE = re.compile(
    r"func\s*\([^)]*\)\s*"
    r"(Update|Apply|Configure)(ConsensusParams|Params|Param)[A-Za-z0-9_]*\s*"
    r"\(",
    re.IGNORECASE,
)

_CALLER_PARAMS_RE = re.compile(
    r"\bmsg\.(Params|ConsensusParams)\b"
    r"|\b(?:params|consensusParams|candidateParams)\s*:=\s*"
    r"msg\.(Params|ConsensusParams)\b",
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
    r"(?:params|consensusParams|candidateParams|msg\.(?:Params|ConsensusParams))\b)",
    re.IGNORECASE,
)

_AUTHORITY_CHECK_RE = re.compile(
    r"(\b(Ensure|Assert|Check|Validate|Require)Authority\b"
    r"|(?<!msg)(?<!Msg)\.GetAuthority\s*\(\s*\)"
    r"|\bk\.authority\b"
    r"|\bm\.authority\b"
    r"|\bauthority\s*(?:!=|==)"
    r"|\bmsg\.(?:Authority|GetAuthority\s*\(\s*\))\s*(?:!=|==)"
    r"|NewModuleAddress\s*\("
    r"|\bgovtypes\.ModuleName\b"
    r"|\bauthorities\s*\[)",
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


def _has_authority_check_before_write(body_text: str, write_idx: int) -> bool:
    authority_idx = _first_match_index(_AUTHORITY_CHECK_RE, body_text)
    return 0 <= authority_idx < write_idx


def _has_whole_validate_before_write(body_text: str, write_idx: int) -> bool:
    validate_idx = _first_match_index(_WHOLE_VALIDATE_RE, body_text)
    return 0 <= validate_idx < write_idx


def run(engine, filepath: str):
    hits = []
    path_text = filepath.replace("\\", "/").lower()
    for fn in engine.functions():
        name = engine.fn_name(fn)
        if not name or name == "?":
            continue
        body = engine.fn_body(fn)
        if body is None:
            continue

        fn_text = _strip_comments(engine.text(fn))
        body_text = _strip_comments(engine.text(body))

        if "consensus" not in path_text and not _CONSENSUS_MARKER_RE.search(fn_text):
            continue

        write_idx = _first_match_index(_WRITE_SINK_RE, body_text)
        if write_idx < 0:
            continue
        if _has_authority_check_before_write(body_text, write_idx):
            continue

        msg_branch = (
            _MSG_HANDLER_RE.search(fn_text)
            and _CALLER_PARAMS_RE.search(fn_text)
        )
        mutator_branch = (
            not _SETTER_NAME_RE.match(name)
            and _EXPORTED_MUTATOR_RE.search(fn_text)
            and not _has_whole_validate_before_write(body_text, write_idx)
        )
        if not (msg_branch or mutator_branch):
            continue

        reason = (
            "caller-supplied Msg consensus params are written without "
            "module-authority validation"
            if msg_branch
            else "exported consensus-param mutator lacks authority validation "
            "and whole-object validation before the write"
        )
        hits.append({
            "severity": "high",
            "line": engine.line(fn),
            "col": engine.col(fn),
            "snippet": engine.text(fn).splitlines()[0][:160],
            "message": (
                f"`{name}` writes consensus params with an authority-validation "
                f"gap: {reason}. Malformed or unauthorized consensus-param "
                f"changes can corrupt consensus configuration. "
                f"(class: consensus-param-corruption)"
            ),
        })
    return hits
