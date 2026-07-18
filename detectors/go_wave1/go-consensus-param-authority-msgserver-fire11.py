"""
go-consensus-param-authority-msgserver-fire11.py

Fire11 companion detector for consensus-param-corruption recall.

Source-backed gap:
- The held-out Go fixture `go-consensus-param-authority-validation-gap-positive`
  validates Msg consensus params and then commits them, but never proves
  `msg.Authority` is the module authority.

This detector is intentionally narrower than the existing full detector. It
only targets MsgServer-style UpdateParams handlers where caller-supplied
consensus params flow to a SetParams/SetConsensusParams sink before any
authority comparison.
"""

from __future__ import annotations

import re

DETECTOR_ID = "go_wave1.go-consensus-param-authority-msgserver-fire11"

_MSG_PARAM_RE = re.compile(r"\bmsg\s+\*?Msg[A-Za-z0-9_]*(?:Params|Consensus)[A-Za-z0-9_]*", re.IGNORECASE)
_UPDATE_NAME_RE = re.compile(r"(?:Update|Set|Apply|Configure)[A-Za-z0-9_]*(?:Params|Consensus)", re.IGNORECASE)
_CONSENSUS_RE = re.compile(
    r"\b(?:ConsensusParams|BlockParams|EvidenceParams|ValidatorParams|VoteExtensionsEnableHeight)\b",
    re.IGNORECASE,
)
_CALLER_PARAMS_RE = re.compile(
    r"\bmsg\.(?:Params|ConsensusParams)\b|\bparams\s*:=\s*msg\.(?:Params|ConsensusParams)\b",
    re.IGNORECASE,
)
_WRITE_RE = re.compile(
    r"\b(?:SetParams|SetConsensusParams|UpdateConsensusParams|WithConsensusParams)\s*\(",
    re.IGNORECASE,
)
_AUTHORITY_GUARD_RE = re.compile(
    r"(?:msg\.(?:Authority|GetAuthority\s*\(\s*\))\s*(?:==|!=)|"
    r"(?:k|m|keeper)\.authority|GetAuthority\s*\(\s*\)\s*(?:==|!=)|"
    r"EnsureAuthority|ValidateAuthority|CheckAuthority|AssertAuthority|"
    r"NewModuleAddress\s*\(|govtypes\.ModuleName)",
    re.IGNORECASE,
)


def _strip_comments(text: str) -> str:
    text = re.sub(r"//.*", "", text)
    return re.sub(r"/\*.*?\*/", "", text, flags=re.S)


def run(engine, filepath: str):
    hits = []
    for fn in engine.functions():
        name = engine.fn_name(fn)
        if not name or name == "?":
            continue
        body = engine.fn_body(fn)
        if body is None:
            continue

        fn_text = _strip_comments(engine.text(fn))
        body_text = _strip_comments(engine.text(body))
        path_text = filepath.replace("\\", "/").lower()
        if not (
            _CONSENSUS_RE.search(fn_text)
            or re.search("Consensus", name, re.IGNORECASE)
            or "consensus-param" in path_text
            or "consensus_param" in path_text
        ):
            continue
        if not (_MSG_PARAM_RE.search(fn_text) and _UPDATE_NAME_RE.search(name)):
            continue
        if not _CALLER_PARAMS_RE.search(fn_text):
            continue

        write = _WRITE_RE.search(body_text)
        if not write:
            continue
        if _AUTHORITY_GUARD_RE.search(body_text[: write.start()]):
            continue

        hits.append({
            "severity": "high",
            "line": engine.line(fn),
            "col": engine.col(fn),
            "snippet": fn_text.splitlines()[0][:160],
            "message": (
                f"`{name}` commits caller-supplied consensus params without "
                f"proving msg authority before the SetParams sink. Bind "
                f"`msg.Authority` to the module authority before mutating "
                f"consensus configuration. (class: consensus-param-corruption)"
            ),
        })
    return hits
