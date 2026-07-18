"""
go-cosmos-signature-replay-scope-missing.py

Sibling Go/Cosmos detector for replayable custom authorization. It catches
two same-class shapes:

1. Direct signature verification over locally built bytes without chain,
   domain, sequence, nonce, or account-number binding.
2. Msg handlers that read Deadline, Timeout, Nonce, or Sequence but never
   compare them to block context and never consume them.
"""

from __future__ import annotations

import re

DETECTOR_ID = "go_wave1.go-cosmos-signature-replay-scope-missing"

_DIRECT_VERIFY_RE = re.compile(
    r"(\bed25519\.Verify\s*\(|\bsecp256k1\.VerifySignature\s*\("
    r"|\becdsa\.Verify(?:ASN1)?\s*\(|\bVerifySignature\s*\("
    r"|\bVerifySig\s*\(|\bVerifyBytes\s*\()"
)
_LOCAL_PREIMAGE_RE = re.compile(
    r"(\[\]byte\s*\(|fmt\.Sprintf\s*\(|json\.Marshal\s*\("
    r"|proto\.Marshal\s*\(|cdc\.Marshal\s*\(|sha256\.Sum256\s*\("
    r"|tmhash\.Sum\s*\(|crypto\.Keccak256\s*\(|\bhash[A-Za-z0-9_]*\s*:=)"
)
_SCOPE_BINDING_RE = re.compile(
    r"(\bSignDoc\b|\bSignModeHandler\b|\bGetSignBytes\b"
    r"|\bChainID\b|\bChainId\b|\bchainID\b|\bchainId\b"
    r"|\bAccountNumber\b|\bSequence\b|\bNonce\b|\bnonce\b"
    r"|\bDomain\b|\bdomain\b|\bEIP712\b|\beip712\b)"
)
_REPLAY_FIELD_RE = re.compile(
    r"\bmsg\.(Deadline|ExpiresAt|ExpiryTime|Expiry|Timeout|TimeoutHeight"
    r"|ValidUntil|Nonce|Sequence|Salt|RequestId|RequestID)\b"
)
_REPLAY_GUARD_RE = re.compile(
    r"(ctx\.BlockTime\s*\(\s*\)|ctx\.BlockHeight\s*\(\s*\)"
    r"|HasNonce\s*\(|ConsumeNonce\s*\(|MarkUsed\s*\(|SetUsed\s*\("
    r"|IsExpired\s*\(|checkExpiry\s*\(|HasBeenUsed\s*\("
    r"|already.{0,12}used|replay)"
)


def run(engine, filepath: str):
    hits = []
    for fn in engine.functions():
        name = engine.fn_name(fn)
        if not name or name == "?":
            continue
        body = engine.fn_body(fn)
        if body is None:
            continue
        body_text = engine.text(body)

        direct_replay = (
            _DIRECT_VERIFY_RE.search(body_text)
            and _LOCAL_PREIMAGE_RE.search(body_text)
            and not _SCOPE_BINDING_RE.search(body_text)
        )
        msg_replay = (
            _REPLAY_FIELD_RE.search(body_text)
            and not _REPLAY_GUARD_RE.search(body_text)
        )
        if not direct_replay and not msg_replay:
            continue

        hits.append({
            "severity": "high",
            "line": engine.line(fn),
            "col": engine.col(fn),
            "snippet": engine.text(fn).splitlines()[0][:160],
            "message": (
                f"`{name}` accepts caller authorization without an obvious "
                f"chain/domain/freshness binding or nonce consumption. "
                f"Bind custom signatures to chain scope and consume replay "
                f"fields before executing the Msg. "
                f"(class: signature-replay-cross-domain)"
            ),
        })
    return hits
