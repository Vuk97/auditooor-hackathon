"""
cosmos_msg_handler_missing_replay_guard.py

Detects Msg handlers that act on a caller-supplied expiry / deadline /
timestamp / nonce field but never compare it against the current block
context - so a stale or already-used message can be replayed.

A cosmos-sdk handler that carries a `Deadline` / `ExpiresAt` / `Timeout` /
`Nonce` / `Sequence` field in its Msg is explicitly designed to be
time-bounded or single-use. If the handler reads that field (or names a
time-bounded action) but never compares it to `ctx.BlockTime()` /
`ctx.BlockHeight()` and never marks the nonce consumed, an attacker can
re-broadcast a previously-valid message after it should have expired
(stale-message replay) or replay a send/claim to double-execute it.

The safe pattern compares against block context and/or consumes the nonce:
    if msg.Deadline < ctx.BlockTime().Unix() { return ErrExpired }
    if k.HasNonce(ctx, msg.Nonce) { return ErrReplay }
    k.ConsumeNonce(ctx, msg.Nonce)

Bug class: HIGH (replay-stale-msg / sending-msg-replay -> double-execute).
Attack-class anchor: zero-coverage classes `replay-stale-msg`
("Stale or old message replayed") and `sending-msg-replay`.
Platform: cosmos-sdk app-chains (dYdX, Osmosis, Sei, Spark coordinator).
"""

from __future__ import annotations

import re

DETECTOR_ID = "go_wave1.cosmos_msg_handler_missing_replay_guard"

# The handler reads a caller-supplied expiry / nonce field.
_REPLAY_FIELD_RE = re.compile(
    r"\bmsg\.(Deadline|ExpiresAt|ExpiryTime|Expiry|Timeout|TimeoutHeight"
    r"|ValidUntil|Nonce|Sequence|Salt|RequestId|RequestID)\b"
)

# A handler whose name implies a time-bounded / single-use action.
_TIMED_NAME_RE = re.compile(
    r"^(Execute|Claim|Redeem|Settle|Finalize|Submit|Process|Fulfill)"
)

# Evidence the handler enforced freshness or single-use.
_GUARD_RE = re.compile(
    r"(ctx\.BlockTime\s*\(\s*\)"
    r"|ctx\.BlockHeight\s*\(\s*\)"
    r"|HasNonce\s*\(|ConsumeNonce\s*\(|MarkUsed\s*\(|SetUsed\s*\("
    r"|IsExpired\s*\(|checkExpiry\s*\(|HasBeenUsed\s*\("
    r"|\.Used\b|\bnonceStore\b|already.{0,12}used|replay)"
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

        reads_field = bool(_REPLAY_FIELD_RE.search(body_text))
        if not reads_field:
            continue
        # Skip handlers that did enforce a freshness / single-use guard.
        if _GUARD_RE.search(body_text):
            continue

        field = _REPLAY_FIELD_RE.search(body_text).group(1)
        hits.append({
            "severity": "high",
            "line": engine.line(fn),
            "col": engine.col(fn),
            "snippet": engine.text(fn).splitlines()[0][:160],
            "message": (
                f"`{name}` reads caller-supplied `msg.{field}` but never "
                f"compares it to ctx.BlockTime()/BlockHeight() and never "
                f"marks it consumed. A stale or already-used message can be "
                f"re-broadcast and double-executed. Enforce expiry against "
                f"block context and consume the nonce. "
                f"(class: replay-stale-msg)"),
        })
    return hits
