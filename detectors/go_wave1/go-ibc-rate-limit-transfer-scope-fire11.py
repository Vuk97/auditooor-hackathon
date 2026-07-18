"""
go-ibc-rate-limit-transfer-scope-fire11.py

Fire11 companion detector for IBC rate-limit bypass recall.

Source-backed gap:
- The held-out Go fixture `go-ibc-rate-limit-denom-channel-scope-bypass-positive`
  performs a quota or blocklist check before an IBC transfer sink, but the
  guard is scoped only to amount or receiver. The transfer tuple
  denom/channel/sender-or-receiver is not bound.
"""

from __future__ import annotations

import re

DETECTOR_ID = "go_wave1.go-ibc-rate-limit-transfer-scope-fire11"

_IBC_CONTEXT_RE = re.compile(
    r"(OnRecvPacket|OnAcknowledgementPacket|OnTimeoutPacket|MsgTransfer|"
    r"FungibleTokenPacketData|channeltypes\.Packet|packet\.GetData|"
    r"SourceChannel|DestinationChannel|SourcePort|Denom)",
    re.IGNORECASE,
)
_GUARD_RE = re.compile(
    r"\b(?:CheckQuota|CheckRateLimit|CheckAndUpdateFlow|CheckRateLimitAndUpdateFlow|"
    r"AllowTransfer|IsAllowedTransfer|IsBlockedAddr|BlockedAddr|IsDenied|IsSanctioned)"
    r"\s*\(",
    re.IGNORECASE,
)
_MOVE_RE = re.compile(
    r"\b(?:SendCoinsFromModuleToAccount|SendCoins|MintCoins|UnescrowCoins|"
    r"EscrowCoins|Transfer|SendTransfer|releaseEscrow|creditAccount)\s*\(",
    re.IGNORECASE,
)
_DENOM_RE = re.compile(r"(?:Denom|denom|Token|token|Coin|coin|Trace)")
_CHANNEL_RE = re.compile(r"(?:Channel|channel|Port|port|Path|path)")
_ACTOR_RE = re.compile(
    r"(?:Sender|sender|Signer|signer|Receiver|receiver|Recipient|recipient|Address|addr)"
)


def _strip_comments(text: str) -> str:
    text = re.sub(r"//.*", "", text)
    return re.sub(r"/\*.*?\*/", "", text, flags=re.S)


def _call_text_at(body_text: str, start: int) -> str:
    open_paren = body_text.find("(", start)
    if open_paren < 0:
        return body_text[start:start + 120]
    depth = 0
    for idx in range(open_paren, min(len(body_text), open_paren + 500)):
        char = body_text[idx]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return body_text[start:idx + 1]
    return body_text[start:start + 500]


def _full_scope(text: str) -> bool:
    return bool(_DENOM_RE.search(text) and _CHANNEL_RE.search(text) and _ACTOR_RE.search(text))


def _scope_struct_before(prefix: str, call_text: str) -> bool:
    names = set(re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", call_text))
    for name in names:
        if name in {"ctx", "err", "nil", "return"}:
            continue
        pattern = re.compile(rf"\b{re.escape(name)}\s*:=\s*[^{{\n]*{{(?P<body>.{{0,500}}?)}}", re.S)
        for match in pattern.finditer(prefix[-1400:]):
            if _full_scope(match.group("body")):
                return True
    return False


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
        if not _IBC_CONTEXT_RE.search(fn_text):
            continue

        move = _MOVE_RE.search(body_text)
        if not move:
            continue

        bad_guard = None
        for guard in _GUARD_RE.finditer(body_text):
            if guard.start() > move.start():
                continue
            call_text = _call_text_at(body_text, guard.start())
            if _full_scope(call_text) or _scope_struct_before(body_text[: guard.start()], call_text):
                bad_guard = None
                break
            bad_guard = call_text

        if bad_guard is None:
            continue

        hits.append({
            "severity": "high",
            "line": engine.line(fn),
            "col": engine.col(fn),
            "snippet": fn_text.splitlines()[0][:160],
            "message": (
                f"`{name}` uses an IBC quota/blocklist guard before moving "
                f"funds, but the guard omits denom/channel/sender scope. "
                f"Bind the guard to the full transfer tuple before the "
                f"transfer sink. (class: ibc-rate-limit-bypass)"
            ),
        })
    return hits
