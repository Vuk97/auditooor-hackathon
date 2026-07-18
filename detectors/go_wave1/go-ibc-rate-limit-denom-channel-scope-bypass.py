"""
go-ibc-rate-limit-denom-channel-scope-bypass.py

Detects IBC packet and transfer paths whose quota or blocklist decision is
not scoped by the IBC transfer tuple. A rate-limit or blocklist guard that
checks only amount, receiver, or a generic address can be bypassed by moving
the same asset through another channel, denom trace, or sender scope.

The safe shape binds the guard to the decoded transfer packet, or explicitly
passes denom, channel, and sender or receiver scope before any bank transfer:

    scope := Scope{Denom: data.Denom, Channel: packet.GetSourceChannel(), Sender: data.Sender}
    if err := k.rateLimitKeeper.CheckQuota(ctx, scope, data.Amount); err != nil { return err }

Bug class: HIGH (ibc-rate-limit-bypass).
Attack-class anchor: ibc-rate-limit-bypass
("IBC rate-limit middleware bypassed via crafted packet").
Platform: cosmos-sdk IBC-enabled app-chains.
"""

from __future__ import annotations

import re

DETECTOR_ID = "go_wave1.go-ibc-rate-limit-denom-channel-scope-bypass"

_IBC_HANDLER_RE = re.compile(
    r"^(OnRecvPacket|OnAcknowledgementPacket|OnTimeoutPacket)$"
)

_TRANSFER_NAME_RE = re.compile(
    r"(SendTransfer|ValidateTransfer|Transfer|RelayTransfer|HandleTransfer)$"
)

_IBC_CONTEXT_RE = re.compile(
    r"(channeltypes\.Packet|FungibleTokenPacketData|packet\.GetData\s*\("
    r"|packet\.Data|SourceChannel|DestinationChannel|SourcePort"
    r"|MsgTransfer|denomTrace|DenomTrace)"
)

_FUND_MOVE_RE = re.compile(
    r"(SendCoins|MintCoins|BurnCoins|EscrowCoins|UnescrowCoins"
    r"|SendCoinsFromModuleToAccount|SendCoinsFromAccountToModule"
    r"|\.Transfer\s*\(|TransferKeeper\.Transfer|SendTransfer"
    r"|releaseEscrow|creditAccount)"
)

_GUARD_NAME_RE = re.compile(
    r"\b(CheckRateLimitAndUpdateFlow|CheckAndUpdateFlow|CheckQuota"
    r"|CheckRateLimit|AllowTransfer|IsAllowedTransfer|RateLimit"
    r"|GetRateLimit|UndoSend|UndoReceive|FlowControl"
    r"|BlockedAddr|IsBlockedAddr|IsBlocked|IsDenied|IsSanctioned"
    r"|IsFrozen|Denylist|Blocklist|IsSendEnabled)"
)

_DENOM_RE = re.compile(r"(Denom|denom|Token|token|Coin|coin|Trace)")
_CHANNEL_RE = re.compile(r"(Channel|channel|Port|port|Path|path)")
_SENDER_RE = re.compile(
    r"(Sender|sender|Signer|signer|FromAddress|fromAddress|Receiver"
    r"|receiver|Recipient|recipient|Address|addr)"
)

_COMPOSITE_ARG_RE = re.compile(
    r"(^|[\s,(])(?:data|packetData|transferData|msg|packet)\s*(?:[,)]|$)"
)


def _guard_calls(body_text: str) -> list[tuple[int, str]]:
    calls = []
    for match in _GUARD_NAME_RE.finditer(body_text):
        start = match.start()
        open_paren = body_text.find("(", match.end())
        if open_paren == -1 or open_paren - match.end() > 80:
            continue
        depth = 0
        end = open_paren
        for idx in range(open_paren, min(len(body_text), open_paren + 500)):
            char = body_text[idx]
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    end = idx + 1
                    break
        calls.append((start, body_text[start:end]))
    return calls


def _first_fund_move(body_text: str) -> int | None:
    match = _FUND_MOVE_RE.search(body_text)
    if not match:
        return None
    return match.start()


def _call_has_full_scope(call_text: str) -> bool:
    if _COMPOSITE_ARG_RE.search(call_text):
        return True
    return (
        bool(_DENOM_RE.search(call_text))
        and bool(_CHANNEL_RE.search(call_text))
        and bool(_SENDER_RE.search(call_text))
    )


def _prefix_defines_scoped_arg(prefix: str, call_text: str) -> bool:
    vars_in_call = set(re.findall(r"\b([A-Za-z_]\w*)\b", call_text))
    for var_name in vars_in_call:
        if var_name in {"ctx", "err", "nil", "return"}:
            continue
        assign_re = re.compile(
            rf"{re.escape(var_name)}\s*:?=\s*[^{{\n]*{{(?P<body>.{{0,500}}?)}}",
            re.DOTALL,
        )
        for match in assign_re.finditer(prefix[-1200:]):
            scope_body = match.group("body")
            if (
                _DENOM_RE.search(scope_body)
                and _CHANNEL_RE.search(scope_body)
                and _SENDER_RE.search(scope_body)
            ):
                return True
    return False


def _has_scoped_guard_before_move(body_text: str, move_idx: int) -> bool:
    for idx, call_text in _guard_calls(body_text):
        if idx > move_idx:
            continue
        if _call_has_full_scope(call_text):
            return True
        if _prefix_defines_scoped_arg(body_text[:idx], call_text):
            return True
    return False


def _has_any_guard_before_move(body_text: str, move_idx: int) -> bool:
    return any(idx <= move_idx for idx, _call_text in _guard_calls(body_text))


def run(engine, filepath: str):
    hits = []
    for fn in engine.functions():
        name = engine.fn_name(fn)
        if not name or name == "?":
            continue
        body = engine.fn_body(fn)
        if body is None:
            continue
        fn_text = engine.text(fn)
        body_text = engine.text(body)

        move_idx = _first_fund_move(body_text)
        if move_idx is None:
            continue

        is_ibc_handler = bool(_IBC_HANDLER_RE.match(name))
        is_transfer_path = bool(_TRANSFER_NAME_RE.search(name))
        has_ibc_context = bool(_IBC_CONTEXT_RE.search(fn_text))
        if not (is_ibc_handler or (is_transfer_path and has_ibc_context)):
            continue

        has_any_guard = _has_any_guard_before_move(body_text, move_idx)
        has_scoped_guard = _has_scoped_guard_before_move(body_text, move_idx)
        if has_scoped_guard:
            continue

        if is_transfer_path and not has_any_guard:
            continue

        reason = "has no quota or blocklist guard"
        if has_any_guard:
            reason = "uses a quota or blocklist guard without denom/channel/sender scope"

        hits.append({
            "severity": "high",
            "line": engine.line(fn),
            "col": engine.col(fn),
            "snippet": engine.text(fn).splitlines()[0][:160],
            "message": (
                f"`{name}` {reason} before moving IBC funds. The guard "
                f"must bind the transfer to denom, channel, and sender or "
                f"receiver scope before updating quota or blocklist state. "
                f"(class: ibc-rate-limit-bypass)"),
        })
    return hits
