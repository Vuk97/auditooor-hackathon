"""
cosmos_ibc_packet_handler_missing_rate_limit.py

Detects IBC packet-callback handlers (`OnRecvPacket`, `OnAcknowledgementPacket`,
`OnTimeoutPacket`) that move funds / mint / escrow on the basis of the
incoming packet WITHOUT consulting a rate-limit / flow-control guard.

IBC rate-limit middleware (Osmosis-style `x/ibc-rate-limit`, Skip's
`x/ratelimit`, the ICS-20 quota wrapper) is the protocol-level defense
against a compromised or malicious counterparty chain draining an escrow
account in a single block. If a custom ICS-4 module implements
`OnRecvPacket` and directly calls into the bank/transfer keeper without
routing through the rate-limit keeper (`CheckRateLimitAndUpdateFlow`,
`UndoSend`, `GetRateLimit`, an `Allow`/`quota` check), a crafted packet
stream bypasses the quota.

Bug class: HIGH (ibc-rate-limit-bypass -> escrow drain via crafted packet).
Attack-class anchor: zero-coverage class `ibc-rate-limit-bypass`
("IBC rate-limit middleware bypassed via crafted packet").
Platform: cosmos-sdk IBC-enabled app-chains (dYdX, Osmosis, Sei, Neutron).
"""

from __future__ import annotations

import re

DETECTOR_ID = "go_wave1.cosmos_ibc_packet_handler_missing_rate_limit"

# IBC packet callback handler names.
_IBC_HANDLER_RE = re.compile(
    r"^(OnRecvPacket|OnAcknowledgementPacket|OnTimeoutPacket)$"
)

# Fund-moving / escrow side effects inside the handler body.
_FUND_MOVE_RE = re.compile(
    r"(SendCoins|MintCoins|BurnCoins|EscrowCoins|UnescrowCoins"
    r"|SendCoinsFromModuleToAccount|SendCoinsFromAccountToModule"
    r"|\.Transfer\s*\(|releaseEscrow|creditAccount)"
)

# Evidence the handler consulted a rate-limit / flow-control guard.
_RATE_LIMIT_RE = re.compile(
    r"(CheckRateLimitAndUpdateFlow|RateLimit|rateLimit|GetRateLimit"
    r"|UndoSend|UndoReceive|CheckQuota|quota|Quota|FlowControl"
    r"|CheckAndUpdateFlow|ratelimitKeeper|rlKeeper)"
)


def run(engine, filepath: str):
    hits = []
    for fn in engine.functions():
        name = engine.fn_name(fn)
        if not name or name == "?":
            continue
        if not _IBC_HANDLER_RE.match(name):
            continue
        body = engine.fn_body(fn)
        if body is None:
            continue
        body_text = engine.text(body)

        # Only OnRecvPacket-class handlers that actually move funds matter.
        if not _FUND_MOVE_RE.search(body_text):
            continue
        if _RATE_LIMIT_RE.search(body_text):
            continue

        hits.append({
            "severity": "high",
            "line": engine.line(fn),
            "col": engine.col(fn),
            "snippet": engine.text(fn).splitlines()[0][:160],
            "message": (
                f"IBC packet handler `{name}` moves funds / escrow on the "
                f"incoming packet but never consults a rate-limit / quota "
                f"guard. A crafted packet stream from a malicious "
                f"counterparty chain drains the escrow account in one "
                f"block. Route through the rate-limit keeper "
                f"(CheckRateLimitAndUpdateFlow). "
                f"(class: ibc-rate-limit-bypass)"),
        })
    return hits
