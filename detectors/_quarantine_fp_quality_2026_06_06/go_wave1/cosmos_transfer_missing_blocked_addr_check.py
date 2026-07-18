"""
cosmos_transfer_missing_blocked_addr_check.py

Detects fund-transfer / credit handlers that move coins to a recipient
address WITHOUT consulting the blocked-address registry (the cosmos-sdk
`BlockedAddr` set, an OFAC/sanctions allowlist, or a per-token freeze
registry).

Cosmos-sdk's bank module maintains a `blockedAddrs` map: module accounts
and sanctioned addresses that must never receive funds. The SendKeeper
checks it in `SendCoins`, but a custom keeper that builds its own credit
path (rewards distribution, airdrop, escrow release, perp settlement)
often forgets to call `BlockedAddr(addr)` first. The result: funds can be
routed to a blocked / frozen / sanctioned address, or to a module account
that then permanently traps them.

The safe pattern checks before crediting:
    if k.bankKeeper.BlockedAddr(recipient) { return ErrBlockedAddress }

Bug class: HIGH (blocked-addr-bypass / token-freeze-bypass).
Attack-class anchor: zero-coverage classes `blocked-addr-bypass`
("Bypass blocked-address registry check") and `token-freeze-bypass`.
Platform: cosmos-sdk app-chains (dYdX, Osmosis, Sei, Spark coordinator).
"""

from __future__ import annotations

import re

DETECTOR_ID = "go_wave1.cosmos_transfer_missing_blocked_addr_check"

# A handler that credits a recipient address.
_CREDIT_RE = re.compile(
    r"(SendCoinsFromModuleToAccount\s*\("
    r"|\.SendCoins\s*\([^\n]*recipient"
    r"|\.SendCoins\s*\([^\n]*to\b"
    r"|creditAccount\s*\("
    r"|\.AddCoins\s*\("
    r"|releaseEscrow\s*\("
    r"|payoutTo\s*\()"
)

# A handler name that names a credit / distribution action.
_CREDIT_NAME_RE = re.compile(
    r"(Distribute|Airdrop|Payout|Reward|Credit|Release|Settle|Refund"
    r"|Disburse|Withdraw)"
)

# Evidence the recipient was checked against the blocked-address registry.
_BLOCKED_CHECK_RE = re.compile(
    r"(BlockedAddr\s*\("
    r"|IsBlockedAddr\s*\("
    r"|blockedAddrs\s*\["
    r"|IsSanctioned\s*\("
    r"|IsFrozen\s*\("
    r"|FrozenAddr\s*\("
    r"|\bblocklist\b|\bblockList\b|\bdenylist\b|allowedRecipient)"
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

        credits = bool(_CREDIT_RE.search(body_text))
        named_credit = bool(_CREDIT_NAME_RE.search(name)) and \
            re.search(r"(SendCoins|AddCoins|Mint|Transfer)", body_text)
        if not (credits or named_credit):
            continue
        if _BLOCKED_CHECK_RE.search(body_text):
            continue

        hits.append({
            "severity": "high",
            "line": engine.line(fn),
            "col": engine.col(fn),
            "snippet": engine.text(fn).splitlines()[0][:160],
            "message": (
                f"`{name}` credits a recipient address without consulting "
                f"the blocked-address / freeze registry (BlockedAddr / "
                f"IsFrozen). Funds can be routed to a sanctioned or frozen "
                f"address, or trapped in a module account. Check "
                f"BlockedAddr(recipient) before crediting. "
                f"(class: blocked-addr-bypass)"),
        })
    return hits
