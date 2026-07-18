"""
go-cosmos-bank-send-before-module-state-commit.py

Detects narrow Cosmos/Go payout paths that move funds with the bank keeper
before committing a module-local consumed or nonce or processed or lock marker.

Confirmed corpus anchors:
- solodit-spec:drafts_cosmos:bank-send-before-consumed-state:c4624df37da4
- solodit-spec:drafts_cosmos:payout-transfer-before-nonce-mark:b41ff3f9a52d

This is the Go/Cosmos sibling of the withdrawal CEI family. It is intentionally
not a generic "external call before any state write" detector. It only fires
when:
1. A handler looks like a payout or withdrawal or claim path.
2. A Cosmos bank send happens.
3. A consumed or nonce or processed or lock marker is written after that send.

The risk is stale local state during hook-driven cross-contract or
reentry-equivalent execution around the bank send.
"""

from __future__ import annotations

import re

DETECTOR_ID = "go_wave1.go-cosmos-bank-send-before-module-state-commit"

_PATH_NAME_RE = re.compile(
    r"(Claim|Withdraw|Payout|Refund|Release|Process|Handle|Complete|Settle)",
    re.IGNORECASE,
)

_BANK_SEND_RE = re.compile(
    r"(SendCoinsFromModuleToAccount|SendCoinsFromModuleToModule|SendCoins)\s*\(",
    re.IGNORECASE,
)

_STATE_MARK_RE = re.compile(
    r"(?ix)"
    r"(?:"
    r"Set(?:Processed|Consumed|Claimed|Settled|Completed|Nonce|Lock|Locked"
    r"|Pending|Used)[A-Za-z_]*\s*\(|"
    r"(?:processed|consumed|claimed|settled|completed|used|pending|locks?"
    r"|nonces?|status)\s*(?:\[[^\]]+\])?\s*="
    r")"
)

_STATE_CONTEXT_RE = re.compile(
    r"(?i)(processed|consumed|nonce|lock|locked|claimed|settled|completed|used|pending)"
)


def _line_for_offset(start_line: int, body_text: str, offset: int) -> int:
    return start_line + body_text[:offset].count("\n")


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
        fn_text = engine.text(fn)

        send_match = _BANK_SEND_RE.search(body_text)
        if not send_match:
            continue
        if not (_PATH_NAME_RE.search(name) or _STATE_CONTEXT_RE.search(fn_text)):
            continue

        post_send = body_text[send_match.end():]
        state_match = _STATE_MARK_RE.search(post_send)
        if not state_match:
            continue

        fn_line = engine.line(fn)
        send_line = _line_for_offset(fn_line, body_text, send_match.start())
        state_line = _line_for_offset(fn_line, body_text, send_match.end() + state_match.start())

        hits.append({
            "severity": "high",
            "line": send_line,
            "col": engine.col(fn),
            "snippet": fn_text.splitlines()[0][:160],
            "message": (
                f"`{name}` moves funds with the bank keeper at line {send_line} "
                f"before committing module-local consumed or nonce or processed "
                f"or lock state at line {state_line}. Commit payout markers "
                f"before SendCoins* to avoid stale-state cross-contract "
                f"reentrancy windows. (class: reentrancy-cross-contract)"
            ),
        })

    return hits
