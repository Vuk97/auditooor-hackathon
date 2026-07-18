"""
go-bridge-destination-settlement-unproven-source-commitment.py

Detects Go bridge settlement handlers that mark a transfer/message id consumed
and release value on the destination side without any visible source-side
commitment verification in the same function body.

Confirmed corpus anchors:
- public-incident:verus-ethereum-bridge:2026-05-17:input-output-mismatch
  (tier-2 verified public archive)
- INV-BRIDGE-P24-025

This detector is intentionally narrow. It only fires when a function:
1. Looks like a bridge settlement / finalize / claim entrypoint.
2. Uses a transfer/message/claim id.
3. Marks that id as processed/used/finalized in a local replay map.
4. Performs a value-bearing side effect.
5. Lacks an obvious source-commitment proof or signature verification call.
"""

from __future__ import annotations

import re

DETECTOR_ID = "go-bridge-destination-settlement-unproven-source-commitment"

_HANDLER_NAME_RE = re.compile(
    r"(?i)(Finalize|Claim|Release|Settle|Execute|Process|Complete|Receive)"
    r".*(Bridge|Transfer|Message|Claim|Withdrawal)?"
    r"|^(OnBridgeReceive|HandleBridgedAsset|CompleteBridgeTransfer)$"
)

_BRIDGE_CONTEXT_RE = re.compile(
    r"(?i)(bridge|cross.?chain|escrow|relayer|transferId|messageId|claimId)"
)

_ID_RE = re.compile(r"\b(?:transferId|messageId|claimId|proofId|txId|nonce)\b")

_REPLAY_MARK_RE = re.compile(
    r"(?i)(?:processed|used|claimed|completed|finalized|nonces)\w*"
    r"\s*\[[^\]]+\]\s*=\s*true"
)

_VALUE_EFFECT_RE = re.compile(
    r"(?i)(SendCoins(?:FromModuleToAccount|FromAccountToModule)?\s*\("
    r"|MintCoins\s*\("
    r"|Transfer\s*\("
    r"|Release\w*\s*\("
    r"|Credit\w*\s*\("
    r"|balances?\w*\s*\[)"
)

_SOURCE_COMMITMENT_RE = re.compile(
    r"(?i)(VerifyMerkleProof\s*\("
    r"|MerkleProof\s*\("
    r"|VerifySignature\s*\("
    r"|verifySignature\s*\("
    r"|ValidateMessage\s*\("
    r"|VerifyMessage\s*\("
    r"|VerifyStorageProof\s*\("
    r"|VerifyStateProof\s*\("
    r"|VerifyVM\s*\("
    r"|CheckProof\s*\("
    r"|VerifyProof\s*\()"
)


def _blank_comment(match: re.Match[str]) -> str:
    return "".join("\n" if ch == "\n" else " " for ch in match.group(0))


def _strip_comments(src: str) -> str:
    src = re.sub(r"//.*", _blank_comment, src)
    return re.sub(r"/\*.*?\*/", _blank_comment, src, flags=re.S)


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
        body_text = _strip_comments(engine.text(body))

        if not (_HANDLER_NAME_RE.search(name) or _BRIDGE_CONTEXT_RE.search(fn_text)):
            continue
        if not _ID_RE.search(fn_text):
            continue
        if not _REPLAY_MARK_RE.search(body_text):
            continue
        if not _VALUE_EFFECT_RE.search(body_text):
            continue
        if _SOURCE_COMMITMENT_RE.search(body_text):
            continue

        hits.append({
            "severity": "high",
            "line": engine.line(fn),
            "col": engine.col(fn),
            "snippet": fn_text.splitlines()[0][:160],
            "message": (
                f"`{name}` marks a bridge transfer/message id consumed and "
                f"releases value without any visible source-commitment proof "
                f"or signature verification in the same body. Destination-side "
                f"bridge settlement must verify the source-side commitment "
                f"before replay marking or payout. "
                f"(class: bridge-proof-domain-bypass)"
            ),
        })

    return hits
