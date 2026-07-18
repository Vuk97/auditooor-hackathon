"""
go-statechain-backup-transaction-stale-fee-rate-unbroadcastable.py

Go statechain detector for the confirmed backup-transaction fee-rate drift
shape: a pre-signed backup tx is built or serialized with a cached fee rate
and no freshness, re-sign, or expiry-warning guard.

Confirmed corpus anchor:
- Mercury Wallet (Statechain) backup-tx fee-rate drift
  (`findings-go:statechain-mercury-backup-tx-fee-rate-class:f32b092d8f25`,
   tier-2 verified public archive)
"""

from __future__ import annotations

import re

DETECTOR_ID = (
    "go_wave1.go-statechain-backup-transaction-stale-fee-rate-unbroadcastable"
)

_STATECHAIN_CONTEXT_RE = re.compile(
    r"(statechain|statecoin|mercury|backup\s*tx|backupTransaction|csv[- ]locked)",
    re.IGNORECASE,
)

_BACKUP_TX_RE = re.compile(
    r"(backup\s*tx|backupTx|backupTransaction|pre[- ]signed|presigned)",
    re.IGNORECASE,
)

_FEE_RATE_RE = re.compile(
    r"(feeRate|fee_rate|FeeRate|fee\s*rate|sat/vB|satPerVByte)",
    re.IGNORECASE,
)

_TX_FLOW_RE = re.compile(
    r"(Build|Create|Prepare|Sign|ReSign|Broadcast|Serialize|Package|Save|"
    r"Store|Update|Refresh|Rebroadcast).*?(backup|tx|fee)|"
    r"backup.*?(Build|Create|Prepare|Sign|Broadcast|Serialize|Update|Refresh)",
    re.IGNORECASE | re.S,
)

_STALE_SNAPSHOT_RE = re.compile(
    r"(fixedAtSigning|signedFeeRate|snapshotFeeRate|storedFeeRate|"
    r"cachedFeeRate|initialFeeRate|feeRateAtSign|signingFeeRate)",
    re.IGNORECASE,
)

_FRESHNESS_GUARD_RE = re.compile(
    r"(refresh.*fee|reSign|resign|warn.*csv|csv.*warn|"
    r"check.*expiry|warnBeforeCSVExpiry|update.*fee|rebroadcast|"
    r"rebuild.*backup)",
    re.IGNORECASE,
)


def _blank_comment(match: re.Match[str]) -> str:
    return "".join("\n" if ch == "\n" else " " for ch in match.group(0))


def _strip_comments(src: str) -> str:
    src = re.sub(r"//.*", _blank_comment, src)
    return re.sub(r"/\*.*?\*/", _blank_comment, src, flags=re.S)


def run(engine, filepath: str):
    hits = []
    path_text = filepath.replace("\\", "/")
    for fn in engine.functions():
        name = engine.fn_name(fn)
        if not name or name == "?":
            continue
        body = engine.fn_body(fn)
        if body is None:
            continue

        fn_text = engine.text(fn)
        body_text = _strip_comments(engine.text(body))
        surface = f"{path_text}\n{fn_text}\n{body_text}"

        if not _STATECHAIN_CONTEXT_RE.search(surface):
            continue
        if not _BACKUP_TX_RE.search(surface):
            continue
        if not _FEE_RATE_RE.search(surface):
            continue
        if not _TX_FLOW_RE.search(surface):
            continue
        if _FRESHNESS_GUARD_RE.search(surface):
            continue
        if not _STALE_SNAPSHOT_RE.search(surface):
            continue

        hits.append({
            "severity": "high",
            "line": engine.line(fn),
            "col": engine.col(fn),
            "snippet": fn_text.splitlines()[0][:160],
            "message": (
                f"`{name}` builds or serializes a backup transaction with a "
                f"cached fee-rate snapshot and no visible re-sign, refresh, "
                f"or expiry-warning guard. Statechain backup txs must be "
                f"re-priced or warned before the CSV window closes. "
                f"(class: backup-transaction-stale-fee-rate-unbroadcastable)"
            ),
        })

    return hits
