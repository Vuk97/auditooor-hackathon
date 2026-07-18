#!/usr/bin/env python3
"""Advisory Go scanner for refund/key-tweak survivability surfaces.

Spark generalized lesson: persisted refund transactions can survive key-share
tweaks or verifying-key transitions unless the code has an explicit
invalidation/revocation/clear path. This is a grep-grade DLT scanner, not a Go
parser and not a submission-ready claim.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


TOOL = "go-refund-tweak-survivability-scan"
POSTURE = "NOT_SUBMIT_READY"
SKIP_DIRS = {".git", "vendor", "node_modules", "__pycache__"}

VERIFYING_KEY_RE = re.compile(
    r"\bverifying[_\-\s]?(?:pub(?:lic)?[_\-\s]?)?key\b"
    r"|\bVerifyingPub(?:lic)?Key\b"
    r"|\bVerifyingPubkey\b"
    r"|\bVerifyingKey\b",
    re.IGNORECASE,
)
SCHEMA_OR_IMMUTABLE_RE = re.compile(
    r"`[^`]*(?:json|db|bson|gorm):\"[^\"]*verifying"
    r"|column\s*:\s*verifying"
    r"|\bimmutable\b"
    r"|\bset[-_\s]?once\b"
    r"|\bstatechain\b"
    r"|\btype\s+[A-Za-z0-9_]*\s+struct\b"
    r"|\bVerifyingPub(?:lic)?Key\b"
    r"|\bVerifyingPubkey\b",
    re.IGNORECASE,
)
KEY_SHARE_TWEAK_RE = re.compile(
    r"\b(?:Apply|Add|Update|Derive|Rotate|Tweak)[A-Za-z0-9_]*(?:KeyShare|Share|PubKey|PrivateKey|Tweak)\b"
    r"|\b(?:key[_\-\s]?share|share|pubkey|privatekey)[A-Za-z0-9_]*\b.*\btweak\b"
    r"|\btweak\b.*\b(?:key[_\-\s]?share|share|pubkey|privatekey)\b"
    r"|\badditive[_\-\s]?tweak\b"
    r"|\bTweakKeyShare\b",
    re.IGNORECASE,
)
REFUND_RE = re.compile(
    r"\b(?:raw|signed)?[_\-\s]?refund[_\-\s]?(?:tx|transaction)\b"
    r"|\bRefund(?:Tx|Transaction)\b"
    r"|\bRawRefundTx\b"
    r"|\bSignedRefundTx\b",
    re.IGNORECASE,
)
PERSISTENCE_RE = re.compile(
    r"\b(?:save|store|persist|put|insert|update|write|create|record|upsert)\b"
    r"|`[^`]*(?:json|db|bson|gorm):\"[^\"]*refund"
    r"|\b(?:sql|gorm|bolt|badger|leveldb|repository|repo|database|db)\b",
    re.IGNORECASE,
)
INVALIDATE_RE = re.compile(
    r"\b(?:invalidate|revoke|clear|delete|drop|expire|cancel|void|reset)[A-Za-z0-9_]*(?:Refund|RefundTx|RefundTransaction)\b"
    r"|\b(?:invalidate|revoke|clear|delete|drop|expire|cancel|void|reset)\b.*\brefund[_\-\s]?(?:tx|transaction)\b"
    r"|\brefund[_\-\s]?(?:tx|transaction)\b.*\b(?:invalidated|revoked|cleared|deleted|expired|cancelled|voided|null)\b",
    re.IGNORECASE,
)
STATECHAIN_RE = re.compile(r"\bstatechain\b|\bstate[_\-\s]?chain\b", re.IGNORECASE)


def _snippet(line: str, limit: int = 180) -> str:
    text = " ".join(line.strip().split())
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."


def _evidence(path: Path, root: Path, line_no: int, line: str, token: str) -> dict[str, Any]:
    try:
        file_name = str(path.relative_to(root))
    except ValueError:
        file_name = str(path)
    return {"file": file_name, "line": line_no, "token": token, "snippet": _snippet(line)}


def _append_unique(bucket: list[dict[str, Any]], item: dict[str, Any]) -> None:
    key = (item["file"], item["line"], item["token"])
    if all((old["file"], old["line"], old["token"]) != key for old in bucket):
        bucket.append(item)


def _go_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root] if root.suffix == ".go" else []

    out: list[Path] = []
    for path in sorted(root.rglob("*.go")):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        out.append(path)
    return out


def scan_workspace(root: Path) -> dict[str, Any]:
    root = root.resolve()
    signals: dict[str, list[dict[str, Any]]] = {
        "statechain_context": [],
        "verifying_key_schema": [],
        "key_share_tweak": [],
        "refund_tx_persistence": [],
        "refund_invalidation": [],
    }

    files = _go_files(root)
    for path in files:
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue

        for line_no, line in enumerate(lines, start=1):
            if match := STATECHAIN_RE.search(line):
                _append_unique(signals["statechain_context"], _evidence(path, root, line_no, line, match.group(0)))

            verifying_match = VERIFYING_KEY_RE.search(line)
            if verifying_match and SCHEMA_OR_IMMUTABLE_RE.search(line):
                _append_unique(
                    signals["verifying_key_schema"],
                    _evidence(path, root, line_no, line, verifying_match.group(0)),
                )

            if match := KEY_SHARE_TWEAK_RE.search(line):
                _append_unique(signals["key_share_tweak"], _evidence(path, root, line_no, line, match.group(0)))

            refund_match = REFUND_RE.search(line)
            if refund_match and PERSISTENCE_RE.search(line):
                _append_unique(
                    signals["refund_tx_persistence"],
                    _evidence(path, root, line_no, line, refund_match.group(0)),
                )

            if match := INVALIDATE_RE.search(line):
                _append_unique(signals["refund_invalidation"], _evidence(path, root, line_no, line, match.group(0)))

    signal_counts = {name: len(items) for name, items in signals.items()}
    cooccurrence_present = all(
        signal_counts[name] > 0 for name in ("verifying_key_schema", "key_share_tweak", "refund_tx_persistence")
    )
    invalidation_present = signal_counts["refund_invalidation"] > 0

    findings: list[dict[str, Any]] = []
    if cooccurrence_present and not invalidation_present:
        findings.append(
            {
                "pattern": "go_refund_tweak_survivability_surface_without_refund_revocation",
                "posture": POSTURE,
                "advisory_only": True,
                "submission_ready": False,
                "workspace": str(root),
                "summary": (
                    "Go workspace contains verifying-pubkey schema, key-share tweak/update helpers, and persisted "
                    "refund transaction signals, but no explicit refund invalidation/revocation/clear path was detected."
                ),
                "refund_invalidation_path_present": False,
                "signal_counts": signal_counts,
                "evidence": {name: items[:8] for name, items in signals.items()},
                "next_steps": [
                    "Manually trace whether persisted refund transactions are recomputed or revoked after key-share tweaks.",
                    "Confirm whether verifying_pubkey records are immutable across the statechain lifecycle.",
                    "Look for protocol-level expiry or database cleanup outside Go before treating this as reportable.",
                ],
            }
        )

    return {
        "tool": TOOL,
        "posture": POSTURE,
        "advisory_only": True,
        "submission_ready": False,
        "workspace": str(root),
        "files_scanned": len(files),
        "cooccurrence_present": cooccurrence_present,
        "refund_invalidation_path_present": invalidation_present,
        "signals": {name: items[:20] for name, items in signals.items()},
        "findings": findings,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Advisory-only JSON scanner for Go refund/key-tweak survivability surfaces."
    )
    parser.add_argument("workspace", type=Path, help="Go workspace, directory, or file")
    parser.add_argument("--json", action="store_true", help="Accepted for consistency; output is always JSON.")
    args = parser.parse_args()

    print(json.dumps(scan_workspace(args.workspace), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
