#!/usr/bin/env python3
"""Phase-A production-path planner/checker for Cosmos app-chain PoCs.

This tool is intentionally narrower than a harness generator. It reads an
optional PoC directory plus optional claim text and emits the concrete
production-path requirements a Cosmos app-chain PoC must satisfy before it can
support HIGH+ node-level claims:

  * real persistent DB backend, not MemDB-only
  * no reflection/unsafe/private runtime-state injection
  * block execution through FinalizeBlock plus Commit, or a documented helper
    that wraps both (for example dYdX TestApp.AdvanceToBlock)
  * restart behavior via close and reopen
  * multi-validator evidence when the claim is network-level

Exit codes:
  0 - ready, advisory/not-applicable, or planner-only output
  1 - missing or violated required evidence
  2 - input error
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.cosmos_production_harness_plan.v1"
TOOL = "cosmos-production-harness-plan"

REAL_BACKEND_RE = re.compile(
    r"\b(?:dbm\.NewGoLevelDB|dbm\.NewPebbleDB|"
    r"db\.NewGoLevelDB|db\.NewPebbleDB|"
    r"cosmos-db\.NewGoLevelDB|cosmos-db\.NewPebbleDB|"
    r"GoLevelDBBackend|PebbleDBBackend)\b"
)
MEMDB_RE = re.compile(r"\b(?:dbm\.NewMemDB|db\.NewMemDB|cosmos-db\.NewMemDB)\b")

PRIVATE_STATE_RE = re.compile(
    r"\b(?:legacyLatestVersion|latestVersion|iavl|nodedb|rootmulti|baseapp|"
    r"commitInfo|orphan|pruning|internal[-_ ]?key|raw[-_ ]?store[-_ ]?key|"
    r"private[-_ ]?state|synthetic[-_ ]?state)\b",
    re.IGNORECASE,
)
REFLECTION_WRITE_RE = re.compile(
    r"\b(?:reflect\.NewAt|unsafe\.Pointer|"
    r"\.FieldByName\s*\(|\.Set(?:String|Int|Uint|Bytes|Bool)?\s*\(|"
    r"\b(?:Batch\.Set|batch\.Set|db\.Set|nodeDB\.Set|store\.Set|rootStore\.Set|"
    r"SetSyncInfo|SetLatestVersion|SetLegacyLatestVersion|setLegacyLatestVersion)\s*\()",
    re.IGNORECASE,
)

FINALIZE_BLOCK_RE = re.compile(r"\bFinalizeBlock\s*\(")
COMMIT_RE = re.compile(r"\bCommit\s*\(")
BLOCK_HELPER_RE = re.compile(r"\bAdvanceToBlock\s*\(")

CLOSE_RE = re.compile(r"\bClose\s*\(")
REOPEN_RE = re.compile(
    r"\b(?:Reopen|Restart|OpenDB|NewGoLevelDB|NewPebbleDB|NewRocksDB|"
    r"openValidator|reopen)\b"
)

NETWORK_CLAIM_RE = re.compile(
    r"\b(?:network-level|multi-validator|multivalidator|consensus halt|"
    r"chain halt|validator-cluster halt|apphash divergence|"
    r"block production|liveness failure)\b",
    re.IGNORECASE,
)
MULTI_VALIDATOR_RE = re.compile(
    r"\b(?:NumValidators\s*(?:[:=]|=)\s*(?:[2-9]|\d{2,})|"
    r"numValidators\s*(?:[:=]|=)\s*(?:[2-9]|\d{2,})|"
    r"validators\s*(?:[:=]|=)\s*(?:[2-9]|\d{2,}))\b"
)
MULTI_VALIDATOR_SUPPORT_RE = re.compile(r"\b(?:BroadcastTxSync\s*\(|testutil/network|network\.New\s*\()")

SKIP_DIRS = {
    ".git",
    "node_modules",
    "vendor",
    "testdata",
    "build",
    "dist",
    "out",
    "cache",
    "__pycache__",
}


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _go_files(poc_dir: Path | None) -> list[Path]:
    if poc_dir is None:
        return []
    files: list[Path] = []
    for path in sorted(poc_dir.rglob("*.go")):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        files.append(path)
    return files


def _line_hits(path: Path, pattern: re.Pattern[str]) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    try:
        text = _read_text(path)
    except Exception:
        return hits
    for line_no, line in enumerate(text.splitlines(), start=1):
        if pattern.search(line):
            hits.append({"path": str(path), "line": line_no, "text": line.strip()[:220]})
    return hits


def _combined_text(files: list[Path]) -> str:
    chunks: list[str] = []
    for path in files:
        try:
            chunks.append(_read_text(path))
        except Exception:
            pass
    return "\n".join(chunks)


def _requirement(
    req_id: str,
    status: str,
    summary: str,
    evidence: list[dict[str, Any]] | None = None,
    remediation: str = "",
    required: bool = True,
) -> dict[str, Any]:
    return {
        "id": req_id,
        "required": required,
        "status": status,
        "summary": summary,
        "evidence": evidence or [],
        "remediation": remediation,
    }


def _check_real_backend(files: list[Path]) -> dict[str, Any]:
    backend_hits: list[dict[str, Any]] = []
    memdb_hits: list[dict[str, Any]] = []
    for path in files:
        backend_hits.extend(_line_hits(path, REAL_BACKEND_RE))
        memdb_hits.extend(_line_hits(path, MEMDB_RE))
    if backend_hits:
        return _requirement(
            "real_db_backend",
            "satisfied",
            "PoC uses a persistent production-profile DB backend.",
            backend_hits[:8],
        )
    if memdb_hits:
        return _requirement(
            "real_db_backend",
            "violated",
            "PoC is MemDB-only; this cannot support production-profile evidence.",
            memdb_hits[:8],
            "Use GoLevelDB or PebbleDB on a filesystem tempdir.",
        )
    return _requirement(
        "real_db_backend",
        "missing",
        "No persistent DB backend signal found.",
        remediation="Instantiate GoLevelDB or PebbleDB from the PoC setup.",
    )


def _check_private_state(files: list[Path]) -> dict[str, Any]:
    hits: list[dict[str, Any]] = []
    for path in files:
        try:
            text = _read_text(path)
        except Exception:
            continue
        if PRIVATE_STATE_RE.search(text) and REFLECTION_WRITE_RE.search(text):
            hits.extend(_line_hits(path, REFLECTION_WRITE_RE))
    if hits:
        return _requirement(
            "no_private_state_injection",
            "violated",
            "PoC writes or mutates private runtime state via reflection/unsafe/raw store access.",
            hits[:8],
            "Drive state through public app, ABCI, tx, keeper, or documented test-network APIs only.",
        )
    return _requirement(
        "no_private_state_injection",
        "satisfied" if files else "missing",
        "No private runtime-state injection signal found." if files else "No Go files were provided to inspect.",
        remediation="" if files else "Provide the PoC Go package for source inspection.",
    )


def _check_block_execution(files: list[Path]) -> dict[str, Any]:
    finalize_hits: list[dict[str, Any]] = []
    commit_hits: list[dict[str, Any]] = []
    helper_hits: list[dict[str, Any]] = []
    for path in files:
        finalize_hits.extend(_line_hits(path, FINALIZE_BLOCK_RE))
        commit_hits.extend(_line_hits(path, COMMIT_RE))
        helper_hits.extend(_line_hits(path, BLOCK_HELPER_RE))
    if finalize_hits and commit_hits:
        return _requirement(
            "finalize_block_commit",
            "satisfied",
            "PoC explicitly drives FinalizeBlock and Commit.",
            (finalize_hits + commit_hits)[:8],
        )
    if helper_hits:
        return _requirement(
            "finalize_block_commit",
            "satisfied",
            "PoC uses a documented app helper that wraps FinalizeBlock and Commit.",
            helper_hits[:8],
        )
    return _requirement(
        "finalize_block_commit",
        "missing",
        "No FinalizeBlock+Commit or AdvanceToBlock-style production-path block driver found.",
        remediation="Drive the claim through FinalizeBlock followed by Commit, or cite a helper that wraps both.",
    )


def _check_restart(files: list[Path]) -> dict[str, Any]:
    close_hits: list[dict[str, Any]] = []
    reopen_hits: list[dict[str, Any]] = []
    for path in files:
        close_hits.extend(_line_hits(path, CLOSE_RE))
        reopen_hits.extend(_line_hits(path, REOPEN_RE))
    if close_hits and reopen_hits:
        return _requirement(
            "restart_behavior",
            "satisfied",
            "PoC includes close plus reopen/restart behavior.",
            (close_hits + reopen_hits)[:8],
        )
    return _requirement(
        "restart_behavior",
        "missing",
        "No close plus reopen/restart sequence found.",
        remediation="Close the app/DB/node, reopen from the same data directory, then replay or assert the post-restart state.",
    )


def _check_multival(files: list[Path], claim_text: str, network_claim: bool) -> dict[str, Any]:
    claimed = bool(network_claim or NETWORK_CLAIM_RE.search(claim_text))
    if not claimed:
        return _requirement(
            "multi_validator_if_claimed",
            "not_applicable",
            "No network-level claim signal found.",
            required=False,
        )
    hits: list[dict[str, Any]] = []
    support_hits: list[dict[str, Any]] = []
    for path in files:
        hits.extend(_line_hits(path, MULTI_VALIDATOR_RE))
        support_hits.extend(_line_hits(path, MULTI_VALIDATOR_SUPPORT_RE))
    if hits:
        return _requirement(
            "multi_validator_if_claimed",
            "satisfied",
            "Network-level claim has an explicit >=2-validator evidence signal.",
            (hits + support_hits)[:8],
        )
    return _requirement(
        "multi_validator_if_claimed",
        "missing",
        "Network-level claim lacks >=2-validator or equivalent subprocess-node evidence.",
        remediation="Use at least two validators/nodes, e.g. NumValidators >= 2 with BroadcastTxSync or equivalent node processes.",
    )


def build_plan(
    poc_dir: Path | None,
    claim_text: str = "",
    network_claim: bool = False,
) -> dict[str, Any]:
    files = _go_files(poc_dir)
    requirements = [
        _check_real_backend(files),
        _check_private_state(files),
        _check_block_execution(files),
        _check_restart(files),
        _check_multival(files, claim_text, network_claim),
    ]
    blocking = [
        req
        for req in requirements
        if req["required"] and req["status"] in {"missing", "violated"}
    ]
    verdict = "ready" if not blocking else "needs_work"
    if poc_dir is None:
        verdict = "planner_only"
    return {
        "schema": SCHEMA,
        "tool": TOOL,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "poc_dir": str(poc_dir) if poc_dir is not None else "",
        "go_files_scanned": len(files),
        "claim_signals": {
            "network_claim": bool(network_claim or NETWORK_CLAIM_RE.search(claim_text)),
        },
        "verdict": verdict,
        "requirements": requirements,
        "production_path_requirements": [
            {
                "id": req["id"],
                "status": req["status"],
                "remediation": req["remediation"],
            }
            for req in blocking
        ],
        "advisory_boundary": (
            "Phase-A planner/checker only. A ready verdict means required source-level "
            "signals are present; it is not proof that the PoC compiles, executes, or "
            "establishes impact."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--poc-dir", type=Path, help="Cosmos PoC Go package directory to inspect.")
    parser.add_argument("--claim-file", type=Path, help="Optional draft/claim text used to detect network-level claims.")
    parser.add_argument("--claim-text", default="", help="Inline claim text used to detect network-level claims.")
    parser.add_argument("--network-claim", action="store_true", help="Force the multi-validator requirement on.")
    args = parser.parse_args(argv)

    poc_dir = args.poc_dir.expanduser().resolve() if args.poc_dir else None
    if poc_dir is not None and not poc_dir.is_dir():
        print(json.dumps({"schema": SCHEMA, "tool": TOOL, "error": "poc-dir not found", "poc_dir": str(poc_dir)}, indent=2))
        return 2

    claim_text = args.claim_text or ""
    if args.claim_file:
        claim_file = args.claim_file.expanduser().resolve()
        if not claim_file.is_file():
            print(json.dumps({"schema": SCHEMA, "tool": TOOL, "error": "claim-file not found", "claim_file": str(claim_file)}, indent=2))
            return 2
        claim_text += "\n" + _read_text(claim_file)

    payload = build_plan(poc_dir, claim_text=claim_text, network_claim=args.network_claim)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 1 if payload["verdict"] == "needs_work" else 0


if __name__ == "__main__":
    raise SystemExit(main())
