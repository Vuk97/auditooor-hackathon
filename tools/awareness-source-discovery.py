#!/usr/bin/env python3
"""Build the complete, pin-bound Step 0d awareness review inventory.

This producer composes raw history artifacts only.  It never classifies a
source as known, accepted, fixed, or out of scope.  A missing source stream
causes a failure; an enumerated stream with zero records gets an explicit
reviewable coverage receipt instead of being silently omitted.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable


SCHEMA = "auditooor.awareness_source_discovery.v1"
SOURCE_KINDS = frozenset({
    "prior_audit", "commit", "pull_request", "issue", "discussion",
    "review_comment", "source_comment", "known_issue_list",
})
GITHUB_SCHEMA = "auditooor.github_awareness_history.v1"
MINING_SCHEMAS = frozenset({"auditooor.git_commits_mining.v1", "auditooor.git_commits_mining.v1.2-solidity"})


class DiscoveryError(ValueError):
    pass


def _text(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def _sha(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


def _read(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DiscoveryError(f"awareness_discovery_unreadable:{path}") from exc


def _row(kind: str, source_id: str, source_ref: str, audit_pin: str) -> dict[str, str]:
    if kind not in SOURCE_KINDS or not source_id or not source_ref:
        raise DiscoveryError("awareness_discovery_source_malformed")
    return {"source_id": source_id, "source_kind": kind, "source_ref": source_ref, "pin_binding": audit_pin}


def _github_rows(paths: Iterable[Path], audit_pin: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    paths = list(paths)
    if not paths:
        raise DiscoveryError("github_awareness_history_missing")
    for path in paths:
        payload = _read(path)
        if not isinstance(payload, dict) or payload.get("schema") != GITHUB_SCHEMA or _text(payload.get("audit_pin")) != audit_pin:
            raise DiscoveryError("github_awareness_history_invalid")
        sources = payload.get("sources")
        coverage = payload.get("coverage")
        if not isinstance(sources, list) or not isinstance(coverage, dict):
            raise DiscoveryError("github_awareness_history_invalid")
        for source in sources:
            if not isinstance(source, dict):
                raise DiscoveryError("github_awareness_history_invalid")
            kind = _text(source.get("source_kind"))
            if kind not in {"pull_request", "issue", "discussion", "review_comment"}:
                raise DiscoveryError("github_awareness_history_invalid")
            rows.append(_row(kind, _text(source.get("source_id")), _text(source.get("source_ref")), audit_pin))
        for kind in ("pull_request", "issue", "discussion", "review_comment"):
            state = coverage.get(kind)
            if not isinstance(state, dict) or state.get("status") != "complete":
                raise DiscoveryError(f"github_awareness_history_incomplete:{kind}")
    return rows


def _local_rows(workspace: Path, audit_pin: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    prior = workspace / "prior_audits"
    if not prior.is_dir():
        raise DiscoveryError("prior_audits_missing")
    for path in sorted(item for item in prior.rglob("*") if item.is_file() and item.name != "known_issues.jsonl"):
        content = path.read_bytes()
        if content:
            rel = path.relative_to(workspace).as_posix()
            rows.append(_row("prior_audit", f"prior-audit:{rel}:{hashlib.sha256(content).hexdigest()}", rel, audit_pin))

    known = prior / "known_issues.jsonl"
    if not known.is_file():
        raise DiscoveryError("known_issues_missing")
    for number, line in enumerate(known.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise DiscoveryError("known_issues_malformed")
        stable = _text(value.get("id")) or _sha(value)
        rows.append(_row("known_issue_list", f"known-issue:{stable}", f"prior_audits/known_issues.jsonl:{number}", audit_pin))

    comment_path = workspace / ".auditooor" / "source_comment_reconciliation.json"
    if not comment_path.is_file():
        raise DiscoveryError("source_comment_reconciliation_missing")
    comments = _read(comment_path)
    items = comments.get("comments") if isinstance(comments, dict) else None
    if not isinstance(items, list):
        raise DiscoveryError("source_comment_reconciliation_malformed")
    for comment in items:
        if not isinstance(comment, dict):
            raise DiscoveryError("source_comment_reconciliation_malformed")
        stable = _text(comment.get("comment_id"))
        file_name = _text(comment.get("source_file"))
        line = _text(comment.get("line"))
        rows.append(_row("source_comment", f"source-comment:{stable}", f"{file_name}:{line}", audit_pin))

    mining = sorted(set(workspace.glob(".auditooor/*git_commits_mining*.json")) | set(workspace.glob("mining_rounds/**/*git_commits_mining*.json")))
    if not mining:
        raise DiscoveryError("commit_mining_missing")
    for path in mining:
        payload = _read(path)
        if not isinstance(payload, dict) or payload.get("schema") not in MINING_SCHEMAS or _text(payload.get("audit_pin_sha")) != audit_pin:
            raise DiscoveryError("commit_mining_invalid")
        repository = _text(payload.get("upstream_repo"))
        if not repository or "/" not in repository:
            raise DiscoveryError("commit_mining_repository_invalid")
        inventory = payload.get("commit_inventory")
        if not isinstance(inventory, list):
            raise DiscoveryError("commit_mining_inventory_missing")
        for entry in inventory:
            if not isinstance(entry, dict):
                raise DiscoveryError("commit_mining_invalid")
            sha = _text(entry.get("sha"))
            ref = _text(entry.get("url"))
            if not sha:
                raise DiscoveryError("commit_mining_invalid")
            rows.append(_row(
                "commit",
                f"commit:{repository}:{sha}",
                ref or f"{path.relative_to(workspace).as_posix()}:{repository}:{sha}",
                audit_pin,
            ))
    return rows


def discover(workspace: Path, audit_pin: str, github_paths: Iterable[Path]) -> dict[str, Any]:
    rows = _github_rows(github_paths, audit_pin) + _local_rows(workspace, audit_pin)
    dedup: dict[str, dict[str, str]] = {}
    for row in rows:
        prior = dedup.get(row["source_id"])
        if prior is not None and prior != row:
            raise DiscoveryError(f"awareness_discovery_conflicting_source:{row['source_id']}")
        dedup[row["source_id"]] = row
    by_kind = {kind: 0 for kind in SOURCE_KINDS}
    for row in dedup.values():
        by_kind[row["source_kind"]] += 1
    for kind, count in by_kind.items():
        if count == 0:
            receipt = _row(kind, f"inventory-empty:{kind}", f".auditooor/awareness_source_discovery.json#coverage:{kind}", audit_pin)
            dedup[receipt["source_id"]] = receipt
    return {
        "schema": SCHEMA,
        "workspace": str(workspace),
        "audit_pin": audit_pin,
        "coverage": {kind: {"status": "complete", "source_count": count} for kind, count in sorted(by_kind.items())},
        "sources": sorted(dedup.values(), key=lambda row: row["source_id"]),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--audit-pin", required=True)
    parser.add_argument("--github-history", action="append", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    workspace = args.workspace.expanduser().resolve()
    histories = args.github_history or sorted((workspace / ".auditooor").glob("github_awareness_history*.json"))
    output = args.output or workspace / ".auditooor" / "awareness_source_discovery.json"
    try:
        payload = discover(workspace, args.audit_pin, histories)
    except (DiscoveryError, OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        return 1
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"ok": True, "source_count": len(payload["sources"]), "output": str(output)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
