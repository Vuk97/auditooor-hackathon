#!/usr/bin/env python3
"""Validate human or agent semantic review decisions for extracted source comments.

This tool never infers a disposition from comment text. The reconciliation step
first extracts every source comment and writes its current source snapshot. A
reviewer then reads those comments in context and supplies one explicit decision
per comment. This adapter validates completeness, reviewer attribution, and the
snapshot binding before publishing the analysis consumed by OOS gates.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping


SCHEMA = "auditooor.source_comment_analysis.v2"
DECISION_SCHEMA = "auditooor.source_comment_review_decisions.v1"
TERMINAL = frozenset({
    "ordinary-comment",
    "known-issue-oos",
    "planned-remediation-oos",
    "risk-accepted-oos",
    "wont-fix-oos",
    "duplicate-oos",
    "claimed-fixed-verified",
    "claimed-fixed-disproved",
    "not-applicable",
})
FIXED_DISPOSITIONS = frozenset({"claimed-fixed-verified", "claimed-fixed-disproved"})


class ReviewError(RuntimeError):
    """Fail-closed source-comment semantic-review error."""


def _snapshot(comments: list[Mapping[str, Any]]) -> str:
    digest = hashlib.sha256()
    for source_file in sorted({str(row.get("source_file") or "") for row in comments}):
        if not source_file:
            continue
        digest.update(source_file.encode("utf-8"))
        digest.update(b"\0")
        try:
            digest.update(Path(source_file).read_bytes())
        except OSError as exc:
            raise ReviewError("source_comment_review_source_missing") from exc
        digest.update(b"\0")
    return digest.hexdigest()


def _load_object(path: Path, code: str) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise ReviewError(code)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReviewError(code + "_malformed") from exc
    if not isinstance(value, dict):
        raise ReviewError(code + "_malformed")
    return value


def validate_review_decisions(comments: list[Mapping[str, Any]], decisions: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Return complete reviewer decisions without lexical classification."""
    if decisions.get("schema") != DECISION_SCHEMA:
        raise ReviewError("source_comment_review_decisions_schema_invalid")
    expected_snapshot = _snapshot(comments)
    if decisions.get("source_snapshot_sha256") != expected_snapshot:
        raise ReviewError("source_comment_review_snapshot_mismatch")
    rows = decisions.get("decisions")
    if not isinstance(rows, list):
        raise ReviewError("source_comment_review_decisions_missing")
    comments_by_id = {
        str(comment.get("comment_id")): comment
        for comment in comments
        if isinstance(comment, Mapping) and isinstance(comment.get("comment_id"), str) and comment.get("comment_id")
    }
    reviewed_by_id: dict[str, dict[str, Any]] = {}
    for number, raw in enumerate(rows, start=1):
        if not isinstance(raw, Mapping):
            raise ReviewError(f"source_comment_review_decision_malformed:row-{number}")
        comment_id = raw.get("comment_id")
        if not isinstance(comment_id, str) or comment_id not in comments_by_id:
            raise ReviewError(f"source_comment_review_comment_unknown:row-{number}")
        if comment_id in reviewed_by_id:
            raise ReviewError(f"source_comment_review_comment_duplicate:{comment_id}")
        disposition = raw.get("disposition")
        if disposition not in TERMINAL:
            raise ReviewError(f"source_comment_review_disposition_invalid:{comment_id}")
        required = ("reviewer_id", "reviewed_at", "review_method", "rationale")
        if any(not isinstance(raw.get(field), str) or not raw[field].strip() for field in required):
            raise ReviewError(f"source_comment_review_attribution_incomplete:{comment_id}")
        evidence = raw.get("current_code_evidence")
        if disposition in FIXED_DISPOSITIONS and (not isinstance(evidence, str) or not evidence.strip()):
            raise ReviewError(f"source_comment_review_fixed_evidence_missing:{comment_id}")
        decision = {
            "comment_id": comment_id,
            "disposition": disposition,
            "rationale": raw["rationale"].strip(),
            "reviewer_id": raw["reviewer_id"].strip(),
            "reviewed_at": raw["reviewed_at"].strip(),
            "review_method": raw["review_method"].strip(),
        }
        if isinstance(evidence, str) and evidence.strip():
            decision["current_code_evidence"] = evidence.strip()
        reviewed_by_id[comment_id] = decision
    expected_ids = set(comments_by_id)
    observed_ids = set(reviewed_by_id)
    if expected_ids != observed_ids:
        missing = sorted(expected_ids - observed_ids)
        stale = sorted(observed_ids - expected_ids)
        raise ReviewError("source_comment_review_incomplete:" + json.dumps({"missing": missing, "stale": stale}))
    return [reviewed_by_id[comment_id] for comment_id in sorted(reviewed_by_id)]


def run(workspace: Path, decisions_path: Path, output_path: Path) -> dict[str, Any]:
    workspace = workspace.expanduser().resolve()
    reconciliation = _load_object(
        workspace / ".auditooor" / "source_comment_reconciliation.json",
        "source_comment_reconciliation_missing",
    )
    comments = reconciliation.get("comments")
    if not isinstance(comments, list) or any(not isinstance(row, Mapping) for row in comments):
        raise ReviewError("source_comment_reconciliation_comments_invalid")
    decisions = _load_object(decisions_path, "source_comment_review_decisions_missing")
    analyses = validate_review_decisions(comments, decisions)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": SCHEMA,
        "workspace": str(workspace),
        "review_method": "explicit contextual reviewer decisions",
        "source_snapshot_sha256": _snapshot(comments),
        "comment_count": len(comments),
        "analysis_count": len(analyses),
        "analyses": analyses,
    }
    output_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workspace", type=Path)
    parser.add_argument(
        "--decisions",
        type=Path,
        help="complete reviewer decision artifact; defaults to .auditooor/source_comment_review_decisions.json",
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    workspace = args.workspace.expanduser().resolve()
    decisions = args.decisions or workspace / ".auditooor" / "source_comment_review_decisions.json"
    output = args.output or workspace / ".auditooor" / "source_comment_analysis.json"
    try:
        payload = run(workspace, decisions, output)
    except ReviewError as exc:
        raise SystemExit(f"FAIL source-comment-semantic-review: {exc}") from exc
    print(f"pass-source-comment-semantic-review comments={payload['analysis_count']} out={output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
