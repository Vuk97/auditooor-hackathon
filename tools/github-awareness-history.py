#!/usr/bin/env python3
"""Snapshot GitHub history for mandatory awareness review.

This is an intake producer, not a classifier.  It enumerates every open and
closed issue and pull request, their issue comments and reviews, and GitHub
Discussions when enabled.  The resulting source rows are pin-bound inputs to
semantic review; no text pattern in this tool can make an item out of scope.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable


SCHEMA = "auditooor.github_awareness_history.v1"
SOURCE_KINDS = frozenset({"pull_request", "issue", "discussion", "review_comment"})


class HistoryError(RuntimeError):
    pass


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _hash(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _text(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def _gh_json(args: list[str]) -> Any:
    result = subprocess.run(
        ["gh", "api", *args], text=True, capture_output=True, check=False
    )
    if result.returncode:
        raise HistoryError(f"github_api_failed:{result.stderr.strip() or result.stdout.strip()}")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise HistoryError("github_api_malformed_json") from exc


def _rest_pages(api: Callable[[list[str]], Any], endpoint: str) -> list[dict[str, Any]]:
    """Read all REST pages through gh's JSON slurp mode."""
    value = api(["--paginate", "--slurp", endpoint])
    if not isinstance(value, list) or any(not isinstance(page, list) for page in value):
        raise HistoryError(f"github_api_pages_malformed:{endpoint}")
    return [row for page in value for row in page if isinstance(row, dict)]


def _source(
    repo: str, audit_pin: str, kind: str, stable_id: str, ref: str, payload: dict[str, Any]
) -> dict[str, str]:
    if kind not in SOURCE_KINDS or not stable_id or not ref:
        raise HistoryError("github_history_source_malformed")
    return {
        "source_id": f"github:{repo}:{kind}:{stable_id}",
        "source_kind": kind,
        "source_ref": ref,
        "pin_binding": audit_pin,
        "snapshot_sha256": _hash(payload),
    }


def _discussion_pages(api: Callable[[list[str]], Any], repo: str) -> list[dict[str, Any]]:
    """Enumerate every GitHub Discussion via GraphQL cursors when enabled."""
    owner, name = repo.split("/", 1)
    query = """query($owner:String!,$name:String!,$cursor:String) {
      repository(owner:$owner,name:$name) {
        discussions(first:100,after:$cursor) {
          nodes { id number url title body createdAt updatedAt author { login } }
          pageInfo { hasNextPage endCursor }
        }
      }
    }"""
    cursor: str | None = None
    rows: list[dict[str, Any]] = []
    while True:
        args = ["graphql", "-f", f"query={query}", "-F", f"owner={owner}", "-F", f"name={name}"]
        if cursor:
            args.extend(["-F", f"cursor={cursor}"])
        payload = api(args)
        connection = (((payload.get("data") if isinstance(payload, dict) else {}) or {}).get("repository") or {}).get("discussions")
        if not isinstance(connection, dict):
            raise HistoryError("github_discussions_malformed")
        nodes = connection.get("nodes")
        page_info = connection.get("pageInfo")
        if not isinstance(nodes, list) or not isinstance(page_info, dict):
            raise HistoryError("github_discussions_malformed")
        rows.extend(row for row in nodes if isinstance(row, dict))
        if not page_info.get("hasNextPage"):
            return rows
        cursor = _text(page_info.get("endCursor"))
        if not cursor:
            raise HistoryError("github_discussions_missing_cursor")


def _discussion_comment_pages(api: Callable[[list[str]], Any], repo: str, number: int) -> list[dict[str, Any]]:
    """Enumerate every top-level Discussion comment with GraphQL cursors."""
    owner, name = repo.split("/", 1)
    query = """query($owner:String!,$name:String!,$number:Int!,$cursor:String) {
      repository(owner:$owner,name:$name) { discussion(number:$number) {
        comments(first:100,after:$cursor) {
          nodes { id url body createdAt updatedAt author { login } }
          pageInfo { hasNextPage endCursor }
        }
      }}
    }"""
    cursor: str | None = None
    rows: list[dict[str, Any]] = []
    while True:
        args = ["graphql", "-f", f"query={query}", "-F", f"owner={owner}", "-F", f"name={name}", "-F", f"number={number}"]
        if cursor:
            args.extend(["-F", f"cursor={cursor}"])
        payload = api(args)
        discussion = (((payload.get("data") if isinstance(payload, dict) else {}) or {}).get("repository") or {}).get("discussion")
        connection = discussion.get("comments") if isinstance(discussion, dict) else None
        if not isinstance(connection, dict):
            raise HistoryError("github_discussion_comments_malformed")
        nodes, page_info = connection.get("nodes"), connection.get("pageInfo")
        if not isinstance(nodes, list) or not isinstance(page_info, dict):
            raise HistoryError("github_discussion_comments_malformed")
        rows.extend(row for row in nodes if isinstance(row, dict))
        if not page_info.get("hasNextPage"):
            return rows
        cursor = _text(page_info.get("endCursor"))
        if not cursor:
            raise HistoryError("github_discussion_comments_missing_cursor")


def _discussion_reply_pages(api: Callable[[list[str]], Any], comment_id: str) -> list[dict[str, Any]]:
    """Enumerate every reply to one Discussion comment with GraphQL cursors."""
    query = """query($commentId:ID!,$cursor:String) {
      node(id:$commentId) { ... on DiscussionComment {
        replies(first:100,after:$cursor) {
          nodes { id url body createdAt updatedAt author { login } }
          pageInfo { hasNextPage endCursor }
        }
      }}
    }"""
    cursor: str | None = None
    rows: list[dict[str, Any]] = []
    while True:
        args = ["graphql", "-f", f"query={query}", "-F", f"commentId={comment_id}"]
        if cursor:
            args.extend(["-F", f"cursor={cursor}"])
        payload = api(args)
        node = ((payload.get("data") if isinstance(payload, dict) else {}) or {}).get("node")
        connection = node.get("replies") if isinstance(node, dict) else None
        if not isinstance(connection, dict):
            raise HistoryError("github_discussion_replies_malformed")
        nodes, page_info = connection.get("nodes"), connection.get("pageInfo")
        if not isinstance(nodes, list) or not isinstance(page_info, dict):
            raise HistoryError("github_discussion_replies_malformed")
        rows.extend(row for row in nodes if isinstance(row, dict))
        if not page_info.get("hasNextPage"):
            return rows
        cursor = _text(page_info.get("endCursor"))
        if not cursor:
            raise HistoryError("github_discussion_replies_missing_cursor")


def collect(repo: str, audit_pin: str, *, api: Callable[[list[str]], Any] = _gh_json) -> dict[str, Any]:
    """Return a complete GitHub awareness snapshot for one repository."""
    if "/" not in repo or not _text(audit_pin):
        raise HistoryError("github_history_repo_or_pin_invalid")
    metadata = api([f"repos/{repo}"])
    if not isinstance(metadata, dict):
        raise HistoryError("github_repository_metadata_malformed")

    issues_and_prs = _rest_pages(api, f"repos/{repo}/issues?state=all&per_page=100")
    sources: list[dict[str, str]] = []
    coverage = {kind: {"status": "complete", "count": 0} for kind in SOURCE_KINDS}
    pull_numbers: list[int] = []
    for row in issues_and_prs:
        number = row.get("number")
        if not isinstance(number, int):
            raise HistoryError("github_issue_number_malformed")
        is_pr = isinstance(row.get("pull_request"), dict)
        kind = "pull_request" if is_pr else "issue"
        ref = _text(row.get("html_url") or row.get("url"))
        sources.append(_source(repo, audit_pin, kind, str(number), ref, row))
        coverage[kind]["count"] += 1
        comments = _rest_pages(api, f"repos/{repo}/issues/{number}/comments?per_page=100")
        for comment in comments:
            comment_id = _text(comment.get("id"))
            comment_ref = _text(comment.get("html_url") or comment.get("url"))
            sources.append(_source(repo, audit_pin, "discussion", f"issue-comment-{comment_id}", comment_ref, comment))
            coverage["discussion"]["count"] += 1
        if is_pr:
            pull_numbers.append(number)

    for number in pull_numbers:
        reviews = _rest_pages(api, f"repos/{repo}/pulls/{number}/reviews?per_page=100")
        review_comments = _rest_pages(api, f"repos/{repo}/pulls/{number}/comments?per_page=100")
        for review in reviews:
            review_id = _text(review.get("id"))
            review_ref = _text(review.get("html_url") or review.get("url"))
            sources.append(_source(repo, audit_pin, "review_comment", f"review-{review_id}", review_ref, review))
            coverage["review_comment"]["count"] += 1
        for comment in review_comments:
            comment_id = _text(comment.get("id"))
            comment_ref = _text(comment.get("html_url") or comment.get("url"))
            sources.append(_source(repo, audit_pin, "review_comment", f"review-comment-{comment_id}", comment_ref, comment))
            coverage["review_comment"]["count"] += 1

    discussion_threads: dict[str, Any]
    if metadata.get("has_discussions") is True:
        discussions = _discussion_pages(api, repo)
        for discussion in discussions:
            discussion_id = _text(discussion.get("id") or discussion.get("number"))
            discussion_ref = _text(discussion.get("url"))
            sources.append(_source(repo, audit_pin, "discussion", f"discussion-{discussion_id}", discussion_ref, discussion))
            coverage["discussion"]["count"] += 1
            number = discussion.get("number")
            if not isinstance(number, int):
                raise HistoryError("github_discussion_number_malformed")
            for comment in _discussion_comment_pages(api, repo, number):
                comment_id = _text(comment.get("id"))
                comment_ref = _text(comment.get("url"))
                sources.append(_source(repo, audit_pin, "discussion", f"discussion-comment-{comment_id}", comment_ref, comment))
                coverage["discussion"]["count"] += 1
                for reply in _discussion_reply_pages(api, comment_id):
                    reply_id = _text(reply.get("id"))
                    reply_ref = _text(reply.get("url"))
                    sources.append(_source(repo, audit_pin, "discussion", f"discussion-reply-{reply_id}", reply_ref, reply))
                    coverage["discussion"]["count"] += 1
        discussion_threads = {"status": "complete", "count": len(discussions)}
    else:
        discussion_threads = {"status": "not_applicable", "count": 0, "reason": "github_discussions_disabled"}

    ids = [row["source_id"] for row in sources]
    if len(ids) != len(set(ids)):
        raise HistoryError("github_history_duplicate_source_id")
    return {
        "schema": SCHEMA,
        "repository": repo,
        "audit_pin": audit_pin,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "coverage": coverage,
        "discussion_threads": discussion_threads,
        "sources": sorted(sources, key=lambda row: row["source_id"]),
    }


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repo", required=True, help="GitHub owner/repository")
    parser.add_argument("--audit-pin", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        payload = collect(args.repo, args.audit_pin)
    except HistoryError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"ok": True, "source_count": len(payload["sources"]), "output": str(args.output)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
