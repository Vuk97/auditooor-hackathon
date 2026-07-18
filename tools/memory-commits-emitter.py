#!/usr/bin/env python3
"""Emit one stable vault note per git commit.

This is the narrow event-driven writer for `obsidian-vault/commits/<sha8>.md`.
It is intended for git hook / watcher use on new local commits, while
`memory-deep-crawler.py` remains the backfill path for older history.

Usage:
    python3 tools/memory-commits-emitter.py [--vault-dir <path>]
                                            [--repo-root <path>]
                                            [--head]
                                            [--ref-path <git-ref-file>]
                                            [--sha <sha>]...
                                            [--dry-run]
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
VAULT_DEFAULT = REPO_ROOT / "obsidian-vault"
GIT_HEADS_DIR = REPO_ROOT / ".git" / "refs" / "heads"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
PR_RE = re.compile(r"#(\d+)")
MAX_FILES = 50


class CommitEmitterError(RuntimeError):
    """Raised when git state cannot be resolved into a commit note."""


@dataclass(frozen=True)
class CommitRecord:
    sha: str
    short_sha: str
    authored_at: str
    author: str
    subject: str
    body: str
    parent_count: int
    changed_files: tuple[str, ...]
    pr_refs: tuple[str, ...]

    @property
    def date(self) -> str:
        return self.authored_at[:10]

    @property
    def is_merge(self) -> bool:
        return self.parent_count > 1


@dataclass(frozen=True)
class EmitResult:
    sha: str
    note_path: Path
    status: str


def _git(repo_root: Path, args: list[str], *, timeout: int = 10) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=repo_root,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    if proc.returncode != 0:
        stderr = proc.stderr.strip() or proc.stdout.strip() or "git command failed"
        raise CommitEmitterError(stderr)
    return proc.stdout


def _normalize_sha(repo_root: Path, sha: str) -> str:
    resolved = _git(repo_root, ["rev-parse", "--verify", f"{sha}^{{commit}}"], timeout=5).strip()
    if not SHA_RE.fullmatch(resolved):
        raise CommitEmitterError(f"invalid resolved commit sha: {resolved!r}")
    return resolved


def head_sha(repo_root: Path) -> str:
    return _normalize_sha(repo_root, "HEAD")


def sha_from_ref_path(repo_root: Path, ref_path: Path) -> str:
    path = ref_path.expanduser().resolve()
    try:
        sha = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise CommitEmitterError(f"could not read ref path {path}: {exc}") from exc
    if not sha:
        raise CommitEmitterError(f"empty ref path: {path}")
    return _normalize_sha(repo_root, sha)


def load_commit(repo_root: Path, sha: str) -> CommitRecord:
    resolved = _normalize_sha(repo_root, sha)
    raw = _git(
        repo_root,
        ["show", "--no-patch", "--format=%H%x00%aI%x00%an%x00%s%x00%b%x00%P", resolved],
    ).rstrip("\n")
    parts = raw.split("\x00", 5)
    if len(parts) != 6:
        raise CommitEmitterError(f"unexpected git show format for {resolved}")
    full_sha, authored_at, author, subject, body, parents = parts
    changed = _git(
        repo_root,
        ["show", "--pretty=format:", "--name-only", full_sha],
    )
    changed_files = tuple(line.strip() for line in changed.splitlines() if line.strip())
    pr_refs = tuple(dict.fromkeys(PR_RE.findall(f"{subject}\n{body}")))
    return CommitRecord(
        sha=full_sha,
        short_sha=full_sha[:8],
        authored_at=authored_at,
        author=author,
        subject=subject.strip(),
        body=body.strip(),
        parent_count=len([part for part in parents.split() if part]),
        changed_files=changed_files,
        pr_refs=pr_refs,
    )


def note_path(vault_dir: Path, record: CommitRecord) -> Path:
    return vault_dir / "commits" / f"{record.short_sha}.md"


def render_note(record: CommitRecord) -> str:
    lines = [
        "---",
        f"sha: {json.dumps(record.sha)}",
        f"short_sha: {json.dumps(record.short_sha)}",
        f"author: {json.dumps(record.author)}",
        f"date: {json.dumps(record.date)}",
        f"datetime: {json.dumps(record.authored_at)}",
        f"parent_count: {record.parent_count}",
        f"is_merge: {'true' if record.is_merge else 'false'}",
        "tags:",
        '  - "commit/git"',
        f'  - "#commit/{record.date[:7]}"',
    ]
    if record.pr_refs:
        lines.append("pr_refs:")
        for pr_ref in record.pr_refs:
            lines.append(f'  - "{pr_ref}"')
    lines.append("---")
    lines.extend(
        [
            "",
            f"# {record.subject}",
            "",
            f"**Author:** {record.author}",
            f"**Date:** `{record.authored_at}`",
            f"**SHA:** `{record.sha}`",
        ]
    )
    if record.pr_refs:
        wikilinks = " ".join(f"[[prs/{pr_ref}]]" for pr_ref in record.pr_refs)
        lines.append(f"**Referenced PRs:** {wikilinks}")
    if record.body:
        lines.extend(
            [
                "",
                "## Message",
                "",
                "```text",
                record.body[:4000],
                "```",
            ]
        )
    if record.changed_files:
        lines.extend(
            [
                "",
                "## Files",
                "",
            ]
        )
        for relpath in record.changed_files[:MAX_FILES]:
            lines.append(f"- `{relpath}`")
        extra = len(record.changed_files) - MAX_FILES
        if extra > 0:
            lines.append(f"- ... and {extra} more")
    lines.append("")
    return "\n".join(lines)


def emit_record(vault_dir: Path, record: CommitRecord, *, dry_run: bool = False) -> EmitResult:
    target = note_path(vault_dir, record)
    content = render_note(record)
    if dry_run:
        return EmitResult(sha=record.sha, note_path=target, status="dry_run")
    if target.exists():
        existing = target.read_text(encoding="utf-8")
        if existing == content:
            return EmitResult(sha=record.sha, note_path=target, status="unchanged")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return EmitResult(sha=record.sha, note_path=target, status="written")


def emit_commits(
    vault_dir: Path,
    *,
    repo_root: Path,
    shas: list[str],
    dry_run: bool = False,
) -> list[EmitResult]:
    seen: set[str] = set()
    results: list[EmitResult] = []
    for sha in shas:
        resolved = _normalize_sha(repo_root, sha)
        if resolved in seen:
            continue
        seen.add(resolved)
        record = load_commit(repo_root, resolved)
        results.append(emit_record(vault_dir, record, dry_run=dry_run))
    return results


def resolve_requested_shas(args: argparse.Namespace, repo_root: Path) -> list[str]:
    requested: list[str] = []
    if args.sha:
        requested.extend(args.sha)
    if args.ref_path:
        requested.append(sha_from_ref_path(repo_root, Path(args.ref_path)))
    if args.head or not requested:
        requested.append(head_sha(repo_root))
    return requested


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Emit stable obsidian-vault commit notes from local git state."
    )
    parser.add_argument("--vault-dir", default=str(VAULT_DEFAULT), help="Target vault directory")
    parser.add_argument("--repo-root", default=str(REPO_ROOT), help="Git repository root")
    parser.add_argument("--head", action="store_true", help="Emit the current HEAD commit note")
    parser.add_argument("--ref-path", help="Emit the commit currently stored in a .git/refs/heads/* file")
    parser.add_argument("--sha", action="append", help="Explicit commit SHA to emit (repeatable)")
    parser.add_argument("--dry-run", action="store_true", help="Resolve and render without writing notes")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    repo_root = Path(args.repo_root).expanduser().resolve()
    vault_dir = Path(args.vault_dir).expanduser().resolve()

    try:
        shas = resolve_requested_shas(args, repo_root)
        results = emit_commits(vault_dir, repo_root=repo_root, shas=shas, dry_run=args.dry_run)
    except CommitEmitterError as exc:
        print(f"[commits] error: {exc}", file=sys.stderr)
        return 2

    for result in results:
        print(f"[commits] {result.status} {result.note_path} ({result.sha[:8]})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
