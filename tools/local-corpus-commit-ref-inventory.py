#!/usr/bin/env python3
"""Inventory local-corpus GitHub commit references without network access."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable


SCHEMA = "auditooor.local_corpus_commit_ref_inventory.v1"
DEFAULT_MAX_FILES = 10_000
DEFAULT_MAX_BYTES_PER_FILE = 1_000_000
DEFAULT_MAX_ROWS = 20_000
DEFAULT_NEAR_WINDOW = 240
SUPPORTED_EXTENSIONS = {
    "",
    ".json",
    ".jsonl",
    ".log",
    ".markdown",
    ".md",
    ".rst",
    ".text",
    ".txt",
}
SKIP_DIRS = {
    ".git",
    ".hg",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "node_modules",
}

FULL_SHA_RE = re.compile(r"(?<![0-9a-fA-F])(?P<sha>[0-9a-fA-F]{40})(?![0-9a-fA-F])")
SHORT_SHA_RE = re.compile(r"(?<![0-9a-fA-F])(?P<sha>[0-9a-fA-F]{7,39})(?![0-9a-fA-F])")
HEX_40_FULLMATCH_RE = re.compile(r"[0-9a-fA-F]{40}")
HEX_SHORT_FULLMATCH_RE = re.compile(r"[0-9a-fA-F]{7,39}")
OWNER_REPO = r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+"
URL_STOP = r"\s#?\"'<>\)\]\}"

GH_URL_RE = re.compile(
    rf"(?P<url>https?://github\.com/"
    rf"(?P<repo>{OWNER_REPO})"
    rf"/(?P<kind>commit|blob|tree)"
    rf"/(?P<ref>[^{URL_STOP}/]+)"
    rf"(?:/(?P<filepath>[^{URL_STOP}]+))?)"
)
GH_RAW_URL_RE = re.compile(
    rf"(?P<url>https?://raw\.githubusercontent\.com/"
    rf"(?P<repo>{OWNER_REPO})"
    rf"/(?P<ref>[^{URL_STOP}/]+)"
    rf"(?:/(?P<filepath>[^{URL_STOP}]+))?)"
)
GH_REPO_URL_RE = re.compile(
    rf"(?P<url>https?://github\.com/(?P<repo>{OWNER_REPO})(?:\.git)?)"
)


def ref_type(ref: str) -> str:
    if HEX_40_FULLMATCH_RE.fullmatch(ref):
        return "commit"
    if HEX_SHORT_FULLMATCH_RE.fullmatch(ref):
        return "short_hash"
    return "named_ref"


def normalized_ref(ref: str) -> str:
    return ref.lower() if HEX_SHORT_FULLMATCH_RE.fullmatch(ref) or HEX_40_FULLMATCH_RE.fullmatch(ref) else ref


def _trim_url_part(value: str | None) -> str | None:
    if value is None:
        return None
    return value.rstrip(".,;:")


def snippet_for_line(line: str, limit: int = 240) -> str:
    snippet = " ".join(line.strip().split())
    if len(snippet) <= limit:
        return snippet
    return snippet[: limit - 1].rstrip() + "..."


def suggested_route(evidence_kind: str, rtype: str, filepath: str | None) -> str:
    if rtype == "named_ref":
        return "blocked_named_ref_unresolved"
    if rtype == "short_hash":
        return "blocked_short_hash_unresolved"
    if filepath and evidence_kind in {"github_blob_url", "github_raw_url", "github_tree_url"}:
        return "source_ref_manifest"
    return "contest_fix_mine_review_lane"


def build_row(
    *,
    source_path: Path,
    repo: str,
    ref: str,
    kind: str,
    filepath: str | None,
    line_no: int,
    line: str,
    evidence_kind: str,
) -> dict[str, Any]:
    normalized = normalized_ref(ref)
    rtype = ref_type(normalized)
    return {
        "source_path": str(source_path.resolve()),
        "repo": repo,
        "commit": normalized if rtype == "commit" else None,
        "ref": normalized,
        "ref_type": rtype,
        "filepath": filepath,
        "line": line_no,
        "snippet": snippet_for_line(line),
        "evidence_kind": evidence_kind,
        "github_url_kind": kind,
        "suggested_downstream_route": suggested_route(evidence_kind, rtype, filepath),
        "route_status": "ready" if rtype == "commit" else "blocked",
        "network_used": False,
    }


def _spans_overlap(span: tuple[int, int], other: tuple[int, int]) -> bool:
    return span[0] < other[1] and other[0] < span[1]


def _distance_between_spans(left: tuple[int, int], right: tuple[int, int]) -> int:
    if _spans_overlap(left, right):
        return 0
    if left[1] <= right[0]:
        return right[0] - left[1]
    return left[0] - right[1]


def _github_url_rows(source_path: Path, line_no: int, line: str) -> tuple[list[dict[str, Any]], list[tuple[int, int]]]:
    rows: list[dict[str, Any]] = []
    url_spans: list[tuple[int, int]] = []
    for match in GH_URL_RE.finditer(line):
        url_spans.append(match.span("url"))
        kind = match.group("kind")
        rows.append(
            build_row(
                source_path=source_path,
                repo=match.group("repo"),
                ref=match.group("ref"),
                kind=kind,
                filepath=_trim_url_part(match.group("filepath")),
                line_no=line_no,
                line=line,
                evidence_kind=f"github_{kind}_url",
            )
        )
    for match in GH_RAW_URL_RE.finditer(line):
        url_spans.append(match.span("url"))
        rows.append(
            build_row(
                source_path=source_path,
                repo=match.group("repo"),
                ref=match.group("ref"),
                kind="raw",
                filepath=_trim_url_part(match.group("filepath")),
                line_no=line_no,
                line=line,
                evidence_kind="github_raw_url",
            )
        )
    return rows, url_spans


def _repo_url_matches(line: str) -> list[re.Match[str]]:
    return list(GH_REPO_URL_RE.finditer(line))


def _near_repo_hash_rows(
    source_path: Path,
    line_no: int,
    line: str,
    *,
    url_spans: list[tuple[int, int]],
    near_window: int,
) -> list[dict[str, Any]]:
    repo_matches = _repo_url_matches(line)
    if not repo_matches:
        return []

    rows: list[dict[str, Any]] = []
    hash_matches = list(FULL_SHA_RE.finditer(line)) + list(SHORT_SHA_RE.finditer(line))
    hash_matches.sort(key=lambda match: match.start())
    for hash_match in hash_matches:
        hash_span = hash_match.span("sha")
        if any(_spans_overlap(hash_span, url_span) for url_span in url_spans):
            continue
        nearest: tuple[int, str, re.Match[str]] | None = None
        for repo_match in repo_matches:
            distance = _distance_between_spans(hash_span, repo_match.span("url"))
            if distance > near_window:
                continue
            candidate = (distance, repo_match.group("repo"), repo_match)
            if nearest is None or candidate[:2] < nearest[:2]:
                nearest = candidate
        if nearest is None:
            continue
        _, repo, _repo_match = nearest
        rows.append(
            build_row(
                source_path=source_path,
                repo=repo,
                ref=hash_match.group("sha"),
                kind="repo_near_hash",
                filepath=None,
                line_no=line_no,
                line=line,
                evidence_kind="near_repo_url_commit_hash",
            )
        )
    return rows


def extract_rows_from_text(
    text: str,
    source_path: Path,
    *,
    near_window: int = DEFAULT_NEAR_WINDOW,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        url_rows, url_spans = _github_url_rows(source_path, line_no, line)
        rows.extend(url_rows)
        rows.extend(
            _near_repo_hash_rows(
                source_path,
                line_no,
                line,
                url_spans=url_spans,
                near_window=near_window,
            )
        )
    return rows


def is_supported_corpus_file(path: Path) -> bool:
    return path.suffix.lower() in SUPPORTED_EXTENSIONS


def iter_corpus_files(inputs: Iterable[Path], *, max_files: int = DEFAULT_MAX_FILES) -> tuple[list[Path], list[dict[str, Any]]]:
    files: list[Path] = []
    skipped: list[dict[str, Any]] = []
    seen: set[Path] = set()
    for raw in inputs:
        path = raw.expanduser()
        if not path.exists():
            skipped.append({"path": str(path), "reason": "missing"})
            continue
        if path.is_file():
            resolved = path.resolve()
            if resolved not in seen:
                seen.add(resolved)
                files.append(resolved)
            continue
        if not path.is_dir():
            skipped.append({"path": str(path), "reason": "unsupported_path_type"})
            continue
        for candidate in sorted(path.rglob("*"), key=lambda item: str(item)):
            if len(files) >= max_files:
                skipped.append({"path": str(path.resolve()), "reason": "max_files_reached"})
                return files, skipped
            if any(part in SKIP_DIRS for part in candidate.parts):
                continue
            if not candidate.is_file() or not is_supported_corpus_file(candidate):
                continue
            resolved = candidate.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            files.append(resolved)
    files.sort(key=lambda item: str(item))
    return files[:max_files], skipped


def read_text_bounded(path: Path, *, max_bytes: int = DEFAULT_MAX_BYTES_PER_FILE) -> tuple[str | None, bool, str | None]:
    try:
        with path.open("rb") as fh:
            data = fh.read(max_bytes + 1)
    except OSError as exc:
        return None, False, f"read_error:{exc.__class__.__name__}"
    truncated = len(data) > max_bytes
    if truncated:
        data = data[:max_bytes]
    if b"\x00" in data[:4096]:
        return None, truncated, "binary_or_nul_bytes"
    return data.decode("utf-8", errors="replace"), truncated, None


def _dedupe_rows(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    unique: dict[tuple[Any, ...], dict[str, Any]] = {}
    for row in rows:
        key = (
            row["source_path"],
            row["line"],
            row["repo"],
            row["ref"],
            row["ref_type"],
            row["filepath"],
            row["evidence_kind"],
        )
        unique.setdefault(key, row)
    return sorted(
        unique.values(),
        key=lambda row: (
            row["source_path"],
            row["line"],
            row["repo"],
            row["ref"],
            row["filepath"] or "",
            row["evidence_kind"],
        ),
    )


def build_inventory(
    inputs: Iterable[Path],
    *,
    max_files: int = DEFAULT_MAX_FILES,
    max_bytes_per_file: int = DEFAULT_MAX_BYTES_PER_FILE,
    max_rows: int = DEFAULT_MAX_ROWS,
    near_window: int = DEFAULT_NEAR_WINDOW,
) -> dict[str, Any]:
    input_paths = list(inputs)
    files, skipped = iter_corpus_files(input_paths, max_files=max_files)
    rows: list[dict[str, Any]] = []
    truncated_files: list[str] = []
    for path in files:
        text, truncated, error = read_text_bounded(path, max_bytes=max_bytes_per_file)
        if truncated:
            truncated_files.append(str(path))
        if error:
            skipped.append({"path": str(path), "reason": error})
            continue
        assert text is not None
        rows.extend(extract_rows_from_text(text, path, near_window=near_window))

    rows = _dedupe_rows(rows)
    rows_truncated = len(rows) > max_rows
    if rows_truncated:
        rows = rows[:max_rows]

    return {
        "schema": SCHEMA,
        "offline": True,
        "network_used": False,
        "input_count": len(input_paths),
        "scanned_file_count": len(files),
        "skipped": sorted(skipped, key=lambda item: (item.get("path", ""), item.get("reason", ""))),
        "truncated_files": sorted(truncated_files),
        "rows_truncated": rows_truncated,
        "row_count": len(rows),
        "rows": rows,
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scan local roots/files for GitHub commit references without network access."
    )
    parser.add_argument("inputs", nargs="+", type=Path, help="Local corpus roots or files to scan.")
    parser.add_argument("--out", type=Path, help="Write deterministic JSON inventory to this path.")
    parser.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES)
    parser.add_argument("--max-bytes-per-file", type=int, default=DEFAULT_MAX_BYTES_PER_FILE)
    parser.add_argument("--max-rows", type=int, default=DEFAULT_MAX_ROWS)
    parser.add_argument("--near-window", type=int, default=DEFAULT_NEAR_WINDOW)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.max_files <= 0 or args.max_bytes_per_file <= 0 or args.max_rows <= 0:
        raise SystemExit("bounds must be positive")
    payload = build_inventory(
        args.inputs,
        max_files=args.max_files,
        max_bytes_per_file=args.max_bytes_per_file,
        max_rows=args.max_rows,
        near_window=args.near_window,
    )
    rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
