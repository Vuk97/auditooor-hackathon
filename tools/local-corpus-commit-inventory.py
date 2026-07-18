#!/usr/bin/env python3
"""Normalize local corpus commit references into bounded offline work rows."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable


REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "auditooor.local_corpus_commit_inventory.v1"
DEFAULT_INPUTS = (
    REPO_ROOT / "reference" / "corpus_txt",
    REPO_ROOT / "reference" / "patterns.dsl",
)
DEFAULT_MAX_FILES = 10_000
DEFAULT_MAX_BYTES_PER_FILE = 1_000_000
DEFAULT_MAX_ROWS = 20_000
DEFAULT_JOIN_LINES = 3
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
    ".yaml",
    ".yml",
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
LIGATURES = str.maketrans(
    {
        "\u00ad": "",
        "\ufb01": "fi",
        "\ufb02": "fl",
        "\ufb03": "ffi",
        "\ufb04": "ffl",
        "\ufb05": "ft",
        "\ufb06": "st",
    }
)

OWNER = r"[A-Za-z0-9_.-]+"
REPO = r"[A-Za-z0-9_.-]+"
OWNER_REPO = rf"(?P<owner>{OWNER})/(?P<repo>{REPO})"
FULL_SHA_RE = re.compile(r"(?<![0-9a-fA-F])(?P<sha>[0-9a-fA-F]{40})(?![0-9a-fA-F])")
SHORT_OR_FULL_SHA_RE = re.compile(r"(?<![0-9a-fA-F])(?P<sha>[0-9a-fA-F]{7,40})(?![0-9a-fA-F])")
STRICT_COMMIT_URL_RE = re.compile(
    rf"(?P<url>https?://github\.com/{OWNER_REPO}/commit/(?P<shaish>[0-9a-fA-F\s]{{7,80}}))",
    re.IGNORECASE,
)
PINNED_BLOB_URL_RE = re.compile(
    rf"(?P<url>https?://github\.com/{OWNER_REPO}/blob/(?P<sha>[0-9a-fA-F]{{40}})"
    rf"(?:/(?P<filepath>[^\s\"'<>\)\]\}}]+))?)",
    re.IGNORECASE,
)
REPO_URL_RE = re.compile(
    rf"(?P<url>https?://github\.com/{OWNER_REPO})(?:\.git)?",
    re.IGNORECASE,
)
VERSION_RE = re.compile(r"^\s*versions?\b", re.IGNORECASE)
REMEDIATION_RE = re.compile(
    r"\b(remediated|fixed|patched|resolved)\b.*?\bcommit\b",
    re.IGNORECASE,
)
INTERNAL_HINT_RE = re.compile(
    r"\b(auditooor|agent_output|agent_outputs|build|worktree|llm_dispatch|codex|archive)\b",
    re.IGNORECASE,
)


def normalize_pdf_text(text: str) -> str:
    return text.translate(LIGATURES).replace("\r\n", "\n").replace("\r", "\n")


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug or "unknown"


def _trim(value: str | None) -> str | None:
    if value is None:
        return None
    return value.rstrip(".,;:)")


def _is_hex_ref(value: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-f]{7,40}", value))


def _repo_identity(owner: str | None, repo: str | None) -> str | None:
    if not owner or not repo:
        return None
    return f"{owner}/{repo}"


def _source_label(path: Path) -> str:
    try:
        return path.resolve().relative_to(REPO_ROOT.resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def _provider_and_title(path: Path) -> tuple[str, str]:
    parts = path.parts
    if "corpus_txt" in parts:
        idx = parts.index("corpus_txt")
        provider = parts[idx + 1] if idx + 1 < len(parts) else "corpus_txt"
        return provider, _clean_title(path.stem)
    if "patterns.dsl" in parts:
        return "patterns", _clean_title(path.stem)
    if "docs" in parts:
        return "docs", _clean_title(path.stem)
    if "reports" in parts:
        return "reports", _clean_title(path.stem)
    return (path.parent.name or "unknown"), _clean_title(path.stem)


def _clean_title(stem: str) -> str:
    title = stem.replace("_", " ").strip()
    for suffix in (
        " - Zellic Audit Report",
        "- Zellic Audit Report",
        " Zellic Audit Report",
        " Audit Report",
        " Smart Contract Security Assessment",
    ):
        if title.endswith(suffix):
            return title[: -len(suffix)].strip()
    return title


def _project_tags(*, provider: str, report_title: str, ref_kind: str, remediation_signal: bool) -> list[str]:
    tags = {f"provider:{provider}", f"report:{_slug(report_title)}", f"ref_kind:{ref_kind}"}
    if provider == "patterns":
        tags.add("detector_provenance")
    if provider in {"docs", "reports"}:
        tags.add("internal_context")
    if remediation_signal:
        tags.add("remediation_signal")
    return sorted(tags)


def _status_for_row(*, ref_kind: str, provider: str, sha_len: int, owner: str | None, repo: str | None) -> str:
    if ref_kind == "internal_hash_ignored":
        return "blocked_internal_hash"
    if provider == "patterns":
        return "already_detectorized_or_patterned"
    if sha_len < 40:
        return "blocked_short_sha_unresolved"
    if owner and repo:
        return "needs_local_mirror"
    return "blocked_missing_repo"


def _next_command(
    *,
    status: str,
    ref_kind: str,
    sha: str,
    owner: str | None,
    repo: str | None,
    source_path: str,
    filepath: str | None,
) -> str:
    repo_identity = _repo_identity(owner, repo)
    if status == "needs_local_mirror" and repo_identity and ref_kind == "pinned_github_blob_url" and filepath:
        return f"git -C <local-mirror/{owner}__{repo}> show {sha}:{filepath}"
    if status == "needs_local_mirror" and repo_identity:
        return f"git -C <local-mirror/{owner}__{repo}> rev-parse --verify {sha}^{{commit}}"
    if status == "already_detectorized_or_patterned":
        return f"rg -n '{sha}' reference/patterns.dsl"
    if status == "blocked_internal_hash":
        return "record internal hash ignore disposition"
    return f"rg -n '{sha}' '{source_path}'"


def _snippet(text: str, limit: int = 220) -> str:
    snippet = " ".join(text.split())
    if len(snippet) <= limit:
        return snippet
    return snippet[: limit - 3].rstrip() + "..."


def _spans_overlap(left: tuple[int, int], right: tuple[int, int]) -> bool:
    return left[0] < right[1] and right[0] < left[1]


def _distance(left: tuple[int, int], right: tuple[int, int]) -> int:
    if _spans_overlap(left, right):
        return 0
    if left[1] <= right[0]:
        return right[0] - left[1]
    return left[0] - right[1]


def _strip_urls(text: str) -> str:
    return re.sub(r"https?://\S+", " ", text)


def _make_row(
    *,
    source_path: Path,
    line_no: int,
    provider: str,
    report_title: str,
    ref_kind: str,
    sha: str,
    owner: str | None,
    repo: str | None,
    context_label: str,
    remediation_signal: bool,
    nearby_repo_url: str | None,
    snippet: str,
    filepath: str | None = None,
) -> dict[str, Any]:
    normalized_sha = sha.lower()
    sha_len = len(normalized_sha)
    source_label = _source_label(source_path)
    status = _status_for_row(
        ref_kind=ref_kind,
        provider=provider,
        sha_len=sha_len,
        owner=owner,
        repo=repo,
    )
    return {
        "source_path": source_label,
        "line": line_no,
        "provider": provider,
        "report_title": report_title,
        "ref_kind": ref_kind,
        "owner": owner,
        "repo": repo,
        "sha": normalized_sha,
        "sha_len": sha_len,
        "context_label": context_label,
        "remediation_signal": remediation_signal,
        "nearby_repo_url": nearby_repo_url,
        "project_tags": _project_tags(
            provider=provider,
            report_title=report_title,
            ref_kind=ref_kind,
            remediation_signal=remediation_signal,
        ),
        "status": status,
        "next_command": _next_command(
            status=status,
            ref_kind=ref_kind,
            sha=normalized_sha,
            owner=owner,
            repo=repo,
            source_path=source_label,
            filepath=filepath,
        ),
        "snippet": snippet,
    }


def _commit_url_rows(source_path: Path, line_no: int, window: str, provider: str, report_title: str) -> tuple[list[dict[str, Any]], list[tuple[int, int]]]:
    rows: list[dict[str, Any]] = []
    spans: list[tuple[int, int]] = []
    for match in STRICT_COMMIT_URL_RE.finditer(window):
        raw_sha = re.sub(r"\s+", "", match.group("shaish")).rstrip(".,;:)")
        if not _is_hex_ref(raw_sha):
            continue
        spans.append(match.span("url"))
        rows.append(
            _make_row(
                source_path=source_path,
                line_no=line_no,
                provider=provider,
                report_title=report_title,
                ref_kind="strict_github_commit_url",
                sha=raw_sha,
                owner=match.group("owner"),
                repo=match.group("repo"),
                context_label="github commit url",
                remediation_signal=False,
                nearby_repo_url=f"https://github.com/{match.group('owner')}/{match.group('repo')}",
                snippet=_snippet(window),
            )
        )
    return rows, spans


def _blob_rows(source_path: Path, line_no: int, window: str, provider: str, report_title: str) -> tuple[list[dict[str, Any]], list[tuple[int, int]]]:
    rows: list[dict[str, Any]] = []
    spans: list[tuple[int, int]] = []
    for match in PINNED_BLOB_URL_RE.finditer(window):
        spans.append(match.span("url"))
        rows.append(
            _make_row(
                source_path=source_path,
                line_no=line_no,
                provider=provider,
                report_title=report_title,
                ref_kind="pinned_github_blob_url",
                sha=match.group("sha"),
                owner=match.group("owner"),
                repo=match.group("repo"),
                context_label=_trim(match.group("filepath")) or "github blob url",
                remediation_signal=False,
                nearby_repo_url=f"https://github.com/{match.group('owner')}/{match.group('repo')}",
                snippet=_snippet(window),
                filepath=_trim(match.group("filepath")),
            )
        )
    return rows, spans


def _version_rows(source_path: Path, line_no: int, line: str, window: str, provider: str, report_title: str) -> list[dict[str, Any]]:
    if not VERSION_RE.search(line):
        return []
    clean_window = _strip_urls(window)
    match = FULL_SHA_RE.search(clean_window)
    if match is None:
        return []
    prefix = clean_window[: match.start("sha")]
    version_match = VERSION_RE.search(prefix)
    context = prefix[version_match.start() :] if version_match else prefix
    return [
        _make_row(
            source_path=source_path,
            line_no=line_no,
            provider=provider,
            report_title=report_title,
            ref_kind="version_hash",
            sha=match.group("sha"),
            owner=None,
            repo=None,
            context_label=_snippet(context) or "version",
            remediation_signal=False,
            nearby_repo_url=None,
            snippet=_snippet(window),
        )
    ]


def _remediation_rows(source_path: Path, line_no: int, line: str, window: str, provider: str, report_title: str) -> list[dict[str, Any]]:
    if not REMEDIATION_RE.search(line):
        return []
    clean_window = _strip_urls(window)
    commit_idx = clean_window.lower().find("commit")
    tail = clean_window[commit_idx:] if commit_idx >= 0 else clean_window
    match = SHORT_OR_FULL_SHA_RE.search(tail)
    if match is None:
        return []
    return [
        _make_row(
            source_path=source_path,
            line_no=line_no,
            provider=provider,
            report_title=report_title,
            ref_kind="remediation_hash",
            sha=match.group("sha"),
            owner=None,
            repo=None,
            context_label="remediated in commit",
            remediation_signal=True,
            nearby_repo_url=None,
            snippet=_snippet(window),
        )
    ]


def _near_repo_hash_rows(
    source_path: Path,
    line_no: int,
    window: str,
    provider: str,
    report_title: str,
    *,
    url_spans: list[tuple[int, int]],
    near_window: int,
) -> list[dict[str, Any]]:
    repo_matches = list(REPO_URL_RE.finditer(window))
    if not repo_matches:
        return []
    rows: list[dict[str, Any]] = []
    for hash_match in FULL_SHA_RE.finditer(window):
        hash_span = hash_match.span("sha")
        if any(_spans_overlap(hash_span, url_span) for url_span in url_spans):
            continue
        nearest: tuple[int, re.Match[str]] | None = None
        for repo_match in repo_matches:
            distance = _distance(hash_span, repo_match.span("url"))
            if distance > near_window:
                continue
            candidate = (distance, repo_match)
            if nearest is None or candidate[0] < nearest[0]:
                nearest = candidate
        if nearest is None:
            continue
        repo_match = nearest[1]
        rows.append(
            _make_row(
                source_path=source_path,
                line_no=line_no,
                provider=provider,
                report_title=report_title,
                ref_kind="commit_hash_near_repo",
                sha=hash_match.group("sha"),
                owner=repo_match.group("owner"),
                repo=repo_match.group("repo"),
                context_label="plain hash near repo url",
                remediation_signal=False,
                nearby_repo_url=repo_match.group("url"),
                snippet=_snippet(window),
            )
        )
    return rows


def _internal_hash_rows(source_path: Path, line_no: int, line: str, provider: str, report_title: str) -> list[dict[str, Any]]:
    if provider not in {"docs", "reports"}:
        return []
    if "github.com/" in line.lower():
        return []
    if not INTERNAL_HINT_RE.search(line):
        return []
    rows: list[dict[str, Any]] = []
    for match in FULL_SHA_RE.finditer(line):
        rows.append(
            _make_row(
                source_path=source_path,
                line_no=line_no,
                provider=provider,
                report_title=report_title,
                ref_kind="internal_hash_ignored",
                sha=match.group("sha"),
                owner=None,
                repo=None,
                context_label="internal local hash",
                remediation_signal=False,
                nearby_repo_url=None,
                snippet=_snippet(line),
            )
        )
    return rows


def extract_rows_from_text(
    text: str,
    source_path: Path,
    *,
    join_lines: int = DEFAULT_JOIN_LINES,
    near_window: int = DEFAULT_NEAR_WINDOW,
) -> list[dict[str, Any]]:
    provider, report_title = _provider_and_title(source_path)
    normalized = normalize_pdf_text(text)
    lines = normalized.splitlines()
    rows: list[dict[str, Any]] = []
    for idx, line in enumerate(lines):
        window = " ".join(part.strip() for part in lines[idx : idx + join_lines] if part.strip())
        if not window:
            continue
        line_no = idx + 1
        commit_spans: list[tuple[int, int]] = []
        blob_spans: list[tuple[int, int]] = []
        line_lower = line.lower()
        if "github.com/" in line_lower:
            commit_rows, commit_spans = _commit_url_rows(source_path, line_no, window, provider, report_title)
            blob_rows, blob_spans = _blob_rows(source_path, line_no, window, provider, report_title)
            rows.extend(commit_rows)
            rows.extend(blob_rows)
        rows.extend(_version_rows(source_path, line_no, line, window, provider, report_title))
        rows.extend(_remediation_rows(source_path, line_no, line, window, provider, report_title))
        if "github.com/" in line_lower and "/commit/" not in line_lower and "/blob/" not in line_lower:
            rows.extend(
                _near_repo_hash_rows(
                    source_path,
                    line_no,
                    line,
                    provider,
                    report_title,
                    url_spans=[*commit_spans, *blob_spans],
                    near_window=near_window,
                )
            )
        rows.extend(_internal_hash_rows(source_path, line_no, line, provider, report_title))
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
            if resolved not in seen and is_supported_corpus_file(resolved):
                files.append(resolved)
                seen.add(resolved)
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
        with path.open("rb") as handle:
            data = handle.read(max_bytes + 1)
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
            row["provider"],
            row["report_title"],
            row["ref_kind"],
            row["owner"],
            row["repo"],
            row["sha"],
            row["context_label"],
        )
        unique.setdefault(key, row)
    ordered = sorted(
        unique.values(),
        key=lambda row: (
            row["source_path"],
            int(row["line"]),
            row["ref_kind"],
            row["owner"] or "",
            row["repo"] or "",
            row["sha"],
        ),
    )
    for idx, row in enumerate(ordered, start=1):
        row["row_id"] = f"LCCI-{idx:05d}"
    return ordered


def _summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_kind: dict[str, int] = {}
    by_status: dict[str, int] = {}
    by_provider: dict[str, int] = {}
    for row in rows:
        by_kind[row["ref_kind"]] = by_kind.get(row["ref_kind"], 0) + 1
        by_status[row["status"]] = by_status.get(row["status"], 0) + 1
        by_provider[row["provider"]] = by_provider.get(row["provider"], 0) + 1
    return {
        "row_kinds": dict(sorted(by_kind.items())),
        "statuses": dict(sorted(by_status.items())),
        "providers": dict(sorted(by_provider.items())),
    }


def build_inventory(
    inputs: Iterable[Path],
    *,
    max_files: int = DEFAULT_MAX_FILES,
    max_bytes_per_file: int = DEFAULT_MAX_BYTES_PER_FILE,
    max_rows: int = DEFAULT_MAX_ROWS,
    join_lines: int = DEFAULT_JOIN_LINES,
    near_window: int = DEFAULT_NEAR_WINDOW,
) -> dict[str, Any]:
    input_paths = list(inputs)
    files, skipped = iter_corpus_files(input_paths, max_files=max_files)
    rows: list[dict[str, Any]] = []
    truncated_files: list[str] = []
    for path in files:
        text, truncated, error = read_text_bounded(path, max_bytes=max_bytes_per_file)
        if truncated:
            truncated_files.append(_source_label(path))
        if error:
            skipped.append({"path": _source_label(path), "reason": error})
            continue
        assert text is not None
        rows.extend(
            extract_rows_from_text(
                text,
                path,
                join_lines=join_lines,
                near_window=near_window,
            )
        )

    rows = _dedupe_rows(rows)
    rows_truncated = len(rows) > max_rows
    if rows_truncated:
        rows = rows[:max_rows]
        for idx, row in enumerate(rows, start=1):
            row["row_id"] = f"LCCI-{idx:05d}"

    return {
        "schema": SCHEMA,
        "offline": True,
        "network_used": False,
        "inputs": [_source_label(path) for path in input_paths],
        "scanned_file_count": len(files),
        "skipped": sorted(skipped, key=lambda item: (item.get("path", ""), item.get("reason", ""))),
        "truncated_files": sorted(truncated_files),
        "rows_truncated": rows_truncated,
        "row_count": len(rows),
        "summary": _summary(rows),
        "rows": rows,
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Normalize local extracted corpus commit refs into offline commit-work rows."
    )
    parser.add_argument("inputs", nargs="*", type=Path, help="Optional local roots/files to scan.")
    parser.add_argument("--out", type=Path, help="Write deterministic JSON inventory to this path.")
    parser.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES)
    parser.add_argument("--max-bytes-per-file", type=int, default=DEFAULT_MAX_BYTES_PER_FILE)
    parser.add_argument("--max-rows", type=int, default=DEFAULT_MAX_ROWS)
    parser.add_argument("--join-lines", type=int, default=DEFAULT_JOIN_LINES)
    parser.add_argument("--near-window", type=int, default=DEFAULT_NEAR_WINDOW)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if (
        args.max_files <= 0
        or args.max_bytes_per_file <= 0
        or args.max_rows <= 0
        or args.join_lines <= 0
        or args.near_window <= 0
    ):
        raise SystemExit("bounds must be positive")
    inputs = args.inputs or list(DEFAULT_INPUTS)
    payload = build_inventory(
        inputs,
        max_files=args.max_files,
        max_bytes_per_file=args.max_bytes_per_file,
        max_rows=args.max_rows,
        join_lines=args.join_lines,
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
