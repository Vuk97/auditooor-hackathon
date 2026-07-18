#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


SCHEMA = "auditooor.klbq006_real_source_anchors.v1"
FINDING_ID = "30522"
LIMITATION_ID = "KLBQ-006"
DEFAULT_RENFT_PINNED_REF = "3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291"
ANCHOR_RE = re.compile(
    r"setFallbackHandler|fallbackHandler|checkTransaction|check_transaction|f08a0323",
    re.IGNORECASE,
)
EXACT_FINDING_RE = re.compile(
    r"Solodit\s+#30522|"
    r"[\"']?(?:solodit_id|source_id|finding_id)[\"']?\s*[:=]\s*[\"']?30522\b|"
    r"source:\s*[\"']?solodit-30522\b",
    re.IGNORECASE,
)
RENFT_BLOB_RE = re.compile(
    r"https://github\.com/re-nft/smart-contracts/blob/"
    r"(?P<ref>[^/\s)>\]]+)/(?P<path>[^#\s)>\]]+)"
    r"(?:#L(?P<start>\d+)(?:-L(?P<end>\d+))?)?"
)
GITHUB_BLOB_RE = re.compile(
    r"(?:https?://)?github\.com/"
    r"(?P<owner>[^/\s)>\]]+)/(?P<repo>[^/\s)>\]]+)/blob/"
    r"(?P<ref>[^/\s)>\]]+)/(?P<path>[^#\s)>\]]+)"
    r"(?:#L(?P<start>\d+)(?:-L(?P<end>\d+))?)?"
)
RENFT_RE = re.compile(r"renft|re-nft|rental", re.IGNORECASE)
TARGET_PATH_RE = re.compile(r"Guard\.sol|Factory\.sol|FallbackManager\.sol|Safe\.sol", re.IGNORECASE)
GUARD_FACTORY_PATH_RE = re.compile(r"Guard\.sol|Factory\.sol", re.IGNORECASE)
SOURCE_SUFFIXES = {
    ".sol",
    ".rs",
    ".vy",
    ".cairo",
    ".ts",
    ".js",
    ".tsx",
    ".jsx",
}
CANONICAL_RENFT_SOURCE_PATHS = (
    "src/policies/Guard.sol",
    "src/policies/Factory.sol",
    "src/libraries/RentalConstants.sol",
)
TEXT_SUFFIXES = SOURCE_SUFFIXES | {
    ".md",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".txt",
}
SKIP_DIR_NAMES = {
    ".git",
    ".venv",
    "__pycache__",
    "node_modules",
    "target",
    "out",
    "cache",
    ".cache",
    "dist",
    "build",
    "coverage",
    "agent_outputs",
}
LOCAL_EVIDENCE_PARTS = {
    "docs",
    "reports",
    "reference",
    "detectors",
    "tools",
    "tests",
    "_archive",
}
GENERATED_ANALYSIS_PARTS = {
    "docs",
    "reports",
    "obsidian-vault",
}
THIRD_PARTY_PART_MARKERS = {
    "openzeppelin",
    "gnosis",
    "safe-contracts",
    "permit2",
    "ethers",
    "v4-core",
    "v4-periphery",
    "uniswap",
}


@dataclass(frozen=True)
class Hit:
    path: Path
    line: int
    text: str
    bucket: str

    def as_json(self) -> dict[str, object]:
        return {
            "path": str(self.path),
            "line": self.line,
            "bucket": self.bucket,
            "snippet": self.text.strip()[:240],
        }


def _is_text_candidate(path: Path) -> bool:
    if path.name.startswith("klbq_006_real_source_anchors_"):
        return False
    return path.suffix.lower() in TEXT_SUFFIXES


def _is_source_candidate(path: Path) -> bool:
    return path.suffix.lower() in SOURCE_SUFFIXES


def _walk_files(roots: Iterable[Path], max_files: int) -> tuple[list[Path], list[str], bool]:
    files: list[Path] = []
    errors: list[str] = []
    truncated = False
    for root in roots:
        if not root.exists():
            errors.append(f"missing root: {root}")
            continue
        if root.is_file():
            if _is_text_candidate(root):
                files.append(root)
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [name for name in dirnames if name not in SKIP_DIR_NAMES]
            for filename in filenames:
                path = Path(dirpath) / filename
                if not _is_text_candidate(path):
                    continue
                files.append(path)
                if len(files) >= max_files:
                    return files, errors, True
    return files, errors, truncated


def _repo_remote_for(path: Path) -> str | None:
    for parent in [path, *path.parents]:
        config = parent / ".git" / "config"
        if not config.exists():
            continue
        try:
            text = config.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
        match = re.search(r"url\s*=\s*(.+)", text)
        if match:
            return match.group(1).strip()
    return None


def _run_git(root: Path, args: list[str]) -> subprocess.CompletedProcess[str] | None:
    if not (root / ".git").exists():
        return None
    return subprocess.run(
        ["git", "-C", str(root), *args],
        capture_output=True,
        text=True,
        check=False,
    )


def _git_stdout(root: Path, args: list[str]) -> str | None:
    proc = _run_git(root, args)
    if proc is None or proc.returncode != 0:
        return None
    return proc.stdout.strip()


def _git_show_text(root: Path, commit: str, rel_path: str) -> str | None:
    proc = _run_git(root, ["show", f"{commit}:{rel_path}"])
    if proc is None or proc.returncode != 0:
        return None
    return proc.stdout


def _repo_slug_from_remote(remote: str | None) -> str | None:
    if not remote:
        return None
    github_match = re.search(
        r"github\.com[:/](?P<owner>[^/\s:]+)/(?P<repo>[^/\s]+?)(?:\.git)?$",
        remote.strip(),
    )
    if not github_match:
        return None
    return f"{github_match.group('owner')}/{github_match.group('repo')}"


def _github_url_for_anchor(
    *,
    repo: str | None,
    commit: str,
    path: str,
    line_start: int,
    line_end: int,
) -> str | None:
    if not repo:
        return None
    suffix = f"#L{line_start}" if line_start == line_end else f"#L{line_start}-L{line_end}"
    return f"https://github.com/{repo}/blob/{commit}/{path}{suffix}"


def _short_range_snippet(lines: list[str], line_start: int, line_end: int) -> str:
    selected = lines[line_start - 1 : line_end]
    for line in selected:
        stripped = line.strip()
        if stripped:
            return stripped[:220]
    return " ".join(line.strip() for line in selected if line.strip())[:220]


def _dedupe_sorted_anchors(anchors: Iterable[dict[str, object]]) -> list[dict[str, object]]:
    deduped: dict[tuple[object, ...], dict[str, object]] = {}
    for anchor in anchors:
        key = (
            anchor.get("repo"),
            anchor.get("remote"),
            anchor.get("commit"),
            anchor.get("path"),
            anchor.get("line_start"),
            anchor.get("line_end"),
            anchor.get("snippet"),
            anchor.get("anchor_kind"),
        )
        deduped.setdefault(key, anchor)
    return sorted(
        deduped.values(),
        key=lambda anchor: (
            str(anchor.get("repo") or ""),
            str(anchor.get("commit") or ""),
            str(anchor.get("path") or ""),
            int(anchor.get("line_start") or 0),
            int(anchor.get("line_end") or 0),
            str(anchor.get("anchor_kind") or ""),
        ),
    )


def _classify(path: Path, root: Path) -> str:
    lowered_parts = {part.lower() for part in path.parts}
    path_text = str(path).lower()
    if lowered_parts & LOCAL_EVIDENCE_PARTS:
        return "local_auditooor_reference"
    if any(marker in path_text for marker in THIRD_PARTY_PART_MARKERS):
        return "third_party_or_unrelated"
    if _is_source_candidate(path):
        remote = _repo_remote_for(path) or ""
        joined = f"{path} {root} {remote}"
        if RENFT_RE.search(joined):
            return "possible_renft_source"
        return "other_source"
    return "other_text"


def _scan_hits(files: Iterable[Path], roots: list[Path], max_hits: int) -> list[Hit]:
    hits: list[Hit] = []
    root_by_path = sorted(roots, key=lambda p: len(str(p)), reverse=True)
    for path in files:
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        root = next((candidate for candidate in root_by_path if path == candidate or candidate in path.parents), path.parent)
        bucket = _classify(path, root)
        for idx, line in enumerate(lines, start=1):
            if not ANCHOR_RE.search(line):
                continue
            hits.append(Hit(path=path, line=idx, text=line, bucket=bucket))
            if len(hits) >= max_hits:
                return hits
    return hits


def _scan_blob_anchors(files: Iterable[Path], max_anchors: int) -> list[dict[str, object]]:
    anchors: list[dict[str, object]] = []
    for path in files:
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        text = "\n".join(lines)
        file_mentions_exact_finding = bool(EXACT_FINDING_RE.search(text))
        generated_analysis = bool({part.lower() for part in path.parts} & GENERATED_ANALYSIS_PARTS)
        for idx, line in enumerate(lines, start=1):
            for match in RENFT_BLOB_RE.finditer(line):
                anchors.append(
                    {
                        "local_path": str(path),
                        "local_line": idx,
                        "ref": match.group("ref"),
                        "target_path": match.group("path"),
                        "line_start": int(match.group("start")) if match.group("start") else None,
                        "line_end": int(match.group("end")) if match.group("end") else None,
                        "mentions_exact_finding_30522": file_mentions_exact_finding,
                        "exact_finding_anchor_eligible": (
                            file_mentions_exact_finding and not generated_analysis
                        ),
                        "snippet": line.strip()[:240],
                    }
                )
                if len(anchors) >= max_anchors:
                    return anchors
    return anchors


def _line_range(match: re.Match[str]) -> tuple[int | None, int | None]:
    start = int(match.group("start")) if match.group("start") else None
    end = int(match.group("end")) if match.group("end") else start
    return start, end


def _source_artifact_kind(path: Path) -> str:
    lowered_parts = [part.lower() for part in path.parts]
    lowered_path = str(path).lower()
    if set(lowered_parts) & GENERATED_ANALYSIS_PARTS:
        return "generated_analysis"
    if "detectors" in lowered_parts and "_specs" in lowered_parts:
        return "detector_source_spec"
    if "reference" in lowered_parts or any(part.startswith("patterns.dsl") for part in lowered_parts):
        return "local_reference_spec"
    if "solodit" in lowered_path:
        return "local_solodit_artifact"
    return "other_local_text"


def _github_blob_anchor_from_match(
    *,
    path: Path,
    line: int,
    match: re.Match[str],
    snippet: str,
) -> dict[str, object]:
    line_start, line_end = _line_range(match)
    owner = match.group("owner")
    repo = match.group("repo")
    target_path = match.group("path")
    return {
        "local_path": str(path),
        "local_line": line,
        "owner": owner,
        "repo": repo,
        "ref": match.group("ref"),
        "target_path": target_path,
        "line_start": line_start,
        "line_end": line_end,
        "has_line_range": line_start is not None,
        "guard_or_factory_citation": bool(GUARD_FACTORY_PATH_RE.search(target_path)),
        "renft_smart_contracts": f"{owner}/{repo}" == "re-nft/smart-contracts",
        "snippet": snippet.strip()[:240],
    }


def _source_spec_disqualification(candidate: dict[str, object]) -> list[str]:
    reasons: list[str] = []
    if candidate.get("source_artifact_kind") == "generated_analysis":
        reasons.append("generated KLBQ analysis is not accepted as source citation evidence")
    eligible_anchors = candidate.get("eligible_replay_anchors")
    if not isinstance(eligible_anchors, list) or not eligible_anchors:
        reasons.append("source spec has no line-level reNFT Guard.sol or Factory.sol citation")
    all_github_blob_anchors = candidate.get("github_blob_anchors")
    if not isinstance(all_github_blob_anchors, list) or not all_github_blob_anchors:
        reasons.append("source spec has no GitHub blob citation")
    return reasons


def _normalize_github_url(raw_url: str) -> str:
    if raw_url.startswith("github.com/"):
        return f"https://{raw_url}"
    return raw_url


def _source_metadata_disqualification(candidate: dict[str, object]) -> list[str]:
    reasons: list[str] = []
    owner = str(candidate.get("owner") or "")
    repo = str(candidate.get("repo") or "")
    target_path = str(candidate.get("target_path") or "")
    if f"{owner}/{repo}" != "re-nft/smart-contracts":
        reasons.append("metadata blob is not re-nft/smart-contracts")
    if not candidate.get("has_line_range"):
        reasons.append("metadata blob has no file-line range")
    if not GUARD_FACTORY_PATH_RE.search(target_path):
        reasons.append("metadata blob does not cite reNFT Guard.sol or Factory.sol")
    if not candidate.get("commit"):
        reasons.append("metadata does not include a reviewed commit")
    return reasons


def _metadata_candidate_from_json(path: Path, payload: object) -> dict[str, object] | None:
    if not isinstance(payload, dict):
        return None
    fid = str(payload.get("fid") or payload.get("finding_id") or payload.get("source_id") or "")
    if fid != FINDING_ID:
        return None

    raw_url = str(payload.get("url") or payload.get("source_url") or "")
    is_source_metadata = (
        path.name == f"finding_{FINDING_ID}.meta.json"
        or str(payload.get("source") or "") == "solodit_raw"
        or "github.com/" in raw_url
    )
    if not is_source_metadata:
        return None
    normalized_url = _normalize_github_url(raw_url)
    match = GITHUB_BLOB_RE.search(normalized_url)
    line_start = line_end = None
    owner = str(payload.get("owner") or "")
    repo = str(payload.get("repo") or "")
    ref = str(payload.get("commit") or "")
    target_path = ""
    if match:
        owner = match.group("owner")
        repo = match.group("repo")
        ref = match.group("ref")
        target_path = match.group("path")
        line_start, line_end = _line_range(match)

    candidate: dict[str, object] = {
        "local_path": str(path),
        "source": str(payload.get("source") or "unknown"),
        "fid": fid,
        "title": str(payload.get("title") or "")[:240],
        "url": normalized_url,
        "owner": owner,
        "repo": repo,
        "ref": ref,
        "commit": str(payload.get("commit") or ref),
        "target_path": target_path,
        "line_start": line_start,
        "line_end": line_end,
        "has_github_blob": bool(match),
        "has_line_range": line_start is not None,
        "target_path_relevant": bool(TARGET_PATH_RE.search(target_path)),
        "guard_or_factory_citation": bool(GUARD_FACTORY_PATH_RE.search(target_path)),
        "touched_files": payload.get("touched_files") if isinstance(payload.get("touched_files"), list) else [],
    }
    reasons = _source_metadata_disqualification(candidate)
    candidate["exact_source_metadata_eligible_for_replay"] = not reasons
    candidate["disqualification_reasons"] = reasons
    return candidate


def _scan_source_metadata(files: Iterable[Path], max_candidates: int) -> list[dict[str, object]]:
    candidates: list[dict[str, object]] = []
    for path in files:
        if path.suffix.lower() != ".json":
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError):
            continue
        candidate = _metadata_candidate_from_json(path, payload)
        if candidate is None:
            continue
        candidates.append(candidate)
        if len(candidates) >= max_candidates:
            return candidates
    return candidates


def _scan_source_spec_candidates(files: Iterable[Path], max_candidates: int) -> list[dict[str, object]]:
    candidates: list[dict[str, object]] = []
    for path in files:
        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        text = "\n".join(lines)
        if not EXACT_FINDING_RE.search(text):
            continue
        kind = _source_artifact_kind(path)
        if kind == "generated_analysis":
            continue
        if kind == "other_local_text" and "solodit" not in str(path).lower():
            continue

        github_blob_anchors: list[dict[str, object]] = []
        for idx, line in enumerate(lines, start=1):
            for match in GITHUB_BLOB_RE.finditer(line):
                github_blob_anchors.append(
                    _github_blob_anchor_from_match(
                        path=path,
                        line=idx,
                        match=match,
                        snippet=line,
                    )
                )

        eligible_anchors = [
            anchor
            for anchor in github_blob_anchors
            if anchor.get("renft_smart_contracts")
            and anchor.get("guard_or_factory_citation")
            and anchor.get("has_line_range")
        ]
        source_urls = sorted(
            {
                match.group(0).rstrip(".,)")
                for match in re.finditer(r"https?://[^\s\"'>)]+", text)
            }
        )
        candidate: dict[str, object] = {
            "local_path": str(path),
            "source_artifact_kind": kind,
            "exact_finding_marker_present": True,
            "source_urls": source_urls[:10],
            "github_blob_anchors": github_blob_anchors[:20],
            "eligible_replay_anchors": eligible_anchors[:20],
        }
        reasons = _source_spec_disqualification(candidate)
        candidate["exact_source_spec_eligible_for_replay"] = not reasons
        candidate["disqualification_reasons"] = reasons
        candidates.append(candidate)
        if len(candidates) >= max_candidates:
            return candidates
    return candidates


def _candidate_roots(roots: list[Path], files: Iterable[Path]) -> list[dict[str, object]]:
    candidates: dict[Path, dict[str, object]] = {}
    for root in roots:
        if RENFT_RE.search(str(root)):
            candidates[root.resolve()] = {
                "path": str(root.resolve()),
                "reason": "root_path_matches_renft",
                "remote": _repo_remote_for(root),
            }
    for path in files:
        remote = _repo_remote_for(path)
        if not remote or not RENFT_RE.search(remote):
            continue
        repo_root = path
        for parent in [path.parent, *path.parents]:
            if (parent / ".git" / "config").exists():
                repo_root = parent
                break
        candidates[repo_root.resolve()] = {
            "path": str(repo_root.resolve()),
            "reason": "git_remote_matches_renft",
            "remote": remote,
        }
    return sorted(candidates.values(), key=lambda item: str(item["path"]))


def _candidate_pinned_refs(
    *,
    pinned_refs: list[str] | None,
    blob_anchors: list[dict[str, object]],
    source_metadata: list[dict[str, object]],
    source_specs: list[dict[str, object]],
) -> list[dict[str, str]]:
    refs: dict[str, str] = {}
    for ref in pinned_refs or []:
        if ref:
            refs.setdefault(ref, "cli_pinned_ref")
    for candidate in source_metadata:
        if not candidate.get("exact_source_metadata_eligible_for_replay"):
            continue
        ref = str(candidate.get("commit") or candidate.get("ref") or "")
        if ref:
            refs.setdefault(ref, "eligible_exact_source_metadata")
    for candidate in source_specs:
        if not candidate.get("exact_source_spec_eligible_for_replay"):
            continue
        eligible_anchors = candidate.get("eligible_replay_anchors")
        if not isinstance(eligible_anchors, list):
            continue
        for anchor in eligible_anchors:
            if not isinstance(anchor, dict):
                continue
            ref = str(anchor.get("ref") or "")
            if ref:
                refs.setdefault(ref, "eligible_exact_source_spec")
    for anchor in blob_anchors:
        if not anchor.get("exact_finding_anchor_eligible"):
            continue
        ref = str(anchor.get("ref") or "")
        if ref:
            refs.setdefault(ref, "eligible_exact_finding_blob_anchor")
    refs.setdefault(DEFAULT_RENFT_PINNED_REF, "klbq006_default_pinned_ref")
    return [
        {"ref": ref, "source": source}
        for ref, source in sorted(refs.items(), key=lambda item: (item[1], item[0]))
    ]


def _cited_source_ranges(
    *,
    source_metadata: list[dict[str, object]],
    source_specs: list[dict[str, object]],
) -> dict[str, dict[str, list[tuple[int, int]]]]:
    ranges: dict[str, dict[str, list[tuple[int, int]]]] = {}

    def add(ref: str, path: str, line_start: object, line_end: object) -> None:
        if not ref or not path or not isinstance(line_start, int):
            return
        end = line_end if isinstance(line_end, int) else line_start
        ranges.setdefault(ref, {}).setdefault(path, []).append((line_start, end))

    for candidate in source_metadata:
        if not candidate.get("exact_source_metadata_eligible_for_replay"):
            continue
        add(
            str(candidate.get("commit") or candidate.get("ref") or ""),
            str(candidate.get("target_path") or ""),
            candidate.get("line_start"),
            candidate.get("line_end"),
        )
    for candidate in source_specs:
        if not candidate.get("exact_source_spec_eligible_for_replay"):
            continue
        eligible_anchors = candidate.get("eligible_replay_anchors")
        if not isinstance(eligible_anchors, list):
            continue
        for anchor in eligible_anchors:
            if not isinstance(anchor, dict):
                continue
            add(
                str(anchor.get("ref") or ""),
                str(anchor.get("target_path") or ""),
                anchor.get("line_start"),
                anchor.get("line_end"),
            )
    return ranges


def _local_source_anchor_candidates(
    *,
    candidate_roots: list[dict[str, object]],
    pinned_refs: list[dict[str, str]],
    cited_ranges: dict[str, dict[str, list[tuple[int, int]]]],
    max_anchors: int,
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    anchors: list[dict[str, object]] = []
    resolution: list[dict[str, object]] = []
    for root_record in candidate_roots:
        root = Path(str(root_record.get("path") or ""))
        remote = _git_stdout(root, ["config", "--get", "remote.origin.url"]) or str(
            root_record.get("remote") or ""
        )
        repo = _repo_slug_from_remote(remote)
        for ref_record in pinned_refs:
            ref = ref_record["ref"]
            commit = _git_stdout(root, ["rev-parse", "--verify", f"{ref}^{{commit}}"])
            if not commit:
                resolution.append(
                    {
                        "ref": ref,
                        "ref_source": ref_record["source"],
                        "status": "missing_local_ref",
                    }
                )
                continue
            paths = set(CANONICAL_RENFT_SOURCE_PATHS)
            paths.update(cited_ranges.get(ref, {}).keys())
            paths.update(cited_ranges.get(commit, {}).keys())
            resolved_count = 0
            missing_paths: list[str] = []
            for rel_path in sorted(paths):
                text = _git_show_text(root, commit, rel_path)
                if text is None:
                    missing_paths.append(rel_path)
                    continue
                lines = text.splitlines()
                resolved_count += 1

                for line_start, line_end in sorted(
                    set(cited_ranges.get(ref, {}).get(rel_path, []))
                    | set(cited_ranges.get(commit, {}).get(rel_path, []))
                ):
                    if line_start < 1 or line_start > len(lines):
                        continue
                    safe_end = min(max(line_end, line_start), len(lines))
                    snippet = _short_range_snippet(lines, line_start, safe_end)
                    url = _github_url_for_anchor(
                        repo=repo,
                        commit=commit,
                        path=rel_path,
                        line_start=line_start,
                        line_end=safe_end,
                    )
                    anchor: dict[str, object] = {
                        "anchor_kind": "cited_blob_range",
                        "repo": repo,
                        "remote": remote or None,
                        "commit": commit,
                        "path": rel_path,
                        "line_start": line_start,
                        "line_end": safe_end,
                        "snippet": snippet,
                        "advisory_only": True,
                    }
                    if url:
                        anchor["url"] = url
                    anchors.append(anchor)

                for idx, line in enumerate(lines, start=1):
                    if not ANCHOR_RE.search(line):
                        continue
                    url = _github_url_for_anchor(
                        repo=repo,
                        commit=commit,
                        path=rel_path,
                        line_start=idx,
                        line_end=idx,
                    )
                    anchor = {
                        "anchor_kind": "local_line_match",
                        "repo": repo,
                        "remote": remote or None,
                        "commit": commit,
                        "path": rel_path,
                        "line_start": idx,
                        "line_end": idx,
                        "snippet": line.strip()[:220],
                        "advisory_only": True,
                    }
                    if url:
                        anchor["url"] = url
                    anchors.append(anchor)
                    if len(anchors) >= max_anchors:
                        return _dedupe_sorted_anchors(anchors)[:max_anchors], resolution
            resolution.append(
                {
                    "ref": ref,
                    "ref_source": ref_record["source"],
                    "status": "resolved" if resolved_count else "resolved_ref_no_source_files",
                    "commit": commit,
                    "repo": repo,
                    "remote": remote or None,
                    "source_files_resolved": resolved_count,
                    "missing_source_paths": missing_paths[:20],
                }
            )
    return _dedupe_sorted_anchors(anchors)[:max_anchors], resolution


def build_report(
    *,
    roots: list[Path],
    pinned_refs: list[str] | None = None,
    max_files: int = 100_000,
    max_hits: int = 500,
) -> dict[str, object]:
    files, errors, truncated = _walk_files(roots, max_files=max_files)
    hits = _scan_hits(files, roots, max_hits=max_hits)
    blob_anchors = _scan_blob_anchors(files, max_anchors=max_hits)
    source_metadata = _scan_source_metadata(files, max_candidates=max_hits)
    source_specs = _scan_source_spec_candidates(files, max_candidates=max_hits)
    candidates = _candidate_roots(roots, files)
    candidate_refs = _candidate_pinned_refs(
        pinned_refs=pinned_refs,
        blob_anchors=blob_anchors,
        source_metadata=source_metadata,
        source_specs=source_specs,
    )
    cited_ranges = _cited_source_ranges(
        source_metadata=source_metadata,
        source_specs=source_specs,
    )
    local_source_anchors, local_source_resolution = _local_source_anchor_candidates(
        candidate_roots=candidates,
        pinned_refs=candidate_refs,
        cited_ranges=cited_ranges,
        max_anchors=max_hits,
    )
    by_bucket: dict[str, list[Hit]] = {}
    for hit in hits:
        by_bucket.setdefault(hit.bucket, []).append(hit)

    source_hits = by_bucket.get("possible_renft_source", [])
    reference_hits = by_bucket.get("local_auditooor_reference", [])
    third_party_hits = by_bucket.get("third_party_or_unrelated", [])
    exact_finding_blob_anchors = [
        anchor for anchor in blob_anchors if anchor.get("exact_finding_anchor_eligible")
    ]
    exact_source_metadata_candidates = [
        candidate for candidate in source_metadata if candidate.get("fid") == FINDING_ID
    ]
    eligible_source_metadata = [
        candidate
        for candidate in exact_source_metadata_candidates
        if candidate.get("exact_source_metadata_eligible_for_replay")
    ]
    exact_source_spec_candidates = source_specs
    eligible_source_specs = [
        candidate
        for candidate in exact_source_spec_candidates
        if candidate.get("exact_source_spec_eligible_for_replay")
    ]
    exact_root_present = bool(candidates and source_hits)
    searched_roots = [
        {
            "path": str(root),
            "exists": root.exists(),
            "is_file": root.is_file(),
            "is_dir": root.is_dir(),
        }
        for root in roots
    ]
    root_flags = " ".join(f"--root {root}" for root in roots)
    query_set = [
        "setFallbackHandler|fallbackHandler|checkTransaction|check_transaction|f08a0323",
        "Solodit\\s+#30522|solodit_id:\\s*['\\\"]?30522\\b|30522.*setFallbackHandler|setFallbackHandler.*30522",
        "https?://github.com/<owner>/<repo>/blob/<ref>/<path>#L<line>",
        "patterns/fixtures/auto/finding_30522.meta.json: fid/url/owner/repo/commit/touched_files",
        "detectors/_specs and reference/patterns.dsl exact #30522 source/spec artifacts",
    ]
    accepted_criteria = [
        "the source artifact names Solodit #30522, carries solodit_id/source_id 30522, or is Solodit raw metadata for fid 30522",
        "the citation is from source metadata, a source spec, or reviewed report evidence rather than generated KLBQ docs",
        "the citation points to re-nft/smart-contracts or an equivalent local checkout for the reviewed vulnerable source",
        "the cited ref resolves locally to the reviewed commit or tag before replay",
        "the cited file/line anchors cover the Guard/Factory fallback-handler path relevant to setFallbackHandler(address)",
    ]
    exact_citation_present = bool(
        eligible_source_metadata or eligible_source_specs or exact_finding_blob_anchors
    )
    exact_ref_sources = {
        "eligible_exact_source_metadata",
        "eligible_exact_source_spec",
        "eligible_exact_finding_blob_anchor",
    }
    exact_ref_resolution = [
        record
        for record in local_source_resolution
        if record.get("ref_source") in exact_ref_sources
    ]
    exact_ref_resolved = any(
        record.get("status") == "resolved"
        and int(record.get("source_files_resolved") or 0) > 0
        for record in exact_ref_resolution
    )
    exact_ref_resolution_state = (
        "resolved"
        if exact_ref_resolved
        else "unresolved"
        if exact_citation_present
        else "not_applicable"
    )
    remaining_missing_inputs = []
    if not exact_citation_present:
        remaining_missing_inputs = [
            "exact Solodit #30522 source report/spec row with a line-level reNFT Guard.sol or Factory.sol citation",
            "reviewed re-nft/smart-contracts commit or tag tied to that exact #30522 line citation",
            "local checkout/ref verification for the cited vulnerable source",
        ]
    elif not exact_ref_resolved:
        remaining_missing_inputs = [
            "local checkout/ref verification for the exact Solodit #30522 citation",
            "cited reNFT Guard.sol or Factory.sol ref must resolve locally before replay",
        ]

    return {
        "schema": SCHEMA,
        "limitation_id": LIMITATION_ID,
        "finding_id": FINDING_ID,
        "classification": {
            "exact_renft_source_root": "present" if exact_root_present else "absent",
            "real_source_anchors": "present" if source_hits else "absent",
            "canonical_local_source_anchors": (
                "present" if local_source_anchors else "absent"
            ),
            "exact_citation_local_ref_resolution": exact_ref_resolution_state,
            "exact_finding_github_blob_anchors": (
                "present" if exact_finding_blob_anchors else "absent"
            ),
            "exact_finding_source_metadata": (
                "eligible"
                if eligible_source_metadata
                else "ineligible_present"
                if exact_source_metadata_candidates
                else "absent"
            ),
            "exact_finding_source_specs": (
                "eligible"
                if eligible_source_specs
                else "ineligible_present"
                if exact_source_spec_candidates
                else "absent"
            ),
            "renft_base_github_blob_anchors": "present" if blob_anchors else "absent",
            "local_reference_anchors": "present" if reference_hits else "absent",
            "third_party_or_unrelated_anchor_terms": "present" if third_party_hits else "absent",
        },
        "summary": {
            "roots_scanned": len(roots),
            "files_considered": len(files),
            "scan_truncated": truncated,
            "candidate_renft_roots": len(candidates),
            "possible_renft_source_hits": len(source_hits),
            "canonical_local_source_anchors": len(local_source_anchors),
            "local_source_ref_resolution_records": len(local_source_resolution),
            "exact_citation_local_ref_resolution_records": len(exact_ref_resolution),
            "exact_finding_github_blob_anchors": len(exact_finding_blob_anchors),
            "exact_finding_source_metadata_candidates": len(exact_source_metadata_candidates),
            "eligible_exact_finding_source_metadata": len(eligible_source_metadata),
            "exact_finding_source_spec_candidates": len(exact_source_spec_candidates),
            "eligible_exact_finding_source_specs": len(eligible_source_specs),
            "renft_base_github_blob_anchors": len(blob_anchors),
            "local_reference_hits": len(reference_hits),
            "third_party_or_unrelated_hits": len(third_party_hits),
            "other_source_hits": len(by_bucket.get("other_source", [])),
            "other_text_hits": len(by_bucket.get("other_text", [])),
            "errors": errors,
        },
        "candidate_renft_roots": candidates,
        "local_source_anchor_refs_considered": candidate_refs,
        "local_source_anchor_resolution": local_source_resolution,
        "canonical_local_source_anchors": local_source_anchors[:50],
        "renft_github_blob_anchors": blob_anchors[:50],
        "exact_finding_source_metadata_candidates": exact_source_metadata_candidates[:50],
        "exact_finding_source_spec_candidates": exact_source_spec_candidates[:50],
        "absence_proof": {
            "searched_roots": searched_roots,
            "query_set": query_set,
            "accepted_exact_citation_criteria": accepted_criteria,
            "exact_citation_local_ref_resolution": exact_ref_resolution_state,
            "remaining_missing_inputs": remaining_missing_inputs,
            "disqualified_exact_metadata_candidates": [
                candidate
                for candidate in exact_source_metadata_candidates
                if not candidate.get("exact_source_metadata_eligible_for_replay")
            ][:50],
            "disqualified_exact_source_spec_candidates": [
                candidate
                for candidate in exact_source_spec_candidates
                if not candidate.get("exact_source_spec_eligible_for_replay")
            ][:50],
        },
        "hits": {
            bucket: [hit.as_json() for hit in bucket_hits[:50]]
            for bucket, bucket_hits in sorted(by_bucket.items())
        },
        "commands_to_reproduce": [
            (
                "python3 tools/klbq006-real-source-anchors.py "
                f"{root_flags} --out reports/klbq_006_real_source_anchors_2026-05-05.json --max-files {max_files}"
            ),
            "python3 tools/klbq006-real-source-anchors.py --root <local-root> --out reports/klbq_006_real_source_anchors_2026-05-05.json",
            "find <local-root> -maxdepth 5 -type d \\( -iname '*renft*' -o -iname '*re-nft*' -o -iname '*rental*' \\) -print",
            "rg -n \"setFallbackHandler|fallbackHandler|checkTransaction|check_transaction|f08a0323\" <local-root> -g '!node_modules/**' -g '!target/**' -g '!out/**' -g '!cache/**' -g '!agent_outputs/**'",
            "rg -n \"Solodit\\s+#30522|solodit_id:\\s*['\\\"]?30522\\b|source_id:\\s*['\\\"]?30522\\b|github.com/.*/blob/.*/.*FallbackManager|github.com/.*/blob/.*/.*Guard\" <local-root>",
        ],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Classify local KLBQ-006 reNFT source anchors versus reference-only hits."
    )
    parser.add_argument(
        "--root",
        action="append",
        type=Path,
        default=[],
        help="Root to scan. May be passed multiple times.",
    )
    parser.add_argument("--out", type=Path, help="Write JSON report to this path.")
    parser.add_argument(
        "--pinned-ref",
        action="append",
        default=[],
        help=(
            "Local git ref/commit to resolve in candidate reNFT mirrors. May be passed "
            "multiple times; no network operations are performed."
        ),
    )
    parser.add_argument("--max-files", type=int, default=100_000)
    parser.add_argument("--max-hits", type=int, default=500)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    roots = args.root or [Path.cwd()]
    report = build_report(
        roots=[root.resolve() for root in roots],
        pinned_refs=args.pinned_ref,
        max_files=args.max_files,
        max_hits=args.max_hits,
    )
    data = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(data, encoding="utf-8")
    else:
        print(data, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
