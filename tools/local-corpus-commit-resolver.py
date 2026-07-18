#!/usr/bin/env python3
"""Resolve local corpus commit inventory rows into bounded offline handoff packets."""

from __future__ import annotations

import argparse
import datetime as dt
import importlib.util
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "auditooor.local_corpus_commit_resolver.v1"
DEFAULT_DATE = "2026-05-05"
DEFAULT_INPUT_REPORT = REPO_ROOT / "reports" / f"local_corpus_commit_mining_inventory_{DEFAULT_DATE}.json"
DEFAULT_OUT = REPO_ROOT / "reports" / f"local_corpus_commit_resolver_{DEFAULT_DATE}.json"
DEFAULT_MIRROR_ROOTS = (
    Path.home() / "audits",
    Path.home() / "Documents" / "Codex",
    Path.home() / "auditooor-worktrees",
)
DEFAULT_MAX_DISCOVERED_REPOS = 200
DEFAULT_MAX_PACKETS = 20
DEFAULT_MAX_ROWS_PER_PACKET = 4
DEFAULT_MAX_COMMANDS_PER_PACKET = 6
PROOF_BOUNDARY = (
    "This resolver is an offline routing artifact only. Mirror verification and "
    "row pairing identify bounded follow-up work, not exploit proof, impact proof, "
    "severity proof, detector-promotion proof, or submission readiness."
)
GIT_TIMEOUT_SECONDS = 10
SKIP_DIRS = {
    ".git",
    ".hg",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "node_modules",
    "vendor",
    "dist",
    "build",
}
ROW_CLASS_PRIORITY = {
    "mirror_verified_fix_pair": 0,
    "mirror_verified_commit_ref": 1,
    "mirror_candidate_full_sha": 2,
    "mirror_candidate_short_sha": 3,
    "needs_repo_inference": 4,
    "already_patterned": 5,
    "ignored_internal_hash": 6,
}
PACKET_CLASS_PRIORITY = {
    "mirror_verified_fix_chain": 0,
    "mirror_verified_source_ref": 1,
    "local_mirror_probe": 2,
    "repo_inference_followup": 3,
}
SELF_LEARNING_TARGETS = {
    "base": "Base Azul",
    "azul": "Base Azul",
    "monetrix": "Monetrix",
    "morpho": "Morpho",
    "centrifuge": "Centrifuge",
}


@dataclass(frozen=True)
class MirrorRepo:
    path: Path
    repo_id: str
    remote_urls: tuple[str, ...]


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _relpath(path: Path) -> str:
    try:
        return path.resolve().relative_to(REPO_ROOT.resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug or "item"


def _stable_slug(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip()).strip("-")
    return slug or "item"


def _canonical_repo(value: str | None) -> str | None:
    if not value:
        return None
    raw = value.strip()
    if not raw:
        return None
    raw = re.sub(r"\s+\((fetch|push)\)$", "", raw)
    raw = raw[:-4] if raw.endswith(".git") else raw
    raw = raw.rstrip("/")

    ssh = re.match(r"^(?:ssh://)?git@([^:/]+)[:/](.+)$", raw)
    if ssh:
        return f"{ssh.group(1).lower()}/{ssh.group(2).strip('/').lower()}"

    https = re.match(r"^(?:https?|git)://([^/]+)/(.+)$", raw)
    if https:
        return f"{https.group(1).lower()}/{https.group(2).strip('/').lower()}"

    if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", raw):
        return f"github.com/{raw.lower()}"

    if re.fullmatch(r"github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", raw, re.IGNORECASE):
        return raw.lower()

    return None


def _repo_identity(row: dict[str, Any]) -> str | None:
    owner = str(row.get("owner") or "").strip()
    repo = str(row.get("repo") or "").strip()
    if owner and repo:
        return _canonical_repo(f"{owner}/{repo}")
    return _canonical_repo(str(row.get("nearby_repo_url") or "").strip())


def _target_policy(row: dict[str, Any]) -> tuple[str, str | None]:
    haystack = " ".join(
        [
            str(row.get("source_path") or ""),
            str(row.get("report_title") or ""),
            str(row.get("provider") or ""),
        ]
    ).lower()
    for token, label in SELF_LEARNING_TARGETS.items():
        if token in haystack:
            return "self_learning_only", label
    return "general_followup", None


def _row_sort_key(row: dict[str, Any]) -> tuple[Any, ...]:
    return (
        ROW_CLASS_PRIORITY.get(str(row.get("row_class")), 99),
        str(row.get("source_path") or ""),
        int(row.get("line") or 0),
        str(row.get("row_id") or ""),
    )


def _packet_sort_key(packet: dict[str, Any]) -> tuple[Any, ...]:
    return (
        PACKET_CLASS_PRIORITY.get(str(packet.get("packet_class")), 99),
        {"high": 0, "medium": 1, "low": 2}.get(str(packet.get("priority")), 9),
        str(packet.get("packet_id") or ""),
    )


def _run_git(repo: Path, args: list[str]) -> tuple[int, str, str]:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        timeout=GIT_TIMEOUT_SECONDS,
        check=False,
    )
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


def _git_config_urls(repo: Path) -> list[str]:
    config = repo / ".git" / "config"
    if not config.is_file():
        return []
    urls: list[str] = []
    for line in config.read_text(encoding="utf-8", errors="replace").splitlines():
        match = re.match(r"\s*url\s*=\s*(.+)$", line)
        if match:
            urls.append(match.group(1).strip())
    return urls


def _discover_git_repos(roots: Iterable[Path], *, max_repos: int) -> list[MirrorRepo]:
    repos: list[MirrorRepo] = []
    seen: set[Path] = set()
    for raw_root in roots:
        root = raw_root.expanduser()
        if not root.exists() or not root.is_dir():
            continue
        for current_root, dirnames, _filenames in os.walk(root):
            current = Path(current_root)
            if ".git" not in dirnames:
                dirnames[:] = [name for name in dirnames if name not in SKIP_DIRS]
                continue
            repo_path = current.resolve()
            dirnames[:] = []
            if repo_path in seen:
                continue
            seen.add(repo_path)
            repo_ids = sorted(
                {
                    repo_id
                    for repo_id in (_canonical_repo(url) for url in _git_config_urls(repo_path))
                    if repo_id
                }
            )
            if not repo_ids:
                continue
            primary = repo_ids[0]
            repos.append(
                MirrorRepo(
                    path=repo_path,
                    repo_id=primary,
                    remote_urls=tuple(sorted(_git_config_urls(repo_path))),
                )
            )
            if len(repos) >= max_repos:
                return sorted(repos, key=lambda item: (item.repo_id, str(item.path)))
    return sorted(repos, key=lambda item: (item.repo_id, str(item.path)))


def _inventory_rows_from_report(report_path: Path) -> tuple[list[dict[str, Any]], dict[str, Any], bool]:
    report = _read_json(report_path)
    if not isinstance(report, dict):
        raise ValueError("input report must be a JSON object")
    for key in ("inventory_rows", "rows"):
        rows = report.get(key)
        if isinstance(rows, list) and rows and all(isinstance(row, dict) for row in rows):
            return rows, report, False

    tool_meta = report.get("implemented_tool")
    if not isinstance(tool_meta, dict):
        raise ValueError("input report does not expose implemented_tool metadata")
    tool_path_raw = tool_meta.get("path")
    if not isinstance(tool_path_raw, str) or not tool_path_raw.strip():
        raise ValueError("implemented_tool.path missing from input report")
    tool_path = Path(tool_path_raw)
    if not tool_path.is_absolute():
        tool_path = REPO_ROOT / tool_path
    default_inputs = tool_meta.get("default_inputs")
    if not isinstance(default_inputs, list) or not default_inputs:
        raise ValueError("implemented_tool.default_inputs missing from input report")
    input_paths = [REPO_ROOT / str(item) for item in default_inputs]

    spec = importlib.util.spec_from_file_location("local_corpus_commit_inventory", tool_path)
    if spec is None or spec.loader is None:
        raise ValueError(f"failed to load inventory tool from {tool_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    payload = module.build_inventory(input_paths)
    rows = payload.get("rows")
    if not isinstance(rows, list):
        raise ValueError("inventory tool did not return rows")
    return [row for row in rows if isinstance(row, dict)], report, True


def _repo_inference_index(rows: list[dict[str, Any]]) -> tuple[dict[str, set[str]], dict[tuple[str, str], set[str]]]:
    by_source: dict[str, set[str]] = {}
    by_report: dict[tuple[str, str], set[str]] = {}
    for row in rows:
        repo_id = _repo_identity(row)
        if not repo_id:
            continue
        source_path = str(row.get("source_path") or "")
        report_key = (str(row.get("provider") or ""), str(row.get("report_title") or ""))
        by_source.setdefault(source_path, set()).add(repo_id)
        by_report.setdefault(report_key, set()).add(repo_id)
    return by_source, by_report


def _infer_repo_id(
    row: dict[str, Any],
    by_source: dict[str, set[str]],
    by_report: dict[tuple[str, str], set[str]],
) -> tuple[str | None, str | None]:
    direct = _repo_identity(row)
    if direct:
        return direct, None
    source_path = str(row.get("source_path") or "")
    source_candidates = sorted(by_source.get(source_path, set()))
    if len(source_candidates) == 1:
        return source_candidates[0], "same_source_unique_repo"
    report_key = (str(row.get("provider") or ""), str(row.get("report_title") or ""))
    report_candidates = sorted(by_report.get(report_key, set()))
    if len(report_candidates) == 1:
        return report_candidates[0], "same_report_unique_repo"
    return None, None


def _resolve_git_ref(repo: Path, ref: str) -> tuple[str, str | None]:
    rc, stdout, stderr = _run_git(repo, ["rev-parse", "--verify", f"{ref}^{{commit}}"])
    if rc == 0 and stdout:
        return stdout.strip(), None
    error = stderr or stdout or f"git rev-parse failed for {ref}"
    if "ambiguous" in error.lower():
        return "", "ambiguous_short_sha"
    if "unknown revision" in error.lower() or "bad object" in error.lower():
        return "", "ref_not_found_locally"
    return "", "git_resolution_failed"


def _repo_index(repos: Iterable[MirrorRepo]) -> dict[str, list[MirrorRepo]]:
    index: dict[str, list[MirrorRepo]] = {}
    for repo in repos:
        index.setdefault(repo.repo_id, []).append(repo)
    for candidates in index.values():
        candidates.sort(key=lambda item: str(item.path))
    return index


def _row_commands(
    *,
    row_class: str,
    repo_path: str | None,
    resolved_sha: str | None,
    input_ref: str,
    row: dict[str, Any],
    search_roots: Iterable[Path],
) -> list[str]:
    commands: list[str] = []
    if repo_path and resolved_sha:
        commands.append(f"git -C {repo_path} rev-parse --verify {resolved_sha}^{{commit}}")
        if row.get("ref_kind") == "pinned_github_blob_url" and row.get("context_label"):
            filepath = str(row.get("context_label"))
            if "/" in filepath:
                commands.append(f"git -C {repo_path} show {resolved_sha}:{filepath}")
        commands.append(f"git -C {repo_path} show --stat --patch --find-renames {resolved_sha}")
    elif repo_path:
        commands.append(f"git -C {repo_path} rev-parse --verify {input_ref}^{{commit}}")
        commands.append(f"git -C {repo_path} log --oneline --decorate --all --grep '{input_ref}'")
    else:
        repo_id = str(row.get("normalized_repo_identity") or "")
        if repo_id:
            owner_repo = repo_id.removeprefix("github.com/")
            search_roots_rendered = " ".join(str(path) for path in search_roots)
            if search_roots_rendered:
                commands.append(
                    f"rg -l '{re.escape(owner_repo)}(\\\\.git)?' {search_roots_rendered} -g '.git/config'"
                )
        commands.append(f"rg -n '{input_ref}' '{row.get('source_path')}'")

    if row_class == "mirror_verified_fix_pair":
        version_ref = row.get("paired_version_sha")
        remediation_ref = row.get("paired_remediation_sha")
        if repo_path and version_ref and remediation_ref:
            commands.append(f"git -C {repo_path} diff --stat {version_ref} {remediation_ref}")
    return commands


def _classify_row(
    row: dict[str, Any],
    repo_candidates: dict[str, list[MirrorRepo]],
    by_source: dict[str, set[str]],
    by_report: dict[tuple[str, str], set[str]],
    version_rows_by_source: dict[tuple[str, str], list[dict[str, Any]]],
    search_roots: Iterable[Path],
) -> dict[str, Any]:
    out = dict(row)
    repo_id, repo_inference = _infer_repo_id(row, by_source, by_report)
    out["normalized_repo_identity"] = repo_id
    out["repo_inference"] = repo_inference
    policy, policy_target = _target_policy(row)
    out["target_policy"] = policy
    out["policy_target"] = policy_target
    out["proof_boundary"] = PROOF_BOUNDARY
    out["inventory_status"] = row.get("status")

    if row.get("status") == "already_detectorized_or_patterned":
        out["row_class"] = "already_patterned"
        out["row_class_reason"] = "existing pattern or detector provenance already covers this commit reference"
        out["next_commands"] = [str(row.get("next_command") or "")]
        out["actionable"] = False
        return out

    if row.get("status") == "blocked_internal_hash":
        out["row_class"] = "ignored_internal_hash"
        out["row_class_reason"] = "internal local hash excluded from external commit-mining follow-up"
        out["next_commands"] = [str(row.get("next_command") or "record internal hash ignore disposition")]
        out["actionable"] = False
        return out

    if not repo_id:
        out["row_class"] = "needs_repo_inference"
        out["row_class_reason"] = "repo identity remains missing after same-source and same-report inference"
        out["next_commands"] = _row_commands(
            row_class=out["row_class"],
            repo_path=None,
            resolved_sha=None,
            input_ref=str(row.get("sha") or ""),
            row=out,
            search_roots=search_roots,
        )
        out["actionable"] = True
        return out

    candidates = repo_candidates.get(repo_id, [])
    out["local_repo_candidates"] = [_relpath(repo.path) for repo in candidates]
    input_ref = str(row.get("sha") or "")
    resolved_sha = ""
    resolution_error: str | None = None
    matched_repo: MirrorRepo | None = None
    for candidate in candidates:
        resolved_sha, resolution_error = _resolve_git_ref(candidate.path, input_ref)
        if resolved_sha:
            matched_repo = candidate
            break
    if matched_repo is None and candidates:
        matched_repo = candidates[0]

    out["resolved_sha"] = resolved_sha or None
    out["mirror_path"] = _relpath(matched_repo.path) if matched_repo else None
    out["mirror_verified"] = bool(resolved_sha and matched_repo)
    out["mirror_resolution_error"] = resolution_error

    paired_version_sha = None
    if str(row.get("ref_kind")) == "remediation_hash":
        key = (str(row.get("source_path") or ""), repo_id)
        versions = version_rows_by_source.get(key, [])
        if len(versions) == 1:
            paired_version_sha = versions[0].get("resolved_sha") or versions[0].get("sha")
    out["paired_version_sha"] = paired_version_sha
    out["paired_remediation_sha"] = resolved_sha or input_ref

    if resolved_sha:
        if str(row.get("ref_kind")) == "remediation_hash" and paired_version_sha:
            out["row_class"] = "mirror_verified_fix_pair"
            out["row_class_reason"] = "remediation hash resolved locally and paired with a single version row from the same source"
        else:
            out["row_class"] = "mirror_verified_commit_ref"
            out["row_class_reason"] = "repo identity and commit ref verified in a local mirror"
    elif len(input_ref) == 40:
        out["row_class"] = "mirror_candidate_full_sha"
        if candidates:
            out["row_class_reason"] = "repo identity known locally, but the full SHA was not found in discovered mirrors"
        else:
            out["row_class_reason"] = "repo identity known, but no discovered local mirror matched the repo remote"
    else:
        out["row_class"] = "mirror_candidate_short_sha"
        if candidates:
            out["row_class_reason"] = "short SHA still needs local expansion or disambiguation in a matching mirror"
        else:
            out["row_class_reason"] = "short SHA has repo identity but no discovered local mirror to resolve it"

    out["next_commands"] = _row_commands(
        row_class=str(out.get("row_class")),
        repo_path=_relpath(matched_repo.path) if matched_repo else None,
        resolved_sha=resolved_sha or None,
        input_ref=input_ref,
        row=out,
        search_roots=search_roots,
    )
    out["actionable"] = out["row_class"] not in {"already_patterned", "ignored_internal_hash"}
    return out


def _packet_class(rows: list[dict[str, Any]]) -> str:
    classes = {str(row.get("row_class")) for row in rows}
    if "mirror_verified_fix_pair" in classes:
        return "mirror_verified_fix_chain"
    if "mirror_verified_commit_ref" in classes:
        return "mirror_verified_source_ref"
    if "needs_repo_inference" in classes:
        return "repo_inference_followup"
    return "local_mirror_probe"


def _packet_priority(packet_class: str, rows: list[dict[str, Any]]) -> str:
    if packet_class == "mirror_verified_fix_chain":
        return "high"
    if packet_class == "mirror_verified_source_ref":
        return "medium"
    if any(str(row.get("target_policy")) == "self_learning_only" for row in rows):
        return "low"
    return "medium" if packet_class == "local_mirror_probe" else "low"


def _group_rows_for_packets(rows: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    groups: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for row in rows:
        if not row.get("actionable"):
            continue
        repo_id = str(row.get("normalized_repo_identity") or "missing-repo")
        key = (
            str(row.get("source_path") or ""),
            repo_id,
            str(row.get("target_policy") or "general_followup"),
        )
        groups.setdefault(key, []).append(row)
    grouped = []
    for group_rows in groups.values():
        grouped.append(sorted(group_rows, key=_row_sort_key))
    grouped.sort(
        key=lambda items: (
            PACKET_CLASS_PRIORITY.get(_packet_class(items), 99),
            str(items[0].get("source_path") or ""),
            str(items[0].get("normalized_repo_identity") or ""),
        )
    )
    return grouped


def _packet_commands(rows: list[dict[str, Any]], *, limit: int) -> list[str]:
    commands: list[str] = []
    for row in rows:
        for command in row.get("next_commands") or []:
            if not isinstance(command, str) or not command.strip():
                continue
            if command not in commands:
                commands.append(command)
            if len(commands) >= limit:
                return commands
    return commands


def _build_packets(
    rows: list[dict[str, Any]],
    *,
    max_packets: int,
    max_rows_per_packet: int,
    max_commands_per_packet: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    packets: list[dict[str, Any]] = []
    truncated: list[dict[str, Any]] = []
    grouped = _group_rows_for_packets(rows)
    for group_index, group_rows in enumerate(grouped, start=1):
        packet_class = _packet_class(group_rows)
        selected_rows = group_rows[:max_rows_per_packet]
        omitted_rows = group_rows[max_rows_per_packet:]
        packet = {
            "packet_id": f"LCCR-PKT-{group_index:03d}",
            "packet_class": packet_class,
            "priority": _packet_priority(packet_class, selected_rows),
            "advisory_only": True,
            "proof_boundary": PROOF_BOUNDARY,
            "source_path": selected_rows[0].get("source_path"),
            "report_title": selected_rows[0].get("report_title"),
            "provider": selected_rows[0].get("provider"),
            "repo_identity": selected_rows[0].get("normalized_repo_identity"),
            "mirror_path": selected_rows[0].get("mirror_path"),
            "target_policy": selected_rows[0].get("target_policy"),
            "policy_target": selected_rows[0].get("policy_target"),
            "row_classes": sorted({str(row.get("row_class")) for row in selected_rows}),
            "row_count_in_group": len(group_rows),
            "selected_row_ids": [str(row.get("row_id")) for row in selected_rows],
            "omitted_row_ids": [str(row.get("row_id")) for row in omitted_rows],
            "exact_next_commands": _packet_commands(selected_rows, limit=max_commands_per_packet),
            "rows": selected_rows,
        }
        packets.append(packet)
        if len(packets) >= max_packets:
            for overflow in grouped[group_index:]:
                truncated.append(
                    {
                        "source_path": overflow[0].get("source_path"),
                        "repo_identity": overflow[0].get("normalized_repo_identity"),
                        "row_ids": [str(row.get("row_id")) for row in overflow],
                        "packet_class": _packet_class(overflow),
                    }
                )
            break
    packets = sorted(packets, key=_packet_sort_key)
    return packets, truncated


def _count_by(rows: Iterable[dict[str, Any]], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        value = str(row.get(key) or "unknown")
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def build_resolver_report(
    *,
    input_report: Path = DEFAULT_INPUT_REPORT,
    mirror_roots: Iterable[Path] = DEFAULT_MIRROR_ROOTS,
    max_discovered_repos: int = DEFAULT_MAX_DISCOVERED_REPOS,
    max_packets: int = DEFAULT_MAX_PACKETS,
    max_rows_per_packet: int = DEFAULT_MAX_ROWS_PER_PACKET,
    max_commands_per_packet: int = DEFAULT_MAX_COMMANDS_PER_PACKET,
) -> dict[str, Any]:
    if max_discovered_repos <= 0 or max_packets <= 0 or max_rows_per_packet <= 0 or max_commands_per_packet <= 0:
        raise ValueError("bounds must be positive")

    mirror_roots = list(mirror_roots)
    inventory_rows, source_report, rebuilt_inventory = _inventory_rows_from_report(input_report)
    repo_inference_source, repo_inference_report = _repo_inference_index(inventory_rows)
    discovered = _discover_git_repos(mirror_roots, max_repos=max_discovered_repos)
    repo_candidates = _repo_index(discovered)

    resolved_rows: list[dict[str, Any]] = []
    version_rows_by_source: dict[tuple[str, str], list[dict[str, Any]]] = {}

    first_pass: list[dict[str, Any]] = []
    for row in inventory_rows:
        provisional = dict(row)
        repo_id, repo_inference = _infer_repo_id(row, repo_inference_source, repo_inference_report)
        provisional["normalized_repo_identity"] = repo_id
        provisional["repo_inference"] = repo_inference
        provisional["resolved_sha"] = row.get("sha")
        if str(row.get("ref_kind")) == "version_hash" and repo_id:
            version_rows_by_source.setdefault((str(row.get("source_path") or ""), repo_id), []).append(provisional)
        first_pass.append(provisional)

    for row in inventory_rows:
        resolved_rows.append(
            _classify_row(
                row,
                repo_candidates,
                repo_inference_source,
                repo_inference_report,
                version_rows_by_source,
                mirror_roots,
            )
        )

    resolved_rows.sort(key=_row_sort_key)
    actionable_rows = [row for row in resolved_rows if row.get("actionable")]
    packets, truncated_packets = _build_packets(
        actionable_rows,
        max_packets=max_packets,
        max_rows_per_packet=max_rows_per_packet,
        max_commands_per_packet=max_commands_per_packet,
    )

    return {
        "schema": SCHEMA,
        "date": DEFAULT_DATE,
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        "network_used": False,
        "advisory_only": True,
        "proof_boundary": PROOF_BOUNDARY,
        "input_report": _relpath(input_report),
        "input_report_schema": source_report.get("schema"),
        "inventory_rows_rebuilt_locally": rebuilt_inventory,
        "inventory_row_count": len(inventory_rows),
        "mirror_search_roots": [_relpath(path) for path in mirror_roots if path.exists()],
        "mirror_repo_count": len(discovered),
        "mirror_repo_identities": _count_by(({"repo_id": repo.repo_id} for repo in discovered), "repo_id"),
        "summary": {
            "row_class_counts": _count_by(resolved_rows, "row_class"),
            "actionable_row_count": len(actionable_rows),
            "mirror_verified_row_count": sum(1 for row in resolved_rows if row.get("mirror_verified")),
            "repo_inference_counts": _count_by(
                (row for row in resolved_rows if row.get("repo_inference")),
                "repo_inference",
            ),
            "packet_class_counts": _count_by(packets, "packet_class"),
            "packet_count": len(packets),
            "truncated_packet_group_count": len(truncated_packets),
            "self_learning_only_row_count": sum(
                1 for row in resolved_rows if row.get("target_policy") == "self_learning_only"
            ),
        },
        "actionable_row_classes": {
            "mirror_verified_fix_pair": "mirror-verified remediation row paired with a single version row from the same source and repo",
            "mirror_verified_commit_ref": "mirror-verified commit or pinned blob reference ready for bounded source review",
            "mirror_candidate_full_sha": "repo identity known or inferred, full SHA present, but a matching local mirror or local ref proof is still missing",
            "mirror_candidate_short_sha": "repo identity known or inferred, but the short SHA still needs local expansion or disambiguation",
            "needs_repo_inference": "commit row still lacks enough repo identity to route into local mirror verification",
            "already_patterned": "existing pattern/detector provenance already captured this commit reference",
            "ignored_internal_hash": "internal project hash excluded from commit-mining follow-up",
        },
        "resolved_rows": resolved_rows,
        "packets": packets,
        "truncated_packet_groups": truncated_packets,
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Resolve the local corpus commit inventory into bounded offline handoff packets."
    )
    parser.add_argument("--input-report", type=Path, default=DEFAULT_INPUT_REPORT)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--mirror-root", dest="mirror_roots", action="append", type=Path, default=[])
    parser.add_argument("--max-discovered-repos", type=int, default=DEFAULT_MAX_DISCOVERED_REPOS)
    parser.add_argument("--max-packets", type=int, default=DEFAULT_MAX_PACKETS)
    parser.add_argument("--max-rows-per-packet", type=int, default=DEFAULT_MAX_ROWS_PER_PACKET)
    parser.add_argument("--max-commands-per-packet", type=int, default=DEFAULT_MAX_COMMANDS_PER_PACKET)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    mirror_roots = args.mirror_roots or list(DEFAULT_MIRROR_ROOTS)
    payload = build_resolver_report(
        input_report=args.input_report,
        mirror_roots=mirror_roots,
        max_discovered_repos=args.max_discovered_repos,
        max_packets=args.max_packets,
        max_rows_per_packet=args.max_rows_per_packet,
        max_commands_per_packet=args.max_commands_per_packet,
    )
    rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(rendered, encoding="utf-8")
    sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
