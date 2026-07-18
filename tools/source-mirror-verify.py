#!/usr/bin/env python3
"""Offline verifier for the source mirror queue.

The verifier intentionally performs no network I/O. It validates each queue row
marked ready against local checkout paths and locally configured git remotes,
then emits one machine-readable result per ready row.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


DEFAULT_QUEUE = Path("reports/source_mirror_queue_2026-05-05.json")
DEFAULT_OUT = Path("reports/source_mirror_verify_2026-05-05.json")
SCHEMA = "auditooor.source_mirror_verify.v1"

READY_FIELDS = (
    "status",
    "queue_status",
    "plan_status",
    "mirror_status",
    "source_mirror_status",
    "verdict",
)
READY_VALUES = {
    "ready",
    "queued-ready",
    "source-mirror-ready",
    "mirror-ready",
    "queued_for_local_mirror_verification",
}
ROW_LIST_KEYS = ("ready_rows", "queue_rows", "rows", "queue", "items", "entries", "candidates")
PATH_KEYS = {
    "path",
    "repo_path",
    "local_path",
    "local_repo_path",
    "source_path",
    "source_repo_path",
    "checkout_path",
    "workspace_path",
    "mirror_path",
    "clone_path",
}
IDENTITY_KEYS = {
    "repo",
    "repository",
    "repo_url",
    "repository_url",
    "source_repo",
    "source_repo_url",
    "source_url",
    "github",
    "github_url",
    "remote",
    "remote_url",
    "clone_url",
    "origin",
    "owner_repo",
    "repo_identity",
    "expected_repo",
}
REF_KEYS = {"ref", "commit", "commit_sha", "sha", "source_ref"}
IDENTITY_EVIDENCE_PATTERN = (
    r"github\.com/|git@github\.com:|repo(_url|sitory)?|source_repo|source_url|clone_url|owner_repo"
)
GITHUB_REPO_RE = re.compile(
    r"(?:https?://github\.com/|git@github\.com:|github\.com/)"
    r"([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)"
)


@dataclass(frozen=True)
class GitInfo:
    path: Path
    root: Path | None
    head: str | None
    branch: str | None
    remotes: dict[str, list[str]]
    error: str | None = None


def _run_git(path: Path, args: list[str]) -> tuple[int, str, str]:
    proc = subprocess.run(
        ["git", "-C", str(path), *args],
        capture_output=True,
        text=True,
        timeout=10,
    )
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


def read_git_info(path: Path) -> GitInfo:
    rc, root_out, root_err = _run_git(path, ["rev-parse", "--show-toplevel"])
    if rc != 0:
        return GitInfo(path=path, root=None, head=None, branch=None, remotes={}, error=root_err or root_out)

    root = Path(root_out).resolve()
    head_rc, head_out, _ = _run_git(root, ["rev-parse", "HEAD"])
    branch_rc, branch_out, _ = _run_git(root, ["branch", "--show-current"])
    remote_rc, remote_out, remote_err = _run_git(root, ["remote", "-v"])
    remotes: dict[str, list[str]] = {}
    if remote_rc == 0:
        for line in remote_out.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                remotes.setdefault(parts[0], [])
                if parts[1] not in remotes[parts[0]]:
                    remotes[parts[0]].append(parts[1])
    elif remote_err:
        remotes["_error"] = [remote_err]

    return GitInfo(
        path=path,
        root=root,
        head=head_out if head_rc == 0 and head_out else None,
        branch=branch_out if branch_rc == 0 and branch_out else None,
        remotes=remotes,
        error=None,
    )


def load_queue(path: Path) -> tuple[list[dict[str, Any]], str]:
    payload = json.loads(path.read_text())
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)], "list"
    if not isinstance(payload, dict):
        raise ValueError("queue JSON must be an object or list")

    for key in ROW_LIST_KEYS:
        rows = payload.get(key)
        if isinstance(rows, list):
            return [row for row in rows if isinstance(row, dict)], key
    raise ValueError(f"queue JSON did not contain any row list key: {', '.join(ROW_LIST_KEYS)}")


def is_ready_row(row: dict[str, Any], source_key: str) -> bool:
    if source_key == "ready_rows":
        return True
    ready = row.get("ready")
    if isinstance(ready, bool):
        return ready
    for field in READY_FIELDS:
        value = row.get(field)
        if isinstance(value, str) and value.strip().lower() in READY_VALUES:
            return True
    return False


def row_id(row: dict[str, Any], index: int) -> str:
    for key in ("id", "row_id", "source_row_id", "queue_id", "report_id", "finding_id", "slug", "name"):
        value = row.get(key)
        if isinstance(value, (str, int)) and str(value).strip():
            return str(value)
    return f"ready-row-{index + 1}"


def _iter_values(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, (int, float)):
        return [str(value)]
    if isinstance(value, list):
        out: list[str] = []
        for item in value:
            out.extend(_iter_values(item))
        return out
    return []


def collect_fields(row: dict[str, Any], wanted_keys: set[str]) -> list[str]:
    found: list[str] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key in wanted_keys:
                    found.extend(_iter_values(value))
                if isinstance(value, (dict, list)):
                    walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(row)
    return [item for item in found if item.strip()]


def expand_path(value: str, base_dir: Path) -> Path:
    expanded = Path(os.path.expandvars(os.path.expanduser(value)))
    if expanded.is_absolute():
        return expanded
    return (base_dir / expanded).resolve()


def canonical_repo(value: str) -> str | None:
    raw = value.strip()
    if not raw:
        return None

    raw = re.sub(r"\s+\((fetch|push)\)$", "", raw)
    raw = raw[:-4] if raw.endswith(".git") else raw
    raw = raw.rstrip("/")

    ssh = re.match(r"^(?:ssh://)?git@([^:/]+)[:/](.+)$", raw)
    if ssh:
        host = ssh.group(1).lower()
        path = ssh.group(2).strip("/")
        return f"{host}/{path.lower()}"

    https = re.match(r"^(?:https?|git)://([^/]+)/(.+)$", raw)
    if https:
        host = https.group(1).lower()
        path = https.group(2).strip("/")
        return f"{host}/{path.lower()}"

    if re.match(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", raw):
        return f"github.com/{raw.lower()}"

    if re.match(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/.+)?$", raw):
        return raw.lower()

    return None


def remote_urls(remotes: dict[str, list[str]]) -> list[str]:
    urls: list[str] = []
    for name, values in remotes.items():
        if name == "_error":
            continue
        for value in values:
            if value not in urls:
                urls.append(value)
    return urls


def repo_url_to_mirror_path(repo_url: str, mirror_root: Path) -> Path | None:
    canonical = canonical_repo(repo_url)
    if not canonical:
        return None
    parts = canonical.split("/")
    if len(parts) < 3:
        return None
    return mirror_root.joinpath(*parts[1:3])


def resolve_commit(path: Path, ref: str) -> tuple[str | None, str | None]:
    rc, out, err = _run_git(path, ["rev-parse", "--verify", f"{ref}^{{commit}}"])
    if rc == 0:
        return out, None
    return None, err or f"git rev-parse failed for {ref}"


def commit_exists(path: Path, ref: str) -> tuple[bool, str | None]:
    resolved, err = resolve_commit(path, ref)
    return resolved is not None, err


def first_remote_name(remotes: dict[str, list[str]]) -> str:
    if "origin" in remotes:
        return "origin"
    for name in remotes:
        if name != "_error":
            return name
    return "origin"


def ref_not_found_terminal_blocker(git_info: GitInfo, ref: str, ref_error: str | None) -> dict[str, Any]:
    git_root = git_info.root or git_info.path
    remote = first_remote_name(git_info.remotes)
    verify_ref = f"{ref}^{{commit}}"
    next_command = (
        f"git -C {shlex.quote(str(git_root))} fetch --tags {shlex.quote(remote)} "
        f"&& git -C {shlex.quote(str(git_root))} rev-parse --verify {shlex.quote(verify_ref)}"
    )
    return {
        "code": "terminal_ref_not_found_locally",
        "terminal": True,
        "no_source_claim": True,
        "reason": (
            "matched repository identity locally, but the requested ref is absent from the local object "
            "database; the offline verifier did not fetch and must not claim this source ref is verified"
        ),
        "ref": ref,
        "git_root": str(git_root),
        "remote": remote,
        "local_error": ref_error,
        "next_command": next_command,
    }


def row_evidence_paths(row: dict[str, Any]) -> list[str]:
    values = _iter_values(row.get("evidence_paths"))
    return [value for value in values if value.strip()]


def row_target(row: dict[str, Any]) -> str | None:
    for key in ("target", "project", "protocol", "title"):
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return None


def missing_identity_class_id(target: str | None, evidence_paths: list[str]) -> str:
    payload = json.dumps([target, evidence_paths], sort_keys=True)
    return "missing-identity-" + hashlib.sha1(payload.encode("utf-8")).hexdigest()[:12]


def _quote_many(values: list[str]) -> str:
    return " ".join(shlex.quote(value) for value in values)


def identity_search_command(evidence_paths: list[str], fallback_path: Path | None = None) -> str:
    paths = evidence_paths or ([str(fallback_path)] if fallback_path is not None else [])
    if not paths:
        return "rg -n -e 'github\\.com/|git@github\\.com:|repo(_url|sitory)?|source_repo|source_url|clone_url|owner_repo'"
    return f"rg -n -e {shlex.quote(IDENTITY_EVIDENCE_PATTERN)} {_quote_many(paths)}"


def ref_search_command(refs: list[str], evidence_paths: list[str], fallback_path: Path | None = None) -> str:
    paths = evidence_paths or ([str(fallback_path)] if fallback_path is not None else [])
    args: list[str] = []
    for ref in refs:
        if ref.strip():
            args.extend(["-e", shlex.quote(ref)])
    ref_args = " ".join(args) if args else "-e ''"
    if not paths:
        return f"rg -n --fixed-strings {ref_args}"
    return f"rg -n --fixed-strings {ref_args} {_quote_many(paths)}"


def _is_relative_to(path: Path, base_dir: Path) -> bool:
    try:
        path.relative_to(base_dir)
        return True
    except ValueError:
        return False


def candidate_repo_identity_evidence(
    evidence_paths: list[str],
    base_dir: Path,
    max_bytes: int = 2_000_000,
) -> list[dict[str, Any]]:
    resolved_base_dir = base_dir.resolve()
    candidates: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int]] = set()
    for raw_path in evidence_paths:
        path = expand_path(raw_path, resolved_base_dir)
        if not _is_relative_to(path, resolved_base_dir) or not path.is_file():
            continue
        try:
            if path.stat().st_size > max_bytes:
                continue
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for lineno, line in enumerate(lines, start=1):
            for match in GITHUB_REPO_RE.finditer(line):
                repo = canonical_repo(f"github.com/{match.group(1)}/{match.group(2)}")
                if repo is None:
                    continue
                key = (raw_path, repo, lineno)
                if key in seen:
                    continue
                seen.add(key)
                candidates.append(
                    {
                        "repo_identity": repo,
                        "evidence_path": raw_path,
                        "line": lineno,
                    }
                )
    return candidates


def candidate_repo_identities(candidates: list[dict[str, Any]]) -> list[str]:
    return sorted(
        {
            candidate["repo_identity"]
            for candidate in candidates
            if isinstance(candidate.get("repo_identity"), str)
        }
    )


def is_missing_identity_blocker(row: dict[str, Any]) -> bool:
    if row.get("mirror_status") == "blocked_missing_repo_identity":
        return True
    blockers = " ".join(normalize_blockers(row.get("blocker") or row.get("blockers"))).lower()
    return "missing_repo_identity" in blockers or "repo identity missing" in blockers


def identity_resolution_hint(
    row: dict[str, Any],
    base_dir: Path,
    queue_path: Path | None = None,
) -> dict[str, Any]:
    evidence_paths = row_evidence_paths(row)
    refs = collect_fields(row, REF_KEYS)
    target = row_target(row)
    class_id = missing_identity_class_id(target, evidence_paths)
    candidates = candidate_repo_identity_evidence(evidence_paths, base_dir)
    return {
        "code": "missing_repo_identity_resolution_hint",
        "terminal": True,
        "class_id": class_id,
        "target": target,
        "candidate_evidence_paths": evidence_paths,
        "candidate_repo_identities": candidate_repo_identities(candidates),
        "candidate_repo_identity_evidence": candidates,
        "safe_local_commands": [
            identity_search_command(evidence_paths, queue_path),
            ref_search_command(refs, evidence_paths, queue_path),
        ],
        "after_repo_identity_attached": {
            "required": "attach repo_url, then pin short/named refs to a full 40-character commit before source verification",
            "safe_local_command_template": "git -C {mirror_root}/{owner}/{repo} rev-parse --verify '<ref>^{commit}'",
            "queue_update_fields": ["repo_url", "ref"],
        },
        "no_source_claim": True,
        "reason": (
            "repo identity is absent; these commands only locate candidate identity evidence and do not verify "
            "that the row's ref belongs to a repository"
        ),
    }


def missing_identity_classes(
    rows: list[dict[str, Any]],
    source_key: str,
    queue_path: Path,
    base_dir: Path,
) -> list[dict[str, Any]]:
    groups: dict[tuple[str | None, tuple[str, ...]], list[tuple[int, dict[str, Any]]]] = {}
    for index, row in enumerate(rows):
        if is_ready_row(row, source_key) or not is_missing_identity_blocker(row):
            continue
        evidence_paths = row_evidence_paths(row)
        groups.setdefault((row_target(row), tuple(evidence_paths)), []).append((index, row))

    classes: list[dict[str, Any]] = []
    for (target, evidence_tuple), grouped_rows in sorted(
        groups.items(),
        key=lambda item: ((item[0][0] or ""), item[0][1]),
    ):
        evidence_paths = list(evidence_tuple)
        refs = sorted({ref for _, row in grouped_rows for ref in collect_fields(row, REF_KEYS)})
        ref_kinds = sorted({row.get("ref_kind") for _, row in grouped_rows if row.get("ref_kind")})
        class_id = missing_identity_class_id(target, evidence_paths)
        candidates = candidate_repo_identity_evidence(evidence_paths, base_dir)
        classes.append(
            {
                "class_id": class_id,
                "target": target,
                "row_count": len(grouped_rows),
                "row_ids": [row_id(row, index) for index, row in grouped_rows],
                "refs": refs,
                "ref_kinds": ref_kinds,
                "candidate_evidence_paths": evidence_paths,
                "candidate_repo_identities": candidate_repo_identities(candidates),
                "candidate_repo_identity_evidence": candidates,
                "safe_local_commands": [
                    identity_search_command(evidence_paths, queue_path),
                    ref_search_command(refs, evidence_paths, queue_path),
                ],
                "resolution_status": "needs_operator_repo_identity",
                "terminal": True,
                "no_source_claim": True,
            }
        )
    return classes


def normalize_blockers(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        blockers: list[str] = []
        for item in value:
            blockers.extend(normalize_blockers(item))
        return blockers
    return [str(value)]


def is_resolution_candidate(row: dict[str, Any], source_key: str) -> bool:
    if is_ready_row(row, source_key):
        return False
    if row.get("mirror_status") != "blocked_pending_resolution":
        return False
    if row.get("ref_kind") not in {"short_sha", "named_ref"}:
        return False
    return bool(row.get("repo_url") and row.get("ref"))


def verify_row(
    row: dict[str, Any],
    index: int,
    base_dir: Path,
    mirror_root: Path | None = None,
    repo_map: dict[str, Path] | None = None,
) -> dict[str, Any]:
    paths = collect_fields(row, PATH_KEYS)
    identities = collect_fields(row, IDENTITY_KEYS)
    expected = sorted({repo for value in identities if (repo := canonical_repo(value))})
    refs = collect_fields(row, REF_KEYS)
    if repo_map:
        for repo in expected:
            mapped = repo_map.get(repo)
            if mapped is not None and str(mapped) not in paths:
                paths.append(str(mapped))
    if mirror_root is not None:
        for identity in identities:
            mirror_path = repo_url_to_mirror_path(identity, mirror_root)
            if mirror_path is not None and str(mirror_path) not in paths:
                paths.append(str(mirror_path))

    result: dict[str, Any] = {
        "row_index": index,
        "id": row_id(row, index),
        "status": "blocked",
        "blockers": normalize_blockers(row.get("blockers") or row.get("blocker")),
        "input": {
            "title": row.get("title"),
            "project": row.get("project") or row.get("protocol"),
            "local_paths": paths,
            "repo_identities": identities,
        },
        "checks": {
            "local_path": None,
            "git_root": None,
            "head": None,
            "branch": None,
            "remotes": {},
            "expected_repo_identities": expected,
            "matched_repo_identity": None,
            "refs": refs,
            "ref_verified": None,
        },
    }

    if isinstance(result["blockers"], str):
        result["blockers"] = [result["blockers"]]

    git_info: GitInfo | None = None
    missing_paths: list[str] = []
    for raw_path in paths:
        path = expand_path(raw_path, base_dir)
        if not path.exists():
            missing_paths.append(str(path))
            continue
        result["checks"]["local_path"] = str(path)
        git_info = read_git_info(path)
        break

    actual: list[str] = []
    if git_info is not None:
        result["checks"]["git_root"] = str(git_info.root) if git_info.root else None
        result["checks"]["head"] = git_info.head
        result["checks"]["branch"] = git_info.branch
        result["checks"]["remotes"] = git_info.remotes
        actual = sorted({repo for url in remote_urls(git_info.remotes) if (repo := canonical_repo(url))})
        result["checks"]["actual_repo_identities"] = actual
        if git_info.error:
            result["blockers"].append(f"local_path_not_git_repo: {git_info.error}")
            return result

    if expected and actual:
        matches = sorted(set(expected) & set(actual))
        if matches:
            result["status"] = "verified"
            result["blockers"] = []
            result["checks"]["matched_repo_identity"] = matches[0]
            if refs and git_info is not None and git_info.root is not None:
                resolved_ref, ref_error = resolve_commit(git_info.root, refs[0])
                result["checks"]["ref_verified"] = resolved_ref is not None
                result["checks"]["resolved_ref"] = resolved_ref
                if resolved_ref is None:
                    result["status"] = "blocked"
                    result["blockers"] = [f"ref_not_found_locally: {refs[0]} ({ref_error})"]
                    result["terminal_blocker"] = ref_not_found_terminal_blocker(git_info, refs[0], ref_error)
            return result
        result["blockers"].append(
            "remote_mismatch: expected "
            + ", ".join(expected)
            + "; actual "
            + ", ".join(actual)
        )
        return result

    if actual and not expected:
        result["status"] = "verified"
        result["blockers"] = []
        result["checks"]["matched_repo_identity"] = actual[0]
        result["checks"]["repo_identity_source"] = "local_git_remote"
        if refs and git_info is not None and git_info.root is not None:
            resolved_ref, ref_error = resolve_commit(git_info.root, refs[0])
            result["checks"]["ref_verified"] = resolved_ref is not None
            result["checks"]["resolved_ref"] = resolved_ref
            if resolved_ref is None:
                result["status"] = "blocked"
                result["blockers"] = [f"ref_not_found_locally: {refs[0]} ({ref_error})"]
                result["terminal_blocker"] = ref_not_found_terminal_blocker(git_info, refs[0], ref_error)
        return result

    if expected and not paths:
        result["blockers"].append("local_repo_path_missing: repo identity present but no local checkout path supplied")
        return result

    if expected and paths:
        suffix = f": {', '.join(missing_paths)}" if missing_paths else ""
        result["blockers"].append("local_repo_unavailable" + suffix)
        return result

    if paths and missing_paths:
        result["blockers"].append("missing_repo_identity: local paths are unavailable and no repo identity was supplied")
        result["blockers"].append("local_repo_unavailable: " + ", ".join(missing_paths))
        return result

    result["blockers"].append("missing_repo_identity: no local git remote or queue repo identity available")
    return result


def build_report(
    queue_path: Path,
    rows: list[dict[str, Any]],
    source_key: str,
    base_dir: Path,
    mirror_root: Path | None = None,
    repo_map: dict[str, Path] | None = None,
) -> dict[str, Any]:
    ready_rows = [row for row in rows if is_ready_row(row, source_key)]
    results = [
        verify_row(row, index, base_dir, mirror_root, repo_map)
        for index, row in enumerate(ready_rows)
    ]
    resolution_results = [
        verify_row(row, index, base_dir, mirror_root, repo_map)
        for index, row in enumerate(rows)
        if is_resolution_candidate(row, source_key)
    ]
    resolved_blockers = [
        {
            **result,
            "resolution_status": "resolved_locally",
            "original_blockers": normalize_blockers(
                rows[result["row_index"]].get("blockers") or rows[result["row_index"]].get("blocker")
            ),
        }
        for result in resolution_results
        if result["status"] == "verified"
    ]
    unresolved_resolution_ids = {
        result["id"] for result in resolution_results if result["status"] != "verified"
    }
    resolved_ids = {result["id"] for result in resolved_blockers}
    preserved_blockers = [
        {
            "id": row_id(row, index),
            "mirror_status": row.get("mirror_status") or row.get("status"),
            "blocker": row.get("blocker") or row.get("blockers"),
            "repo_url": row.get("repo_url"),
            "ref": row.get("ref"),
            "ref_kind": row.get("ref_kind"),
            "resolution_attempt": next(
                (result for result in resolution_results if result["id"] == row_id(row, index)),
                None,
            ),
            **(
                {"identity_resolution_hint": identity_resolution_hint(row, base_dir, queue_path)}
                if is_missing_identity_blocker(row)
                else {}
            ),
        }
        for index, row in enumerate(rows)
        if not is_ready_row(row, source_key)
        and row_id(row, index) not in resolved_ids
        and (
            row.get("blocker")
            or row.get("blockers")
            or row_id(row, index) in unresolved_resolution_ids
        )
    ]
    counts = {
        "ready": len(ready_rows),
        "verified": sum(1 for row in results if row["status"] == "verified"),
        "blocked": sum(1 for row in results if row["status"] == "blocked"),
        "resolved_blockers": len(resolved_blockers),
        "preserved_blockers": len(preserved_blockers),
    }
    return {
        "schema": SCHEMA,
        "queue_path": str(queue_path),
        "network": "not_used",
        "source_row_key": source_key,
        "counts": counts,
        "results": results,
        "resolved_blockers": resolved_blockers,
        "preserved_blockers": preserved_blockers,
        "identity_resolution_classes": missing_identity_classes(rows, source_key, queue_path, base_dir),
    }


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--queue", type=Path, default=DEFAULT_QUEUE, help=f"queue JSON path (default: {DEFAULT_QUEUE})")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help=f"report JSON path (default: {DEFAULT_OUT})")
    parser.add_argument(
        "--base-dir",
        type=Path,
        default=Path.cwd(),
        help="base directory for relative local paths in the queue",
    )
    parser.add_argument(
        "--mirror-root",
        type=Path,
        default=None,
        help="optional local mirror root; repo_url owner/name maps to <mirror-root>/<owner>/<name>",
    )
    parser.add_argument(
        "--repo-map",
        action="append",
        default=[],
        metavar="REPO=PATH",
        help="explicit local checkout mapping, e.g. github.com/base/base=/path/to/base",
    )
    parser.add_argument("--fail-on-blocked", action="store_true", help="exit non-zero when any ready row is blocked")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    queue = args.queue
    if not queue.exists():
        print(f"error: queue not found: {queue}", file=sys.stderr)
        return 2

    try:
        rows, source_key = load_queue(queue)
        mirror_root = args.mirror_root.resolve() if args.mirror_root else None
        repo_map: dict[str, Path] = {}
        for item in args.repo_map:
            if "=" not in item:
                print(f"error: invalid --repo-map value: {item}", file=sys.stderr)
                return 2
            repo, raw_path = item.split("=", 1)
            canonical = canonical_repo(repo)
            if canonical is None:
                print(f"error: invalid --repo-map repo identity: {repo}", file=sys.stderr)
                return 2
            repo_map[canonical] = expand_path(raw_path, args.base_dir.resolve())
        report = build_report(queue, rows, source_key, args.base_dir.resolve(), mirror_root, repo_map)
    except Exception as exc:
        print(f"error: failed to verify source mirror queue: {exc}", file=sys.stderr)
        return 2

    write_json(args.out, report)
    counts = report["counts"]
    print(
        f"[source-mirror-verify] ready={counts['ready']} "
        f"verified={counts['verified']} blocked={counts['blocked']} "
        f"resolved_blockers={counts.get('resolved_blockers', 0)} out={args.out}"
    )
    if args.fail_on_blocked and counts["blocked"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
