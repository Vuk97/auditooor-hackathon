#!/usr/bin/env python3
"""Offline deployment-timeline planning for audit-pin vs live-risk decisions.

The collector is intentionally conservative: it only uses local git metadata
and deployment/config files already present on disk.  It does not call RPCs or
network services; instead, uncertain live-deployment questions are preserved as
flags with exact follow-up commands for an operator to run later.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


SCHEMA = "auditooor.control.deployment_timeline.v1"

DEPLOYMENT_DIR_NAMES = {
    "contract-deployments",
    "deploy",
    "deployment",
    "deployments",
    "env",
}
DEPLOYMENT_FILE_SUFFIXES = {
    ".csv",
    ".env",
    ".json",
    ".md",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}
SKIP_DIR_NAMES = {
    ".git",
    ".tox",
    ".venv",
    "__pycache__",
    "cache",
    "node_modules",
    "out",
    "target",
    "vendor",
}
MAX_DEPLOYMENT_FILES = 100
MAX_DEPLOYMENT_ROOT_DEPTH = 5
MAX_COMMIT_CANDIDATES_PER_FILE = 5
MAX_ADDRESSES_PER_ENTRY = 25

COMMIT_LABEL_RE = re.compile(
    r"(?i)\b(?:"
    r"commit|git_commit|source_commit|sourceCommit|implementation_commit|"
    r"implementationCommit|deployment_commit|deploymentCommit|contracts_commit|"
    r"op_contracts_commit|l1_contracts_commit|l2_contracts_commit|version"
    r")\b\s*[:=]\s*[\"']?([0-9a-f]{7,40})\b"
)
GENERIC_COMMIT_RE = re.compile(r"(?<!0x)\b[0-9a-f]{40}\b", re.IGNORECASE)
ADDRESS_RE = re.compile(r"0x[a-fA-F0-9]{40}")
TIMESTAMP_RE = re.compile(
    r"\b20\d{2}-\d{2}-\d{2}"
    r"(?:[T ][0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)?\b"
)


def collect_deployment_timeline(
    workspace: str | Path,
    *,
    asset: str | None = None,
    repo_path: str | Path | None = None,
    bug_commit: str | None = None,
    deployment_roots: Iterable[str | Path] | None = None,
    network: str = "base",
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Return a conservative offline deployment-timeline packet.

    ``bug_commit`` is optional because some follow-up lanes start with a source
    symptom rather than a known introducing commit.  Unknown or unresolvable
    commits are modeled explicitly instead of being guessed.
    """

    ws = Path(workspace).expanduser().resolve()
    repo = _resolve_repo(ws, repo_path=repo_path)
    asset_name = asset or (repo.name if repo else ws.name)
    repo_info = _repo_info(repo)
    asset_pin = _asset_pin(repo)
    bug = _bug_info(repo, bug_commit)

    roots = _deployment_roots(ws, deployment_roots)
    scan = _scan_deployments(ws, repo, roots)
    risk_window = _risk_window(repo, asset_pin, bug, scan["entries"])
    uncertainty_flags = _global_uncertainty(repo_info, asset_pin, bug, scan, risk_window)

    payload = {
        "schema": SCHEMA,
        "workspace": ws.as_posix(),
        "generated_at": generated_at or _utc_now(),
        "asset": {
            "name": asset_name,
            "repo": repo_info,
            "pin": asset_pin,
        },
        "bug": bug,
        "deployment_evidence": scan,
        "risk_window": risk_window,
        "uncertainty_flags": uncertainty_flags,
        "follow_up_commands": _follow_up_commands(
            workspace=ws,
            repo=repo,
            asset=asset_name,
            bug_commit=bug_commit,
            deployment_entries=scan["entries"],
            uncertainty_flags=uncertainty_flags,
            network=network,
        ),
    }
    return payload


def render_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def write_timeline(payload: dict[str, Any], out_path: str | Path) -> Path:
    path = Path(out_path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_json(payload), encoding="utf-8")
    return path.resolve()


def _repo_info(repo: Path | None) -> dict[str, Any]:
    if repo is None:
        return {
            "path": None,
            "found": False,
            "uncertainty_flags": ["asset_repo_not_found"],
        }
    return {
        "path": repo.as_posix(),
        "found": True,
        "uncertainty_flags": [],
    }


def _asset_pin(repo: Path | None) -> dict[str, Any]:
    if repo is None:
        return {
            "commit": None,
            "commit_time": None,
            "source": "missing_local_git_repo",
            "uncertainty_flags": ["asset_pin_unknown"],
        }
    commit = _git(repo, "rev-parse", "HEAD")
    if not commit:
        return {
            "commit": None,
            "commit_time": None,
            "source": "git rev-parse HEAD failed",
            "uncertainty_flags": ["asset_pin_unknown"],
        }
    info = _commit_info(repo, commit)
    flags = [] if info.get("known") else ["asset_pin_time_unknown"]
    return {
        "commit": info.get("commit") or commit,
        "short_commit": _short(info.get("commit") or commit),
        "commit_time": info.get("commit_time"),
        "subject": info.get("subject"),
        "source": "git HEAD",
        "uncertainty_flags": flags,
    }


def _bug_info(repo: Path | None, bug_commit: str | None) -> dict[str, Any]:
    if not bug_commit:
        return {
            "introduced_commit": None,
            "introduced_time": None,
            "status": "unknown",
            "source": "not_provided",
            "uncertainty_flags": ["bug_commit_unknown"],
        }
    if repo is None:
        return {
            "introduced_commit": bug_commit,
            "introduced_time": None,
            "status": "unknown",
            "source": "provided_but_no_local_repo",
            "uncertainty_flags": ["asset_repo_not_found", "bug_commit_unverified"],
        }
    info = _commit_info(repo, bug_commit)
    if not info.get("known"):
        return {
            "introduced_commit": bug_commit,
            "introduced_time": None,
            "status": "unknown",
            "source": "provided_but_not_in_local_git",
            "uncertainty_flags": ["bug_commit_unknown"],
        }
    return {
        "introduced_commit": info.get("commit"),
        "short_commit": _short(str(info.get("commit") or bug_commit)),
        "introduced_time": info.get("commit_time"),
        "subject": info.get("subject"),
        "status": "known",
        "source": "provided_local_git_commit",
        "uncertainty_flags": [],
    }


def _scan_deployments(ws: Path, repo: Path | None, roots: list[Path]) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    files_scanned = 0
    truncated = False
    for file_path in _iter_deployment_files(roots):
        if files_scanned >= MAX_DEPLOYMENT_FILES:
            truncated = True
            break
        files_scanned += 1
        entry = _deployment_entry(ws, repo, file_path)
        if entry is not None:
            entries.append(entry)

    status = "found" if entries else "missing"
    flags: list[str] = []
    if not roots:
        flags.append("deployment_roots_missing")
    if not entries:
        flags.append("no_deployment_evidence")
    if truncated:
        flags.append("deployment_scan_truncated")

    return {
        "status": status,
        "search_roots": [root.as_posix() for root in roots],
        "files_scanned": files_scanned,
        "entries": entries,
        "uncertainty_flags": sorted(set(flags)),
    }


def _deployment_entry(ws: Path, repo: Path | None, path: Path) -> dict[str, Any] | None:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    if not text.strip():
        return None

    labeled_commits = _ordered_unique(m.group(1) for m in COMMIT_LABEL_RE.finditer(text))
    generic_commits = _ordered_unique(m.group(0) for m in GENERIC_COMMIT_RE.finditer(text))
    explicit_commits = _ordered_unique(labeled_commits + generic_commits)
    explicit_timestamps = _ordered_unique(m.group(0) for m in TIMESTAMP_RE.finditer(text))
    raw_addresses = _ordered_unique(ADDRESS_RE.findall(text))
    if not explicit_commits and not explicit_timestamps and not raw_addresses:
        return None
    addresses = raw_addresses[:MAX_ADDRESSES_PER_ENTRY]
    entry_flags: list[str] = []
    if len(raw_addresses) > MAX_ADDRESSES_PER_ENTRY:
        entry_flags.append("addresses_truncated")

    lookup_commits = labeled_commits or (generic_commits if len(generic_commits) <= 2 else [])
    source_commit = _first_known_commit(repo, lookup_commits)
    source_commit_info = _commit_info(repo, source_commit) if repo and source_commit else {}
    timestamp_info = _first_timestamp(explicit_timestamps)

    deployment_time = timestamp_info.get("timestamp")
    deployment_time_source = timestamp_info.get("source")
    flags = entry_flags + list(timestamp_info.get("uncertainty_flags") or [])
    if deployment_time is None and source_commit_info.get("commit_time"):
        deployment_time = source_commit_info["commit_time"]
        deployment_time_source = "source_commit_time"
    file_repo: Path | None = None
    file_commit_info: dict[str, Any] = {}
    if deployment_time is None and _path_is_within_repo(path, repo):
        file_repo = _git_root(path.parent)
        file_commit_info = _file_last_commit_info(file_repo, path) if file_repo else {}
    if deployment_time is None and file_commit_info.get("commit_time"):
        deployment_time = file_commit_info["commit_time"]
        deployment_time_source = "deployment_file_git_time"
        flags.append("deployment_time_from_file_commit")
    if explicit_commits and not source_commit:
        flags.append("deployment_source_commit_not_in_local_git")
    if not explicit_commits:
        flags.append("deployment_source_commit_missing")
    if deployment_time is None:
        flags.append("deployment_time_unknown")

    return {
        "path": path.as_posix(),
        "relative_path": _relative(path, ws),
        "explicit_commits": explicit_commits,
        "source_commit": source_commit_info.get("commit"),
        "source_commit_time": source_commit_info.get("commit_time"),
        "source_commit_subject": source_commit_info.get("subject"),
        "deployment_file_repo": file_repo.as_posix() if file_repo else None,
        "deployment_file_commit": file_commit_info.get("commit"),
        "deployment_file_commit_time": file_commit_info.get("commit_time"),
        "deployment_time": deployment_time,
        "deployment_time_source": deployment_time_source or "unknown",
        "explicit_timestamps": explicit_timestamps,
        "addresses": addresses,
        "uncertainty_flags": sorted(set(flags)),
    }


def _risk_window(
    repo: Path | None,
    asset_pin: dict[str, Any],
    bug: dict[str, Any],
    entries: list[dict[str, Any]],
) -> dict[str, Any]:
    flags: list[str] = []
    bug_commit = bug.get("introduced_commit")
    bug_time = _parse_time(bug.get("introduced_time"))
    pin_commit = asset_pin.get("commit")
    audit_pin_contains_bug = _contains_commit(repo, bug_commit, pin_commit)

    if audit_pin_contains_bug is None and bug_commit:
        flags.append("audit_pin_contains_bug_unknown")

    base = {
        "audit_pin_contains_bug": audit_pin_contains_bug,
        "start": None,
        "start_source": None,
        "end": None,
        "end_source": None,
        "end_status": "not_applicable",
        "classification": "unknown",
        "severity_decision_hint": "needs_manual_review",
        "supporting_deployment": None,
        "uncertainty_flags": flags,
    }

    if bug.get("status") != "known":
        base.update(
            {
                "classification": "unknown_bug_commit",
                "severity_decision_hint": "cannot_separate_audit_pin_from_live_risk_until_bug_commit_is_known",
            }
        )
        base["uncertainty_flags"] = sorted(set(flags + ["bug_commit_unknown", "cannot_order_bug_vs_deployment"]))
        return base

    if not entries:
        base.update(
            {
                "classification": "no_deployment_evidence",
                "severity_decision_hint": "audit_pin_source_risk_only_until_deployment_evidence_is_imported",
            }
        )
        base["uncertainty_flags"] = sorted(set(flags + ["no_deployment_evidence", "live_deployment_refresh_needed"]))
        return base

    enriched = [_deployment_relation(repo, bug_commit, bug_time, entry) for entry in entries]
    certain_including = [row for row in enriched if row["relation"] == "deployment_commit_contains_bug"]
    possible_after_bug = [row for row in enriched if row["relation"] == "deployment_time_after_bug_commit_unknown"]
    known_predating = [row for row in enriched if row["relation"] == "deployment_commit_predates_bug"]
    time_predating = [row for row in enriched if row["relation"] == "deployment_time_predates_bug_commit_unknown"]

    if certain_including:
        first = _earliest(certain_including)
        base.update(
            {
                "start": first.get("deployment_time") or first.get("source_commit_time"),
                "start_source": first.get("deployment_time_source") or "source_commit_time",
                "end": None,
                "end_source": None,
                "end_status": "open_until_fix_or_live_verification",
                "classification": "bug_before_deployment",
                "severity_decision_hint": "live_deployment_risk_possible_from_start",
                "supporting_deployment": _supporting_deployment(first),
            }
        )
        base["uncertainty_flags"] = sorted(set(flags + ["risk_window_end_unverified"]))
        return base

    if possible_after_bug:
        first = _earliest(possible_after_bug)
        base.update(
            {
                "start": first.get("deployment_time"),
                "start_source": first.get("deployment_time_source"),
                "end": None,
                "end_source": None,
                "end_status": "open_if_live_deployment_contains_bug",
                "classification": "deployment_after_bug_time_commit_unknown",
                "severity_decision_hint": "live_deployment_risk_possible_but_requires_source_commit_or_rpc_verification",
                "supporting_deployment": _supporting_deployment(first),
            }
        )
        base["uncertainty_flags"] = sorted(
            set(flags + ["deployment_source_commit_missing", "live_window_start_uncertain", "risk_window_end_unverified"])
        )
        return base

    if known_predating and len(known_predating) == len(enriched):
        latest = _latest(known_predating)
        base.update(
            {
                "classification": "known_deployments_predate_bug",
                "severity_decision_hint": "audit_pin_risk_only_for_known_deployments_until_live_deployment_refresh",
                "supporting_deployment": _supporting_deployment(latest),
            }
        )
        base["uncertainty_flags"] = sorted(set(flags + ["no_known_live_deployment_includes_bug", "live_deployment_refresh_needed"]))
        return base

    if (known_predating or time_predating) and len(known_predating) + len(time_predating) == len(enriched):
        latest = _latest(known_predating + time_predating)
        base.update(
            {
                "classification": "deployment_evidence_predates_bug",
                "severity_decision_hint": "audit_pin_risk_only_unless_newer_live_deployment_exists",
                "supporting_deployment": _supporting_deployment(latest),
            }
        )
        base["uncertainty_flags"] = sorted(
            set(flags + ["deployment_source_commit_missing", "no_known_live_deployment_includes_bug", "live_deployment_refresh_needed"])
        )
        return base

    base.update(
        {
            "classification": "deployment_order_uncertain",
            "severity_decision_hint": "needs_deployment_commit_or_live_rpc_verification",
        }
    )
    base["uncertainty_flags"] = sorted(set(flags + ["deployment_order_uncertain", "live_deployment_refresh_needed"]))
    return base


def _deployment_relation(
    repo: Path | None,
    bug_commit: str | None,
    bug_time: datetime | None,
    entry: dict[str, Any],
) -> dict[str, Any]:
    row = dict(entry)
    source_commit = entry.get("source_commit")
    deployment_time = _parse_time(entry.get("deployment_time"))
    if repo and bug_commit and source_commit:
        contains = _contains_commit(repo, bug_commit, source_commit)
        if contains is True:
            row["relation"] = "deployment_commit_contains_bug"
            return row
        predates = _contains_commit(repo, source_commit, bug_commit)
        if predates is True:
            row["relation"] = "deployment_commit_predates_bug"
            return row
        row["relation"] = "deployment_commit_unrelated_or_unknown"
        return row
    if bug_time and deployment_time:
        row["relation"] = (
            "deployment_time_after_bug_commit_unknown"
            if deployment_time >= bug_time
            else "deployment_time_predates_bug_commit_unknown"
        )
        return row
    row["relation"] = "deployment_order_unknown"
    return row


def _global_uncertainty(
    repo_info: dict[str, Any],
    asset_pin: dict[str, Any],
    bug: dict[str, Any],
    scan: dict[str, Any],
    risk_window: dict[str, Any],
) -> list[str]:
    flags: list[str] = []
    for section in (repo_info, asset_pin, bug, scan, risk_window):
        flags.extend(section.get("uncertainty_flags") or [])
    for entry in scan.get("entries") or []:
        flags.extend(entry.get("uncertainty_flags") or [])
    return sorted(set(str(flag) for flag in flags if flag))


def _follow_up_commands(
    *,
    workspace: Path,
    repo: Path | None,
    asset: str,
    bug_commit: str | None,
    deployment_entries: list[dict[str, Any]],
    uncertainty_flags: list[str],
    network: str,
) -> list[dict[str, Any]]:
    commands: list[dict[str, Any]] = []
    quoted_ws = shlex.quote(workspace.as_posix())
    quoted_asset = shlex.quote(asset)
    rpc_env_var = _rpc_env_var(network)
    if repo and ("bug_commit_unknown" in uncertainty_flags or not bug_commit):
        commands.append(
            {
                "id": "locate_bug_commit",
                "requires_network": False,
                "reason": "Find the first local commit that introduced the vulnerable behavior.",
                "command": f"git -C {shlex.quote(repo.as_posix())} log --all --date=iso-strict --reverse -- .",
            }
        )
    if "no_deployment_evidence" in uncertainty_flags or "deployment_roots_missing" in uncertainty_flags:
        commands.append(
            {
                "id": "find_deployment_roots",
                "requires_network": False,
                "reason": "Locate local deployment/config directories that were not imported into the workspace.",
                "command": (
                    f"find {quoted_ws} -maxdepth 5 -type d "
                    r"\( -name deployments -o -name deploy -o -name contract-deployments -o -name env \) -print"
                ),
            }
        )
        commands.append(
            {
                "id": "deployment_lookup",
                "requires_network": False,
                "reason": "Search local deployment/config evidence for the affected asset.",
                "command": f"bash tools/deploy-state-lookup.sh {quoted_ws} {quoted_asset} --json",
            }
        )
    if (
        "deployment_source_commit_missing" in uncertainty_flags
        or "deployment_order_uncertain" in uncertainty_flags
        or "live_deployment_refresh_needed" in uncertainty_flags
    ):
        commands.append(
            {
                "id": "refresh_deployment_lookup_with_rpc",
                "requires_network": True,
                "reason": "Resolve whether the live deployment still points at code containing the bug.",
                "command": (
                    f"bash tools/deploy-state-lookup.sh {quoted_ws} {quoted_asset} "
                    f"--network {shlex.quote(network)} --rpc-url \"${rpc_env_var}\" --json"
                ),
            }
        )

    live_addresses = _ordered_unique(
        address for entry in deployment_entries for address in entry.get("addresses", [])
    )
    if live_addresses and any(
        flag in uncertainty_flags
        for flag in (
            "live_window_start_uncertain",
            "risk_window_end_unverified",
            "live_deployment_refresh_needed",
        )
    ):
        for index, address in enumerate(live_addresses[:3], start=1):
            commands.append(
                {
                    "id": f"live_state_check_{index}",
                    "requires_network": True,
                    "reason": "Pin live state for a candidate deployed address before using live severity framing.",
                    "command": (
                        f"python3 tools/live-state-checker.py --workspace {quoted_ws} "
                        f"--network {shlex.quote(network)} --rpc-url \"${rpc_env_var}\" "
                        f"--address {shlex.quote(address)} --json"
                    ),
                }
            )
    return commands


def _deployment_roots(ws: Path, explicit_roots: Iterable[str | Path] | None) -> list[Path]:
    if explicit_roots is not None:
        roots: list[Path] = []
        for root in explicit_roots:
            resolved = _resolve_existing(ws, root)
            roots.extend(_expand_deployment_root(resolved))
        return _ordered_paths(roots)

    candidates: list[Path] = [
        ws / "deployments",
        ws / "deployment",
        ws / "deploy",
        ws / "env",
        ws / "env" / "latest",
        ws / "external" / "contract-deployments",
    ]
    candidates.extend(_discover_deployment_roots(ws))
    return _ordered_paths(candidate for candidate in candidates if candidate.exists())


def _expand_deployment_root(root: Path) -> list[Path]:
    """Return bounded deployment roots for an explicit operator path.

    Operators often pass the workspace root as ``--deployment-root``.  Treating
    that as a recursive scan target can walk huge borrowed source trees, so a
    broad directory is first reduced to deployment-like children and direct
    config files.
    """

    if not root.exists():
        return []
    if root.is_file():
        return [root] if _is_deployment_file(root) else []
    if _is_deployment_root_dir(root):
        return [root]

    roots: list[Path] = []
    roots.extend(_direct_deployment_files(root))
    roots.extend(_discover_deployment_roots(root))
    return roots


def _discover_deployment_roots(base: Path) -> list[Path]:
    candidates: list[Path] = []
    if not base.exists() or not base.is_dir():
        return candidates

    for root, dirs, _files in os.walk(base):
        root_path = Path(root)
        dirs[:] = [
            name
            for name in dirs
            if name not in SKIP_DIR_NAMES and not name.startswith(".")
        ]
        depth = len(root_path.relative_to(base).parts) if root_path != base else 0
        if depth >= MAX_DEPLOYMENT_ROOT_DEPTH:
            dirs[:] = []
            continue
        keep_dirs: list[str] = []
        for name in dirs:
            child = root_path / name
            if _is_deployment_root_dir(child):
                candidates.append(child)
                # The deployment root itself will be scanned later; avoid
                # continuing root discovery through large nested artifacts.
                continue
            keep_dirs.append(name)
        dirs[:] = keep_dirs
    return candidates


def _direct_deployment_files(root: Path) -> list[Path]:
    try:
        return sorted(path for path in root.iterdir() if path.is_file() and _is_broad_root_deployment_file(path))
    except OSError:
        return []


def _is_deployment_root_dir(path: Path) -> bool:
    name = path.name
    return name in DEPLOYMENT_DIR_NAMES or (name == "latest" and path.parent.name == "env")


def _iter_deployment_files(roots: Iterable[Path]) -> Iterable[Path]:
    seen: set[Path] = set()
    for root in roots:
        if root.is_file():
            if _is_deployment_file(root) and root not in seen:
                seen.add(root)
                yield root
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [name for name in dirnames if name not in SKIP_DIR_NAMES and not name.startswith(".")]
            for filename in sorted(filenames):
                path = Path(dirpath) / filename
                if path in seen or not _is_deployment_file(path):
                    continue
                seen.add(path)
                yield path


def _is_deployment_file(path: Path) -> bool:
    name = path.name.lower()
    return path.suffix.lower() in DEPLOYMENT_FILE_SUFFIXES or name.startswith(".env")


def _is_broad_root_deployment_file(path: Path) -> bool:
    name = path.name.lower()
    if name.startswith(".env"):
        return True
    if path.suffix.lower() not in DEPLOYMENT_FILE_SUFFIXES:
        return False
    return any(token in name for token in ("deploy", "deployment", "address"))


def _resolve_repo(ws: Path, *, repo_path: str | Path | None) -> Path | None:
    starts: list[Path] = []
    if repo_path is not None:
        starts.append(Path(repo_path).expanduser())
    else:
        starts.extend([ws, ws / "src"])
        external = ws / "external"
        if external.is_dir():
            starts.extend(sorted(path for path in external.iterdir() if path.is_dir()))

    for start in starts:
        root = _git_root(start)
        if root is not None:
            return root
    return None


def _git_root(path: Path) -> Path | None:
    if not path.exists():
        return None
    out = _git(path, "rev-parse", "--show-toplevel")
    if not out:
        return None
    return Path(out).resolve()


def _commit_info(repo: Path | None, ref: str | None) -> dict[str, Any]:
    if not repo or not ref:
        return {"known": False}
    commit = _git(repo, "rev-parse", "--verify", f"{ref}^{{commit}}")
    if not commit:
        return {"known": False, "ref": ref}
    raw = _git(repo, "show", "-s", "--format=%H%x00%cI%x00%s", commit)
    if not raw:
        return {"known": False, "ref": ref}
    parts = raw.split("\x00", 2)
    return {
        "known": True,
        "commit": parts[0],
        "commit_time": _normalize_time(parts[1]) if len(parts) > 1 else None,
        "subject": parts[2] if len(parts) > 2 else None,
    }


def _file_last_commit_info(repo: Path | None, path: Path) -> dict[str, Any]:
    if not repo:
        return {}
    try:
        rel = path.resolve().relative_to(repo)
    except ValueError:
        return {}
    commit = _git(repo, "log", "-1", "--format=%H", "--", rel.as_posix())
    if not commit:
        return {}
    return _commit_info(repo, commit)


def _first_known_commit(repo: Path | None, commits: list[str]) -> str | None:
    if not repo:
        return None
    for commit in commits[:MAX_COMMIT_CANDIDATES_PER_FILE]:
        info = _commit_info(repo, commit)
        if info.get("known"):
            return str(info["commit"])
    return None


def _contains_commit(repo: Path | None, ancestor: Any, descendant: Any) -> bool | None:
    if not repo or not ancestor or not descendant:
        return None
    result = subprocess.run(
        ["git", "-C", repo.as_posix(), "merge-base", "--is-ancestor", str(ancestor), str(descendant)],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        return True
    if result.returncode == 1:
        return False
    return None


def _git(repo: Path, *args: str) -> str | None:
    try:
        result = subprocess.run(
            ["git", "-C", repo.as_posix(), *args],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def _first_timestamp(values: list[str]) -> dict[str, Any]:
    flags: list[str] = []
    for raw in values:
        normalized = _normalize_time(raw)
        if normalized is None:
            flags.append("deployment_timestamp_unparseable")
            continue
        if re.fullmatch(r"20\d{2}-\d{2}-\d{2}", raw):
            flags.append("deployment_timestamp_date_only")
        if "T" not in raw and " " in raw:
            flags.append("deployment_timestamp_timezone_assumed_utc")
        if "Z" not in raw and not re.search(r"[+-]\d{2}:?\d{2}$", raw):
            flags.append("deployment_timestamp_timezone_assumed_utc")
        return {
            "timestamp": normalized,
            "source": "explicit_timestamp",
            "uncertainty_flags": sorted(set(flags)),
        }
    return {"timestamp": None, "source": None, "uncertainty_flags": sorted(set(flags))}


def _normalize_time(value: Any) -> str | None:
    parsed = _parse_time(value)
    if parsed is None:
        return None
    return parsed.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    raw = value.strip().replace(" ", "T")
    if re.fullmatch(r"20\d{2}-\d{2}-\d{2}", raw):
        raw = f"{raw}T00:00:00Z"
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    if re.search(r"[+-]\d{4}$", raw):
        raw = raw[:-5] + raw[-5:-2] + ":" + raw[-2:]
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _earliest(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return sorted(rows, key=lambda row: _sort_time(row, latest=False))[0]


def _latest(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return sorted(rows, key=lambda row: _sort_time(row, latest=True), reverse=True)[0]


def _sort_time(row: dict[str, Any], *, latest: bool) -> datetime:
    parsed = _parse_time(row.get("deployment_time") or row.get("source_commit_time"))
    if parsed is not None:
        return parsed
    return datetime.max.replace(tzinfo=timezone.utc) if not latest else datetime.min.replace(tzinfo=timezone.utc)


def _supporting_deployment(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "path": row.get("path"),
        "relative_path": row.get("relative_path"),
        "source_commit": row.get("source_commit"),
        "deployment_time": row.get("deployment_time"),
        "deployment_time_source": row.get("deployment_time_source"),
        "relation": row.get("relation"),
    }


def _resolve_existing(ws: Path, root: str | Path) -> Path:
    path = Path(root).expanduser()
    if not path.is_absolute():
        path = ws / path
    return path.resolve()


def _path_is_within_repo(path: Path, repo: Path | None) -> bool:
    if repo is None:
        return False
    try:
        path.resolve().relative_to(repo.resolve())
    except ValueError:
        return False
    return True


def _ordered_paths(paths: Iterable[Path]) -> list[Path]:
    out: list[Path] = []
    seen: set[Path] = set()
    for path in paths:
        resolved = path.resolve()
        if resolved in seen or not resolved.exists():
            continue
        seen.add(resolved)
        out.append(resolved)
    return out


def _ordered_unique(values: Iterable[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        item = str(value).strip()
        key = item.lower()
        if not item or key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def _relative(path: Path, base: Path) -> str:
    try:
        return path.resolve().relative_to(base.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _short(commit: str | None) -> str | None:
    return commit[:12] if commit else None


def _rpc_env_var(network: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9]+", "_", network or "base").strip("_").upper()
    return f"{normalized or 'BASE'}_RPC_URL"


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def main() -> None:
    parser = argparse.ArgumentParser(description="Build an offline deployment timeline for severity planning")
    parser.add_argument("workspace", help="Audit workspace or local asset repository")
    parser.add_argument("--asset", help="Human asset name for report output")
    parser.add_argument("--repo", help="Local git repository root when it differs from workspace")
    parser.add_argument("--bug-commit", help="Known introducing commit or ref")
    parser.add_argument("--deployment-root", action="append", help="Deployment/config directory or file to scan")
    parser.add_argument("--network", default="base", help="Network label for generated follow-up commands")
    parser.add_argument("--out", help="Optional JSON output path")
    args = parser.parse_args()

    payload = collect_deployment_timeline(
        args.workspace,
        asset=args.asset,
        repo_path=args.repo,
        bug_commit=args.bug_commit,
        deployment_roots=args.deployment_root,
        network=args.network,
    )
    if args.out:
        write_timeline(payload, args.out)
    print(render_json(payload), end="")


__all__ = [
    "SCHEMA",
    "collect_deployment_timeline",
    "render_json",
    "write_timeline",
]


if __name__ == "__main__":
    main()
