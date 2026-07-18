#!/usr/bin/env python3
"""Emit offline source-review packets for mirror-verified commit-mining tasks.

This runner consumes the scan-task queue produced after source-mirror
verification and performs only local git inspection. It intentionally stops at
source-review packets: the output is not exploit proof, impact proof, detector
promotion proof, or submission readiness.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any


REPO = Path(__file__).resolve().parents[1]
DEFAULT_IN = REPO / "reports" / "commit_mining_scan_tasks_2026-05-05.json"
DEFAULT_OUT = REPO / "reports" / "commit_mining_source_review_2026-05-05.json"
DEFAULT_MD = REPO / "docs" / "COMMIT_MINING_SOURCE_REVIEW_2026-05-05.md"
SCHEMA = "auditooor.commit_mining_source_review.v1"
SUBMISSION_POSTURE = "NOT_SUBMIT_READY"
DEFAULT_GENERATED_AT = "1970-01-01T00:00:00+00:00"
MAX_HOTSPOTS = 8
MAX_FILE_SAMPLES = 12
MAX_DIRECTORY_SAMPLES = 5
LARGE_COMMIT_FILE_THRESHOLD = 200
ALLOWED_GIT_SUBCOMMANDS = frozenset({"cat-file", "diff-tree", "rev-parse", "show", "tag"})
DISALLOWED_CLAIMS = (
    "exploitability",
    "impact",
    "severity",
    "detector promotion",
    "submission readiness",
)

PROOF_BOUNDARY = (
    "Offline source-review packets summarize local git metadata and diff stats "
    "for mirror-verified refs only. They are not exploit proof, severity proof, "
    "impact proof, detector promotion proof, or submission readiness."
)

REVIEW_KEYWORDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("consensus_or_fork_logic", ("consensus", "fork", "isthmus", "ecotone", "fjord", "withdrawal", "beacon", "blob")),
    ("state_transition", ("state", "transition", "deposit", "withdraw", "finalize", "execute", "derivation")),
    ("fee_or_accounting", ("fee", "balance", "amount", "credit", "debit", "accounting", "refund")),
    ("authorization", ("auth", "admin", "owner", "permission", "allow", "deny", "role")),
    ("proof_or_hashing", ("proof", "root", "hash", "merkle", "signature", "verify")),
    ("availability_or_dos", ("timeout", "limit", "queue", "pause", "block", "dos", "gas")),
    ("tests_or_fixtures", ("test", "fixture", "spec", "mock")),
)


@dataclass(frozen=True)
class GitResult:
    returncode: int
    stdout: str
    stderr: str


def _run_git(git_root: Path, args: list[str]) -> GitResult:
    if not args or args[0] not in ALLOWED_GIT_SUBCOMMANDS:
        raise ValueError(f"disallowed git subcommand for offline source review: {args[0] if args else '<empty>'}")
    proc = subprocess.run(
        ["git", "-C", str(git_root), *args],
        capture_output=True,
        text=True,
        timeout=30,
    )
    return GitResult(proc.returncode, proc.stdout, proc.stderr)


def _rel(path: Path, repo: Path) -> str:
    try:
        return path.resolve().relative_to(repo.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def load_scan_tasks(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _deterministic_generated_at(scan_tasks: dict[str, Any], input_path: Path | None) -> str:
    for key in ("generated_at_utc", "date"):
        raw = str(scan_tasks.get(key) or "").strip()
        if not raw:
            continue
        if key == "generated_at_utc":
            return raw
        return f"{raw}T00:00:00+00:00"
    if input_path is not None:
        match = re.search(r"(\d{4}-\d{2}-\d{2})", input_path.name)
        if match:
            return f"{match.group(1)}T00:00:00+00:00"
    return DEFAULT_GENERATED_AT


def _is_verified_task(task: dict[str, Any]) -> bool:
    verify = task.get("source_mirror_verify")
    if not isinstance(verify, dict):
        return False
    return verify.get("status") == "verified" and verify.get("ref_verified") is True


def _parse_commit_metadata(raw: str) -> dict[str, Any]:
    lines = raw.splitlines()
    keys = (
        "commit",
        "parents",
        "author_name",
        "author_email",
        "author_date",
        "committer_name",
        "committer_email",
        "committer_date",
        "subject",
    )
    values = {key: (lines[idx] if idx < len(lines) else "") for idx, key in enumerate(keys)}
    parents = [p for p in values["parents"].split() if p]
    return {
        "commit": values["commit"],
        "parents": parents,
        "parent_count": len(parents),
        "author": {
            "name": values["author_name"],
            "email": values["author_email"],
            "date": values["author_date"],
        },
        "committer": {
            "name": values["committer_name"],
            "email": values["committer_email"],
            "date": values["committer_date"],
        },
        "subject": values["subject"],
    }


def _parse_name_status(raw: str) -> list[dict[str, Any]]:
    files: list[dict[str, Any]] = []
    for line in raw.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        status = parts[0]
        if status.startswith("R") and len(parts) >= 3:
            files.append({"status": "R", "similarity": status[1:], "old_path": parts[1], "path": parts[2]})
        elif status.startswith("C") and len(parts) >= 3:
            files.append({"status": "C", "similarity": status[1:], "old_path": parts[1], "path": parts[2]})
        elif len(parts) >= 2:
            files.append({"status": status, "path": parts[1]})
    return files


def _parse_numstat(raw: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in raw.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        added_raw, deleted_raw, path = parts[0], parts[1], parts[-1]
        binary = added_raw == "-" or deleted_raw == "-"
        rows.append(
            {
                "path": path,
                "additions": None if binary else int(added_raw),
                "deletions": None if binary else int(deleted_raw),
                "binary": binary,
            }
        )
    return rows


def _extension(path: str) -> str:
    suffix = Path(path).suffix.lower()
    return suffix if suffix else "[no extension]"


def _directory(path: str) -> str:
    parts = Path(path).parts
    if len(parts) >= 2:
        return "/".join(parts[:2])
    if len(parts) == 1:
        return parts[0]
    return "."


def _review_focus(paths: list[str], subject: str) -> list[str]:
    haystack = " ".join([subject, *paths]).lower()
    focus = [label for label, words in REVIEW_KEYWORDS if any(word in haystack for word in words)]
    return focus or ["general_patch_review"]


def _stable_counter_rows(counter: Counter[str], *, limit: int | None = None) -> list[dict[str, Any]]:
    rows = [{"name": name, "count": count} for name, count in counter.items()]
    rows.sort(key=lambda row: (-int(row["count"]), str(row["name"])))
    return rows[:limit] if limit is not None else rows


def _sample_changed_files(
    name_status: list[dict[str, Any]],
    path_to_stats: dict[str, dict[str, Any]],
) -> tuple[list[dict[str, Any]], int]:
    rows: list[dict[str, Any]] = []
    for row in sorted(name_status, key=lambda item: str(item.get("path") or "")):
        path = str(row.get("path") or "")
        if not path:
            continue
        stat = path_to_stats.get(path, {})
        sample = {
            "path": path,
            "status": str(row.get("status") or ""),
            "additions": stat.get("additions"),
            "deletions": stat.get("deletions"),
            "binary": bool(stat.get("binary", False)),
        }
        if row.get("old_path"):
            sample["old_path"] = str(row["old_path"])
        if row.get("similarity"):
            sample["similarity"] = str(row["similarity"])
        rows.append(sample)
    sampled = rows[:MAX_FILE_SAMPLES]
    return sampled, max(0, len(rows) - len(sampled))


def _build_diff_stats(numstat: list[dict[str, Any]], name_status: list[dict[str, Any]]) -> dict[str, Any]:
    path_to_stats = {row["path"]: row for row in numstat}
    changed_paths = [row.get("path", "") for row in name_status if row.get("path")]
    if not changed_paths:
        changed_paths = [row["path"] for row in numstat]

    additions = sum(row["additions"] or 0 for row in numstat)
    deletions = sum(row["deletions"] or 0 for row in numstat)
    binary_files = sum(1 for row in numstat if row["binary"])
    status_counts = Counter(row.get("status", "?")[0] for row in name_status)
    ext_counts = Counter(_extension(path) for path in changed_paths)
    dir_counts = Counter(_directory(path) for path in changed_paths)

    hotspots: list[dict[str, Any]] = []
    for path in changed_paths:
        stat = path_to_stats.get(path, {})
        add = stat.get("additions") or 0
        delete = stat.get("deletions") or 0
        hotspots.append(
            {
                "path": path,
                "additions": stat.get("additions"),
                "deletions": stat.get("deletions"),
                "binary": bool(stat.get("binary", False)),
                "churn": add + delete,
            }
        )
    hotspots.sort(key=lambda row: (-row["churn"], row["path"]))
    sample_changed_files, omitted_changed_file_count = _sample_changed_files(name_status, path_to_stats)

    return {
        "changed_file_count": len(changed_paths),
        "additions": additions,
        "deletions": deletions,
        "binary_file_count": binary_files,
        "status_counts": dict(sorted(status_counts.items())),
        "extension_counts": dict(sorted(ext_counts.items())),
        "top_directories": _stable_counter_rows(dir_counts, limit=MAX_DIRECTORY_SAMPLES),
        "hotspots": hotspots[:MAX_HOTSPOTS],
        "sample_changed_files": sample_changed_files,
        "omitted_changed_file_count": omitted_changed_file_count,
    }


def _scope_flags(commit_metadata: dict[str, Any], diff_stats: dict[str, Any]) -> list[str]:
    flags: list[str] = []
    if int(commit_metadata.get("parent_count") or 0) == 0:
        flags.append("root_or_grafted_snapshot")
    file_count = int(diff_stats["changed_file_count"])
    if file_count >= LARGE_COMMIT_FILE_THRESHOLD:
        flags.append("broad_multi_module_change")
    elif file_count == 1:
        flags.append("single_file_patch")
    elif file_count <= 5:
        flags.append("narrow_patch")
    if int(diff_stats["binary_file_count"]) > 0:
        flags.append("contains_binary_artifacts")
    return flags


def _primary_paths(diff_stats: dict[str, Any]) -> list[str]:
    return [str(row["path"]) for row in diff_stats["hotspots"]]


def _scope_summary(commit_metadata: dict[str, Any], diff_stats: dict[str, Any], focus: list[str]) -> str:
    file_count = int(diff_stats["changed_file_count"])
    primary_files = _primary_paths(diff_stats)
    primary_file = primary_files[0] if primary_files else "no sampled file"
    directories = [str(row["name"]) for row in diff_stats["top_directories"][:2]]
    directory_clause = ""
    if directories:
        directory_clause = f" across {', '.join(directories)}"
    focus_clause = ", ".join(focus[:2])
    if int(commit_metadata.get("parent_count") or 0) == 0 or file_count >= LARGE_COMMIT_FILE_THRESHOLD:
        return (
            f"Broad advisory packet for {file_count} changed files{directory_clause}; "
            f"treat it as import-level context and narrow follow-up review to specific hotspots such as {primary_file} "
            f"before making any separate exploit, impact, severity, or submission assessment."
        )
    if file_count == 1:
        return (
            f"Single-file advisory patch centered on {primary_file}; review {focus_clause or 'local logic'} "
            f"and preserve a separate proof step for any exploit, impact, severity, or submission claim."
        )
    return (
        f"Focused advisory packet covering {file_count} files{directory_clause}; start from {primary_file} and use "
        f"{focus_clause or 'the sampled hotspots'} to guide any later follow-up without promoting this packet beyond source review."
    )


def _assessment_posture() -> dict[str, Any]:
    return {
        "advisory_only": True,
        "exploit_proof": False,
        "severity_claim": "",
        "exploitability_claim": "",
        "impact_claim": "",
        "submission_posture": SUBMISSION_POSTURE,
        "submit_ready": False,
        "disallowed_claims": list(DISALLOWED_CLAIMS),
    }


def _normalize_string_list(values: Any) -> list[str]:
    if not isinstance(values, list):
        return []
    return sorted({str(value) for value in values if str(value or "").strip()})


def _task_sort_key(task: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(task.get("task_id") or ""),
        str(task.get("source_row_id") or ""),
        str(task.get("commit_sha") or ""),
    )


def inspect_task(task: dict[str, Any], repo: Path) -> dict[str, Any]:
    task_id = str(task.get("task_id") or "")
    commit_sha = str(task.get("commit_sha") or "")
    git_root = Path(str(task.get("git_root") or ""))
    blockers: list[dict[str, str]] = []
    posture = _assessment_posture()

    if not _is_verified_task(task):
        blockers.append({"code": "source_mirror_not_verified", "message": "task is not source-mirror verified"})
    if not commit_sha:
        blockers.append({"code": "missing_commit_sha", "message": "task has no commit_sha"})
    if not git_root.is_dir():
        blockers.append({"code": "missing_git_root", "message": f"git_root does not exist: {git_root}"})

    if blockers:
        return _blocked_packet(task, blockers)

    commit_check = _run_git(git_root, ["cat-file", "-e", f"{commit_sha}^{{commit}}"])
    if commit_check.returncode != 0:
        blockers.append(
            {
                "code": "commit_not_available_locally",
                "message": commit_check.stderr.strip() or f"commit not available locally: {commit_sha}",
            }
        )
        return _blocked_packet(task, blockers)

    top = _run_git(git_root, ["rev-parse", "--show-toplevel"])
    if top.returncode != 0:
        blockers.append({"code": "git_toplevel_failed", "message": top.stderr.strip()})
        return _blocked_packet(task, blockers)
    local_top = Path(top.stdout.strip())

    meta_raw = _run_git(
        git_root,
        ["show", "-s", "--format=%H%n%P%n%an%n%ae%n%aI%n%cn%n%ce%n%cI%n%s", commit_sha],
    )
    if meta_raw.returncode != 0:
        blockers.append({"code": "git_metadata_failed", "message": meta_raw.stderr.strip()})
        return _blocked_packet(task, blockers)
    metadata = _parse_commit_metadata(meta_raw.stdout)
    tags_raw = _run_git(git_root, ["tag", "--points-at", commit_sha])
    if tags_raw.returncode == 0:
        metadata["tags"] = sorted(line.strip() for line in tags_raw.stdout.splitlines() if line.strip())
    else:
        metadata["tags"] = []

    name_status_raw = _run_git(git_root, ["diff-tree", "--root", "--no-commit-id", "--name-status", "-r", "-M", commit_sha])
    numstat_raw = _run_git(git_root, ["diff-tree", "--root", "--no-commit-id", "--numstat", "-r", "-M", commit_sha])
    if name_status_raw.returncode != 0 or numstat_raw.returncode != 0:
        blockers.append(
            {
                "code": "git_diff_stats_failed",
                "message": (name_status_raw.stderr + numstat_raw.stderr).strip(),
            }
        )
        return _blocked_packet(task, blockers)

    name_status = _parse_name_status(name_status_raw.stdout)
    numstat = _parse_numstat(numstat_raw.stdout)
    diff_stats = _build_diff_stats(numstat, name_status)
    if diff_stats["changed_file_count"] == 0:
        blockers.append({"code": "empty_commit_diff", "message": "commit produced no local diff-tree file stats"})
        return _blocked_packet(task, blockers)

    changed_paths = [row.get("path", "") for row in diff_stats["sample_changed_files"] if row.get("path")]
    if len(changed_paths) < diff_stats["changed_file_count"]:
        changed_paths = [row.get("path", "") for row in diff_stats["hotspots"] if row.get("path")] or changed_paths
    focus = _review_focus(changed_paths, metadata["subject"])
    scope_flags = _scope_flags(metadata, diff_stats)

    return {
        "task_id": task_id,
        "source_row_id": task.get("source_row_id"),
        "target": task.get("target"),
        "repo_identity": task.get("repo_identity"),
        "commit_sha": commit_sha,
        "status": "source_review_packet_emitted",
        "blockers": [],
        **posture,
        "proof_boundary": PROOF_BOUNDARY,
        "local_git": {
            "git_root": str(git_root),
            "toplevel": str(local_top),
            "commit_present_locally": True,
            "network_used": False,
            "allowed_git_subcommands": sorted(ALLOWED_GIT_SUBCOMMANDS),
        },
        "commit_metadata": metadata,
        "diff_stats": diff_stats,
        "source_review_packet": {
            "packet_id": f"source-review-{task_id}",
            "review_objective": task.get("review_objective"),
            "review_focus": focus,
            "scope_flags": scope_flags,
            "summary": _scope_summary(metadata, diff_stats, focus),
            "primary_files": _primary_paths(diff_stats),
            "primary_directories": [str(row["name"]) for row in diff_stats["top_directories"]],
            "terminal_state_options": _normalize_string_list(task.get("terminal_state_options", [])),
            "required_next_step": (
                "Record a source-review disposition or a separate follow-up review plan. "
                "Do not mark exploitability, impact, severity, detector promotion, or submission readiness from this advisory packet alone."
            ),
        },
        "input_evidence_paths": _normalize_string_list(task.get("evidence_paths", [])),
    }


def _blocked_packet(task: dict[str, Any], blockers: list[dict[str, str]]) -> dict[str, Any]:
    posture = _assessment_posture()
    return {
        "task_id": task.get("task_id"),
        "source_row_id": task.get("source_row_id"),
        "target": task.get("target"),
        "repo_identity": task.get("repo_identity"),
        "commit_sha": task.get("commit_sha"),
        "status": "blocked",
        "blockers": blockers,
        **posture,
        "proof_boundary": PROOF_BOUNDARY,
    }


def build_report(
    scan_tasks: dict[str, Any],
    repo: Path,
    *,
    input_path: Path | None = None,
    generated_at_utc: str | None = None,
) -> dict[str, Any]:
    tasks = scan_tasks.get("tasks", [])
    if not isinstance(tasks, list):
        raise ValueError("input report must contain a tasks list")

    posture = _assessment_posture()
    ordered_tasks = sorted((task for task in tasks if isinstance(task, dict)), key=_task_sort_key)
    packets = [inspect_task(task, repo) for task in ordered_tasks]
    blocked = [packet for packet in packets if packet["status"] == "blocked"]
    emitted = [packet for packet in packets if packet["status"] == "source_review_packet_emitted"]
    blocker_counts = Counter(blocker["code"] for packet in blocked for blocker in packet["blockers"])
    focus_counts = Counter(
        focus
        for packet in emitted
        for focus in packet.get("source_review_packet", {}).get("review_focus", [])
    )

    return {
        "schema": SCHEMA,
        "generated_at_utc": generated_at_utc or _deterministic_generated_at(scan_tasks, input_path),
        "network_used": False,
        **posture,
        "proof_boundary": PROOF_BOUNDARY,
        "input_report": _rel(input_path, repo) if input_path is not None else _rel(DEFAULT_IN, repo),
        "input_schema": scan_tasks.get("schema"),
        "summary": {
            "input_task_count": len(tasks),
            "packets_emitted": len(emitted),
            "advisory_packets_emitted": len(emitted),
            "blocked_task_count": len(blocked),
            "blocker_counts": dict(sorted(blocker_counts.items())),
            "review_focus_counts": dict(sorted(focus_counts.items())),
            "changed_file_count": sum(p["diff_stats"]["changed_file_count"] for p in emitted),
            "additions": sum(p["diff_stats"]["additions"] for p in emitted),
            "deletions": sum(p["diff_stats"]["deletions"] for p in emitted),
        },
        "source_review_packets": packets,
    }


def render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# Commit Mining Source Review - 2026-05-05",
        "",
        "Generated by `tools/commit-mining-source-review.py` from the mirror-verified scan-task queue.",
        "",
        "## Counts",
        "",
        f"- Input tasks: **{summary['input_task_count']}**",
        f"- Advisory source-review packets emitted: **{summary['advisory_packets_emitted']}**",
        f"- Blocked tasks: **{summary['blocked_task_count']}**",
        f"- Changed files inspected: **{summary['changed_file_count']}**",
        f"- Insertions/deletions summarized: **{summary['additions']} / {summary['deletions']}**",
        f"- Submission posture: **{report['submission_posture']}**",
        "",
        "## Proof Boundary",
        "",
        PROOF_BOUNDARY,
        "",
        "## Blockers",
        "",
    ]
    if summary["blocker_counts"]:
        for code, count in summary["blocker_counts"].items():
            lines.append(f"- `{code}`: {count}")
    else:
        lines.append("- None")

    lines.extend(["", "## Review Focus", ""])
    if summary["review_focus_counts"]:
        for focus, count in summary["review_focus_counts"].items():
            lines.append(f"- `{focus}`: {count}")
    else:
        lines.append("- None")

    lines.extend(
        [
            "",
            "## Packets",
            "",
            "| task | status | commit | files | +/- | focus | blockers |",
            "|---|---|---|---:|---:|---|---|",
        ]
    )
    for packet in report["source_review_packets"]:
        commit = str(packet.get("commit_sha") or "")
        short = commit[:12] if commit else "-"
        if packet["status"] == "source_review_packet_emitted":
            stats = packet["diff_stats"]
            focus = ", ".join(packet["source_review_packet"]["review_focus"])
            blockers = "-"
            files = stats["changed_file_count"]
            churn = f"{stats['additions']} / {stats['deletions']}"
        else:
            focus = "-"
            blockers = ", ".join(blocker["code"] for blocker in packet["blockers"])
            files = 0
            churn = "-"
        lines.append(
            f"| `{packet.get('task_id')}` | `{packet['status']}` | `{short}` | "
            f"{files} | {churn} | {focus} | {blockers} |"
        )
    lines.extend(["", "## Advisory Packet Details", ""])
    for packet in report["source_review_packets"]:
        lines.append(f"### `{packet.get('task_id')}`")
        lines.append("")
        lines.append(f"- Status: `{packet['status']}`")
        if packet["status"] == "source_review_packet_emitted":
            metadata = packet["commit_metadata"]
            packet_body = packet["source_review_packet"]
            diff_stats = packet["diff_stats"]
            lines.append(f"- Commit: `{str(packet.get('commit_sha') or '')[:12]}` - {metadata.get('subject') or ''}")
            lines.append(f"- Advisory summary: {packet_body['summary']}")
            lines.append(f"- Review focus: {', '.join(packet_body['review_focus'])}")
            if packet_body["scope_flags"]:
                lines.append(f"- Scope flags: {', '.join(packet_body['scope_flags'])}")
            if packet_body["primary_directories"]:
                lines.append(f"- Primary directories: {', '.join(packet_body['primary_directories'])}")
            if packet_body["primary_files"]:
                lines.append(f"- Primary files: {', '.join(packet_body['primary_files'])}")
            lines.append(
                f"- Diff summary: {diff_stats['changed_file_count']} files, {diff_stats['additions']} additions, "
                f"{diff_stats['deletions']} deletions, {diff_stats['binary_file_count']} binary"
            )
            lines.append(
                f"- Next step: {packet_body['required_next_step']}"
            )
        else:
            lines.append(f"- Blockers: {', '.join(blocker['code'] for blocker in packet['blockers'])}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=REPO)
    parser.add_argument("--input", type=Path, default=DEFAULT_IN)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--markdown-out", type=Path, default=DEFAULT_MD)
    args = parser.parse_args(argv)

    scan_tasks = load_scan_tasks(args.input)
    report = build_report(scan_tasks, args.repo.resolve(), input_path=args.input.resolve())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    args.markdown_out.parent.mkdir(parents=True, exist_ok=True)
    args.markdown_out.write_text(render_markdown(report), encoding="utf-8")

    summary = report["summary"]
    print(
        f"[commit-mining-source-review] tasks={summary['input_task_count']} "
        f"packets={summary['packets_emitted']} blocked={summary['blocked_task_count']} "
        f"files={summary['changed_file_count']}"
    )
    print(f"[commit-mining-source-review] blockers={summary['blocker_counts']}")
    print(f"[commit-mining-source-review] wrote {_rel(args.out, args.repo)} and {_rel(args.markdown_out, args.repo)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
