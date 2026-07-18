#!/usr/bin/env python3
"""Emit one bounded commit-mining source-review next-step packet.

The runner is offline and source-review-only. It consumes the commit-mining
source disposition report, selects one queued bounded source-review row,
verifies that row's commit in a local mirror, and writes a packet naming the
exact refs/files to inspect. It does not make proof, promotion, or submission
readiness claims.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.commit_mining_next_step_packet.v1"
DEFAULT_INPUT = "reports/commit_mining_source_disposition_2026-05-05.json"
DEFAULT_OUT = "reports/commit_mining_next_step_packet_2026-05-05.json"
DEFAULT_DOC = "docs/COMMIT_MINING_NEXT_STEP_PACKET_2026-05-05.md"
NARROW_ACTION = "narrow_consensus_patch_review"
SUPPORTED_ACTIONS = frozenset(
    {
        "broad_import_triage",
        "narrow_consensus_patch_review",
        "prover_service_review",
    }
)
REQUIRED_DISALLOWED_CLAIMS = (
    "exploitability finding",
    "severity finding",
    "impact finding",
    "detector promotion finding",
    "submission readiness finding",
)
PROOF_BOUNDARY = (
    "This packet only routes bounded source-review follow-up. It does not make "
    "exploitability, severity, impact, detector-promotion, or submission-readiness findings."
)


class PacketError(RuntimeError):
    """Raised for fail-closed packet construction errors."""


def utc_now() -> str:
    return datetime.now(tz=timezone.utc).replace(microsecond=0).isoformat()


def read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise PacketError(f"input report not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise PacketError(f"input report is not valid JSON: {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise PacketError(f"input report must be a JSON object: {path}")
    return payload


def require_str(row: dict[str, Any], key: str) -> str:
    value = row.get(key)
    if not isinstance(value, str) or not value.strip():
        raise PacketError(f"selected row missing string field {key!r}")
    return value.strip()


def require_bool_true(payload: dict[str, Any], key: str) -> None:
    if payload.get(key) is not True:
        raise PacketError(f"input report must set {key}=true")


def string_list(value: Any, *, field: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise PacketError(f"{field} must be a list")
    out: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise PacketError(f"{field} must contain only non-empty strings")
        out.append(item.strip())
    return out


def positive_int(value: Any, *, field: str, default: int | None = None) -> int:
    if value is None:
        if default is None:
            raise PacketError(f"{field} must be a positive integer")
        value = default
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise PacketError(f"{field} must be a positive integer")
    return value


def validate_input_boundary(payload: dict[str, Any]) -> list[str]:
    if payload.get("schema") != "auditooor.commit_mining_source_disposition.v1":
        raise PacketError("input report must use auditooor.commit_mining_source_disposition.v1")
    require_bool_true(payload, "advisory_only")
    claims = string_list(payload.get("disallowed_claims"), field="disallowed_claims")
    missing = [claim for claim in REQUIRED_DISALLOWED_CLAIMS if claim not in claims]
    if missing:
        raise PacketError("input report missing required disallowed claims: " + ", ".join(missing))
    return claims


def selected_bounded_review(row: dict[str, Any]) -> dict[str, Any]:
    review = row.get("bounded_review")
    if not isinstance(review, dict):
        raise PacketError("selected row missing bounded_review object")
    selected_files = string_list(review.get("selected_files"), field="bounded_review.selected_files")
    selected_directories = string_list(
        review.get("selected_directories"), field="bounded_review.selected_directories"
    )
    review_focus = string_list(review.get("review_focus"), field="bounded_review.review_focus")
    if not selected_files:
        raise PacketError("selected row has no bounded selected_files")
    max_files = positive_int(
        review.get("max_files"), field="bounded_review.max_files", default=len(selected_files)
    )
    max_directories = positive_int(
        review.get("max_directories"),
        field="bounded_review.max_directories",
        default=max(len(selected_directories), 1),
    )
    if len(selected_files) > max_files:
        raise PacketError(
            f"selected row exceeds bounded file limit: {len(selected_files)} > {max_files}"
        )
    if len(selected_directories) > max_directories:
        raise PacketError(
            "selected row exceeds bounded directory limit: "
            f"{len(selected_directories)} > {max_directories}"
        )
    if len(review_focus) > 3:
        raise PacketError(f"selected row exceeds bounded focus limit: {len(review_focus)} > 3")
    return {
        "max_directories": max_directories,
        "max_files": max_files,
        "review_focus": review_focus,
        "selected_directories": selected_directories,
        "selected_files": selected_files,
    }


def disposition_rows(payload: dict[str, Any]) -> list[dict[str, Any]]:
    rows = payload.get("disposition_queue")
    if not isinstance(rows, list):
        raise PacketError("input report missing disposition_queue list")
    out: list[dict[str, Any]] = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise PacketError(f"disposition_queue[{index}] must be an object")
        out.append(row)
    return out


def select_row(
    rows: list[dict[str, Any]],
    *,
    source_row_id: str | None,
    queue_index: int | None,
    action_type: str | None = None,
) -> dict[str, Any]:
    if action_type is not None and action_type not in SUPPORTED_ACTIONS:
        supported = ", ".join(sorted(SUPPORTED_ACTIONS))
        raise PacketError(f"unsupported action_type {action_type!r}; supported: {supported}")
    candidates = [row for row in rows if row.get("status") == "queued"]
    if action_type is not None:
        candidates = [row for row in candidates if row.get("action_type") == action_type]
    elif source_row_id is None and queue_index is None:
        candidates = [row for row in candidates if row.get("action_type") == NARROW_ACTION]
    else:
        candidates = [row for row in candidates if row.get("action_type") in SUPPORTED_ACTIONS]
    if source_row_id:
        candidates = [row for row in candidates if row.get("source_row_id") == source_row_id]
    if queue_index is not None:
        candidates = [row for row in candidates if row.get("queue_index") == queue_index]
    if not candidates:
        selector = source_row_id if source_row_id else queue_index
        action_label = action_type or (
            NARROW_ACTION if source_row_id is None and queue_index is None else "supported source-review"
        )
        raise PacketError(f"no queued {action_label} row matched selector {selector!r}")
    candidates.sort(key=lambda row: (row.get("queue_index", 10**9), row.get("source_row_id", "")))
    return candidates[0]


def run_git(git_root: Path, args: list[str]) -> str:
    cmd = ["git", "-C", str(git_root), *args]
    try:
        completed = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except OSError as exc:
        raise PacketError(f"failed to run git: {exc}") from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise PacketError(f"git command failed: {' '.join(cmd)}: {detail}")
    return completed.stdout.strip()


def commit_parents(git_root: Path, commit_sha: str) -> list[str]:
    line = run_git(git_root, ["rev-list", "--parents", "-n", "1", commit_sha])
    parts = line.split()
    if not parts or parts[0] != commit_sha:
        raise PacketError(f"unexpected rev-list output for {commit_sha}: {line}")
    return parts[1:]


def parse_name_status(text: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) < 2:
            raise PacketError(f"unexpected git name-status row: {line}")
        status = parts[0]
        path = parts[-1]
        rows.append({"status": status, "path": path})
    return rows


def object_exists(git_root: Path, object_ref: str) -> bool:
    try:
        run_git(git_root, ["cat-file", "-e", object_ref])
    except PacketError:
        return False
    return True


def inspect_local_mirror(
    git_root: Path, commit_sha: str, selected_files: list[str]
) -> dict[str, Any]:
    if not git_root.exists():
        raise PacketError(f"git root does not exist: {git_root}")
    toplevel = Path(run_git(git_root, ["rev-parse", "--show-toplevel"]))
    verified_commit = run_git(toplevel, ["rev-parse", "--verify", f"{commit_sha}^{{commit}}"])
    parents = commit_parents(toplevel, verified_commit)
    first_parent = parents[0] if parents else None
    diff_kind = "first_parent" if first_parent else "root_or_grafted_snapshot"
    if first_parent:
        name_status_text = run_git(
            toplevel, ["diff", "--name-status", first_parent, verified_commit, "--", *selected_files]
        )
    else:
        name_status_text = run_git(
            toplevel,
            ["show", "--format=", "--name-status", "--no-renames", verified_commit, "--", *selected_files],
        )
    name_status = parse_name_status(name_status_text)
    changed_selected = {row["path"] for row in name_status}
    file_rows = []
    for relpath in selected_files:
        changed_in_selected_diff = relpath in changed_selected
        file_rows.append(
            {
                "path": relpath,
                "exists_at_commit": object_exists(toplevel, f"{verified_commit}:{relpath}"),
                "changed_in_selected_diff": changed_in_selected_diff,
                "changed_in_first_parent_diff": bool(first_parent and changed_in_selected_diff),
            }
        )
    return {
        "git_root": str(toplevel),
        "commit_verified": True,
        "commit_sha": verified_commit,
        "parents": parents,
        "first_parent": first_parent,
        "diff_ref": f"{first_parent}..{verified_commit}" if first_parent else verified_commit,
        "diff_kind": diff_kind,
        "selected_file_name_status": name_status,
        "selected_files": file_rows,
    }


def allowed_source_review_claims(
    row: dict[str, Any], mirror: dict[str, Any], review: dict[str, Any]
) -> list[str]:
    source_row_id = require_str(row, "source_row_id")
    action_type = require_str(row, "action_type")
    commit_sha = str(mirror["commit_sha"])
    selected_files = ", ".join(review["selected_files"])
    changed = [
        item["path"]
        for item in mirror["selected_files"]
        if item.get("changed_in_selected_diff")
    ]
    claims = [
        f"{source_row_id} is a queued {action_type} source-review row in the input disposition report.",
        f"Commit {commit_sha} is present in the named local git mirror.",
        f"The bounded review file list for this packet is limited to: {selected_files}.",
    ]
    if changed and mirror.get("first_parent"):
        claims.append(
            "The first-parent diff for the verified commit changes the selected file(s): "
            + ", ".join(changed)
            + "."
        )
    elif changed:
        claims.append(
            "The root or grafted snapshot for the verified commit includes the selected file(s): "
            + ", ".join(changed)
            + "."
        )
    else:
        claims.append(
            "The selected file list did not appear in the selected name-status diff; inspect only as source-review context."
        )
    claims.append(
        "Any proof, detector-promotion, or submission-readiness claim requires a separate proof packet."
    )
    return claims


def packet_summary(row: dict[str, Any], mirror: dict[str, Any], review: dict[str, Any]) -> dict[str, Any]:
    selected_files = mirror["selected_files"]
    return {
        "selected_source_row_id": row.get("source_row_id"),
        "selected_queue_index": row.get("queue_index"),
        "selected_action_type": row.get("action_type"),
        "review_focus": review["review_focus"],
        "selected_file_count": len(selected_files),
        "existing_selected_file_count": sum(
            1 for item in selected_files if item.get("exists_at_commit") is True
        ),
        "changed_selected_file_count": sum(
            1 for item in selected_files if item.get("changed_in_selected_diff") is True
        ),
        "diff_ref": mirror["diff_ref"],
    }


def build_packet(
    *,
    input_path: Path,
    git_root: Path,
    source_row_id: str | None = None,
    queue_index: int | None = None,
    action_type: str | None = None,
) -> dict[str, Any]:
    payload = read_json(input_path)
    disallowed_claims = validate_input_boundary(payload)
    row = select_row(
        disposition_rows(payload),
        source_row_id=source_row_id,
        queue_index=queue_index,
        action_type=action_type,
    )
    review = selected_bounded_review(row)
    commit_sha = require_str(row, "commit_sha")
    mirror = inspect_local_mirror(git_root, commit_sha, review["selected_files"])
    commands = [
        f"git -C {mirror['git_root']} rev-parse --verify {commit_sha}^{{commit}}",
    ]
    if mirror["first_parent"]:
        commands.append(
            "git -C "
            + mirror["git_root"]
            + " diff --name-status "
            + mirror["first_parent"]
            + " "
            + mirror["commit_sha"]
            + " -- "
            + " ".join(review["selected_files"])
        )
    else:
        commands.append(
            "git -C "
            + mirror["git_root"]
            + " show --format= --name-status --no-renames "
            + mirror["commit_sha"]
            + " -- "
            + " ".join(review["selected_files"])
        )
    return {
        "schema": SCHEMA,
        "generated_at_utc": utc_now(),
        "network_used": False,
        "advisory_only": True,
        "source_review_only": True,
        "input_report": str(input_path),
        "input_schema": payload.get("schema"),
        "summary": packet_summary(row, mirror, review),
        "selected_row": {
            "disposition_id": row.get("disposition_id"),
            "task_id": row.get("task_id"),
            "source_row_id": row.get("source_row_id"),
            "queue_index": row.get("queue_index"),
            "action_type": row.get("action_type"),
            "lane": row.get("lane"),
            "status": row.get("status"),
            "target": row.get("target"),
            "repo_identity": row.get("repo_identity"),
            "commit_sha": commit_sha,
            "commit_short": row.get("commit_short"),
            "priority": row.get("priority"),
            "rationale": row.get("rationale"),
            "next_action": row.get("next_action"),
            "source_review_summary": row.get("source_review_summary"),
        },
        "bounded_review": review,
        "local_mirror": mirror,
        "refs_to_inspect": {
            "commit": mirror["commit_sha"],
            "parents": mirror["parents"],
            "first_parent": mirror["first_parent"],
            "diff_ref": mirror["diff_ref"],
        },
        "files_to_inspect": mirror["selected_files"],
        "commands_run_or_replayable": commands,
        "allowed_source_review_claims": allowed_source_review_claims(row, mirror, review),
        "disallowed_claims": disallowed_claims,
        "proof_boundary": PROOF_BOUNDARY,
    }


def render_markdown(packet: dict[str, Any]) -> str:
    row = packet["selected_row"]
    refs = packet["refs_to_inspect"]
    summary = packet.get("summary") if isinstance(packet.get("summary"), dict) else {}
    files_to_inspect = packet["files_to_inspect"]
    review_focus = summary.get("review_focus") or packet["bounded_review"].get("review_focus") or []
    selected_file_count = summary.get("selected_file_count", len(files_to_inspect))
    existing_file_count = summary.get(
        "existing_selected_file_count",
        sum(1 for item in files_to_inspect if item.get("exists_at_commit") is True),
    )
    changed_file_count = summary.get(
        "changed_selected_file_count",
        sum(1 for item in files_to_inspect if item.get("changed_in_first_parent_diff") is True),
    )
    lines = [
        "# Commit Mining Next-Step Packet",
        "",
        f"- Source row: `{row['source_row_id']}`",
        f"- Task: `{row['task_id']}`",
        f"- Repo identity: `{row['repo_identity']}`",
        f"- Local mirror: `{packet['local_mirror']['git_root']}`",
        f"- Commit: `{refs['commit']}`",
        f"- Diff ref: `{refs['diff_ref']}`",
        f"- Network used: `{str(packet['network_used']).lower()}`",
        f"- Advisory only: `{str(packet['advisory_only']).lower()}`",
        f"- Source review only: `{str(packet['source_review_only']).lower()}`",
        "",
        "## Operational Summary",
        "",
        f"- Selected queue index: `{summary.get('selected_queue_index', row.get('queue_index'))}`",
        f"- Selected action: `{summary.get('selected_action_type', row.get('action_type'))}`",
        f"- Review focus: `{', '.join(review_focus)}`",
        f"- Selected files: `{selected_file_count}`",
        f"- Existing at commit: `{existing_file_count}`",
        f"- Changed in selected diff: `{changed_file_count}`",
        "",
        "## Files To Inspect",
    ]
    for item in files_to_inspect:
        lines.append(
            "- `"
            + item["path"]
            + "`"
            + f" (exists_at_commit={item['exists_at_commit']}, changed_in_selected_diff={item['changed_in_selected_diff']})"
        )
    lines.extend(["", "## Allowed Source-Review Claims"])
    for claim in packet["allowed_source_review_claims"]:
        lines.append(f"- {claim}")
    lines.extend(["", "## Disallowed Claims"])
    for claim in packet["disallowed_claims"]:
        lines.append(f"- {claim}")
    lines.extend(["", "## Replay Commands"])
    for command in packet["commands_run_or_replayable"]:
        lines.append(f"- `{command}`")
    lines.extend(["", "## Boundary", "", packet["proof_boundary"], ""])
    return "\n".join(lines)


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", default=DEFAULT_INPUT, help="source disposition JSON")
    parser.add_argument("--git-root", required=True, help="local git mirror root")
    parser.add_argument("--source-row-id", help="specific source row id to select")
    parser.add_argument("--queue-index", type=int, help="specific queue_index to select")
    parser.add_argument(
        "--action-type",
        choices=sorted(SUPPORTED_ACTIONS),
        help="specific source-review action type to select",
    )
    parser.add_argument("--out", default=DEFAULT_OUT, help="packet JSON output path")
    parser.add_argument("--doc", default=DEFAULT_DOC, help="packet Markdown output path")
    parser.add_argument("--json", action="store_true", help="print packet JSON to stdout")
    args = parser.parse_args(argv)

    try:
        packet = build_packet(
            input_path=Path(args.input),
            git_root=Path(args.git_root),
            source_row_id=args.source_row_id,
            queue_index=args.queue_index,
            action_type=args.action_type,
        )
    except PacketError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    out_path = Path(args.out)
    doc_path = Path(args.doc)
    write_text(out_path, json.dumps(packet, indent=2, sort_keys=True) + "\n")
    write_text(doc_path, render_markdown(packet))
    if args.json:
        print(json.dumps(packet, indent=2, sort_keys=True))
    else:
        print(f"wrote {out_path} and {doc_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
