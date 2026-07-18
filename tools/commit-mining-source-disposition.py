#!/usr/bin/env python3
"""Emit a bounded advisory disposition queue from source-review packets."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path
from typing import Any


REPO = Path(__file__).resolve().parents[1]
DEFAULT_DATE = "2026-05-05"
DEFAULT_IN = REPO / "reports" / f"commit_mining_source_review_{DEFAULT_DATE}.json"
DEFAULT_OUT = REPO / "reports" / f"commit_mining_source_disposition_{DEFAULT_DATE}.json"
DEFAULT_MD = REPO / "docs" / f"COMMIT_MINING_SOURCE_DISPOSITION_{DEFAULT_DATE}.md"
DEFAULT_NEXT_STEP = REPO / "reports" / f"commit_mining_next_step_packet_{DEFAULT_DATE}.json"
SCHEMA = "auditooor.commit_mining_source_disposition.v1"
SOURCE_REVIEW_SCHEMA = "auditooor.commit_mining_source_review.v1"
NEXT_STEP_SCHEMA = "auditooor.commit_mining_next_step_packet.v1"
MAX_QUEUE_ITEMS = 25
MAX_FILES_PER_ITEM = 5
MAX_DIRECTORIES_PER_ITEM = 3
MAX_FOCUS_PER_ITEM = 3
LARGE_CHANGE_FILE_THRESHOLD = 200
ADVISORY_BOUNDARY = (
    "This disposition queue only routes source-review follow-up. It does not make "
    "exploitability, severity, impact, detector-promotion, or submission-readiness findings."
)
DISALLOWED_CLAIMS = (
    "exploitability finding",
    "severity finding",
    "impact finding",
    "detector promotion finding",
    "submission readiness finding",
)
ACTION_ORDER = (
    "broad_import_triage",
    "narrow_consensus_patch_review",
    "prover_service_review",
    "blocked_no_op",
)
ACTION_LABELS = {
    "broad_import_triage": "Broad import triage",
    "narrow_consensus_patch_review": "Narrow consensus patch review",
    "prover_service_review": "Prover-service review",
    "blocked_no_op": "Blocked/no-op",
}
ACTION_LANES = {
    "broad_import_triage": "source_review_broad_import",
    "narrow_consensus_patch_review": "source_review_consensus_patch",
    "prover_service_review": "source_review_prover_service",
    "blocked_no_op": "source_review_absent_or_blocked",
}
ACTION_PRIORITIES = {
    "broad_import_triage": "medium",
    "narrow_consensus_patch_review": "medium",
    "prover_service_review": "medium",
    "blocked_no_op": "low",
}
PROVER_TOKENS = (
    "prover",
    "proof/zk",
    "proof/tee",
    "zk/service",
    "op_succinct",
    "postgres_integration",
    "proof_or_hashing",
)
CONSENSUS_TOKENS = (
    "consensus",
    "gossip",
    "rpc-types-engine",
    "is_deposits_only",
    "consensus_or_fork_logic",
    "state_transition",
)


def _read_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"expected JSON object: {path}")
    return payload


def _rel(path: Path, repo: Path) -> str:
    try:
        return path.resolve().relative_to(repo.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _stable_slug(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip()).strip("-")
    return slug or "source-review"


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _strings(value: Any, *, limit: int | None = None) -> list[str]:
    strings = [str(item) for item in _as_list(value) if str(item or "").strip()]
    return strings[:limit] if limit is not None else strings


def _primary_directories(packet_body: dict[str, Any]) -> list[str]:
    directories = _strings(packet_body.get("primary_directories"), limit=MAX_DIRECTORIES_PER_ITEM)
    if directories:
        return directories
    files = _strings(packet_body.get("primary_files"), limit=MAX_FILES_PER_ITEM)
    derived: list[str] = []
    for path in files:
        parts = Path(path).parts
        directory = "/".join(parts[:2]) if len(parts) >= 2 else path
        if directory not in derived:
            derived.append(directory)
    return derived[:MAX_DIRECTORIES_PER_ITEM]


def _packet_text(packet: dict[str, Any]) -> str:
    body = packet.get("source_review_packet") if isinstance(packet.get("source_review_packet"), dict) else {}
    parts: list[str] = [
        str(packet.get("task_id") or ""),
        str(packet.get("source_row_id") or ""),
        str(packet.get("commit_sha") or ""),
        str(body.get("summary") or ""),
    ]
    metadata = packet.get("commit_metadata")
    if isinstance(metadata, dict):
        parts.append(str(metadata.get("subject") or ""))
    for key in ("review_focus", "scope_flags", "primary_files", "primary_directories"):
        parts.extend(_strings(body.get(key)))
    return " ".join(parts).lower()


def _changed_file_count(packet: dict[str, Any]) -> int:
    stats = packet.get("diff_stats")
    if not isinstance(stats, dict):
        return 0
    try:
        return int(stats.get("changed_file_count") or 0)
    except (TypeError, ValueError):
        return 0


def _is_broad(packet: dict[str, Any]) -> bool:
    body = packet.get("source_review_packet") if isinstance(packet.get("source_review_packet"), dict) else {}
    flags = set(_strings(body.get("scope_flags")))
    return bool(
        flags.intersection({"root_or_grafted_snapshot", "broad_multi_module_change"})
        or _changed_file_count(packet) >= LARGE_CHANGE_FILE_THRESHOLD
    )


def _contains_any(text: str, tokens: tuple[str, ...]) -> bool:
    return any(token in text for token in tokens)


def _classify_action(packet: dict[str, Any]) -> str:
    if packet.get("status") != "source_review_packet_emitted":
        return "blocked_no_op"
    text = _packet_text(packet)
    if _is_broad(packet):
        return "broad_import_triage"
    if _contains_any(text, PROVER_TOKENS):
        return "prover_service_review"
    if _contains_any(text, CONSENSUS_TOKENS):
        return "narrow_consensus_patch_review"
    return "blocked_no_op"


def _action_rationale(action_type: str, packet: dict[str, Any]) -> str:
    body = packet.get("source_review_packet") if isinstance(packet.get("source_review_packet"), dict) else {}
    flags = _strings(body.get("scope_flags"))
    focus = _strings(body.get("review_focus"))
    files = _changed_file_count(packet)
    if action_type == "broad_import_triage":
        return (
            f"Source review spans {files} changed files with scope flags "
            f"{', '.join(flags) or 'none'}; keep follow-up at import triage and split only bounded hotspots."
        )
    if action_type == "narrow_consensus_patch_review":
        return (
            "Source review is a narrow consensus-facing patch; inspect the selected files for local logic and "
            "record a source-review-only disposition."
        )
    if action_type == "prover_service_review":
        return (
            "Source review touches prover or proof-service code; inspect service boundaries, backends, storage, "
            "and tests from the bounded file list."
        )
    if packet.get("status") == "source_review_packet_emitted":
        return (
            "Source review is present but did not match the bounded follow-up lanes "
            f"(focus: {', '.join(focus) or 'none'})."
        )
    blockers = packet.get("blockers")
    if isinstance(blockers, list) and blockers:
        codes = [str(row.get("code") or row) if isinstance(row, dict) else str(row) for row in blockers]
        return f"Source review packet is blocked: {', '.join(codes)}."
    return "Source review packet is absent or not emitted."


def _next_action(action_type: str) -> str:
    if action_type == "broad_import_triage":
        return "Triage only the bounded directories and hotspot files, then split any useful lead into a narrower source-review note."
    if action_type == "narrow_consensus_patch_review":
        return "Review the bounded consensus patch files and record whether a follow-up proof task is warranted."
    if action_type == "prover_service_review":
        return "Review the bounded prover-service files and record service-boundary questions or follow-up proof tasks."
    return "No source-review action; keep the row blocked or closed until a source-review packet exists."


def _queue_item(packet: dict[str, Any], ordinal: int) -> dict[str, Any]:
    body = packet.get("source_review_packet") if isinstance(packet.get("source_review_packet"), dict) else {}
    action_type = _classify_action(packet)
    task_id = str(packet.get("task_id") or f"packet-{ordinal:03d}")
    commit = str(packet.get("commit_sha") or "")
    selected_files = _strings(body.get("primary_files"), limit=MAX_FILES_PER_ITEM)
    selected_dirs = _primary_directories(body)
    focus = _strings(body.get("review_focus"), limit=MAX_FOCUS_PER_ITEM)
    item = {
        "disposition_id": f"source-disposition-{_stable_slug(task_id)}",
        "queue_index": ordinal,
        "status": "queued" if action_type != "blocked_no_op" else "blocked_no_op",
        "action_type": action_type,
        "action_label": ACTION_LABELS[action_type],
        "lane": ACTION_LANES[action_type],
        "priority": ACTION_PRIORITIES[action_type],
        "task_id": packet.get("task_id"),
        "source_row_id": packet.get("source_row_id"),
        "target": packet.get("target"),
        "repo_identity": packet.get("repo_identity"),
        "commit_sha": commit,
        "commit_short": commit[:12] if commit else "",
        "packet_status": packet.get("status"),
        "rationale": _action_rationale(action_type, packet),
        "next_action": _next_action(action_type),
        "bounded_review": {
            "max_files": MAX_FILES_PER_ITEM,
            "max_directories": MAX_DIRECTORIES_PER_ITEM,
            "selected_files": selected_files,
            "selected_directories": selected_dirs,
            "review_focus": focus,
        },
        "source_review_summary": body.get("summary") if isinstance(body.get("summary"), str) else "",
        "proof_boundary": ADVISORY_BOUNDARY,
    }
    blockers = packet.get("blockers")
    if isinstance(blockers, list) and blockers:
        item["blockers"] = blockers
    return item


def _next_step_evidence_from_payload(
    payload: dict[str, Any],
    evidence_path: str,
    *,
    source_ref: str | None = None,
) -> dict[str, Any] | None:
    if payload.get("schema") != NEXT_STEP_SCHEMA:
        return None
    if payload.get("advisory_only") is not True or payload.get("source_review_only") is not True:
        return None
    selected = payload.get("selected_row")
    if not isinstance(selected, dict):
        return None
    source_row_id = str(selected.get("source_row_id") or "").strip()
    task_id = str(selected.get("task_id") or "").strip()
    disposition_id = str(selected.get("disposition_id") or "").strip()
    commit_sha = str(selected.get("commit_sha") or "").strip()
    if not source_row_id and not task_id and not disposition_id:
        return None
    evidence = {
        "evidence_path": evidence_path,
        "source_row_id": source_row_id,
        "task_id": task_id,
        "disposition_id": disposition_id,
        "commit_sha": commit_sha,
        "action_type": selected.get("action_type"),
        "generated_at_utc": payload.get("generated_at_utc"),
    }
    if source_ref:
        evidence["source_ref"] = source_ref
    return evidence


def _next_step_evidence_key(evidence: dict[str, Any]) -> tuple[str, str, str, str]:
    return (
        str(evidence.get("source_row_id") or ""),
        str(evidence.get("task_id") or ""),
        str(evidence.get("disposition_id") or ""),
        str(evidence.get("commit_sha") or ""),
    )


def _next_step_sort_key(evidence: dict[str, Any]) -> tuple[str, str, str, str]:
    return (
        str(evidence.get("source_row_id") or ""),
        str(evidence.get("task_id") or ""),
        str(evidence.get("generated_at_utc") or ""),
        str(evidence.get("source_ref") or evidence.get("evidence_path") or ""),
    )


def load_next_step_evidence(paths: list[Path], repo: Path) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    for path in paths:
        try:
            payload = _read_json(path)
        except (OSError, json.JSONDecodeError, ValueError):
            continue
        item = _next_step_evidence_from_payload(payload, _rel(path, repo))
        if item is not None:
            evidence.append(item)
    return sorted(evidence, key=_next_step_sort_key)


def _git_output(repo: Path, args: list[str]) -> str | None:
    try:
        completed = subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout


def discover_next_step_history(repo: Path, relpath: str = _rel(DEFAULT_NEXT_STEP, REPO)) -> list[dict[str, Any]]:
    revisions = _git_output(repo, ["log", "--format=%H", "--", relpath])
    if not revisions:
        return []
    evidence: list[dict[str, Any]] = []
    for revision in revisions.splitlines():
        commit = revision.strip()
        if not commit:
            continue
        text = _git_output(repo, ["show", f"{commit}:{relpath}"])
        if not text:
            continue
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict):
            continue
        item = _next_step_evidence_from_payload(
            payload,
            relpath,
            source_ref=f"{commit}:{relpath}",
        )
        if item is not None:
            evidence.append(item)
    return sorted(evidence, key=_next_step_sort_key)


def _next_step_matches_packet(evidence: dict[str, Any], item: dict[str, Any]) -> bool:
    for evidence_key, item_key in (
        ("source_row_id", "source_row_id"),
        ("task_id", "task_id"),
        ("disposition_id", "disposition_id"),
    ):
        evidence_value = str(evidence.get(evidence_key) or "")
        item_value = str(item.get(item_key) or "")
        if evidence_value and item_value and evidence_value != item_value:
            return False
    if not any(
        str(evidence.get(key) or "") and str(item.get(key) or "")
        for key in ("source_row_id", "task_id", "disposition_id")
    ):
        return False
    evidence_commit = str(evidence.get("commit_sha") or "")
    item_commit = str(item.get("commit_sha") or "")
    if evidence_commit and item_commit and evidence_commit != item_commit:
        return False
    return True


def _completed_next_step_evidence(
    item: dict[str, Any],
    next_step_evidence: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    return [evidence for evidence in next_step_evidence if _next_step_matches_packet(evidence, item)]


def _apply_completed_next_step_evidence(
    item: dict[str, Any],
    next_step_evidence: list[dict[str, Any]],
) -> dict[str, Any]:
    if item.get("status") != "queued":
        return item
    matching = _completed_next_step_evidence(item, next_step_evidence)
    if not matching:
        return item
    item = dict(item)
    item["status"] = "completed_next_step_emitted"
    item["priority"] = "low"
    item["next_action"] = "Next-step packet already emitted; do not re-queue unless this source-review slice is reopened."
    item["completed_next_step_evidence"] = sorted(matching, key=_next_step_sort_key)
    return item


def _absent_item(reason: str) -> dict[str, Any]:
    return {
        "disposition_id": "source-disposition-source-review-absent",
        "queue_index": 1,
        "status": "blocked_no_op",
        "action_type": "blocked_no_op",
        "action_label": ACTION_LABELS["blocked_no_op"],
        "lane": ACTION_LANES["blocked_no_op"],
        "priority": ACTION_PRIORITIES["blocked_no_op"],
        "task_id": None,
        "source_row_id": None,
        "target": None,
        "repo_identity": None,
        "commit_sha": "",
        "commit_short": "",
        "packet_status": "absent",
        "rationale": reason,
        "next_action": _next_action("blocked_no_op"),
        "bounded_review": {
            "max_files": MAX_FILES_PER_ITEM,
            "max_directories": MAX_DIRECTORIES_PER_ITEM,
            "selected_files": [],
            "selected_directories": [],
            "review_focus": [],
        },
        "source_review_summary": "",
        "proof_boundary": ADVISORY_BOUNDARY,
    }


def _action_counts(items: list[dict[str, Any]]) -> dict[str, int]:
    counts = {action: 0 for action in ACTION_ORDER}
    for item in items:
        action = str(item.get("action_type") or "blocked_no_op")
        counts[action] = counts.get(action, 0) + 1
    return counts


def _status_rank(item: dict[str, Any]) -> int:
    status = str(item.get("status") or "")
    if status == "queued":
        return 0
    if status == "completed_next_step_emitted":
        return 1
    return 2


def _sort_key(item: dict[str, Any]) -> tuple[int, int, str, str]:
    return (
        _status_rank(item),
        ACTION_ORDER.index(str(item.get("action_type"))) if item.get("action_type") in ACTION_ORDER else 99,
        str(item.get("task_id") or ""),
        str(item.get("commit_sha") or ""),
    )


def build_report(
    source_review: dict[str, Any],
    repo: Path,
    *,
    input_path: Path | None = None,
    max_queue_items: int = MAX_QUEUE_ITEMS,
    next_step_evidence: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    packets_raw = source_review.get("source_review_packets")
    packets = [packet for packet in _as_list(packets_raw) if isinstance(packet, dict)]
    if packets:
        items = [_queue_item(packet, idx + 1) for idx, packet in enumerate(packets)]
        next_step_evidence = next_step_evidence or []
        items = [_apply_completed_next_step_evidence(item, next_step_evidence) for item in items]
        items = sorted(items, key=_sort_key)[:max_queue_items]
        for idx, item in enumerate(items, start=1):
            item["queue_index"] = idx
    else:
        reason = "Source review is absent; no disposition work is queued."
        if packets_raw == []:
            reason = "Source review packet list is empty; no disposition work is queued."
        items = [_absent_item(reason)]

    action_counts = _action_counts(items)
    emitted = [packet for packet in packets if packet.get("status") == "source_review_packet_emitted"]
    completed_next_step_count = sum(1 for item in items if item.get("status") == "completed_next_step_emitted")
    return {
        "schema": SCHEMA,
        "date": DEFAULT_DATE,
        "generated_at_utc": str(source_review.get("generated_at_utc") or f"{DEFAULT_DATE}T00:00:00+00:00"),
        "advisory_only": True,
        "network_used": False,
        "input_report": _rel(input_path, repo) if input_path is not None else _rel(DEFAULT_IN, repo),
        "input_schema": source_review.get("schema"),
        "proof_boundary": ADVISORY_BOUNDARY,
        "disallowed_claims": list(DISALLOWED_CLAIMS),
        "bounded_limits": {
            "max_queue_items": max_queue_items,
            "max_files_per_item": MAX_FILES_PER_ITEM,
            "max_directories_per_item": MAX_DIRECTORIES_PER_ITEM,
            "max_focus_per_item": MAX_FOCUS_PER_ITEM,
        },
        "summary": {
            "source_packets_seen": len(packets),
            "source_packets_emitted": len(emitted),
            "queue_items_emitted": len(items),
            "queued_actionable_count": sum(1 for item in items if item.get("status") == "queued"),
            "completed_next_step_count": completed_next_step_count,
            "blocked_no_op_count": action_counts.get("blocked_no_op", 0),
            "action_counts": action_counts,
        },
        "disposition_queue": items,
    }


def render_markdown(report: dict[str, Any]) -> str:
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    action_counts = summary.get("action_counts") if isinstance(summary.get("action_counts"), dict) else {}
    lines = [
        f"# Commit Mining Source Disposition - {report.get('date') or DEFAULT_DATE}",
        "",
        "Generated by `tools/commit-mining-source-disposition.py` from advisory source-review packets.",
        "",
        "## Counts",
        "",
        f"- Source packets seen: {summary.get('source_packets_seen', 0)}",
        f"- Source packets emitted: {summary.get('source_packets_emitted', 0)}",
        f"- Queue items emitted: {summary.get('queue_items_emitted', 0)}",
        f"- Queued actionable items: {summary.get('queued_actionable_count', 0)}",
        f"- Completed next-step items: {summary.get('completed_next_step_count', 0)}",
        f"- Blocked/no-op items: {summary.get('blocked_no_op_count', 0)}",
    ]
    for action in ACTION_ORDER:
        lines.append(f"- {action}: {action_counts.get(action, 0)}")
    lines.extend(
        [
            "",
            "## Advisory Boundary",
            "",
            str(report.get("proof_boundary") or ADVISORY_BOUNDARY),
            "",
            "## Queue",
            "",
            "| index | task | status | action | priority | commit | bounded files | next action |",
            "|---:|---|---|---|---|---|---:|---|",
        ]
    )
    for item in _as_list(report.get("disposition_queue")):
        if not isinstance(item, dict):
            continue
        bounded = item.get("bounded_review") if isinstance(item.get("bounded_review"), dict) else {}
        files = len(_as_list(bounded.get("selected_files")))
        lines.append(
            f"| {item.get('queue_index')} | `{item.get('task_id') or '-'}` | `{item.get('status')}` | `{item.get('action_type')}` | "
            f"`{item.get('priority')}` | `{item.get('commit_short') or '-'}` | {files} | {item.get('next_action') or ''} |"
        )
    lines.extend(["", "## Details", ""])
    for item in _as_list(report.get("disposition_queue")):
        if not isinstance(item, dict):
            continue
        lines.append(f"### `{item.get('disposition_id')}`")
        lines.append("")
        lines.append(f"- Status: `{item.get('status')}`")
        lines.append(f"- Action: `{item.get('action_type')}`")
        lines.append(f"- Lane: `{item.get('lane')}`")
        lines.append(f"- Rationale: {item.get('rationale')}")
        bounded = item.get("bounded_review") if isinstance(item.get("bounded_review"), dict) else {}
        files = _strings(bounded.get("selected_files"))
        directories = _strings(bounded.get("selected_directories"))
        focus = _strings(bounded.get("review_focus"))
        if directories:
            lines.append(f"- Bounded directories: {', '.join(directories)}")
        if files:
            lines.append(f"- Bounded files: {', '.join(files)}")
        if focus:
            lines.append(f"- Review focus: {', '.join(focus)}")
        completed = [row for row in _as_list(item.get("completed_next_step_evidence")) if isinstance(row, dict)]
        if completed:
            evidence_refs = ", ".join(
                str(row.get("source_ref") or row.get("evidence_path") or "-") for row in completed
            )
            lines.append(f"- Completed next-step evidence: {evidence_refs}")
        lines.append(f"- Next action: {item.get('next_action')}")
        lines.append("")
    lines.extend(["## Inputs", "", f"- source_review: `{report.get('input_report')}`"])
    return "\n".join(lines).rstrip() + "\n"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=REPO)
    parser.add_argument("--input", type=Path, default=DEFAULT_IN)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--markdown-out", type=Path, default=DEFAULT_MD)
    parser.add_argument("--max-queue-items", type=int, default=MAX_QUEUE_ITEMS)
    parser.add_argument(
        "--completed-next-step",
        type=Path,
        action="append",
        default=[],
        help="Additional commit-mining next-step packet JSON to treat as completed source-review evidence.",
    )
    parser.add_argument(
        "--no-auto-completed-next-step",
        action="store_true",
        help="Do not auto-load current and committed next-step packet evidence from the repo.",
    )
    parser.add_argument("--json", action="store_true", help="Print JSON to stdout.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.max_queue_items < 1:
        raise SystemExit("--max-queue-items must be at least 1")
    source_review = _read_json(args.input)
    if source_review.get("schema") not in (SOURCE_REVIEW_SCHEMA, None):
        raise ValueError(f"unexpected input schema: {source_review.get('schema')}")
    next_step_evidence: list[dict[str, Any]] = []
    if not args.no_auto_completed_next_step:
        default_next_step = args.repo / "reports" / f"commit_mining_next_step_packet_{DEFAULT_DATE}.json"
        next_step_evidence.extend(
            load_next_step_evidence([default_next_step], args.repo)
        )
        next_step_evidence.extend(discover_next_step_history(args.repo))
    next_step_evidence.extend(load_next_step_evidence(list(args.completed_next_step), args.repo))
    deduped_next_step_evidence = {
        _next_step_evidence_key(item): item for item in next_step_evidence
    }
    report = build_report(
        source_review,
        args.repo,
        input_path=args.input,
        max_queue_items=args.max_queue_items,
        next_step_evidence=sorted(deduped_next_step_evidence.values(), key=_next_step_sort_key),
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.markdown_out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    args.markdown_out.write_text(render_markdown(report), encoding="utf-8")
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        counts = report["summary"]["action_counts"]
        print(
            f"wrote {args.out} and {args.markdown_out} "
            f"(broad={counts.get('broad_import_triage', 0)}, "
            f"consensus={counts.get('narrow_consensus_patch_review', 0)}, "
            f"prover={counts.get('prover_service_review', 0)}, "
            f"blocked_no_op={counts.get('blocked_no_op', 0)})"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
