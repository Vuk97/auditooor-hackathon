#!/usr/bin/env python3
"""Build a bounded worker packet for one real-world recall attack class.

The gap prioritizer ranks weak classes and the work queue creates closeable
tasks. This tool sits between them and worker dispatch: it renders one compact
drilldown packet with source freshness, miss examples, detector hints, quality
blockers, commands, and control obligations. It is advisory capability work and
must never imply exploitability or submission readiness.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PRIORITIES = REPO_ROOT / "reports" / "realworld_recall_gap_priorities.json"
DEFAULT_QUEUE = REPO_ROOT / "reports" / "realworld_recall_work_queue.jsonl"
DEFAULT_OUT_JSON = REPO_ROOT / "reports" / "realworld_recall_drilldown.json"
DEFAULT_OUT_MD = REPO_ROOT / "reports" / "realworld_recall_drilldown.md"

PRIORITIES_SCHEMA = "auditooor.realworld_recall_gap_priorities.v1"
QUEUE_ROW_SCHEMAS = {
    "auditooor.realworld_recall_work_queue.row.v1",
    "auditooor.realworld_recall_work_queue.row.v2",
}
DRILLDOWN_SCHEMA = "auditooor.realworld_recall_drilldown.v1"


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _relpath(path: Path) -> str:
    try:
        return path.resolve().relative_to(REPO_ROOT.resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def _string(value: Any) -> str:
    return str(value or "").strip()


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _bounded_dicts(value: Any, limit: int) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    out: list[dict[str, Any]] = []
    for item in value:
        if isinstance(item, dict):
            out.append(item)
        if len(out) >= limit:
            break
    return out


def resolve_queue_path(path: Path) -> Path:
    """Use the requested queue, or latest generated queue when default is absent."""
    expanded = path.expanduser().resolve()
    if expanded.is_file() or expanded != DEFAULT_QUEUE.resolve():
        return expanded
    candidates = sorted(
        (REPO_ROOT / "reports").glob("realworld_recall_work_queue*.jsonl"),
        key=lambda item: (item.stat().st_mtime, item.name),
        reverse=True,
    )
    return candidates[0].resolve() if candidates else expanded


def load_priorities(path: Path) -> tuple[dict[str, Any], str]:
    if not path.is_file():
        raise FileNotFoundError(f"priorities file not found: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path}: top-level JSON must be an object")
    if payload.get("schema") != PRIORITIES_SCHEMA:
        raise ValueError(f"{path}: schema must be {PRIORITIES_SCHEMA}")
    if not isinstance(payload.get("priorities"), list):
        raise ValueError(f"{path}: priorities must be a list")
    return payload, _sha256(path)


def load_queue_rows(path: Path) -> tuple[list[dict[str, Any]], list[str]]:
    if not path.is_file():
        return [], [f"queue file not found: {path}"]
    rows: list[dict[str, Any]] = []
    warnings: list[str] = []
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            warnings.append(f"{path}:{lineno}: invalid JSON: {exc}")
            continue
        if not isinstance(row, dict):
            warnings.append(f"{path}:{lineno}: row must be an object")
            continue
        if row.get("schema") not in QUEUE_ROW_SCHEMAS:
            warnings.append(f"{path}:{lineno}: schema mismatch")
            continue
        rows.append(row)
    return rows, warnings


def choose_priority(payload: dict[str, Any], attack_class: str | None) -> tuple[dict[str, Any], str]:
    priorities = [row for row in payload.get("priorities", []) if isinstance(row, dict)]
    if attack_class:
        wanted = attack_class.strip().lower()
        for row in priorities:
            if _string(row.get("attack_class")).lower() == wanted:
                return row, "explicit_attack_class"
        raise ValueError(f"attack class not found in priorities: {attack_class}")
    if not priorities:
        raise ValueError("priorities file has no priority rows")
    return priorities[0], "top_priority"


def _compact_miss(item: dict[str, Any]) -> dict[str, Any]:
    detectors = [_string(det) for det in (item.get("independent_firing_detectors") or []) if _string(det)]
    return {
        "slug": _string(item.get("slug")),
        "source": _string(item.get("source")),
        "sample_origin": _string(item.get("sample_origin")),
        "own_detector_fired": bool(item.get("own_detector_fired")),
        "independent_any_fired": bool(item.get("independent_any_fired")),
        "independent_firing_detectors": detectors[:8],
    }


def _compact_queue_row(row: dict[str, Any]) -> dict[str, Any]:
    quality = row.get("external_recall_quality") if isinstance(row.get("external_recall_quality"), dict) else {}
    return {
        "queue_id": _string(row.get("queue_id")),
        "status": _string(row.get("status")) or "open",
        "task_type": _string((row.get("work_item") or {}).get("task_type")),
        "summary": _string((row.get("work_item") or {}).get("summary")),
        "quality_blocked": bool(quality.get("quality_blocked")),
        "quality_blocked_reason": _string(quality.get("quality_blocked_reason")),
        "provider_dispatch_ready": bool(row.get("provider_dispatch_ready")),
        "workability_status": _string(row.get("workability_status")) or "unknown",
        "workability_blockers": [
            _string(item) for item in (row.get("workability_blockers") or []) if _string(item)
        ][:8],
        "provider_dispatch_reason": _string(row.get("provider_dispatch_reason")),
        "suggested_commands": [_string(cmd) for cmd in (row.get("suggested_commands") or []) if _string(cmd)][:6],
        "closeout_requirements": [
            _string(item) for item in (row.get("closeout_requirements") or []) if _string(item)
        ][:8],
    }


def _queue_workability(rows: list[dict[str, Any]]) -> dict[str, Any]:
    known_rows = [row for row in rows if "provider_dispatch_ready" in row]
    by_status = Counter(_string(row.get("workability_status")) or "unknown" for row in known_rows)
    blockers = Counter(
        _string(blocker)
        for row in known_rows
        for blocker in (row.get("workability_blockers") or [])
        if _string(blocker)
    )
    ready = sum(1 for row in known_rows if bool(row.get("provider_dispatch_ready")))
    return {
        "rows": len(rows),
        "provider_dispatch_ready_rows": ready,
        "provider_dispatch_blocked_rows": len(known_rows) - ready,
        "provider_dispatch_unknown_rows": len(rows) - len(known_rows),
        "by_workability_status": dict(sorted(by_status.items())),
        "workability_blocker_counts": dict(sorted(blockers.items())),
    }


def _detector_hints(priority: dict[str, Any], miss_examples: list[dict[str, Any]]) -> list[dict[str, Any]]:
    hints: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in _bounded_dicts(priority.get("top_cross_class_detectors_on_misses"), 8):
        detector = _string(item.get("detector"))
        if detector and detector not in seen:
            seen.add(detector)
            hints.append({"detector": detector, "source": "top_cross_class_on_misses", "count": _int(item.get("count"))})
    counts: Counter[str] = Counter()
    for miss in miss_examples:
        for detector in miss.get("independent_firing_detectors", []):
            counts[detector] += 1
    for detector, count in counts.most_common(8):
        if detector and detector not in seen:
            seen.add(detector)
            hints.append({"detector": detector, "source": "miss_example_firing_detector", "count": count})
        if len(hints) >= 10:
            break
    return hints[:10]


def _freshness(
    *,
    priorities_path: Path,
    priorities_sha: str,
    queue_path: Path,
    queue_rows: list[dict[str, Any]],
    queue_warnings: list[str],
) -> dict[str, Any]:
    row_shas = sorted({_string(row.get("source_report_sha256")) for row in queue_rows if row.get("source_report_sha256")})
    matching_rows = sum(1 for row in queue_rows if _string(row.get("source_report_sha256")) == priorities_sha)
    stale_rows = sum(1 for row in queue_rows if _string(row.get("source_report_sha256")) and _string(row.get("source_report_sha256")) != priorities_sha)
    current = bool(queue_rows) and stale_rows == 0 and matching_rows == len(queue_rows)
    warnings = list(queue_warnings)
    if not queue_rows:
        warnings.append("no queue rows loaded; run make realworld-recall-work-queue")
    elif stale_rows:
        warnings.append("queue rows were generated from a different priorities sha; refresh the queue before closing detector work")
    return {
        "priorities_path": _relpath(priorities_path),
        "priorities_sha256": priorities_sha,
        "queue_path": _relpath(queue_path),
        "queue_rows_loaded": len(queue_rows),
        "queue_source_report_sha256_values": row_shas[:8],
        "matching_queue_rows": matching_rows,
        "stale_queue_rows": stale_rows,
        "current_for_priorities": current,
        "refresh_command": "make realworld-recall-work-queue OUT=reports/realworld_recall_work_queue.jsonl JSON=1",
        "warnings": warnings,
    }


def build_packet(
    *,
    priorities_path: Path,
    queue_path: Path,
    attack_class: str | None = None,
    miss_limit: int = 6,
    queue_limit: int = 8,
) -> dict[str, Any]:
    priorities, priorities_sha = load_priorities(priorities_path)
    priority, selection_reason = choose_priority(priorities, attack_class)
    selected = _string(priority.get("attack_class")) or "uncategorized"
    queue_rows, queue_warnings = load_queue_rows(queue_path)
    selected_queue_rows = [
        row
        for row in queue_rows
        if _string((row.get("source_priority") or {}).get("attack_class")) == selected
    ]
    miss_examples = [_compact_miss(item) for item in _bounded_dicts(priority.get("miss_examples"), miss_limit)]
    queue_packets = [_compact_queue_row(row) for row in selected_queue_rows[:queue_limit]]
    quality_rows = [
        row.get("external_recall_quality")
        for row in selected_queue_rows
        if isinstance(row.get("external_recall_quality"), dict) and row.get("external_recall_quality")
    ]
    quality = quality_rows[0] if quality_rows else {}
    external_evidence = priority.get("external_evidence") if isinstance(priority.get("external_evidence"), dict) else {}
    commands = [
        "python3 tools/audit/realworld-recall-gap-prioritizer.py --quiet",
        "make realworld-recall-work-queue OUT=reports/realworld_recall_work_queue.jsonl JSON=1",
    ]
    for row in queue_packets:
        for command in row.get("suggested_commands", []):
            if command not in commands and len(commands) < 10:
                commands.append(command)
    return {
        "schema": DRILLDOWN_SCHEMA,
        "generated_at_utc": _utc_now(),
        "submission_posture": "NOT_SUBMIT_READY",
        "selection": {
            "attack_class": selected,
            "selection_reason": selection_reason,
            "priority_rank": _int(priority.get("rank")),
            "priority_band": _string(priority.get("priority_band")),
            "priority_score": _float(priority.get("priority_score")),
        },
        "freshness": _freshness(
            priorities_path=priorities_path,
            priorities_sha=priorities_sha,
            queue_path=queue_path,
            queue_rows=queue_rows,
            queue_warnings=queue_warnings,
        ),
        "recall_metrics": {
            "same_class_recall": _float(priority.get("same_class_recall")),
            "same_class_misses": _int(priority.get("same_class_misses")),
            "samples_total": _int(priority.get("samples_total")),
            "realworld_recall_any": _float(priority.get("realworld_recall_any")),
            "gap_vs_any_pp": _float(priority.get("gap_vs_any_pp")),
            "gap_vs_self_test_pp": _float(priority.get("gap_vs_self_test_pp")),
        },
        "external_evidence": {
            "measured_external_samples": _int(external_evidence.get("measured_external_samples")),
            "external_same_class_recall": _float(external_evidence.get("external_same_class_recall")),
            "repo_examples": _bounded_dicts(external_evidence.get("repo_examples"), 6),
        },
        "quality_state": {
            "quality_blocked": bool(quality.get("quality_blocked")),
            "quality_blocked_reason": _string(quality.get("quality_blocked_reason")),
            "quality_report_paths": [
                _string(path) for path in (quality.get("quality_report_paths") or []) if _string(path)
            ][:6],
            "required_actions": [
                _string(action) for action in (quality.get("required_actions") or []) if _string(action)
            ][:6],
        },
        "queue_workability": _queue_workability(selected_queue_rows),
        "miss_examples": miss_examples,
        "detector_hints": _detector_hints(priority, miss_examples),
        "queue_work_items": queue_packets,
        "commands": commands,
        "control_obligations": [
            "Before/after recall scoreboard or scoped external replay must be linked.",
            "At least one negative/control sample is required for detector broadening, or a NO_CONTROL reason.",
            "Quality-blocked external rows require source-state replacement before detector work.",
            "This packet is advisory capability work; do not claim exploitability or submission readiness.",
        ],
    }


def render_markdown(packet: dict[str, Any]) -> str:
    selection = packet["selection"]
    freshness = packet["freshness"]
    lines = [
        f"# Real-World Recall Drilldown: {selection['attack_class']}",
        "",
        f"- Schema: `{packet['schema']}`",
        f"- Submission posture: `{packet['submission_posture']}`",
        f"- Selection: `{selection['selection_reason']}` rank `{selection['priority_rank']}` score `{selection['priority_score']}`",
        f"- Current for priorities: `{freshness['current_for_priorities']}`",
    ]
    for warning in freshness.get("warnings") or []:
        lines.append(f"- Warning: {warning}")
    lines.extend(
        [
            "",
            "## Metrics",
            "",
        ]
    )
    for key, value in packet["recall_metrics"].items():
        lines.append(f"- `{key}`: `{value}`")
    lines.extend(["", "## Detector Hints", ""])
    for hint in packet["detector_hints"]:
        lines.append(f"- `{hint['detector']}` ({hint['source']}, count `{hint['count']}`)")
    lines.extend(["", "## Queue Work Items", ""])
    if not packet["queue_work_items"]:
        lines.append("- No matching queue rows were found; refresh the queue.")
    for item in packet["queue_work_items"]:
        quality = f", quality_blocked={item['quality_blocked']}" if item["quality_blocked"] else ""
        dispatch = "dispatch_ready" if item["provider_dispatch_ready"] else item["workability_status"]
        lines.append(
            f"- `{item['queue_id']}` `{item['task_type']}` `{item['status']}` `{dispatch}`{quality}: {item['summary']}"
        )
    lines.extend(["", "## Miss Examples", ""])
    for miss in packet["miss_examples"]:
        detectors = ", ".join(f"`{det}`" for det in miss["independent_firing_detectors"][:4]) or "none"
        lines.append(f"- `{miss['slug']}` from `{miss['source']}`: independent detectors {detectors}")
    lines.extend(["", "## Commands", ""])
    for command in packet["commands"]:
        lines.append(f"- `{command}`")
    lines.extend(["", "## Control Obligations", ""])
    for obligation in packet["control_obligations"]:
        lines.append(f"- {obligation}")
    return "\n".join(lines) + "\n"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--priorities", type=Path, default=DEFAULT_PRIORITIES)
    parser.add_argument("--queue", type=Path, default=DEFAULT_QUEUE)
    parser.add_argument("--attack-class")
    parser.add_argument("--out-json", type=Path, default=DEFAULT_OUT_JSON)
    parser.add_argument("--out-md", type=Path, default=DEFAULT_OUT_MD)
    parser.add_argument("--miss-limit", type=int, default=6)
    parser.add_argument("--queue-limit", type=int, default=8)
    parser.add_argument("--json", action="store_true", help="Print JSON packet to stdout")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    packet = build_packet(
        priorities_path=args.priorities.expanduser().resolve(),
        queue_path=resolve_queue_path(args.queue),
        attack_class=args.attack_class,
        miss_limit=max(0, int(args.miss_limit)),
        queue_limit=max(0, int(args.queue_limit)),
    )
    args.out_json.expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
    args.out_md.expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
    args.out_json.expanduser().resolve().write_text(json.dumps(packet, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    args.out_md.expanduser().resolve().write_text(render_markdown(packet), encoding="utf-8")
    if args.json:
        print(json.dumps(packet, indent=2, sort_keys=True))
    else:
        selected = packet["selection"]["attack_class"]
        print(f"[realworld-recall-drilldown] attack_class={selected} out={_relpath(args.out_json)}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001
        print(f"[realworld-recall-drilldown] ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
