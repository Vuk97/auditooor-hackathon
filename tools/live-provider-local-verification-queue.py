#!/usr/bin/env python3
"""Build advisory local verification queues from live provider triage rows."""
from __future__ import annotations

import argparse
import datetime as dt
import importlib.util
import json
import re
import shlex
from pathlib import Path
from typing import Any, Iterable, Sequence

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TRIAGE = ROOT / ".audit_logs" / "pr560_worker_an" / "live_provider_result_triage.json"
DEFAULT_OUT_JSON = ROOT / ".audit_logs" / "pr560_worker_at" / "local_provider_verification_queue.json"
DEFAULT_OUT_MD = ROOT / ".audit_logs" / "pr560_worker_at" / "local_provider_verification_queue.md"
TRIAGE_TOOL = ROOT / "tools" / "live-provider-result-triage.py"
GENERATED_EVIDENCE_CLASS = "generated_hypothesis"

QUEUE_SECTIONS = (
    "local_grep_tasks",
    "fixture_needed_tasks",
    "source_review_tasks",
    "killed_rows",
)


def _load_triage_parser() -> Any:
    spec = importlib.util.spec_from_file_location("live_provider_result_triage_for_queue", TRIAGE_TOOL)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load triage parser: {TRIAGE_TOOL}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


TRIAGE = _load_triage_parser()


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SystemExit(f"[live-provider-local-verification-queue] missing triage JSON: {path}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f"[live-provider-local-verification-queue] unreadable triage JSON: {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit(f"[live-provider-local-verification-queue] expected object JSON: {path}")
    return payload


def _read_provider_objects(row: dict[str, Any]) -> list[dict[str, Any]]:
    objects: list[dict[str, Any]] = []
    for key in ("kimi_output", "minimax_output"):
        raw = row.get(key)
        if not raw:
            continue
        path = Path(str(raw))
        if not path.is_file():
            continue
        parsed, _notes = TRIAGE.parse_provider_objects(path.read_text(encoding="utf-8", errors="replace"))
        objects.extend(obj for obj in parsed if isinstance(obj, dict))
    return objects


def _flatten(value: Any) -> Iterable[Any]:
    if isinstance(value, dict):
        for key, child in value.items():
            yield key
            yield from _flatten(child)
    elif isinstance(value, list):
        for child in value:
            yield from _flatten(child)
    else:
        yield value


def _unique(values: Iterable[Any], *, limit: int = 12) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
        if len(out) >= limit:
            break
    return out


def _walk_items(value: Any) -> Iterable[tuple[str, Any]]:
    if isinstance(value, dict):
        for key, child in value.items():
            yield str(key), child
            yield from _walk_items(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_items(child)


def _extract_file_hints(objects: Sequence[dict[str, Any]]) -> list[str]:
    hints: list[str] = []
    file_keys = {"file", "file_path", "path", "source_file"}
    for obj in objects:
        for key, value in _walk_items(obj):
            if key in file_keys and isinstance(value, str) and value:
                hints.append(value)
            elif key == "location" and isinstance(value, str) and "/" in value:
                hints.append(value)
            elif key == "location" and isinstance(value, dict):
                maybe = value.get("file") or value.get("path")
                if isinstance(maybe, str):
                    hints.append(maybe)
    return _unique(hints, limit=6)


def _normalize_pattern(value: Any) -> str:
    text = str(value or "").strip()
    text = re.sub(r"\s+", " ", text)
    if len(text) > 120:
        text = text[:117] + "..."
    return text


def _extract_grep_patterns(objects: Sequence[dict[str, Any]], row: dict[str, Any]) -> list[str]:
    patterns: list[str] = []
    for obj in objects:
        shape = obj.get("candidate_detector_shape")
        if isinstance(shape, dict):
            patterns.extend(_flatten(shape.get("local_verification_grep_patterns")))
            for key in ("pattern", "detector_type", "detector_concept", "pattern_type"):
                value = shape.get(key)
                if isinstance(value, str):
                    patterns.append(value)
        patterns.extend(_flatten(obj.get("local_checks_required")))
        facts = obj.get("extracted_source_facts")
        if isinstance(facts, dict):
            for key in ("symbol", "function", "function_signature", "implementation"):
                value = facts.get(key)
                if isinstance(value, str):
                    patterns.append(value)
    for classification_obj in objects:
        followup = classification_obj.get("minimum_followup_check")
        if isinstance(followup, str):
            patterns.extend(re.findall(r"`([^`]{2,80})`", followup))
            patterns.extend(re.findall(r"\b[A-Za-z_][A-Za-z0-9_]{3,}\b", followup)[:6])
    patterns.extend(row.get("classifications") or [])
    return _unique((_normalize_pattern(p) for p in patterns), limit=8)


def _candidate_family(objects: Sequence[dict[str, Any]]) -> str:
    for obj in objects:
        shape = obj.get("candidate_detector_shape")
        if not isinstance(shape, dict):
            continue
        for key in ("family", "detector_family", "detector_concept", "detector_type", "pattern_type"):
            value = shape.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return "provider-advisory"


def _minimum_followup(objects: Sequence[dict[str, Any]], fallback: str) -> str:
    for obj in reversed(objects):
        value = obj.get("minimum_followup_check")
        if isinstance(value, str) and value.strip():
            return value.strip()
    for obj in objects:
        checks = obj.get("local_checks_required")
        if isinstance(checks, list) and checks:
            return "; ".join(str(v) for v in checks[:4])
    return fallback


def _grep_command(patterns: Sequence[str], file_hints: Sequence[str]) -> str:
    if not patterns:
        return "rg -n '<provider-derived-pattern>' tools docs"
    usable = [
        p
        for p in patterns
        if len(p) <= 80
        and not p.lower().startswith(("grep ", "check ", "verify ", "confirm ", "examine ", "determine "))
        and (" " not in p or p.startswith("def "))
    ]
    usable = usable or list(patterns[:3])
    regex = "|".join(re.escape(p) for p in usable[:4])
    targets = []
    for hint in file_hints[:3]:
        hint = re.sub(r":\d+(?:-\d+)?$", "", hint)
        if hint.startswith(str(ROOT)):
            hint = str(Path(hint).resolve().relative_to(ROOT))
        targets.append(hint)
    if not targets:
        targets = ["tools", "docs"]
    return f"rg -n {shlex.quote(regex)} " + " ".join(shlex.quote(t) for t in targets)


def _base_task(
    *,
    queue_id: str,
    route: str,
    row: dict[str, Any],
    objects: Sequence[dict[str, Any]],
    title_suffix: str,
    triage_path: Path,
) -> dict[str, Any]:
    file_hints = _extract_file_hints(objects)
    grep_patterns = _extract_grep_patterns(objects, row)
    family = _candidate_family(objects)
    return {
        "queue_id": queue_id,
        "route": route,
        "task_id": str(row.get("task_id") or ""),
        "title": f"{family}: {title_suffix}",
        "provider_primary_category": str(row.get("primary_category") or ""),
        "provider_categories": list(row.get("categories") or []),
        "provider_classifications": list(row.get("classifications") or []),
        "source_triage_artifact": str(triage_path),
        "provider_final": str(row.get("final") or ""),
        "provider_outputs": {
            "kimi": str(row.get("kimi_output") or ""),
            "minimax": str(row.get("minimax_output") or ""),
        },
        "candidate_family": family,
        "file_hints": file_hints,
        "grep_patterns": grep_patterns,
        "minimum_followup_check": _minimum_followup(objects, str(row.get("reason") or "")),
        "advisory_only": True,
        "evidence_class": GENERATED_EVIDENCE_CLASS,
        "promotion_authority": False,
        "severity": "none",
        "selected_impact": "",
        "submission_posture": "NOT_SUBMIT_READY",
        "submit_ready": False,
    }


def _numbered(prefix: str, index: int) -> str:
    return f"{prefix}-{index:03d}"


def build_queue(triage_path: Path) -> dict[str, Any]:
    triage = _read_json(triage_path)
    rows = [row for row in triage.get("rows", []) if isinstance(row, dict)]
    candidate_rows = [row for row in rows if row.get("primary_category") == "candidate_harvest"]
    killed_rows_source = [row for row in rows if row.get("primary_category") == "killed_by_minimax"]

    local_grep_tasks: list[dict[str, Any]] = []
    fixture_needed_tasks: list[dict[str, Any]] = []
    source_review_tasks: list[dict[str, Any]] = []
    killed_rows: list[dict[str, Any]] = []

    for row in candidate_rows:
        objects = _read_provider_objects(row)
        categories = set(str(v) for v in row.get("categories") or [])
        if "needs_local_grep" in categories:
            task = _base_task(
                queue_id=_numbered("LPV-GREP", len(local_grep_tasks) + 1),
                route="local_grep",
                row=row,
                objects=objects,
                title_suffix="verify provider-suggested source shape with local grep",
                triage_path=triage_path,
            )
            task["next_command"] = _grep_command(task["grep_patterns"], task["file_hints"])
            task["terminal_state_options"] = ["verified_source_shape", "killed_false_positive", "needs_fixture", "source_review_only"]
            local_grep_tasks.append(task)
        if "needs_fixture" in categories:
            task = _base_task(
                queue_id=_numbered("LPV-FIX", len(fixture_needed_tasks) + 1),
                route="fixture_needed",
                row=row,
                objects=objects,
                title_suffix="design paired vulnerable and clean fixture before detector work",
                triage_path=triage_path,
            )
            task["next_command"] = "create paired vulnerable/clean fixture notes; do not promote detector until smoke-fire passes"
            task["fixture_requirements"] = [
                "vulnerable fixture demonstrating the source shape",
                "clean fixture covering the non-vulnerable neighbor",
                "local smoke command and captured output",
            ]
            task["terminal_state_options"] = ["fixture_smoke_ready", "killed_no_fixture_path", "source_review_only"]
            fixture_needed_tasks.append(task)
        if "non_detectorizable" in categories:
            task = _base_task(
                queue_id=_numbered("LPV-SRC", len(source_review_tasks) + 1),
                route="source_review_only",
                row=row,
                objects=objects,
                title_suffix="route to source review or invariant note instead of detector promotion",
                triage_path=triage_path,
            )
            task["next_command"] = "write source-review terminal note with exact file/line evidence or kill reason"
            task["terminal_state_options"] = ["source_review_note", "killed_duplicate_or_oos", "needs_harness_with_exact_impact"]
            source_review_tasks.append(task)

    for row in killed_rows_source:
        objects = _read_provider_objects(row)
        task = _base_task(
            queue_id=_numbered("LPV-KILL", len(killed_rows) + 1),
            route="killed_by_minimax",
            row=row,
            objects=objects,
            title_suffix="preserve local kill row unless grep contradicts minimax",
            triage_path=triage_path,
        )
        task["next_command"] = _grep_command(task["grep_patterns"], task["file_hints"])
        task["kill_reason"] = str(row.get("reason") or "")
        task["terminal_state_options"] = ["kill_confirmed", "reopen_for_local_grep_only"]
        killed_rows.append(task)

    summary = {
        "triage_rows": len(rows),
        "candidate_harvest_rows": len(candidate_rows),
        "killed_by_minimax_rows": len(killed_rows_source),
        "local_grep_tasks": len(local_grep_tasks),
        "fixture_needed_tasks": len(fixture_needed_tasks),
        "source_review_tasks": len(source_review_tasks),
        "killed_rows": len(killed_rows),
        "total_queue_items": len(local_grep_tasks) + len(fixture_needed_tasks) + len(source_review_tasks) + len(killed_rows),
    }
    return {
        "schema": "auditooor.live_provider_local_verification_queue.v1",
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "source_triage": str(triage_path),
        "advisory_only": True,
        "evidence_class": GENERATED_EVIDENCE_CLASS,
        "promotion_authority": False,
        "severity": "none",
        "selected_impact": "",
        "submission_posture": "NOT_SUBMIT_READY",
        "submit_ready": False,
        "summary": summary,
        "local_grep_tasks": local_grep_tasks,
        "fixture_needed_tasks": fixture_needed_tasks,
        "source_review_tasks": source_review_tasks,
        "killed_rows": killed_rows,
        "rows": local_grep_tasks + fixture_needed_tasks + source_review_tasks + killed_rows,
        "status": "actionable_verification_queue" if summary["total_queue_items"] else "empty_no_provider_triage_rows",
    }


def render_markdown(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    lines = [
        "# Live Provider Local Verification Queue",
        "",
        "Advisory local-only queue generated from live provider triage. No row promotes severity, detector readiness, PoC readiness, or submission readiness.",
        "",
        f"- source triage: `{payload['source_triage']}`",
        f"- total queue items: `{summary['total_queue_items']}`",
        f"- candidate harvest rows: `{summary['candidate_harvest_rows']}`",
        f"- killed rows: `{summary['killed_by_minimax_rows']}`",
        f"- advisory only: `{str(payload['advisory_only']).lower()}`",
        f"- submit ready: `{str(payload['submit_ready']).lower()}`",
        "",
        "## Summary",
        "",
        "| Queue | Items |",
        "|---|---:|",
    ]
    for section in QUEUE_SECTIONS:
        lines.append(f"| `{section}` | {summary[section]} |")
    for section in QUEUE_SECTIONS:
        lines.extend(["", f"## {section.replace('_', ' ').title()}", "", "| ID | Task | Title | Next command |", "|---|---|---|---|"])
        rows = payload.get(section) or []
        if not rows:
            lines.append("| _none_ | _none_ | _none_ | _none_ |")
            continue
        for row in rows:
            title = str(row.get("title") or "").replace("|", "\\|")
            command = str(row.get("next_command") or "").replace("|", "\\|")
            lines.append(f"| `{row['queue_id']}` | `{row['task_id']}` | {title} | `{command}` |")
    return "\n".join(lines) + "\n"


def write_outputs(payload: dict[str, Any], out_json: Path, out_md: Path | None) -> None:
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if out_md is not None:
        out_md.parent.mkdir(parents=True, exist_ok=True)
        out_md.write_text(render_markdown(payload), encoding="utf-8")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--triage-json", type=Path, default=DEFAULT_TRIAGE)
    parser.add_argument("--out-json", type=Path, default=DEFAULT_OUT_JSON)
    parser.add_argument("--out-md", type=Path, default=DEFAULT_OUT_MD)
    parser.add_argument("--print-json", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    payload = build_queue(args.triage_json)
    write_outputs(payload, args.out_json, args.out_md)
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
