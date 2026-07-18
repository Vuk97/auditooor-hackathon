#!/usr/bin/env python3
"""Terminalize source/local proof rows left by full-corpus agent recall.

The output is deliberately conservative: it can close a recall task as
bounded/terminal for the recall loop, but it never promotes severity, selected
impact, or submission readiness.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Sequence


SCHEMA = "auditooor.pr560.agent_recall_source_local_proof_closure.v1"


def _read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _records(payload: dict[str, Any], *keys: str) -> list[dict[str, Any]]:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, list):
            return [row for row in value if isinstance(row, dict)]
    return []


def _slug(value: object, fallback: str = "row") -> str:
    text = str(value or "")
    out = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return out[:90] or fallback


def _safe_read_text(path: Path, limit: int = 200_000) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:limit]
    except OSError:
        return ""


def _provider_row(row: dict[str, Any], workspace: Path) -> dict[str, Any]:
    artifact = Path(str(row.get("source_artifact") or ""))
    if not artifact.is_absolute():
        artifact = workspace / artifact
    payload = _read_json(artifact)
    source_id = str(row.get("source_id") or "")
    for item in _records(payload, "rows"):
        if str(item.get("task_id") or "") == source_id:
            return item
    return {}


def _line_hits_for_provider(provider: dict[str, Any], workspace: Path) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    symbols = [str(symbol) for symbol in provider.get("symbols", []) if str(symbol)]
    paths: list[str] = []
    for key in ("source_paths",):
        values = provider.get(key)
        if isinstance(values, list):
            paths.extend(str(path) for path in values if str(path))
    for hit in provider.get("source_hits", []) if isinstance(provider.get("source_hits"), list) else []:
        if isinstance(hit, dict) and str(hit.get("path") or ""):
            paths.append(str(hit["path"]))
    for raw_path in sorted(set(paths)):
        path = Path(raw_path)
        if not path.is_absolute():
            path = workspace / path
        if not path.is_file():
            continue
        text = _safe_read_text(path)
        for lineno, line in enumerate(text.splitlines(), start=1):
            if any(symbol in line for symbol in symbols):
                hits.append({"path": str(path), "line": lineno, "text": line.strip()[:240]})
    return hits[:20]


def _source_decision(task: dict[str, Any], row: dict[str, Any], workspace: Path) -> dict[str, Any]:
    provider = _provider_row(row, workspace) if row.get("source") == "provider_local_verification" else {}
    artifact = Path(str(row.get("source_artifact") or ""))
    if not artifact.is_absolute():
        artifact = workspace / artifact
    artifact_text = _safe_read_text(artifact)
    line_hits = _line_hits_for_provider(provider, workspace) if provider else []
    provider_paths = [str(path) for path in provider.get("source_paths", []) if str(path)] if provider else []
    internal_prefixes = ("tools/", "docs/", "reference/", "Makefile")
    internal_tool_only = bool(provider_paths) and all(path.startswith(internal_prefixes) for path in provider_paths)
    missing_candidate_source = bool(provider.get("missing_sources")) if provider else False
    if provider and (internal_tool_only or provider.get("evidence_class") == "generated_hypothesis"):
        decision = "terminal_internal_tool_or_generated_hypothesis"
        terminal_state = "non_detectorizable_terminal" if internal_tool_only and not missing_candidate_source else "source_proof_terminal_blocked"
        reason = "provider row is an internal/generated tooling hypothesis, not candidate-bound project source proof"
    elif "cannot-run: no-api-key" in artifact_text:
        decision = "terminal_live_dispatch_summary_no_source_candidate"
        terminal_state = "source_proof_terminal_blocked"
        reason = "agent artifact is a live-dispatch skip summary and has no candidate-bound source proof"
    elif "Not pinging for merge" in artifact_text or "No ask." in artifact_text:
        decision = "terminal_checkpoint_note_not_source_candidate"
        terminal_state = "source_proof_terminal_blocked"
        reason = "agent artifact is a checkpoint/nudge note, not source proof for a finding"
    else:
        decision = "blocked_missing_candidate_bound_source_citation"
        terminal_state = "source_proof_terminal_blocked"
        reason = "no candidate-bound line-cited project source proof was found locally"
    blockers = [
        "no_exact_impact_contract",
        "no_selected_impact",
        "no_oos_duplicate_clearance",
    ]
    if not line_hits:
        blockers.append("no_line_cited_project_source")
    if missing_candidate_source:
        blockers.append("provider_missing_source_file")
    return {
        "decision": decision,
        "terminal_state": terminal_state,
        "action_lane": "source_proof_terminal_review",
        "proof_status": "terminal_source_review_recorded",
        "reason": reason,
        "line_hits": line_hits,
        "terminal_blockers": sorted(set(blockers)),
        "next_command": "provide candidate-bound project source path plus exact impact contract before reopening",
    }


def _local_decision(row: dict[str, Any], workspace: Path) -> dict[str, Any]:
    artifact = Path(str(row.get("source_artifact") or ""))
    if not artifact.is_absolute():
        artifact = workspace / artifact
    manifest = _read_json(artifact)
    status = str(manifest.get("status") or "")
    tests_passed = int(manifest.get("tests_passed") or 0)
    tests_failed = int(manifest.get("tests_failed") or 0)
    decision = "local_proof_recorded_no_counterexample" if status == "no-counterexample" and tests_failed == 0 else "local_proof_recorded_terminal_blocker"
    blockers = [
        "advisory_symbolic_or_harness_artifact_not_submission_proof",
        "no_exact_impact_contract",
        "no_selected_impact",
    ]
    if status == "timeout":
        blockers.extend(["solver_timeout", "rerun_required_with_bounded_profile"])
    elif status != "no-counterexample":
        blockers.append(f"manifest_status_{_slug(status, 'unknown')}")
    return {
        "decision": decision,
        "terminal_state": "local_proof_recorded_terminal",
        "action_lane": "local_proof_terminal_review",
        "proof_status": f"recorded_{status or 'unknown'}",
        "reason": "bounded local proof manifest exists; it is terminal for recall but not exploit proof",
        "manifest_status": status,
        "tests_passed": tests_passed,
        "tests_failed": tests_failed,
        "engine": str(manifest.get("engine") or ""),
        "mapping_strength": str(manifest.get("mapping_strength") or ""),
        "harness": str(manifest.get("harness") or ""),
        "workspace_harness_path": str(manifest.get("workspace_harness_path") or ""),
        "terminal_blockers": sorted(set(blockers)),
        "next_command": str(manifest.get("workspace_harness_path") or "rerun bounded harness with project-specific proof profile"),
    }


def build_closure(workspace: Path) -> dict[str, Any]:
    queue = _read_json(workspace / ".auditooor" / "agent_recall_detector_queue_full_corpus.json")
    proof = _read_json(workspace / ".auditooor" / "agent_recall_full_corpus_proof.json")
    rows_by_queue = {str(row.get("queue_id") or ""): row for row in _records(queue, "rows")}
    closure_rows: list[dict[str, Any]] = []
    for task in _records(proof, "remaining_open_tasks"):
        task_type = str(task.get("task_type") or "")
        if task_type not in {"source_proof_task", "local_proof_task"}:
            continue
        queue_id = str(task.get("queue_id") or "")
        row = rows_by_queue.get(queue_id, {})
        if task_type == "source_proof_task":
            decision = _source_decision(task, row, workspace)
        else:
            decision = _local_decision(row, workspace)
        closure_row = {
            "task_id": str(task.get("task_id") or ""),
            "queue_id": queue_id,
            "source": str(task.get("source") or ""),
            "source_id": str(task.get("source_id") or ""),
            "task_type_before": task_type,
            "source_artifact": str(row.get("source_artifact") or ""),
            "closure_artifact": str(workspace / ".auditooor" / "agent_recall_source_local_proof_closure.json"),
            "promotion_allowed": False,
            "severity": "none",
            "selected_impact": "",
            "submission_posture": "NOT_SUBMIT_READY",
            **decision,
        }
        closure_rows.append(closure_row)
    counts = Counter(str(row.get("decision") or "unknown") for row in closure_rows)
    state_counts = Counter(str(row.get("terminal_state") or "unknown") for row in closure_rows)
    task_counts = Counter(str(row.get("task_type_before") or "unknown") for row in closure_rows)
    return {
        "schema": SCHEMA,
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "workspace": str(workspace),
        "input_queue": str(workspace / ".auditooor" / "agent_recall_detector_queue_full_corpus.json"),
        "input_full_corpus_proof": str(workspace / ".auditooor" / "agent_recall_full_corpus_proof.json"),
        "rows_evaluated": len(closure_rows),
        "task_type_before_counts": dict(sorted(task_counts.items())),
        "decision_counts": dict(sorted(counts.items())),
        "terminal_state_counts": dict(sorted(state_counts.items())),
        "closed_for_recall_count": len(closure_rows),
        "promoted_count": 0,
        "exploit_impact_claims": 0,
        "advisory_only": True,
        "promotion_allowed": False,
        "submission_posture": "NOT_SUBMIT_READY",
        "limitations": [
            "terminal for the recall queue does not mean exploit proof",
            "no row assigns severity or selected impact",
            "source-proof terminal rows need candidate-bound project source and exact impact contract before reopening",
            "local-proof terminal rows are bounded harness/symbolic records only unless a proved exploit-impact execution manifest exists",
        ],
        "rows": closure_rows,
    }


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Agent Recall Source/Local Proof Closure",
        "",
        "Conservative closure record for source/local proof rows left open by full-corpus recall.",
        "",
        f"- rows evaluated: `{payload['rows_evaluated']}`",
        f"- closed for recall: `{payload['closed_for_recall_count']}`",
        f"- promoted exploit-impact claims: `{payload['exploit_impact_claims']}`",
        f"- submission posture: `{payload['submission_posture']}`",
        "",
        "## Decisions",
        "",
    ]
    for decision, count in payload["decision_counts"].items():
        lines.append(f"- `{decision}`: {count}")
    lines.extend([
        "",
        "## Rows",
        "",
        "| Task | Queue | Before | Terminal state | Decision | Blockers |",
        "|---|---|---|---|---|---|",
    ])
    for row in payload["rows"]:
        blockers = ", ".join(row.get("terminal_blockers", [])[:4])
        if len(row.get("terminal_blockers", [])) > 4:
            blockers += ", ..."
        lines.append("| `{}` | `{}` | `{}` | `{}` | `{}` | `{}` |".format(
            row["task_id"],
            row["queue_id"],
            row["task_type_before"],
            row["terminal_state"],
            row["decision"],
            blockers,
        ))
    return "\n".join(lines) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-md", type=Path)
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args(argv)

    workspace = args.workspace.expanduser().resolve()
    payload = build_closure(workspace)
    out_json = args.out_json or workspace / ".auditooor" / "agent_recall_source_local_proof_closure.json"
    out_md = args.out_md or workspace / ".auditooor" / "agent_recall_source_local_proof_closure.md"
    _write_json(out_json, payload)
    _write_text(out_md, render_markdown(payload))
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"wrote {out_json}")
        print(f"wrote {out_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
