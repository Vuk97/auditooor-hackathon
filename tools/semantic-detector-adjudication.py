#!/usr/bin/env python3
"""Adjudicate semantic query matches into advisory detector next actions.

This is the layer after semantic-graph-query: it consumes executed
semantic_graph_query results and emits detector rewrite briefs, fixture
requirements, or explicit non-detectorizable/source-review-only rows. It never
promotes severity, selected impact, PoC posture, or submission readiness.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "auditooor.semantic_detector_adjudication.v1"
SOURCE_SHAPE_LIMITATIONS = [
    "adjudication consumes semantic_graph_query source-shape matches only",
    "detector rewrite briefs are not detector implementations or smoke-fire proof",
    "multi-hop paths require fixture/source-invariant proof before detector rewrite",
    "zero/generic/orphaned rows must be killed, reframed, or kept source-review-only",
    "severity, selected impact, PoC posture, and submission readiness remain blocked",
]
DETECTORIZABLE_SHAPES = {
    "factory_proxy_or_clone_relation",
    "verifier_adapter_relation",
    "registry_write_relation",
    "oracle_or_root_relation",
    "impact_worklist_component_relations",
}
FIXTURE_FIRST_SHAPES = {
    "bridge_or_proof_finalization_path",
    "state_root_validation_path",
    "external_validation_path",
    "impact_worklist_multihop_path",
}


def _load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SystemExit(f"[semantic-detector-adjudication] missing {label}: {path}") from exc
    except (json.JSONDecodeError, OSError) as exc:
        raise SystemExit(f"[semantic-detector-adjudication] unreadable {label}: {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit(f"[semantic-detector-adjudication] expected object JSON for {label}: {path}")
    return payload


def _slug(value: str, fallback: str = "semantic") -> str:
    out = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return out or fallback


def _task_index(worklist: dict[str, Any]) -> dict[str, dict[str, Any]]:
    tasks = worklist.get("tasks") if isinstance(worklist.get("tasks"), list) else []
    return {
        str(task.get("task_id") or ""): task
        for task in tasks
        if isinstance(task, dict) and str(task.get("task_id") or "")
    }


def _match_sample(result: dict[str, Any]) -> dict[str, Any]:
    matches = result.get("matches") if isinstance(result.get("matches"), list) else []
    first = matches[0] if matches and isinstance(matches[0], dict) else {}
    return {
        "file": first.get("file", ""),
        "line": first.get("line", 0),
        "source_contract": first.get("source_contract", ""),
        "source_function": first.get("source_function", ""),
        "source_component": first.get("source_component", ""),
        "sink_component": first.get("sink_component", ""),
        "path_id": first.get("path_id", ""),
        "kind": first.get("kind", ""),
        "receiver": first.get("receiver", ""),
        "target_type": first.get("target_type", ""),
        "method": first.get("method", ""),
    }


def _fixture_tags(task: dict[str, Any]) -> list[str]:
    bridge = task.get("detector_query_bridge") if isinstance(task.get("detector_query_bridge"), dict) else {}
    tags = bridge.get("fixture_tags") if isinstance(bridge.get("fixture_tags"), list) else []
    return [str(tag) for tag in tags if tag]


def _workspace_make(command: str, workspace: Path, *args: str) -> str:
    parts = [f"make {command}", f"WS={workspace}"]
    parts.extend(arg for arg in args if arg)
    return " ".join(parts)


def _base_row(result: dict[str, Any], task: dict[str, Any]) -> dict[str, Any]:
    sample = _match_sample(result)
    task_id = str(result.get("task_id") or task.get("task_id") or result.get("route_id") or "")
    family = str(result.get("candidate_detector_family") or task.get("candidate_detector_family") or result.get("impact_family") or "semantic_source_shape")
    return {
        "task_id": task_id,
        "route_id": result.get("route_id", task_id),
        "impact_id": result.get("impact_id", ""),
        "impact_family": result.get("impact_family", task.get("impact_family", "")),
        "candidate_detector_family": family,
        "query_shape": result.get("query_shape", ""),
        "source_collection": result.get("source_collection", ""),
        "query_status": result.get("query_status", ""),
        "match_count": int(result.get("match_count") or 0),
        "truncated": bool(result.get("truncated")),
        "sample": sample,
        "fixture_tags": _fixture_tags(task),
        "action_lane": result.get("action_lane", task.get("action_lane", "")),
        "detectorization_readiness": result.get(
            "detectorization_readiness",
            task.get("detectorization_readiness", ""),
        ),
        "worklist_task_found": bool(task),
        "source_shape_limitations": SOURCE_SHAPE_LIMITATIONS,
        "coverage_claim": "none_source_shape_only",
        "advisory_only": True,
        "promotion_allowed": False,
        "severity": "none",
        "severity_claim": "none",
        "selected_impact": "",
        "submission_posture": "NOT_SUBMIT_READY",
        "submit_status": "NOT_SUBMIT_READY",
        "impact_contract_required": True,
        "submit_ready": False,
    }


def _detector_brief(base: dict[str, Any], idx: int, workspace: Path) -> dict[str, Any]:
    family_slug = _slug(str(base["candidate_detector_family"]), "semantic-detector")
    task_slug = _slug(str(base["task_id"] or base["route_id"]), f"row-{idx:03d}")
    fixture_id = f"SDA-FIX-{idx:03d}"
    return {
        **base,
        "brief_id": f"SDA-DET-{idx:03d}",
        "adjudication": "detector_rewrite_brief",
        "next_action_type": "detector_rewrite_with_paired_fixtures",
        "detector_slug": f"{family_slug}_{task_slug}",
        "detector_goal": (
            "Rewrite or add a static predicate for the matched semantic source shape; "
            "do not encode impact or severity in the detector."
        ),
        "static_predicate_requirements": [
            "anchor on the matched query_shape/source_collection",
            "require the observed receiver/method/type/path fields where present",
            "avoid broad keyword-only matching unless paired with a structural predicate",
            "emit no severity, selected_impact, PoC, or submit-ready fields",
        ],
        "terminal_decision_required": "detectorizable_with_vulnerable_and_clean_fixtures",
        "fixture_requirement_ids": [fixture_id],
        "fixture_plan": {
            "required_fixture_ids": [fixture_id],
            "positive_fixture_glob": f"detectors/fixtures/**/{fixture_id.lower()}*_positive*",
            "clean_fixture_glob": f"detectors/fixtures/**/{fixture_id.lower()}*_clean*",
            "fixture_tags": list(base.get("fixture_tags") or []),
        },
        "promotion_blockers": [
            "vulnerable fixture missing",
            "clean fixture missing",
            "detector smoke output missing",
            "exact impact contract missing",
        ],
        "local_checklist": [
            "write or rewrite the detector predicate",
            "add the paired positive fixture",
            "add the paired clean fixture",
            "run detector smoke and capture output",
            "refresh semantic-detector-adjudication and pr560-next-actions",
        ],
        "next_command": _workspace_make(
            "semantic-detector-adjudication",
            workspace,
            f"# implement {family_slug}_{task_slug} with SDA-FIX-{idx:03d} positive/clean fixtures, then run detector smoke",
        ),
        "smoke_command": f"make -C detectors run TARGET=detectors/fixtures/{family_slug} DETECTOR={family_slug}_{task_slug} # after fixtures exist",
    }


def _fixture_requirement(base: dict[str, Any], idx: int, workspace: Path) -> dict[str, Any]:
    family_slug = _slug(str(base["candidate_detector_family"]), "semantic")
    fixture_id = f"SDA-FIX-{idx:03d}"
    return {
        **base,
        "fixture_id": fixture_id,
        "adjudication": "fixture_requirement",
        "next_action_type": "paired_fixture_task",
        "positive_fixture_name": f"{family_slug}_positive_{idx:03d}",
        "clean_fixture_name": f"{family_slug}_clean_{idx:03d}",
        "fixture_artifact_requirements": [
            {
                "kind": "positive_fixture",
                "suggested_path": f"detectors/fixtures/{family_slug}/{family_slug}_positive_{idx:03d}.sol",
                "must_match_query_shape": base.get("query_shape", ""),
            },
            {
                "kind": "clean_fixture",
                "suggested_path": f"detectors/fixtures/{family_slug}/{family_slug}_clean_{idx:03d}.sol",
                "must_not_match_query_shape": base.get("query_shape", ""),
            },
            {
                "kind": "smoke_record",
                "suggested_path": f"detectors/fixtures/{family_slug}/{fixture_id.lower()}_smoke.json",
                "must_record": "hit count plus advisory-only posture",
            },
        ],
        "required_assertions": [
            "positive fixture matches the same semantic query shape",
            "clean fixture contains adjacent safe code that must not match",
            "smoke output records hit count without severity or submit-ready fields",
            "fixture does not rely on a local-only mock as impact evidence",
        ],
        "terminal_decision_required": (
            "fixture_first_before_detector_rewrite"
            if base.get("source_collection") == "multi_hop_paths"
            else "detectorizable_with_vulnerable_and_clean_fixtures"
        ),
        "blocked_until": [
            "fixture files exist",
            "detector smoke command is recorded",
            "exact impact contract remains separate from detector matching",
        ],
        "next_command": _workspace_make(
            "semantic-detector-adjudication",
            workspace,
            f"# create {fixture_id} vulnerable/clean fixtures for task {base.get('task_id') or base.get('route_id')}",
        ),
    }


def _non_detectorizable(base: dict[str, Any], idx: int, reason: str, workspace: Path) -> dict[str, Any]:
    source_review_id = f"SDA-SRC-{idx:03d}"
    return {
        **base,
        "row_id": f"SDA-ND-{idx:03d}",
        "source_review_id": source_review_id,
        "adjudication": "non_detectorizable",
        "next_action_type": "source_review_or_kill_note",
        "reason": reason,
        "terminal_state": "source_or_invariant_review_only",
        "terminal_decision_required": "source_review_or_invariant_only",
        "triage_requirements": [
            "write a kill/reframe/source-review note before removing from the queue",
            "do not create a detector until a narrower structural predicate is specified",
            "do not promote severity or selected impact from this source-shape row",
        ],
        "recommended_action": (
            "Keep this as source-review/invariant-only input unless a narrower "
            "static predicate and paired fixtures are later identified."
        ),
        "next_command": _workspace_make(
            "source-proof-task-queue",
            workspace,
            f"# record {source_review_id} source-review-only rationale for {reason}",
        ),
    }


def _action_item(row: dict[str, Any]) -> dict[str, Any]:
    identifier = str(
        row.get("brief_id")
        or row.get("fixture_id")
        or row.get("row_id")
        or row.get("task_id")
        or row.get("route_id")
        or ""
    )
    return {
        "action_id": identifier,
        "action_type": row.get("next_action_type") or row.get("adjudication") or "",
        "task_id": row.get("task_id", ""),
        "route_id": row.get("route_id", ""),
        "candidate_detector_family": row.get("candidate_detector_family", ""),
        "query_shape": row.get("query_shape", ""),
        "source_collection": row.get("source_collection", ""),
        "terminal_decision_required": row.get("terminal_decision_required", ""),
        "next_command": row.get("next_command", ""),
        "submit_ready": False,
        "severity": "none",
        "selected_impact": "",
        "promotion_allowed": False,
        "coverage_claim": "none_source_shape_only",
    }


def build_adjudication(
    workspace: Path,
    results: dict[str, Any],
    worklist: dict[str, Any],
    *,
    limit: int = 50,
) -> dict[str, Any]:
    task_by_id = _task_index(worklist)
    detector_briefs: list[dict[str, Any]] = []
    fixture_requirements: list[dict[str, Any]] = []
    non_detectorizable: list[dict[str, Any]] = []
    action_items: list[dict[str, Any]] = []
    rows = [row for row in (results.get("results") or []) if isinstance(row, dict)]
    for idx, result in enumerate(rows[: max(0, limit)], start=1):
        task_id = str(result.get("task_id") or "")
        task = task_by_id.get(task_id, {})
        base = _base_row(result, task)
        shape = str(base.get("query_shape") or "")
        source_collection = str(base.get("source_collection") or "")
        match_count = int(base.get("match_count") or 0)
        query_status = str(base.get("query_status") or "")
        if query_status and query_status != "executed":
            nd = _non_detectorizable(base, idx, f"query_status_{_slug(query_status)}", workspace)
            non_detectorizable.append(nd)
            action_items.append(_action_item(nd))
            continue
        if match_count <= 0:
            nd = _non_detectorizable(base, idx, "zero_match_query_result", workspace)
            non_detectorizable.append(nd)
            action_items.append(_action_item(nd))
            continue
        if not base.get("worklist_task_found") and results.get("source_mode") == "semantic_detector_worklist":
            nd = _non_detectorizable(base, idx, "worklist_task_missing_for_query_result", workspace)
            non_detectorizable.append(nd)
            action_items.append(_action_item(nd))
            continue
        if shape in DETECTORIZABLE_SHAPES and source_collection == "relation_edges":
            brief = _detector_brief(base, idx, workspace)
            fixture = _fixture_requirement(base, idx, workspace)
            detector_briefs.append(brief)
            fixture_requirements.append(fixture)
            action_items.extend([_action_item(brief), _action_item(fixture)])
        elif shape in FIXTURE_FIRST_SHAPES and source_collection == "multi_hop_paths":
            fixture = _fixture_requirement(base, idx, workspace)
            nd = _non_detectorizable(base, idx, "multi_hop_path_requires_fixture_or_invariant_before_detector_rewrite", workspace)
            fixture_requirements.append(fixture)
            non_detectorizable.append(nd)
            action_items.extend([_action_item(fixture), _action_item(nd)])
        else:
            nd = _non_detectorizable(base, idx, "source_shape_too_generic_for_detector_rewrite", workspace)
            non_detectorizable.append(nd)
            action_items.append(_action_item(nd))

    matched_rows = sum(int(row.get("match_count") or 0) for row in rows)
    reason_counts: dict[str, int] = {}
    for row in non_detectorizable:
        reason = str(row.get("reason") or "unknown")
        reason_counts[reason] = reason_counts.get(reason, 0) + 1
    closure_commands = [
        *[str(row.get("next_command") or "") for row in detector_briefs],
        *[str(row.get("next_command") or "") for row in fixture_requirements],
        *[str(row.get("next_command") or "") for row in non_detectorizable],
    ]
    return {
        "schema": SCHEMA_VERSION,
        "workspace": str(workspace),
        "source_artifact": results.get("source_artifact", ""),
        "query_results_artifact": str(workspace / ".auditooor" / "semantic_graph_query_results.json"),
        "detector_worklist_artifact": str(workspace / ".auditooor" / "semantic_detector_worklist.json"),
        "source_mode": results.get("source_mode", ""),
        "coverage_claim": "none_source_shape_only",
        "source_shape_limitations": SOURCE_SHAPE_LIMITATIONS,
        "advisory_only": True,
        "promotion_allowed": False,
        "severity": "none",
        "severity_claim": "none",
        "selected_impact": "",
        "submission_posture": "NOT_SUBMIT_READY",
        "submit_status": "NOT_SUBMIT_READY",
        "impact_contract_required": True,
        "processed_query_count": min(len(rows), max(0, limit)),
        "input_query_count": len(rows),
        "input_matched_row_count": matched_rows,
        "truncated": len(rows) > max(0, limit),
        "detector_rewrite_brief_count": len(detector_briefs),
        "fixture_requirement_count": len(fixture_requirements),
        "non_detectorizable_count": len(non_detectorizable),
        "action_item_count": len(action_items),
        "adjudication_summary": {
            "detector_rewrite_brief_count": len(detector_briefs),
            "fixture_requirement_count": len(fixture_requirements),
            "non_detectorizable_count": len(non_detectorizable),
            "non_detectorizable_reason_counts": reason_counts,
            "orphaned_query_result_count": reason_counts.get("worklist_task_missing_for_query_result", 0),
            "non_executed_query_result_count": sum(
                count for reason, count in reason_counts.items() if reason.startswith("query_status_")
            ),
        },
        "readiness": {
            "ready_for_detector_rewrite_count": len(detector_briefs),
            "fixture_first_count": len(fixture_requirements),
            "source_review_only_count": len(non_detectorizable),
            "ready_for_submission": False,
            "ready_for_poc": False,
            "ready_for_severity": False,
        },
        "detector_rewrite_briefs": detector_briefs,
        "fixture_requirements": fixture_requirements,
        "non_detectorizable_rows": non_detectorizable,
        "action_items": action_items[: max(0, limit) * 3],
        "mining_priority_integration": {
            "status": "ready_for_sidecar",
            "priority_hint": "matched relation-edge briefs first, multi-hop rows after fixture planning",
            "blocked_submission_claims": [
                "severity",
                "selected_impact",
                "PoC readiness",
                "submit readiness",
            ],
        },
        "next_actions": [
            "Implement only detector_rewrite_brief rows with paired fixture requirements.",
            "Route non_detectorizable rows to source/invariant review or kill/reframe notes.",
            "Refresh mining priorities so this adjudication appears as an advisory sidecar.",
        ],
        "next_commands": [command for command in closure_commands[:50] if command],
    }


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Semantic Detector Adjudication",
        "",
        "Advisory post-query triage for semantic detector work. These rows are not findings, PoCs, severity approvals, or submit-ready candidates.",
        "",
        f"- schema: `{payload['schema']}`",
        f"- processed queries: {payload['processed_query_count']} / {payload['input_query_count']}",
        f"- detector rewrite briefs: {payload['detector_rewrite_brief_count']}",
        f"- fixture requirements: {payload['fixture_requirement_count']}",
        f"- non-detectorizable rows: {payload['non_detectorizable_count']}",
        f"- coverage claim: `{payload['coverage_claim']}`",
        f"- submission posture: `{payload['submission_posture']}`",
        f"- ready for submission: `{str((payload.get('readiness') or {}).get('ready_for_submission', False)).lower()}`",
        "",
        "## Source-Shape Limitations",
        "",
    ]
    for limitation in payload.get("source_shape_limitations", []):
        lines.append(f"- {limitation}")
    lines.extend([
        "",
        "## Detector Rewrite Briefs",
        "",
    ]
    )
    briefs = payload.get("detector_rewrite_briefs") if isinstance(payload.get("detector_rewrite_briefs"), list) else []
    if not briefs:
        lines.append("_No detector rewrite briefs._")
    else:
        lines.extend(["| Brief | Task | Shape | Decision | Matches | Detector Slug | Next command |", "|---|---|---|---|---:|---|---|"])
        for row in briefs:
            lines.append("| `{}` | `{}` | `{}` | `{}` | {} | `{}` | `{}` |".format(
                row.get("brief_id", ""),
                row.get("task_id", ""),
                row.get("query_shape", ""),
                row.get("terminal_decision_required", ""),
                row.get("match_count", 0),
                row.get("detector_slug", ""),
                row.get("next_command", ""),
            ))
    lines.extend(["", "## Fixture Requirements", ""])
    fixtures = payload.get("fixture_requirements") if isinstance(payload.get("fixture_requirements"), list) else []
    if not fixtures:
        lines.append("_No fixture requirements._")
    else:
        lines.extend(["| Fixture | Task | Decision | Positive | Clean | Posture | Next command |", "|---|---|---|---|---|---|---|"])
        for row in fixtures:
            lines.append("| `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` |".format(
                row.get("fixture_id", ""),
                row.get("task_id", ""),
                row.get("terminal_decision_required", ""),
                row.get("positive_fixture_name", ""),
                row.get("clean_fixture_name", ""),
                row.get("submission_posture", ""),
                row.get("next_command", ""),
            ))
    lines.extend(["", "## Non-Detectorizable Rows", ""])
    nd_rows = payload.get("non_detectorizable_rows") if isinstance(payload.get("non_detectorizable_rows"), list) else []
    if not nd_rows:
        lines.append("_No explicit non-detectorizable rows._")
    else:
        lines.extend(["| Row | Task | Shape | Reason | Next command |", "|---|---|---|---|---|"])
        for row in nd_rows:
            lines.append("| `{}` | `{}` | `{}` | {} | `{}` |".format(
                row.get("row_id", ""),
                row.get("task_id", ""),
                row.get("query_shape", ""),
                row.get("reason", ""),
                row.get("next_command", ""),
            ))
    summary = payload.get("adjudication_summary") if isinstance(payload.get("adjudication_summary"), dict) else {}
    reason_counts = summary.get("non_detectorizable_reason_counts") if isinstance(summary.get("non_detectorizable_reason_counts"), dict) else {}
    lines.extend(["", "## Non-Detectorizable Reason Counts", ""])
    if reason_counts:
        for reason, count in sorted(reason_counts.items()):
            lines.append(f"- `{reason}`: {count}")
    else:
        lines.append("- _none_")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--query-results", type=Path)
    parser.add_argument("--worklist", type=Path)
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-md", type=Path)
    parser.add_argument("--limit", type=int, default=50)
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args()

    workspace = args.workspace.expanduser().resolve()
    if not workspace.is_dir():
        print(f"[semantic-detector-adjudication] workspace not found: {workspace}", file=sys.stderr)
        return 2
    query_path = (args.query_results or workspace / ".auditooor" / "semantic_graph_query_results.json").expanduser().resolve()
    worklist_path = (args.worklist or workspace / ".auditooor" / "semantic_detector_worklist.json").expanduser().resolve()
    results = _load_json(query_path, "semantic query results")
    worklist = _load_json(worklist_path, "semantic detector worklist")
    payload = build_adjudication(workspace, results, worklist, limit=max(0, args.limit))
    out_json = args.out_json or (workspace / ".auditooor" / "semantic_detector_adjudication.json")
    out_md = args.out_md or (workspace / ".auditooor" / "semantic_detector_adjudication.md")
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(payload), encoding="utf-8")
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    print(
        "[semantic-detector-adjudication] OK "
        f"briefs={payload['detector_rewrite_brief_count']} "
        f"fixtures={payload['fixture_requirement_count']} "
        f"non_detectorizable={payload['non_detectorizable_count']} json={out_json}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
