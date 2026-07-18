#!/usr/bin/env python3
"""Execute advisory semantic_graph_query specs against semantic_graph.json.

This is intentionally narrow: it evaluates the query specs emitted by
semantic-detector-worklist.py against relation_edges and multi_hop_paths only.
Results are source-shape matches for local detector planning, not findings.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "auditooor.semantic_graph_query_results.v1"
SOURCE_SHAPE_LIMITATIONS = [
    "matches are semantic_graph source-shape rows only",
    "query execution does not run detectors or detector smoke tests",
    "query execution does not prove runtime reachability, value flow, roles, deployment state, or impact",
    "all matched rows remain NOT_SUBMIT_READY until exact impact proof, fixtures, and execution artifacts exist",
]


def _load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SystemExit(f"[semantic-graph-query] missing JSON artifact: {path}") from exc
    except (json.JSONDecodeError, OSError) as exc:
        raise SystemExit(f"[semantic-graph-query] unreadable JSON artifact: {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit(f"[semantic-graph-query] expected object JSON in {path}")
    return payload


def _as_text(value: Any) -> str:
    if isinstance(value, list):
        return " ".join(_as_text(item) for item in value)
    if isinstance(value, dict):
        return " ".join(f"{key}={_as_text(val)}" for key, val in value.items())
    return "" if value is None else str(value)


def _field_values(row: dict[str, Any], key: str) -> list[str]:
    if key == "receiver":
        return [_as_text(row.get("receiver")), _as_text(row.get("target"))]
    if key == "source_component":
        source = "{}.{}".format(row.get("source_contract", ""), row.get("source_function", "")).strip(".")
        return [_as_text(row.get("source_component")), source]
    if key == "sink_component":
        return [_as_text(row.get("sink_component")), _as_text(row.get("target"))]
    return [_as_text(row.get(key))]


def _has_present(row: dict[str, Any], key: str) -> bool:
    return any(bool(value) for value in _field_values(row, key))


def _match_exact(row: dict[str, Any], key: str, expected: Any) -> bool:
    expected_text = _as_text(expected)
    if not expected_text:
        return True
    return any(value == expected_text for value in _field_values(row, key))


def _match_regex(row: dict[str, Any], keys: list[str], pattern: Any) -> bool:
    pattern_text = _as_text(pattern)
    if not pattern_text:
        return True
    try:
        rx = re.compile(pattern_text)
    except re.error:
        return False
    haystack = " ".join(_as_text(row.get(key)) for key in keys)
    return bool(rx.search(haystack))


def _match_mapped_stages(row: dict[str, Any], expected: Any) -> bool:
    expected_stages = [str(stage) for stage in (expected or []) if stage]
    if not expected_stages:
        return True
    actual = {str(stage) for stage in (row.get("mapped_stages") or []) if stage}
    return all(stage in actual for stage in expected_stages)


def _match_condition(row: dict[str, Any], condition: dict[str, Any]) -> bool:
    for key, expected in condition.items():
        if key == "target_regex":
            if not _match_regex(row, ["target", "receiver", "target_type"], expected):
                return False
        elif key == "target_or_method_regex":
            if not _match_regex(row, ["target", "receiver", "target_type", "method"], expected):
                return False
        elif key == "receiver_or_method_regex":
            if not _match_regex(row, ["receiver", "target", "receiver_source", "method"], expected):
                return False
        elif key == "evidence_regex":
            if not _match_regex(row, ["evidence", "evidence_edges"], expected):
                return False
        elif key == "target_type_present":
            if bool(expected) and not _has_present(row, "target_type"):
                return False
        elif key == "receiver_source_present":
            if bool(expected) and not _has_present(row, "receiver_source"):
                return False
        elif key == "mapped_stages":
            if not _match_mapped_stages(row, expected):
                return False
        else:
            if not _match_exact(row, key, expected):
                return False
    return True


def _matches_spec(row: dict[str, Any], spec: dict[str, Any]) -> bool:
    match_fields = spec.get("match_fields") if isinstance(spec.get("match_fields"), dict) else {}
    for key, expected in match_fields.items():
        if key == "mapped_stages":
            if not _match_mapped_stages(row, expected):
                return False
        elif not _match_exact(row, key, expected):
            return False
    required_stages = [str(stage) for stage in (spec.get("required_stages") or []) if stage]
    if required_stages and not _match_mapped_stages(row, required_stages):
        return False
    must_match_any = spec.get("must_match_any") if isinstance(spec.get("must_match_any"), list) else []
    conditions = [item for item in must_match_any if isinstance(item, dict)]
    if conditions and not any(_match_condition(row, condition) for condition in conditions):
        return False
    return True


def _project_row(row: dict[str, Any], required_fields: list[str], source_collection: str) -> dict[str, Any]:
    out = {field: row.get(field, "") for field in required_fields}
    if source_collection == "relation_edges":
        source = "{}.{}".format(row.get("source_contract", ""), row.get("source_function", "")).strip(".")
        out.setdefault("source_contract", row.get("source_contract", ""))
        out.setdefault("source_function", row.get("source_function", ""))
        out.setdefault("source_component", source)
    if source_collection == "multi_hop_paths":
        out.setdefault("path_id", row.get("path_id", ""))
    out["source_collection"] = source_collection
    out["advisory_only"] = True
    out["coverage_claim"] = "none_source_shape_only"
    out["severity"] = "none"
    out["selected_impact"] = ""
    out["submission_posture"] = "NOT_SUBMIT_READY"
    out["impact_contract_required"] = True
    out["promotion_allowed"] = False
    return out


def execute_spec(
    graph: dict[str, Any],
    spec: dict[str, Any],
    *,
    task: dict[str, Any] | None = None,
    limit: int = 50,
) -> dict[str, Any]:
    if spec.get("backend") != "semantic_graph_query":
        raise ValueError("unsupported query backend")
    source_collection = str(spec.get("source_collection") or "")
    if source_collection not in {"relation_edges", "multi_hop_paths"}:
        raise ValueError(f"unsupported source_collection: {source_collection or '<empty>'}")
    rows = [row for row in graph.get(source_collection, []) if isinstance(row, dict)]
    required_fields = [str(field) for field in (spec.get("required_output_fields") or []) if field]
    matched = [_project_row(row, required_fields, source_collection) for row in rows if _matches_spec(row, spec)]
    task = task or {}
    action_lane = str(task.get("action_lane") or "")
    detectorization_readiness = str(task.get("detectorization_readiness") or "")
    if not action_lane:
        action_lane = "fixture_first_source_invariant" if source_collection == "multi_hop_paths" else "detector_rewrite_candidate"
    if not detectorization_readiness:
        detectorization_readiness = (
            "not_ready_fixture_or_invariant_first"
            if source_collection == "multi_hop_paths"
            else "candidate_static_predicate_needs_fixtures"
        )
    return {
        "task_id": task.get("task_id", ""),
        "source_id": task.get("source_id", ""),
        "candidate_detector_family": task.get("candidate_detector_family", ""),
        "impact_id": task.get("impact_id", ""),
        "impact_family": task.get("impact_family", ""),
        "route_id": task.get("route_id", task.get("task_id", "")),
        "route_kind": task.get("route_kind", ""),
        "component_id": task.get("component_id", ""),
        "source_artifact_kind": task.get("source_artifact_kind", ""),
        "query_shape": spec.get("query_shape", ""),
        "source_collection": source_collection,
        "query_status": "executed",
        "action_lane": action_lane,
        "detectorization_readiness": detectorization_readiness,
        "source_shape_limitations": SOURCE_SHAPE_LIMITATIONS,
        "required_terminal_decision": [
            "detectorizable_with_vulnerable_and_clean_fixtures",
            "fixture_first_before_detector_rewrite",
            "source_review_or_invariant_only",
            "kill_or_reframe_as_non_detectorizable",
        ],
        "advisory_only": True,
        "promotion_allowed": False,
        "severity": "none",
        "severity_claim": "none",
        "selected_impact": "",
        "submission_posture": "NOT_SUBMIT_READY",
        "submit_status": "NOT_SUBMIT_READY",
        "impact_contract_required": True,
        "coverage_claim": "none_source_shape_only",
        "match_count": len(matched),
        "matches": matched[: max(0, limit)],
        "truncated": len(matched) > max(0, limit),
    }


def _result_accounting(results: list[dict[str, Any]]) -> dict[str, Any]:
    by_collection: dict[str, int] = {}
    by_shape: dict[str, int] = {}
    by_lane: dict[str, int] = {}
    zero_match = 0
    matched_queries = 0
    for result in results:
        collection = str(result.get("source_collection") or "unknown")
        shape = str(result.get("query_shape") or "unknown")
        lane = str(result.get("action_lane") or "unknown")
        by_collection[collection] = by_collection.get(collection, 0) + 1
        by_shape[shape] = by_shape.get(shape, 0) + 1
        by_lane[lane] = by_lane.get(lane, 0) + 1
        if int(result.get("match_count") or 0) > 0:
            matched_queries += 1
        else:
            zero_match += 1
    return {
        "query_count_by_collection": by_collection,
        "query_count_by_shape": by_shape,
        "query_count_by_action_lane": by_lane,
        "matched_query_count": matched_queries,
        "zero_match_query_count": zero_match,
    }


def _task_specs(worklist: dict[str, Any], task_ids: set[str]) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    out: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for task in worklist.get("tasks", []):
        if not isinstance(task, dict):
            continue
        task_id = str(task.get("task_id") or "")
        if task_ids and task_id not in task_ids:
            continue
        spec = task.get("detector_query_bridge")
        if isinstance(spec, dict) and spec.get("backend") == "semantic_graph_query":
            out.append((task, spec))
    return out


def _impact_worklist_specs(payload: dict[str, Any], task_ids: set[str]) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    out: list[tuple[dict[str, Any], dict[str, Any]]] = []
    rows = payload.get("worklists") if isinstance(payload.get("worklists"), list) else []
    for row in rows:
        if not isinstance(row, dict):
            continue
        handoff = row.get("source_review_handoff") if isinstance(row.get("source_review_handoff"), dict) else {}
        routes = handoff.get("routes") if isinstance(handoff.get("routes"), list) else []
        for route in routes:
            if not isinstance(route, dict) or route.get("route_kind") != "semantic_graph_query":
                continue
            route_id = str(route.get("route_id") or "")
            if task_ids and route_id not in task_ids:
                continue
            spec = route.get("semantic_graph_query")
            if not isinstance(spec, dict) or spec.get("backend") != "semantic_graph_query":
                continue
            if spec.get("source_collection") not in {"relation_edges", "multi_hop_paths"}:
                continue
            task = {
                "task_id": route_id,
                "source_id": row.get("impact_id", ""),
                "candidate_detector_family": row.get("impact_family", ""),
                "impact_id": row.get("impact_id", ""),
                "impact_family": row.get("impact_family", ""),
                "route_id": route_id,
                "route_kind": route.get("route_kind", ""),
                "component_id": route.get("component_id", ""),
                "source_artifact_kind": "impact_family_worklist",
            }
            out.append((task, spec))
    return out


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Semantic Graph Query Results",
        "",
        "Advisory source-shape matches from `semantic_graph_query` specs.",
        "These rows are not findings, severity approvals, PoCs, or submit-ready candidates.",
        "",
        f"- schema: `{payload['schema']}`",
        f"- source mode: `{payload.get('source_mode', 'semantic_detector_worklist')}`",
        f"- query count: {payload['query_count']}",
        f"- matched rows: {payload['matched_row_count']}",
        f"- impact worklist rows: {payload.get('impact_worklist_row_count', 0)}",
        f"- coverage claim: `{payload['coverage_claim']}`",
        f"- submission posture: `{payload['submission_posture']}`",
        f"- matched queries: {payload.get('query_accounting', {}).get('matched_query_count', 0)}",
        f"- zero-match queries: {payload.get('query_accounting', {}).get('zero_match_query_count', 0)}",
        "",
        "## Source-Shape Limitations",
        "",
    ]
    for limitation in payload.get("source_shape_limitations", []):
        lines.append(f"- {limitation}")
    lines.extend([
        "",
        "## Results",
        "",
        "| Task | Shape | Lane | Collection | Matches | Posture |",
        "|---|---|---|---|---|---|",
    ]
    )
    for result in payload.get("results", []):
        lines.append(
            "| `{}` | `{}` | `{}` | `{}` | {} | `{}` |".format(
                result.get("task_id", ""),
                result.get("query_shape", ""),
                result.get("action_lane", ""),
                result.get("source_collection", ""),
                result.get("match_count", 0),
                result.get("submission_posture", ""),
            )
        )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--graph", type=Path)
    parser.add_argument("--worklist", type=Path)
    parser.add_argument(
        "--impact-worklist",
        type=Path,
        help="Execute semantic_graph_query routes from impact_family_worklists.json instead of semantic_detector_worklist.json.",
    )
    parser.add_argument("--query-json", type=Path, help="Execute one standalone semantic_graph_query spec JSON.")
    parser.add_argument("--task-id", action="append", default=[], help="Limit worklist execution to one task id; repeatable.")
    parser.add_argument("--limit", type=int, default=50, help="Maximum matched rows stored per query.")
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-md", type=Path)
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args()

    workspace = args.workspace.expanduser().resolve()
    if not workspace.is_dir():
        print(f"[semantic-graph-query] workspace not found: {workspace}", file=sys.stderr)
        return 2
    graph_path = (args.graph or workspace / ".auditooor" / "semantic_graph.json").expanduser().resolve()
    graph = _load_json(graph_path)
    task_specs: list[tuple[dict[str, Any], dict[str, Any]]]
    source_artifact = ""
    source_mode = "semantic_detector_worklist"
    impact_worklist_row_count = 0
    if args.query_json:
        spec_path = args.query_json.expanduser().resolve()
        task_specs = [({}, _load_json(spec_path))]
        source_artifact = str(spec_path)
        source_mode = "standalone_query_json"
    elif args.impact_worklist:
        impact_worklist_path = args.impact_worklist.expanduser().resolve()
        impact_worklist = _load_json(impact_worklist_path)
        rows = impact_worklist.get("worklists") if isinstance(impact_worklist.get("worklists"), list) else []
        impact_worklist_row_count = len([row for row in rows if isinstance(row, dict)])
        task_specs = _impact_worklist_specs(impact_worklist, set(args.task_id))
        source_artifact = str(impact_worklist_path)
        source_mode = "impact_family_worklist"
    else:
        worklist_path = (args.worklist or workspace / ".auditooor" / "semantic_detector_worklist.json").expanduser().resolve()
        worklist = _load_json(worklist_path)
        task_specs = _task_specs(worklist, set(args.task_id))
        source_artifact = str(worklist_path)
    results: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    for task, spec in task_specs:
        try:
            results.append(execute_spec(graph, spec, task=task, limit=max(0, args.limit)))
        except ValueError as exc:
            errors.append({"task_id": str(task.get("task_id") or ""), "error": str(exc)})
    accounting = _result_accounting(results)
    payload = {
        "schema": SCHEMA_VERSION,
        "workspace": str(workspace),
        "graph_artifact": str(graph_path),
        "source_artifact": source_artifact,
        "source_mode": source_mode,
        "impact_worklist_row_count": impact_worklist_row_count,
        "query_count": len(results),
        "error_count": len(errors),
        "matched_row_count": sum(int(result.get("match_count") or 0) for result in results),
        "query_accounting": accounting,
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
        "results": results,
        "errors": errors,
        "next_actions": [
            "Review matched rows for detectorizability only.",
            "Keep rows marked source/invariant-only when no static predicate is credible.",
            "Require exact impact contract, vulnerable/clean fixtures, and smoke output before promotion.",
        ],
    }
    out_json = args.out_json or (workspace / ".auditooor" / "semantic_graph_query_results.json")
    out_md = args.out_md or (workspace / ".auditooor" / "semantic_graph_query_results.md")
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(payload), encoding="utf-8")
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    print(
        f"[semantic-graph-query] OK queries={payload['query_count']} matches={payload['matched_row_count']} json={out_json}",
        file=sys.stderr,
    )
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
