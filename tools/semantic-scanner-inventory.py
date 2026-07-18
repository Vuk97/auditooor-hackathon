#!/usr/bin/env python3
"""Build a scanner-facing inventory from semantic graph detector artifacts.

This is a PR560 bridge between function/cross-contract source-shape mapping
and detector/coverage planning. It intentionally does not run detectors or
promote findings. It records which semantic functions/relations already have
worklist, query, or adjudication routes, and which remain coverage-only rows.
It also normalizes those rows into a concrete detector/fixture/source-review
task queue so scanner owners can pick bounded local follow-up work without
mistaking source-shape inventory for proof.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SEMANTIC_GRAPH = ROOT / "tools" / "semantic-graph.py"
SCHEMA_VERSION = "auditooor.semantic_scanner_inventory.v1"
SOURCE_SHAPE_LIMITATIONS = [
    "inventory rows are derived from semantic graph source-shape artifacts only",
    "the bridge does not run scanners, detectors, fixtures, or smoke tests",
    "function/cross-contract mappings are not compiler-backed callgraph, value-flow, delegatecall, or deployment proof",
    "coverage rows do not imply detector coverage until a detector predicate, vulnerable fixture, clean fixture, and smoke output exist",
    "all rows remain NOT_SUBMIT_READY with severity none until exact impact proof and execution artifacts exist",
]


def _slug(value: str, fallback: str = "row") -> str:
    out = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return out or fallback


def _load_json(path: Path, label: str, *, required: bool = False) -> dict[str, Any]:
    if not path.is_file():
        if required:
            raise SystemExit(f"[semantic-scanner-inventory] missing {label}: {path}")
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise SystemExit(f"[semantic-scanner-inventory] unreadable {label}: {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit(f"[semantic-scanner-inventory] expected object JSON for {label}: {path}")
    return payload


def _ensure_graph(workspace: Path, graph_path: Path, *, generate: bool) -> None:
    if graph_path.is_file() or not generate:
        return
    subprocess.run(
        [sys.executable, str(SEMANTIC_GRAPH), "--workspace", str(workspace)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def _component(contract: Any, function: Any) -> str:
    return "{}.{}".format(contract or "", function or "").strip(".")


def _task_index(worklist: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(task.get("task_id") or ""): task
        for task in (worklist.get("tasks") or [])
        if isinstance(task, dict) and str(task.get("task_id") or "")
    }


def _query_index(query_results: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(result.get("task_id") or result.get("route_id") or ""): result
        for result in (query_results.get("results") or [])
        if isinstance(result, dict) and str(result.get("task_id") or result.get("route_id") or "")
    }


def _adjudication_index(adjudication: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    for key in ("detector_rewrite_briefs", "fixture_requirements", "non_detectorizable_rows", "action_items"):
        for row in (adjudication.get(key) or []):
            if not isinstance(row, dict):
                continue
            task_id = str(row.get("task_id") or "")
            if task_id:
                out.setdefault(task_id, []).append(row)
    return out


def _relation_key(edge: dict[str, Any]) -> str:
    return "{}:{}:{}:{}".format(
        _component(edge.get("source_contract"), edge.get("source_function")),
        edge.get("kind", ""),
        edge.get("method", ""),
        edge.get("line", 0),
    )


def _graph_indexes(graph: dict[str, Any]) -> tuple[dict[str, dict[str, Any]], dict[str, list[dict[str, Any]]], dict[str, list[dict[str, Any]]]]:
    entrypoints = {
        _component(row.get("contract"), row.get("function")): row
        for row in (graph.get("entrypoints") or [])
        if isinstance(row, dict) and _component(row.get("contract"), row.get("function"))
    }
    relation_by_component: dict[str, list[dict[str, Any]]] = {}
    for edge in (graph.get("relation_edges") or []):
        if not isinstance(edge, dict):
            continue
        relation_by_component.setdefault(
            _component(edge.get("source_contract"), edge.get("source_function")),
            [],
        ).append(edge)
    mh_by_component: dict[str, list[dict[str, Any]]] = {}
    for path in (graph.get("multi_hop_paths") or []):
        if not isinstance(path, dict):
            continue
        mh_by_component.setdefault(str(path.get("source_component") or ""), []).append(path)
    return entrypoints, relation_by_component, mh_by_component


def _route_status(task_id: str, query: dict[str, Any], adj_rows: list[dict[str, Any]]) -> str:
    adjudications = {str(row.get("adjudication") or row.get("action_type") or "") for row in adj_rows}
    if "detector_rewrite_brief" in adjudications:
        return "detector_rewrite_brief"
    if "fixture_requirement" in adjudications:
        return "fixture_requirement"
    if "non_detectorizable" in adjudications:
        return "source_review_or_kill"
    if query:
        if str(query.get("query_status") or "") != "executed":
            return "query_not_executed"
        return "query_matched" if int(query.get("match_count") or 0) > 0 else "query_zero_match"
    if task_id:
        return "worklist_unqueried"
    return "coverage_only_unrouted"


def _detector_slug(item: dict[str, Any]) -> str:
    family = str(item.get("candidate_detector_family") or item.get("relation_kind") or "semantic")
    source = str(item.get("source_component") or item.get("source_id") or item.get("inventory_id") or "row")
    method = str(item.get("method") or item.get("query_shape") or "")
    return _slug("_".join(part for part in (family, source, method) if part), "semantic-detector").replace("-", "_")


def _queue_task_type(status: str, item_kind: str) -> str:
    if status in {"detector_task_routed", "detector_rewrite_brief"}:
        return "detector_rewrite_with_fixture_pair"
    if status == "fixture_requirement":
        return "fixture_pair_before_detector_rewrite"
    if status in {"source_review_or_kill", "query_zero_match", "query_not_executed"}:
        return "source_review_or_kill_note"
    if item_kind.startswith("raw_relation") or "relation" in status or "multihop" in status:
        return "coverage_to_detector_worklist"
    return "coverage_inventory_review"


def _queue_item(idx: int, item: dict[str, Any], workspace: Path) -> dict[str, Any]:
    status = str(item.get("scanner_inventory_status") or "")
    item_kind = str(item.get("item_kind") or "")
    task_type = _queue_task_type(status, item_kind)
    detector_slug = _detector_slug(item)
    fixture_id = f"SSI-FIX-{idx:03d}"
    if task_type in {"detector_rewrite_with_fixture_pair", "fixture_pair_before_detector_rewrite"}:
        next_command = (
            f"make semantic-scanner-inventory WS={workspace} "
            f"# implement detector {detector_slug} with {fixture_id} positive/clean fixtures, then run detector smoke"
        )
    elif task_type == "coverage_to_detector_worklist":
        next_command = f"make semantic-detector-worklist WS={workspace}"
    else:
        next_command = (
            f"make semantic-scanner-inventory WS={workspace} "
            f"# record source-review/kill note for {item.get('inventory_id', '')}"
        )
    return {
        "queue_id": f"SSI-Q-{idx:03d}",
        "inventory_id": item.get("inventory_id", ""),
        "task_type": task_type,
        "source_inventory_kind": item_kind,
        "scanner_inventory_status": status,
        "source_component": item.get("source_component", ""),
        "target_component": item.get("target_component", ""),
        "query_shape": item.get("query_shape", item.get("relation_kind", "")),
        "source_collection": item.get("source_collection", ""),
        "action_lane": item.get("action_lane", ""),
        "candidate_detector_family": item.get("candidate_detector_family", ""),
        "suggested_detector_slug": detector_slug if task_type.startswith("detector") else "",
        "fixture_task": {
            "fixture_id": fixture_id,
            "positive_fixture_path": f"detectors/fixtures/{detector_slug}/{fixture_id.lower()}_positive.sol",
            "clean_fixture_path": f"detectors/fixtures/{detector_slug}/{fixture_id.lower()}_clean.sol",
            "smoke_record_path": f"detectors/fixtures/{detector_slug}/{fixture_id.lower()}_smoke.json",
        } if task_type in {"detector_rewrite_with_fixture_pair", "fixture_pair_before_detector_rewrite"} else {},
        "required_artifacts": [
            "detector predicate diff" if task_type.startswith("detector") else "coverage/source-review decision note",
            "positive fixture" if task_type in {"detector_rewrite_with_fixture_pair", "fixture_pair_before_detector_rewrite"} else "narrower detectorizable source-shape predicate if available",
            "clean fixture" if task_type in {"detector_rewrite_with_fixture_pair", "fixture_pair_before_detector_rewrite"} else "kill/reframe rationale if non-detectorizable",
            "detector smoke output" if task_type.startswith("detector") else "refreshed semantic scanner inventory",
            "exact impact contract before harness/report work",
        ],
        "promotion_blockers": [
            "source-shape evidence only",
            "vulnerable fixture missing",
            "clean fixture missing",
            "detector smoke output missing",
            "exact impact contract missing",
        ],
        "next_command": next_command,
        "coverage_claim": "none_source_shape_only",
        "advisory_only": True,
        "promotion_allowed": False,
        "severity": "none",
        "selected_impact": "",
        "submission_posture": "NOT_SUBMIT_READY",
        "impact_contract_required": True,
        "source_shape_limitations": SOURCE_SHAPE_LIMITATIONS,
    }


def _task_item(
    *,
    idx: int,
    task: dict[str, Any],
    query: dict[str, Any],
    adj_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    bridge = task.get("detector_query_bridge") if isinstance(task.get("detector_query_bridge"), dict) else {}
    task_id = str(task.get("task_id") or "")
    status = _route_status(task_id, query, adj_rows)
    next_commands = sorted({
        str(row.get("next_command") or "")
        for row in adj_rows
        if isinstance(row, dict) and str(row.get("next_command") or "")
    })
    return {
        "inventory_id": f"SSI-{idx:03d}",
        "item_kind": "semantic_detector_route",
        "task_id": task_id,
        "source_kind": task.get("source_kind", ""),
        "source_id": task.get("source_id", ""),
        "source_component": task.get("source_component", ""),
        "target_component": task.get("target_component", task.get("sink_component", "")),
        "relation_kind": task.get("relation_kind", ""),
        "method": task.get("method", ""),
        "file": task.get("file", ""),
        "line": task.get("line", 0),
        "candidate_detector_family": task.get("candidate_detector_family", ""),
        "query_shape": bridge.get("query_shape", query.get("query_shape", "")),
        "source_collection": bridge.get("source_collection", query.get("source_collection", "")),
        "action_lane": task.get("action_lane", query.get("action_lane", "")),
        "detectorization_readiness": task.get("detectorization_readiness", query.get("detectorization_readiness", "")),
        "query_match_count": int(query.get("match_count") or 0) if query else 0,
        "route_status": status,
        "scanner_inventory_status": (
            "detector_task_routed"
            if status in {"detector_rewrite_brief", "fixture_requirement", "query_matched"}
            else status
        ),
        "terminal_decision_required": task.get("required_terminal_decision", []),
        "required_next_artifacts": task.get("required_next_artifacts", []),
        "next_commands": next_commands[:3],
        "coverage_claim": "none_source_shape_only",
        "advisory_only": True,
        "promotion_allowed": False,
        "severity": "none",
        "selected_impact": "",
        "submission_posture": "NOT_SUBMIT_READY",
        "impact_contract_required": True,
        "source_shape_limitations": SOURCE_SHAPE_LIMITATIONS,
    }


def _coverage_item(
    *,
    idx: int,
    component: str,
    entrypoint: dict[str, Any],
    relation_edges: list[dict[str, Any]],
    multi_hop_paths: list[dict[str, Any]],
    routed_task_ids: list[str],
) -> dict[str, Any]:
    if routed_task_ids:
        status = "covered_by_semantic_detector_task"
    elif multi_hop_paths:
        status = "coverage_only_multihop_unrouted"
    elif relation_edges:
        status = "coverage_only_relation_unrouted"
    else:
        status = "coverage_only_no_cross_contract_mapping"
    return {
        "inventory_id": f"SSI-{idx:03d}",
        "item_kind": "function_coverage_inventory",
        "source_component": component,
        "file": entrypoint.get("file", ""),
        "line": entrypoint.get("line", 0),
        "visibility": entrypoint.get("visibility", ""),
        "role": entrypoint.get("role", ""),
        "privileged": bool(entrypoint.get("privileged")),
        "state_write_count": len(entrypoint.get("state_writes") or []),
        "external_call_count": len(entrypoint.get("external_calls") or []),
        "value_movement": bool(entrypoint.get("value_movement")),
        "relation_edge_count": len(relation_edges),
        "multi_hop_path_count": len(multi_hop_paths),
        "relation_kinds": sorted({str(edge.get("kind") or "") for edge in relation_edges if edge.get("kind")}),
        "multi_hop_families": sorted({str(row.get("impact_family") or "") for row in multi_hop_paths if row.get("impact_family")}),
        "routed_task_ids": routed_task_ids,
        "scanner_inventory_status": status,
        "recommended_next_command": (
            "make semantic-detector-worklist WS=<workspace>"
            if status.startswith("coverage_only")
            else "make semantic-graph-query WS=<workspace> && make semantic-detector-adjudication WS=<workspace>"
        ),
        "coverage_claim": "none_source_shape_only",
        "advisory_only": True,
        "promotion_allowed": False,
        "severity": "none",
        "selected_impact": "",
        "submission_posture": "NOT_SUBMIT_READY",
        "impact_contract_required": True,
        "source_shape_limitations": SOURCE_SHAPE_LIMITATIONS,
    }


def build_inventory(
    workspace: Path,
    graph: dict[str, Any],
    worklist: dict[str, Any],
    query_results: dict[str, Any],
    adjudication: dict[str, Any],
    *,
    limit: int = 50,
) -> dict[str, Any]:
    task_by_id = _task_index(worklist)
    query_by_id = _query_index(query_results)
    adj_by_id = _adjudication_index(adjudication)
    entrypoints, relation_by_component, mh_by_component = _graph_indexes(graph)
    task_ids_by_component: dict[str, list[str]] = {}
    items: list[dict[str, Any]] = []
    known_relation_keys: set[str] = set()

    for task_id, task in sorted(task_by_id.items()):
        if len(items) >= limit:
            break
        component = str(task.get("source_component") or "")
        if component:
            task_ids_by_component.setdefault(component, []).append(task_id)
        items.append(_task_item(
            idx=len(items) + 1,
            task=task,
            query=query_by_id.get(task_id, {}),
            adj_rows=adj_by_id.get(task_id, []),
        ))

    for component, entrypoint in sorted(entrypoints.items()):
        if len(items) >= limit:
            break
        if component in task_ids_by_component:
            continue
        rels = relation_by_component.get(component, [])
        mhs = mh_by_component.get(component, [])
        if not rels and not mhs:
            continue
        items.append(_coverage_item(
            idx=len(items) + 1,
            component=component,
            entrypoint=entrypoint,
            relation_edges=rels,
            multi_hop_paths=mhs,
            routed_task_ids=[],
        ))

    # If no worklist exists yet, still expose raw relation edges as concrete
    # scanner-planning rows rather than pretending coverage is empty.
    raw_relation_edges = graph.get("relation_edges") or []
    if task_by_id:
        raw_relation_edges = []
    for edge in raw_relation_edges:
        if len(items) >= limit:
            break
        if not isinstance(edge, dict):
            continue
        key = _relation_key(edge)
        if key in known_relation_keys:
            continue
        known_relation_keys.add(key)
        component = _component(edge.get("source_contract"), edge.get("source_function"))
        items.append({
            "inventory_id": f"SSI-{len(items) + 1:03d}",
            "item_kind": "raw_relation_coverage_inventory",
            "source_component": component,
            "target_component": edge.get("target") or "",
            "relation_kind": edge.get("kind", ""),
            "method": edge.get("method", ""),
            "file": edge.get("file", ""),
            "line": edge.get("line", 0),
            "scanner_inventory_status": "coverage_only_relation_unrouted",
            "recommended_next_command": "make semantic-detector-worklist WS=<workspace>",
            "coverage_claim": "none_source_shape_only",
            "advisory_only": True,
            "promotion_allowed": False,
            "severity": "none",
            "selected_impact": "",
            "submission_posture": "NOT_SUBMIT_READY",
            "impact_contract_required": True,
            "source_shape_limitations": SOURCE_SHAPE_LIMITATIONS,
        })

    status_counts: dict[str, int] = {}
    kind_counts: dict[str, int] = {}
    for item in items:
        status = str(item.get("scanner_inventory_status") or "unknown")
        kind = str(item.get("item_kind") or "unknown")
        status_counts[status] = status_counts.get(status, 0) + 1
        kind_counts[kind] = kind_counts.get(kind, 0) + 1
    task_queue = [_queue_item(idx, item, workspace) for idx, item in enumerate(items, start=1)]
    task_type_counts: dict[str, int] = {}
    for row in task_queue:
        task_type = str(row.get("task_type") or "unknown")
        task_type_counts[task_type] = task_type_counts.get(task_type, 0) + 1
    function_count = len(entrypoints)
    routed_components = len(task_ids_by_component)
    return {
        "schema": SCHEMA_VERSION,
        "workspace": str(workspace),
        "source_artifacts": {
            "semantic_graph": str(workspace / ".auditooor" / "semantic_graph.json"),
            "semantic_detector_worklist": str(workspace / ".auditooor" / "semantic_detector_worklist.json"),
            "semantic_graph_query_results": str(workspace / ".auditooor" / "semantic_graph_query_results.json"),
            "semantic_detector_adjudication": str(workspace / ".auditooor" / "semantic_detector_adjudication.json"),
        },
        "coverage_claim": "none_source_shape_only",
        "advisory_only": True,
        "promotion_allowed": False,
        "severity": "none",
        "selected_impact": "",
        "submission_posture": "NOT_SUBMIT_READY",
        "impact_contract_required": True,
        "source_shape_limitations": SOURCE_SHAPE_LIMITATIONS,
        "limit": limit,
        "item_count": len(items),
        "task_queue_count": len(task_queue),
        "truncated": (
            len(task_by_id) + len(graph.get("relation_edges") or []) + len(graph.get("multi_hop_paths") or [])
        ) > limit,
        "scanner_inventory_status_counts": status_counts,
        "item_kind_counts": kind_counts,
        "task_queue_type_counts": task_type_counts,
        "function_coverage_summary": {
            "entrypoint_count": function_count,
            "function_with_relation_edges_count": len(relation_by_component),
            "function_with_multi_hop_paths_count": len(mh_by_component),
            "function_with_detector_task_count": routed_components,
            "function_without_detector_task_but_with_mapping_count": len(
                {
                    *relation_by_component.keys(),
                    *mh_by_component.keys(),
                }
                - set(task_ids_by_component.keys())
            ),
        },
        "mechanical_bridge": [
            "semantic_graph entrypoints/relation_edges/multi_hop_paths",
            "semantic_detector_worklist detector/source-invariant routes",
            "semantic_graph_query executed match accounting",
            "semantic_detector_adjudication detector/fixture/source-only decisions",
            "semantic_scanner_inventory bounded scanner-facing coverage/action rows",
        ],
        "items": items,
        "detector_fixture_task_queue": task_queue,
        "next_actions": [
            "Run semantic-detector-worklist when relation/multi-hop rows are still coverage-only.",
            "Run semantic-graph-query and semantic-detector-adjudication before assigning detector rewrite work.",
            "Run semantic-fixture-smoke-gate with STRICT=1 before treating detector/fixture rows as implemented.",
            "Promote only rows with paired vulnerable/clean fixtures and detector smoke output; keep impact proof separate.",
        ],
    }


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Semantic Scanner Inventory",
        "",
        "Bounded scanner-facing inventory for semantic function and cross-contract source-shape mappings.",
        "Rows are planning/coverage input only, not detector proof or submission evidence.",
        "",
        f"- schema: `{payload['schema']}`",
        f"- item count: {payload['item_count']}",
        f"- detector/fixture task queue count: {payload.get('task_queue_count', 0)}",
        f"- limit: {payload['limit']}",
        f"- truncated: `{str(payload['truncated']).lower()}`",
        f"- coverage claim: `{payload['coverage_claim']}`",
        f"- submission posture: `{payload['submission_posture']}`",
        "",
        "## Source-Shape Limitations",
        "",
    ]
    for limitation in payload.get("source_shape_limitations", []):
        lines.append(f"- {limitation}")
    lines.extend(["", "## Status Counts", ""])
    for status, count in sorted((payload.get("scanner_inventory_status_counts") or {}).items()):
        lines.append(f"- `{status}`: {count}")
    lines.extend(["", "## Detector/Fixture Task Queue", ""])
    queue = payload.get("detector_fixture_task_queue") if isinstance(payload.get("detector_fixture_task_queue"), list) else []
    if not queue:
        lines.append("_No detector/fixture task rows were generated._")
    else:
        lines.extend([
            "| Queue | Task Type | Inventory | Source | Detector | Posture | Next command |",
            "|---|---|---|---|---|---|---|",
        ])
        for row in queue:
            lines.append("| `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` |".format(
                row.get("queue_id", ""),
                row.get("task_type", ""),
                row.get("inventory_id", ""),
                row.get("source_component", ""),
                row.get("suggested_detector_slug", ""),
                row.get("submission_posture", ""),
                row.get("next_command", ""),
            ))
    lines.extend([
        "",
        "## Items",
        "",
        "| ID | Kind | Status | Source | Target | Shape | Lane | Query Matches |",
        "|---|---|---|---|---|---|---|---:|",
    ])
    for item in payload.get("items", []):
        lines.append("| `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | {} |".format(
            item.get("inventory_id", ""),
            item.get("item_kind", ""),
            item.get("scanner_inventory_status", ""),
            item.get("source_component", ""),
            item.get("target_component", ""),
            item.get("query_shape", item.get("relation_kind", "")),
            item.get("action_lane", ""),
            item.get("query_match_count", 0),
        ))
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--graph", type=Path)
    parser.add_argument("--worklist", type=Path)
    parser.add_argument("--query-results", type=Path)
    parser.add_argument("--adjudication", type=Path)
    parser.add_argument("--limit", type=int, default=50)
    parser.add_argument("--generate-graph", action="store_true")
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-md", type=Path)
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args()

    workspace = args.workspace.expanduser().resolve()
    if not workspace.is_dir():
        print(f"[semantic-scanner-inventory] workspace not found: {workspace}", file=sys.stderr)
        return 2
    graph_path = (args.graph or workspace / ".auditooor" / "semantic_graph.json").expanduser().resolve()
    _ensure_graph(workspace, graph_path, generate=args.generate_graph)
    graph = _load_json(graph_path, "semantic graph", required=True)
    worklist = _load_json((args.worklist or workspace / ".auditooor" / "semantic_detector_worklist.json").expanduser().resolve(), "semantic detector worklist")
    query_results = _load_json((args.query_results or workspace / ".auditooor" / "semantic_graph_query_results.json").expanduser().resolve(), "semantic graph query results")
    adjudication = _load_json((args.adjudication or workspace / ".auditooor" / "semantic_detector_adjudication.json").expanduser().resolve(), "semantic detector adjudication")
    payload = build_inventory(
        workspace,
        graph,
        worklist,
        query_results,
        adjudication,
        limit=max(0, args.limit),
    )
    out_json = args.out_json or (workspace / ".auditooor" / "semantic_scanner_inventory.json")
    out_md = args.out_md or (workspace / ".auditooor" / "semantic_scanner_inventory.md")
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(payload), encoding="utf-8")
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    print(
        f"[semantic-scanner-inventory] OK items={payload['item_count']} json={out_json}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
