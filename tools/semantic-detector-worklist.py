#!/usr/bin/env python3
"""Build advisory detector-rewrite tasks from semantic graph path inventory.

This is a narrow PR560 bridge: it turns semantic graph relation edges and
multi-hop paths into machine-readable detector worklist rows. It does not
generate detectors, rank severity, or mark anything submit-ready.
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
SCHEMA_VERSION = "auditooor.semantic_detector_worklist.v1"
SOURCE_SHAPE_LIMITATIONS = [
    "semantic graph rows are syntactic/source-shape evidence only",
    "no compiler-backed callgraph fixpoint is proven",
    "no value-flow, role reachability, or runtime deployment proof is proven",
    "no severity, selected impact, PoC posture, or submission readiness may be inferred",
]


def _slug(value: str, fallback: str = "unknown") -> str:
    out = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return out or fallback


def _load_graph(workspace: Path, *, generate: bool) -> dict[str, Any]:
    path = workspace / ".auditooor" / "semantic_graph.json"
    if not path.is_file() and generate:
        subprocess.run(
            [sys.executable, str(SEMANTIC_GRAPH), "--workspace", str(workspace)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SystemExit(
            f"[semantic-detector-worklist] semantic graph missing: {path}; "
            "run `make semantic-graph WS=<workspace>` first or pass --generate-graph"
        ) from exc
    except (json.JSONDecodeError, OSError) as exc:
        raise SystemExit(f"[semantic-detector-worklist] unreadable semantic graph: {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit(f"[semantic-detector-worklist] malformed semantic graph: {path}")
    return payload


def _relation_family(edge: dict[str, Any]) -> str:
    kind = str(edge.get("kind") or "relation-edge")
    method = str(edge.get("method") or "")
    target = str(edge.get("target") or "")
    haystack = f"{kind} {method} {target}".lower()
    if "proxy" in haystack or "clone" in haystack or "implementation" in haystack:
        return "factory_proxy_relation"
    if re.search(r'\b(verif|proof)\w*', haystack):  # r36-rebuttal: bugfix-inventory-claude-20260610
        return "verifier_relation"
    if "registry" in haystack or "register" in haystack:
        return "registry_relation"
    if "oracle" in haystack or "price" in haystack or "root" in haystack:
        return "oracle_or_root_relation"
    return _slug(kind, "relation_edge").replace("-", "_")


def _relation_query_shape(edge: dict[str, Any], family: str) -> dict[str, Any]:
    """Return a deterministic advisory query spec for detector triage.

    The spec is intentionally phrased as a source-shape query against
    semantic_graph relation rows. It is not a finding, severity signal, or
    proof that a detector should exist.
    """
    kind = str(edge.get("kind") or "")
    receiver_source = str(edge.get("receiver_source") or "")
    target_type = str(edge.get("target_type") or "")
    method = str(edge.get("method") or "")
    receiver = str(edge.get("receiver") or edge.get("target") or "")
    base = {
        "backend": "semantic_graph_query",
        "advisory_only": True,
        "coverage_claim": "none_source_shape_only",
        "query_status": "candidate_spec",
        "source_collection": "relation_edges",
        "match_fields": {
            "kind": kind,
            "receiver_source": receiver_source,
            "target_type": target_type,
            "method": method,
            "receiver": receiver,
        },
        "required_output_fields": [
            "file",
            "line",
            "source_contract",
            "source_function",
            "kind",
            "receiver",
            "target_type",
            "method",
            "evidence",
        ],
        "promotion_blockers": [
            "requires vulnerable fixture",
            "requires clean fixture",
            "requires detector smoke output",
            "requires exact impact contract before any report or harness work",
        ],
        "source_shape_limitations": SOURCE_SHAPE_LIMITATIONS,
    }
    if family == "factory_proxy_relation":
        base.update({
            "query_shape": "factory_proxy_or_clone_relation",
            "must_match_any": [
                {"kind": "proxy-deploy"},
                {"kind": "clone-deploy"},
                {"target_regex": "(?i)(proxy|implementation|clone)"},
            ],
            "fixture_tags": ["factory", "proxy", "clone"],
        })
    elif family == "verifier_relation":
        base.update({
            "query_shape": "verifier_adapter_relation",
            "must_match_any": [
                {"kind": "verifier-adapter-call"},
                {"target_or_method_regex": "(?i)(verif|proof|attestation|signature)"},
            ],
            "fixture_tags": ["verifier", "proof", "adapter"],
        })
    elif family == "registry_relation":
        base.update({
            "query_shape": "registry_write_relation",
            "must_match_any": [
                {"kind": "registry-write"},
                {"receiver_or_method_regex": "(?i)(registry|register|mark|set)"},
            ],
            "fixture_tags": ["registry", "write", "configuration"],
        })
    elif family == "oracle_or_root_relation":
        base.update({
            "query_shape": "oracle_or_root_relation",
            "must_match_any": [
                {"target_or_method_regex": "(?i)(oracle|price|root|claim)"},
                {"evidence_regex": "(?i)(oracle|price|stateRoot|outputRoot|rootClaim)"},
            ],
            "fixture_tags": ["oracle", "root", "validation"],
        })
    else:
        base.update({
            "query_shape": "generic_typed_relation",
            "must_match_any": [
                {"target_type_present": True},
                {"receiver_source_present": True},
            ],
            "fixture_tags": ["relation", "typed-receiver"],
        })
    return base


def _multihop_query_shape(path_row: dict[str, Any], family: str) -> dict[str, Any]:
    mapped = [
        str(stage)
        for stage in (path_row.get("mapped_stages") or [])
        if stage
    ]
    required = [stage for stage in ("caller", "validation") if stage in mapped]
    if family in {"bridge_finalization", "proof_dispute", "proof_finalization"}:
        required.extend([
            stage
            for stage in ("parser", "state_root", "proof_dispute_bridge_finalization")
            if stage in mapped
        ])
        query_shape = "bridge_or_proof_finalization_path"
        fixture_tags = ["bridge", "proof", "finalization"]
    elif family == "state_root_validation":
        required.extend([stage for stage in ("parser", "state_root") if stage in mapped])
        query_shape = "state_root_validation_path"
        fixture_tags = ["state-root", "validation"]
    elif family == "validation_path":
        query_shape = "external_validation_path"
        fixture_tags = ["validation", "entrypoint"]
    else:
        query_shape = "generic_multihop_source_path"
        fixture_tags = ["multihop", "source-shape"]
    return {
        "backend": "semantic_graph_query",
        "advisory_only": True,
        "coverage_claim": "none_source_shape_only",
        "query_status": "candidate_spec",
        "source_collection": "multi_hop_paths",
        "query_shape": query_shape,
        "match_fields": {
            "impact_family": family,
            "mapped_stages": mapped,
            "source_component": path_row.get("source_component", ""),
            "sink_component": path_row.get("sink_component", ""),
        },
        "required_stages": required,
        "required_output_fields": [
            "path_id",
            "impact_family",
            "source_component",
            "sink_component",
            "mapped_stages",
            "missing_stages",
            "evidence_edges",
        ],
        "fixture_tags": fixture_tags,
        "promotion_blockers": [
            "requires vulnerable fixture",
            "requires clean fixture",
            "requires detector smoke output",
            "requires exact impact contract before any report or harness work",
        ],
        "source_shape_limitations": SOURCE_SHAPE_LIMITATIONS,
    }


def _task_common(task_id: str, source_kind: str, source_id: str, family: str) -> dict[str, Any]:
    return {
        "task_id": task_id,
        "source_kind": source_kind,
        "source_id": source_id,
        "candidate_detector_family": family,
        "detector_task_status": "advisory_untriaged",
        "terminal_state": "open_advisory",
        "submission_posture": "NOT_SUBMIT_READY",
        "submit_status": "NOT_SUBMIT_READY",
        "severity": "none",
        "severity_claim": "none",
        "selected_impact": "",
        "impact_contract_id": "",
        "impact_contract_required": True,
        "advisory_only": True,
        "promotion_allowed": False,
        "detector_query_bridge": {},
        "source_shape_limitations": SOURCE_SHAPE_LIMITATIONS,
        "acceptance_criteria": [
            "rewrite or add a detector predicate only if the row is statically checkable",
            "add vulnerable and clean fixtures before detector promotion",
            "run detector smoke tests and record output",
            "keep any report/harness work blocked until an exact impact contract and proof exist",
        ],
        "required_terminal_decision": [
            "detectorizable_with_vulnerable_and_clean_fixtures",
            "fixture_first_before_detector_rewrite",
            "source_review_or_invariant_only",
            "kill_or_reframe_as_non_detectorizable",
        ],
    }


def _proof_task_common(task_id: str, source_id: str, family: str) -> dict[str, Any]:
    return {
        "task_id": task_id,
        "source_kind": "semantic_causal_composition_edge",
        "source_id": source_id,
        "impact_family": family,
        "proof_task_status": "hypothesis_unproved",
        "terminal_state": "open_advisory",
        "submission_posture": "NOT_SUBMIT_READY",
        "submit_status": "NOT_SUBMIT_READY",
        "severity": "none",
        "severity_claim": "none",
        "selected_impact": "",
        "impact_contract_id": "",
        "impact_contract_required": True,
        "advisory_only": True,
        "promotion_allowed": False,
        "source_shape_limitations": SOURCE_SHAPE_LIMITATIONS + [
            "causal composition rows are weak same-entrypoint hypotheses only",
        ],
        "required_terminal_decision": [
            "prove_source_path_to_sink_locally",
            "kill_as_non_causal_same_entrypoint_cooccurrence",
        ],
    }


def relation_edge_task(edge: dict[str, Any], index: int) -> dict[str, Any]:
    source = "{}.{}".format(edge.get("source_contract", ""), edge.get("source_function", "")).strip(".")
    task_id = f"SDW-REL-{index:03d}"
    row = _task_common(
        task_id,
        "semantic_relation_edge",
        f"{source}:{edge.get('kind', '')}:{edge.get('line', 0)}",
        _relation_family(edge),
    )
    row.update(
        {
            "detector_task_kind": "semantic_relation_detector_rewrite",
            "action_lane": "detector_rewrite_candidate",
            "detectorization_readiness": "candidate_static_predicate_needs_fixtures",
            "required_next_artifacts": [
                "detector predicate diff",
                "positive fixture",
                "clean fixture",
                "detector smoke output",
                "exact impact contract before harness/report work",
            ],
            "relation_kind": edge.get("kind", ""),
            "source_component": source,
            "target_component": edge.get("target") or "",
            "method": edge.get("method") or "",
            "file": edge.get("file", ""),
            "line": edge.get("line", 0),
            "evidence": edge.get("evidence", ""),
            "recommended_action": (
                "Evaluate whether this relation edge should become a detector "
                "predicate or be marked non-detectorizable/source-review-only."
            ),
            "detector_query_bridge": _relation_query_shape(edge, str(row["candidate_detector_family"])),
        }
    )
    return row


def multi_hop_task(path_row: dict[str, Any], index: int) -> dict[str, Any]:
    path_id = str(path_row.get("path_id") or f"SG-MH-{index:03d}")
    family = _slug(str(path_row.get("impact_family") or "source_multihop")).replace("-", "_")
    row = _task_common(
        f"SDW-MH-{index:03d}",
        "semantic_multi_hop_path",
        path_id,
        family,
    )
    row.update(
        {
            "detector_task_kind": "semantic_multihop_detector_rewrite",
            "action_lane": "fixture_first_source_invariant",
            "detectorization_readiness": "not_ready_fixture_or_invariant_first",
            "required_next_artifacts": [
                "source/invariant review note for the full path",
                "positive multi-hop fixture or invariant scenario before detector rewrite",
                "clean adjacent path fixture before detector promotion",
                "exact impact contract before harness/report work",
            ],
            "impact_family": path_row.get("impact_family", ""),
            "source_component": path_row.get("source_component", ""),
            "sink_component": path_row.get("sink_component", ""),
            "mapped_stages": path_row.get("mapped_stages") or [],
            "missing_stages": path_row.get("missing_stages") or [],
            "evidence_edges": path_row.get("evidence_edges") or [],
            "recommended_action": (
                "Treat this as fixture-first/source-invariant work. Only rewrite "
                "a detector after a narrower static predicate and paired fixtures "
                "are identified."
            ),
            "detector_query_bridge": _multihop_query_shape(path_row, family),
        }
    )
    return row


def causal_composition_proof_task(edge: dict[str, Any], index: int) -> dict[str, Any]:
    family = _slug(str(edge.get("impact_family") or "causal_composition")).replace("-", "_")
    row = _proof_task_common(
        f"SDW-CC-{index:03d}",
        str(edge.get("edge_id") or f"SG-CC-{index:03d}"),
        family,
    )
    row.update(
        {
            "proof_task_kind": "semantic_causal_composition_proof",
            "action_lane": "proof_first_causal_composition",
            "proof_readiness": "needs_local_source_proof_or_kill",
            "source_component": edge.get("source_component", ""),
            "path_id": edge.get("path_id", ""),
            "path_summary": edge.get("path_summary", ""),
            "path_stages": edge.get("path_stages") or [],
            "path_missing_stages": edge.get("path_missing_stages") or [],
            "relation_kind": edge.get("relation_kind", ""),
            "relation_sink_component": edge.get("relation_sink_component", ""),
            "relation_method": edge.get("relation_method", ""),
            "relation_file": edge.get("relation_file", ""),
            "relation_line": edge.get("relation_line", 0),
            "hypothesis_strength": edge.get("hypothesis_strength", "weak_same_entrypoint_source_shape"),
            "proof_boundary": edge.get("proof_boundary", ""),
            "required_next_artifacts": [
                "source proof note tying semantic path stages to the relation sink",
                "kill note if the sink is incidental or non-causal",
                "exact impact contract before any harness/report work",
            ],
            "recommended_action": (
                "Treat this as proof-first source review. Either prove the path-to-sink "
                "composition locally or kill it as same-entrypoint coincidence."
            ),
            "proof_obligation": {
                "claim_shape": "same_entrypoint_path_to_relation_sink",
                "path_id": edge.get("path_id", ""),
                "path_stages": edge.get("path_stages") or [],
                "relation_sink_component": edge.get("relation_sink_component", ""),
                "relation_evidence": edge.get("relation_evidence", ""),
                "required_verdict": "prove_or_kill",
            },
        }
    )
    return row


def _canonical_mirror_path(path: str) -> str:
    parts = Path(path).as_posix().split("/")
    if len(parts) >= 3 and parts[0] in {"external", "src"}:
        return "/".join(parts[1:])
    return "/".join(parts)


def _dedupe_relation_edges(edges: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    seen: set[tuple[str, str, str, str, str, str, str, int]] = set()
    deduped: list[dict[str, Any]] = []
    duplicate_count = 0
    for edge in edges:
        key = (
            _canonical_mirror_path(str(edge.get("file") or "")),
            str(edge.get("source_contract") or ""),
            str(edge.get("source_function") or ""),
            str(edge.get("kind") or ""),
            str(edge.get("receiver") or ""),
            str(edge.get("target_type") or ""),
            str(edge.get("method") or ""),
            int(edge.get("line") or 0),
        )
        if key in seen:
            duplicate_count += 1
            continue
        seen.add(key)
        deduped.append(edge)
    return deduped, duplicate_count


def build_worklist(workspace: Path, graph: dict[str, Any], *, limit: int = 200) -> dict[str, Any]:
    raw_relation_edges = [
        edge for edge in graph.get("relation_edges", [])
        if isinstance(edge, dict)
    ]
    relation_edges, mirror_duplicate_relation_edge_count = _dedupe_relation_edges(raw_relation_edges)
    multi_hop_paths = [
        row for row in graph.get("multi_hop_paths", [])
        if isinstance(row, dict)
    ]
    causal_composition_edges = [
        row for row in graph.get("causal_composition_edges", [])
        if isinstance(row, dict)
    ]
    tasks: list[dict[str, Any]] = []
    for idx, edge in enumerate(relation_edges, start=1):
        if len(tasks) >= limit:
            break
        tasks.append(relation_edge_task(edge, idx))
    mh_start = 1
    for idx, row in enumerate(multi_hop_paths, start=mh_start):
        if len(tasks) >= limit:
            break
        tasks.append(multi_hop_task(row, idx))
    proof_tasks = [
        causal_composition_proof_task(row, idx)
        for idx, row in enumerate(causal_composition_edges[:limit], start=1)
    ]
    family_counts: dict[str, int] = {}
    query_shape_counts: dict[str, int] = {}
    action_lane_counts: dict[str, int] = {}
    detectorization_readiness_counts: dict[str, int] = {}
    proof_action_lane_counts: dict[str, int] = {}
    proof_readiness_counts: dict[str, int] = {}
    for task in tasks:
        family = str(task.get("candidate_detector_family") or "unknown")
        family_counts[family] = family_counts.get(family, 0) + 1
        action_lane = str(task.get("action_lane") or "unknown")
        action_lane_counts[action_lane] = action_lane_counts.get(action_lane, 0) + 1
        readiness = str(task.get("detectorization_readiness") or "unknown")
        detectorization_readiness_counts[readiness] = detectorization_readiness_counts.get(readiness, 0) + 1
        bridge = task.get("detector_query_bridge")
        if isinstance(bridge, dict):
            shape = str(bridge.get("query_shape") or "unknown")
            query_shape_counts[shape] = query_shape_counts.get(shape, 0) + 1
    for task in proof_tasks:
        action_lane = str(task.get("action_lane") or "unknown")
        proof_action_lane_counts[action_lane] = proof_action_lane_counts.get(action_lane, 0) + 1
        readiness = str(task.get("proof_readiness") or "unknown")
        proof_readiness_counts[readiness] = proof_readiness_counts.get(readiness, 0) + 1
    return {
        "schema": SCHEMA_VERSION,
        "workspace": str(workspace),
        "source_artifact": str(workspace / ".auditooor" / "semantic_graph.json"),
        "coverage_claim": "none_source_shape_only",
        "advisory_only": True,
        "promotion_allowed": False,
        "task_count": len(tasks),
        "relation_edge_task_count": sum(1 for task in tasks if task["source_kind"] == "semantic_relation_edge"),
        "multi_hop_task_count": sum(1 for task in tasks if task["source_kind"] == "semantic_multi_hop_path"),
        "proof_task_count": len(proof_tasks),
        "raw_relation_edge_count": len(raw_relation_edges),
        "mirror_duplicate_relation_edge_count": mirror_duplicate_relation_edge_count,
        "candidate_detector_family_counts": family_counts,
        "detector_query_bridge_counts": query_shape_counts,
        "action_lane_counts": action_lane_counts,
        "detectorization_readiness_counts": detectorization_readiness_counts,
        "proof_action_lane_counts": proof_action_lane_counts,
        "proof_readiness_counts": proof_readiness_counts,
        "source_shape_limitations": SOURCE_SHAPE_LIMITATIONS,
        "mechanical_path": [
            "semantic_graph relation_edges/multi_hop_paths",
            "semantic_graph causal_composition_edges weak hypotheses",
            "semantic_detector_worklist candidate specs",
            "semantic_graph_query executed source-shape matches",
            "semantic_detector_adjudication detector/fixture/source-only routing",
            "detector promotion only after fixtures, smoke output, and exact impact proof",
        ],
        "tasks": tasks,
        "proof_tasks": proof_tasks,
        "next_actions": [
            "Pick one task and decide detectorizable vs source/invariant-only.",
            "For causal composition proof rows, prove or kill the path-to-sink hypothesis locally.",
            "For detectorizable rows, add detector code plus vulnerable and clean fixtures.",
            "Do not create report text, severity, or PoC posture from this worklist alone.",
        ],
    }


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Semantic Detector Worklist",
        "",
        "Advisory detector-rewrite tasks derived from semantic graph relation and multi-hop path inventory.",
        "Rows are source-shape only and are not findings, severity approvals, PoC tasks, or submit-ready candidates.",
        "",
        f"- schema: `{payload['schema']}`",
        f"- task count: {payload['task_count']}",
        f"- relation-edge tasks: {payload['relation_edge_task_count']}",
        f"- multi-hop tasks: {payload['multi_hop_task_count']}",
        f"- proof tasks: {payload.get('proof_task_count', 0)}",
        f"- coverage claim: `{payload['coverage_claim']}`",
        f"- promotion allowed: `{str(payload['promotion_allowed']).lower()}`",
        "",
        "## Source-Shape Limitations",
        "",
    ]
    for limitation in payload.get("source_shape_limitations", []):
        lines.append(f"- {limitation}")
    lines.extend([
        "",
        "## Tasks",
        "",
    ]
    )
    tasks = payload.get("tasks") if isinstance(payload.get("tasks"), list) else []
    if not tasks:
        lines.append("_No semantic detector tasks were generated._")
        return "\n".join(lines) + "\n"
    lines.extend(["| Task | Lane | Readiness | Family | Query Shape | Source | Posture | Action |", "|---|---|---|---|---|---|---|---|"])
    for task in tasks[:200]:
        source = task.get("source_component") or task.get("source_id") or ""
        bridge = task.get("detector_query_bridge") if isinstance(task.get("detector_query_bridge"), dict) else {}
        lines.append(
            "| `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | {} |".format(
                task.get("task_id", ""),
                task.get("action_lane", ""),
                task.get("detectorization_readiness", ""),
                task.get("candidate_detector_family", ""),
                bridge.get("query_shape", ""),
                source,
                task.get("submission_posture", ""),
                task.get("recommended_action", ""),
            )
        )
    proof_tasks = payload.get("proof_tasks") if isinstance(payload.get("proof_tasks"), list) else []
    if proof_tasks:
        lines.extend([
            "",
            "## Proof Tasks",
            "",
            "| Task | Lane | Readiness | Impact Family | Source | Relation Sink | Posture | Action |",
            "|---|---|---|---|---|---|---|---|",
        ])
        for task in proof_tasks[:200]:
            lines.append(
                "| `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | {} |".format(
                    task.get("task_id", ""),
                    task.get("action_lane", ""),
                    task.get("proof_readiness", ""),
                    task.get("impact_family", ""),
                    task.get("source_component", ""),
                    task.get("relation_sink_component", ""),
                    task.get("submission_posture", ""),
                    task.get("recommended_action", ""),
                )
            )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-md", type=Path)
    parser.add_argument("--limit", type=int, default=200)
    parser.add_argument("--generate-graph", action="store_true")
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args()

    workspace = args.workspace.expanduser().resolve()
    if not workspace.is_dir():
        print(f"[semantic-detector-worklist] workspace not found: {workspace}", file=sys.stderr)
        return 2
    graph = _load_graph(workspace, generate=args.generate_graph)
    payload = build_worklist(workspace, graph, limit=max(0, args.limit))
    out_json = args.out_json or (workspace / ".auditooor" / "semantic_detector_worklist.json")
    out_md = args.out_md or (workspace / ".auditooor" / "semantic_detector_worklist.md")
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(payload), encoding="utf-8")
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    print(
        f"[semantic-detector-worklist] OK tasks={payload['task_count']} "
        f"proof_tasks={payload.get('proof_task_count', 0)} json={out_json}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
