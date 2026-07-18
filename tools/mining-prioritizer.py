#!/usr/bin/env python3
"""
mining-prioritizer.py — Rank CCIA attack angles by mining priority

Scores each attack angle on:
  - Severity weight (CRITICAL=5, HIGH=4, MEDIUM=2, LOW=1)
  - Exploitability (external call + state write = +3)
  - Auth gap (unauthenticated state write = +3)
  - Cross-contract impact (+2 per additional contract)
  - Prior submission penalty (-5 if similar already filed)
  - Pattern novelty (+2 if not yet paid in this workspace)

Usage:
    mining-prioritizer.py <workspace> [--top N] [--json] [--out <path>]
    mining-prioritizer.py ~/audits/<project> --top 10
    mining-prioritizer.py ~/audits/<project> --unmined-only

Output:
    Ranked list of angles with scores and rationale.
"""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from submission_ledger import load_submission_entries
from submission_paths import find_submission_file
from outcome_reweight import (
    compute_reweight,
    history_version,
    load_outcome_history,
)
from lib import program_impact_mapping as impact_mapping


DEFAULT_OUTCOMES_PATH = Path(__file__).resolve().parents[1] / "reference" / "outcomes.jsonl"


def rust_contract_from_file(file_path: str) -> str:
    """Best-effort crate/contract label from a ccia-rust source path."""
    parts = file_path.replace("\\", "/").split("/")
    if "contracts" in parts:
        idx = parts.index("contracts")
        if idx + 1 < len(parts):
            return parts[idx + 1]
    if parts:
        return parts[-1]
    return ""


def rust_angle_severity(angle_id: str, confidence: str) -> str:
    """Translate ccia-rust advisory rows into prioritizer severities.

    The Rust report is a source-shape worklist, not proof. Keep the default
    conservative, but let medium-confidence auth/oracle rows rank above pure
    arithmetic/rounding review chores.
    """
    if confidence.lower() == "medium" and angle_id in {"A-AUTH", "A-ORACLE"}:
        return "HIGH"
    return "MEDIUM"


def normalize_ccia_rust_angles(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Normalize tools/ccia-rust.py rows into generic mining-prioritizer angles."""
    rows = payload.get("angles", [])
    if not isinstance(rows, list):
        return []

    angles: List[Dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        angle_id = str(row.get("angle") or "").strip()
        if not angle_id:
            continue
        file_path = str(row.get("file") or "")
        confidence = str(row.get("confidence") or "")
        contract = rust_contract_from_file(file_path)
        reason = str(row.get("reason") or angle_id)
        title = reason
        if file_path:
            title = f"{reason} ({file_path}:{row.get('line', 0)})"
        normalized = {
            "id": angle_id,
            "severity": rust_angle_severity(angle_id, confidence),
            "title": title,
            "contracts": [contract] if contract else [],
            "source": "ccia-rust",
            "file": file_path,
            "line": row.get("line", 0),
            "confidence": confidence,
            "reason": reason,
            "snippet": row.get("snippet", ""),
        }
        angles.append(normalized)
    return angles


def load_ccia_rust(ws: Path) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Load ccia-rust data when a Rust/Soroban workspace has no Solidity angles."""
    candidates = [ws / "ccia_rust_report.json"]
    audit_dir = ws / "audit"
    if audit_dir.is_dir():
        candidates.extend(sorted(audit_dir.glob("ccia_rust_*.json"), reverse=True))

    for path in candidates:
        if not path.is_file():
            continue
        try:
            payload = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        if not isinstance(payload, dict):
            continue
        angles = normalize_ccia_rust_angles(payload)
        if angles:
            return {
                "lang": payload.get("lang", "rust"),
                "workspace": payload.get("workspace", str(ws)),
                "total_files_scanned": payload.get("total_files_scanned", 0),
                "source": str(path),
            }, angles
    return {}, []


def load_ccia(ws: Path) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Load CCIA data and attack angles, including Rust/Soroban fallback."""
    json_path = ws / "ccia_report.json"
    if json_path.exists():
        data = json.loads(json_path.read_text())
        if isinstance(data, dict):
            angles = data.get("attack_angles", [])
            if angles:
                return data.get("ccia", {}), angles
            rust_ccia, rust_angles = load_ccia_rust(ws)
            if rust_angles:
                return rust_ccia, rust_angles
            return data.get("ccia", {}), []
        if isinstance(data, list) and data:
            return {}, data
        rust_ccia, rust_angles = load_ccia_rust(ws)
        if rust_angles:
            return rust_ccia, rust_angles
        return {}, []
    # Try markdown
    md_path = ws / "ccia_report.md"
    if md_path.exists():
        angles = parse_angles_from_md(md_path.read_text())
        if angles:
            return {}, angles
        rust_ccia, rust_angles = load_ccia_rust(ws)
        if rust_angles:
            return rust_ccia, rust_angles
        return {}, []
    rust_ccia, rust_angles = load_ccia_rust(ws)
    if rust_angles:
        return rust_ccia, rust_angles
    return {}, []


def parse_angles_from_md(text: str) -> List[Dict]:
    """Extract attack angles from markdown CCIA report."""
    angles = []
    lines = text.splitlines()
    for line in lines:
        m = re.match(r'###\s+(A-[A-Z0-9]+)\s+—\s+(\w+)\s+—\s+(.+)', line)
        if m:
            angles.append({
                "id": m.group(1),
                "severity": m.group(2),
                "title": m.group(3),
            })
    return angles


def load_prior_submissions(ws: Path) -> List[Dict]:
    """Load prior submissions from the active workspace ledger, whatever its layout."""
    sub_file = find_submission_file(ws)
    if sub_file is None or not sub_file.exists():
        return []
    return load_submission_entries(sub_file)


def load_topology(ws: Path) -> Dict[str, Dict[str, Any]]:
    """Load deployment topology artifact keyed by contract name."""
    path = ws / "deployment_topology.json"
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text())
    except json.JSONDecodeError:
        return {}
    entries = payload.get("entries", [])
    topology: Dict[str, Dict[str, Any]] = {}
    if isinstance(entries, list):
        for entry in entries:
            if isinstance(entry, dict):
                contract = entry.get("contract")
                if isinstance(contract, str) and contract:
                    topology[contract] = entry
    return topology


def load_asset_coverage_plan(ws: Path) -> Dict[str, Any]:
    """Load asset_coverage_plan from INTAKE_BASELINE.json.

    Returns an empty dict when the baseline is missing or malformed so
    callers can treat asset quotas as opt-in.
    """
    path = ws / "INTAKE_BASELINE.json"
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return {}
    plan = payload.get("asset_coverage_plan", {})
    if not isinstance(plan, dict):
        return {}
    return plan


def compute_per_asset_allocation(
    plan: Dict[str, Any], total_agent_hours: int = 50
) -> Dict[str, Dict[str, Any]]:
    """Gap E — convert per-asset quota percentages into absolute hour budgets.

    `plan` is the asset_coverage_plan dict from INTAKE_BASELINE.json. Emits:
        {
          "<asset>": {
            "target_agent_hours": int,
            "agent_hour_quota_pct": int,
            "estimated_hours": int,
            "plan_status": str,
            "roots": [...]
          },
          ...
        }
    """
    allocation: Dict[str, Dict[str, Any]] = {}
    if not plan:
        return allocation
    for asset, entry in plan.items():
        if not isinstance(entry, dict):
            continue
        quota_pct = int(entry.get("agent_hour_quota_pct", 0) or 0)
        estimated = int(entry.get("estimated_hours", 0) or 0)
        # Prefer the explicit estimated_hours; fall back to quota * total / 100.
        target = estimated if estimated else int(round(total_agent_hours * quota_pct / 100))
        allocation[asset] = {
            "target_agent_hours": target,
            "agent_hour_quota_pct": quota_pct,
            "estimated_hours": estimated,
            "plan_status": entry.get("plan_status", "missing"),
            "roots": entry.get("roots", []),
        }
    return allocation


def load_semantic_path_inventory(ws: Path) -> Dict[str, Any]:
    """Load advisory semantic-graph path accounting for pre-agent detector work.

    The semantic graph is source-shape evidence, not full coverage. This helper
    only carries counts plus bounded worklists into `mining_priorities.json` so
    detector lanes can see cross-contract / multi-hop rows before agent dispatch.
    """
    path = ws / ".auditooor" / "semantic_graph.json"
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return {
            "status": "unreadable",
            "artifact": str(path),
            "coverage_claim": "none_source_shape_only",
        }
    if not isinstance(payload, dict):
        return {
            "status": "malformed",
            "artifact": str(path),
            "coverage_claim": "none_source_shape_only",
        }

    entrypoints = payload.get("entrypoints") if isinstance(payload.get("entrypoints"), list) else []
    relation_edges = payload.get("relation_edges") if isinstance(payload.get("relation_edges"), list) else []
    multi_hop_paths = payload.get("multi_hop_paths") if isinstance(payload.get("multi_hop_paths"), list) else []

    entrypoint_roles: Dict[str, int] = {}
    for entry in entrypoints:
        if not isinstance(entry, dict):
            continue
        role = str(entry.get("role") or "unknown")
        entrypoint_roles[role] = entrypoint_roles.get(role, 0) + 1

    relation_worklist: List[Dict[str, Any]] = []
    for edge in relation_edges[:50]:
        if not isinstance(edge, dict):
            continue
        relation_worklist.append({
            "kind": edge.get("kind", ""),
            "source": "{}.{}".format(edge.get("source_contract", ""), edge.get("source_function", "")),
            "target": edge.get("target") or "",
            "method": edge.get("method") or "",
            "receiver": edge.get("receiver") or edge.get("target") or "",
            "target_type": edge.get("target_type") or "",
            "receiver_source": edge.get("receiver_source") or "",
            "resolution": edge.get("resolution") or "",
            "detector_hint": edge.get("detector_hint") or "",
            "file": edge.get("file", ""),
            "line": edge.get("line", 0),
            "detector_next_action": (
                "consider typed-receiver detector predicate for this source-shape relation edge"
                if edge.get("target_type")
                else "consider detector predicate for this source-shape relation edge"
            ),
        })

    multihop_worklist: List[Dict[str, Any]] = []
    for path_row in multi_hop_paths[:50]:
        if not isinstance(path_row, dict):
            continue
        multihop_worklist.append({
            "path_id": path_row.get("path_id", ""),
            "impact_family": path_row.get("impact_family", ""),
            "source_component": path_row.get("source_component", ""),
            "mapped_stages": path_row.get("mapped_stages") or [],
            "missing_stages": path_row.get("missing_stages") or [],
            "detector_next_action": (
                "map this semantic path to a detector, exact-impact candidate, "
                "or explicit non-detectorizable note"
            ),
        })

    return {
        "status": "present",
        "artifact": str(path),
        "schema_version": payload.get("schema_version", ""),
        "coverage_claim": "none_source_shape_only",
        "summary": {
            "source_file_count": payload.get("source_file_count", 0),
            "contract_count": payload.get("contract_count", 0),
            "entrypoint_count": payload.get("entrypoint_count", len(entrypoints)),
            "relation_edge_count": payload.get("relation_edge_count", len(relation_edges)),
            "evidence_edge_count": payload.get("evidence_edge_count", 0),
            "multi_hop_path_count": payload.get("multi_hop_path_count", len(multi_hop_paths)),
            "entrypoint_roles": entrypoint_roles,
        },
        "relation_edge_worklist": relation_worklist,
        "multi_hop_path_worklist": multihop_worklist,
    }


def load_semantic_graph_query_results(ws: Path) -> Dict[str, Any]:
    """Load advisory semantic query execution accounting.

    Query results are source-shape matches only. They can guide detector and
    source-review prioritization, but they never prove impact or promotion.
    """
    path = ws / ".auditooor" / "semantic_graph_query_results.json"
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return {
            "status": "unreadable",
            "artifact": str(path),
            "coverage_claim": "none_source_shape_only",
            "advisory_only": True,
            "promotion_allowed": False,
        }
    if not isinstance(payload, dict):
        return {
            "status": "malformed",
            "artifact": str(path),
            "coverage_claim": "none_source_shape_only",
            "advisory_only": True,
            "promotion_allowed": False,
        }
    results = payload.get("results") if isinstance(payload.get("results"), list) else []
    status_counts: Dict[str, int] = {}
    shape_counts: Dict[str, int] = {}
    collection_counts: Dict[str, int] = {}
    sample: List[Dict[str, Any]] = []
    for result in results[:50]:
        if not isinstance(result, dict):
            continue
        status = str(result.get("query_status") or "unknown")
        shape = str(result.get("query_shape") or "unknown")
        collection = str(result.get("source_collection") or "unknown")
        status_counts[status] = status_counts.get(status, 0) + 1
        shape_counts[shape] = shape_counts.get(shape, 0) + 1
        collection_counts[collection] = collection_counts.get(collection, 0) + 1
        sample.append({
            "task_id": result.get("task_id", ""),
            "route_id": result.get("route_id", ""),
            "impact_id": result.get("impact_id", ""),
            "impact_family": result.get("impact_family", ""),
            "candidate_detector_family": result.get("candidate_detector_family", ""),
            "query_shape": result.get("query_shape", ""),
            "source_collection": result.get("source_collection", ""),
            "match_count": int(result.get("match_count") or 0),
            "truncated": bool(result.get("truncated")),
            "submission_posture": result.get("submission_posture", "NOT_SUBMIT_READY"),
            "submit_status": result.get("submit_status", "NOT_SUBMIT_READY"),
            "severity": result.get("severity", "none"),
            "selected_impact": result.get("selected_impact", ""),
            "impact_contract_required": bool(result.get("impact_contract_required", True)),
            "advisory_only": bool(result.get("advisory_only", True)),
            "promotion_allowed": bool(result.get("promotion_allowed", False)),
        })
    return {
        "status": "present",
        "artifact": str(path),
        "schema": payload.get("schema", ""),
        "source_mode": payload.get("source_mode", ""),
        "source_artifact": payload.get("source_artifact", ""),
        "coverage_claim": payload.get("coverage_claim", "none_source_shape_only"),
        "advisory_only": bool(payload.get("advisory_only", True)),
        "promotion_allowed": bool(payload.get("promotion_allowed", False)),
        "submission_posture": payload.get("submission_posture", "NOT_SUBMIT_READY"),
        "submit_status": payload.get("submit_status", "NOT_SUBMIT_READY"),
        "severity": payload.get("severity", "none"),
        "selected_impact": payload.get("selected_impact", ""),
        "impact_contract_required": bool(payload.get("impact_contract_required", True)),
        "query_count": int(payload.get("query_count") or len(results)),
        "error_count": int(payload.get("error_count") or 0),
        "matched_row_count": int(payload.get("matched_row_count") or 0),
        "impact_worklist_row_count": int(payload.get("impact_worklist_row_count") or 0),
        "query_status_counts": status_counts,
        "query_shape_counts": shape_counts,
        "source_collection_counts": collection_counts,
        "result_sample": sample,
        "next_actions": [
            "refresh impact-worklist to propagate query-result accounting into source_review_handoff rows",
            "triage zero-match rows as source-review-only, invariant-only, or kill/reframe",
            "do not promote without exact impact proof, fixtures, and execution artifacts",
        ],
    }


def semantic_query_results_by_task(ws: Path) -> Dict[str, Dict[str, Any]]:
    sidecar = load_semantic_graph_query_results(ws)
    rows = sidecar.get("result_sample") if isinstance(sidecar.get("result_sample"), list) else []
    return {
        str(row.get("task_id") or ""): row
        for row in rows
        if isinstance(row, dict) and str(row.get("task_id") or "")
    }


def load_semantic_detector_worklist(ws: Path) -> Dict[str, Any]:
    """Load advisory detector rewrite rows generated by semantic-detector-worklist.

    This deliberately preserves fail-closed posture fields and carries only a
    bounded task sample into mining priorities. The worklist is detector
    planning input, not severity evidence or submission readiness.
    """
    path = ws / ".auditooor" / "semantic_detector_worklist.json"
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return {
            "status": "unreadable",
            "artifact": str(path),
            "coverage_claim": "none_source_shape_only",
            "advisory_only": True,
            "promotion_allowed": False,
        }
    if not isinstance(payload, dict):
        return {
            "status": "malformed",
            "artifact": str(path),
            "coverage_claim": "none_source_shape_only",
            "advisory_only": True,
            "promotion_allowed": False,
        }

    tasks = payload.get("tasks") if isinstance(payload.get("tasks"), list) else []
    query_results = semantic_query_results_by_task(ws)
    task_sample: List[Dict[str, Any]] = []
    executed_query_count = 0
    matched_query_count = 0
    matched_row_count = 0
    for task in tasks[:50]:
        if not isinstance(task, dict):
            continue
        query_result = query_results.get(str(task.get("task_id") or ""))
        match_count = int((query_result or {}).get("match_count") or 0)
        if query_result:
            executed_query_count += 1
            matched_row_count += match_count
            if match_count:
                matched_query_count += 1
        task_sample.append({
            "task_id": task.get("task_id", ""),
            "source_kind": task.get("source_kind", ""),
            "source_id": task.get("source_id", ""),
            "detector_task_kind": task.get("detector_task_kind", ""),
            "candidate_detector_family": task.get("candidate_detector_family", ""),
            "detector_task_status": task.get("detector_task_status", "advisory_untriaged"),
            "terminal_state": task.get("terminal_state", "open_advisory"),
            "submission_posture": task.get("submission_posture", "NOT_SUBMIT_READY"),
            "submit_status": task.get("submit_status", "NOT_SUBMIT_READY"),
            "severity": task.get("severity", "none"),
            "severity_claim": task.get("severity_claim", "none"),
            "selected_impact": task.get("selected_impact", ""),
            "impact_contract_id": task.get("impact_contract_id", ""),
            "impact_contract_required": bool(task.get("impact_contract_required", True)),
            "advisory_only": bool(task.get("advisory_only", True)),
            "promotion_allowed": bool(task.get("promotion_allowed", False)),
            "source_component": task.get("source_component", ""),
            "target_component": task.get("target_component", ""),
            "impact_family": task.get("impact_family", ""),
            "file": task.get("file", ""),
            "line": task.get("line", 0),
            "recommended_action": task.get("recommended_action", ""),
            "detector_query_bridge": (
                task.get("detector_query_bridge")
                if isinstance(task.get("detector_query_bridge"), dict)
                else {}
            ),
            "query_result_status": "executed" if query_result else "not_executed",
            "query_match_count": match_count,
        })

    return {
        "status": "present",
        "artifact": str(path),
        "schema": payload.get("schema", ""),
        "coverage_claim": payload.get("coverage_claim", "none_source_shape_only"),
        "advisory_only": bool(payload.get("advisory_only", True)),
        "promotion_allowed": bool(payload.get("promotion_allowed", False)),
        "task_count": payload.get("task_count", len(tasks)),
        "relation_edge_task_count": payload.get("relation_edge_task_count", 0),
        "multi_hop_task_count": payload.get("multi_hop_task_count", 0),
        "candidate_detector_family_counts": (
            payload.get("candidate_detector_family_counts")
            if isinstance(payload.get("candidate_detector_family_counts"), dict)
            else {}
        ),
        "detector_query_bridge_counts": (
            payload.get("detector_query_bridge_counts")
            if isinstance(payload.get("detector_query_bridge_counts"), dict)
            else {}
        ),
        "query_result_accounting": {
            "result_artifact": str(ws / ".auditooor" / "semantic_graph_query_results.json"),
            "candidate_query_count": len(tasks),
            "executed_query_count": executed_query_count,
            "matched_query_count": matched_query_count,
            "zero_match_query_count": max(0, executed_query_count - matched_query_count),
            "matched_row_count": matched_row_count,
        },
        "task_sample": task_sample,
        "next_actions": [
            "triage each task as detectorizable vs source/invariant-only",
            "add vulnerable and clean fixtures before detector promotion",
            "keep rows NOT_SUBMIT_READY until an exact impact contract and proof exist",
        ],
    }


def load_semantic_detector_adjudication(ws: Path) -> Dict[str, Any]:
    """Load post-query detector adjudication sidecar.

    The adjudication artifact turns matched semantic query rows into detector
    rewrite briefs, fixture requirements, or explicit non-detectorizable rows.
    It remains planning/accounting input only.
    """
    path = ws / ".auditooor" / "semantic_detector_adjudication.json"
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return {
            "status": "unreadable",
            "artifact": str(path),
            "coverage_claim": "none_source_shape_only",
            "advisory_only": True,
            "promotion_allowed": False,
        }
    if not isinstance(payload, dict):
        return {
            "status": "malformed",
            "artifact": str(path),
            "coverage_claim": "none_source_shape_only",
            "advisory_only": True,
            "promotion_allowed": False,
        }
    briefs = payload.get("detector_rewrite_briefs") if isinstance(payload.get("detector_rewrite_briefs"), list) else []
    fixtures = payload.get("fixture_requirements") if isinstance(payload.get("fixture_requirements"), list) else []
    non_detectorizable = (
        payload.get("non_detectorizable_rows")
        if isinstance(payload.get("non_detectorizable_rows"), list)
        else []
    )
    summary = payload.get("adjudication_summary") if isinstance(payload.get("adjudication_summary"), dict) else {}
    readiness = payload.get("readiness") if isinstance(payload.get("readiness"), dict) else {}
    next_commands = payload.get("next_commands") if isinstance(payload.get("next_commands"), list) else []
    return {
        "status": "present",
        "artifact": str(path),
        "schema": payload.get("schema", ""),
        "source_mode": payload.get("source_mode", ""),
        "coverage_claim": payload.get("coverage_claim", "none_source_shape_only"),
        "advisory_only": bool(payload.get("advisory_only", True)),
        "promotion_allowed": bool(payload.get("promotion_allowed", False)),
        "submission_posture": payload.get("submission_posture", "NOT_SUBMIT_READY"),
        "submit_status": payload.get("submit_status", "NOT_SUBMIT_READY"),
        "severity": payload.get("severity", "none"),
        "selected_impact": payload.get("selected_impact", ""),
        "impact_contract_required": bool(payload.get("impact_contract_required", True)),
        "processed_query_count": int(payload.get("processed_query_count") or 0),
        "input_query_count": int(payload.get("input_query_count") or 0),
        "input_matched_row_count": int(payload.get("input_matched_row_count") or 0),
        "detector_rewrite_brief_count": int(payload.get("detector_rewrite_brief_count") or len(briefs)),
        "fixture_requirement_count": int(payload.get("fixture_requirement_count") or len(fixtures)),
        "non_detectorizable_count": int(payload.get("non_detectorizable_count") or len(non_detectorizable)),
        "adjudication_summary": summary,
        "readiness": {
            "ready_for_detector_rewrite_count": int(
                readiness.get("ready_for_detector_rewrite_count")
                or payload.get("detector_rewrite_brief_count")
                or len(briefs)
                or 0
            ),
            "fixture_first_count": int(
                readiness.get("fixture_first_count")
                or payload.get("fixture_requirement_count")
                or len(fixtures)
                or 0
            ),
            "source_review_only_count": int(
                readiness.get("source_review_only_count")
                or payload.get("non_detectorizable_count")
                or len(non_detectorizable)
                or 0
            ),
            "ready_for_submission": bool(readiness.get("ready_for_submission", False)),
            "ready_for_poc": bool(readiness.get("ready_for_poc", False)),
            "ready_for_severity": bool(readiness.get("ready_for_severity", False)),
        },
        "non_detectorizable_reason_counts": (
            summary.get("non_detectorizable_reason_counts")
            if isinstance(summary.get("non_detectorizable_reason_counts"), dict)
            else {}
        ),
        "detector_rewrite_brief_sample": briefs[:20],
        "fixture_requirement_sample": fixtures[:20],
        "non_detectorizable_sample": non_detectorizable[:20],
        "next_command_sample": [str(command) for command in next_commands[:20] if command],
        "next_actions": [
            "implement detector rewrite briefs only with paired vulnerable and clean fixtures",
            "route non-detectorizable rows to source/invariant review notes",
            "keep all rows NOT_SUBMIT_READY until exact impact proof and execution artifacts exist",
        ],
    }


def load_impact_family_worklists(ws: Path) -> Dict[str, Any]:
    """Load upstream listed-impact worklists for pre-harness planning.

    The worklists are fail-closed planning rows. Mining priorities carry them
    as sidecar context only so agents pick scoped roots/components before any
    harness/report route.
    """
    path = ws / ".auditooor" / "impact_family_worklists.json"
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return {
            "status": "unreadable",
            "artifact": str(path),
            "advisory_only": True,
            "promotion_allowed": False,
        }
    if not isinstance(payload, dict):
        return {
            "status": "malformed",
            "artifact": str(path),
            "advisory_only": True,
            "promotion_allowed": False,
        }
    rows = payload.get("worklists") if isinstance(payload.get("worklists"), list) else []
    sample: List[Dict[str, Any]] = []
    for row in rows[:50]:
        if not isinstance(row, dict):
            continue
        handoff = row.get("source_review_handoff") if isinstance(row.get("source_review_handoff"), dict) else {}
        sample.append({
            "impact_id": row.get("impact_id", ""),
            "worklist_id": row.get("worklist_id", ""),
            "impact_family": row.get("impact_family", ""),
            "severity": row.get("severity", ""),
            "impact": row.get("impact", ""),
            "status": row.get("status", ""),
            "submission_posture": row.get("submission_posture", "NOT_SUBMIT_READY"),
            "submit_ready": bool(row.get("submit_ready", False)),
            "proof_class": row.get("proof_class") or row.get("required_evidence_class", ""),
            "required_artifacts": row.get("required_artifacts", []),
            "relevant_source_roots": row.get("relevant_source_roots", []),
            "component_count": row.get("component_count", 0),
            "components": row.get("components", [])[:10],
            "oos_traps": row.get("oos_traps", [])[:10],
            "source_review_handoff": {
                "route_count": handoff.get("route_count", 0),
                "route_kind_counts": (
                    handoff.get("route_kind_counts")
                    if isinstance(handoff.get("route_kind_counts"), dict)
                    else {}
                ),
                "semantic_graph_query_result_status": handoff.get("semantic_graph_query_result_status", "missing_or_empty"),
                "query_result_accounting": (
                    handoff.get("query_result_accounting")
                    if isinstance(handoff.get("query_result_accounting"), dict)
                    else {}
                ),
                "submission_posture": handoff.get("submission_posture", "NOT_SUBMIT_READY"),
                "submit_ready": bool(handoff.get("submit_ready", False)),
                "promotion_allowed": bool(handoff.get("promotion_allowed", False)),
            },
            "next_command": row.get("next_command", ""),
        })
    return {
        "status": "present",
        "artifact": str(path),
        "schema": payload.get("schema", ""),
        "worklist_count": len(rows),
        "blocker_category_counts": payload.get("blocker_category_counts", {}),
        "strict_blocking_categories": payload.get("strict_blocking_categories", []),
        "open_work_categories": payload.get("open_work_categories", []),
        "advisory_only": True,
        "promotion_allowed": False,
        "submission_posture": "NOT_SUBMIT_READY",
        "worklists": sample,
    }


def load_live_checks(ws: Path) -> Dict[str, List[Dict[str, Any]]]:
    """Load live topology dossier entries keyed by contract name."""
    path = ws / "live_topology_checks.json"
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text())
    except json.JSONDecodeError:
        return {}
    results = payload.get("results", [])
    live_checks: Dict[str, List[Dict[str, Any]]] = {}
    if isinstance(results, list):
        for result in results:
            if not isinstance(result, dict):
                continue
            contract = result.get("contract")
            if isinstance(contract, str) and contract:
                live_checks.setdefault(contract, []).append(result)
    return live_checks


def angle_matches_live_check(angle: Dict[str, Any], entry: Dict[str, Any]) -> bool:
    angle_id = str(angle.get("id") or "").strip()
    related = [
        str(item).strip()
        for item in entry.get("related_angle_ids", [])
        if str(item).strip()
    ]
    if related:
        return angle_id in related
    return True


def exact_angle_linked(entry: Dict[str, Any], angle_id: str) -> bool:
    related = {
        str(item).strip()
        for item in entry.get("related_angle_ids", [])
        if str(item).strip()
    }
    return bool(related) and angle_id in related


def pairable_generated_relations(angle: Dict[str, Any], rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    angle_id = str(angle.get("id") or "").strip()
    if angle_id not in {"A-RACE", "A-AUTH", "A-ORACLE"}:
        return []

    selected: List[Dict[str, Any]] = []
    seen_keys: Set[Tuple[str, str, str]] = set()
    for entry in rows:
        if not exact_angle_linked(entry, angle_id):
            continue
        if not (bool(entry.get("generated")) or str(entry.get("spec_source") or "") == "generated-relation"):
            continue
        source = str(entry.get("contract") or "").strip()
        check = entry.get("check", {})
        if not isinstance(check, dict):
            check = {}
        call = str(check.get("call") or entry.get("call") or "").strip()
        target = str(check.get("expect_ref") or entry.get("expect_ref") or "").strip()
        if not source or not call or not target:
            continue
        semantic_key = (source, call, target)
        if semantic_key in seen_keys:
            continue
        seen_keys.add(semantic_key)
        selected.append(entry)
    return selected


def severity_weight(sev: str) -> int:
    """Convert severity string to numeric weight."""
    return {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 2, "LOW": 1, "INFO": 0}.get(sev.upper(), 1)


def _severity_claim(sev: Any) -> str:
    normalized = str(sev or "").strip().capitalize()
    return normalized if normalized in {"Critical", "High", "Medium"} else ""


def summarize_angle_impact_contract(ws: Path, angle: Dict[str, Any]) -> Dict[str, Any]:
    """Attach conservative pre-work impact-contract state to one angle."""
    contracts = angle.get("contracts", [])
    if not isinstance(contracts, list):
        contracts = []
    return impact_mapping.impact_contract_summary(
        ws,
        candidate_id=str(angle.get("candidate_id") or angle.get("id") or ""),
        angle_id=str(angle.get("id") or ""),
        contracts=[str(contract) for contract in contracts],
        severity_claim=_severity_claim(angle.get("severity")),
        direct_submit=bool(angle.get("direct_submit") or angle.get("submit_ready")),
    )


def angle_to_keywords(angle: Dict) -> Set[str]:
    """Extract searchable keywords from an angle."""
    keywords = set()
    title = angle.get("title", "").lower()
    desc = angle.get("description", "").lower()
    text = title + " " + desc
    
    # Extract contract and function names
    for m in re.finditer(r'`([A-Za-z_][A-Za-z0-9_]*)`', text):
        keywords.add(m.group(1).lower())
    for m in re.finditer(r'\b([A-Za-z_][A-Za-z0-9_]+)\.', text):
        keywords.add(m.group(1).lower())
    
    # Bug class keywords
    bug_classes = ["reentrancy", "oracle", "timestamp", "delegatecall", "flash", "auth", "access", "race", "upgrade", "erc4626", "vault"]
    for bc in bug_classes:
        if bc in text:
            keywords.add(bc)
    
    return keywords


def submission_to_keywords(sub: Dict) -> Set[str]:
    """Extract keywords from a submission."""
    title = sub.get("title", "").lower()
    keywords = set()
    for m in re.finditer(r'`([A-Za-z_][A-Za-z0-9_]*)`', title):
        keywords.add(m.group(1).lower())
    for m in re.finditer(r'\b([A-Za-z_][A-Za-z0-9_]+)\.', title):
        keywords.add(m.group(1).lower())
    bug_classes = ["reentrancy", "oracle", "timestamp", "delegatecall", "flash", "auth", "access", "race", "upgrade", "erc4626", "vault"]
    for bc in bug_classes:
        if bc in title:
            keywords.add(bc)
    return keywords


def extract_specific_keywords(text: str) -> Set[str]:
    """Extract contract/function names (specific) vs bug classes (generic)."""
    specific = set()
    for m in re.finditer(r'`([A-Za-z_][A-Za-z0-9_]*)`', text):
        specific.add(m.group(1).lower())
    for m in re.finditer(r'\b([A-Za-z_][A-Za-z0-9_]+)\.', text):
        specific.add(m.group(1).lower())
    return specific


def extract_generic_keywords(text: str) -> Set[str]:
    """Extract bug-class keywords only."""
    generic = set()
    bug_classes = ["reentrancy", "oracle", "timestamp", "delegatecall", "flash", "auth", "access", "race", "upgrade", "erc4626", "vault"]
    for bc in bug_classes:
        if bc in text:
            generic.add(bc)
    return generic


def check_prior_overlap(angle: Dict, subs: List[Dict]) -> Tuple[float, Optional[str]]:
    """Check if angle overlaps with prior submissions. Returns (penalty, reason).
    
    Penalty is weighted toward *specific* keyword overlap (contract/function names).
    Generic bug-class overlap (e.g., both mention 'auth') produces only a small
    penalty to avoid suppressing unrelated angles that happen to share a broad category.
    """
    angle_title = angle.get("title", "").lower()
    angle_desc = angle.get("description", "").lower()
    angle_text = angle_title + " " + angle_desc
    angle_specific = extract_specific_keywords(angle_text)
    angle_generic = extract_generic_keywords(angle_text)
    
    best_overlap = 0.0
    best_reason = None
    
    for sub in subs:
        sub_title = sub.get("title", "").lower()
        sub_specific = extract_specific_keywords(sub_title)
        sub_generic = extract_generic_keywords(sub_title)
        
        if not angle_specific and not angle_generic:
            continue
        if not sub_specific and not sub_generic:
            continue
        
        # Specific overlap: same contract / function names (high confidence dupe signal)
        spec_intersection = angle_specific & sub_specific
        spec_union = angle_specific | sub_specific
        spec_overlap = len(spec_intersection) / len(spec_union) if spec_union else 0.0
        
        # Generic overlap: same bug class (low confidence on its own)
        gen_intersection = angle_generic & sub_generic
        gen_union = angle_generic | sub_generic
        gen_overlap = len(gen_intersection) / len(gen_union) if gen_union else 0.0
        
        # Combined score: specific overlap dominates; generic-only overlap is damped
        if spec_overlap > 0:
            overlap = 0.7 * spec_overlap + 0.3 * gen_overlap
        else:
            overlap = 0.2 * gen_overlap
        
        if overlap > best_overlap:
            best_overlap = overlap
            status = sub.get("status", "").lower()
            if "dupe" in status or "duplicate" in status:
                best_reason = f"Near prior dupe: '{sub.get('title', '')[:50]}'"
            elif "paid" in status or "accept" in status:
                best_reason = f"Similar to paid finding: '{sub.get('title', '')[:50]}'"
            else:
                best_reason = f"Similar to pending finding: '{sub.get('title', '')[:50]}'"
    
    # Scale penalty by overlap strength
    penalty = -5 * best_overlap
    return penalty, best_reason if best_overlap > 0.25 else None


def score_angle(angle: Dict, subs: List[Dict], ccia: Dict) -> Tuple[float, List[str]]:
    """Score an attack angle. Returns (score, rationale)."""
    score = 0.0
    rationale = []
    
    # Severity weight
    sev = angle.get("severity", "MEDIUM")
    sw = severity_weight(sev)
    score += sw
    rationale.append(f"severity={sev} (+{sw})")
    
    # Check angle ID early for use in scoring logic
    angle_id = angle.get("id", "")
    
    # Exploitability: external calls + state writes in same function
    # We need to look up the function in ccia data
    contracts = angle.get("contracts", [])
    cross_contract = len(contracts) > 1
    
    # Cross-contract bonus
    if cross_contract:
        # A-RACE angles are often name-collision false positives; cap their bonus
        if angle_id == "A-RACE":
            bonus = min(4, len(contracts) - 1)
        else:
            bonus = 2 * (len(contracts) - 1)
        score += bonus
        rationale.append(f"cross-contract={len(contracts)} (+{bonus})")
    
    # Check angle ID for specific bonuses
    if angle_id == "A-REENT":
        score += 3
        rationale.append("reentrancy surface (+3)")
    elif angle_id == "A-AUTH":
        score += 3
        rationale.append("unauthenticated state write (+3)")
    elif angle_id == "A-ORACLE":
        score += 2
        rationale.append("oracle manipulation (+2)")
    elif angle_id == "A-DELEGATE":
        score += 3
        rationale.append("delegatecall hijack (+3)")
    elif angle_id == "A-ERC4626":
        score += 2
        rationale.append("ERC4626 inflation (+2)")
    elif angle_id == "A-FLASH":
        score += 3
        rationale.append("flash loan reentrancy (+3)")
    elif angle_id == "A-TIMESTAMP":
        score += 1
        rationale.append("timestamp dependence (+1)")
    
    # Prior submission penalty
    penalty, reason = check_prior_overlap(angle, subs)
    if penalty < 0:
        score += penalty
        rationale.append(f"prior overlap ({penalty:.1f}) — {reason}")
    
    return score, rationale


def apply_topology_adjustments(angle: Dict, topology: Dict[str, Dict[str, Any]]) -> Tuple[float, List[str]]:
    """Small scoring adjustments based on deployment-topology evidence."""
    contracts = [contract for contract in angle.get("contracts", []) if isinstance(contract, str)]
    if not contracts:
        return 0.0, []

    matched = [topology.get(contract) for contract in contracts if topology.get(contract)]
    if not matched:
        return 0.0, []

    score = 0.0
    rationale: List[str] = []
    resolved = any(entry.get("status") == "resolved" for entry in matched)
    ambiguous = any(entry.get("status") == "ambiguous" for entry in matched)
    unresolved = all(entry.get("status") == "unresolved" for entry in matched)
    rpc_ready = any(entry.get("rpc_ready") for entry in matched)

    if resolved:
        score += 1.0
        rationale.append("deployment address resolved (+1.0)")
    if rpc_ready:
        score += 0.5
        rationale.append("workspace RPC configured (+0.5)")
    if not resolved and ambiguous:
        score -= 0.5
        rationale.append("deployment topology ambiguous (-0.5)")
    elif unresolved:
        score -= 0.5
        rationale.append("deployment topology unresolved (-0.5)")
    return score, rationale


def apply_live_check_adjustments(angle: Dict, live_checks: Dict[str, List[Dict[str, Any]]]) -> Tuple[float, List[str]]:
    """Small scoring/rationale adjustments based on live-topology dossier state."""
    contracts = [contract for contract in angle.get("contracts", []) if isinstance(contract, str)]
    if not contracts:
        return 0.0, []

    matched: List[Dict[str, Any]] = []
    for contract in contracts:
        matched.extend(
            entry
            for entry in live_checks.get(contract, [])
            if angle_matches_live_check(angle, entry)
        )
    if not matched:
        return 0.0, []

    statuses = {str(entry.get("status") or "") for entry in matched}
    evidence_classes = {str(entry.get("evidence_class") or "") for entry in matched}
    score = 0.0
    rationale: List[str] = []
    relation_rows = [entry for entry in matched if str(entry.get("evidence_class") or "") == "topology-relation"]
    generated_relation_rows = [
        entry for entry in relation_rows
        if bool(entry.get("generated")) or str(entry.get("spec_source") or "") == "generated-relation"
    ]
    paired_generated_rows = pairable_generated_relations(angle, relation_rows)
    paired_generated_contracts = {
        str(entry.get("contract") or "").strip()
        for entry in paired_generated_rows
        if str(entry.get("contract") or "").strip()
    }

    if "pass" in statuses or "fail" in statuses:
        score += 0.5
        rationale.append(f"angle-linked live checks executable (+0.5, rows={len(matched)})")
    if "fail" in statuses:
        score += 0.5
        rationale.append("angle-linked live mismatch observed (+0.5)")
    if relation_rows and ("pass" in statuses or "fail" in statuses):
        score += 0.75
        rationale.append(f"topology-relation proof executable (+0.75, rows={len(relation_rows)})")
    if generated_relation_rows and ("pass" in statuses or "fail" in statuses):
        score += 0.5
        rationale.append(
            f"source-backed generated relation proof executable (+0.5, rows={len(generated_relation_rows)})"
        )
    if len(paired_generated_contracts) >= 2 and ("pass" in statuses or "fail" in statuses):
        score += 0.75
        rationale.append(
            "paired source-backed generated relation proof executable (+0.75)"
        )
    if relation_rows and "fail" in statuses:
        score += 0.75
        rationale.append("topology-relation mismatch observed (+0.75)")
    if generated_relation_rows and "fail" in statuses:
        score += 0.5
        rationale.append("source-backed generated relation mismatch observed (+0.5)")
    if "dry_run" in statuses:
        rationale.append("angle-linked live checks scaffolded (dry-run only)")
        if relation_rows:
            rationale.append("topology-relation checks scaffolded (dry-run only)")
        if generated_relation_rows:
            rationale.append("source-backed generated relation checks scaffolded (dry-run only)")
        if len(paired_generated_contracts) >= 2:
            score += 0.25
            rationale.append("paired source-backed generated relation scaffold exists (+0.25)")
    if "blocked_missing_rpc" in statuses:
        rationale.append("angle-linked live checks blocked on RPC")
    if "blocked_unresolved_address" in statuses:
        score -= 0.25
        rationale.append("angle-linked live checks blocked on address resolution (-0.25)")
        if relation_rows:
            rationale.append("topology-relation checks blocked on address resolution")
        if generated_relation_rows:
            rationale.append("source-backed generated relation checks blocked on address resolution")
    if "error" in statuses:
        score -= 0.5
        rationale.append("angle-linked live check runner error (-0.5)")

    return score, rationale


def main() -> None:
    parser = argparse.ArgumentParser(description="Mining priority scorer")
    parser.add_argument("workspace", help="Workspace directory")
    parser.add_argument("--top", type=int, default=20, help="Show top N angles")
    parser.add_argument("--unmined-only", action="store_true", help="Only show angles not near prior submissions")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    parser.add_argument("--out", help="Optional JSON output path for ranked priorities")
    parser.add_argument("--min-score", type=float, default=0, help="Minimum score to include")
    parser.add_argument(
        "--no-outcome-reweight",
        action="store_true",
        help="Disable PR 112 outcome-driven reweighting (A/B comparison + fallback).",
    )
    parser.add_argument(
        "--outcomes-path",
        default=str(DEFAULT_OUTCOMES_PATH),
        help="Path to reference/outcomes.jsonl for outcome reweighting.",
    )
    args = parser.parse_args()

    ws = Path(args.workspace).expanduser().resolve()
    if not ws.exists():
        print(f"[prio] Workspace not found: {ws}")
        sys.exit(1)

    ccia, angles = load_ccia(ws)
    if not angles:
        print(f"[prio] No CCIA angles found. Run CCIA first.")
        sys.exit(1)

    subs = load_prior_submissions(ws)
    topology = load_topology(ws)
    live_checks = load_live_checks(ws)
    asset_plan = load_asset_coverage_plan(ws)
    per_asset_allocation = compute_per_asset_allocation(asset_plan)
    semantic_path_inventory = load_semantic_path_inventory(ws)
    semantic_graph_query_results = load_semantic_graph_query_results(ws)
    semantic_detector_worklist = load_semantic_detector_worklist(ws)
    semantic_detector_adjudication = load_semantic_detector_adjudication(ws)
    impact_family_worklists = load_impact_family_worklists(ws)

    # PR 112 — outcome-driven reweight (additive, NOT a replacement).
    reweight_enabled = not args.no_outcome_reweight
    outcomes_path = Path(args.outcomes_path).expanduser()
    history: Dict[str, Any] = {}
    if reweight_enabled:
        if outcomes_path.exists():
            history = load_outcome_history(outcomes_path)
        else:
            print(
                "[mining-prioritizer] no outcome history; running in baseline mode",
                file=sys.stderr if args.json else sys.stdout,
            )

    print(
        f"[prio] Loaded {len(angles)} angle(s), {len(subs)} prior submission(s), "
        f"{len(topology)} topology entrie(s), {sum(len(v) for v in live_checks.values())} live check row(s)",
        file=sys.stderr if args.json else sys.stdout,
    )

    scored = []
    for angle in angles:
        score, rationale = score_angle(angle, subs, ccia)
        topo_score, topo_rationale = apply_topology_adjustments(angle, topology)
        score += topo_score
        rationale.extend(topo_rationale)
        live_score, live_rationale = apply_live_check_adjustments(angle, live_checks)
        score += live_score
        rationale.extend(live_rationale)

        pre_reweight_score = score
        reweight_delta = 0.0
        reweight_rationale: List[str] = []
        if reweight_enabled and history:
            reweight_delta, reweight_rationale = compute_reweight(
                angle, history, ws.name
            )
            score += reweight_delta
            rationale.extend(reweight_rationale)

        if score < args.min_score:
            continue
        if args.unmined_only and any("prior overlap" in r for r in rationale):
            continue
        scored.append({
            "angle": angle,
            "score": score,
            "pre_reweight_score": pre_reweight_score,
            "reweight_delta": reweight_delta,
            "reweight_rationale": reweight_rationale,
            "rationale": rationale,
            "impact_contract": summarize_angle_impact_contract(ws, angle),
        })

    scored.sort(key=lambda x: x["score"], reverse=True)

    output = [
        {
            "rank": i + 1,
            "id": s["angle"]["id"],
            "severity": s["angle"].get("severity", "?"),
            "title": s["angle"].get("title", ""),
            "score": s["score"],
            "pre_reweight_score": s.get("pre_reweight_score", s["score"]),
            "reweight_delta": s.get("reweight_delta", 0.0),
            "reweight_rationale": s.get("reweight_rationale", []),
            "outcome_history_version": history_version(history) if reweight_enabled else "disabled",
            "rationale": s["rationale"],
            "contracts": s["angle"].get("contracts", []),
            "impact_contract": s.get("impact_contract", {}),
        }
        for i, s in enumerate(scored[:args.top])
    ]

    # Gap E / PR560 — wrap the flat angle list when sidecar inventory exists.
    # Back-compat: no asset plan and no semantic graph still emits the
    # historical flat list. mining-brief-generator accepts both shapes.
    if (
        per_asset_allocation
        or semantic_path_inventory
        or semantic_graph_query_results
        or semantic_detector_worklist
        or semantic_detector_adjudication
        or impact_family_worklists
    ):
        wrapped_output: Any = {
            "angles": output,
            "outcome_history_version": (
                history_version(history) if reweight_enabled else "disabled"
            ),
        }
        if per_asset_allocation:
            wrapped_output["per_asset_allocation"] = per_asset_allocation
        if semantic_path_inventory:
            wrapped_output["semantic_path_inventory"] = semantic_path_inventory
        if semantic_graph_query_results:
            wrapped_output["semantic_graph_query_results"] = semantic_graph_query_results
        if semantic_detector_worklist:
            wrapped_output["semantic_detector_worklist"] = semantic_detector_worklist
        if semantic_detector_adjudication:
            wrapped_output["semantic_detector_adjudication"] = semantic_detector_adjudication
        if impact_family_worklists:
            wrapped_output["impact_family_worklists"] = impact_family_worklists
    else:
        wrapped_output = output

    if args.out:
        out_path = Path(args.out).expanduser().resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(wrapped_output, indent=2) + "\n")

    if args.json:
        print(json.dumps(wrapped_output, indent=2))
    else:
        print(f"\n{'Rank':<6} {'Score':<6} {'ID':<12} {'Severity':<8} {'Title'}")
        print("-" * 90)
        for i, s in enumerate(scored[:args.top], 1):
            angle = s["angle"]
            title = angle.get("title", "")[:50]
            print(f"{i:<6} {s['score']:<6.1f} {angle['id']:<12} {angle.get('severity', '?'):<8} {title}")
            for r in s["rationale"]:
                print(f"       → {r}")
            print()

    footer_stream = sys.stderr if args.json else sys.stdout
    print(f"[prio] Top {min(args.top, len(scored))} of {len(scored)} angles shown", file=footer_stream)
    if args.out:
        print(f"[prio] Wrote ranked priorities to {args.out}", file=footer_stream)


if __name__ == "__main__":
    main()
