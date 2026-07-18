#!/usr/bin/env python3
"""Backfill impact-proof source citations without promoting proof.

This PR560 closure helper consumes the impact-proof execution ledger and checks
whether rows blocked on source proof can be linked to exact project source
citations. It deliberately treats semantic-graph matches as advisory hints:
they may identify where a human/agent should run source review next, but they do
not prove the listed impact or make any row submit-ready.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.pr560.impact_proof_source_citation_backfill.v1"
DEFAULT_IN = ".auditooor/impact_proof_requirement_execution.json"
DEFAULT_OUT = ".auditooor/impact_proof_source_citation_backfill.json"
DEFAULT_OUT_MD = ".auditooor/impact_proof_source_citation_backfill.md"
DEFAULT_BLOCKER_DIR = ".auditooor/impact_proof_source_citation_blockers"
DEFAULT_CANDIDATE_DIR = ".auditooor/impact_proof_source_citation_candidates"
PROOF_BOUNDARY = (
    "Source-citation backfill rows are proof-path accounting only; they do not "
    "prove listed impact, set severity, authorize submission, or override OOS/scope gates."
)


GENERATED_PREFIXES = (
    ".auditooor/",
    "agent_outputs/",
    "poc-tests/",
    "poc_execution/",
    "source_proofs/",
    "submissions/",
)


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.rstrip() + "\n", encoding="utf-8")


def slug(value: str) -> str:
    return re.sub(r"[^a-z0-9_.-]+", "-", value.lower()).strip("-") or "item"


def list_rows(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        rows = payload.get("rows") or payload.get("items") or []
    elif isinstance(payload, list):
        rows = payload
    else:
        rows = []
    return [row for row in rows if isinstance(row, dict)]


def rel_path(workspace: Path, path_text: str) -> str:
    if not path_text:
        return ""
    path = Path(path_text)
    try:
        return str(path.resolve().relative_to(workspace.resolve()))
    except (OSError, ValueError):
        return str(path_text)


def is_generated_path(path_text: str) -> bool:
    value = str(path_text or "").lstrip("./")
    return value.startswith(GENERATED_PREFIXES)


def citation_from_dict(workspace: Path, citation: dict[str, Any]) -> dict[str, Any]:
    raw_path = str(citation.get("path") or citation.get("file") or "")
    rel = rel_path(workspace, raw_path)
    start = int(citation.get("start_line") or citation.get("line") or 0)
    end = int(citation.get("end_line") or start or 0)
    path = workspace / rel if rel and not Path(rel).is_absolute() else Path(raw_path)
    exists = bool(citation.get("exists")) if "exists" in citation else path.exists()
    valid_lines = bool(citation.get("valid_lines")) if "valid_lines" in citation else start > 0
    return {
        "raw": str(citation.get("raw") or (f"{rel}:{start}" if rel and start else "")),
        "path": rel,
        "start_line": start,
        "end_line": end,
        "exists": exists,
        "valid_lines": valid_lines,
        "project_source": exists and valid_lines and bool(rel) and not is_generated_path(rel),
    }


def load_source_proof(workspace: Path, path_text: str) -> dict[str, Any]:
    path = Path(path_text)
    if not path.is_absolute():
        path = workspace / path
    payload = read_json(path)
    if not isinstance(payload, dict):
        return {"path": str(path), "exists": False}
    citations = [
        citation_from_dict(workspace, item)
        for item in payload.get("source_citations") or []
        if isinstance(item, dict)
    ]
    return {
        "path": str(path),
        "exists": True,
        "candidate_id": str(payload.get("candidate_id") or ""),
        "final_verdict": str(payload.get("final_verdict") or ""),
        "impact_contract_linked": bool(payload.get("impact_contract_linked")),
        "promotion_allowed": bool(payload.get("promotion_allowed")),
        "valid_source_citation_count": int(payload.get("valid_source_citation_count") or 0),
        "source_citations": citations,
        "project_source_citation_count": sum(1 for item in citations if item["project_source"]),
        "evidence_class": str(payload.get("evidence_class") or ""),
    }


def source_proof_paths(row: dict[str, Any]) -> list[str]:
    paths: list[str] = []
    for item in row.get("source_proofs") or []:
        if isinstance(item, dict) and item.get("path"):
            paths.append(str(item["path"]))
    local = row.get("local_artifacts") or {}
    for path in local.get("source_proof_paths") or []:
        if isinstance(path, str):
            paths.append(path)
    return sorted(set(paths))


def semantic_hints(workspace: Path, route_family: str, limit: int) -> list[dict[str, Any]]:
    graph = read_json(workspace / ".auditooor" / "semantic_graph.scoped.json")
    if not isinstance(graph, dict):
        graph = read_json(workspace / ".auditooor" / "semantic_graph.json")
    if not isinstance(graph, dict):
        return []
    hints: list[dict[str, Any]] = []
    for path in graph.get("multi_hop_paths") or []:
        if not isinstance(path, dict) or str(path.get("impact_family") or "") != route_family:
            continue
        edges = []
        for edge in path.get("evidence_edges") or []:
            if not isinstance(edge, dict):
                continue
            file = str(edge.get("file") or "")
            line = int(edge.get("line") or 0)
            if file and line:
                edges.append(
                    {
                        "path": file,
                        "line": line,
                        "stage": str(edge.get("stage") or ""),
                        "evidence": str(edge.get("evidence") or ""),
                    }
                )
        if edges:
            hints.append(
                {
                    "source": "semantic_graph.multi_hop_paths",
                    "path_id": str(path.get("path_id") or ""),
                    "source_component": str(path.get("source_component") or ""),
                    "impact_family": route_family,
                    "citations": edges[:5],
                    "advisory_only": True,
                }
            )
        if len(hints) >= limit:
            break
    if hints:
        return hints
    for edge in graph.get("evidence_edges") or []:
        if not isinstance(edge, dict):
            continue
        stage = str(edge.get("stage") or "")
        evidence = str(edge.get("evidence") or "")
        blob = f"{stage} {evidence}".lower()
        tokens = [token for token in route_family.split("_") if len(token) > 3]
        if not any(token in blob for token in tokens):
            continue
        file = str(edge.get("file") or "")
        line = int(edge.get("line") or 0)
        if file and line:
            hints.append(
                {
                    "source": "semantic_graph.evidence_edges",
                    "path_id": str(edge.get("edge_id") or ""),
                    "source_component": f"{edge.get('source_contract', '')}.{edge.get('source_function', '')}".strip("."),
                    "impact_family": route_family,
                    "citations": [{"path": file, "line": line, "stage": stage, "evidence": evidence}],
                    "advisory_only": True,
                }
            )
        if len(hints) >= limit:
            break
    return hints


def semantic_hint_index(workspace: Path, limit: int) -> dict[str, list[dict[str, Any]]]:
    graph = read_json(workspace / ".auditooor" / "semantic_graph.scoped.json")
    if not isinstance(graph, dict):
        graph = read_json(workspace / ".auditooor" / "semantic_graph.json")
    if not isinstance(graph, dict):
        return {}
    indexed: dict[str, list[dict[str, Any]]] = {}
    for path in graph.get("multi_hop_paths") or []:
        if not isinstance(path, dict):
            continue
        family = str(path.get("impact_family") or "")
        if not family or len(indexed.get(family, [])) >= limit:
            continue
        edges = []
        for edge in path.get("evidence_edges") or []:
            if not isinstance(edge, dict):
                continue
            file = str(edge.get("file") or "")
            line = int(edge.get("line") or 0)
            if file and line:
                edges.append(
                    {
                        "path": file,
                        "line": line,
                        "stage": str(edge.get("stage") or ""),
                        "evidence": str(edge.get("evidence") or ""),
                    }
                )
        if edges:
            indexed.setdefault(family, []).append(
                {
                    "source": "semantic_graph.multi_hop_paths",
                    "path_id": str(path.get("path_id") or ""),
                    "source_component": str(path.get("source_component") or ""),
                    "impact_family": family,
                    "citations": edges[:5],
                    "advisory_only": True,
                }
            )
    families = {
        "access_control",
        "asset_custody",
        "availability_dos",
        "bridge_finalization",
        "consensus_safety",
        "governance_integrity",
        "liquidation_solvency",
        "node_liveness",
        "oracle_settlement",
        "proof_verification",
        "resource_consumption",
        "signature_replay",
    }
    for edge in graph.get("evidence_edges") or []:
        if not isinstance(edge, dict):
            continue
        stage = str(edge.get("stage") or "")
        evidence = str(edge.get("evidence") or "")
        blob = f"{stage} {evidence}".lower()
        file = str(edge.get("file") or "")
        line = int(edge.get("line") or 0)
        if not file or not line:
            continue
        for family in families:
            if len(indexed.get(family, [])) >= limit:
                continue
            tokens = [token for token in family.split("_") if len(token) > 3]
            if any(token in blob for token in tokens):
                indexed.setdefault(family, []).append(
                    {
                        "source": "semantic_graph.evidence_edges",
                        "path_id": str(edge.get("edge_id") or ""),
                        "source_component": f"{edge.get('source_contract', '')}.{edge.get('source_function', '')}".strip("."),
                        "impact_family": family,
                        "citations": [{"path": file, "line": line, "stage": stage, "evidence": evidence}],
                        "advisory_only": True,
                    }
                )
    return indexed


def next_commands(workspace: Path, row: dict[str, Any], hints: list[dict[str, Any]]) -> list[str]:
    candidate = str(row.get("candidate_id") or "")
    route_family = str(row.get("route_family") or "")
    commands = [
        f"make source-proof-record WS={workspace} CANDIDATE={candidate} CITATION='<project-source-file:line>' OOS=in_scope VERDICT=proved_source_only NOTE='Exact {route_family} source citation; still requires impact execution proof'",
        f"make impact-proof-requirement-executor WS={workspace} JSON=1",
    ]
    if hints:
        first = hints[0]["citations"][0]
        commands.insert(
            0,
            f"rg -n \"{str(first.get('evidence') or route_family).replace(chr(34), '')[:80]}\" {workspace / str(first.get('path'))}",
        )
    else:
        commands.insert(
            0,
            f"make semantic-graph-query WS={workspace} IMPACT_WORKLIST=1 JSON=1",
        )
    return commands


def decision_for(row: dict[str, Any], proofs: list[dict[str, Any]], hints: list[dict[str, Any]]) -> tuple[str, list[str]]:
    blockers = set(str(item) for item in row.get("terminal_blockers") or [] if item)
    if not bool(row.get("listed_impact_proven")):
        blockers.add("listed_impact_not_proven")
    if not proofs:
        blockers.add("missing_source_proof_record")
        blockers.add("missing_project_specific_proof_path")
        if hints:
            blockers.add("semantic_graph_hints_advisory_not_project_specific_proof")
        else:
            blockers.add("no_semantic_graph_source_hint")
        return "terminal_missing_project_specific_proof_path", sorted(blockers)
    if any(proof.get("project_source_citation_count", 0) > 0 for proof in proofs):
        if bool(row.get("listed_impact_proven")):
            return "source_citation_backfilled_requires_execution_scope_oos", sorted(blockers)
        blockers.add("source_citation_present_but_listed_impact_unproved")
        blockers.add("missing_poc_execution_manifest")
        return "source_citation_backfilled_impact_unproved", sorted(blockers)
    blockers.add("source_proof_missing_project_source_citation")
    if hints:
        blockers.add("semantic_graph_hints_advisory_not_exact_source_proof")
        return "terminal_source_citation_missing_with_advisory_hints", sorted(blockers)
    blockers.add("no_semantic_graph_source_hint")
    return "terminal_source_citation_missing_no_hint", sorted(blockers)


def build_payload(workspace: Path, *, manifest_path: Path, hint_limit: int, write_rows: bool) -> dict[str, Any]:
    execution = read_json(manifest_path)
    rows = list_rows(execution)
    out_rows: list[dict[str, Any]] = []
    blocker_dir = workspace / DEFAULT_BLOCKER_DIR
    candidate_dir = workspace / DEFAULT_CANDIDATE_DIR
    hints_by_family = semantic_hint_index(workspace, hint_limit)
    for row in rows:
        blockers = set(str(item) for item in row.get("terminal_blockers") or [])
        target = (
            "source_proof_missing_project_source_citation" in blockers
            or "missing_execution_or_source_proof" in blockers
            or str(row.get("decision") or "") in {
                "terminal_blocker_source_proof_incomplete",
                "terminal_blocker_missing_project_specific_proof",
            }
        )
        if not target:
            continue
        candidate = str(row.get("candidate_id") or "")
        proofs = [load_source_proof(workspace, path) for path in source_proof_paths(row)]
        hints = hints_by_family.get(str(row.get("route_family") or ""), [])
        decision, terminal_blockers = decision_for(row, proofs, hints)
        output_root = candidate_dir if decision.startswith("source_citation_backfilled") else blocker_dir
        output_path = output_root / f"{slug(candidate)}.json"
        out_row = {
            "schema": "auditooor.pr560.impact_proof_source_citation_backfill_row.v1",
            "candidate_id": candidate,
            "requirement_id": str(row.get("requirement_id") or ""),
            "tier": str(row.get("tier") or ""),
            "route_family": str(row.get("route_family") or ""),
            "decision": decision,
            "terminal_blockers": terminal_blockers,
            "source_proofs": proofs,
            "semantic_graph_hints": hints,
            "next_local_commands": next_commands(workspace, row, hints),
            "promotion_allowed": False,
            "submission_posture": "NOT_SUBMIT_READY",
            "proof_boundary": PROOF_BOUNDARY,
            "listed_impact_proven": bool(row.get("listed_impact_proven")),
            "exact_impact_row": bool(row.get("exact_impact_row")),
            "resolution_manifest_path": str(output_path),
        }
        if write_rows:
            write_json(output_path, out_row)
        out_rows.append(out_row)

    decisions = Counter(row["decision"] for row in out_rows)
    terminal_blockers = Counter(blocker for row in out_rows for blocker in row["terminal_blockers"])
    summary = {
        "processed_target_rows": len(out_rows),
        "closure_candidate_count": sum(1 for row in out_rows if row["decision"].startswith("source_citation_backfilled")),
        "terminal_blocker_count": sum(1 for row in out_rows if row["decision"].startswith("terminal_")),
        "decision_counts": dict(sorted(decisions.items())),
        "terminal_blocker_counts": dict(sorted(terminal_blockers.items())),
        "tier_counts": dict(sorted(Counter(row["tier"] for row in out_rows).items())),
        "route_family_counts": dict(sorted(Counter(row["route_family"] for row in out_rows).items())),
        "project_source_citation_rows": sum(
            1
            for row in out_rows
            if any(proof.get("project_source_citation_count", 0) > 0 for proof in row["source_proofs"])
        ),
        "advisory_hint_rows": sum(1 for row in out_rows if row["semantic_graph_hints"]),
        "blocker_dir": str(blocker_dir),
        "candidate_dir": str(candidate_dir),
    }
    return {
        "schema": SCHEMA,
        "generated_at": now_iso(),
        "workspace": str(workspace),
        "source_manifest": str(manifest_path),
        "status": "NOT_SUBMIT_READY",
        "submission_posture": "NOT_SUBMIT_READY",
        "promotion_allowed": False,
        "proof_boundary": PROOF_BOUNDARY,
        "summary": summary,
        "rows": out_rows,
    }


def render_markdown(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    lines = [
        "# Impact-Proof Source Citation Backfill",
        "",
        f"- Status: `{payload['status']}`",
        f"- Target rows processed: {summary['processed_target_rows']}",
        f"- Source-citation backfill candidates: {summary['closure_candidate_count']}",
        f"- Terminal blockers: {summary['terminal_blocker_count']}",
        f"- Rows with project source citations: {summary['project_source_citation_rows']}",
        f"- Rows with advisory semantic hints: {summary['advisory_hint_rows']}",
        "",
        "## Decisions",
    ]
    for key, value in summary["decision_counts"].items():
        lines.append(f"- `{key}`: {value}")
    lines.extend(["", "## Top Blockers"])
    for key, value in sorted(summary["terminal_blocker_counts"].items(), key=lambda item: (-item[1], item[0]))[:20]:
        lines.append(f"- `{key}`: {value}")
    lines.extend(["", "## Sample Rows"])
    for row in payload["rows"][:20]:
        lines.append(
            f"- `{row['candidate_id']}` `{row['decision']}` next: `{row['next_local_commands'][0]}`"
        )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--manifest", default=DEFAULT_IN)
    parser.add_argument("--out", default=DEFAULT_OUT)
    parser.add_argument("--out-md", default=DEFAULT_OUT_MD)
    parser.add_argument("--hint-limit", type=int, default=3)
    parser.add_argument("--no-row-manifests", action="store_true")
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args()
    workspace = Path(args.workspace).expanduser().resolve()
    if not workspace.exists():
        raise SystemExit(f"[impact-proof-source-citation-backfill] ERR workspace not found: {workspace}")
    manifest = Path(args.manifest)
    if not manifest.is_absolute():
        manifest = workspace / manifest
    if not manifest.exists():
        raise SystemExit(f"[impact-proof-source-citation-backfill] ERR manifest not found: {manifest}")
    payload = build_payload(
        workspace,
        manifest_path=manifest,
        hint_limit=max(0, args.hint_limit),
        write_rows=not args.no_row_manifests,
    )
    out = Path(args.out)
    if not out.is_absolute():
        out = workspace / out
    out_md = Path(args.out_md)
    if not out_md.is_absolute():
        out_md = workspace / out_md
    write_json(out, payload)
    write_text(out_md, render_markdown(payload))
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        summary = payload["summary"]
        print(
            "[impact-proof-source-citation-backfill] "
            f"rows={summary['processed_target_rows']} candidates={summary['closure_candidate_count']} "
            f"terminal={summary['terminal_blocker_count']} hints={summary['advisory_hint_rows']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
