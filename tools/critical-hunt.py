#!/usr/bin/env python3
# SCOPE-TIER: lightweight advisory dossier emitter for high-impact surfaces only.
# NOT a duplicate of hunt-orchestrate.py (full-ws 10-step driver) or
# base-critical-hunt.py (5-step critical-candidate verifier) - each covers a distinct tier.
"""Opt-in critical-candidate hunter.

This consumes the semantic graph and emits conservative dossiers for high
impact surfaces only. It never writes submission text and never calls anything
Critical; candidates start as `needs_production_path`.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SEMANTIC_GRAPH = ROOT / "tools" / "semantic-graph.py"
SCHEMA_VERSION = "auditooor.critical_candidates.v1"

SURFACE_KEYWORDS = {
    "asset-custody": ("withdraw", "deposit", "transfer", "claim", "redeem", "sweep", "mint", "burn"),
    "bridge-finalization": ("bridge", "withdrawal", "finalize", "portal", "dispute", "game"),
    "oracle-settlement": ("oracle", "price", "settle", "liquidat", "resolve"),
    "signature-proof": ("signature", "permit", "verify", "proof", "tee", "zk"),
    "upgrade-factory": ("upgrade", "factory", "clone", "proxy", "implementation"),
    "fee-share-math": ("fee", "share", "round", "account", "collateral", "debt"),
    "cross-domain-message": ("message", "domain", "chain", "relay", "nonce"),
}


def _load_exact_impact_contracts(workspace: Path) -> dict[str, dict[str, Any]]:
    path = workspace / ".auditooor" / "impact_contracts.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}
    if not isinstance(payload, dict):
        return {}
    contracts = payload.get("contracts")
    if not isinstance(contracts, list):
        return {}
    out: dict[str, dict[str, Any]] = {}
    for contract in contracts:
        if not isinstance(contract, dict):
            continue
        candidate_id = str(contract.get("candidate_id") or "").strip()
        selected = str(
            contract.get("selected_impact")
            or contract.get("original_selected_impact")
            or ""
        ).strip()
        if candidate_id and contract.get("exact_impact_row") is True and selected:
            out[candidate_id] = contract
    return out


def _load_impact_family_worklists(workspace: Path) -> dict[str, Any]:
    path = workspace / ".auditooor" / "impact_family_worklists.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}
    if not isinstance(payload, dict):
        return {}
    rows = payload.get("worklists") if isinstance(payload.get("worklists"), list) else []
    return {
        "artifact": str(path),
        "status": payload.get("status", ""),
        "worklist_count": len(rows),
        "advisory_only": True,
        "promotion_allowed": False,
        "submission_posture": "NOT_SUBMIT_READY",
        "worklists": [
            {
                "impact_id": row.get("impact_id", ""),
                "impact_family": row.get("impact_family", ""),
                "severity": row.get("severity", ""),
                "impact": row.get("impact", ""),
                "required_evidence_class": row.get("required_evidence_class", ""),
                "relevant_source_roots": row.get("relevant_source_roots", []),
                "component_count": row.get("component_count", 0),
                "components": row.get("components", [])[:8],
                "oos_traps": row.get("oos_traps", [])[:8],
                "status": row.get("status", ""),
                "next_command": row.get("next_command", ""),
                "submit_ready": False,
            }
            for row in rows[:50]
            if isinstance(row, dict)
        ],
    }


def ensure_graph(workspace: Path) -> dict[str, Any]:
    graph_path = workspace / ".auditooor" / "semantic_graph.json"
    if not graph_path.is_file():
        subprocess.run(
            [sys.executable, str(SEMANTIC_GRAPH), "--workspace", str(workspace)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    data = json.loads(graph_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{graph_path}: expected JSON object")
    return data


def surface_tags(entry: dict[str, Any]) -> list[str]:
    haystack = " ".join(
        [
            str(entry.get("contract", "")),
            str(entry.get("function", "")),
            " ".join(entry.get("state_writes") or []),
            " ".join(entry.get("external_calls") or []),
        ]
    ).lower()
    tags = [
        tag
        for tag, keywords in SURFACE_KEYWORDS.items()
        if any(keyword.lower() in haystack for keyword in keywords)
    ]
    if entry.get("value_movement") and "asset-custody" not in tags:
        tags.append("asset-custody")
    return sorted(tags)


def build_candidates(
    graph: dict[str, Any],
    impact_contracts: dict[str, dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    exact_contracts = impact_contracts or {}
    candidates: list[dict[str, Any]] = []
    for entry in graph.get("entrypoints", []) if isinstance(graph.get("entrypoints"), list) else []:
        if not isinstance(entry, dict):
            continue
        tags = surface_tags(entry)
        if not tags:
            continue
        candidate_id = "{contract}:{function}:{line}".format(
            contract=entry.get("contract", "unknown"),
            function=entry.get("function", "unknown"),
            line=entry.get("line", 0),
        )
        blockers = ["production_path_unproven", "runnable_proof_missing"]
        if entry.get("privileged"):
            blockers.append("privileged_entrypoint")
        impact_contract = exact_contracts.get(candidate_id)
        impact_contract_id = str(
            (impact_contract or {}).get("impact_contract_id")
            or (impact_contract or {}).get("contract_id")
            or ""
        ).strip()
        impact_contract_linked = bool(impact_contract)
        impact_contract_status = (
            "exact_impact_contract_linked"
            if impact_contract_linked
            else "missing_exact_impact_contract"
        )
        if not impact_contract_linked:
            blockers.append("missing_exact_impact_contract")
        next_actions = [
            "Build or cite production_path_dossier.json for this entrypoint.",
            "Write the smallest runnable PoC/replay only if external reachability is proven.",
            "Run Minimax OOS/FP kill pass before drafting any report text.",
        ]
        if not impact_contract_linked:
            next_actions.insert(
                0,
                "Use impact_family_worklists to pick scoped roots/components, then create an exact impact_contract row before severity or direct-submit posture.",
            )
        candidates.append({
            "candidate_id": candidate_id,
            "surface_tags": tags,
            "entrypoint": entry,
            "status": "needs_production_path",
            "candidate_status": "not_submit_ready",
            "advisory_only": not impact_contract_linked,
            "reportable_status": (
                "impact_contract_linked_proof_required"
                if impact_contract_linked
                else "advisory_missing_exact_impact_contract"
            ),
            "severity_claim": "none",
            "severity_ceiling": "none",
            "submission_posture": "not_submit_ready",
            "submit_verdict": "not_submission_ready",
            "impact_contract_id": impact_contract_id,
            "impact_contract_linked": impact_contract_linked,
            "impact_contract_status": impact_contract_status,
            "blockers": sorted(set(blockers)),
            "next_actions": next_actions,
        })
    return candidates


def semantic_path_inventory(graph: dict[str, Any], limit: int = 50) -> dict[str, Any]:
    """Return bounded advisory path accounting from the semantic graph.

    Critical-hunt candidates are entrypoint-focused. This sidecar preserves
    cross-contract relation and multi-hop rows that may not yet map to a
    candidate, without upgrading them into findings or severity claims.
    """
    relation_edges = graph.get("relation_edges") if isinstance(graph.get("relation_edges"), list) else []
    multi_hop_paths = graph.get("multi_hop_paths") if isinstance(graph.get("multi_hop_paths"), list) else []
    return {
        "coverage_claim": "none_source_shape_only",
        "relation_edge_count": graph.get("relation_edge_count", len(relation_edges)),
        "multi_hop_path_count": graph.get("multi_hop_path_count", len(multi_hop_paths)),
        "relation_edge_worklist": [
            {
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
                "next_action": (
                    "map typed-receiver relation edge to detector predicate or exact-impact candidate"
                    if edge.get("target_type")
                    else "map relation edge to detector predicate or exact-impact candidate"
                ),
            }
            for edge in relation_edges[:limit]
            if isinstance(edge, dict)
        ],
        "multi_hop_path_worklist": [
            {
                "path_id": row.get("path_id", ""),
                "impact_family": row.get("impact_family", ""),
                "source_component": row.get("source_component", ""),
                "mapped_stages": row.get("mapped_stages") or [],
                "missing_stages": row.get("missing_stages") or [],
                "next_action": row.get(
                    "next_action",
                    "route semantic path to exact-impact candidate or mark non-detectorizable",
                ),
            }
            for row in multi_hop_paths[:limit]
            if isinstance(row, dict)
        ],
    }


def render_markdown(payload: dict[str, Any]) -> str:
    inventory = payload.get("semantic_path_inventory")
    impact_worklists = payload.get("impact_family_worklists")
    lines = [
        "# Critical Hunt Candidates",
        "",
        "This is an opt-in high-impact surface shortlist. It is not a finding",
        "list and it contains no severity approval or direct-submit posture.",
        "",
        f"- candidates: {payload.get('candidate_count', 0)}",
        f"- advisory_only_without_exact_impact_contract: {payload.get('advisory_only_without_exact_impact_contract', True)}",
    ]
    if isinstance(inventory, dict):
        lines.extend([
            f"- semantic relation edges: {inventory.get('relation_edge_count', 0)}",
            f"- semantic multi-hop paths: {inventory.get('multi_hop_path_count', 0)}",
            f"- semantic coverage claim: `{inventory.get('coverage_claim', 'none_source_shape_only')}`",
        ])
    if isinstance(impact_worklists, dict):
        lines.extend([
            f"- listed-impact worklists: {impact_worklists.get('worklist_count', 0)}",
            f"- listed-impact posture: `{impact_worklists.get('submission_posture', 'NOT_SUBMIT_READY')}`",
        ])
    lines.append("")
    if not payload.get("candidates"):
        lines.extend(["No high-impact surfaces matched by the v1 semantic graph.", ""])
        return "\n".join(lines)
    lines.extend(["| Candidate | Tags | Role | Impact Contract | Blockers |", "|---|---|---|---|---|"])
    for cand in payload["candidates"][:200]:
        entry = cand.get("entrypoint", {})
        lines.append(
            "| `{}` | {} | {} | {} | {} |".format(
                cand.get("candidate_id", ""),
                ", ".join(cand.get("surface_tags") or []),
                entry.get("role", ""),
                cand.get("impact_contract_status", "missing_exact_impact_contract"),
                ", ".join(cand.get("blockers") or []),
            )
        )
    lines.append("")
    if isinstance(inventory, dict) and (
        inventory.get("relation_edge_worklist") or inventory.get("multi_hop_path_worklist")
    ):
        lines.extend([
            "## Semantic Path Worklist",
            "",
            "These rows are source-shape inventory for detector/source-review follow-up; they are not findings.",
            "",
        ])
        for row in (inventory.get("multi_hop_path_worklist") or [])[:20]:
            lines.append(
                "- `{}` {} `{}` stages={}".format(
                    row.get("path_id", ""),
                    row.get("impact_family", ""),
                    row.get("source_component", ""),
                    " -> ".join(row.get("mapped_stages") or []),
                )
            )
        for row in (inventory.get("relation_edge_worklist") or [])[:20]:
            lines.append(
                "- `{}` `{}` -> `{}` method=`{}`".format(
                    row.get("kind", ""),
                    row.get("source", ""),
                    row.get("target", ""),
                    row.get("method", ""),
                )
            )
        lines.append("")
    if isinstance(impact_worklists, dict) and impact_worklists.get("worklists"):
        lines.extend([
            "## Listed Impact Worklists",
            "",
            "These rows choose scoped roots/components before harness/report work; they are not findings.",
            "",
        ])
        for row in impact_worklists.get("worklists", [])[:20]:
            lines.append(
                "- `{}` `{}` components={} evidence=`{}` next=`{}`".format(
                    row.get("impact_id", ""),
                    row.get("impact_family", ""),
                    row.get("component_count", 0),
                    row.get("required_evidence_class", ""),
                    row.get("next_command", ""),
                )
            )
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-md", type=Path)
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args()
    ws = args.workspace.expanduser().resolve()
    if not ws.is_dir():
        print(f"[critical-hunt] ERR workspace not found: {ws}", file=sys.stderr)
        return 2
    graph = ensure_graph(ws)
    impact_contracts = _load_exact_impact_contracts(ws)
    impact_family_worklists = _load_impact_family_worklists(ws)
    candidates = build_candidates(graph, impact_contracts)
    payload = {
        "schema_version": SCHEMA_VERSION,
        "workspace": str(ws),
        "semantic_graph": str(ws / ".auditooor" / "semantic_graph.json"),
        "candidate_count": len(candidates),
        "advisory_only_without_exact_impact_contract": True,
        "semantic_path_inventory": semantic_path_inventory(graph),
        "impact_family_worklists": impact_family_worklists,
        "candidates": candidates,
    }
    out_json = args.out_json or (ws / ".auditooor" / "critical_candidates.json")
    out_md = args.out_md or (ws / ".auditooor" / "critical_candidates.md")
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(payload), encoding="utf-8")
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    print(f"[critical-hunt] OK candidates={len(candidates)} json={out_json}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
