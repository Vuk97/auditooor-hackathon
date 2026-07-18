#!/usr/bin/env python3
"""Inventory semantic/live topology depth blockers for PR560 closure.

This bridge joins the semantic graph/scanner inventory with live topology
proof-pair evidence. It does not prove findings. Its job is to make the next
depth blocker explicit per row, especially when source-shape semantic evidence
has no same-block live proof pair or when proxy/delegate/Rust runtime depth is
still outside the current model.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.semantic_live_depth_blockers.v1"
GENERATED_EVIDENCE_CLASS = "generated_hypothesis"
DEFAULT_LIMIT = 400
SOURCE_SHAPE_LIMITATIONS = [
    "semantic inputs are source-shape planning evidence unless paired with executed live rows",
    "executed live proof pairs show deployment/config facts only, not vulnerability impact",
    "proxy/delegate/facet/factory paths still require production-path proof before promotion",
    "Rust/DLT rows still require trait/cfg/runtime-state resolution before promotion",
    "all rows remain NOT_SUBMIT_READY until exact impact proof and execution artifacts exist",
]


def _load_json(path: Path, *, required: bool = False) -> dict[str, Any]:
    if not path.is_file():
        if required:
            raise SystemExit(f"[semantic-live-depth-blockers] missing JSON artifact: {path}")
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"[semantic-live-depth-blockers] unreadable JSON artifact: {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit(f"[semantic-live-depth-blockers] expected object JSON: {path}")
    return payload


def _semantic_item_count(graph: dict[str, Any]) -> int:
    return len(graph.get("relation_edges") or []) + len(graph.get("multi_hop_paths") or [])


def _generate_scoped_graph(workspace: Path, *, limit: int) -> tuple[Path, dict[str, Any]]:
    audit_dir = workspace / ".auditooor"
    out_path = audit_dir / "semantic_graph.scoped.json"
    tool = Path(__file__).resolve().with_name("semantic-graph.py")
    proc = subprocess.run(
        [
            sys.executable,
            str(tool),
            "--workspace",
            str(workspace),
            "--scoped",
            "--target-items",
            str(limit),
            "--min-items",
            "300",
            "--max-items",
            "500",
            "--out-json",
            str(out_path),
            "--out-md",
            str(audit_dir / "semantic_graph.scoped.md"),
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        raise SystemExit(
            "[semantic-live-depth-blockers] failed to generate scoped semantic graph: "
            + (proc.stderr or proc.stdout)
        )
    return out_path, _load_json(out_path, required=True)


def _resolve_graph(workspace: Path, explicit_graph: Path | None, *, limit: int) -> tuple[Path, dict[str, Any], str]:
    if explicit_graph:
        path = explicit_graph.expanduser().resolve()
        return path, _load_json(path, required=True), "explicit_graph"
    audit_dir = workspace / ".auditooor"
    scoped = audit_dir / "semantic_graph.scoped.json"
    if scoped.is_file():
        graph = _load_json(scoped, required=True)
        if 300 <= _semantic_item_count(graph) <= 500 or not (audit_dir / "semantic_graph.json").is_file():
            return scoped, graph, "existing_scoped_graph"
    full = audit_dir / "semantic_graph.json"
    if full.is_file():
        graph = _load_json(full, required=True)
        if _semantic_item_count(graph) <= 500:
            return full, graph, "repo_semantic_graph"
    path, graph = _generate_scoped_graph(workspace, limit=limit)
    return path, graph, "generated_scoped_graph"


def _component(contract: Any, function: Any) -> str:
    return "{}.{}".format(contract or "", function or "").strip(".")


def _contract(component: str) -> str:
    return component.split(".", 1)[0] if component else ""


def _is_cross_contract(row: dict[str, Any]) -> bool:
    source = _contract(str(row.get("source_component") or ""))
    target = str(row.get("target_component") or row.get("target") or row.get("target_type") or "")
    target_contract = _contract(target) if "." in target else target
    if not source or not target_contract:
        return False
    return source.lower() != target_contract.lower()


def _needs_production_path_depth(row: dict[str, Any]) -> bool:
    text = " ".join(
        str(row.get(key) or "")
        for key in ("relation_kind", "method", "target_component", "target", "query_shape", "candidate_detector_family")
    ).lower()
    return bool(re.search(r"\b(proxy|clone|factory|delegate|delegatecall|facet|diamond|implementation)\b", text))


def _semantic_rows(graph: dict[str, Any], scanner: dict[str, Any], limit: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in scanner.get("items") or []:
        if isinstance(item, dict):
            rows.append(
                {
                    "source": "semantic_scanner_inventory",
                    "source_id": item.get("inventory_id", ""),
                    "source_component": item.get("source_component", ""),
                    "target_component": item.get("target_component", ""),
                    "relation_kind": item.get("relation_kind", item.get("query_shape", "")),
                    "method": item.get("method", ""),
                    "file": item.get("file", ""),
                    "line": item.get("line", 0),
                    "scanner_inventory_status": item.get("scanner_inventory_status", ""),
                }
            )
            if len(rows) >= limit:
                return rows
    for edge in graph.get("relation_edges") or []:
        if not isinstance(edge, dict):
            continue
        rows.append(
            {
                "source": "semantic_graph.relation_edges",
                "source_id": "{}:{}:{}".format(
                    _component(edge.get("source_contract"), edge.get("source_function")),
                    edge.get("kind", ""),
                    edge.get("line", 0),
                ),
                "source_component": _component(edge.get("source_contract"), edge.get("source_function")),
                "target_component": edge.get("target_type") or edge.get("target") or "",
                "relation_kind": edge.get("kind", ""),
                "method": edge.get("method", ""),
                "file": edge.get("file", ""),
                "line": edge.get("line", 0),
                "scanner_inventory_status": "graph_only_uninventoried",
            }
        )
        if len(rows) >= limit:
            return rows
    for path in graph.get("multi_hop_paths") or []:
        if not isinstance(path, dict):
            continue
        rows.append(
            {
                "source": "semantic_graph.multi_hop_paths",
                "source_id": path.get("path_id", ""),
                "source_component": path.get("source_component", ""),
                "target_component": path.get("sink_component", ""),
                "relation_kind": path.get("impact_family", "multi_hop_path"),
                "method": "",
                "file": "",
                "line": 0,
                "scanner_inventory_status": "graph_only_uninventoried",
            }
        )
        if len(rows) >= limit:
            break
    return rows


def _live_summary(live: dict[str, Any]) -> dict[str, Any]:
    results = [row for row in (live.get("results") or []) if isinstance(row, dict)]
    pairs = [row for row in (live.get("proof_pairs") or []) if isinstance(row, dict)]
    proved_pairs = [row for row in pairs if str(row.get("status") or "") == "proved"]
    executed_results = [
        row for row in results
        if str(row.get("status") or "") in {"pass", "fail"}
    ]
    pair_contracts: dict[str, set[str]] = {}
    by_id = {str(row.get("id") or ""): row for row in results if row.get("id")}
    for pair in pairs:
        contracts = set()
        for row_id in pair.get("row_ids") or []:
            row = by_id.get(str(row_id))
            if row and row.get("contract"):
                contracts.add(str(row.get("contract")))
        if contracts:
            pair_contracts[str(pair.get("id") or "")] = contracts
    return {
        "artifact_present": bool(live),
        "result_count": len(results),
        "executed_result_count": len(executed_results),
        "proof_pair_count": len(pairs),
        "proved_pair_count": len(proved_pairs),
        "proof_pair_status_counts": _counts(str(row.get("status") or "unknown") for row in pairs),
        "proved_pair_ids": [str(row.get("id") or "") for row in proved_pairs if row.get("id")],
        "pair_contracts": {key: sorted(value) for key, value in pair_contracts.items()},
    }


def _counts(values: Any) -> dict[str, int]:
    out: dict[str, int] = {}
    for value in values:
        out[value] = out.get(value, 0) + 1
    return out


def _rust_depth_state(workspace: Path, rust_summary: dict[str, Any]) -> dict[str, Any]:
    roots = [path for path in workspace.rglob("Cargo.toml") if "/vendor/" not in str(path) and "/lib/" not in str(path)]
    semantic_depth = rust_summary.get("semantic_depth_accounting") if isinstance(rust_summary.get("semantic_depth_accounting"), dict) else {}
    return {
        "rust_root_count": len(roots),
        "rust_roots_sample": [str(path.relative_to(workspace)) for path in roots[:8]],
        "rust_scan_summary_present": bool(rust_summary),
        "semantic_depth_accounting": semantic_depth,
        "runtime_depth_closed": bool(semantic_depth.get("runtime_depth_closed")),
    }


def _row_live_evidence(row: dict[str, Any], live_summary: dict[str, Any]) -> dict[str, Any]:
    source_contract = _contract(str(row.get("source_component") or ""))
    target_contract = _contract(str(row.get("target_component") or ""))
    matched_pairs: list[str] = []
    for pair_id, contracts in (live_summary.get("pair_contracts") or {}).items():
        contract_set = {str(contract).lower() for contract in contracts}
        if source_contract.lower() in contract_set and (not target_contract or target_contract.lower() in contract_set):
            matched_pairs.append(str(pair_id))
    proved = [pair_id for pair_id in matched_pairs if pair_id in set(live_summary.get("proved_pair_ids") or [])]
    return {
        "matched_pair_ids": matched_pairs,
        "proved_pair_ids": proved,
        "has_executed_same_block_pair": bool(proved),
    }


def build_payload(
    workspace: Path,
    graph: dict[str, Any],
    scanner: dict[str, Any],
    live: dict[str, Any],
    rust_summary: dict[str, Any],
    *,
    limit: int,
    graph_artifact: Path | None = None,
    graph_source: str = "",
) -> dict[str, Any]:
    semantic = _semantic_rows(graph, scanner, limit)
    live_info = _live_summary(live)
    rust_info = _rust_depth_state(workspace, rust_summary)
    items: list[dict[str, Any]] = []
    for idx, row in enumerate(semantic, start=1):
        blockers: list[str] = []
        blocker_details: list[str] = []
        cross_contract = _is_cross_contract(row)
        if _needs_production_path_depth(row):
            blockers.append("semantic-production-path-depth")
            blocker_details.append("proxy/clone/factory/delegate/facet path needs production-path resolution")
        if cross_contract:
            blockers.append("semantic-cross-contract-proof")
            blocker_details.append("cross-contract source-shape row needs relation edge plus live paired proof or explicit blocker")
        live_evidence = _row_live_evidence(row, live_info)
        if cross_contract and not live_evidence["has_executed_same_block_pair"]:
            blockers.append("semantic-live-proof-pairs")
            blocker_details.append("no executed same-block topology proof pair matched this source/target contract route")
        if rust_info["rust_root_count"] and not rust_info["runtime_depth_closed"]:
            blockers.append("semantic-rust-runtime")
            blocker_details.append("workspace has Rust roots without closed runtime semantic-depth accounting")
        blockers = sorted(set(blockers))
        if not blockers:
            blocker_details.append("no semantic/live depth blocker detected by this inventory; still requires exact impact proof before promotion")
        items.append(
            {
                "item_id": f"SLD-{idx:03d}",
                **row,
                "cross_contract_route": cross_contract,
                "live_evidence": live_evidence,
                "depth_status": "blocked" if blockers else "live_pair_accounted_or_not_cross_contract",
                "blocker_ids": blockers,
                "blocker_details": blocker_details,
                "next_command": _next_command(blockers),
                "coverage_claim": "none_source_shape_only",
                "evidence_class": GENERATED_EVIDENCE_CLASS,
                "advisory_only": True,
                "promotion_allowed": False,
                "severity": "none",
                "selected_impact": "",
                "submission_posture": "NOT_SUBMIT_READY",
                "impact_contract_required": True,
            }
        )
    return {
        "schema": SCHEMA,
        "workspace": str(workspace),
        "limit": limit,
        "source_semantic_graph_artifact": str(graph_artifact or ""),
        "source_semantic_graph_mode": graph_source,
        "source_semantic_graph_selection": graph.get("selection_metadata") or {},
        "item_count": len(items),
        "truncated": len(semantic) >= limit and (
            len(scanner.get("items") or []) + len(graph.get("relation_edges") or []) + len(graph.get("multi_hop_paths") or [])
        ) > limit,
        "coverage_claim": "none_source_shape_only",
        "evidence_class": GENERATED_EVIDENCE_CLASS,
        "advisory_only": True,
        "promotion_allowed": False,
        "severity": "none",
        "selected_impact": "",
        "submission_posture": "NOT_SUBMIT_READY",
        "impact_contract_required": True,
        "source_shape_limitations": SOURCE_SHAPE_LIMITATIONS,
        "live_topology_summary": live_info,
        "rust_runtime_depth_summary": rust_info,
        "blocker_counts": _counts(blocker for item in items for blocker in item["blocker_ids"]),
        "depth_status_counts": _counts(str(item["depth_status"]) for item in items),
        "items": items,
        "next_actions": [
            "Generate or refresh live_topology_checks.json for cross-contract rows that lack executed same-block proof pairs.",
            "Run semantic-scanner-inventory after semantic worklist/query/adjudication so scanner owners get bounded rows.",
            "Keep every row NOT_SUBMIT_READY until exact impact proof, fixture/proof artifacts, and execution evidence exist.",
        ],
    }


def _next_command(blockers: list[str]) -> str:
    if "semantic-rust-runtime" in blockers:
        return "python3 tools/rust-cross-crate-graph.py --workspace <workspace> --validate"
    if "semantic-live-proof-pairs" in blockers or "semantic-cross-contract-proof" in blockers:
        return "make semantic-graph WS=<workspace> && python3 tools/engage.py --workspace <workspace> --stage live-checks"
    if "semantic-production-path-depth" in blockers:
        return "make semantic-graph WS=<workspace>"
    return "make semantic-live-depth-blockers WS=<workspace>"


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Semantic/Live Depth Blockers",
        "",
        "Strict blocker inventory joining semantic route rows with live topology proof-pair accounting.",
        "Rows are advisory only and never submission-ready by themselves.",
        "",
        f"- schema: `{payload['schema']}`",
        f"- item count: {payload['item_count']}",
        f"- limit: {payload['limit']}",
        f"- semantic graph mode: `{payload.get('source_semantic_graph_mode', '')}`",
        f"- semantic graph artifact: `{payload.get('source_semantic_graph_artifact', '')}`",
        f"- submission posture: `{payload['submission_posture']}`",
        f"- live proof pairs: {payload['live_topology_summary'].get('proof_pair_count', 0)}",
        f"- proved live proof pairs: {payload['live_topology_summary'].get('proved_pair_count', 0)}",
        "",
        "## Blocker Counts",
        "",
    ]
    for blocker, count in sorted((payload.get("blocker_counts") or {}).items()):
        lines.append(f"- `{blocker}`: {count}")
    if not payload.get("blocker_counts"):
        lines.append("- none detected by this inventory")
    lines.extend([
        "",
        "## Items",
        "",
        "| ID | Source | Target | Live Pair | Blockers | Posture | Next command |",
        "|---|---|---|---|---|---|---|",
    ])
    for item in payload.get("items", []):
        live_pair = ",".join(item.get("live_evidence", {}).get("proved_pair_ids") or [])
        lines.append("| `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` |".format(
            item.get("item_id", ""),
            item.get("source_component", ""),
            item.get("target_component", ""),
            live_pair,
            ",".join(item.get("blocker_ids") or []),
            item.get("submission_posture", ""),
            item.get("next_command", ""),
        ))
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--graph", type=Path)
    parser.add_argument("--scanner-inventory", type=Path)
    parser.add_argument("--live-topology", type=Path)
    parser.add_argument("--rust-summary", type=Path)
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-md", type=Path)
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args()

    workspace = args.workspace.expanduser().resolve()
    if not workspace.is_dir():
        print(f"[semantic-live-depth-blockers] workspace not found: {workspace}", file=sys.stderr)
        return 2
    audit_dir = workspace / ".auditooor"
    graph_path, graph, graph_source = _resolve_graph(workspace, args.graph, limit=max(0, args.limit))
    scanner = _load_json((args.scanner_inventory or audit_dir / "semantic_scanner_inventory.json").expanduser().resolve())
    live = _load_json((args.live_topology or workspace / "live_topology_checks.json").expanduser().resolve())
    rust_summary = _load_json((args.rust_summary or workspace / "scanners" / "rust" / "SCAN_RUST_SUMMARY.json").expanduser().resolve())
    payload = build_payload(
        workspace,
        graph,
        scanner,
        live,
        rust_summary,
        limit=max(0, args.limit),
        graph_artifact=graph_path,
        graph_source=graph_source,
    )
    out_json = args.out_json or audit_dir / "semantic_live_depth_blockers.json"
    out_md = args.out_md or audit_dir / "semantic_live_depth_blockers.md"
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(payload), encoding="utf-8")
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    print(f"[semantic-live-depth-blockers] OK items={payload['item_count']} json={out_json}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
