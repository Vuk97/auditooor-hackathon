#!/usr/bin/env python3
"""Build a semantic/live depth proof-pair queue.

This verifier consumes ``semantic_live_depth_blockers.json`` and
``live_topology_checks.json``. It can close only the semantic/live topology
depth row: a row is closeable when an exact proved same-block proof pair covers
the semantic source and target contracts. It never promotes a finding, assigns
severity, or changes submission readiness.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.semantic_live_depth_queue.v1"
GENERATED_EVIDENCE_CLASS = "generated_hypothesis"
DEFAULT_LIMIT = 400
ADVISORY_POSTURE = {
    "coverage_claim": "semantic_live_depth_accounting_only",
    "evidence_class": GENERATED_EVIDENCE_CLASS,
    "advisory_only": True,
    "promotion_allowed": False,
    "severity": "none",
    "selected_impact": "",
    "submission_posture": "NOT_SUBMIT_READY",
    "impact_contract_required": True,
}
EXECUTED_STATUSES = {"pass", "fail"}


def _load_json(path: Path, label: str, *, required: bool = True) -> dict[str, Any]:
    if not path.is_file():
        if required:
            raise SystemExit(f"[semantic-live-depth-queue] missing {label}: {path}")
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"[semantic-live-depth-queue] unreadable {label}: {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit(f"[semantic-live-depth-queue] expected object JSON for {label}: {path}")
    return payload


def _contract(component: Any) -> str:
    text = str(component or "").strip()
    return text.split(".", 1)[0] if text else ""


def _status_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        status = str(row.get("status") or "unknown")
        counts[status] = counts.get(status, 0) + 1
    return counts


def _pair_row_ids(pair: dict[str, Any]) -> list[str]:
    return [str(row_id).strip() for row_id in pair.get("row_ids") or [] if str(row_id).strip()]


def _row_contracts(row_ids: list[str], rows_by_id: dict[str, dict[str, Any]]) -> list[str]:
    contracts: list[str] = []
    seen: set[str] = set()
    for row_id in row_ids:
        contract = str((rows_by_id.get(row_id) or {}).get("contract") or "").strip()
        key = contract.lower()
        if contract and key not in seen:
            seen.add(key)
            contracts.append(contract)
    return contracts


def _pair_blocks(pair: dict[str, Any], row_ids: list[str], rows_by_id: dict[str, dict[str, Any]]) -> list[str]:
    blocks = {
        str((rows_by_id.get(row_id) or {}).get("block") or "").strip()
        for row_id in row_ids
        if str((rows_by_id.get(row_id) or {}).get("block") or "").strip()
    }
    for block in pair.get("pair_blocks") or []:
        if str(block).strip():
            blocks.add(str(block).strip())
    shared = str(pair.get("shared_block") or "").strip()
    if shared:
        blocks.add(shared)
    return sorted(blocks)


def _verify_pair(
    pair_id: str,
    *,
    source_contract: str,
    target_contract: str,
    pairs_by_id: dict[str, dict[str, Any]],
    rows_by_id: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    pair = pairs_by_id.get(pair_id)
    blockers: list[str] = []
    if not pair:
        return {
            "pair_id": pair_id,
            "exact": False,
            "blockers": ["proof pair missing from live_topology_checks.json"],
            "row_ids": [],
            "contracts": [],
            "blocks": [],
        }

    row_ids = _pair_row_ids(pair)
    missing_rows = [row_id for row_id in row_ids if row_id not in rows_by_id]
    row_statuses = {
        row_id: str((rows_by_id.get(row_id) or {}).get("status") or "").strip()
        for row_id in row_ids
    }
    evidence_classes = {
        row_id: str((rows_by_id.get(row_id) or {}).get("evidence_class") or "").strip()
        for row_id in row_ids
    }
    executed = [status for status in row_statuses.values() if status in EXECUTED_STATUSES]
    contracts = _row_contracts(row_ids, rows_by_id)
    contract_lc = {contract.lower() for contract in contracts}
    blocks = _pair_blocks(pair, row_ids, rows_by_id)

    if str(pair.get("status") or "").strip() != "proved":
        blockers.append("proof pair status is not proved")
    if missing_rows:
        blockers.append("proof pair references missing row ids: " + ",".join(missing_rows))
    if len(row_ids) < 2:
        blockers.append("proof pair has fewer than two rows")
    if len(executed) < 2:
        blockers.append("proof pair has fewer than two executed rows")
    if any(evidence != "topology-relation" for evidence in evidence_classes.values()):
        blockers.append("proof pair rows are not all topology-relation evidence")
    if len(blocks) != 1:
        blockers.append("proof pair is not pinned to one shared block")
    if source_contract and source_contract.lower() not in contract_lc:
        blockers.append(f"source contract not covered by pair: {source_contract}")
    if target_contract and target_contract.lower() not in contract_lc:
        blockers.append(f"target contract not covered by pair: {target_contract}")

    return {
        "pair_id": pair_id,
        "exact": not blockers,
        "blockers": blockers,
        "row_ids": row_ids,
        "contracts": contracts,
        "blocks": blocks,
        "row_statuses": row_statuses,
        "evidence_classes": evidence_classes,
        "status": pair.get("status", ""),
        "shared_block": blocks[0] if len(blocks) == 1 else "",
    }


def _candidate_pair_ids(item: dict[str, Any]) -> list[str]:
    live_evidence = item.get("live_evidence") if isinstance(item.get("live_evidence"), dict) else {}
    ids: list[str] = []
    for key in ("proved_pair_ids", "matched_pair_ids"):
        for pair_id in live_evidence.get(key) or []:
            text = str(pair_id).strip()
            if text and text not in ids:
                ids.append(text)
    return ids


def _assess_item(
    item: dict[str, Any],
    *,
    pairs_by_id: dict[str, dict[str, Any]],
    rows_by_id: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    source_contract = _contract(item.get("source_component"))
    target_contract = _contract(item.get("target_component"))
    pair_checks = [
        _verify_pair(
            pair_id,
            source_contract=source_contract,
            target_contract=target_contract,
            pairs_by_id=pairs_by_id,
            rows_by_id=rows_by_id,
        )
        for pair_id in _candidate_pair_ids(item)
    ]
    exact_pairs = [check for check in pair_checks if check.get("exact")]
    if exact_pairs:
        status = "semantic_live_depth_closed_by_same_block_pair"
        task_type = "record_depth_closure"
        blockers: list[str] = []
        next_command = "cite semantic_live_depth_queue row as depth accounting only; keep finding gates separate"
        depth_closure_allowed = True
    else:
        status = "queued_missing_exact_same_block_pair"
        task_type = "collect_or_repair_same_block_proof_pair"
        blockers = ["missing exact proved same-block live proof pair for semantic route"]
        if pair_checks:
            blockers.extend(
                blocker
                for check in pair_checks
                for blocker in check.get("blockers", [])
                if blocker
            )
        next_command = "python3 tools/engage.py --workspace <workspace> --stage live-checks --pin-block latest"
        depth_closure_allowed = False

    return {
        "queue_id": str(item.get("item_id") or ""),
        "source_item_id": str(item.get("item_id") or ""),
        "source_artifact": str(item.get("source") or ""),
        "source_id": str(item.get("source_id") or ""),
        "task_type": task_type,
        "status": status,
        "source_component": item.get("source_component", ""),
        "target_component": item.get("target_component", ""),
        "source_contract": source_contract,
        "target_contract": target_contract,
        "relation_kind": item.get("relation_kind", ""),
        "candidate_pair_ids": _candidate_pair_ids(item),
        "exact_pair_ids": [str(check.get("pair_id") or "") for check in exact_pairs],
        "pair_verification": pair_checks,
        "depth_closure_allowed": depth_closure_allowed,
        "depth_closure_scope": "semantic_live_topology_depth_only",
        "blockers": sorted(set(blockers)),
        "next_command": next_command,
        **ADVISORY_POSTURE,
    }


def build_queue(
    workspace: Path,
    blockers: dict[str, Any],
    live: dict[str, Any],
    *,
    limit: int,
) -> dict[str, Any]:
    rows = [row for row in live.get("results") or [] if isinstance(row, dict)]
    pairs = [row for row in live.get("proof_pairs") or [] if isinstance(row, dict)]
    rows_by_id = {str(row.get("id") or "").strip(): row for row in rows if str(row.get("id") or "").strip()}
    pairs_by_id = {str(pair.get("id") or "").strip(): pair for pair in pairs if str(pair.get("id") or "").strip()}
    source_items = [row for row in blockers.get("items") or [] if isinstance(row, dict)]
    queue = [
        _assess_item(item, pairs_by_id=pairs_by_id, rows_by_id=rows_by_id)
        for item in source_items[: max(0, limit)]
    ]
    closed = [row for row in queue if row.get("depth_closure_allowed")]
    blocked = [row for row in queue if not row.get("depth_closure_allowed")]
    return {
        "schema": SCHEMA,
        "workspace": str(workspace),
        "source_blockers_artifact": str(workspace / ".auditooor" / "semantic_live_depth_blockers.json"),
        "source_live_topology_artifact": str(workspace / "live_topology_checks.json"),
        "limit": limit,
        "source_item_count": len(source_items),
        "processed_count": len(queue),
        "depth_closed_count": len(closed),
        "blocking_count": len(blocked),
        "status_counts": _status_counts(queue),
        "proof_pair_count": len(pairs),
        "exact_same_block_pair_ids": sorted(
            {
                pair_id
                for row in closed
                for pair_id in row.get("exact_pair_ids", [])
                if str(pair_id).strip()
            }
        ),
        "rows": queue,
        "next_actions": [
            "Use record_depth_closure rows only to close semantic/live topology depth accounting.",
            "For queued rows, collect two executed topology-relation rows on the same block and preserve them as a proved proof pair.",
            "Keep every row NOT_SUBMIT_READY until separate exact impact proof, production path proof, and execution artifacts exist.",
        ],
        **ADVISORY_POSTURE,
    }


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Semantic/Live Depth Proof-Pair Queue",
        "",
        "Verifier queue for semantic/live topology depth rows.",
        "Rows closed here are depth-accounting closures only; they are not submission proof.",
        "",
        f"- schema: `{payload['schema']}`",
        f"- processed rows: {payload['processed_count']}",
        f"- depth-closed rows: {payload['depth_closed_count']}",
        f"- blocking rows: {payload['blocking_count']}",
        f"- submission posture: `{payload['submission_posture']}`",
        "",
        "## Status Counts",
        "",
    ]
    for status, count in sorted((payload.get("status_counts") or {}).items()):
        lines.append(f"- `{status}`: {count}")
    lines.extend([
        "",
        "## Rows",
        "",
        "| Queue | Status | Source | Target | Exact pairs | Blockers |",
        "|---|---|---|---|---|---|",
    ])
    for row in payload.get("rows", []):
        lines.append("| `{}` | `{}` | `{}` | `{}` | `{}` | `{}` |".format(
            row.get("queue_id", ""),
            row.get("status", ""),
            row.get("source_component", ""),
            row.get("target_component", ""),
            ",".join(row.get("exact_pair_ids") or []),
            "; ".join(row.get("blockers") or []),
        ))
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--blockers", type=Path)
    parser.add_argument("--live-topology", type=Path)
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-md", type=Path)
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args()

    workspace = args.workspace.expanduser().resolve()
    if not workspace.is_dir():
        print(f"[semantic-live-depth-queue] workspace not found: {workspace}", file=sys.stderr)
        return 2
    audit_dir = workspace / ".auditooor"
    blockers = _load_json(
        (args.blockers or audit_dir / "semantic_live_depth_blockers.json").expanduser().resolve(),
        "semantic live-depth blockers",
    )
    live = _load_json(
        (args.live_topology or workspace / "live_topology_checks.json").expanduser().resolve(),
        "live topology",
    )
    payload = build_queue(workspace, blockers, live, limit=max(0, args.limit))
    out_json = args.out_json or audit_dir / "semantic_live_depth_queue.json"
    out_md = args.out_md or audit_dir / "semantic_live_depth_queue.md"
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(payload), encoding="utf-8")
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    print(
        f"[semantic-live-depth-queue] OK processed={payload['processed_count']} closed={payload['depth_closed_count']} json={out_json}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
