#!/usr/bin/env python3
"""Generate workspace-neutral live-topology proof-pair requirements.

This tool does not call RPC and does not claim that any live proof exists. It
converts semantic/live depth blocker rows into concrete same-block proof-pair
requirements so a missing ``live_topology_checks.json`` is no longer a dead
end: operators get row-level requirements that can later be imported into a
real live-check spec or satisfied by executed topology rows.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.live_topology_proof_requirements.v1"
DEFAULT_LIMIT = 400
ADVISORY_POSTURE = {
    "coverage_claim": "proof_requirements_only_no_live_execution",
    "evidence_class": "scaffolded_unverified",
    "advisory_only": True,
    "promotion_allowed": False,
    "severity": "none",
    "selected_impact": "",
    "submission_posture": "NOT_SUBMIT_READY",
    "impact_contract_required": True,
}


def _load_json(path: Path, label: str) -> dict[str, Any]:
    if not path.is_file():
        raise SystemExit(f"[live-topology-proof-requirements] missing {label}: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"[live-topology-proof-requirements] unreadable {label}: {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit(f"[live-topology-proof-requirements] expected object JSON for {label}: {path}")
    return payload


def _contract(component: Any) -> str:
    text = str(component or "").strip()
    return text.split(".", 1)[0] if text else ""


def _row_needs_requirement(row: dict[str, Any]) -> bool:
    blockers = {str(item) for item in row.get("blocker_ids") or []}
    return "semantic-live-proof-pairs" in blockers or "semantic-cross-contract-proof" in blockers


def _requirement_for(row: dict[str, Any], idx: int) -> dict[str, Any]:
    source_contract = _contract(row.get("source_component"))
    target_contract = _contract(row.get("target_component"))
    requirement_id = f"LTPR-{idx:03d}"
    pair_id = f"{requirement_id}-pair"
    source_row_id = f"{requirement_id}-edge"
    target_row_id = f"{requirement_id}-authority"
    return {
        "requirement_id": requirement_id,
        "source_item_id": str(row.get("item_id") or ""),
        "source_component": row.get("source_component", ""),
        "target_component": row.get("target_component", ""),
        "source_contract": source_contract,
        "target_contract": target_contract,
        "relation_kind": row.get("relation_kind", ""),
        "required_proof_pair_id": pair_id,
        "same_block_required": True,
        "minimum_executed_rows": 2,
        "required_evidence_class": "topology-relation",
        "required_contracts": [contract for contract in (source_contract, target_contract) if contract],
        "required_live_rows": [
            {
                "id": source_row_id,
                "contract": source_contract,
                "evidence_class": "topology-relation",
                "status": "required_not_collected",
                "proof_pair_id": pair_id,
                "block": "<same-block>",
                "requirement_role": "relation-edge",
            },
            {
                "id": target_row_id,
                "contract": target_contract,
                "evidence_class": "topology-relation",
                "status": "required_not_collected",
                "proof_pair_id": pair_id,
                "block": "<same-block>",
                "requirement_role": "authority-or-wiring",
            },
        ],
        "live_topology_pair_skeleton": {
            "id": pair_id,
            "status": "required_not_collected",
            "row_ids": [source_row_id, target_row_id],
            "shared_block": "<same-block>",
            "pair_blocks": ["<same-block>"],
        },
        "import_hint": (
            "Collect these rows with live-check-runner/live-state-checker and preserve the same "
            "proof_pair_id; do not mark proved until both rows execute at one block."
        ),
        "next_command": "python3 tools/engage.py --workspace <workspace> --stage live-checks",
        **ADVISORY_POSTURE,
    }


def build_requirements(workspace: Path, blockers: dict[str, Any], *, limit: int) -> dict[str, Any]:
    source_items = [row for row in blockers.get("items") or [] if isinstance(row, dict)]
    requirement_source = [row for row in source_items if _row_needs_requirement(row)]
    requirements = [
        _requirement_for(row, idx)
        for idx, row in enumerate(requirement_source[: max(0, limit)], start=1)
    ]
    return {
        "schema": SCHEMA,
        "workspace": str(workspace),
        "source_blockers_artifact": str(workspace / ".auditooor" / "semantic_live_depth_blockers.json"),
        "limit": limit,
        "source_item_count": len(source_items),
        "eligible_requirement_count": len(requirement_source),
        "requirement_count": len(requirements),
        "truncated": len(requirement_source) > max(0, limit),
        "requirements": requirements,
        "next_actions": [
            "Use this artifact as the offline proof-pair checklist when live_topology_checks.json is absent.",
            "Execute or import two topology-relation rows per requirement at the same block before depth closure is counted.",
            "Keep every requirement NOT_SUBMIT_READY; this artifact contains no RPC/live execution evidence.",
        ],
        **ADVISORY_POSTURE,
    }


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Live Topology Proof Requirements",
        "",
        "Offline same-block proof-pair requirements generated from semantic/live depth blockers.",
        "This is not live evidence and does not prove impact.",
        "",
        f"- schema: `{payload['schema']}`",
        f"- requirement count: {payload['requirement_count']}",
        f"- eligible source rows: {payload['eligible_requirement_count']}",
        f"- submission posture: `{payload['submission_posture']}`",
        "",
        "## Requirements",
        "",
        "| ID | Source | Target | Pair | Required rows | Next command |",
        "|---|---|---|---|---|---|",
    ]
    for req in payload.get("requirements", []):
        row_ids = ",".join(str(row.get("id") or "") for row in req.get("required_live_rows") or [])
        lines.append("| `{}` | `{}` | `{}` | `{}` | `{}` | `{}` |".format(
            req.get("requirement_id", ""),
            req.get("source_component", ""),
            req.get("target_component", ""),
            req.get("required_proof_pair_id", ""),
            row_ids,
            req.get("next_command", ""),
        ))
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--blockers", type=Path)
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-md", type=Path)
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args()

    workspace = args.workspace.expanduser().resolve()
    if not workspace.is_dir():
        print(f"[live-topology-proof-requirements] workspace not found: {workspace}", file=sys.stderr)
        return 2
    audit_dir = workspace / ".auditooor"
    blockers = _load_json(
        (args.blockers or audit_dir / "semantic_live_depth_blockers.json").expanduser().resolve(),
        "semantic live-depth blockers",
    )
    payload = build_requirements(workspace, blockers, limit=max(0, args.limit))
    out_json = args.out_json or audit_dir / "live_topology_proof_requirements.json"
    out_md = args.out_md or audit_dir / "live_topology_proof_requirements.md"
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(payload), encoding="utf-8")
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    print(
        "[live-topology-proof-requirements] OK "
        f"requirements={payload['requirement_count']} json={out_json}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
