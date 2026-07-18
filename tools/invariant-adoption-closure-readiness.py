#!/usr/bin/env python3
"""Validate whether P0-0 invariant adoption can close.

This gate is deliberately stricter than the current-workspace adoption reducer.
`invariant-discovery-adoption.py` can close the "row or explicit blocker"
branch for one workspace. P0-0 is broader: it needs adoption evidence across
fresh engagements plus at least one real proof-class promotion path.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.invariant_adoption_closure_readiness.v1"
FRESH_METRICS_SCHEMA = "auditooor.invariant_adoption_fresh_engagement_metrics.v1"
MIN_FRESH_ENGAGEMENTS = 3
MIN_ADOPTION_RATE = 0.80


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _records(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ("rows", "items", "units", "results"):
        value = payload.get(key)
        if isinstance(value, list):
            return [row for row in value if isinstance(row, dict)]
    return []


def _adoption_status(ws: Path) -> dict[str, Any]:
    path = ws / ".auditooor" / "invariant_discovery_adoption.json"
    payload = _read_json(path) or {}
    generated = payload.get("generated_review") if isinstance(payload.get("generated_review"), dict) else {}
    units = payload.get("route_family_units") if isinstance(payload.get("route_family_units"), list) else []
    blocked_units = [
        unit for unit in units
        if str(unit.get("review_state") or "").startswith("blocked_")
        and unit.get("next_commands")
    ]
    ready = (
        bool(payload)
        and bool(payload.get("adopted_to_canonical_invariant_ledger"))
        and int(generated.get("unreviewed_missing_count") or 0) == 0
        and len(units) > 0
        and len(blocked_units) == len(units)
        and int(payload.get("closure_candidate_count") or 0) == 0
        and not bool(payload.get("promotion_allowed"))
    )
    return {
        "artifact_path": str(path),
        "ready": ready,
        "route_family_unit_count": len(units),
        "blocked_route_family_unit_count": len(blocked_units),
        "unreviewed_generated_count": int(generated.get("unreviewed_missing_count") or 0),
        "adopted_to_canonical_invariant_ledger": bool(payload.get("adopted_to_canonical_invariant_ledger")),
    }


def _fresh_metrics_status(ws: Path) -> dict[str, Any]:
    path = ws / ".auditooor" / "invariant_adoption_fresh_engagement_metrics.json"
    payload = _read_json(path) or {}
    rows = _records(payload)
    valid_rows = []
    for row in rows:
        adoption_rate = float(row.get("adoption_rate") or 0)
        high_critical_total = int(row.get("high_critical_route_family_count") or 0)
        high_critical_adopted = int(row.get("high_critical_route_family_adopted_count") or 0)
        has_check = bool(row.get("invariant_ledger_check_passed"))
        if (
            str(row.get("engagement_id") or row.get("workspace") or "").strip()
            and adoption_rate >= MIN_ADOPTION_RATE
            and high_critical_total > 0
            and high_critical_adopted >= high_critical_total
            and has_check
        ):
            valid_rows.append(row)
    ready = len(valid_rows) >= MIN_FRESH_ENGAGEMENTS
    return {
        "artifact_path": str(path),
        "schema": payload.get("schema") if isinstance(payload, dict) else None,
        "status": str(payload.get("status") or "missing_fresh_engagement_metrics")
        if isinstance(payload, dict) else "missing_fresh_engagement_metrics",
        "ready": ready,
        "required_fresh_engagement_count": MIN_FRESH_ENGAGEMENTS,
        "minimum_adoption_rate": MIN_ADOPTION_RATE,
        "fresh_engagement_count": len(rows),
        "valid_fresh_engagement_count": len(valid_rows),
        "invalid_fresh_engagement_count": max(0, len(rows) - len(valid_rows)),
        "missing_fresh_engagement_count": max(0, MIN_FRESH_ENGAGEMENTS - len(valid_rows)),
    }


def _proof_status(ws: Path) -> dict[str, Any]:
    proof_path = ws / ".auditooor" / "execution_manifest_proof_readiness.json"
    source_path = ws / ".auditooor" / "project_source_root_readiness.json"
    impact_path = ws / ".auditooor" / "impact_binding_source_import_readiness.json"
    proof_payload = _read_json(proof_path) or {}
    source_payload = _read_json(source_path) or {}
    impact_payload = _read_json(impact_path) or {}
    proof_rows = _records(proof_payload)
    proof_ready = [
        row for row in proof_rows
        if bool(row.get("execution_proof_ready"))
        or bool(row.get("proof_ready"))
        or str(row.get("status") or "") == "execution_proof_ready"
        or str(row.get("readiness_status") or "") == "execution_proof_ready"
    ]
    ready_sources = int(
        source_payload.get("ready_count")
        or source_payload.get("ready_project_source_root_count")
        or 0
    ) if isinstance(source_payload, dict) else 0
    line_hits = int(
        impact_payload.get("line_hit_unit_count")
        or impact_payload.get("ready_line_hit_units")
        or 0
    ) if isinstance(impact_payload, dict) else 0
    ready = ready_sources > 0 and line_hits > 0 and len(proof_ready) > 0
    return {
        "ready": ready,
        "execution_manifest_proof_readiness_path": str(proof_path),
        "project_source_root_readiness_path": str(source_path),
        "impact_binding_source_import_readiness_path": str(impact_path),
        "proof_ready_execution_manifest_count": len(proof_ready),
        "ready_project_source_root_count": ready_sources,
        "source_line_hit_unit_count": line_hits,
    }


def run(ws: Path) -> dict[str, Any]:
    adoption = _adoption_status(ws)
    fresh = _fresh_metrics_status(ws)
    proof = _proof_status(ws)
    blockers: list[str] = []
    if not adoption["ready"]:
        blockers.append("current_workspace_invariant_adoption_incomplete")
    if not fresh["ready"]:
        blockers.append("fresh_engagement_adoption_metrics_missing_or_below_threshold")
    if proof["ready_project_source_root_count"] == 0:
        blockers.append("project_source_roots_missing")
    if proof["source_line_hit_unit_count"] == 0:
        blockers.append("candidate_bound_source_line_hits_missing")
    if proof["proof_ready_execution_manifest_count"] == 0:
        blockers.append("proved_exploit_impact_execution_manifest_missing")
    p0_ready = adoption["ready"] and fresh["ready"] and proof["ready"]
    payload = {
        "schema": SCHEMA,
        "workspace": str(ws),
        "status": "p0_invariant_adoption_closure_ready" if p0_ready else "p0_invariant_adoption_blocked_exact",
        "p0_closure_ready": p0_ready,
        "submission_posture": "NOT_SUBMIT_READY" if not p0_ready else "INTERNAL_CLOSEOUT_ONLY",
        "promotion_allowed": False,
        "current_workspace_adoption": adoption,
        "fresh_engagement_metrics": fresh,
        "proof_class_evidence": proof,
        "blockers": blockers,
        "next_commands": [
            "make invariant-discovery-adoption WS=<fresh-workspace> ADOPT_LEDGER=1 JSON=1",
            "make invariant-adoption-fresh-metrics WS=<workspace> SOURCE_WS=<fresh-workspace> JSON=1",
            "make project-source-root-readiness WS=<target-workspace> JSON=1",
            "make impact-binding-source-import-readiness WS=<target-workspace> JSON=1",
            "make execution-manifest-proof-readiness WS=<target-workspace> JSON=1",
        ],
        "proof_boundary": (
            "This gate can close P0-0 only for invariant adoption mechanics. It does not promote "
            "severity, OOS, production-path, exploit-impact, or submission readiness."
        ),
    }
    out = ws / ".auditooor" / "invariant_adoption_closure_readiness.json"
    _write_json(out, payload)
    md = [
        "# Invariant Adoption Closure Readiness",
        "",
        f"- Status: `{payload['status']}`",
        f"- P0 closure ready: `{payload['p0_closure_ready']}`",
        f"- Current workspace adoption ready: `{adoption['ready']}`",
        f"- Fresh engagements valid: `{fresh['valid_fresh_engagement_count']}/{fresh['required_fresh_engagement_count']}`",
        f"- Proof-ready execution manifests: `{proof['proof_ready_execution_manifest_count']}`",
        f"- Ready project source roots: `{proof['ready_project_source_root_count']}`",
        f"- Source line-hit units: `{proof['source_line_hit_unit_count']}`",
        "",
        "## Blockers",
        "",
    ]
    if blockers:
        md.extend(f"- `{blocker}`" for blocker in blockers)
    else:
        md.append("- _none_")
    md.extend(["", "## Boundary", "", payload["proof_boundary"], ""])
    (ws / ".auditooor" / "invariant_adoption_closure_readiness.md").write_text(
        "\n".join(md), encoding="utf-8"
    )
    return payload


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, help="Workspace path")
    parser.add_argument("--print-json", action="store_true", help="Print JSON summary")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    ws = Path(args.workspace).expanduser().resolve()
    if not ws.exists():
        print(f"[invariant-adoption-closure-readiness] workspace not found: {ws}")
        return 2
    payload = run(ws)
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(
            "[invariant-adoption-closure-readiness] "
            f"{payload['status']}: blockers={len(payload['blockers'])}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
