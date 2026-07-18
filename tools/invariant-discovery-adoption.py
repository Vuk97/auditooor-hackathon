#!/usr/bin/env python3
"""Adopt generated invariant candidates into reviewable ledger/blocker rows.

This reducer is intentionally conservative. It does not claim proof, severity,
or submission readiness. It converts generated-vs-accepted invariant discovery
evidence plus Impact-Miss route families into:

- canonical invariant-ledger rows with `status=blocked`;
- per-family review bundles with executable next commands; and
- a workspace-local adoption summary that closeout can account for.

The stop-condition boundary is "named invariant row or explicit blocker", not
"finding proven".
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.invariant_discovery_adoption.v1"
REVIEW_SCHEMA = "auditooor.invariant_discovery_review_unit.v1"


def _load_invariant_ledger_module():
    tool = Path(__file__).resolve().with_name("invariant-ledger.py")
    spec = importlib.util.spec_from_file_location("invariant_ledger_runtime", tool)
    if not spec or not spec.loader:
        raise RuntimeError(f"could not import {tool}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["invariant_ledger_runtime"] = mod
    spec.loader.exec_module(mod)
    return mod


INV = _load_invariant_ledger_module()


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError:
        return None
    except json.JSONDecodeError as exc:
        raise SystemExit(f"invalid JSON: {path}: {exc}") from exc


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _slug(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9]+", "-", value).strip("-").lower()
    return value[:80] or "unknown"


def _artifact_rel(ws: Path, path: Path) -> str:
    try:
        return str(path.relative_to(ws))
    except ValueError:
        return str(path)


def _tier_rank(tier: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(tier.lower(), 0)


def _highest_tier(values: list[str]) -> str:
    return max(values or ["Unknown"], key=_tier_rank)


def _route_family(item: dict[str, Any]) -> str:
    expected = item.get("expected") if isinstance(item.get("expected"), dict) else {}
    return str(expected.get("route_family") or item.get("route_family") or "unknown")


def _impact_text(item: dict[str, Any]) -> str:
    inp = item.get("input") if isinstance(item.get("input"), dict) else {}
    return str(inp.get("impact_text") or item.get("benchmark_id") or "impact route")


def _engine_for_family(family: str, asset_categories: list[str]) -> str:
    if any(str(a).lower() == "blockchain/dlt" for a in asset_categories):
        return "cargo"
    if family in {"node_liveness", "consensus_safety", "resource_consumption"}:
        return "cargo"
    if family in {"bridge_finalization", "oracle_integrity"}:
        return "differential"
    if family in {"asset_custody", "economic_safety"}:
        return "forge"
    return "manual"


def _negative_test_for_family(family: str) -> str:
    mapping = {
        "asset_custody": "Attempt non-privileged value movement that violates custody accounting.",
        "bridge_finalization": "Attempt finalization/withdrawal before the accepted proof/finality condition.",
        "node_liveness": "Replay a bounded input that should not halt or exhaust the runtime node.",
        "resource_consumption": "Replay bounded adversarial input and assert resource usage stays within policy.",
        "consensus_safety": "Replay divergent consensus input and assert client state/finality remains consistent.",
        "oracle_integrity": "Feed stale/manipulated oracle data and assert protected state cannot be updated.",
    }
    return mapping.get(family, "Construct the smallest counterexample for this route family and assert it is rejected.")


def _statement_for_family(family: str, examples: list[str]) -> str:
    sample = examples[0] if examples else family
    return (
        f"All in-scope `{family}` impact routes must have a named invariant or "
        f"explicit blocker before harness/report work; representative impact: {sample}"
    )[:260]


def _load_generated_review_payloads(ws: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    generated_path = ws / ".auditooor" / "generated_invariants.json"
    review_path = ws / ".auditooor" / "invariant_acceptance_ledger.json"
    generated = _read_json(generated_path) or {}
    review = _read_json(review_path) or {}
    return generated, review


def _load_generated_review(ws: Path) -> dict[str, Any]:
    generated_path = ws / ".auditooor" / "generated_invariants.json"
    review_path = ws / ".auditooor" / "invariant_acceptance_ledger.json"
    generated, review = _load_generated_review_payloads(ws)
    generated_rows = generated.get("generated_rows") if isinstance(generated.get("generated_rows"), list) else []
    review_rows = review.get("rows") if isinstance(review.get("rows"), list) else []
    terminal = {"accepted", "merged", "killed", "needs_harness", "advisory_harness_required"}
    terminal_by_id = {
        str(r.get("generated_id") or r.get("invariant_id") or r.get("row_id") or ""): r
        for r in review_rows
        if str(r.get("review_state") or r.get("status") or "") in terminal
    }
    missing_rows = list(((generated.get("diff") or {}).get("missing") or []))
    reviewed_missing = [
        r for r in missing_rows
        if str(r.get("generated_id") or "") in terminal_by_id
    ]
    return {
        "generated_path": str(generated_path),
        "review_path": str(review_path),
        "generated_count": int(generated.get("generated_count") or len(generated_rows)),
        "missing_count": len(missing_rows),
        "terminal_review_count": len(reviewed_missing),
        "unreviewed_missing_count": max(0, len(missing_rows) - len(reviewed_missing)),
        "review_states": dict(Counter(str(r.get("review_state") or r.get("status") or "unknown") for r in review_rows)),
    }


def _terminalize_reviewed_generated_rows(ws: Path, rows: list[Any]) -> int:
    """Make generated rows that have terminal review states schema-valid.

    Older from-scope runs added README-derived TODO rows to the canonical
    invariant ledger before the acceptance ledger killed them. Keeping those
    rows as `missing_harness` leaves `invariant-ledger --check` noisy even
    though the review ledger already made a terminal decision. This converts
    those exact rows into `killed` ledger rows with a real artifact citation.
    """
    generated, review = _load_generated_review_payloads(ws)
    generated_rows = {
        str(row.get("id") or row.get("generated_id") or ""): row
        for row in generated.get("generated_rows") or []
        if isinstance(row, dict)
    }
    review_rows = review.get("rows") if isinstance(review.get("rows"), list) else []
    terminal_states = {"killed", "accepted", "merged", "needs_harness", "advisory_harness_required"}
    reviews = {
        str(row.get("generated_id") or row.get("invariant_id") or row.get("row_id") or ""): row
        for row in review_rows
        if str(row.get("review_state") or row.get("status") or "") in terminal_states
    }
    updated = 0
    for idx, row in enumerate(rows):
        review_row = reviews.get(row.id)
        if not review_row:
            continue
        state = str(review_row.get("review_state") or review_row.get("status") or "")
        generated_row = generated_rows.get(row.id) or {}
        if state == "killed":
            reason = str(review_row.get("reason") or "generated invariant candidate was killed by review")
            rows[idx] = INV.Row(
                id=row.id,
                scope_asset=row.scope_asset or str(generated_row.get("scope_asset") or "generated invariant candidate"),
                invariant_family=row.invariant_family or str(generated_row.get("invariant_family") or "reviewed_generated_invariant"),
                statement=row.statement or str(generated_row.get("statement") or "Generated invariant candidate killed by review."),
                source_citations=row.source_citations or [str(generated_row.get("source_file") or ".auditooor/generated_invariants.json")],
                attacker_capability="not applicable: generated invariant candidate was rejected before promotion",
                trusted_boundary="not applicable: generated invariant candidate was rejected before promotion",
                oos_boundary="not applicable: generated invariant candidate was rejected before promotion",
                production_path="not applicable: generated invariant candidate was rejected before promotion",
                harness_target="not applicable: killed generated invariant candidate",
                required_engine="manual",
                negative_test="not applicable: generated invariant candidate was killed by review",
                status="killed",
                artifacts=[".auditooor/invariant_acceptance_ledger.json"],
                owner="Codex",
                notes=f"terminal_review_state=killed; reason={reason[:180]}",
            )
            updated += 1
    return updated


def build_route_units(ws: Path) -> list[dict[str, Any]]:
    benchmark_path = ws / ".auditooor" / "impact_miss_offset_benchmark.json"
    runtime_path = ws / ".auditooor" / "runtime_dlt_execution_evidence_validator.json"
    source_roots_path = ws / ".auditooor" / "project_source_root_readiness.json"
    benchmark = _read_json(benchmark_path) or {}
    runtime = _read_json(runtime_path) or {}
    source_roots = _read_json(source_roots_path) or {}

    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in benchmark.get("items") or []:
        if not isinstance(item, dict):
            continue
        tier = str(item.get("tier") or "")
        if tier.lower() not in {"critical", "high"}:
            continue
        grouped[_route_family(item)].append(item)

    runtime_rows = runtime.get("rows") if isinstance(runtime.get("rows"), list) else []
    runtime_by_family = defaultdict(list)
    for row in runtime_rows:
        if isinstance(row, dict):
            runtime_by_family[str(row.get("route_family") or "unknown")].append(row)

    ready_roots = int(source_roots.get("ready_count") or source_roots.get("ready_project_source_root_count") or 0)
    source_status = str(source_roots.get("status") or ("no_readiness_artifact" if not source_roots else "unknown"))

    units: list[dict[str, Any]] = []
    for family in sorted(grouped):
        items = grouped[family]
        tiers = [str(i.get("tier") or "Unknown") for i in items]
        asset_categories = sorted({str(i.get("asset_category") or "unknown") for i in items})
        examples = [_impact_text(i) for i in items[:5]]
        runtime_family_rows = runtime_by_family.get(family, [])
        is_dlt = any(a.lower() == "blockchain/dlt" for a in asset_categories) or bool(runtime_family_rows)
        blockers = [
            "project_bound_harness_missing",
            "proved_exploit_impact_manifest_missing",
        ]
        review_state = "blocked_needs_project_source_and_harness"
        if ready_roots == 0:
            blockers.append("project_source_roots_missing")
            review_state = "blocked_no_project_source_roots"
        if is_dlt:
            blockers.append("runtime_family_execution_evidence_missing")
            review_state = "blocked_runtime_project_evidence_missing"
        unit_id = f"INV-DISC-{_slug(family).upper()}"
        commands = [
            f"make project-source-root-readiness WS={ws} JSON=1",
            f"make impact-binding-source-harness-discovery WS={ws} JSON=1",
            f"make invariant-discovery-adoption WS={ws} ADOPT_LEDGER=1 JSON=1",
        ]
        if is_dlt:
            commands.insert(1, f"make runtime-dlt-execution-evidence WS={ws} DEMO_FIXTURE=1 JSON=1")
        commands.append(
            "make poc-execution-record WS=<target-workspace> "
            f"CANDIDATE_ID=<candidate-for-{family}> CMD='<project-bound command>' "
            "RESULT=proved IMPACT=exploit_impact"
        )
        units.append({
            "schema": REVIEW_SCHEMA,
            "unit_id": unit_id,
            "route_family": family,
            "review_state": review_state,
            "blockers": blockers,
            "tier": _highest_tier(tiers),
            "asset_categories": asset_categories,
            "benchmark_count": len(items),
            "runtime_row_count": len(runtime_family_rows),
            "ready_project_source_root_count": ready_roots,
            "project_source_root_status": source_status,
            "statement": _statement_for_family(family, examples),
            "source_citations": [
                f".auditooor/impact_miss_offset_benchmark.json::{str(i.get('benchmark_id') or family)}"
                for i in items[:5]
            ],
            "attacker_capability": "non-privileged external actor, bounded by the benchmark route family until target source is imported",
            "trusted_boundary": "generated blocker: resolve project roles, trusted actors, runtime clients, and providers before promotion",
            "oos_boundary": "generated blocker: exact program impact/OOS/duplicate review required before severity or submission work",
            "production_path": "blocked: target project source root and production path not yet bound",
            "harness_target": f"EXPECTED:.auditooor/invariant_discovery_review_units/{unit_id}.json (review blocker bundle)",
            "required_engine": _engine_for_family(family, asset_categories),
            "negative_test": _negative_test_for_family(family),
            "status": "blocked",
            "artifacts": [
                f".auditooor/invariant_discovery_review_units/{unit_id}.json",
                "blocker: project-bound source/harness/proof evidence missing",
            ],
            "owner": "Codex",
            "severity": _highest_tier(tiers) if _highest_tier(tiers) in {"Critical", "High"} else None,
            "notes": "generated_by=invariant-discovery-adoption; advisory_only=true; not_submit_ready=true",
            "next_commands": commands,
            "promotion_allowed": False,
            "submission_posture": "NOT_SUBMIT_READY",
        })
    return units


def adopt_units(ws: Path, units: list[dict[str, Any]]) -> tuple[int, int, int]:
    rows = INV.load_rows(ws)
    terminalized = _terminalize_reviewed_generated_rows(ws, rows)
    existing_ids = {r.id for r in rows}
    added = 0
    updated = 0
    for unit in units:
        row = INV.Row(
            id=unit["unit_id"],
            scope_asset=", ".join(unit["asset_categories"]),
            invariant_family=unit["route_family"],
            statement=unit["statement"],
            source_citations=unit["source_citations"],
            attacker_capability=unit["attacker_capability"],
            trusted_boundary=unit["trusted_boundary"],
            oos_boundary=unit["oos_boundary"],
            production_path=unit["production_path"],
            harness_target=unit["harness_target"],
            required_engine=unit["required_engine"],
            negative_test=unit["negative_test"],
            status="blocked",
            artifacts=unit["artifacts"],
            owner="Codex",
            severity=unit.get("severity"),
            notes=unit["notes"],
        )
        if row.id in existing_ids:
            for idx, existing in enumerate(rows):
                if existing.id == row.id:
                    rows[idx] = row
                    updated += 1
                    break
        else:
            rows.append(row)
            existing_ids.add(row.id)
            added += 1
    INV.save_rows(ws, rows)
    return added, updated, terminalized


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Invariant Discovery Adoption",
        "",
        f"- Status: `{payload['status']}`",
        f"- Generated invariants: `{payload['generated_review']['generated_count']}`",
        f"- Generated missing reviewed: `{payload['generated_review']['terminal_review_count']}`",
        f"- Generated missing unreviewed: `{payload['generated_review']['unreviewed_missing_count']}`",
        f"- Route-family units: `{payload['route_family_unit_count']}`",
        f"- Canonical ledger rows added: `{payload['ledger_rows_added']}`",
        f"- Canonical ledger rows updated: `{payload['ledger_rows_updated']}`",
        f"- Closure candidates: `{payload['closure_candidate_count']}`",
        "",
        "## Boundary",
        payload["proof_boundary"],
        "",
        "## Route Families",
        "",
        "| Unit | Family | Tier | State | Benchmarks | Blockers |",
        "|---|---|---|---|---:|---|",
    ]
    for unit in payload["route_family_units"]:
        lines.append(
            f"| `{unit['unit_id']}` | `{unit['route_family']}` | `{unit['tier']}` | "
            f"`{unit['review_state']}` | {unit['benchmark_count']} | "
            f"{', '.join(unit['blockers'])} |"
        )
    return "\n".join(lines) + "\n"


def run(ws: Path, *, adopt_ledger: bool) -> dict[str, Any]:
    units = build_route_units(ws)
    review_dir = ws / ".auditooor" / "invariant_discovery_review_units"
    for unit in units:
        _write_json(review_dir / f"{unit['unit_id']}.json", unit)
    added = updated = terminalized = 0
    if adopt_ledger:
        added, updated, terminalized = adopt_units(ws, units)
    generated_review = _load_generated_review(ws)
    unreviewed = int(generated_review["unreviewed_missing_count"])
    status = "reduced_invariant_discovery_units_ready"
    if unreviewed:
        status = "blocked_unreviewed_generated_invariants"
    elif adopt_ledger and units:
        status = "reduced_adopted_blocker_rows"
    payload = {
        "schema": SCHEMA,
        "workspace": str(ws),
        "status": status,
        "generated_review": generated_review,
        "route_family_unit_count": len(units),
        "route_family_units": units,
        "review_unit_dir": str(review_dir),
        "ledger_rows_added": added,
        "ledger_rows_updated": updated,
        "generated_ledger_rows_terminalized": terminalized,
        "adopted_to_canonical_invariant_ledger": bool(adopt_ledger),
        "closure_candidate_count": 0,
        "promotion_allowed": False,
        "submission_posture": "NOT_SUBMIT_READY",
        "workspace_neutral": True,
        "proof_boundary": (
            "Invariant discovery adoption names route-family invariants and blockers only. "
            "It does not prove exploit impact, production reachability, OOS clearance, or submit readiness."
        ),
        "next_commands": [
            f"python3 tools/invariant-ledger.py --workspace {ws} --check",
            f"python3 tools/invariant-ledger.py --workspace {ws} --require-high-impact-harness",
            f"make known-limitations-burndown WS={ws} JSON=1",
        ],
    }
    out = ws / ".auditooor" / "invariant_discovery_adoption.json"
    _write_json(out, payload)
    (ws / ".auditooor" / "invariant_discovery_adoption.md").write_text(
        render_markdown(payload), encoding="utf-8"
    )
    return payload


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, help="Workspace path")
    parser.add_argument("--adopt-ledger", action="store_true", help="Append/update blocked rows in INVARIANT_LEDGER")
    parser.add_argument("--print-json", action="store_true", help="Print summary JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    ws = Path(args.workspace).expanduser().resolve()
    if not ws.exists():
        print(f"[invariant-discovery-adoption] workspace not found: {ws}", file=sys.stderr)
        return 2
    payload = run(ws, adopt_ledger=bool(args.adopt_ledger))
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(
            "[invariant-discovery-adoption] "
            f"{payload['status']}: units={payload['route_family_unit_count']} "
            f"added={payload['ledger_rows_added']} updated={payload['ledger_rows_updated']}"
        )
    return 0 if payload["status"] != "blocked_unreviewed_generated_invariants" else 1


if __name__ == "__main__":
    raise SystemExit(main())
