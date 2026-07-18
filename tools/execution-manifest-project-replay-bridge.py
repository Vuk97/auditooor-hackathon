#!/usr/bin/env python3
"""Bridge replay-bundle rows toward project-specific harness requirements.

This reducer intentionally does not prove impact. It consumes an accepted
blocked replay bundle, checks whether each row has candidate-bound project
source/setup evidence, and emits exact terminal requirements when only neutral
Impact-Miss scaffolds are present.
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.execution_manifest_project_replay_bridge.v1"
PROOF_BOUNDARY = (
    "Project replay bridge rows are setup/source requirements only. They do "
    "not prove exploit impact or authorize promotion; proof still requires "
    "poc_execution/**/execution_manifest.json with final_result=proved, "
    "impact_assertion=exploit_impact, evidence_class=executed_with_manifest, "
    "and at least one structured command row with non-empty command, "
    "status=pass, and exit_code=0."
)

SOURCE_EXTENSIONS = {".sol", ".rs", ".go", ".py", ".vy", ".move", ".circom"}
GENERATED_ROOT_PARTS = {
    ".auditooor",
    ".audit_logs",
    "detectors",
    "docs",
    "patterns",
    "poc-tests",
    "poc_execution",
    "source_proofs",
    "test_fixtures",
    "tools",
}
FAMILY_QUERY_TERMS = {
    "access_control": "owner|admin|role|permission|authorize|onlyOwner|access",
    "asset_custody": "transfer|withdraw|deposit|balance|custody|escrow|vault",
    "availability_dos": "pause|halt|revert|loop|limit|gas|DoS|availability|liveness",
    "bridge_finalization": "finalize|withdraw|prove|relay|bridge|message|root",
    "consensus_safety": "consensus|validator|quorum|fork|finality|checkpoint",
    "governance_integrity": "governance|proposal|vote|timelock|delegate|execute",
    "liquidation_solvency": "liquidate|solvency|collateral|debt|health|margin",
    "node_liveness": "heartbeat|sequencer|validator|timeout|liveness|availability",
    "oracle_settlement": "oracle|price|settle|round|feed|stale|twap",
    "proof_verification": "verify|proof|zk|merkle|signature|attestation|root",
    "resource_consumption": "resource|gas|decode|input|limit|exhaust|DoS",
    "signature_replay": "signature|nonce|replay|permit|domain|chainid|ecrecover",
}

FAMILY_LABELS = {
    "access_control": "access-control",
    "asset_custody": "asset-custody",
    "availability_dos": "availability/liveness",
    "bridge_finalization": "bridge-finalization",
    "consensus_safety": "consensus-safety",
    "execution_manifest": "execution-manifest",
    "governance_integrity": "governance-integrity",
    "liquidation_solvency": "liquidation/solvency",
    "node_liveness": "node-liveness",
    "oracle_settlement": "oracle/settlement",
    "proof_verification": "proof-verification",
    "resource_consumption": "resource-consumption",
    "signature_replay": "signature-replay",
}


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise SystemExit(f"[project-replay-bridge] ERR missing input: {path}") from None
    except json.JSONDecodeError as exc:
        raise SystemExit(f"[project-replay-bridge] ERR invalid JSON in {path}: {exc}") from None


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def is_project_source(path: Path, workspace: Path) -> bool:
    try:
        rel = path.resolve().relative_to(workspace)
    except ValueError:
        return False
    if path.suffix not in SOURCE_EXTENSIONS:
        return False
    if not rel.parts:
        return False
    return rel.parts[0] not in GENERATED_ROOT_PARTS


def discover_project_source_files(workspace: Path, limit: int = 50) -> list[str]:
    found: list[str] = []
    for path in workspace.rglob("*"):
        if len(found) >= limit:
            break
        if path.is_file() and is_project_source(path, workspace):
            found.append(str(path.relative_to(workspace)))
    return sorted(found)


def source_review_by_candidate(workspace: Path) -> dict[str, dict[str, Any]]:
    path = workspace / ".auditooor" / "impact_proof_source_review_plan.json"
    if not path.exists():
        return {}
    payload = load_json(path)
    rows = payload.get("rows") if isinstance(payload, dict) else []
    return {
        str(row.get("candidate_id")): row
        for row in rows or []
        if isinstance(row, dict) and row.get("candidate_id")
    }


def load_optional_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    payload = load_json(path)
    return payload if isinstance(payload, dict) else {}


def classify_row(
    workspace: Path,
    family: str,
    row: dict[str, Any],
    source_review: dict[str, dict[str, Any]],
    project_source_files: list[str],
) -> dict[str, Any]:
    candidate_id = str(row.get("candidate_id") or "")
    family_label = FAMILY_LABELS.get(family, family.replace("_", "-"))
    poc_dir = workspace / "poc-tests" / candidate_id
    fixture_dir = workspace / "test_fixtures" / candidate_id
    harness_plan = load_optional_json(poc_dir / "harness_plan.json")
    bounded_fixture = load_optional_json(fixture_dir / "bounded_input_fixture.json")
    review = source_review.get(candidate_id, {})
    review_candidates = review.get("review_candidates") if isinstance(review, dict) else []
    project_review_candidates = [
        item for item in review_candidates or [] if isinstance(item, dict) and item.get("project_source")
    ]

    missing: list[str] = []
    if not review:
        missing.append("source_review_row")
    if not project_source_files:
        missing.append("project_source_root")
    if not project_review_candidates:
        missing.append("candidate_bound_project_source_citation")
    if not poc_dir.exists():
        missing.append("poc_tests_dir")
    if not (poc_dir / "run_harness.sh").exists():
        missing.append("harness_run_command")
    if not fixture_dir.exists():
        missing.append("bounded_input_fixture_dir")
    if not bounded_fixture:
        missing.append("bounded_input_fixture_json")
    if str(row.get("accepted_blocked_status") or "") == "accepted_blocked_missing_target_project":
        missing.append("target_project_binding")

    if missing:
        status = "terminal_missing_project_source_and_setup"
    else:
        status = "project_binding_possible_requires_harness_execution"

    required_setup = [
        {
            "artifact": "project_source_root",
            "status": "missing" if "project_source_root" in missing else "present",
            "description": "In-scope project source files outside generated/tooling directories.",
        },
        {
            "artifact": "candidate_bound_project_source_citation",
            "status": "missing" if "candidate_bound_project_source_citation" in missing else "present",
            "description": f"Line-cited source path for the exact {family_label} mechanism.",
        },
        {
            "artifact": "source_review_row",
            "status": "missing" if "source_review_row" in missing else "present",
            "description": "Source-review plan row for this exact replay candidate.",
        },
        {
            "artifact": "target_project_binding",
            "status": "missing" if "target_project_binding" in missing else "present",
            "description": "Harness replaces neutral benchmark scaffold with project runtime/setup.",
        },
        {
            "artifact": "proved_execution_manifest",
            "status": "missing",
            "description": "Only after project binding may a run be recorded as proved/exploit_impact.",
        },
    ]

    query_terms = FAMILY_QUERY_TERMS.get(family, "impact|exploit|invariant|proof|state")
    next_commands = [
        f"rg -n \"{query_terms}\" <project-source-root> # for {candidate_id}",
        (
            "python3 tools/source-proof-record.py "
            f"--workspace {workspace} --candidate {candidate_id} "
            "--citation '<project-source-file:line>' --oos in_scope "
            f"--verdict proved_source_only --notes '{family_label} project source path; execution proof still required'"
        ),
        (
            f"edit poc-tests/{candidate_id}/run_harness.sh to call the project-specific "
            f"{family_label} benchmark, then run it locally"
        ),
        (
            "python3 tools/poc-execution-record.py "
            f"--workspace {workspace} --brief .auditooor/impact_miss_harness_briefs/{candidate_id}.md "
            f"--candidate-id {candidate_id} --run '<project-specific resource harness command>' "
            "--final-result needs_human --impact-assertion unknown"
        ),
    ]

    return {
        "candidate_id": candidate_id,
        "family": family,
        "bridge_status": status,
        "accepted_blocked_status": row.get("accepted_blocked_status") or "",
        "source_review_decision": review.get("decision") or "",
        "missing_requirements": sorted(set(missing)),
        "required_setup_artifacts": required_setup,
        "project_source_sample": project_source_files[:10],
        "project_review_candidate_count": len(project_review_candidates),
        "harness_plan_status": harness_plan.get("status") or "",
        "bounded_fixture_status": bounded_fixture.get("status") or "",
        "neutral_replay_command": row.get("replay_command") or "",
        "next_local_commands": next_commands,
        "promotion_allowed": False,
        "submit_ready": False,
        "proof_boundary": PROOF_BOUNDARY,
    }


def build_bridge(workspace: Path, family: str, limit: int = 0) -> dict[str, Any]:
    bundle_path = workspace / ".auditooor" / f"execution_manifest_replay_bundle_{family}.json"
    bundle = load_json(bundle_path)
    rows = [row for row in bundle.get("rows") or [] if isinstance(row, dict)]
    if limit > 0:
        rows = rows[:limit]
    reviews = source_review_by_candidate(workspace)
    project_sources = discover_project_source_files(workspace)
    bridge_rows = [classify_row(workspace, family, row, reviews, project_sources) for row in rows]
    terminal = [row for row in bridge_rows if row["bridge_status"].startswith("terminal_")]
    possible = [row for row in bridge_rows if row["bridge_status"] == "project_binding_possible_requires_harness_execution"]
    return {
        "schema": SCHEMA,
        "generated_at_unix": int(time.time()),
        "workspace": str(workspace),
        "family": family,
        "source_bundle_path": str(bundle_path),
        "row_count": len(bridge_rows),
        "terminal_missing_project_source_and_setup_count": len(terminal),
        "project_binding_possible_count": len(possible),
        "project_source_file_count": len(project_sources),
        "promotion_allowed": False,
        "submission_posture": "NOT_SUBMIT_READY",
        "proof_boundary": PROOF_BOUNDARY,
        "rows": bridge_rows,
        "blockers_reduced": {
            "accepted_blocked_rows_terminalized_to_exact_setup_requirements": len(terminal),
            "rows_with_project_binding_possible": len(possible),
        },
    }


def discover_bundle_families(workspace: Path) -> list[str]:
    families: list[str] = []
    for path in sorted((workspace / ".auditooor").glob("execution_manifest_replay_bundle_*.json")):
        if path.name == "execution_manifest_replay_bundle_batch.json":
            continue
        payload = load_json(path)
        if isinstance(payload, dict) and payload.get("schema") == "auditooor.execution_manifest_replay_bundle.v1":
            families.append(str(payload.get("family") or path.stem.replace("execution_manifest_replay_bundle_", "")))
    return sorted(set(families))


def write_bridge_outputs(workspace: Path, payload: dict[str, Any], out_dir: Path | None = None) -> tuple[Path, Path]:
    base = out_dir or (workspace / ".auditooor")
    out_json = base / f"execution_manifest_project_replay_bridge_{payload['family']}.json"
    out_md = base / f"execution_manifest_project_replay_bridge_{payload['family']}.md"
    write_json(out_json, payload)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text(render_markdown(payload), encoding="utf-8")
    return out_json, out_md


def build_batch(workspace: Path, families: list[str], limit: int = 0, out_dir: Path | None = None) -> dict[str, Any]:
    family_payloads = []
    for family in families:
        payload = build_bridge(workspace, family, limit)
        out_json, out_md = write_bridge_outputs(workspace, payload, out_dir)
        family_payloads.append(
            {
                "family": family,
                "row_count": payload["row_count"],
                "terminal_missing_project_source_and_setup_count": payload[
                    "terminal_missing_project_source_and_setup_count"
                ],
                "project_binding_possible_count": payload["project_binding_possible_count"],
                "project_source_file_count": payload["project_source_file_count"],
                "out_json": str(out_json),
                "out_md": str(out_md),
            }
        )
    return {
        "schema": "auditooor.execution_manifest_project_replay_bridge_batch.v1",
        "generated_at_unix": int(time.time()),
        "workspace": str(workspace),
        "family_count": len(family_payloads),
        "row_count": sum(row["row_count"] for row in family_payloads),
        "terminal_missing_project_source_and_setup_count": sum(
            row["terminal_missing_project_source_and_setup_count"] for row in family_payloads
        ),
        "project_binding_possible_count": sum(row["project_binding_possible_count"] for row in family_payloads),
        "promotion_allowed": False,
        "submission_posture": "NOT_SUBMIT_READY",
        "proof_boundary": PROOF_BOUNDARY,
        "families": family_payloads,
    }


def render_batch_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Project Replay Bridge Batch",
        "",
        payload["proof_boundary"],
        "",
        "## Summary",
        "",
        f"- Families: `{payload['family_count']}`",
        f"- Rows: `{payload['row_count']}`",
        f"- Terminal missing source/setup: `{payload['terminal_missing_project_source_and_setup_count']}`",
        f"- Project binding possible: `{payload['project_binding_possible_count']}`",
        f"- Promotion allowed: `{payload['promotion_allowed']}`",
        "",
        "## Families",
        "",
        "| Family | Rows | Terminal missing setup | Binding possible | Artifact |",
        "|---|---:|---:|---:|---|",
    ]
    for row in payload["families"]:
        lines.append(
            f"| `{row['family']}` | `{row['row_count']}` | "
            f"`{row['terminal_missing_project_source_and_setup_count']}` | "
            f"`{row['project_binding_possible_count']}` | `{row['out_json']}` |"
        )
    if not payload["families"]:
        lines.append("| _none_ | 0 | 0 | 0 | _none_ |")
    return "\n".join(lines) + "\n"


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        f"# Project Replay Bridge: {payload['family']}",
        "",
        payload["proof_boundary"],
        "",
        "## Summary",
        "",
        f"- Rows: `{payload['row_count']}`",
        f"- Terminal missing source/setup: `{payload['terminal_missing_project_source_and_setup_count']}`",
        f"- Project binding possible: `{payload['project_binding_possible_count']}`",
        f"- Project source files found: `{payload['project_source_file_count']}`",
        f"- Promotion allowed: `{payload['promotion_allowed']}`",
        "",
        "## Rows",
        "",
        "| Candidate | Bridge status | Missing requirements |",
        "|---|---|---|",
    ]
    for row in payload["rows"]:
        missing = ", ".join(row.get("missing_requirements") or [])
        lines.append(f"| `{row['candidate_id']}` | `{row['bridge_status']}` | `{missing}` |")
    if not payload["rows"]:
        lines.append("| _none_ | _none_ | _none_ |")
    lines.extend(
        [
            "",
            "## Proof Boundary",
            "",
            "Rows here reduce replay blockers into exact source/setup requirements. They remain non-submit-ready until project-specific harness execution is recorded with the exact listed impact.",
        ]
    )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--family", default="resource_consumption")
    parser.add_argument("--families", help="Comma-separated replay bundle families to bridge.")
    parser.add_argument("--all-families", action="store_true", help="Bridge every replay bundle artifact in .auditooor.")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-md", type=Path)
    parser.add_argument("--out-dir", type=Path)
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args(argv)

    workspace = args.workspace.expanduser().resolve()
    if args.all_families or args.families:
        families = discover_bundle_families(workspace) if args.all_families else [
            family.strip() for family in (args.families or "").split(",") if family.strip()
        ]
        if not families:
            raise SystemExit("[project-replay-bridge] ERR no families selected")
        out_dir = args.out_dir.expanduser().resolve() if args.out_dir else None
        payload = build_batch(workspace, families, args.limit, out_dir)
        out_json = args.out_json or workspace / ".auditooor" / "execution_manifest_project_replay_bridge_batch.json"
        out_md = args.out_md or workspace / ".auditooor" / "execution_manifest_project_replay_bridge_batch.md"
        write_json(out_json, payload)
        out_md.parent.mkdir(parents=True, exist_ok=True)
        out_md.write_text(render_batch_markdown(payload), encoding="utf-8")
        if args.print_json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        print(
            "[project-replay-bridge] OK batch "
            f"families={payload['family_count']} rows={payload['row_count']} "
            f"terminal_missing={payload['terminal_missing_project_source_and_setup_count']} "
            f"binding_possible={payload['project_binding_possible_count']}"
        )
        return 0

    out_json = args.out_json or workspace / ".auditooor" / f"execution_manifest_project_replay_bridge_{args.family}.json"
    out_md = args.out_md or workspace / ".auditooor" / f"execution_manifest_project_replay_bridge_{args.family}.md"
    payload = build_bridge(workspace, args.family, args.limit)
    if args.out_json or args.out_md:
        write_json(out_json, payload)
        out_md.parent.mkdir(parents=True, exist_ok=True)
        out_md.write_text(render_markdown(payload), encoding="utf-8")
    else:
        write_bridge_outputs(workspace, payload)
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    print(
        "[project-replay-bridge] OK "
        f"family={payload['family']} rows={payload['row_count']} "
        f"terminal_missing={payload['terminal_missing_project_source_and_setup_count']} "
        f"binding_possible={payload['project_binding_possible_count']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
