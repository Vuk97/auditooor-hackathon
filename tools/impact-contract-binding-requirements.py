#!/usr/bin/env python3
"""Join impact contracts to exact proof-binding requirements.

This PR #560 reducer is intentionally conservative. It consumes the impact
contract split plus source-review, replay-bridge, execution, production-path,
live/fork, and bounded-input artifacts, then emits machine-readable missing
input bundles. It never promotes severity, listed impact, or submit readiness.
"""

from __future__ import annotations

import argparse
import json
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.pr560.impact_contract_binding_requirements.v1"
DEFAULT_OUT = ".auditooor/impact_contract_binding_requirements.json"
DEFAULT_OUT_MD = ".auditooor/impact_contract_binding_requirements.md"
DEFAULT_BUNDLE_DIR = ".auditooor/impact_contract_binding_requirement_bundles"
PROOF_BOUNDARY = (
    "Impact-contract binding requirement rows are exact missing-input bundles "
    "only. They do not prove listed impact, set severity, authorize submission, "
    "or replace pre-submit/OOS/live-proof gates."
)


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError as exc:
        raise SystemExit(f"[impact-binding] ERR invalid JSON in {path}: {exc}") from None


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.rstrip() + "\n", encoding="utf-8")


def passing_structured_command_count(payload: dict[str, Any]) -> int:
    commands = payload.get("commands_attempted")
    if not isinstance(commands, list):
        return 0
    count = 0
    for row in commands:
        if not isinstance(row, dict):
            continue
        command = str(row.get("command") or "").strip()
        status = str(row.get("status") or "").strip().lower()
        exit_code = row.get("exit_code")
        if not command:
            continue
        if status != "pass":
            continue
        if isinstance(exit_code, bool) or exit_code not in {0, "0"}:
            continue
        count += 1
    return count


def is_proved_execution_manifest(payload: dict[str, Any]) -> bool:
    return (
        str(payload.get("final_result") or "") == "proved"
        and str(payload.get("impact_assertion") or "") == "exploit_impact"
        and str(payload.get("evidence_class") or "") == "executed_with_manifest"
        and passing_structured_command_count(payload) > 0
    )


def execution_manifests_by_candidate(workspace: Path) -> dict[str, list[dict[str, Any]]]:
    found: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for path in sorted((workspace / "poc_execution").glob("*/execution_manifest.json")):
        payload = load_json(path)
        if not isinstance(payload, dict):
            continue
        candidate = str(payload.get("candidate_id") or path.parent.name)
        found[candidate].append({"path": str(path), **payload})
    return found


def source_proofs_by_candidate(workspace: Path) -> dict[str, list[dict[str, Any]]]:
    found: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for path in sorted((workspace / "source_proofs").glob("*/source_proof.json")):
        payload = load_json(path)
        if not isinstance(payload, dict):
            continue
        candidate = str(payload.get("candidate_id") or path.parent.name)
        if candidate.endswith("-source-proof"):
            candidate = candidate[: -len("-source-proof")]
        found[candidate].append({"path": str(path), **payload})
    return found


def source_review_by_candidate(workspace: Path) -> dict[str, dict[str, Any]]:
    payload = load_json(workspace / ".auditooor" / "impact_proof_source_review_plan.json")
    rows = payload.get("rows") if isinstance(payload, dict) else []
    return {
        str(row.get("candidate_id")): row
        for row in rows or []
        if isinstance(row, dict) and row.get("candidate_id")
    }


def replay_bridge_by_candidate(workspace: Path) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for path in sorted((workspace / ".auditooor").glob("execution_manifest_project_replay_bridge_*.json")):
        if path.name == "execution_manifest_project_replay_bridge_batch.json":
            continue
        payload = load_json(path)
        if not isinstance(payload, dict) or payload.get("schema") != "auditooor.execution_manifest_project_replay_bridge.v1":
            continue
        for row in payload.get("rows") or []:
            if isinstance(row, dict) and row.get("candidate_id"):
                rows[str(row["candidate_id"])] = {**row, "_artifact": str(path)}
    return rows


def artifact_status(path: Path) -> dict[str, Any]:
    payload = load_json(path)
    if isinstance(payload, dict):
        return {"path": str(path), **payload}
    return {}


def source_citation_status(candidate: str, reviews: dict[str, dict[str, Any]], proofs: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    review = reviews.get(candidate, {})
    review_candidates = review.get("review_candidates") if isinstance(review, dict) else []
    project_review_candidates = [
        row for row in review_candidates or [] if isinstance(row, dict) and row.get("project_source")
    ]
    proof_rows = proofs.get(candidate, [])
    valid_proof_rows = [
        row
        for row in proof_rows
        if int(row.get("valid_source_citation_count") or 0) > 0
        and str(row.get("final_verdict") or "") in {"proved_source_only", "proved"}
    ]
    present = bool(project_review_candidates or valid_proof_rows)
    return {
        "artifact": "candidate_bound_project_source_citation",
        "status": "present" if present else "missing",
        "review_decision": str(review.get("decision") or ""),
        "project_review_candidate_count": len(project_review_candidates),
        "valid_source_proof_count": len(valid_proof_rows),
        "source_proof_paths": [str(row.get("path") or "") for row in proof_rows],
        "missing_reason": "" if present else "no candidate-bound project source citation or proved source-proof row",
    }


def harness_status(candidate: str, replay_rows: dict[str, dict[str, Any]]) -> dict[str, Any]:
    row = replay_rows.get(candidate, {})
    missing = set(row.get("missing_requirements") or [])
    ready = bool(row) and not missing and row.get("bridge_status") == "project_binding_possible_requires_harness_execution"
    return {
        "artifact": "project_specific_harness_execution",
        "status": "present" if ready else "missing",
        "replay_bridge_artifact": str(row.get("_artifact") or ""),
        "replay_bridge_status": str(row.get("bridge_status") or ""),
        "missing_requirements": sorted(missing) if row else ["execution_manifest_project_replay_bridge_row"],
        "missing_reason": "" if ready else "neutral replay scaffold is not bound to project source/runtime",
    }


def proved_execution_status(candidate: str, manifests: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    rows = manifests.get(candidate, [])
    proved = [row for row in rows if is_proved_execution_manifest(row)]
    return {
        "artifact": "proved_exploit_impact_execution_manifest",
        "status": "present" if proved else "missing",
        "manifest_paths": [str(row.get("path") or "") for row in rows],
        "proved_manifest_paths": [str(row.get("path") or "") for row in proved],
        "missing_reason": ""
        if proved
        else (
            "no poc_execution manifest with final_result=proved, impact_assertion=exploit_impact, "
            "evidence_class=executed_with_manifest, and structured status=pass/exit_code=0 command evidence"
        ),
    }


def production_path_status(workspace: Path, candidate: str) -> dict[str, Any]:
    row = artifact_status(workspace / ".auditooor" / "production_path_dossiers" / f"{candidate}.json")
    status = str(row.get("status") or "")
    present = bool(row) and not status.startswith("blocked") and bool(row.get("production_path_proved") or row.get("external_path_reachable"))
    return {
        "artifact": "production_path_dossier",
        "status": "present" if present else "missing",
        "path": str(row.get("path") or workspace / ".auditooor" / "production_path_dossiers" / f"{candidate}.json"),
        "dossier_status": status,
        "missing_reason": "" if present else "production path dossier is missing or terminally blocked",
    }


def live_or_fork_status(workspace: Path, candidate: str) -> dict[str, Any]:
    row = artifact_status(workspace / ".auditooor" / "live_proof" / f"{candidate}.json")
    status = str(row.get("status") or "")
    present = bool(row) and not status.startswith("terminal_missing") and bool(
        row.get("same_block_proved") or row.get("fork_replay_proved") or row.get("executed")
    )
    return {
        "artifact": "paired_live_or_fork_proof",
        "status": "present" if present else "missing",
        "path": str(row.get("path") or workspace / ".auditooor" / "live_proof" / f"{candidate}.json"),
        "proof_status": status,
        "missing_reason": "" if present else "no executed same-block live proof or fork replay proof",
    }


def bounded_input_status(workspace: Path, candidate: str) -> dict[str, Any]:
    row = artifact_status(workspace / "test_fixtures" / candidate / "bounded_input_fixture.json")
    status = str(row.get("status") or "")
    present = bool(row) and ("project_bound" in status or bool(row.get("project_bound")))
    return {
        "artifact": "bounded_project_input_fixture",
        "status": "present" if present else "missing",
        "path": str(row.get("path") or workspace / "test_fixtures" / candidate / "bounded_input_fixture.json"),
        "fixture_status": status,
        "missing_reason": "" if present else "bounded fixture is missing or still neutral/unbound",
    }


REQUIREMENT_CHECKS = {
    "candidate_bound_project_source_citation": source_citation_status,
    "project_specific_harness_execution": harness_status,
    "proved_exploit_impact_execution_manifest": proved_execution_status,
    "production_path_dossier": production_path_status,
    "paired_live_or_fork_proof": live_or_fork_status,
    "bounded_project_input_fixture": bounded_input_status,
}


def next_commands(workspace: Path, candidate: str, route_family: str, missing: list[str]) -> list[str]:
    commands: list[str] = []
    if "candidate_bound_project_source_citation" in missing:
        commands.append(
            f"rg -n \"{route_family}|impact|invariant|withdraw|settle|verify|signature|role\" <project-source-root>"
        )
        commands.append(
            f"python3 tools/source-proof-record.py --workspace {workspace} --candidate {candidate} "
            "--citation '<project-source-file:line>' --oos in_scope --verdict proved_source_only"
        )
    if "project_specific_harness_execution" in missing:
        commands.append(f"edit poc-tests/{candidate}/run_harness.sh to replace neutral scaffold with project-specific setup")
    if "bounded_project_input_fixture" in missing:
        commands.append(f"write project-bound bounded fixture at test_fixtures/{candidate}/bounded_input_fixture.json")
    if "production_path_dossier" in missing:
        commands.append(f"python3 tools/production-path-dossier.py --workspace {workspace} <typed-candidate-for-{candidate}.json>")
    if "paired_live_or_fork_proof" in missing:
        commands.append(f"capture same-block live proof or fork replay for {candidate} with exact expected values")
    if "proved_exploit_impact_execution_manifest" in missing:
        commands.append(
            f"python3 tools/poc-execution-record.py --workspace {workspace} --candidate-id {candidate} "
            "--run '<project-specific harness command>' --final-result proved --impact-assertion exploit_impact"
        )
    return commands


def build_payload(workspace: Path, *, bundle_dir: Path | None = None) -> dict[str, Any]:
    contracts_payload = load_json(workspace / ".auditooor" / "impact_contracts.json")
    contracts = [row for row in contracts_payload.get("contracts") or [] if isinstance(row, dict)]
    reviews = source_review_by_candidate(workspace)
    proofs = source_proofs_by_candidate(workspace)
    replay_rows = replay_bridge_by_candidate(workspace)
    manifests = execution_manifests_by_candidate(workspace)

    rows: list[dict[str, Any]] = []
    for contract in sorted(contracts, key=lambda row: str(row.get("candidate_id") or "")):
        candidate = str(contract.get("candidate_id") or "")
        route_family = str(contract.get("route_family") or "")
        requirements = [str(item) for item in contract.get("exact_proof_requirements") or []]
        requirement_rows: list[dict[str, Any]] = []
        for requirement in requirements:
            if requirement == "candidate_bound_project_source_citation":
                requirement_rows.append(source_citation_status(candidate, reviews, proofs))
            elif requirement == "project_specific_harness_execution":
                requirement_rows.append(harness_status(candidate, replay_rows))
            elif requirement == "proved_exploit_impact_execution_manifest":
                requirement_rows.append(proved_execution_status(candidate, manifests))
            elif requirement == "production_path_dossier":
                requirement_rows.append(production_path_status(workspace, candidate))
            elif requirement == "paired_live_or_fork_proof":
                requirement_rows.append(live_or_fork_status(workspace, candidate))
            elif requirement == "bounded_project_input_fixture":
                requirement_rows.append(bounded_input_status(workspace, candidate))
            else:
                requirement_rows.append(
                    {
                        "artifact": requirement,
                        "status": "missing",
                        "missing_reason": "unknown requirement checker",
                    }
                )
        missing = [row["artifact"] for row in requirement_rows if row.get("status") != "present"]
        proved_manifest = any(row.get("artifact") == "proved_exploit_impact_execution_manifest" and row.get("status") == "present" for row in requirement_rows)
        listed_impact_proven = bool(contract.get("listed_impact_proven"))
        closure_candidate = listed_impact_proven and not missing and proved_manifest
        rows.append(
            {
                "candidate_id": candidate,
                "impact_contract_id": str(contract.get("impact_contract_id") or ""),
                "route_family": route_family,
                "tier": str(contract.get("tier") or ""),
                "required_artifacts": list(contract.get("required_artifacts") or []),
                "exact_proof_requirements": requirements,
                "listed_impact_proven": listed_impact_proven,
                "closure_candidate": closure_candidate,
                "status": "closure_candidate_ready" if closure_candidate else "terminal_missing_binding_inputs",
                "missing_requirements": missing,
                "requirement_statuses": requirement_rows,
                "next_local_commands": next_commands(workspace, candidate, route_family, missing),
                "promotion_allowed": False,
                "submission_posture": "NOT_SUBMIT_READY",
                "proof_boundary": PROOF_BOUNDARY,
            }
        )

    status_counts = Counter(row["status"] for row in rows)
    route_counts = Counter(row["route_family"] for row in rows)
    missing_counts = Counter(item for row in rows for item in row["missing_requirements"])
    requirement_counts = Counter(item for row in rows for item in row["exact_proof_requirements"])
    closure_candidates = [row for row in rows if row["closure_candidate"]]
    payload = {
        "schema": SCHEMA,
        "generated_at_unix": int(time.time()),
        "workspace": str(workspace),
        "contract_count": len(rows),
        "closure_candidate_count": len(closure_candidates),
        "promotion_allowed": False,
        "submission_posture": "NOT_SUBMIT_READY",
        "proof_boundary": PROOF_BOUNDARY,
        "summary": {
            "status_counts": dict(sorted(status_counts.items())),
            "route_family_counts": dict(sorted(route_counts.items())),
            "requirement_counts": dict(sorted(requirement_counts.items())),
            "missing_requirement_counts": dict(sorted(missing_counts.items())),
            "source_review_rows": len(reviews),
            "source_proof_candidates": len(proofs),
            "project_replay_bridge_rows": len(replay_rows),
            "execution_manifest_candidates": len(manifests),
        },
        "rows": rows,
    }
    if bundle_dir:
        write_family_bundles(bundle_dir, payload)
    return payload


def write_family_bundles(bundle_dir: Path, payload: dict[str, Any]) -> None:
    by_family: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in payload["rows"]:
        by_family[str(row.get("route_family") or "unknown")].append(row)
    for family, rows in sorted(by_family.items()):
        missing_counts = Counter(item for row in rows for item in row["missing_requirements"])
        write_json(
            bundle_dir / f"{family}.json",
            {
                "schema": "auditooor.pr560.impact_contract_binding_requirement_family.v1",
                "workspace": payload["workspace"],
                "route_family": family,
                "row_count": len(rows),
                "closure_candidate_count": sum(1 for row in rows if row["closure_candidate"]),
                "missing_requirement_counts": dict(sorted(missing_counts.items())),
                "promotion_allowed": False,
                "submission_posture": "NOT_SUBMIT_READY",
                "proof_boundary": PROOF_BOUNDARY,
                "rows": rows,
            },
        )


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Impact Contract Binding Requirements",
        "",
        PROOF_BOUNDARY,
        "",
        "## Summary",
        "",
        f"- Contracts: `{payload['contract_count']}`",
        f"- Closure candidates: `{payload['closure_candidate_count']}`",
        f"- Promotion allowed: `{payload['promotion_allowed']}`",
        f"- Submission posture: `{payload['submission_posture']}`",
        "",
        "## Missing Requirement Counts",
        "",
    ]
    for key, value in payload["summary"]["missing_requirement_counts"].items():
        lines.append(f"- `{key}`: {value}")
    lines.extend(["", "## Route Families", ""])
    for key, value in payload["summary"]["route_family_counts"].items():
        lines.append(f"- `{key}`: {value}")
    lines.extend(["", "## Sample Rows", ""])
    for row in payload["rows"][:25]:
        lines.append(
            f"- `{row['candidate_id']}`: `{row['status']}`; missing "
            f"{', '.join(f'`{item}`' for item in row['missing_requirements']) or '`none`'}"
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-md", type=Path)
    parser.add_argument("--bundle-dir", type=Path)
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args(argv)

    workspace = args.workspace.expanduser().resolve()
    bundle_dir = (args.bundle_dir or workspace / DEFAULT_BUNDLE_DIR).expanduser().resolve()
    payload = build_payload(workspace, bundle_dir=bundle_dir)
    out_json = (args.out_json or workspace / DEFAULT_OUT).expanduser().resolve()
    out_md = (args.out_md or workspace / DEFAULT_OUT_MD).expanduser().resolve()
    write_json(out_json, payload)
    write_text(out_md, render_markdown(payload))
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    print(
        "[impact-binding] OK "
        f"contracts={payload['contract_count']} closure_candidates={payload['closure_candidate_count']} "
        f"missing={payload['summary']['missing_requirement_counts']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
