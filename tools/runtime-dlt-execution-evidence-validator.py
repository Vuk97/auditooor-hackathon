#!/usr/bin/env python3
"""Validate Rust/DLT runtime execution-evidence blockers.

This sits after ``rust-runtime-semantic-blockers.py`` and the Impact-Miss
harness queue. It joins Blockchain/DLT benchmark rows to runtime-family
coverage, hermetic/non-Base fixture evidence, and poc execution manifests.
The output is a concrete execution-evidence requirement map, not a proof claim.
"""
from __future__ import annotations

import argparse
import json
import shlex
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))
from execution_manifest_proof import (  # noqa: E402
    bound_source_validation,
    command_evidence_counts,
    is_strict_proved_execution_manifest,
)


SCHEMA = "auditooor.pr560.runtime_dlt_execution_evidence_validator.v1"
DEFAULT_RUNTIME_BLOCKERS = ".auditooor/rust_runtime_semantic_blockers.json"
DEFAULT_HARNESS_QUEUE = ".auditooor/impact_miss_harness_blocker_queue.json"
DEFAULT_OUT = ".auditooor/runtime_dlt_execution_evidence_validator.json"
DEFAULT_OUT_MD = ".auditooor/runtime_dlt_execution_evidence_validator.md"
DEFAULT_BUNDLE_DIR = ".auditooor/runtime_dlt_execution_evidence_bundles"

DLT_ROUTE_RUNTIME_FAMILIES = {
    "node_liveness": "execution_client",
    "resource_consumption": "runtime_resource",
    "consensus_safety": "consensus_client",
}

PROOF_BOUNDARY = (
    "Runtime/DLT execution-evidence rows are readiness and blocker evidence "
    "only. A row closes only with project-bound runtime evidence, a hermetic "
    "or non-Base fixture check, and a strict poc_execution manifest with "
    "final_result=proved, impact_assertion=exploit_impact, "
    "evidence_class=executed_with_manifest, and structured status=pass/exit_code=0 "
    "command evidence."
)


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError as exc:
        raise SystemExit(f"[runtime-dlt-evidence] invalid JSON in {path}: {exc}") from None


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.rstrip() + "\n", encoding="utf-8")


def dlt_rows(queue: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        row for row in queue.get("rows") or []
        if isinstance(row, dict) and row.get("asset_category") == "Blockchain/DLT"
    ]


def runtime_family_counts(runtime_payload: dict[str, Any]) -> dict[str, int]:
    counts = runtime_payload.get("runtime_component_family_counts")
    if not isinstance(counts, dict):
        return {}
    out: dict[str, int] = {}
    for key, value in counts.items():
        try:
            out[str(key)] = int(value)
        except (TypeError, ValueError):
            out[str(key)] = 0
    return out


def runtime_family_rows(runtime_payload: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    rows: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in runtime_payload.get("items") or []:
        if isinstance(row, dict):
            rows[str(row.get("runtime_component_family") or "unknown")].append(row)
    return rows


def manifest_for(workspace: Path, benchmark_id: str) -> tuple[Path, dict[str, Any]]:
    path = workspace / "poc_execution" / benchmark_id / "execution_manifest.json"
    payload = load_json(path)
    return path, payload if isinstance(payload, dict) else {}


def manifest_status(workspace: Path, benchmark_id: str) -> dict[str, Any]:
    path, payload = manifest_for(workspace, benchmark_id)
    final_result = str(payload.get("final_result") or "")
    impact_assertion = str(payload.get("impact_assertion") or "")
    evidence_class = str(payload.get("evidence_class") or "")
    counts = command_evidence_counts(payload)
    bound_sources = bound_source_validation(payload, workspace)
    proved = is_strict_proved_execution_manifest(payload) and bound_sources["valid"]
    if not path.is_file():
        status = "missing_execution_manifest"
    elif proved:
        status = "proved_exploit_impact"
    elif final_result:
        status = f"terminal_manifest_{final_result}"
    else:
        status = "terminal_manifest_unproved"
    return {
        "path": str(path),
        "exists": path.is_file(),
        "status": status,
        "final_result": final_result,
        "impact_assertion": impact_assertion,
        "evidence_class": evidence_class,
        "command_count": counts["commands_attempted_count"],
        "structured_command_count": counts["structured_command_count"],
        "passing_command_count": counts["passing_command_count"],
        "proved_exploit_impact": proved,
        "bound_sources": bound_sources,
    }


def artifact_exists(row: dict[str, Any], artifact: str) -> bool:
    for item in row.get("required_artifacts") or []:
        if not isinstance(item, dict):
            continue
        if item.get("artifact") == artifact:
            return bool(item.get("exists"))
    return False


def run_harness_path(workspace: Path, benchmark_id: str) -> Path:
    return workspace / "poc-tests" / benchmark_id / "run_harness.sh"


def harness_binding_status(workspace: Path, row: dict[str, Any]) -> dict[str, Any]:
    benchmark_id = str(row.get("benchmark_id") or "")
    harness = run_harness_path(workspace, benchmark_id)
    text = harness.read_text(encoding="utf-8", errors="replace") if harness.is_file() else ""
    neutral_tokens = ("blocked_missing_target_project", "neutral scaffold", "benchmark-only")
    if not harness.is_file():
        status = "missing_runtime_harness"
    elif any(token in text for token in neutral_tokens):
        status = "terminal_neutral_scaffold_not_project_bound"
    else:
        status = "present_unverified_project_binding"
    return {
        "path": str(harness),
        "exists": harness.is_file(),
        "status": status,
        "project_bound": status == "present_unverified_project_binding",
    }


def write_demo_fixture(workspace: Path) -> Path:
    fixture = workspace / "benchmark_fixtures" / "runtime_dlt_execution_evidence" / "non_base_runtime_demo"
    src = fixture / "src"
    src.mkdir(parents=True, exist_ok=True)
    (fixture / "runtime_model_fixture.json").write_text(
        json.dumps(
            {
                "schema": "auditooor.runtime_dlt_fixture.v1",
                "fixture_kind": "non_base_hermetic",
                "runtime_component_families": ["execution_client", "runtime_resource", "consensus_client"],
                "state_machines": [
                    "block execution / transaction application",
                    "bounded input/resource lifecycle",
                    "fork-choice/finality transition",
                ],
                "proof_boundary": "fixture proves validator plumbing only, not a vulnerability",
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    (src / "lib.rs").write_text(
        "\n".join(
            [
                "pub enum RuntimeFamily { ExecutionClient, RuntimeResource, ConsensusClient }",
                "pub fn execution_client_fixture(input: &[u8]) -> usize { input.len() }",
                "pub fn runtime_resource_fixture(limit: usize) -> bool { limit < 1_000_000 }",
                "pub fn consensus_client_fixture(slot: u64, parent: u64) -> bool { slot >= parent }",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    return fixture


def hermetic_fixture_check(workspace: Path, *, create: bool) -> dict[str, Any]:
    fixture = workspace / "benchmark_fixtures" / "runtime_dlt_execution_evidence" / "non_base_runtime_demo"
    if create:
        fixture = write_demo_fixture(workspace)
    model_path = fixture / "runtime_model_fixture.json"
    source_path = fixture / "src" / "lib.rs"
    model = load_json(model_path)
    source = source_path.read_text(encoding="utf-8", errors="replace") if source_path.is_file() else ""
    required = set(DLT_ROUTE_RUNTIME_FAMILIES.values())
    observed = set(model.get("runtime_component_families") or []) if isinstance(model, dict) else set()
    source_hits = {
        "execution_client": "execution_client_fixture" in source,
        "runtime_resource": "runtime_resource_fixture" in source,
        "consensus_client": "consensus_client_fixture" in source,
    }
    missing = sorted(required - observed)
    missing.extend(sorted(family for family, hit in source_hits.items() if not hit))
    status = "passed" if not missing and model_path.is_file() and source_path.is_file() else "missing_or_incomplete"
    return {
        "status": status,
        "fixture_dir": str(fixture),
        "model_path": str(model_path),
        "source_path": str(source_path),
        "non_base_or_hermetic": True,
        "required_runtime_families": sorted(required),
        "observed_runtime_families": sorted(observed),
        "source_hits": source_hits,
        "missing_inputs": sorted(set(missing)),
        "proof_boundary": "Hermetic fixture check demonstrates validator plumbing only; it is not exploit proof.",
    }


def next_commands(workspace: Path, row: dict[str, Any], expected_family: str, blockers: list[str]) -> list[str]:
    benchmark_id = str(row.get("benchmark_id") or "")
    ws = shlex.quote(str(workspace))
    commands = [
        f"make rust-runtime-semantic-blockers WS={ws} GENERATE=1 LIMIT=300",
        f"python3 tools/runtime-dlt-execution-evidence-validator.py --workspace {ws} --demo-fixture --print-json",
    ]
    if "missing_expected_runtime_family" in blockers:
        commands.append(
            f"python3 tools/rust-runtime-semantic-blockers.py --workspace {ws} --generate-graphs --limit 300"
        )
    if "missing_or_incomplete_hermetic_fixture" in blockers:
        commands.append(
            f"python3 tools/runtime-dlt-execution-evidence-validator.py --workspace {ws} --demo-fixture"
        )
    if "runtime_harness_not_project_bound" in blockers:
        commands.append(
            f"replace poc-tests/{benchmark_id}/run_harness.sh with a project-bound {expected_family} replay/integration command"
        )
    if "execution_manifest_not_proved" in blockers:
        commands.append(
            f"make poc-execution-record WS={ws} CANDIDATE_ID={benchmark_id} "
            f"BRIEF=.auditooor/impact_miss_harness_briefs/{benchmark_id}.md "
            "CMD='<project-bound runtime command>' RESULT=proved IMPACT=exploit_impact"
        )
    return list(dict.fromkeys(commands))


def classify_row(
    workspace: Path,
    row: dict[str, Any],
    family_counts: dict[str, int],
    family_rows: dict[str, list[dict[str, Any]]],
    fixture: dict[str, Any],
) -> dict[str, Any]:
    benchmark_id = str(row.get("benchmark_id") or "")
    route_family = str(row.get("route_family") or "")
    expected_family = DLT_ROUTE_RUNTIME_FAMILIES.get(route_family, "execution_client")
    matching_runtime_rows = int(family_counts.get(expected_family, 0))
    manifest = manifest_status(workspace, benchmark_id)
    harness = harness_binding_status(workspace, row)
    blockers: list[str] = []
    if matching_runtime_rows <= 0:
        blockers.append("missing_expected_runtime_family")
    else:
        blockers.append("runtime_family_present_but_unproved")
    if fixture.get("status") != "passed":
        blockers.append("missing_or_incomplete_hermetic_fixture")
    if not harness.get("project_bound"):
        blockers.append("runtime_harness_not_project_bound")
    if not manifest.get("proved_exploit_impact"):
        blockers.append("execution_manifest_not_proved")
    if not artifact_exists(row, "impact_contract"):
        blockers.append("impact_contract_missing")
    status = "closure_candidate" if not blockers else "terminal_runtime_execution_inputs_missing"
    return {
        "benchmark_id": benchmark_id,
        "task_id": str(row.get("task_id") or ""),
        "tier": str(row.get("tier") or ""),
        "route_family": route_family,
        "expected_runtime_component_family": expected_family,
        "status": status,
        "blockers": blockers,
        "matching_runtime_rows": matching_runtime_rows,
        "sample_runtime_queue_ids": [
            str(item.get("queue_id") or "") for item in family_rows.get(expected_family, [])[:5]
        ],
        "hermetic_fixture_status": fixture.get("status"),
        "harness_binding_status": harness,
        "execution_manifest_status": manifest,
        "next_commands": next_commands(workspace, row, expected_family, blockers),
        "promotion_allowed": False,
        "submission_posture": "NOT_SUBMIT_READY",
        "proof_boundary": PROOF_BOUNDARY,
    }


def build_payload(
    workspace: Path,
    *,
    runtime_path: Path,
    queue_path: Path,
    bundle_dir: Path | None = None,
    create_demo_fixture: bool = False,
) -> dict[str, Any]:
    runtime_payload = load_json(runtime_path)
    queue = load_json(queue_path)
    rows = dlt_rows(queue if isinstance(queue, dict) else {})
    family_counts = runtime_family_counts(runtime_payload if isinstance(runtime_payload, dict) else {})
    family_rows = runtime_family_rows(runtime_payload if isinstance(runtime_payload, dict) else {})
    fixture = hermetic_fixture_check(workspace, create=create_demo_fixture)
    evidence_rows = [
        classify_row(workspace, row, family_counts, family_rows, fixture)
        for row in rows
    ]
    by_route: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in evidence_rows:
        by_route[row["route_family"]].append(row)
    if bundle_dir:
        bundle_dir.mkdir(parents=True, exist_ok=True)
        for route_family, route_rows in sorted(by_route.items()):
            write_json(
                bundle_dir / f"{route_family}.json",
                {
                    "schema": "auditooor.pr560.runtime_dlt_execution_evidence_family.v1",
                    "workspace": str(workspace),
                    "route_family": route_family,
                    "expected_runtime_component_family": DLT_ROUTE_RUNTIME_FAMILIES.get(route_family, "execution_client"),
                    "row_count": len(route_rows),
                    "rows": route_rows,
                    "proof_boundary": PROOF_BOUNDARY,
                },
            )

    blocker_counts = Counter(blocker for row in evidence_rows for blocker in row["blockers"])
    status_counts = Counter(row["status"] for row in evidence_rows)
    route_counts = Counter(row["route_family"] for row in evidence_rows)
    family_status_counts = Counter(
        f"{row['expected_runtime_component_family']}:{'present' if row['matching_runtime_rows'] else 'missing'}"
        for row in evidence_rows
    )
    closure_candidates = [row for row in evidence_rows if row["status"] == "closure_candidate"]
    return {
        "schema": SCHEMA,
        "generated_at_unix": int(time.time()),
        "workspace": str(workspace),
        "runtime_blockers_path": str(runtime_path),
        "harness_queue_path": str(queue_path),
        "dlt_row_count": len(evidence_rows),
        "closure_candidate_count": len(closure_candidates),
        "proved_exploit_impact_count": sum(
            1 for row in evidence_rows if row["execution_manifest_status"].get("proved_exploit_impact")
        ),
        "promotion_allowed": False,
        "submission_posture": "NOT_SUBMIT_READY",
        "proof_boundary": PROOF_BOUNDARY,
        "hermetic_fixture_check": fixture,
        "summary": {
            "status_counts": dict(sorted(status_counts.items())),
            "route_family_counts": dict(sorted(route_counts.items())),
            "expected_runtime_family_status_counts": dict(sorted(family_status_counts.items())),
            "blocker_counts": dict(sorted(blocker_counts.items())),
            "runtime_component_family_counts": dict(sorted(family_counts.items())),
        },
        "reduction_notes": [
            "P1-2 reduced by converting runtime-family source-shape rows into per-DLT execution evidence gates.",
            "P0-6 reduced by joining Blockchain/DLT Impact-Miss rows to expected runtime family, hermetic fixture, harness binding, and execution manifest status.",
            "No row is closed unless all proof-class inputs are present and an exploit-impact execution manifest is proved.",
        ],
        "rows": evidence_rows,
    }


def render_markdown(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    lines = [
        "# Runtime/DLT Execution Evidence Validator",
        "",
        f"- DLT rows: `{payload['dlt_row_count']}`",
        f"- Closure candidates: `{payload['closure_candidate_count']}`",
        f"- Proved exploit-impact manifests: `{payload['proved_exploit_impact_count']}`",
        f"- Submission posture: `{payload['submission_posture']}`",
        f"- Hermetic fixture check: `{payload['hermetic_fixture_check']['status']}`",
        "",
        "## Summary",
        "",
        f"- Status counts: `{summary['status_counts']}`",
        f"- Route-family counts: `{summary['route_family_counts']}`",
        f"- Expected runtime-family status counts: `{summary['expected_runtime_family_status_counts']}`",
        f"- Blocker counts: `{summary['blocker_counts']}`",
        "",
        "## Rows",
        "",
        "| Benchmark | Route | Runtime family | Status | Blockers |",
        "|---|---|---|---|---|",
    ]
    for row in payload["rows"][:300]:
        lines.append(
            "| `{}` | `{}` | `{}` | `{}` | {} |".format(
                row["benchmark_id"],
                row["route_family"],
                row["expected_runtime_component_family"],
                row["status"],
                ", ".join(f"`{blocker}`" for blocker in row["blockers"]) or "none",
            )
        )
    lines.extend(["", "## Proof Boundary", "", payload["proof_boundary"]])
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--runtime-blockers", type=Path)
    parser.add_argument("--harness-queue", type=Path)
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-md", type=Path)
    parser.add_argument("--bundle-dir", type=Path)
    parser.add_argument("--demo-fixture", action="store_true")
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args()

    workspace = args.workspace.expanduser().resolve()
    if not workspace.is_dir():
        print(f"[runtime-dlt-evidence] workspace not found: {workspace}")
        return 2
    runtime_path = (args.runtime_blockers or workspace / DEFAULT_RUNTIME_BLOCKERS).expanduser().resolve()
    queue_path = (args.harness_queue or workspace / DEFAULT_HARNESS_QUEUE).expanduser().resolve()
    out_json = args.out_json or workspace / DEFAULT_OUT
    out_md = args.out_md or workspace / DEFAULT_OUT_MD
    bundle_dir = args.bundle_dir or workspace / DEFAULT_BUNDLE_DIR
    payload = build_payload(
        workspace,
        runtime_path=runtime_path,
        queue_path=queue_path,
        bundle_dir=bundle_dir,
        create_demo_fixture=args.demo_fixture,
    )
    write_json(out_json, payload)
    write_text(out_md, render_markdown(payload))
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    print(
        "[runtime-dlt-evidence] OK "
        f"dlt_rows={payload['dlt_row_count']} closure_candidates={payload['closure_candidate_count']} json={out_json}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
