#!/usr/bin/env python3
"""Materialize neutral next-step artifacts for Impact-Miss blocker rows.

The Impact-Miss benchmark is workspace-neutral, so this executor deliberately
does not prove any finding. It consumes the generated blocker queue and writes
the exact artifact paths that future workers need in order to execute, review,
or terminally close each route-family row without rediscovering the same
missing-artifact state.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.pr560.impact_miss_harness_blocker_execution.v1"
DEFAULT_QUEUE = ".auditooor/impact_miss_harness_blocker_queue.json"
DEFAULT_OUT = ".auditooor/impact_miss_harness_blocker_execution.json"
DEFAULT_OUT_MD = ".auditooor/impact_miss_harness_blocker_execution.md"
PROOF_BOUNDARY = (
    "Generated Impact-Miss artifacts are next-step scaffolds or terminal "
    "missing-evidence blockers only. They are not exploit proof."
)


HARNESS_ARTIFACTS = {
    "funds_flow_poc_or_fork_replay",
    "economic_or_settlement_harness",
    "negative_authorization_fixture",
    "replay_harness",
    "forgery_or_bypass_harness",
    "node_harness",
    "resource_benchmark",
    "consensus_replay_or_model",
    "solvency_harness",
    "governance_state_harness",
    "availability_harness",
}
SOURCE_ARTIFACTS = {"source_proof", "domain_binding_source_proof", "non_privileged_vote_path"}
PRODUCTION_DOSSIERS = {"production_path_dossier", "production_verifier_path"}
LIVE_OR_FORK_ARTIFACTS = {"paired_live_or_fork_proof"}
EXECUTION_ARTIFACTS = {
    "poc_execution_manifest",
    "liveness_measurement",
    "same_input_divergence_proof",
    "victim_accounting_assertion",
    "victim_action_blocked_assertion",
}


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def slug(value: str) -> str:
    return re.sub(r"[^a-z0-9_.-]+", "-", value.lower()).strip("-") or "item"


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_text(path: Path, text: str, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.rstrip() + "\n", encoding="utf-8")
    if mode is not None:
        os.chmod(path, mode)


def load_queue(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise SystemExit(f"[impact-miss-executor] queue missing: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or not isinstance(payload.get("rows"), list):
        raise SystemExit("[impact-miss-executor] queue must be an object with rows[]")
    return payload


def artifact_names(row: dict[str, Any]) -> list[str]:
    names: list[str] = []
    for item in row.get("required_artifacts") or []:
        if isinstance(item, dict) and item.get("artifact"):
            names.append(str(item["artifact"]))
    return names


def artifact_path(row: dict[str, Any], artifact: str) -> Path | None:
    for item in row.get("required_artifacts") or []:
        if isinstance(item, dict) and item.get("artifact") == artifact and item.get("path"):
            return Path(str(item["path"]))
    return None


def impact_contracts_path(workspace: Path) -> Path:
    return workspace / ".auditooor" / "impact_contracts.json"


def load_existing_contracts(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def ensure_impact_contracts(workspace: Path, rows: list[dict[str, Any]]) -> Path:
    path = impact_contracts_path(workspace)
    existing = load_existing_contracts(path)
    existing_contracts = [c for c in existing.get("contracts", []) if isinstance(c, dict)]
    by_candidate = {str(c.get("candidate_id") or ""): c for c in existing_contracts}
    for row in rows:
        candidate = str(row.get("benchmark_id") or row.get("task_id") or "")
        if not candidate or candidate in by_candidate:
            continue
        by_candidate[candidate] = {
            "candidate_id": candidate,
            "impact_contract_id": f"impact-contract-{candidate}",
            "route_family": row.get("route_family"),
            "tier": row.get("tier"),
            "asset_category": row.get("asset_category"),
            "selected_impact": (
                f"{row.get('tier')} {row.get('route_family')} benchmark impact route "
                "requires local proof before submission"
            ),
            "exact_impact_row": True,
            "listed_impact_proven": False,
            "promotion_allowed": False,
            "submission_posture": "NOT_SUBMIT_READY",
            "proof_boundary": PROOF_BOUNDARY,
        }
    payload = {
        "schema": existing.get("schema") or "auditooor.pr560.impact_contracts.v1",
        "generated_at": now_iso(),
        "workspace": str(workspace),
        "status": "benchmark_next_step_contracts_not_proof",
        "contracts": [by_candidate[key] for key in sorted(by_candidate)],
    }
    write_json(path, payload)
    return path


def write_harness(workspace: Path, row: dict[str, Any]) -> list[str]:
    benchmark_id = str(row["benchmark_id"])
    harness_dir = workspace / "poc-tests" / benchmark_id
    plan_path = harness_dir / "harness_plan.json"
    run_path = harness_dir / "run_harness.sh"
    manifest_path = harness_dir / "attempt_manifest.json"
    write_json(
        plan_path,
        {
            "schema": "auditooor.pr560.impact_miss_harness_plan.v1",
            "benchmark_id": benchmark_id,
            "task_id": row.get("task_id"),
            "tier": row.get("tier"),
            "route_family": row.get("route_family"),
            "harness_family": row.get("harness_family"),
            "required_artifacts": artifact_names(row),
            "status": "executable_next_step_not_proof",
            "promotion_allowed": False,
            "submission_posture": "NOT_SUBMIT_READY",
            "proof_boundary": PROOF_BOUNDARY,
        },
    )
    write_text(
        run_path,
        f"""#!/usr/bin/env bash
set -uo pipefail
cat <<'JSON'
{{"benchmark_id":"{benchmark_id}","status":"blocked_missing_target_project","proof":false,"next_step":"replace neutral benchmark scaffold with project-specific harness and rerun poc-execution-record"}}
JSON
exit 2
""",
        mode=0o755,
    )
    write_json(
        manifest_path,
        {
            "schema": "auditooor.pr560.impact_miss_attempt_manifest.v1",
            "benchmark_id": benchmark_id,
            "status": "scaffolded_unverified",
            "harness_dir": str(harness_dir),
            "run_command": str(run_path),
            "proof_boundary": PROOF_BOUNDARY,
        },
    )
    return [str(plan_path), str(run_path), str(manifest_path)]


def write_source_proof(workspace: Path, row: dict[str, Any]) -> list[str]:
    benchmark_id = str(row["benchmark_id"])
    out = workspace / "source_proofs" / f"{benchmark_id}-source-proof" / "source_proof.json"
    write_json(
        out,
        {
            "schema_version": "auditooor.source_proof.v1",
            "candidate_id": benchmark_id,
            "route_family": row.get("route_family"),
            "tier": row.get("tier"),
            "final_verdict": "blocked_missing_project_source_citation",
            "impact_contract_linked": True,
            "source_citations": [],
            "valid_source_citation_count": 0,
            "promotion_allowed": False,
            "evidence_class": "generated_hypothesis",
            "proof_boundary": PROOF_BOUNDARY,
            "next_command": (
                f"make source-proof-record WS={workspace} CANDIDATE={benchmark_id} "
                "CITATION=<path:line> OOS=in_scope VERDICT=proved_source_only"
            ),
        },
    )
    return [str(out)]


def write_production_dossier(workspace: Path, row: dict[str, Any], artifact: str) -> list[str]:
    benchmark_id = str(row["benchmark_id"])
    path = artifact_path(row, artifact) or workspace / ".auditooor" / "production_path_dossiers" / f"{benchmark_id}.json"
    write_json(
        path,
        {
            "schema": "auditooor.pr560.production_path_dossier.v1",
            "benchmark_id": benchmark_id,
            "route_family": row.get("route_family"),
            "tier": row.get("tier"),
            "verdict": "blocked_missing_project_production_path",
            "promotion_allowed": False,
            "required_follow_up": "bind the benchmark route to deployed or in-repo production verifier/bridge wiring",
            "proof_boundary": PROOF_BOUNDARY,
        },
    )
    return [str(path)]


def write_live_or_fork_blocker(workspace: Path, row: dict[str, Any], artifact: str) -> list[str]:
    benchmark_id = str(row["benchmark_id"])
    path = artifact_path(row, artifact) or workspace / ".auditooor" / "live_proof" / f"{benchmark_id}.json"
    write_json(
        path,
        {
            "schema": "auditooor.pr560.live_or_fork_blocker.v1",
            "benchmark_id": benchmark_id,
            "route_family": row.get("route_family"),
            "tier": row.get("tier"),
            "status": "terminal_missing_live_or_fork_target",
            "promotion_allowed": False,
            "proof_boundary": PROOF_BOUNDARY,
        },
    )
    return [str(path)]


def write_bounded_fixture(workspace: Path, row: dict[str, Any], artifact: str) -> list[str]:
    benchmark_id = str(row["benchmark_id"])
    path = artifact_path(row, artifact) or workspace / "test_fixtures" / benchmark_id
    path.mkdir(parents=True, exist_ok=True)
    fixture = path / "bounded_input_fixture.json"
    write_json(
        fixture,
        {
            "schema": "auditooor.pr560.bounded_input_fixture.v1",
            "benchmark_id": benchmark_id,
            "route_family": row.get("route_family"),
            "max_input_bytes": 4096,
            "status": "neutral_fixture_ready_for_project_binding",
            "proof_boundary": PROOF_BOUNDARY,
        },
    )
    return [str(fixture)]


def record_execution(workspace: Path, row: dict[str, Any], harness_paths: list[str]) -> list[str]:
    benchmark_id = str(row["benchmark_id"])
    brief = workspace / ".auditooor" / "impact_miss_harness_briefs" / f"{benchmark_id}.md"
    run_path = workspace / "poc-tests" / benchmark_id / "run_harness.sh"
    if not brief.is_file() or not run_path.is_file():
        return []
    cmd = [
        sys.executable,
        str(Path(__file__).resolve().parent / "poc-execution-record.py"),
        "--workspace",
        str(workspace),
        "--brief",
        str(brief),
        "--candidate-id",
        benchmark_id,
        "--assigned-model",
        "worker-dm",
        "--cwd",
        str(workspace),
        "--run",
        str(run_path),
        "--impact-assertion",
        "not_demonstrated",
        "--final-result",
        "blocked_path",
        "--notes",
        "Neutral Impact-Miss scaffold executed and correctly blocked until project-specific target artifacts are supplied.",
    ]
    for path in harness_paths:
        cmd.extend(["--artifact", path])
    subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return [str(workspace / "poc_execution" / slug(benchmark_id) / "execution_manifest.json")]


def process_row(workspace: Path, row: dict[str, Any], execute_safe: bool) -> dict[str, Any]:
    names = artifact_names(row)
    written: list[str] = []
    actions: list[str] = []
    harness_paths: list[str] = []
    if any(name in HARNESS_ARTIFACTS for name in names):
        harness_paths = write_harness(workspace, row)
        written.extend(harness_paths)
        actions.append("executable_harness_scaffold")
    if any(name in SOURCE_ARTIFACTS for name in names):
        written.extend(write_source_proof(workspace, row))
        actions.append("source_proof_next_step")
    for name in names:
        if name in PRODUCTION_DOSSIERS:
            written.extend(write_production_dossier(workspace, row, name))
            actions.append("terminal_production_path_blocker")
        if name in LIVE_OR_FORK_ARTIFACTS:
            written.extend(write_live_or_fork_blocker(workspace, row, name))
            actions.append("terminal_live_or_fork_blocker")
        if name == "bounded_input_fixture":
            written.extend(write_bounded_fixture(workspace, row, name))
            actions.append("bounded_input_fixture")
    if execute_safe and any(name in EXECUTION_ARTIFACTS for name in names):
        written.extend(record_execution(workspace, row, harness_paths))
        actions.append("blocked_path_execution_manifest")
    return {
        "task_id": row.get("task_id"),
        "benchmark_id": row.get("benchmark_id"),
        "tier": row.get("tier"),
        "route_family": row.get("route_family"),
        "actions": sorted(set(actions)),
        "artifact_paths": sorted(set(written)),
        "promotion_allowed": False,
        "submission_posture": "NOT_SUBMIT_READY",
        "proof_boundary": PROOF_BOUNDARY,
    }


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Impact-Miss Harness Blocker Execution",
        "",
        f"- Rows processed: `{payload['summary']['processed']}`",
        f"- Action counts: `{payload['summary']['action_counts']}`",
        f"- Submission posture: `{payload['submission_posture']}`",
        "",
        "| Task | Tier | Route family | Actions |",
        "|---|---|---|---|",
    ]
    for row in payload["rows"][:300]:
        lines.append(
            f"| `{row['task_id']}` | {row['tier']} | `{row['route_family']}` | "
            f"{', '.join(row['actions']) or 'none'} |"
        )
    lines.extend(["", "## Proof Boundary", "", payload["proof_boundary"]])
    return "\n".join(lines).rstrip() + "\n"


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--queue", type=Path, help=f"Queue JSON; default {DEFAULT_QUEUE}")
    parser.add_argument("--limit", type=int, default=0, help="Optional row limit")
    parser.add_argument("--execute-safe", action="store_true", help="Run neutral blocker harnesses through poc-execution-record")
    parser.add_argument("--out-json", type=Path, help=f"Output JSON; default {DEFAULT_OUT}")
    parser.add_argument("--out-md", type=Path, help=f"Output Markdown; default {DEFAULT_OUT_MD}")
    parser.add_argument("--print-json", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    workspace = args.workspace.expanduser().resolve()
    queue_path = (args.queue or workspace / DEFAULT_QUEUE).expanduser().resolve()
    queue = load_queue(queue_path)
    rows = [row for row in queue["rows"] if isinstance(row, dict)]
    if args.limit:
        rows = rows[: args.limit]
    ensure_impact_contracts(workspace, rows)
    processed = [process_row(workspace, row, args.execute_safe) for row in rows]
    action_counts = Counter(action for row in processed for action in row["actions"])
    tier_counts = Counter(str(row.get("tier") or "") for row in processed)
    route_counts = Counter(str(row.get("route_family") or "") for row in processed)
    payload = {
        "schema": SCHEMA,
        "generated_at": now_iso(),
        "workspace": str(workspace),
        "queue_path": str(queue_path),
        "processed_at_unix": int(time.time()),
        "submission_posture": "NOT_SUBMIT_READY",
        "promotion_allowed": False,
        "submit_ready": False,
        "proof_boundary": PROOF_BOUNDARY,
        "summary": {
            "processed": len(processed),
            "action_counts": dict(sorted(action_counts.items())),
            "tier_counts": dict(sorted(tier_counts.items())),
            "route_family_counts": dict(sorted(route_counts.items())),
        },
        "rows": processed,
    }
    out_json = (args.out_json or workspace / DEFAULT_OUT).expanduser().resolve()
    out_md = (args.out_md or workspace / DEFAULT_OUT_MD).expanduser().resolve()
    write_json(out_json, payload)
    write_text(out_md, render_markdown(payload))
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"[impact-miss-executor] processed {len(processed)} rows -> {out_json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
