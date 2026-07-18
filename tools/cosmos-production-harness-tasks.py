#!/usr/bin/env python3
"""Phase-B checklist/artifact emitter for Cosmos production-harness gaps.

This tool is deliberately advisory. It consumes the Phase-A
``cosmos-production-harness-plan.py`` JSON, or invokes the planner over a PoC
directory, and turns missing/violated production-path requirements into
concrete harness tasks.

It does not generate runnable Go code and it does not claim runtime proof.
The output is a work queue for the next human/agent step before any
High/Critical Cosmos app-chain claim can rely on dynamic evidence.

When ``--artifact-dir`` is provided, the tool also writes a bounded v1
production-harness task bundle: per-task JSON records, a Markdown task packet,
a runtime marker contract compatible with ``cosmos-production-harness-exec.py``,
and a Go-facing harness outline. These are concrete task artifacts, not a
project-specific dYdX/Cosmos app factory.

Exit codes:
  0 - checklist emitted
  2 - input error
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.cosmos_production_harness_tasks.v1"
ARTIFACT_BUNDLE_SCHEMA = "auditooor.cosmos_production_harness_task_artifacts.v1"
TASK_ARTIFACT_SCHEMA = "auditooor.cosmos_production_harness_task_artifact.v1"
MARKER_CONTRACT_SCHEMA = "auditooor.cosmos_production_harness_runtime_marker_contract.v1"
TOOL = "cosmos-production-harness-tasks"
REPO = Path(__file__).resolve().parent.parent
PLANNER_PATH = REPO / "tools" / "cosmos-production-harness-plan.py"
RUNTIME_EVENT_SCHEMA = "auditooor.cosmos_production_harness_runtime_event.v1"
RUNTIME_EVENT_PREFIX = "AUDITOOOR_COSMOS_HARNESS_EVENT "
BASE_RUNTIME_EVENTS = ("app_profile", "block_execution", "restart_check", "impact_assertion")
NETWORK_RUNTIME_EVENT = "network_profile"
PRODUCTION_DB_BACKENDS = ("GoLevelDB", "PebbleDB")
PRODUCTION_CONSTRAINTS = {
    "persistent_db_backends": list(PRODUCTION_DB_BACKENDS),
    "forbidden_db_backends": ["MemDB"],
    "forbidden_state_setup": [
        "reflect.NewAt / unsafe.Pointer private-field mutation",
        "raw store or private DB writes to seed proof state",
        "latestVersion / commitInfo / IAVL node DB surgery",
    ],
    "block_driver": "FinalizeBlock followed by Commit, or a documented helper that wraps both.",
    "restart_check": "Close and reopen from the same filesystem data directory, then assert post-restart state.",
    "network_claim_profile": "Network-level claims require >=2 validators/nodes plus liveness/app-hash observations.",
}


TASK_TEMPLATES: dict[str, dict[str, Any]] = {
    "real_db_backend": {
        "title": "Replace MemDB-only setup with persistent production-profile DB",
        "objective": "Drive the PoC against a filesystem-backed Cosmos DB profile.",
        "implementation_notes": [
            "Create a temp data directory owned by the harness.",
            "Instantiate GoLevelDB or PebbleDB from the app setup path.",
            "Keep MemDB only for unit-only helper tests outside the production proof.",
        ],
        "done_when": [
            "Planner sees a persistent DB backend signal.",
            "The harness records the DB type and data directory used.",
        ],
        "suggested_artifacts": [
            "PoC Go test setup diff",
            "planner JSON after rerun",
        ],
    },
    "no_private_state_injection": {
        "title": "Remove private runtime-state mutation from the proof path",
        "objective": "Express the state transition through public app, ABCI, tx, keeper, or documented test-network APIs.",
        "implementation_notes": [
            "Delete reflection/unsafe/raw-store writes from the production proof.",
            "Seed preconditions through genesis, tx delivery, public keeper calls, or documented fixtures.",
            "Leave synthetic state mutation only in a separate negative-control test if useful.",
        ],
        "done_when": [
            "Planner no longer flags reflection/unsafe/raw store writes.",
            "The proof narrative names the public ingress used for every state change.",
        ],
        "suggested_artifacts": [
            "PoC Go test diff",
            "production path notes in draft or harness README",
        ],
    },
    "finalize_block_commit": {
        "title": "Drive block execution through FinalizeBlock plus Commit",
        "objective": "Exercise the same block execution boundary used by the app chain.",
        "implementation_notes": [
            "Call FinalizeBlock and Commit directly, or cite a helper that wraps both.",
            "Record block height and app hash before and after the transition.",
            "Avoid treating a keeper-only call as node-level execution evidence.",
        ],
        "done_when": [
            "Planner sees FinalizeBlock+Commit or an accepted helper signal.",
            "Execution notes identify the exact block driver path.",
        ],
        "suggested_artifacts": [
            "PoC Go test diff",
            "block execution transcript or test log",
        ],
    },
    "restart_behavior": {
        "title": "Add close and reopen restart survival check",
        "objective": "Show the claimed state survives app/DB restart from the same persistent data directory.",
        "implementation_notes": [
            "Close the app, DB, or node cleanly after commit.",
            "Reopen from the same data directory and re-query the relevant state.",
            "Record the pre-restart and post-restart assertion values.",
        ],
        "done_when": [
            "Planner sees close plus reopen/restart behavior.",
            "Harness output includes post-restart state assertions.",
        ],
        "suggested_artifacts": [
            "PoC Go test diff",
            "restart assertion log",
        ],
    },
    "multi_validator_if_claimed": {
        "title": "Run network-level claims on a multi-validator profile",
        "objective": "Back consensus, liveness, AppHash divergence, or chain-halt claims with >=2-validator evidence.",
        "implementation_notes": [
            "Use a test network or subprocess-node harness with at least two validators.",
            "Broadcast the triggering transaction through the network path.",
            "Record per-validator height, app hash, and relevant error/liveness observations.",
        ],
        "done_when": [
            "Planner sees an explicit >=2-validator signal.",
            "Evidence identifies all validator/node processes used in the run.",
        ],
        "suggested_artifacts": [
            "multi-validator harness config",
            "per-validator run transcript",
        ],
    },
}


def _load_planner_module():
    spec = importlib.util.spec_from_file_location("cosmos_production_harness_plan", PLANNER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load planner module from {PLANNER_PATH}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _slug(value: str) -> str:
    out: list[str] = []
    for ch in value.strip().lower():
        if ch.isalnum() or ch in "._-":
            out.append(ch)
        else:
            out.append("-")
    return "".join(out).strip("-") or "candidate"


def _artifact_file_stem(task_id: str) -> str:
    return _slug(task_id).replace(".", "-")


def _poc_inventory(poc_dir: str | Path | None) -> dict[str, Any]:
    if not poc_dir:
        return {"poc_dir": "", "go_files": [], "claim_files": [], "go_mod": ""}
    root = Path(poc_dir)
    if not root.is_dir():
        return {"poc_dir": str(root), "go_files": [], "claim_files": [], "go_mod": ""}
    go_files: list[str] = []
    claim_files: list[str] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = str(path.relative_to(root))
        if path.suffix == ".go":
            go_files.append(rel)
        elif path.suffix.lower() in {".md", ".txt"} and len(claim_files) < 12:
            claim_files.append(rel)
    go_mod = root / "go.mod"
    return {
        "poc_dir": str(root),
        "go_files": go_files[:50],
        "claim_files": claim_files,
        "go_mod": str(go_mod) if go_mod.is_file() else "",
    }


def _load_plan(path: Path) -> dict[str, Any]:
    text = sys.stdin.read() if str(path) == "-" else _read_text(path)
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid planner JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("planner JSON must be an object")
    return payload


def _build_plan_from_inputs(
    poc_dir: Path | None,
    claim_file: Path | None,
    claim_text: str,
    network_claim: bool,
) -> dict[str, Any]:
    planner = _load_planner_module()
    combined_claim = claim_text or ""
    if claim_file is not None:
        if not claim_file.is_file():
            raise ValueError(f"claim-file not found: {claim_file}")
        combined_claim += "\n" + _read_text(claim_file)
    if poc_dir is not None and not poc_dir.is_dir():
        raise ValueError(f"poc-dir not found: {poc_dir}")
    return planner.build_plan(poc_dir, claim_text=combined_claim, network_claim=network_claim)


def _requirements_by_status(plan: dict[str, Any], statuses: set[str]) -> list[dict[str, Any]]:
    requirements = plan.get("requirements", [])
    if not isinstance(requirements, list):
        return []
    return [
        req
        for req in requirements
        if isinstance(req, dict)
        and req.get("required", True)
        and req.get("status") in statuses
    ]


def _task_for_requirement(req: dict[str, Any], ordinal: int) -> dict[str, Any]:
    req_id = str(req.get("id", "unknown_requirement"))
    template = TASK_TEMPLATES.get(req_id, {})
    return {
        "task_id": f"cosmos-phase-b-{ordinal:02d}-{req_id}",
        "source_requirement": req_id,
        "source_status": req.get("status", "unknown"),
        "title": template.get("title", f"Resolve planner requirement: {req_id}"),
        "objective": template.get("objective", req.get("summary", "")),
        "planner_summary": req.get("summary", ""),
        "planner_remediation": req.get("remediation", ""),
        "implementation_notes": template.get("implementation_notes", []),
        "done_when": template.get("done_when", []),
        "suggested_artifacts": template.get("suggested_artifacts", []),
        "evidence_excerpt": req.get("evidence", [])[:3] if isinstance(req.get("evidence"), list) else [],
        "production_constraints": PRODUCTION_CONSTRAINTS,
    }


def build_tasks(plan: dict[str, Any]) -> dict[str, Any]:
    blocking = _requirements_by_status(plan, {"missing", "violated"})
    tasks = [_task_for_requirement(req, idx) for idx, req in enumerate(blocking, start=1)]

    next_runtime_tasks: list[dict[str, Any]] = []
    if not tasks and plan.get("verdict") == "ready":
        next_runtime_tasks = [
            {
                "task_id": "cosmos-phase-b-runtime-01-compile",
                "title": "Compile and run the PoC through the repository's Go test entrypoint",
                "objective": "Move from source-signal readiness to an execution transcript.",
                "done_when": [
                    "The exact go test command is recorded.",
                    "The result is captured in a poc-execution-record or equivalent manifest.",
                ],
            },
            {
                "task_id": "cosmos-phase-b-runtime-02-record-boundary",
                "title": "Record runtime proof boundary before promotion",
                "objective": "Prevent checklist completion from being treated as exploit proof.",
                "done_when": [
                    "The execution record states pass/fail and observed impact.",
                    "Any remaining assumptions are carried into the draft blocker list.",
                ],
            },
        ]

    return {
        "schema": SCHEMA,
        "tool": TOOL,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_plan_schema": plan.get("schema", ""),
        "source_plan_verdict": plan.get("verdict", ""),
        "poc_dir": plan.get("poc_dir", ""),
        "go_files_scanned": plan.get("go_files_scanned", 0),
        "runtime_proof_claimed": False,
        "phase_b_capability": "checklist_from_planner_gaps",
        "summary": {
            "blocking_gap_count": len(tasks),
            "next_runtime_task_count": len(next_runtime_tasks),
            "network_claim": bool((plan.get("claim_signals") or {}).get("network_claim"))
            if isinstance(plan.get("claim_signals"), dict)
            else False,
        },
        "tasks": tasks,
        "next_runtime_tasks": next_runtime_tasks,
        "advisory_boundary": (
            "Phase-B checklist emitter only. Completing these tasks can make a PoC "
            "ready for execution-record capture; it is not runtime proof, exploit "
            "proof, or High/Critical submission evidence by itself."
        ),
    }


def _runtime_task_artifacts(payload: dict[str, Any]) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    for idx, task in enumerate(payload.get("next_runtime_tasks", []), start=1):
        if not isinstance(task, dict):
            continue
        artifacts.append(
            {
                "schema": TASK_ARTIFACT_SCHEMA,
                "task_id": str(task.get("task_id", f"cosmos-runtime-{idx:02d}")),
                "task_phase": "runtime_execution",
                "title": task.get("title", ""),
                "objective": task.get("objective", ""),
                "source_plan_verdict": payload.get("source_plan_verdict", ""),
                "done_when": task.get("done_when", []),
                "production_constraints": PRODUCTION_CONSTRAINTS,
                "required_runtime_markers": list(BASE_RUNTIME_EVENTS),
                "network_runtime_marker": NETWORK_RUNTIME_EVENT
                if payload.get("summary", {}).get("network_claim")
                else "",
                "execution_command_prompt": (
                    "Run a project-owned `go test ...` command through "
                    "`tools/cosmos-production-harness-exec.py --require-runtime-markers`."
                ),
                "runtime_proof_claimed": False,
            }
        )
    return artifacts


def _blocking_task_artifacts(payload: dict[str, Any]) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    for task in payload.get("tasks", []):
        if not isinstance(task, dict):
            continue
        req_id = str(task.get("source_requirement", "unknown_requirement"))
        artifact = {
            "schema": TASK_ARTIFACT_SCHEMA,
            "task_id": str(task.get("task_id", req_id)),
            "task_phase": "source_readiness",
            "title": task.get("title", ""),
            "objective": task.get("objective", ""),
            "source_requirement": req_id,
            "source_status": task.get("source_status", ""),
            "planner_summary": task.get("planner_summary", ""),
            "planner_remediation": task.get("planner_remediation", ""),
            "implementation_notes": task.get("implementation_notes", []),
            "done_when": task.get("done_when", []),
            "suggested_artifacts": task.get("suggested_artifacts", []),
            "evidence_excerpt": task.get("evidence_excerpt", []),
            "production_constraints": PRODUCTION_CONSTRAINTS,
            "runtime_proof_claimed": False,
        }
        if req_id == "multi_validator_if_claimed":
            artifact["multi_validator_liveness_prompts"] = [
                "Record validator_count and node identities; validator_count must be >= 2.",
                "Record the network ingress used for the trigger, e.g. BroadcastTxSync or subprocess node RPC.",
                "Record each validator height and app hash before and after the trigger.",
                "Record whether block production continues for the agreed observation window.",
                "Record timeout or halt symptoms per validator if liveness fails.",
            ]
        artifacts.append(artifact)
    return artifacts


def _marker_contract(network_claim: bool) -> dict[str, Any]:
    required_events = list(BASE_RUNTIME_EVENTS)
    if network_claim:
        required_events.append(NETWORK_RUNTIME_EVENT)
    return {
        "schema": MARKER_CONTRACT_SCHEMA,
        "marker_prefix": RUNTIME_EVENT_PREFIX,
        "marker_event_schema": RUNTIME_EVENT_SCHEMA,
        "required_events": required_events,
        "event_shapes": {
            "app_profile": {
                "required": {
                    "schema": RUNTIME_EVENT_SCHEMA,
                    "event": "app_profile",
                    "app_chain": "<target app-chain slug>",
                    "db_backend": "GoLevelDB | PebbleDB",
                    "data_dir": "<filesystem data directory>",
                    "private_state_injection": False,
                },
                "notes": [
                    "db_backend must be GoLevelDB or PebbleDB.",
                    "MemDB and synthetic private DB mutation are not accepted for production-harness evidence.",
                ],
            },
            "block_execution": {
                "required": {
                    "schema": RUNTIME_EVENT_SCHEMA,
                    "event": "block_execution",
                    "height": "<committed height>",
                    "finalize_block": True,
                    "commit": True,
                    "app_hash": "<post-commit app hash>",
                }
            },
            "restart_check": {
                "required": {
                    "schema": RUNTIME_EVENT_SCHEMA,
                    "event": "restart_check",
                    "restarted": True,
                    "same_data_dir": True,
                    "post_restart_assertion": "<state assertion after reopen>",
                }
            },
            "impact_assertion": {
                "required": {
                    "schema": RUNTIME_EVENT_SCHEMA,
                    "event": "impact_assertion",
                    "assertion": "<invariant or impact statement>",
                    "observed": "<observed state after production block path>",
                }
            },
            "network_profile": {
                "required_when": "network_claim == true",
                "required": {
                    "schema": RUNTIME_EVENT_SCHEMA,
                    "event": "network_profile",
                    "validator_count": ">= 2",
                    "liveness_observation": "<heights/app hashes or halt evidence per validator>",
                },
            },
        },
        "advisory_boundary": (
            "Runtime markers are transcript observations consumed by "
            "cosmos-production-harness-exec.py. They do not independently prove exploit impact."
        ),
    }


def _render_harness_outline(bundle: dict[str, Any], marker_contract_path: str) -> str:
    network_claim = bundle["summary"]["network_claim"]
    lines = [
        "# Cosmos Production Harness Outline",
        "",
        f"- Candidate: `{bundle['candidate_id']}`",
        f"- Source plan verdict: `{bundle['source_plan_verdict']}`",
        f"- Runtime proof claimed: `{str(bundle['runtime_proof_claimed']).lower()}`",
        f"- Marker contract: `{marker_contract_path}`",
        "",
        "## Required App-Chain Shape",
        "",
        "- Use GoLevelDB or PebbleDB on a filesystem temp directory.",
        "- Seed state through genesis, tx delivery, public keeper APIs, or documented test-network fixtures.",
        "- Do not use reflection, unsafe, raw DB writes, or private store mutation to create proof state.",
        "- Drive the transition through FinalizeBlock followed by Commit, or a documented helper that wraps both.",
        "- Close and reopen from the same data directory, then assert the claimed state after restart.",
    ]
    if network_claim:
        lines.extend(
            [
                "- Run the trigger against at least two validators/nodes.",
                "- Record per-validator height, app hash, and liveness outcome for the observation window.",
            ]
        )
    lines.extend(
        [
            "",
            "## Marker Emission Contract",
            "",
            "The Go test should print one JSON marker per observation line:",
            "",
            "```text",
            "AUDITOOOR_COSMOS_HARNESS_EVENT {\"schema\":\"auditooor.cosmos_production_harness_runtime_event.v1\",\"event\":\"app_profile\",...}",
            "```",
            "",
            "Required events:",
        ]
    )
    for event_name in bundle["marker_contract"]["required_events"]:
        lines.append(f"- `{event_name}`")
    lines.extend(
        [
            "",
            "## Execution Prompt",
            "",
            "After the source-readiness tasks are complete, run the project-owned Go test through:",
            "",
            "```bash",
            "python3 tools/cosmos-production-harness-exec.py \\",
            "  --workspace <audit-workspace> \\",
            "  --poc-dir <audit-workspace>/poc-tests/<candidate> \\",
            "  --candidate-id <candidate> \\",
            "  --command 'go test ./... -run TestProductionPath -count=1' \\",
            "  --cwd <audit-workspace>/poc-tests/<candidate> \\",
            "  --require-runtime-markers \\",
            "  --target-app-chain <app-chain-slug> \\",
            "  --print-json",
            "```",
            "",
            "This execution record remains advisory until a project-specific harness establishes the claimed impact.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def _render_artifact_markdown(bundle: dict[str, Any]) -> str:
    lines = [
        "# Cosmos Production Harness Task Bundle",
        "",
        f"- Candidate: `{bundle['candidate_id']}`",
        f"- Source plan verdict: `{bundle['source_plan_verdict']}`",
        f"- Blocking gaps: {bundle['summary']['blocking_gap_count']}",
        f"- Runtime task artifacts: {bundle['summary']['runtime_task_artifact_count']}",
        f"- Network claim: `{str(bundle['summary']['network_claim']).lower()}`",
        f"- Runtime proof claimed: `{str(bundle['runtime_proof_claimed']).lower()}`",
        "",
        bundle["advisory_boundary"],
        "",
        "## Artifacts",
        "",
    ]
    for artifact in bundle["artifacts"]:
        lines.append(f"- `{artifact['kind']}`: `{artifact['path']}`")
    lines.extend(["", "## Task Records", ""])
    for task in bundle["task_artifacts"]:
        lines.append(f"### {task['task_id']}: {task['title']}")
        lines.append("")
        if task.get("source_requirement"):
            lines.append(f"- Requirement: `{task['source_requirement']}` (`{task.get('source_status', '')}`)")
        lines.append(f"- Phase: `{task['task_phase']}`")
        if task.get("objective"):
            lines.append(f"- Objective: {task['objective']}")
        if task.get("planner_remediation"):
            lines.append(f"- Remediation: {task['planner_remediation']}")
        if task.get("multi_validator_liveness_prompts"):
            lines.append("- Multi-validator liveness prompts:")
            lines.extend(f"  - {item}" for item in task["multi_validator_liveness_prompts"])
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def write_artifact_bundle(
    payload: dict[str, Any],
    artifact_dir: Path,
    *,
    candidate_id: str = "",
) -> dict[str, Any]:
    artifact_dir.mkdir(parents=True, exist_ok=True)
    tasks_dir = artifact_dir / "tasks"
    tasks_dir.mkdir(parents=True, exist_ok=True)

    candidate = candidate_id or Path(str(payload.get("poc_dir") or "candidate")).name or "candidate"
    network_claim = bool((payload.get("summary") or {}).get("network_claim"))
    marker_contract = _marker_contract(network_claim)
    task_artifacts = _blocking_task_artifacts(payload) or _runtime_task_artifacts(payload)

    bundle: dict[str, Any] = {
        "schema": ARTIFACT_BUNDLE_SCHEMA,
        "tool": TOOL,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "candidate_id": candidate,
        "source_plan_schema": payload.get("source_plan_schema", ""),
        "source_plan_verdict": payload.get("source_plan_verdict", ""),
        "poc_dir": payload.get("poc_dir", ""),
        "poc_inventory": _poc_inventory(payload.get("poc_dir")),
        "runtime_proof_claimed": False,
        "production_constraints": PRODUCTION_CONSTRAINTS,
        "marker_contract": marker_contract,
        "task_artifacts": task_artifacts,
        "summary": {
            "blocking_gap_count": int((payload.get("summary") or {}).get("blocking_gap_count") or 0),
            "task_artifact_count": len(task_artifacts),
            "runtime_task_artifact_count": len([t for t in task_artifacts if t.get("task_phase") == "runtime_execution"]),
            "network_claim": network_claim,
        },
        "artifacts": [],
        "advisory_boundary": (
            "Cosmos harness artifact bundle only. These files define concrete source-readiness "
            "and runtime-observation tasks for a project-owned app-chain harness; they are not "
            "generated exploit proof or submission-ready evidence."
        ),
    }

    task_paths: list[dict[str, str]] = []
    for task in task_artifacts:
        task_path = tasks_dir / f"{_artifact_file_stem(str(task['task_id']))}.json"
        task_path.write_text(json.dumps(task, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        task_paths.append({"kind": "task", "path": str(task_path), "sha256": _sha256_file(task_path)})

    marker_path = artifact_dir / "runtime_marker_contract.json"
    marker_path.write_text(json.dumps(marker_contract, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    outline_path = artifact_dir / "GO_PRODUCTION_HARNESS_OUTLINE.md"
    outline_path.write_text(_render_harness_outline(bundle, str(marker_path)), encoding="utf-8")

    tasks_json_path = artifact_dir / "cosmos_production_harness_tasks.json"
    tasks_json_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    bundle["artifacts"] = [
        {"kind": "tasks_json", "path": str(tasks_json_path), "sha256": _sha256_file(tasks_json_path)},
        {"kind": "marker_contract", "path": str(marker_path), "sha256": _sha256_file(marker_path)},
        {"kind": "harness_outline", "path": str(outline_path), "sha256": _sha256_file(outline_path)},
        *task_paths,
    ]
    bundle_path = artifact_dir / "cosmos_production_harness_task_bundle.json"
    packet_path = artifact_dir / "COSMOS_PRODUCTION_HARNESS_TASKS.md"
    bundle["artifacts"].extend(
        [
            {"kind": "bundle_json", "path": str(bundle_path), "sha256": ""},
            {"kind": "task_packet_markdown", "path": str(packet_path), "sha256": ""},
        ]
    )
    packet_path.write_text(_render_artifact_markdown(bundle), encoding="utf-8")
    bundle_path.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return bundle


def _render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Cosmos Production Harness Phase-B Tasks",
        "",
        f"- Source plan verdict: `{payload.get('source_plan_verdict', '')}`",
        f"- Blocking gaps: {payload['summary']['blocking_gap_count']}",
        f"- Runtime proof claimed: `{str(payload['runtime_proof_claimed']).lower()}`",
        "",
        payload["advisory_boundary"],
        "",
    ]
    tasks = payload.get("tasks", [])
    if tasks:
        lines.append("## Blocking Harness Tasks")
        lines.append("")
        for task in tasks:
            lines.append(f"### {task['task_id']}: {task['title']}")
            lines.append("")
            lines.append(f"- Source requirement: `{task['source_requirement']}` (`{task['source_status']}`)")
            if task.get("objective"):
                lines.append(f"- Objective: {task['objective']}")
            if task.get("planner_remediation"):
                lines.append(f"- Planner remediation: {task['planner_remediation']}")
            if task.get("done_when"):
                lines.append("- Done when:")
                lines.extend(f"  - {item}" for item in task["done_when"])
            lines.append("")
    else:
        lines.append("## Blocking Harness Tasks")
        lines.append("")
        lines.append("No missing or violated required planner requirements were found.")
        lines.append("")

    next_tasks = payload.get("next_runtime_tasks", [])
    if next_tasks:
        lines.append("## Next Runtime-Proof Tasks")
        lines.append("")
        for task in next_tasks:
            lines.append(f"### {task['task_id']}: {task['title']}")
            lines.append("")
            lines.append(f"- Objective: {task['objective']}")
            if task.get("done_when"):
                lines.append("- Done when:")
                lines.extend(f"  - {item}" for item in task["done_when"])
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--plan", type=Path, help="Planner JSON path, or '-' for stdin.")
    source.add_argument("--poc-dir", type=Path, help="Cosmos PoC Go package directory to inspect via the planner.")
    parser.add_argument("--claim-file", type=Path, help="Optional draft/claim text for planner network-claim detection.")
    parser.add_argument("--claim-text", default="", help="Inline claim text for planner network-claim detection.")
    parser.add_argument("--network-claim", action="store_true", help="Force the planner multi-validator requirement on.")
    parser.add_argument("--format", choices=("json", "markdown"), default="json", help="Output format.")
    parser.add_argument("--out", type=Path, help="Optional output path. Defaults to stdout.")
    parser.add_argument(
        "--artifact-dir",
        type=Path,
        help="Optional directory where concrete v1 production-harness task artifacts are written.",
    )
    parser.add_argument(
        "--candidate-id",
        default="",
        help="Optional candidate id used in artifact bundle metadata; defaults to the PoC directory name.",
    )
    args = parser.parse_args(argv)

    try:
        if args.plan:
            plan = _load_plan(args.plan.expanduser())
        else:
            poc_dir = args.poc_dir.expanduser().resolve() if args.poc_dir else None
            claim_file = args.claim_file.expanduser().resolve() if args.claim_file else None
            plan = _build_plan_from_inputs(poc_dir, claim_file, args.claim_text, args.network_claim)
        payload = build_tasks(plan)
        artifact_bundle = None
        if args.artifact_dir:
            artifact_bundle = write_artifact_bundle(
                payload,
                args.artifact_dir.expanduser().resolve(),
                candidate_id=args.candidate_id,
            )
            payload["artifact_bundle"] = {
                "schema": artifact_bundle["schema"],
                "candidate_id": artifact_bundle["candidate_id"],
                "path": str(args.artifact_dir.expanduser().resolve() / "cosmos_production_harness_task_bundle.json"),
                "artifact_count": len(artifact_bundle["artifacts"]),
                "task_artifact_count": artifact_bundle["summary"]["task_artifact_count"],
            }
    except Exception as exc:
        print(json.dumps({"schema": SCHEMA, "tool": TOOL, "error": str(exc)}, indent=2), file=sys.stderr)
        return 2

    rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if args.format == "markdown":
        rendered = _render_markdown(payload)

    if args.out:
        out = args.out.expanduser().resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
