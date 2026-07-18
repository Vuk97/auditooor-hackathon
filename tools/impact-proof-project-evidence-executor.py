#!/usr/bin/env python3
"""Resolve Impact-Miss proof blockers against local project evidence.

This PR560 helper is intentionally conservative: it may reduce a blocker from
"missing proof path" to "materialized path needs execution", but it never treats
semantic hints, scaffolds, provider text, or blocked manifests as proof.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from execution_manifest_proof import command_evidence_counts, is_strict_proved_execution_manifest, strict_terminal_blockers


SCHEMA = "auditooor.pr560.impact_proof_project_evidence_executor.v1"
DEFAULT_BACKFILL = ".auditooor/impact_proof_source_citation_backfill.json"
DEFAULT_EXECUTION = ".auditooor/impact_proof_requirement_execution.json"
DEFAULT_OUT = ".auditooor/impact_proof_project_evidence_executor_eo.json"
DEFAULT_OUT_MD = ".auditooor/impact_proof_project_evidence_executor_eo.md"
DEFAULT_ROW_DIR = ".auditooor/impact_proof_project_evidence_rows"
PROOF_BOUNDARY = (
    "Project-evidence execution rows are closure accounting only; they do not "
    "prove listed impact, authorize severity, or allow submission without exact "
    "impact proof, scope/OOS review, and a strict proved execution manifest "
    "(executed_with_manifest plus structured status=pass/exit_code=0 command evidence)."
)
SOURCE_REF_KEYS = (
    "source_refs",
    "source_paths",
    "file_hints",
    "file_line",
    "file_path",
    "source_ref",
    "project_source_refs",
    "project_source_citations",
)
BLOCKER_MARKER_KEYS = (
    "terminal_blockers",
    "blocker",
    "blockers",
    "blocked_reason",
    "blocked_reasons",
    "proof_completion_blockers",
)
CLEARABLE_BLOCKER_MARKERS = {
    "listed_impact_not_proven",
    "missing_execution_or_source_proof",
    "missing_poc_execution_manifest",
    "missing_project_specific_proof_path",
    "missing_proved_poc_execution_manifest",
    "source_proof_missing_project_source_citation",
}
BOOLEAN_BLOCKER_KEYS = ("blocked", "is_blocked", "non_executable", "requires_manual_review")
BOOLEAN_ADVISORY_KEYS = ("advisory", "advisory_only", "informational_only")
STATUS_MARKER_KEYS = (
    "status",
    "requirement_status",
    "proof_status",
    "proof_completion_status",
    "readiness",
    "execution_status",
    "source_status",
)
BLOCKED_STATUS_TOKENS = {
    "advisory",
    "advisory_only",
    "blocked",
    "blocked_path",
    "blocker",
    "generated_hypothesis",
    "informational",
    "manual_only",
    "needs_human",
    "not_executable",
    "not_proof_complete",
    "not_ready",
    "requires_human",
    "requires_manual",
    "scaffolded_unverified",
    "terminal_blocker",
}
EXTERNAL_REF_PREFIXES = (
    "http://",
    "https://",
    "repo:",
    "solodit:",
    "vault://",
    "gh:",
)
LINE_REF_RE = re.compile(r"^(?P<path>.+?):(?P<line>\d+)(?::(?P<end>\d+))?$")


PROOF_PATH_ARTIFACTS = {
    "availability_harness",
    "bounded_input_fixture",
    "consensus_replay_or_model",
    "domain_binding_source_proof",
    "economic_or_settlement_harness",
    "forgery_or_bypass_harness",
    "funds_flow_poc_or_fork_replay",
    "governance_state_harness",
    "liveness_measurement",
    "negative_authorization_fixture",
    "node_harness",
    "non_privileged_vote_path",
    "paired_live_or_fork_proof",
    "poc_execution_manifest",
    "production_path_dossier",
    "production_verifier_path",
    "replay_harness",
    "resource_benchmark",
    "same_input_divergence_proof",
    "solvency_harness",
    "source_proof",
    "victim_accounting_assertion",
    "victim_action_blocked_assertion",
}


FAMILY_COMMANDS = {
    "access_control": [
        "make source-proof-record WS={ws} CANDIDATE={candidate} CITATION='<auth/source/file:line>' OOS=in_scope VERDICT=proved_source_only NOTE='exact non-privileged authorization path'",
        "make poc-execution-record WS={ws} CANDIDATE_ID={candidate} BRIEF=.auditooor/impact_miss_harness_briefs/{candidate}.md CMD='<forge/test command proving non-privileged impact>' RESULT=proved IMPACT=exploit_impact",
    ],
    "bridge_finalization": [
        "python3 tools/live-check-runner.py --workspace {ws} --spec monitoring/live_topology_proof_requirements.generated.json --out-json live_topology_checks.json",
        "make poc-execution-record WS={ws} CANDIDATE_ID={candidate} BRIEF=.auditooor/impact_miss_harness_briefs/{candidate}.md CMD='<same-block bridge/fork proof command>' RESULT=proved IMPACT=exploit_impact",
    ],
    "governance_integrity": [
        "make source-proof-record WS={ws} CANDIDATE={candidate} CITATION='<governance/source/file:line>' OOS=in_scope VERDICT=proved_source_only NOTE='exact non-privileged governance path'",
        "make poc-execution-record WS={ws} CANDIDATE_ID={candidate} BRIEF=.auditooor/impact_miss_harness_briefs/{candidate}.md CMD='<governance-state harness command>' RESULT=proved IMPACT=exploit_impact",
    ],
    "oracle_settlement": [
        "make source-proof-record WS={ws} CANDIDATE={candidate} CITATION='<oracle/settlement/source:line>' OOS=in_scope VERDICT=proved_source_only NOTE='exact oracle settlement path'",
        "make poc-execution-record WS={ws} CANDIDATE_ID={candidate} BRIEF=.auditooor/impact_miss_harness_briefs/{candidate}.md CMD='<oracle/economic settlement harness command>' RESULT=proved IMPACT=exploit_impact",
    ],
    "proof_verification": [
        "make source-proof-record WS={ws} CANDIDATE={candidate} CITATION='<production verifier source:line>' OOS=in_scope VERDICT=proved_source_only NOTE='exact production verifier bypass path'",
        "make poc-execution-record WS={ws} CANDIDATE_ID={candidate} BRIEF=.auditooor/impact_miss_harness_briefs/{candidate}.md CMD='<forgery/replay harness command>' RESULT=proved IMPACT=exploit_impact",
    ],
    "resource_consumption": [
        "make source-proof-record WS={ws} CANDIDATE={candidate} CITATION='<runtime/resource source:line>' OOS=in_scope VERDICT=proved_source_only NOTE='exact bounded-resource path'",
        "make poc-execution-record WS={ws} CANDIDATE_ID={candidate} BRIEF=.auditooor/impact_miss_harness_briefs/{candidate}.md CMD='<resource benchmark command>' RESULT=proved IMPACT=exploit_impact",
    ],
    "signature_replay": [
        "make source-proof-record WS={ws} CANDIDATE={candidate} CITATION='<domain/signature source:line>' OOS=in_scope VERDICT=proved_source_only NOTE='exact signature domain/replay path'",
        "make poc-execution-record WS={ws} CANDIDATE_ID={candidate} BRIEF=.auditooor/impact_miss_harness_briefs/{candidate}.md CMD='<signature replay harness command>' RESULT=proved IMPACT=exploit_impact",
    ],
}


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def slug(value: str) -> str:
    return re.sub(r"[^a-z0-9_.-]+", "-", value.lower()).strip("-") or "item"


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.rstrip() + "\n", encoding="utf-8")


def rows(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        value = payload.get("rows") or []
    elif isinstance(payload, list):
        value = payload
    else:
        value = []
    return [row for row in value if isinstance(row, dict)]


def rel_path(workspace: Path, value: str) -> str:
    if not value:
        return ""
    path = Path(value)
    try:
        return str(path.resolve().relative_to(workspace.resolve()))
    except (OSError, ValueError):
        return str(path)


def coerce_str_list(value: object) -> list[str]:
    if isinstance(value, str):
        text = value.strip()
        return [text] if text else []
    if isinstance(value, list):
        out: list[str] = []
        for item in value:
            out.extend(coerce_str_list(item))
        return out
    if isinstance(value, tuple):
        out: list[str] = []
        for item in value:
            out.extend(coerce_str_list(item))
        return out
    if isinstance(value, dict):
        out: list[str] = []
        for key in ("path", "source_ref", "file_line", "file_path", "artifact", "reason", "status"):
            out.extend(coerce_str_list(value.get(key)))
        return out
    return []


def uniq(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = value.strip()
        if text and text not in seen:
            seen.add(text)
            out.append(text)
    return out


def normalized_token(value: object) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value or "").strip().lower()).strip("_")


def is_under(path: Path, root: Path) -> bool:
    try:
        return path == root or root in path.parents
    except RuntimeError:
        return False


def split_line_ref(ref: str) -> tuple[str, int | None, int | None]:
    text = ref.strip()
    match = LINE_REF_RE.match(text)
    if not match:
        return text, None, None
    start = int(match.group("line"))
    end_text = match.group("end")
    return match.group("path"), start, int(end_text) if end_text else start


def workspace_ref_path(workspace: Path, ref: str) -> tuple[Path | None, str]:
    text = ref.strip()
    if not text:
        return None, "empty"
    if text.lower().startswith(EXTERNAL_REF_PREFIXES):
        return None, "external"
    if text.startswith("<workspace>/"):
        text = text.removeprefix("<workspace>/")
    elif text.startswith("workspace:"):
        text = text.removeprefix("workspace:")
    path_text, _, _ = split_line_ref(text)
    if not path_text or path_text == "<workspace>" or path_text.startswith("<"):
        return None, "placeholder"
    candidate = Path(path_text).expanduser()
    if not candidate.is_absolute():
        candidate = workspace / candidate
    try:
        resolved = candidate.resolve()
    except OSError:
        resolved = candidate
    if not is_under(resolved, workspace):
        return resolved, "outside_workspace"
    return resolved, "workspace"


def line_ref_exists(path: Path, start: int | None, end: int | None) -> bool:
    if start is None:
        return True
    try:
        line_count = sum(1 for _ in path.open("r", encoding="utf-8", errors="ignore"))
    except OSError:
        return False
    return 1 <= start <= line_count and (end is None or start <= end <= line_count)


def current_workspace_refs(workspace: Path, refs: list[str]) -> dict[str, Any]:
    current: list[str] = []
    stale: list[str] = []
    outside: list[str] = []
    external_or_placeholder: list[str] = []
    for ref in uniq(refs):
        path_text, start, end = split_line_ref(ref)
        path, status = workspace_ref_path(workspace, path_text)
        if status == "outside_workspace":
            outside.append(ref)
            continue
        if status != "workspace" or path is None:
            external_or_placeholder.append(ref)
            continue
        if not path.is_file() or not line_ref_exists(path, start, end):
            stale.append(ref)
            continue
        current.append(ref)
    return {
        "current": current,
        "stale": stale,
        "outside_workspace": outside,
        "external_or_placeholder": external_or_placeholder,
    }


def source_refs_from_payload(workspace: Path, payload: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    for key in SOURCE_REF_KEYS:
        refs.extend(coerce_str_list(payload.get(key)))
    for source in payload.get("source_proofs") or []:
        if not isinstance(source, dict):
            continue
        for key in SOURCE_REF_KEYS:
            refs.extend(coerce_str_list(source.get(key)))
        source_path = str(source.get("path") or "").strip()
        if not source_path:
            continue
        path = Path(source_path).expanduser()
        if not path.is_absolute():
            path = workspace / path
        source_payload = read_json(path)
        if isinstance(source_payload, dict):
            for key in SOURCE_REF_KEYS:
                refs.extend(coerce_str_list(source_payload.get(key)))
    return uniq(refs)


def blocker_advisory_markers(*payloads: dict[str, Any]) -> list[str]:
    markers: list[str] = []
    for payload in payloads:
        for key in BOOLEAN_BLOCKER_KEYS:
            if bool(payload.get(key)):
                markers.append(f"{key}_marker")
        for key in BOOLEAN_ADVISORY_KEYS:
            if bool(payload.get(key)):
                markers.append("advisory_only_requirement")
        for key in BLOCKER_MARKER_KEYS:
            for value in coerce_str_list(payload.get(key)):
                if value not in CLEARABLE_BLOCKER_MARKERS:
                    markers.append(value)
        for key in STATUS_MARKER_KEYS:
            token = normalized_token(payload.get(key))
            if token in BLOCKED_STATUS_TOKENS or token.startswith(("blocked", "terminal", "requires_human")):
                markers.append(f"{key}_{token}")
    return uniq(markers)


def project_citation_count(backfill_row: dict[str, Any]) -> int:
    total = 0
    for proof in backfill_row.get("source_proofs") or []:
        if isinstance(proof, dict):
            total += int(proof.get("project_source_citation_count") or 0)
    return total


def proof_path_artifact_status(workspace: Path, execution_row: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    current: list[dict[str, Any]] = []
    stale: list[dict[str, Any]] = []
    outside: list[dict[str, Any]] = []
    external_or_placeholder: list[dict[str, Any]] = []
    for ref in (execution_row.get("local_artifacts") or {}).get("artifact_refs") or []:
        if not isinstance(ref, dict):
            continue
        artifact = str(ref.get("artifact") or "")
        path = str(ref.get("path") or "")
        if artifact not in PROOF_PATH_ARTIFACTS:
            continue
        parsed_path, status = workspace_ref_path(workspace, path)
        row = {
            "artifact": artifact,
            "path": rel_path(workspace, path),
            "required": bool(ref.get("required")),
            "declared_exists": bool(ref.get("exists")),
            "evidence_class": "local_artifact_reference",
        }
        if status == "workspace" and parsed_path is not None and parsed_path.exists() and ref.get("exists"):
            current.append(row)
        elif status == "outside_workspace":
            outside.append(row)
        elif status != "workspace":
            external_or_placeholder.append(row)
        else:
            stale.append(row)
    return {
        "current": current,
        "stale": stale,
        "outside_workspace": outside,
        "external_or_placeholder": external_or_placeholder,
    }


def proof_path_refs(workspace: Path, execution_row: dict[str, Any]) -> list[dict[str, Any]]:
    return proof_path_artifact_status(workspace, execution_row)["current"]


def execution_manifest_status(workspace: Path, execution_row: dict[str, Any]) -> dict[str, Any]:
    manifest = ""
    for ref in (execution_row.get("local_artifacts") or {}).get("artifact_refs") or []:
        if isinstance(ref, dict) and ref.get("artifact") == "poc_execution_manifest" and ref.get("path"):
            manifest = str(ref["path"])
            break
    if not manifest:
        manifest = str(((execution_row.get("execution_manifest") or {}).get("path")) or "")
    path = Path(manifest)
    if manifest and not path.is_absolute():
        path = workspace / manifest
    payload = read_json(path) if manifest else {}
    if not isinstance(payload, dict) or not payload:
        return {"exists": False, "path": rel_path(workspace, manifest)}
    command_counts = command_evidence_counts(payload)
    return {
        "exists": True,
        "path": rel_path(workspace, str(path)),
        "final_result": str(payload.get("final_result") or ""),
        "impact_assertion": str(payload.get("impact_assertion") or ""),
        "evidence_class": str(payload.get("evidence_class") or ""),
        "commands_attempted_count": int(command_counts["commands_attempted_count"]),
        "structured_command_count": int(command_counts["structured_command_count"]),
        "passing_command_count": int(command_counts["passing_command_count"]),
        "proved_impact": is_strict_proved_execution_manifest(payload),
        "strict_proof_blockers": strict_terminal_blockers(payload),
    }


def proof_readiness(
    workspace: Path,
    backfill_row: dict[str, Any],
    execution_row: dict[str, Any],
    refs: list[dict[str, Any]],
    artifact_status: dict[str, list[dict[str, Any]]],
    exec_status: dict[str, Any],
) -> dict[str, Any]:
    source_refs = source_refs_from_payload(workspace, backfill_row) + source_refs_from_payload(workspace, execution_row)
    source_status = current_workspace_refs(workspace, source_refs)
    markers = blocker_advisory_markers(backfill_row, execution_row)
    has_concrete_proof_evidence = bool(exec_status.get("proved_impact")) or bool(refs)
    typed_reasons: list[str] = []
    if not source_status["current"]:
        typed_reasons.append("missing_current_workspace_source_refs")
    if source_status["stale"]:
        typed_reasons.append("stale_workspace_source_ref")
    if source_status["outside_workspace"]:
        typed_reasons.append("source_ref_outside_current_workspace")
    if artifact_status["stale"]:
        typed_reasons.append("stale_workspace_proof_artifact")
    if artifact_status["outside_workspace"]:
        typed_reasons.append("proof_artifact_outside_current_workspace")
    if not has_concrete_proof_evidence:
        typed_reasons.append("missing_concrete_proof_evidence")
    if markers:
        typed_reasons.append("blocker_or_advisory_marker_present")
    executable = (
        bool(source_status["current"])
        and has_concrete_proof_evidence
        and not markers
        and not source_status["stale"]
        and not source_status["outside_workspace"]
        and not artifact_status["stale"]
        and not artifact_status["outside_workspace"]
    )
    proof_ready = executable and bool(exec_status.get("proved_impact"))
    return {
        "executable": executable,
        "proof_ready": proof_ready,
        "typed_reasons": uniq(typed_reasons),
        "current_workspace_source_refs": source_status["current"],
        "stale_workspace_source_refs": source_status["stale"],
        "outside_workspace_source_refs": source_status["outside_workspace"],
        "external_or_placeholder_source_refs": source_status["external_or_placeholder"],
        "has_concrete_proof_command": bool(exec_status.get("proved_impact")),
        "current_workspace_proof_artifacts": refs,
        "stale_workspace_proof_artifacts": artifact_status["stale"],
        "outside_workspace_proof_artifacts": artifact_status["outside_workspace"],
        "external_or_placeholder_proof_artifacts": artifact_status["external_or_placeholder"],
        "blocker_advisory_markers": markers,
    }


def next_commands(workspace: Path, candidate: str, family: str, refs: list[dict[str, Any]]) -> list[str]:
    commands = [
        command.format(ws=workspace, candidate=candidate)
        for command in FAMILY_COMMANDS.get(family, FAMILY_COMMANDS["access_control"])
    ]
    for ref in refs[:3]:
        commands.insert(0, f"test -f {workspace / ref['path']} && sed -n '1,160p' {workspace / ref['path']}")
    commands.append(f"make impact-proof-requirement-executor WS={workspace} JSON=1")
    commands.append(f"make impact-proof-source-citation-backfill WS={workspace} JSON=1")
    return commands


def decision_for(
    backfill_row: dict[str, Any],
    execution_row: dict[str, Any],
    refs: list[dict[str, Any]],
    exec_status: dict[str, Any],
    readiness: dict[str, Any],
) -> tuple[str, list[str]]:
    blockers = set(str(item) for item in backfill_row.get("terminal_blockers") or [] if item)
    blockers.update(str(item) for item in execution_row.get("terminal_blockers") or [] if item)
    blockers.update(readiness["typed_reasons"])
    blockers.update(readiness["blocker_advisory_markers"])
    source_citations = len(readiness["current_workspace_source_refs"])
    listed_impact = bool(execution_row.get("listed_impact_proven") or backfill_row.get("listed_impact_proven"))
    if source_citations:
        blockers.discard("source_proof_missing_project_source_citation")
    if exec_status.get("proved_impact"):
        blockers.discard("missing_poc_execution_manifest")
        blockers.discard("missing_proved_poc_execution_manifest")
    elif exec_status.get("exists"):
        blockers.add("missing_proved_poc_execution_manifest")
        for blocker in exec_status.get("strict_proof_blockers") or []:
            blockers.add(f"execution_manifest_{blocker}")
    else:
        blockers.add("missing_proved_poc_execution_manifest")
    if refs:
        blockers.discard("missing_project_specific_proof_path")
        blockers.discard("missing_execution_or_source_proof")
    if listed_impact:
        blockers.discard("listed_impact_not_proven")
    else:
        blockers.add("listed_impact_not_proven")
    if readiness["proof_ready"] and listed_impact and not blockers:
        return "closure_candidate_requires_scope_oos_review", sorted(blockers)
    if source_citations:
        if readiness["blocker_advisory_markers"] or "blocker_or_advisory_marker_present" in readiness["typed_reasons"]:
            return "project_evidence_blocked_by_markers", sorted(blockers)
        blockers.add("source_citation_present_but_impact_execution_unproved")
        return "source_citation_resolved_execution_unproved", sorted(blockers)
    if refs:
        blockers.add("proof_path_materialized_but_not_executed")
        blockers.add("source_review_required_for_materialized_path")
        return "proof_path_materialized_requires_source_and_execution", sorted(blockers)
    blockers.add("missing_project_specific_proof_path")
    return "terminal_missing_project_specific_proof_path", sorted(blockers)


def build_payload(workspace: Path, *, backfill_path: Path, execution_path: Path, write_rows: bool) -> dict[str, Any]:
    backfill_rows = rows(read_json(backfill_path))
    execution_by_candidate = {str(row.get("candidate_id") or ""): row for row in rows(read_json(execution_path))}
    out_rows = []
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    row_dir = workspace / DEFAULT_ROW_DIR
    for backfill_row in backfill_rows:
        candidate = str(backfill_row.get("candidate_id") or "")
        execution_row = execution_by_candidate.get(candidate, {})
        family = str(backfill_row.get("route_family") or execution_row.get("route_family") or "")
        artifact_status = proof_path_artifact_status(workspace, execution_row)
        refs = artifact_status["current"]
        exec_status = execution_manifest_status(workspace, execution_row)
        readiness = proof_readiness(workspace, backfill_row, execution_row, refs, artifact_status, exec_status)
        decision, blockers = decision_for(backfill_row, execution_row, refs, exec_status, readiness)
        row_path = row_dir / f"{slug(candidate)}.json"
        row = {
            "schema": "auditooor.pr560.impact_proof_project_evidence_executor_row.v1",
            "candidate_id": candidate,
            "requirement_id": str(backfill_row.get("requirement_id") or execution_row.get("requirement_id") or ""),
            "tier": str(backfill_row.get("tier") or execution_row.get("tier") or ""),
            "route_family": family,
            "decision": decision,
            "project_source_citation_count": len(readiness["current_workspace_source_refs"]),
            "reported_project_source_citation_count": project_citation_count(backfill_row),
            "proof_path_artifacts": refs,
            "proof_path_artifact_count": len(refs),
            "proof_path_artifact_status": artifact_status,
            "execution_manifest": exec_status,
            "listed_impact_proven": bool(execution_row.get("listed_impact_proven") or backfill_row.get("listed_impact_proven")),
            "executable": bool(readiness["executable"]),
            "proof_ready": bool(readiness["proof_ready"]) and decision.startswith("closure_candidate"),
            "non_executable_reasons": readiness["typed_reasons"],
            "proof_completeness": readiness,
            "terminal_blockers": blockers,
            "next_local_commands": next_commands(workspace, candidate, family, refs),
            "promotion_allowed": False,
            "submission_posture": "NOT_SUBMIT_READY",
            "proof_boundary": PROOF_BOUNDARY,
            "resolution_manifest_path": str(row_path),
        }
        if write_rows:
            write_json(row_path, row)
        grouped[family].append(
            {
                "candidate_id": candidate,
                "decision": decision,
                "next_local_commands": row["next_local_commands"][:3],
                "terminal_blockers": blockers,
            }
        )
        out_rows.append(row)

    decisions = Counter(row["decision"] for row in out_rows)
    blockers = Counter(blocker for row in out_rows for blocker in row["terminal_blockers"])
    summary = {
        "processed_rows": len(out_rows),
        "closure_candidate_count": decisions.get("closure_candidate_requires_scope_oos_review", 0),
        "source_citation_resolved_count": decisions.get("source_citation_resolved_execution_unproved", 0),
        "proof_path_materialized_count": decisions.get("proof_path_materialized_requires_source_and_execution", 0),
        "terminal_missing_proof_path_count": decisions.get("terminal_missing_project_specific_proof_path", 0),
        "project_source_citation_rows": sum(1 for row in out_rows if row["project_source_citation_count"] > 0),
        "reported_project_source_citation_rows": sum(
            1 for row in out_rows if row["reported_project_source_citation_count"] > 0
        ),
        "proved_execution_manifest_rows": sum(1 for row in out_rows if row["execution_manifest"].get("proved_impact")),
        "proof_ready_rows": sum(1 for row in out_rows if row["proof_ready"]),
        "executable_rows": sum(1 for row in out_rows if row["executable"]),
        "decision_counts": dict(sorted(decisions.items())),
        "terminal_blocker_counts": dict(sorted(blockers.items())),
        "non_executable_reason_counts": dict(
            sorted(Counter(reason for row in out_rows for reason in row["non_executable_reasons"]).items())
        ),
        "tier_counts": dict(sorted(Counter(row["tier"] for row in out_rows).items())),
        "route_family_counts": dict(sorted(Counter(row["route_family"] for row in out_rows).items())),
        "row_dir": str(row_dir),
    }
    return {
        "schema": SCHEMA,
        "generated_at": now_iso(),
        "workspace": str(workspace),
        "source_backfill": str(backfill_path),
        "source_execution": str(execution_path),
        "status": "NOT_SUBMIT_READY",
        "promotion_allowed": False,
        "submission_posture": "NOT_SUBMIT_READY",
        "proof_boundary": PROOF_BOUNDARY,
        "summary": summary,
        "proof_family_work": dict(sorted(grouped.items())),
        "rows": out_rows,
    }


def render_markdown(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    lines = [
        "# Impact-Proof Project Evidence Executor",
        "",
        f"- Status: `{payload['status']}`",
        f"- Rows processed: {summary['processed_rows']}",
        f"- Closure candidates: {summary['closure_candidate_count']}",
        f"- Source-citation resolved rows: {summary['source_citation_resolved_count']}",
        f"- Proof paths materialized: {summary['proof_path_materialized_count']}",
        f"- Terminal missing proof path rows: {summary['terminal_missing_proof_path_count']}",
        f"- Proved execution manifests: {summary['proved_execution_manifest_rows']}",
        f"- Proof-ready rows: {summary['proof_ready_rows']}",
        f"- Executable rows: {summary['executable_rows']}",
        "",
        "## Decisions",
    ]
    for key, value in summary["decision_counts"].items():
        lines.append(f"- `{key}`: {value}")
    lines.extend(["", "## Top Blockers"])
    for key, value in sorted(summary["terminal_blocker_counts"].items(), key=lambda item: (-item[1], item[0]))[:20]:
        lines.append(f"- `{key}`: {value}")
    lines.extend(["", "## Non-Executable Reasons"])
    for key, value in sorted(summary["non_executable_reason_counts"].items(), key=lambda item: (-item[1], item[0]))[:20]:
        lines.append(f"- `{key}`: {value}")
    lines.extend(["", "## Proof Families"])
    for family, items in payload["proof_family_work"].items():
        first = items[0]["next_local_commands"][0] if items and items[0].get("next_local_commands") else ""
        lines.append(f"- `{family}`: {len(items)} rows; first next command: `{first}`")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--backfill", default=DEFAULT_BACKFILL)
    parser.add_argument("--execution", default=DEFAULT_EXECUTION)
    parser.add_argument("--out", default=DEFAULT_OUT)
    parser.add_argument("--out-md", default=DEFAULT_OUT_MD)
    parser.add_argument("--no-row-manifests", action="store_true")
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args()

    workspace = Path(args.workspace).expanduser().resolve()
    if not workspace.exists():
        raise SystemExit(f"[impact-proof-project-evidence-executor] ERR workspace not found: {workspace}")
    backfill = Path(args.backfill)
    if not backfill.is_absolute():
        backfill = workspace / backfill
    execution = Path(args.execution)
    if not execution.is_absolute():
        execution = workspace / execution
    if not backfill.exists():
        raise SystemExit(f"[impact-proof-project-evidence-executor] ERR backfill not found: {backfill}")
    if not execution.exists():
        raise SystemExit(f"[impact-proof-project-evidence-executor] ERR execution not found: {execution}")

    payload = build_payload(
        workspace,
        backfill_path=backfill,
        execution_path=execution,
        write_rows=not args.no_row_manifests,
    )
    out = Path(args.out)
    if not out.is_absolute():
        out = workspace / out
    out_md = Path(args.out_md)
    if not out_md.is_absolute():
        out_md = workspace / out_md
    write_json(out, payload)
    write_text(out_md, render_markdown(payload))
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        summary = payload["summary"]
        print(
            "[impact-proof-project-evidence-executor] "
            f"rows={summary['processed_rows']} proof_paths={summary['proof_path_materialized_count']} "
            f"citations={summary['source_citation_resolved_count']} closures={summary['closure_candidate_count']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
