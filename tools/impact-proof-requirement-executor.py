#!/usr/bin/env python3
"""Resolve PR560 impact-proof requirements into closure candidates or blockers.

This tool consumes `.auditooor/impact_proof_requirement_manifests.json` and
cross-links each requirement to local source-proof, harness, Impact-Miss,
scanner-autonomy, and execution-proof artifacts. It is deliberately conservative:
it never marks impact proved unless the exact row already has a proof-quality
PoC execution manifest and an explicit listed-impact proof flag.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))
try:
    from execution_manifest_proof import (  # noqa: E402
        command_evidence_counts,
        command_status_counts,
        is_strict_proved_execution_manifest,
        strict_proof_blockers,
    )
except ImportError:
    def _manifest_commands(payload: dict[str, Any] | Any) -> list[Any]:
        commands = payload.get("commands_attempted") if isinstance(payload, dict) else payload
        return commands if isinstance(commands, list) else []


    def _is_zero_exit_code(value: object) -> bool:
        if isinstance(value, bool):
            return False
        if isinstance(value, int):
            return value == 0
        if isinstance(value, str):
            return value.strip() == "0"
        return False


    def command_evidence_counts(payload: dict[str, Any]) -> dict[str, int]:
        commands = _manifest_commands(payload)
        structured = 0
        passing = 0
        for row in commands:
            if not isinstance(row, dict):
                continue
            structured += 1
            command = str(row.get("command") or "").strip()
            status = str(row.get("status") or "").strip().lower()
            if command and status == "pass" and _is_zero_exit_code(row.get("exit_code")):
                passing += 1
        return {
            "commands_attempted_count": len(commands),
            "structured_command_count": structured,
            "passing_command_count": passing,
        }


    def command_status_counts(payload: dict[str, Any] | Any) -> dict[str, int]:
        counts: Counter[str] = Counter()
        for row in _manifest_commands(payload):
            if isinstance(row, dict):
                counts[str(row.get("status") or "unknown")] += 1
            else:
                counts["unstructured"] += 1
        return dict(sorted(counts.items()))


    def is_strict_proved_execution_manifest(payload: dict[str, Any]) -> bool:
        counts = command_evidence_counts(payload)
        return (
            str(payload.get("final_result") or payload.get("result") or "") == "proved"
            and str(payload.get("impact_assertion") or "") == "exploit_impact"
            and str(payload.get("evidence_class") or "") == "executed_with_manifest"
            and counts["passing_command_count"] > 0
        )


    def strict_proof_blockers(payload: dict[str, Any]) -> list[str]:
        blockers: list[str] = []
        counts = command_evidence_counts(payload)
        if counts["commands_attempted_count"] <= 0:
            blockers.append("commands_attempted")
        if counts["structured_command_count"] <= 0:
            blockers.append("commands_attempted_structured")
        if counts["passing_command_count"] <= 0:
            blockers.append("commands_attempted_pass_exit_0")
        return blockers


SCHEMA = "auditooor.pr560.impact_proof_requirement_execution.v1"
DEFAULT_IN = ".auditooor/impact_proof_requirement_manifests.json"
DEFAULT_OUT = ".auditooor/impact_proof_requirement_execution.json"
DEFAULT_OUT_MD = ".auditooor/impact_proof_requirement_execution.md"
DEFAULT_BLOCKER_DIR = ".auditooor/impact_proof_terminal_blockers"
DEFAULT_CANDIDATE_DIR = ".auditooor/impact_proof_closure_candidates"
PROOF_BOUNDARY = (
    "Impact-proof execution rows are local closure/blocker evidence only; "
    "they do not set severity, authorize submission, or override scope/OOS gates."
)
SOURCE_REF_KEYS = ("source_refs", "source_paths", "file_hints", "file_line", "file_path", "source_ref")
ARTIFACT_REF_KEYS = (
    "artifact_refs",
    "artifact_paths",
    "proof_artifacts",
    "evidence_artifacts",
    "required_artifacts",
    "output_artifacts",
)
ARTIFACT_PATH_KEYS = (
    "artifact",
    "source_artifact",
    "proof_artifact",
    "transcript_path",
    "output_path",
    "stdout_path",
    "stderr_path",
)
STATUS_MARKER_KEYS = (
    "status",
    "requirement_status",
    "proof_status",
    "proof_completion_status",
    "readiness",
    "execution_status",
    "source_status",
    "bridge_status",
    "benchmark_status",
)
BLOCKER_MARKER_KEYS = (
    "terminal_blockers",
    "blocker",
    "blockers",
    "blocked_reason",
    "blocked_reasons",
    "proof_completion_blockers",
)
BOOLEAN_BLOCKER_KEYS = ("blocked", "is_blocked", "non_executable", "requires_manual_review")
BOOLEAN_ADVISORY_KEYS = ("advisory", "advisory_only", "informational_only")
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


def source_refs_from_payload(payload: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    for key in SOURCE_REF_KEYS:
        refs.extend(coerce_str_list(payload.get(key)))
    for source in payload.get("source_proofs") or []:
        if not isinstance(source, dict):
            continue
        for key in SOURCE_REF_KEYS:
            refs.extend(coerce_str_list(source.get(key)))
        source_path = str(source.get("path") or "").strip()
        source_payload = read_json(Path(source_path)) if source_path else {}
        if isinstance(source_payload, dict):
            for key in SOURCE_REF_KEYS:
                refs.extend(coerce_str_list(source_payload.get(key)))
    return uniq(refs)


def artifact_refs_from_payload(payload: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    for key in ARTIFACT_REF_KEYS:
        refs.extend(coerce_str_list(payload.get(key)))
    for key in ARTIFACT_PATH_KEYS:
        refs.extend(coerce_str_list(payload.get(key)))
    for command in payload.get("commands_attempted") or []:
        if isinstance(command, dict):
            for key in ARTIFACT_PATH_KEYS:
                refs.extend(coerce_str_list(command.get(key)))
    return uniq(refs)


def current_workspace_artifacts(workspace: Path, refs: list[str]) -> list[str]:
    current: list[str] = []
    for ref in uniq(refs):
        path, status = workspace_ref_path(workspace, ref)
        if status == "workspace" and path is not None and path.exists():
            current.append(ref)
    return current


def blocker_advisory_markers(row: dict[str, Any]) -> list[str]:
    markers: list[str] = []
    for key in BOOLEAN_BLOCKER_KEYS:
        if bool(row.get(key)):
            markers.append(f"{key}_marker")
    for key in BOOLEAN_ADVISORY_KEYS:
        if bool(row.get(key)):
            markers.append("advisory_only_requirement")
    for key in BLOCKER_MARKER_KEYS:
        for value in coerce_str_list(row.get(key)):
            markers.append(value)
    for key in STATUS_MARKER_KEYS:
        token = normalized_token(row.get(key))
        if token in BLOCKED_STATUS_TOKENS or token.startswith(("blocked", "terminal", "requires_human")):
            markers.append(f"{key}_{token}")
    return uniq(markers)


def proof_completeness(row: dict[str, Any], manifest: dict[str, Any], workspace: Path) -> dict[str, Any]:
    source_refs = source_refs_from_payload(row)
    ref_status = current_workspace_refs(workspace, source_refs)
    command_evidence = is_strict_proved_execution_manifest(manifest) if manifest else False
    artifact_refs = artifact_refs_from_payload(row) + artifact_refs_from_payload(manifest)
    current_artifacts = current_workspace_artifacts(workspace, artifact_refs)
    markers = blocker_advisory_markers(row)
    reasons: list[str] = []
    if not ref_status["current"]:
        reasons.append("missing_current_workspace_source_refs")
    if ref_status["stale"]:
        reasons.append("stale_workspace_source_ref")
    if ref_status["outside_workspace"]:
        reasons.append("source_ref_outside_current_workspace")
    if not command_evidence and not current_artifacts:
        reasons.append("missing_concrete_proof_evidence")
    if markers:
        reasons.append("blocker_or_advisory_marker_present")
    proof_complete = bool(ref_status["current"]) and command_evidence and not markers and not ref_status["stale"] and not ref_status["outside_workspace"]
    executable = bool(ref_status["current"]) and (command_evidence or bool(current_artifacts)) and not markers and not ref_status["stale"] and not ref_status["outside_workspace"]
    return {
        "executable": executable,
        "proof_complete": proof_complete,
        "typed_reasons": uniq(reasons),
        "current_workspace_source_refs": ref_status["current"],
        "stale_workspace_source_refs": ref_status["stale"],
        "outside_workspace_source_refs": ref_status["outside_workspace"],
        "external_or_placeholder_source_refs": ref_status["external_or_placeholder"],
        "has_concrete_proof_command": command_evidence,
        "current_workspace_proof_artifacts": current_artifacts,
        "blocker_advisory_markers": markers,
    }


def list_rows(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        rows = payload.get("rows") or payload.get("contracts") or payload.get("items") or []
    elif isinstance(payload, list):
        rows = payload
    else:
        rows = []
    return [row for row in rows if isinstance(row, dict)]


def rows_by_candidate(payload: Any, *keys: str) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    for row in list_rows(payload):
        candidate = ""
        for key in keys:
            candidate = str(row.get(key) or "")
            if candidate:
                break
        if candidate:
            out.setdefault(candidate, []).append(row)
    return out


def summarize_execution_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    if not manifest:
        return {}
    commands = manifest.get("commands_attempted")
    command_rows = commands if isinstance(commands, list) else []
    counts = command_evidence_counts(manifest)
    return {
        "path": str(manifest.get("path") or ""),
        "final_result": str(manifest.get("final_result") or manifest.get("result") or ""),
        "impact_assertion": str(manifest.get("impact_assertion") or ""),
        "commands_attempted_count": len(command_rows),
        "structured_command_count": counts["structured_command_count"],
        "passing_command_count": counts["passing_command_count"],
        "command_status_counts": command_status_counts(manifest),
        "evidence_class": str(manifest.get("evidence_class") or ""),
        "first_command": str(command_rows[0].get("command") or "") if command_rows and isinstance(command_rows[0], dict) else "",
        "strict_proved": is_strict_proved_execution_manifest(manifest),
        "strict_proof_blockers": strict_proof_blockers(manifest),
    }


def read_manifest_from_path(row: dict[str, Any]) -> dict[str, Any]:
    path_text = str((row.get("execution_manifest") or {}).get("path") or "")
    if not path_text:
        return {}
    payload = read_json(Path(path_text))
    if isinstance(payload, dict):
        payload.setdefault("path", path_text)
        return payload
    return {}


def next_commands(row: dict[str, Any], queue_row: dict[str, Any]) -> list[str]:
    commands: list[str] = []
    for command in queue_row.get("runnable_next_commands") or []:
        if isinstance(command, str) and command not in commands:
            commands.append(command)
    candidate = str(row.get("candidate_id") or "")
    if not commands and candidate:
        commands.extend(
            [
                f"make impact-miss-harness-blocker-executor WS=<workspace> LIMIT=384",
                f"make poc-execution-record WS=<workspace> BRIEF=.auditooor/impact_miss_harness_briefs/{candidate}.md CANDIDATE_ID={candidate} CMD='<executed local harness command>' RESULT=needs_human IMPACT=unknown",
            ]
        )
    return commands


def local_artifact_links(
    row: dict[str, Any],
    *,
    queue_row: dict[str, Any],
    impact_miss_row: dict[str, Any],
    bridge_row: dict[str, Any],
    scanner_rows: list[dict[str, Any]],
    execution_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    candidate = str(row.get("candidate_id") or "")
    manifest = read_manifest_from_path(row)
    links = {
        "requirement_manifest_path": str(row.get("requirement_manifest_path") or ""),
        "impact_contract_id": str(row.get("impact_contract_id") or ""),
        "source_proof_paths": [
            str(source.get("path") or "")
            for source in row.get("source_proofs") or []
            if isinstance(source, dict) and source.get("path")
        ],
        "artifact_refs": row.get("artifact_refs") or [],
        "impact_miss_artifact_paths": impact_miss_row.get("artifact_paths") or [],
        "harness_family": str(queue_row.get("harness_family") or ""),
        "bridge_status": str(bridge_row.get("status") or row.get("bridge_status") or ""),
        "scanner_autonomy_matches": [
            {
                "source_id": str(scanner.get("source_id") or ""),
                "status": str(scanner.get("status") or ""),
                "action_lane": str(scanner.get("action_lane") or ""),
                "source_artifact": str(scanner.get("source_artifact") or ""),
            }
            for scanner in scanner_rows
        ],
        "execution_proof_matches": [
            {
                "task_id": str(item.get("task_id") or ""),
                "readiness": str(item.get("readiness") or ""),
                "proof_kind": str(item.get("proof_kind") or ""),
                "runnable_command": str(item.get("runnable_command") or ""),
            }
            for item in execution_rows
        ],
        "poc_execution_manifest": summarize_execution_manifest(manifest),
    }
    if candidate:
        links["candidate_local_paths"] = {
            "poc_tests_dir": f"poc-tests/{candidate}",
            "poc_execution_dir": f"poc_execution/{candidate}",
            "impact_miss_brief": f".auditooor/impact_miss_harness_briefs/{candidate}.md",
        }
    return links


def decision_for(row: dict[str, Any], manifest: dict[str, Any], workspace: Path) -> tuple[str, list[str], dict[str, Any]]:
    blockers = set(str(item) for item in row.get("terminal_blockers") or [] if item)
    proof_check = proof_completeness(row, manifest, workspace)
    blockers.update(proof_check["typed_reasons"])
    blockers.update(proof_check["blocker_advisory_markers"])
    if not bool(row.get("exact_impact_row")):
        blockers.add("impact_contract_not_exact")
    if not bool(row.get("listed_impact_proven")):
        blockers.add("listed_impact_not_proven")
    final_result = str(manifest.get("final_result") or manifest.get("result") or "")
    impact_assertion = str(manifest.get("impact_assertion") or "")
    evidence_class = str(manifest.get("evidence_class") or "")
    commands = manifest.get("commands_attempted")
    command_count = len(commands) if isinstance(commands, list) else 0
    strict_manifest = is_strict_proved_execution_manifest(manifest)
    if manifest:
        if final_result != "proved":
            blockers.add(f"execution_manifest_{final_result or 'not_proved'}")
        if impact_assertion != "exploit_impact":
            blockers.add(f"impact_assertion_{impact_assertion or 'missing'}")
        if command_count <= 0:
            blockers.add("execution_manifest_missing_commands_attempted")
        if evidence_class != "executed_with_manifest":
            blockers.add("execution_manifest_evidence_class_executed_with_manifest")
        strict_blockers = set(strict_proof_blockers(manifest))
        if "commands_attempted_structured" in strict_blockers:
            blockers.add("execution_manifest_commands_attempted_structured")
        if "commands_attempted_pass_exit_0" in strict_blockers:
            blockers.add("execution_manifest_commands_attempted_pass_exit_0")
    else:
        blockers.add("missing_poc_execution_manifest")
    source_rows = [source for source in row.get("source_proofs") or [] if isinstance(source, dict)]
    if source_rows and not any(int(source.get("valid_source_citation_count") or 0) > 0 for source in source_rows):
        blockers.add("source_proof_missing_project_source_citation")
    if (
        bool(row.get("exact_impact_row"))
        and bool(row.get("listed_impact_proven"))
        and manifest
        and strict_manifest
        and proof_check["proof_complete"]
        and not blockers
    ):
        return "closure_candidate_requires_scope_oos_review", sorted(blockers), proof_check
    if manifest:
        return "terminal_blocker_execution_manifest_unproved", sorted(blockers), proof_check
    if source_rows or source_refs_from_payload(row):
        return "terminal_blocker_source_proof_incomplete", sorted(blockers), proof_check
    return "terminal_blocker_missing_project_specific_proof", sorted(blockers), proof_check


def build_payload(workspace: Path, *, manifest_path: Path, write_rows: bool) -> dict[str, Any]:
    payload = read_json(manifest_path)
    requirement_rows = list_rows(payload)
    aud = workspace / ".auditooor"
    queue_by_candidate = rows_by_candidate(read_json(aud / "impact_miss_harness_blocker_queue.json"), "benchmark_id", "candidate_id")
    impact_miss_by_candidate = rows_by_candidate(read_json(aud / "impact_miss_harness_blocker_execution.json"), "benchmark_id", "candidate_id")
    bridge_by_candidate = rows_by_candidate(read_json(aud / "source_proof_impact_bridge.json"), "candidate_id")
    scanner_rows = list_rows(read_json(aud / "scanner_autonomy_execution.json"))
    exec_proof_rows = list_rows(read_json(aud / "execution_proof_command_manifest.json"))

    out_rows: list[dict[str, Any]] = []
    blocker_dir = workspace / DEFAULT_BLOCKER_DIR
    candidate_dir = workspace / DEFAULT_CANDIDATE_DIR
    for index, row in enumerate(requirement_rows, start=1):
        candidate = str(row.get("candidate_id") or "")
        queue_row = (queue_by_candidate.get(candidate) or [{}])[0]
        impact_miss_row = (impact_miss_by_candidate.get(candidate) or [{}])[0]
        bridge_row = (bridge_by_candidate.get(candidate) or [{}])[0]
        scanner_matches = [
            item
            for item in scanner_rows
            if candidate and candidate in json.dumps(item, sort_keys=True)
        ][:5]
        execution_matches = [
            item
            for item in exec_proof_rows
            if candidate and candidate in json.dumps(item, sort_keys=True)
        ][:5]
        manifest = read_manifest_from_path(row)
        decision, blockers, proof_check = decision_for(row, manifest, workspace)
        output_path = candidate_dir / f"{slug(candidate)}.json" if decision.startswith("closure_candidate") else blocker_dir / f"{slug(candidate)}.json"
        resolved = {
            "schema": "auditooor.pr560.impact_proof_requirement_execution_row.v1",
            "resolution_id": f"IPRE-{index:03d}",
            "candidate_id": candidate,
            "requirement_id": str(row.get("requirement_id") or ""),
            "tier": str(row.get("tier") or ""),
            "route_family": str(row.get("route_family") or ""),
            "asset_category": str(row.get("asset_category") or ""),
            "decision": decision,
            "promotion_allowed": False,
            "submission_posture": "NOT_SUBMIT_READY",
            "exact_impact_row": bool(row.get("exact_impact_row")),
            "listed_impact_proven": bool(row.get("listed_impact_proven")),
            "executable": bool(proof_check["executable"]),
            "proof_complete": bool(proof_check["proof_complete"]),
            "non_executable_reasons": proof_check["typed_reasons"],
            "proof_completeness": proof_check,
            "terminal_blockers": blockers,
            "next_local_commands": next_commands(row, queue_row),
            "local_artifacts": local_artifact_links(
                row,
                queue_row=queue_row,
                impact_miss_row=impact_miss_row,
                bridge_row=bridge_row,
                scanner_rows=scanner_matches,
                execution_rows=execution_matches,
            ),
            "acceptance_gate": row.get("acceptance_gate")
            or "Requires exact listed impact proof plus a proved poc_execution manifest.",
            "proof_boundary": PROOF_BOUNDARY,
        }
        if write_rows:
            write_json(output_path, resolved)
            resolved["resolution_manifest_path"] = str(output_path)
        out_rows.append(resolved)

    decisions = Counter(row["decision"] for row in out_rows)
    blockers = Counter(blocker for row in out_rows for blocker in row["terminal_blockers"])
    routes = Counter(row["route_family"] for row in out_rows)
    tiers = Counter(row["tier"] for row in out_rows)
    closure_candidates = [row for row in out_rows if row["decision"].startswith("closure_candidate")]
    return {
        "schema": SCHEMA,
        "generated_at": now_iso(),
        "workspace": str(workspace),
        "source_manifest": str(manifest_path),
        "status": "ok_resolved_requirements",
        "summary": {
            "requirement_count": len(out_rows),
            "closure_candidate_count": len(closure_candidates),
            "terminal_blocker_count": len(out_rows) - len(closure_candidates),
            "decision_counts": dict(sorted(decisions.items())),
            "terminal_blocker_counts": dict(sorted(blockers.items())),
            "route_family_counts": dict(sorted(routes.items())),
            "tier_counts": dict(sorted(tiers.items())),
            "blocker_dir": str(blocker_dir) if write_rows else "",
            "closure_candidate_dir": str(candidate_dir) if write_rows else "",
        },
        "promotion_allowed": False,
        "submission_posture": "NOT_SUBMIT_READY",
        "proof_boundary": PROOF_BOUNDARY,
        "rows": out_rows,
    }


def render_md(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    lines = [
        "# Impact Proof Requirement Execution",
        "",
        f"- Status: `{payload['status']}`",
        f"- Requirements resolved: `{summary['requirement_count']}`",
        f"- Closure candidates: `{summary['closure_candidate_count']}`",
        f"- Terminal blockers: `{summary['terminal_blocker_count']}`",
        f"- Submission posture: `{payload['submission_posture']}`",
        f"- Promotion allowed: `{str(payload['promotion_allowed']).lower()}`",
        "",
        "## Decisions",
        "",
    ]
    for key, value in summary["decision_counts"].items():
        lines.append(f"- `{key}`: {value}")
    lines.extend(["", "## Top Blockers", ""])
    for key, value in sorted(summary["terminal_blocker_counts"].items(), key=lambda item: (-item[1], item[0]))[:25]:
        lines.append(f"- `{key}`: {value}")
    lines.extend(["", "## Route Families", ""])
    for key, value in summary["route_family_counts"].items():
        lines.append(f"- `{key}`: {value}")
    lines.extend(["", "## Sample Rows", "", "| Candidate | Decision | Next command |", "|---|---|---|"])
    for row in payload["rows"][:25]:
        command = (row.get("next_local_commands") or [""])[0]
        lines.append(f"| `{row['candidate_id']}` | `{row['decision']}` | `{command}` |")
    lines.extend(["", "## Proof Boundary", "", payload["proof_boundary"]])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-md", type=Path)
    parser.add_argument("--no-row-manifests", action="store_true")
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args(argv)

    workspace = args.workspace.expanduser().resolve()
    if not workspace.is_dir():
        raise SystemExit(f"[impact-proof-requirement-executor] ERR workspace not found: {workspace}")
    manifest = args.manifest.expanduser().resolve() if args.manifest else workspace / DEFAULT_IN
    if not manifest.is_file():
        raise SystemExit(f"[impact-proof-requirement-executor] ERR manifest not found: {manifest}")
    payload = build_payload(workspace, manifest_path=manifest, write_rows=not args.no_row_manifests)
    out_json = args.out_json.expanduser().resolve() if args.out_json else workspace / DEFAULT_OUT
    out_md = args.out_md.expanduser().resolve() if args.out_md else workspace / DEFAULT_OUT_MD
    write_json(out_json, payload)
    write_text(out_md, render_md(payload))
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    print(
        f"[impact-proof-requirement-executor] {payload['status']} "
        f"requirements={payload['summary']['requirement_count']} "
        f"closure_candidates={payload['summary']['closure_candidate_count']} json={out_json}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
