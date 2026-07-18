#!/usr/bin/env python3
"""Emit exact impact-proof requirement manifests for blocked PR560 rows.

The manifests are closure/accounting artifacts. They make each exact but
unproved impact contract actionable by joining the impact-contract row to
available source-proof, benchmark, harness, execution, production-path, and
live/fork artifacts. They never mark a row proved.
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


SCHEMA = "auditooor.pr560.impact_proof_requirement_manifests.v1"
ROW_SCHEMA = "auditooor.pr560.impact_proof_requirement.v1"
DEFAULT_OUT = ".auditooor/impact_proof_requirement_manifests.json"
DEFAULT_OUT_MD = ".auditooor/impact_proof_requirement_manifests.md"
DEFAULT_ROW_DIR = ".auditooor/impact_proof_requirements"
DEFAULT_MIN_ITEMS = 300
DEFAULT_MAX_ITEMS = 500
PROOF_BOUNDARY = (
    "Impact-proof requirement manifests are closure requirements only; "
    "they do not prove impact, set severity, or authorize submission."
)
SCAFFOLDED_EVIDENCE_CLASS = "scaffolded_unverified"
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
CONCRETE_ARTIFACT_TOKENS = (
    "benchmark",
    "execution",
    "forge",
    "harness",
    "poc",
    "replay",
    "test",
    "transcript",
)
LINE_REF_RE = re.compile(r"^(?P<path>.+?):(?P<line>\d+)(?::(?P<end>\d+))?$")


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def slug(value: str) -> str:
    return re.sub(r"[^a-z0-9_.-]+", "-", value.lower()).strip("-") or "item"


def read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.rstrip() + "\n", encoding="utf-8")


def rows_by_id(payload: dict[str, Any], key: str) -> dict[str, dict[str, Any]]:
    rows = payload.get("rows") or payload.get("contracts") or payload.get("items") or []
    out: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        value = str(row.get(key) or row.get("candidate_id") or row.get("benchmark_id") or "")
        if value:
            out[value] = row
    return out


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


def current_workspace_refs(workspace: Path, refs: list[str]) -> dict[str, list[str]]:
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


def source_refs_from_payloads(*payloads: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    for payload in payloads:
        for key in SOURCE_REF_KEYS:
            refs.extend(coerce_str_list(payload.get(key)))
        for source in payload.get("source_proofs") or []:
            if not isinstance(source, dict):
                continue
            for key in SOURCE_REF_KEYS:
                refs.extend(coerce_str_list(source.get(key)))
            source_path = str(source.get("path") or "").strip()
            source_payload = read_json(Path(source_path)) if source_path else {}
            for key in SOURCE_REF_KEYS:
                refs.extend(coerce_str_list(source_payload.get(key)))
    return uniq(refs)


def artifact_refs_from_payloads(*payloads: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    for payload in payloads:
        for key in ARTIFACT_REF_KEYS:
            refs.extend(coerce_str_list(payload.get(key)))
        for key in ARTIFACT_PATH_KEYS:
            refs.extend(coerce_str_list(payload.get(key)))
        for command in payload.get("commands_attempted") or []:
            if isinstance(command, dict):
                for key in ARTIFACT_PATH_KEYS:
                    refs.extend(coerce_str_list(command.get(key)))
    return uniq(refs)


def is_concrete_artifact_ref(ref: str) -> bool:
    lowered = ref.lower()
    return any(token in lowered for token in CONCRETE_ARTIFACT_TOKENS)


def current_workspace_artifacts(workspace: Path, refs: list[str]) -> list[str]:
    current: list[str] = []
    for ref in uniq(refs):
        if not is_concrete_artifact_ref(ref):
            continue
        path, status = workspace_ref_path(workspace, ref)
        if status == "workspace" and path is not None and path.exists():
            current.append(ref)
    return current


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
                markers.append(value)
        for key in STATUS_MARKER_KEYS:
            token = normalized_token(payload.get(key))
            if token in BLOCKED_STATUS_TOKENS or token.startswith(("blocked", "terminal", "requires_human")):
                markers.append(f"{key}_{token}")
    return uniq(markers)


def proof_readiness(
    *,
    workspace: Path,
    contract: dict[str, Any],
    source_rows: list[dict[str, Any]],
    exec_manifest: dict[str, Any],
    artifact_refs: list[dict[str, Any]],
    bridge_row: dict[str, Any],
    benchmark_row: dict[str, Any],
) -> dict[str, Any]:
    source_refs = source_refs_from_payloads(contract, {"source_proofs": source_rows}, bridge_row)
    ref_status = current_workspace_refs(workspace, source_refs)
    command_evidence = proved_execution_manifest(exec_manifest) if exec_manifest else False
    artifact_ref_payload = {"artifact_refs": artifact_refs}
    artifact_refs_raw = artifact_refs_from_payloads(contract, artifact_ref_payload, bridge_row, benchmark_row)
    current_artifacts = current_workspace_artifacts(workspace, artifact_refs_raw)
    markers = blocker_advisory_markers(contract, bridge_row, benchmark_row)
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
    if not bool(contract.get("exact_impact_row")):
        reasons.append("impact_contract_not_exact")
    if not bool(contract.get("listed_impact_proven")):
        reasons.append("listed_impact_not_proven")
    ready = not reasons
    return {
        "status": "ready" if ready else "non_ready",
        "ready": ready,
        "non_ready_reasons": uniq(reasons),
        "current_workspace_source_refs": ref_status["current"],
        "stale_workspace_source_refs": ref_status["stale"],
        "outside_workspace_source_refs": ref_status["outside_workspace"],
        "external_or_placeholder_source_refs": ref_status["external_or_placeholder"],
        "has_concrete_proof_command": command_evidence,
        "current_workspace_proof_artifacts": current_artifacts,
        "blocker_advisory_markers": markers,
    }


def source_proofs_by_candidate(workspace: Path) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    for path in sorted((workspace / "source_proofs").glob("*/source_proof.json")):
        payload = read_json(path)
        if not payload:
            continue
        candidate = str(payload.get("candidate_id") or path.parent.name)
        if candidate.endswith("-source-proof"):
            candidate = candidate[: -len("-source-proof")]
        out.setdefault(candidate, []).append(
            {
                "path": str(path),
                "final_verdict": str(payload.get("final_verdict") or ""),
                "impact_contract_linked": bool(payload.get("impact_contract_linked")),
                "valid_source_citation_count": int(payload.get("valid_source_citation_count") or 0),
                "promotion_allowed": bool(payload.get("promotion_allowed")),
                "source_refs": source_refs_from_payloads(payload),
            }
        )
    return out


def proved_execution_manifest(exec_row: dict[str, Any]) -> bool:
    if "strict_proved" in exec_row:
        return bool(exec_row.get("strict_proved"))
    return (
        exec_row.get("final_result") == "proved"
        and exec_row.get("impact_assertion") == "exploit_impact"
        and exec_row.get("evidence_class") == "executed_with_manifest"
        and int(exec_row.get("passing_command_count") or 0) > 0
    )


def execution_manifest(path: Path) -> dict[str, Any]:
    payload = read_json(path)
    if not payload:
        return {}
    commands = payload.get("commands_attempted")
    counts = command_evidence_counts(payload)
    command_count = len(commands) if isinstance(commands, list) else 0
    return {
        "path": str(path),
        "final_result": str(payload.get("final_result") or payload.get("result") or ""),
        "impact_assertion": str(payload.get("impact_assertion") or ""),
        "evidence_class": str(payload.get("evidence_class") or ""),
        "commands_attempted_count": command_count,
        "structured_command_count": counts["structured_command_count"],
        "passing_command_count": counts["passing_command_count"],
        "command_status_counts": command_status_counts(payload),
        "strict_proved": is_strict_proved_execution_manifest(payload),
        "strict_proof_blockers": strict_proof_blockers(payload),
    }


def artifact_status(path_text: str) -> dict[str, Any]:
    path = Path(path_text)
    return {"path": path_text, "exists": path.exists()}


def proof_status(
    source_rows: list[dict[str, Any]],
    exec_row: dict[str, Any],
    *,
    listed_impact_proven: bool,
) -> tuple[str, list[str]]:
    blockers = [] if listed_impact_proven else ["listed_impact_not_proven"]
    if exec_row:
        if exec_row.get("final_result") != "proved":
            blockers.append(f"execution_manifest_{exec_row.get('final_result') or 'not_proved'}")
        if exec_row.get("impact_assertion") != "exploit_impact":
            blockers.append(f"impact_assertion_{exec_row.get('impact_assertion') or 'missing'}")
        if int(exec_row.get("commands_attempted_count") or 0) <= 0:
            blockers.append("execution_manifest_missing_commands_attempted")
        if exec_row.get("evidence_class") != "executed_with_manifest":
            blockers.append("execution_manifest_evidence_class_executed_with_manifest")
        strict_blockers = set(exec_row.get("strict_proof_blockers") or [])
        if "commands_attempted" in strict_blockers:
            blockers.append("execution_manifest_missing_commands_attempted")
        if "commands_attempted_structured" in strict_blockers:
            blockers.append("execution_manifest_commands_attempted_structured")
        if "commands_attempted_pass_exit_0" in strict_blockers:
            blockers.append("execution_manifest_commands_attempted_pass_exit_0")
    if source_rows:
        if not any(int(row.get("valid_source_citation_count") or 0) > 0 for row in source_rows):
            blockers.append("source_proof_missing_project_source_citation")
        for row in source_rows:
            verdict = str(row.get("final_verdict") or "")
            if verdict and not verdict.startswith("proved"):
                blockers.append(f"source_proof_{verdict}")
    if exec_row and proved_execution_manifest(exec_row):
        return "terminal_requires_human_listed_impact_attestation", sorted(set(blockers))
    if exec_row:
        return "terminal_execution_blocker_recorded", sorted(set(blockers))
    if source_rows:
        return "terminal_source_proof_blocker_recorded", sorted(set(blockers))
    return "requires_project_specific_impact_proof", sorted(set(blockers + ["missing_execution_or_source_proof"]))


def build_payload(workspace: Path, *, min_items: int, max_items: int, write_rows: bool) -> dict[str, Any]:
    aud = workspace / ".auditooor"
    contracts_payload = read_json(aud / "impact_contracts.json")
    queue_payload = read_json(aud / "impact_miss_harness_blocker_queue.json")
    execution_payload = read_json(aud / "impact_miss_harness_blocker_execution.json")
    bridge_payload = read_json(aud / "source_proof_impact_bridge.json")
    benchmark_payload = read_json(aud / "impact_miss_offset_benchmark.json")

    queue_by_candidate = rows_by_id(queue_payload, "benchmark_id")
    execution_by_candidate = rows_by_id(execution_payload, "benchmark_id")
    bridge_by_candidate = rows_by_id(bridge_payload, "candidate_id")
    benchmark_by_candidate = rows_by_id(benchmark_payload, "benchmark_id")
    source_by_candidate = source_proofs_by_candidate(workspace)

    rows: list[dict[str, Any]] = []
    row_dir = workspace / DEFAULT_ROW_DIR
    for contract in sorted(contracts_payload.get("contracts") or [], key=lambda row: str(row.get("candidate_id") or "")):
        if not isinstance(contract, dict):
            continue
        candidate = str(contract.get("candidate_id") or "")
        if not candidate:
            continue
        queue_row = queue_by_candidate.get(candidate, {})
        exec_row = execution_by_candidate.get(candidate, {})
        bridge_row = bridge_by_candidate.get(candidate, {})
        source_rows = source_by_candidate.get(candidate, [])
        manifest_path = workspace / "poc_execution" / slug(candidate) / "execution_manifest.json"
        manifest = execution_manifest(manifest_path)
        required_artifacts = queue_row.get("required_artifacts") or []
        artifact_rows = [item for item in required_artifacts if isinstance(item, dict)]
        present = [str(item.get("artifact")) for item in artifact_rows if item.get("exists")]
        missing = [str(item.get("artifact")) for item in artifact_rows if not item.get("exists")]
        artifact_refs = []
        for item in artifact_rows:
            path = str(item.get("path") or "")
            artifact_refs.append(
                {
                    "artifact": str(item.get("artifact") or ""),
                    "required": bool(item.get("required")),
                    "exists": bool(item.get("exists")),
                    "path": path,
                }
            )
        for path in exec_row.get("artifact_paths") or []:
            if isinstance(path, str):
                artifact_refs.append({"artifact": "materialized_next_step", **artifact_status(path)})
        status, blockers = proof_status(
            source_rows,
            manifest,
            listed_impact_proven=bool(contract.get("listed_impact_proven")),
        )
        readiness = proof_readiness(
            workspace=workspace,
            contract=contract,
            source_rows=source_rows,
            exec_manifest=manifest,
            artifact_refs=artifact_refs,
            bridge_row=bridge_row,
            benchmark_row=benchmark_by_candidate.get(candidate, {}),
        )
        if readiness["ready"]:
            status = "ready_requires_scope_oos_review"
            blockers = []
        else:
            blockers = sorted(
                set(
                    blockers
                    + readiness["non_ready_reasons"]
                    + readiness["blocker_advisory_markers"]
                )
            )
            if bool(contract.get("listed_impact_proven")):
                status = "non_ready_requirement_recorded"
        if bridge_row.get("terminal_blockers"):
            blockers = sorted(set(blockers + [str(item) for item in bridge_row.get("terminal_blockers") or []]))
        row_payload = {
            "schema": ROW_SCHEMA,
            "requirement_id": f"IPR-{len(rows) + 1:03d}",
            "candidate_id": candidate,
            "impact_contract_id": str(contract.get("impact_contract_id") or ""),
            "tier": str(contract.get("tier") or ""),
            "route_family": str(contract.get("route_family") or ""),
            "asset_category": str(contract.get("asset_category") or ""),
            "exact_impact_row": bool(contract.get("exact_impact_row")),
            "listed_impact_proven": bool(contract.get("listed_impact_proven")),
            "evidence_class": "executed_with_manifest" if readiness["ready"] else SCAFFOLDED_EVIDENCE_CLASS,
            "selected_impact": str(contract.get("selected_impact") or ""),
            "requirement_status": status,
            "terminal_blockers": blockers,
            "proof_ready": bool(readiness["ready"]),
            "non_ready_reasons": readiness["non_ready_reasons"],
            "proof_readiness": readiness,
            "required_artifact_names": [str(item.get("artifact") or "") for item in artifact_rows],
            "present_artifact_names": sorted(set(present)),
            "missing_artifact_names": sorted(set(missing)),
            "source_proofs": source_rows,
            "execution_manifest": manifest,
            "bridge_status": str(bridge_row.get("status") or ""),
            "benchmark_status": str(benchmark_by_candidate.get(candidate, {}).get("expected", {}).get("terminal_decision") or ""),
            "artifact_refs": artifact_refs,
            "acceptance_gate": (
                "Close only when the exact row has listed_impact_proven=true, a project-specific proof artifact, "
                "and a poc_execution manifest with final_result=proved, impact_assertion=exploit_impact, "
                "evidence_class=executed_with_manifest, and a structured commands_attempted row with non-empty "
                "command, status=pass, and exit_code=0."
            ),
            "severity": "none",
            "submission_posture": "NOT_SUBMIT_READY",
            "promotion_allowed": False,
            "proof_boundary": PROOF_BOUNDARY,
        }
        if write_rows:
            per_row_path = row_dir / f"{slug(candidate)}.json"
            write_json(per_row_path, row_payload)
            row_payload["requirement_manifest_path"] = str(per_row_path)
        rows.append(row_payload)

    status = "ok_requirements_recorded" if min_items <= len(rows) <= max_items else "hard_blocker_item_target_out_of_range"
    status_counts = Counter(row["requirement_status"] for row in rows)
    blocker_counts = Counter(blocker for row in rows for blocker in row["terminal_blockers"])
    route_counts = Counter(row["route_family"] for row in rows)
    tier_counts = Counter(row["tier"] for row in rows)
    return {
        "schema": SCHEMA,
        "generated_at": now_iso(),
        "workspace": str(workspace),
        "status": status,
        "target_range": f"{min_items}-{max_items}",
        "source_artifacts": {
            "impact_contracts": str(aud / "impact_contracts.json") if contracts_payload else "",
            "impact_miss_harness_blocker_queue": str(aud / "impact_miss_harness_blocker_queue.json") if queue_payload else "",
            "impact_miss_harness_blocker_execution": str(aud / "impact_miss_harness_blocker_execution.json") if execution_payload else "",
            "source_proof_impact_bridge": str(aud / "source_proof_impact_bridge.json") if bridge_payload else "",
            "impact_miss_offset_benchmark": str(aud / "impact_miss_offset_benchmark.json") if benchmark_payload else "",
        },
        "summary": {
            "requirement_count": len(rows),
            "status_counts": dict(sorted(status_counts.items())),
            "terminal_blocker_counts": dict(sorted(blocker_counts.items())),
            "route_family_counts": dict(sorted(route_counts.items())),
            "tier_counts": dict(sorted(tier_counts.items())),
            "per_row_manifest_dir": str(row_dir) if write_rows else "",
        },
        "severity": "none",
        "selected_impact": "",
        "submission_posture": "NOT_SUBMIT_READY",
        "promotion_allowed": False,
        "proof_boundary": PROOF_BOUNDARY,
        "rows": rows,
    }


def render_md(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    lines = [
        "# Impact Proof Requirement Manifests",
        "",
        f"- Status: `{payload['status']}`",
        f"- Requirements: `{summary['requirement_count']}` (target {payload['target_range']})",
        f"- Submission posture: `{payload['submission_posture']}`",
        f"- Promotion allowed: `{str(payload['promotion_allowed']).lower()}`",
        f"- Per-row manifests: `{summary['per_row_manifest_dir']}`",
        "",
        "## Requirement Status",
        "",
    ]
    for key, value in summary["status_counts"].items():
        lines.append(f"- `{key}`: {value}")
    lines.extend(["", "## Terminal Blockers", ""])
    for key, value in summary["terminal_blocker_counts"].items():
        lines.append(f"- `{key}`: {value}")
    lines.extend(["", "## Route Families", ""])
    for key, value in summary["route_family_counts"].items():
        lines.append(f"- `{key}`: {value}")
    lines.extend(["", "## Sample Rows", "", "| Requirement | Candidate | Status | Blockers |", "|---|---|---|---|"])
    for row in payload["rows"][:25]:
        blockers = ", ".join(row["terminal_blockers"][:4])
        lines.append(f"| `{row['requirement_id']}` | `{row['candidate_id']}` | `{row['requirement_status']}` | {blockers} |")
    lines.extend(["", "## Proof Boundary", "", payload["proof_boundary"]])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-md", type=Path)
    parser.add_argument("--min-items", type=int, default=DEFAULT_MIN_ITEMS)
    parser.add_argument("--max-items", type=int, default=DEFAULT_MAX_ITEMS)
    parser.add_argument("--no-row-manifests", action="store_true")
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args(argv)

    workspace = args.workspace.expanduser().resolve()
    if not workspace.is_dir():
        raise SystemExit(f"[impact-proof-requirements] ERR workspace not found: {workspace}")
    payload = build_payload(
        workspace,
        min_items=args.min_items,
        max_items=args.max_items,
        write_rows=not args.no_row_manifests,
    )
    out_json = args.out_json.expanduser().resolve() if args.out_json else workspace / DEFAULT_OUT
    out_md = args.out_md.expanduser().resolve() if args.out_md else workspace / DEFAULT_OUT_MD
    write_json(out_json, payload)
    write_text(out_md, render_md(payload))
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    print(
        f"[impact-proof-requirements] {payload['status']} "
        f"requirements={payload['summary']['requirement_count']} json={out_json}"
    )
    return 2 if payload["status"] == "hard_blocker_item_target_out_of_range" else 0


if __name__ == "__main__":
    raise SystemExit(main())
