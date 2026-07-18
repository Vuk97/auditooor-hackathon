#!/usr/bin/env python3
"""Build a PR560 impact-proof reconciliation ledger."""

from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from execution_manifest_proof import (
    STRICT_EVIDENCE_CLASS,
    bound_source_validation,
    command_evidence_counts as strict_command_evidence_counts,
    is_strict_proved_execution_manifest as strict_is_strict_proved_execution_manifest,
)


SOURCE_BLOCKER_TOKENS = {
    "benchmark_generated_source_shape_not_project_file",
    "source_proof_blocked_missing_project_source_citation",
    "source_proof_has_zero_valid_source_citations",
    "source_proof_missing_project_source_citation",
    "terminal_no_project_source_citation_eu",
}

SOURCE_REF_KEYS = (
    "source_refs",
    "source_paths",
    "file_hints",
    "file_line",
    "file_path",
    "source_ref",
    "project_source_refs",
    "project_source_citations",
    "source_citations",
)
PROOF_ARTIFACT_REF_KEYS = (
    "artifact_refs",
    "artifact_paths",
    "proof_artifacts",
    "evidence_artifacts",
    "required_artifacts",
    "output_artifacts",
)
PROOF_ARTIFACT_PATH_KEYS = (
    "artifact",
    "source_artifact",
    "proof_artifact",
    "transcript_path",
    "output_path",
    "stdout_path",
    "stderr_path",
    "proof_file",
    "proof_path",
    "proof_artifact_path",
    "poc_path",
    "poc_paths",
    "test_path",
    "test_paths",
    "harness_path",
    "harness_paths",
    "execution_manifest_path",
    "poc_execution_manifest_path",
    "poc_transcript_path",
)
PROOF_EVIDENCE_TEXT_KEYS = (
    "pass_evidence_lines",
    "poc_pass_evidence",
    "proof_evidence",
    "harness_evidence",
    "reproduction_evidence",
    "test_output",
    "forge_output",
    "go_test_output",
    "proof_transcript",
    "poc_transcript",
    "validation_evidence",
)
PASS_EVIDENCE_RE = re.compile(
    r"--- PASS:|Suite result:\s*ok|\bPASS\b|\bpassed\b|\breproduced\b|\bconfirmed\b|\bverified\b",
    re.IGNORECASE,
)
EXTERNAL_REF_PREFIXES = (
    "http://",
    "https://",
    "repo:",
    "solodit:",
    "vault://",
    "gh:",
)
LINE_REF_RE = re.compile(r"^(?P<path>.+?):(?P<line>\d+)(?:(?::|-)(?P<end>\d+))?$")
BOOLEAN_BLOCKER_KEYS = ("blocked", "is_blocked", "non_executable", "requires_manual_review")
BOOLEAN_ADVISORY_KEYS = ("advisory", "advisory_only", "informational_only", "out_of_scope")
BLOCKER_MARKER_KEYS = (
    "terminal_blockers",
    "blocker",
    "blockers",
    "blocked_reason",
    "blocked_reasons",
    "proof_completion_blockers",
)
STATUS_MARKER_KEYS = (
    "status",
    "decision",
    "requirement_status",
    "proof_status",
    "proof_completion_status",
    "readiness",
    "execution_status",
    "source_status",
)
BLOCKED_STATUS_TOKENS = {
    "blocked",
    "blocked_path",
    "blocker",
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
ADVISORY_STATUS_TOKENS = {
    "advisory",
    "advisory_only",
    "generated_hypothesis",
    "informational",
    "informational_only",
    "out_of_scope",
}


def rel(workspace: Path, path: Path) -> str:
    try:
        return str(path.relative_to(workspace))
    except ValueError:
        return str(path)


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
        fh.write("\n")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def count_by(values: list[str]) -> dict[str, int]:
    return dict(sorted(Counter(values).items()))


def uniq(values: list[Any]) -> list[Any]:
    out: list[Any] = []
    for value in values:
        if value not in out:
            out.append(value)
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


def source_ref_list(value: object) -> list[str]:
    if isinstance(value, list):
        out: list[str] = []
        for item in value:
            out.extend(source_ref_list(item))
        return out
    if isinstance(value, tuple):
        out: list[str] = []
        for item in value:
            out.extend(source_ref_list(item))
        return out
    if isinstance(value, dict):
        raw = value.get("raw")
        if isinstance(raw, str) and raw.strip():
            return [raw.strip()]
        path = value.get("path") or value.get("file") or value.get("file_path")
        line = value.get("start_line") or value.get("line")
        if isinstance(path, str) and path.strip() and line:
            return [f"{path.strip()}:{line}"]
    return coerce_str_list(value)


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


def current_workspace_artifacts(workspace: Path, refs: list[str]) -> list[str]:
    current: list[str] = []
    for ref in uniq(refs):
        path, status = workspace_ref_path(workspace, ref)
        if status == "workspace" and path is not None and path.is_file():
            current.append(ref)
    return current


def source_refs_from_payload(payload: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    for key in SOURCE_REF_KEYS:
        refs.extend(source_ref_list(payload.get(key)))
    source_proof = payload.get("source_proof")
    if isinstance(source_proof, dict):
        for key in SOURCE_REF_KEYS:
            refs.extend(source_ref_list(source_proof.get(key)))
    for source in payload.get("source_proofs") or []:
        if not isinstance(source, dict):
            continue
        for key in SOURCE_REF_KEYS:
            refs.extend(source_ref_list(source.get(key)))
    return uniq(refs)


def proof_artifact_refs_from_payload(payload: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    for key in PROOF_ARTIFACT_REF_KEYS:
        refs.extend(coerce_str_list(payload.get(key)))
    for key in PROOF_ARTIFACT_PATH_KEYS:
        refs.extend(coerce_str_list(payload.get(key)))
    for command in payload.get("commands_attempted") or []:
        if isinstance(command, dict):
            for key in PROOF_ARTIFACT_PATH_KEYS:
                refs.extend(coerce_str_list(command.get(key)))
    return uniq(refs)


def proof_evidence_text_from_payload(payload: dict[str, Any]) -> list[str]:
    evidence: list[str] = []
    for key in PROOF_EVIDENCE_TEXT_KEYS:
        for text in coerce_str_list(payload.get(key)):
            if PASS_EVIDENCE_RE.search(text):
                evidence.append(re.sub(r"\s+", " ", text[:240]).strip())
    return uniq(evidence)


def marker_reasons_from_payload(payload: dict[str, Any]) -> tuple[list[str], list[str]]:
    blockers: list[str] = []
    advisory: list[str] = []
    for key in BOOLEAN_BLOCKER_KEYS:
        if bool(payload.get(key)):
            blockers.append(f"{key}_marker")
    for key in BOOLEAN_ADVISORY_KEYS:
        if bool(payload.get(key)):
            advisory.append(f"{key}_marker")
    for key in BLOCKER_MARKER_KEYS:
        for value in coerce_str_list(payload.get(key)):
            if value:
                blockers.append(value)
    for key in STATUS_MARKER_KEYS:
        token = normalized_token(payload.get(key))
        if not token:
            continue
        if token in ADVISORY_STATUS_TOKENS:
            advisory.append(f"{key}_{token}")
        if token in BLOCKED_STATUS_TOKENS or token.startswith(("blocked", "terminal", "requires_human")):
            blockers.append(f"{key}_{token}")
    return uniq(blockers), uniq(advisory)


def compact_summary(data: Any) -> Any:
    if not isinstance(data, dict):
        return None
    summary = data.get("summary")
    if isinstance(summary, dict):
        return summary
    return None


def classify_input(path: Path) -> str:
    name = path.name
    if name.startswith("impact_proof_requirement_execution"):
        return "impact_requirement_execution"
    if name.startswith("impact_proof_project_evidence_executor"):
        return "project_evidence_executor"
    if name.startswith("source_citation_closure_eu"):
        return "source_citation_closure_eu"
    if name.startswith("pr560_worker_ev_bridge_finalization_closure"):
        return "worker_ev_bridge_finalization_closure"
    if name.startswith("pr560_worker_fg_proof_live_closure"):
        return "worker_fg_proof_live_closure"
    return "other"


def input_paths(workspace: Path) -> list[Path]:
    patterns = [
        ".auditooor/pr560_worker_fg_proof_live_closure.*",
        ".auditooor/source_citation_closure_eu.*",
        ".auditooor/pr560_worker_ev_bridge_finalization_closure.*",
        ".auditooor/impact_proof_requirement_execution*.json",
        ".auditooor/impact_proof_requirement_execution*.md",
        ".auditooor/impact_proof_project_evidence_executor*.json",
        ".auditooor/impact_proof_project_evidence_executor*.md",
    ]
    found: list[Path] = []
    seen: set[Path] = set()
    for pattern in patterns:
        for match in glob.glob(str(workspace / pattern)):
            path = Path(match)
            if path not in seen:
                seen.add(path)
                found.append(path)
    return sorted(found)


def ensure_candidate(candidates: dict[str, dict[str, Any]], candidate_id: str) -> dict[str, Any]:
    row = candidates.setdefault(
        candidate_id,
        {
            "candidate_id": candidate_id,
            "route_family": "",
            "tier": "",
            "requirement_ids": [],
            "source_files": [],
            "decisions": [],
            "terminal_blockers": [],
            "next_local_commands": [],
            "listed_impact_proven": False,
            "project_source_citation_count": 0,
            "valid_source_citation_count": 0,
            "source_citation_count": 0,
            "source_evidence": [],
            "execution_evidence": [],
            "source_refs": [],
            "proof_artifact_refs": [],
            "proof_evidence_text": [],
            "blocker_markers": [],
            "advisory_markers": [],
        },
    )
    return row


def add_unique(items: list[Any], value: Any) -> None:
    if value not in items:
        items.append(value)


def commands_attempted_count(manifest: dict[str, Any]) -> int:
    if not isinstance(manifest, dict):
        return 0
    counts = strict_command_evidence_counts(manifest)
    if isinstance(manifest.get("commands_attempted"), list):
        return int(counts["commands_attempted_count"])
    value = manifest.get("commands_attempted_count")
    if isinstance(value, int):
        return value
    return int(counts["commands_attempted_count"])


def command_evidence_counts(manifest: dict[str, Any]) -> tuple[int, int, int]:
    if not isinstance(manifest, dict):
        return 0, 0, 0
    counts = strict_command_evidence_counts(manifest)
    if isinstance(manifest.get("commands_attempted"), list):
        return (
            int(counts["commands_attempted_count"]),
            int(counts["structured_command_count"]),
            int(counts["passing_command_count"]),
        )
    return (
        commands_attempted_count(manifest),
        int(manifest.get("structured_command_count") or 0),
        int(manifest.get("passing_command_count") or 0),
    )


def is_strict_proved_execution_manifest(manifest: dict[str, Any]) -> bool:
    return strict_is_strict_proved_execution_manifest(manifest)


def validate_manifest_bound_sources(manifest: dict[str, Any], workspace: Path) -> dict[str, Any]:
    """Keep legacy absent/empty bindings compatible while validating supplied ones."""
    if "bound_sources" not in manifest or manifest.get("bound_sources") == []:
        return {
            "supplied": "bound_sources" in manifest,
            "valid": True,
            "entries": [],
            "errors": [],
        }
    try:
        result = bound_source_validation(manifest, workspace)
    except Exception as exc:  # A validator failure must never grant proof credit.
        return {
            "supplied": True,
            "valid": False,
            "entries": [],
            "errors": [f"bound_source_validation_error:{type(exc).__name__}"],
        }
    if not isinstance(result, dict):
        return {
            "supplied": True,
            "valid": False,
            "entries": [],
            "errors": ["bound_source_validation_invalid_result"],
        }
    errors = [str(error) for error in result.get("errors") or []]
    return {
        "supplied": True,
        "valid": bool(result.get("valid")) and not errors,
        "entries": result.get("entries") if isinstance(result.get("entries"), list) else [],
        "errors": errors,
    }


def add_execution_evidence(
    cand: dict[str, Any],
    source_path: str,
    manifest: dict[str, Any],
    workspace: Path,
    diagnostics: list[dict[str, Any]],
) -> None:
    if not isinstance(manifest, dict) or not manifest:
        return
    final_result = manifest.get("final_result", "")
    impact_assertion = manifest.get("impact_assertion", "")
    path = manifest.get("path", "")
    if not path and manifest.get("candidate_id"):
        path = f"poc_execution/{manifest['candidate_id']}/execution_manifest.json"
    command_count, structured_count, passing_count = command_evidence_counts(manifest)
    bound_sources = validate_manifest_bound_sources(manifest, workspace)
    if bound_sources["errors"]:
        diagnostics.append(
            {
                "type": "bound_source_validation",
                "manifest_path": source_path,
                "candidate_id": manifest.get("candidate_id", ""),
                "errors": bound_sources["errors"],
            }
        )
    evidence = {
        "source": source_path,
        "path": path,
        "final_result": final_result,
        "impact_assertion": impact_assertion,
        "commands_attempted_count": command_count,
        "structured_command_count": structured_count,
        "passing_command_count": passing_count,
        "first_command": manifest.get("first_command", ""),
        "evidence_class": manifest.get("evidence_class", ""),
        "bound_source_validation": bound_sources,
        "proof_counted": is_strict_proved_execution_manifest(manifest) and bound_sources["valid"],
    }
    add_unique(cand["execution_evidence"], evidence)
    for ref in proof_artifact_refs_from_payload(manifest):
        add_unique(cand["proof_artifact_refs"], ref)
    for text in proof_evidence_text_from_payload(manifest):
        add_unique(cand["proof_evidence_text"], text)


def source_signal_from_row(row: dict[str, Any]) -> dict[str, Any]:
    source_proof = row.get("source_proof") if isinstance(row.get("source_proof"), dict) else {}
    valid = int(source_proof.get("valid_source_citation_count") or 0)
    count = int(source_proof.get("source_citation_count") or 0)
    project_count = int(row.get("project_source_citation_count") or 0)
    source_shape_project_file = bool(row.get("source_shape_is_project_file"))
    return {
        "project_source_citation_count": project_count,
        "valid_source_citation_count": valid,
        "source_citation_count": count,
        "source_shape_is_project_file": source_shape_project_file,
        "source_proof_path": source_proof.get("path", ""),
        "source_proof_final_verdict": source_proof.get("final_verdict", ""),
        "impact_contract_linked": bool(source_proof.get("impact_contract_linked")),
    }


def add_row(
    candidates: dict[str, dict[str, Any]],
    workspace: Path,
    path: Path,
    data_kind: str,
    row: dict[str, Any],
    diagnostics: list[dict[str, Any]],
) -> None:
    candidate_id = row.get("candidate_id")
    if not isinstance(candidate_id, str) or not candidate_id:
        return
    cand = ensure_candidate(candidates, candidate_id)
    source_path = rel(workspace, path)
    add_unique(cand["source_files"], source_path)
    decision = row.get("decision")
    if isinstance(decision, str) and decision:
        add_unique(cand["decisions"], decision)
    route = row.get("route_family")
    tier = row.get("tier")
    if isinstance(route, str) and route:
        cand["route_family"] = cand["route_family"] or route
    if isinstance(tier, str) and tier:
        cand["tier"] = cand["tier"] or tier
    req_id = row.get("requirement_id")
    if isinstance(req_id, str) and req_id:
        add_unique(cand["requirement_ids"], req_id)
    if row.get("listed_impact_proven") is True:
        cand["listed_impact_proven"] = True
    blockers = row.get("terminal_blockers")
    if isinstance(blockers, list):
        for blocker in blockers:
            if isinstance(blocker, str):
                add_unique(cand["terminal_blockers"], blocker)
    commands = row.get("next_local_commands")
    if isinstance(commands, list):
        for command in commands:
            if isinstance(command, str):
                add_unique(cand["next_local_commands"], command)
    for ref in source_refs_from_payload(row):
        add_unique(cand["source_refs"], ref)
    for ref in proof_artifact_refs_from_payload(row):
        add_unique(cand["proof_artifact_refs"], ref)
    for text in proof_evidence_text_from_payload(row):
        add_unique(cand["proof_evidence_text"], text)
    blockers, advisory = marker_reasons_from_payload(row)
    for marker in blockers:
        add_unique(cand["blocker_markers"], marker)
    for marker in advisory:
        add_unique(cand["advisory_markers"], marker)

    signal = source_signal_from_row(row)
    cand["project_source_citation_count"] = max(
        cand["project_source_citation_count"], signal["project_source_citation_count"]
    )
    cand["valid_source_citation_count"] = max(
        cand["valid_source_citation_count"], signal["valid_source_citation_count"]
    )
    cand["source_citation_count"] = max(cand["source_citation_count"], signal["source_citation_count"])
    if any(
        [
            signal["project_source_citation_count"] > 0,
            signal["valid_source_citation_count"] > 0,
            signal["source_citation_count"] > 0,
            signal["source_shape_is_project_file"],
            signal["source_proof_path"],
        ]
    ):
        signal["source"] = source_path
        signal["kind"] = data_kind
        add_unique(cand["source_evidence"], signal)

    local_artifacts = row.get("local_artifacts")
    if isinstance(local_artifacts, dict):
        add_execution_evidence(
            cand,
            source_path,
            local_artifacts.get("poc_execution_manifest", {}),
            workspace,
            diagnostics,
        )
    add_execution_evidence(cand, source_path, row.get("execution_manifest", {}), workspace, diagnostics)


def add_json_rows(
    candidates: dict[str, dict[str, Any]],
    workspace: Path,
    path: Path,
    data: Any,
    diagnostics: list[dict[str, Any]],
) -> None:
    if not isinstance(data, dict):
        return
    kind = classify_input(path)
    rows = data.get("rows")
    if isinstance(rows, list):
        for row in rows:
            if isinstance(row, dict):
                add_row(candidates, workspace, path, kind, row, diagnostics)
    row_accounting = data.get("row_accounting")
    if isinstance(row_accounting, list):
        for row in row_accounting:
            if isinstance(row, dict):
                add_row(candidates, workspace, path, kind, row, diagnostics)
    for key in ("closed_rows", "closure_candidates"):
        keyed = data.get(key)
        if isinstance(keyed, list):
            for row in keyed:
                if isinstance(row, dict):
                    add_row(candidates, workspace, path, kind, row, diagnostics)


def scan_execution_manifests(workspace: Path, candidates: dict[str, dict[str, Any]]) -> dict[str, Any]:
    counts_final: Counter[str] = Counter()
    counts_impact: Counter[str] = Counter()
    command_counts: Counter[str] = Counter()
    proved_paths: list[str] = []
    diagnostics: list[dict[str, Any]] = []
    manifest_count = 0
    for path in sorted(workspace.glob("poc_execution/**/execution_manifest.json")):
        try:
            data = load_json(path)
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict):
            continue
        manifest_count += 1
        counts_final[str(data.get("final_result", ""))] += 1
        counts_impact[str(data.get("impact_assertion", ""))] += 1
        command_counts[str(commands_attempted_count(data))] += 1
        candidate_id = data.get("candidate_id")
        if isinstance(candidate_id, str) and candidate_id in candidates:
            data = dict(data)
            data["path"] = rel(workspace, path)
            add_execution_evidence(candidates[candidate_id], rel(workspace, path), data, workspace, diagnostics)
        bound_sources = validate_manifest_bound_sources(data, workspace)
        if is_strict_proved_execution_manifest(data) and bound_sources["valid"]:
            proved_paths.append(rel(workspace, path))
    return {
        "manifest_count": manifest_count,
        "final_result_counts": dict(sorted(counts_final.items())),
        "impact_assertion_counts": dict(sorted(counts_impact.items())),
        "commands_attempted_count_distribution": dict(sorted(command_counts.items())),
        "proved_or_exploit_impact_manifest_paths": proved_paths,
        "strict_proved_exploit_impact_manifest_paths": proved_paths,
        "bound_source_validation_diagnostics": diagnostics,
    }


def scan_source_proofs(workspace: Path, candidates: dict[str, dict[str, Any]]) -> dict[str, Any]:
    valid_counts: Counter[str] = Counter()
    source_counts: Counter[str] = Counter()
    verdict_counts: Counter[str] = Counter()
    valid_linked_to_row: list[str] = []
    valid_not_row: list[str] = []
    proof_count = 0
    for path in sorted(workspace.glob("source_proofs/**/source_proof.json")):
        try:
            data = load_json(path)
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict):
            continue
        proof_count += 1
        valid = int(data.get("valid_source_citation_count") or 0)
        count = int(data.get("source_citation_count") or len(data.get("source_citations") or []))
        valid_counts[str(valid)] += 1
        source_counts[str(count)] += 1
        verdict_counts[str(data.get("final_verdict", ""))] += 1
        candidate_id = data.get("candidate_id")
        if isinstance(candidate_id, str) and candidate_id in candidates:
            cand = candidates[candidate_id]
            cand["valid_source_citation_count"] = max(cand["valid_source_citation_count"], valid)
            cand["source_citation_count"] = max(cand["source_citation_count"], count)
            cand["project_source_citation_count"] = max(
                cand["project_source_citation_count"],
                valid if data.get("impact_contract_linked") else 0,
            )
            add_unique(
                cand["source_evidence"],
                {
                    "source": rel(workspace, path),
                    "kind": "local_source_proof_inventory",
                    "project_source_citation_count": valid if data.get("impact_contract_linked") else 0,
                    "valid_source_citation_count": valid,
                    "source_citation_count": count,
                    "source_proof_path": rel(workspace, path),
                    "source_proof_final_verdict": data.get("final_verdict", ""),
                    "impact_contract_linked": bool(data.get("impact_contract_linked")),
                },
            )
            for ref in source_refs_from_payload(data):
                add_unique(cand["source_refs"], ref)
            blockers, advisory = marker_reasons_from_payload(data)
            for marker in blockers:
                add_unique(cand["blocker_markers"], marker)
            for marker in advisory:
                add_unique(cand["advisory_markers"], marker)
            if valid > 0:
                valid_linked_to_row.append(candidate_id)
        elif valid > 0:
            valid_not_row.append(rel(workspace, path))
    return {
        "source_proof_count": proof_count,
        "valid_source_citation_count_distribution": dict(sorted(valid_counts.items())),
        "source_citation_count_distribution": dict(sorted(source_counts.items())),
        "final_verdict_counts": dict(sorted(verdict_counts.items())),
        "valid_source_citations_linked_to_reconciled_rows": sorted(set(valid_linked_to_row)),
        "valid_source_citation_paths_not_in_reconciled_rows": sorted(valid_not_row),
    }


def has_proved_execution(cand: dict[str, Any]) -> bool:
    for evidence in cand["execution_evidence"]:
        if isinstance(evidence, dict) and bool(evidence.get("proof_counted")):
            return True
    return False


def has_blocked_execution(cand: dict[str, Any]) -> bool:
    for evidence in cand["execution_evidence"]:
        if evidence.get("final_result") == "blocked_path":
            return True
    return "execution_manifest_blocked_path" in cand["terminal_blockers"]


def has_real_source_citation(cand: dict[str, Any]) -> bool:
    if int(cand.get("project_source_citation_count") or 0) > 0:
        return True
    for evidence in cand["source_evidence"]:
        if (
            int(evidence.get("valid_source_citation_count") or 0) > 0
            and bool(evidence.get("impact_contract_linked"))
            and not str(evidence.get("source_proof_final_verdict", "")).startswith("blocked_")
        ):
            return True
    return False


def strict_manifest_paths(cand: dict[str, Any]) -> list[str]:
    paths: list[str] = []
    for evidence in cand["execution_evidence"]:
        if isinstance(evidence, dict) and bool(evidence.get("proof_counted")):
            path = str(evidence.get("path") or "")
            if path:
                paths.append(path)
    return uniq(paths)


def proof_readiness(workspace: Path, cand: dict[str, Any]) -> dict[str, Any]:
    source_status = current_workspace_refs(workspace, cand["source_refs"])
    proof_artifacts = current_workspace_artifacts(workspace, cand["proof_artifact_refs"])
    strict_paths = strict_manifest_paths(cand)
    has_concrete_evidence = bool(strict_paths or proof_artifacts or cand["proof_evidence_text"])
    reasons: list[str] = []
    if not source_status["current"]:
        reasons.append("missing_current_workspace_source_refs")
    if source_status["stale"]:
        reasons.append("stale_workspace_source_ref")
    if source_status["outside_workspace"]:
        reasons.append("source_ref_outside_current_workspace")
    if not has_real_source_citation(cand):
        reasons.append("missing_project_source_citation")
    if not has_concrete_evidence:
        reasons.append("missing_concrete_proof_evidence")
    if not has_proved_execution(cand):
        reasons.append("missing_proved_execution_manifest")
    if not cand["listed_impact_proven"]:
        reasons.append("listed_impact_not_proven")
    if cand["blocker_markers"]:
        reasons.append("blocker_present")
    if cand["advisory_markers"]:
        reasons.append("advisory_only")
    proof_ready = not reasons
    return {
        "proof_ready": proof_ready,
        "proof_readiness_reasons": reasons,
        "current_workspace_source_refs": source_status["current"],
        "stale_workspace_source_refs": source_status["stale"],
        "outside_workspace_source_refs": source_status["outside_workspace"],
        "external_or_placeholder_source_refs": source_status["external_or_placeholder"],
        "current_workspace_proof_artifacts": proof_artifacts,
        "proof_evidence_text": cand["proof_evidence_text"],
        "strict_proved_execution_manifest_paths": strict_paths,
        "has_concrete_proof_or_harness_evidence": has_concrete_evidence,
    }


def concise_candidate(workspace: Path, cand: dict[str, Any]) -> dict[str, Any]:
    readiness = proof_readiness(workspace, cand)
    return {
        "candidate_id": cand["candidate_id"],
        "route_family": cand["route_family"],
        "tier": cand["tier"],
        "requirement_ids": cand["requirement_ids"],
        "decisions": cand["decisions"],
        "terminal_blockers": sorted(cand["terminal_blockers"]),
        "listed_impact_proven": cand["listed_impact_proven"],
        "has_real_project_source_citation": has_real_source_citation(cand),
        "has_proved_execution_manifest": has_proved_execution(cand),
        "has_blocked_path_execution_manifest": has_blocked_execution(cand),
        "proof_ready": readiness["proof_ready"],
        "proof_readiness_reasons": readiness["proof_readiness_reasons"],
        "current_workspace_source_refs": readiness["current_workspace_source_refs"],
        "stale_workspace_source_refs": readiness["stale_workspace_source_refs"],
        "outside_workspace_source_refs": readiness["outside_workspace_source_refs"],
        "external_or_placeholder_source_refs": readiness["external_or_placeholder_source_refs"],
        "has_concrete_proof_or_harness_evidence": readiness["has_concrete_proof_or_harness_evidence"],
        "current_workspace_proof_artifacts": readiness["current_workspace_proof_artifacts"],
        "proof_evidence_text": readiness["proof_evidence_text"],
        "strict_proved_execution_manifest_paths": readiness["strict_proved_execution_manifest_paths"],
        "blocker_markers": cand["blocker_markers"],
        "advisory_markers": cand["advisory_markers"],
        "project_source_citation_count": cand["project_source_citation_count"],
        "valid_source_citation_count": cand["valid_source_citation_count"],
        "source_citation_count": cand["source_citation_count"],
        "execution_evidence": cand["execution_evidence"],
        "source_evidence": cand["source_evidence"],
        "source_files": cand["source_files"],
        "next_local_commands": cand["next_local_commands"],
    }


def first_summary_by_kind(inputs: list[dict[str, Any]], kind: str) -> list[dict[str, Any]]:
    return [row for row in inputs if row["kind"] == kind and row.get("summary") is not None]


def build_markdown(ledger: dict[str, Any]) -> str:
    summary = ledger["summary"]
    before_after = ledger["before_after_counts"]
    blockers = ledger["blocker_counts"]
    next_families = ledger["terminal_next_command_families"]

    lines = [
        "# PR560 Worker FK Impact-Proof Reconciliation Ledger",
        "",
        f"- Workspace: `{ledger['workspace']}`",
        f"- Generated: `{ledger['generated_at']}`",
        f"- Inputs consumed: {summary['input_file_count']} files ({summary['json_input_count']} JSON, {summary['markdown_input_count']} Markdown)",
        f"- Reconciled rows: {summary['reconciled_row_count']}",
        f"- Conservative closure candidates: {summary['conservative_closure_candidate_count']}",
        f"- Source+proved rows needing listed-impact review: {summary['source_and_proved_without_listed_impact_count']}",
        f"- Submission posture: `{ledger['submission_posture']}`",
        "",
        "## Before / After",
        "",
    ]
    for item in before_after:
        lines.append(
            f"- {item['metric']}: before `{item.get('before', '')}` -> after `{item.get('after', '')}`"
            f" (delta `{item.get('delta', '')}`)"
        )
    lines.extend(
        [
            "",
            "## Blocker Separation",
            "",
            f"- Blocked-path execution rows: {blockers['blocked_path_execution_rows']}",
            f"- Source-citation blocker rows: {blockers['source_citation_blocker_rows']}",
            f"- Listed-impact blocker rows: {blockers['listed_impact_blocker_rows']}",
            f"- Missing proved execution rows: {blockers['missing_proved_execution_rows']}",
            f"- Rows with real project source citation: {blockers['rows_with_real_project_source_citation']}",
            f"- Rows with proved execution manifest: {blockers['rows_with_proved_execution_manifest']}",
            f"- Proof-ready rows: {blockers['proof_ready_rows']}",
            "",
            "## Closure Candidates",
            "",
        ]
    )
    if ledger["conservative_closure_candidates"]:
        for row in ledger["conservative_closure_candidates"]:
            lines.append(
                f"- `{row['candidate_id']}`: source citation and proved execution present; "
                f"listed impact proven=`{row['listed_impact_proven']}`"
            )
    else:
        lines.append("- None. No reconciled row has both real project source citation and a proved exploit-impact execution manifest.")
    lines.extend(["", "## Proof Readiness Reasons", ""])
    if ledger["proof_readiness_reason_counts"]:
        for reason, count in ledger["proof_readiness_reason_counts"].items():
            lines.append(f"- `{reason}`: {count}")
    else:
        lines.append("- None.")
    lines.extend(["", "## Terminal Next Command Families", ""])
    for family in next_families:
        lines.append(f"- `{family['family']}` ({family['count']} rows): {family['next_command']}")
    lines.extend(
        [
            "",
            "Per-row next commands are preserved in the JSON ledger under `terminalized_rows[].next_local_commands`.",
            "",
            "## Why No More Local Closure Was Safe",
            "",
        ]
    )
    for reason in ledger["why_no_more_local_closure_safe"]:
        lines.append(f"- {reason}")
    lines.append("")
    return "\n".join(lines)


def build_ledger(workspace: Path) -> dict[str, Any]:
    paths = input_paths(workspace)
    inputs: list[dict[str, Any]] = []
    candidates: dict[str, dict[str, Any]] = {}
    json_data_by_name: dict[str, Any] = {}
    bound_source_diagnostics: list[dict[str, Any]] = []

    for path in paths:
        entry = {
            "path": rel(workspace, path),
            "kind": classify_input(path),
            "size_bytes": path.stat().st_size,
            "sha256": sha256_file(path),
            "parsed": False,
            "row_count": None,
            "summary": None,
        }
        if path.suffix == ".json":
            try:
                data = load_json(path)
            except json.JSONDecodeError as exc:
                entry["parse_error"] = str(exc)
            else:
                entry["parsed"] = True
                if isinstance(data, dict):
                    rows = data.get("rows")
                    if isinstance(rows, list):
                        entry["row_count"] = len(rows)
                    elif isinstance(data.get("row_accounting"), list):
                        entry["row_count"] = len(data["row_accounting"])
                    entry["summary"] = compact_summary(data)
                json_data_by_name[path.name] = data
                add_json_rows(candidates, workspace, path, data, bound_source_diagnostics)
        inputs.append(entry)

    execution_inventory = scan_execution_manifests(workspace, candidates)
    bound_source_diagnostics.extend(execution_inventory["bound_source_validation_diagnostics"])
    source_inventory = scan_source_proofs(workspace, candidates)

    rows = [concise_candidate(workspace, cand) for cand in candidates.values()]
    rows.sort(key=lambda row: row["candidate_id"])
    source_blocker_rows = [
        row for row in rows if any(token in row["terminal_blockers"] for token in SOURCE_BLOCKER_TOKENS)
    ]
    blocked_path_rows = [row for row in rows if row["has_blocked_path_execution_manifest"]]
    listed_impact_rows = [row for row in rows if not row["listed_impact_proven"]]
    proved_rows = [row for row in rows if row["has_proved_execution_manifest"]]
    source_rows = [row for row in rows if row["has_real_project_source_citation"]]
    source_and_proved = [
        row for row in rows if row["has_real_project_source_citation"] and row["has_proved_execution_manifest"]
    ]
    conservative_closure_candidates = [row for row in rows if row["proof_ready"]]
    source_and_proved_without_listed = [row for row in source_and_proved if not row["listed_impact_proven"]]
    non_ready_rows = [row for row in rows if not row["proof_ready"]]
    proof_readiness_reason_counts = count_by(
        [reason for row in rows for reason in row["proof_readiness_reasons"]]
    )

    requirement_summaries = first_summary_by_kind(inputs, "impact_requirement_execution")
    source_summary = next(
        (entry["summary"] for entry in inputs if entry["path"].endswith("source_citation_closure_eu.json")),
        {},
    )
    fg = json_data_by_name.get("pr560_worker_fg_proof_live_closure.json", {})
    ev = json_data_by_name.get("pr560_worker_ev_bridge_finalization_closure.json", {})
    fg_counts = fg.get("before_after_counts", {}) if isinstance(fg, dict) else {}
    ev_counts = ev.get("before_after_counts", {}) if isinstance(ev, dict) else {}

    before_after = []
    if requirement_summaries:
        first = requirement_summaries[0]["summary"] or {}
        last = requirement_summaries[-1]["summary"] or {}
        for token in (
            "execution_manifest_blocked_path",
            "impact_assertion_not_demonstrated",
            "missing_execution_or_source_proof",
            "missing_poc_execution_manifest",
            "listed_impact_not_proven",
            "source_proof_missing_project_source_citation",
        ):
            before = (first.get("terminal_blocker_counts") or {}).get(token, 0)
            after = (last.get("terminal_blocker_counts") or {}).get(token, 0)
            before_after.append({"metric": token, "before": before, "after": after, "delta": after - before})
    if isinstance(ev_counts, dict):
        for key, value in sorted(ev_counts.items()):
            if isinstance(value, dict) and {"before", "after", "delta"} <= set(value):
                before_after.append(
                    {
                        "metric": f"worker_ev.{key}",
                        "before": value["before"],
                        "after": value["after"],
                        "delta": value["delta"],
                    }
                )
    if isinstance(source_summary, dict):
        before_after.append(
            {
                "metric": "source_citation_eu.missing_project_source_citation_rows",
                "before": source_summary.get("input_source_proof_missing_project_source_citation", 0),
                "after": source_summary.get(
                    "canonical_source_proof_missing_project_source_citation_preserved_until_project_source_exists",
                    source_summary.get("terminal_no_source_citation_rows", 0),
                ),
                "delta": int(
                    source_summary.get(
                        "canonical_source_proof_missing_project_source_citation_preserved_until_project_source_exists",
                        source_summary.get("terminal_no_source_citation_rows", 0),
                    )
                )
                - int(source_summary.get("input_source_proof_missing_project_source_citation", 0)),
            }
        )
        before_after.append(
            {
                "metric": "source_citation_eu.valid_project_source_citation_rows",
                "before": 0,
                "after": source_summary.get("source_proofs_with_valid_citations", 0),
                "delta": int(source_summary.get("source_proofs_with_valid_citations", 0)),
            }
        )
    if isinstance(fg_counts, dict):
        impact = fg_counts.get("impact_proof") if isinstance(fg_counts.get("impact_proof"), dict) else {}
        live = fg_counts.get("live_topology") if isinstance(fg_counts.get("live_topology"), dict) else {}
        before_after.append(
            {
                "metric": "worker_fg.impact_proof.closure_candidates",
                "before": 0,
                "after": int(impact.get("closure_candidates", 0) or 0),
                "delta": int(impact.get("closure_candidates", 0) or 0),
            }
        )
        before_after.append(
            {
                "metric": "worker_fg.live_topology.closure_candidates",
                "before": 0,
                "after": int(live.get("closure_candidates", 0) or 0),
                "delta": int(live.get("closure_candidates", 0) or 0),
            }
        )

    terminal_next_command_families = []
    if isinstance(fg, dict):
        for family in fg.get("terminal_next_command_families", []) or []:
            if isinstance(family, dict):
                terminal_next_command_families.append(family)
    if isinstance(ev, dict):
        residual = ev.get("residual_blockers", {}) if isinstance(ev.get("residual_blockers"), dict) else {}
        bridge = residual.get("bridge_finalization_rows")
        if isinstance(bridge, dict):
            terminal_next_command_families.append(
                {
                    "family": "bridge_finalization_project_specific_binding_exact_template",
                    "count": bridge.get("count", 0),
                    "status": "terminal_until_project_specific_same_block_bridge_fork_proof_exists",
                    "next_command": bridge.get("next_project_specific_binding_command_template", ""),
                }
            )

    why = []
    if isinstance(fg, dict):
        why.extend(fg.get("why_no_more_local_closure_safe", []) or [])
    if isinstance(ev, dict):
        why.extend(ev.get("why_no_additional_local_closure_safe", []) or [])
    if rows and not source_rows:
        why.append("Row-level reconciliation found no real project source citation attached to any reconciled impact-proof row.")
    if rows and not proved_rows:
        why.append(
            "Local poc_execution inventory found no strict proved-impact execution manifests "
            "(final_result=proved, impact_assertion=exploit_impact, evidence_class=executed_with_manifest, "
            "and structured status=pass/exit_code=0 command evidence)."
        )
    if rows and len(listed_impact_rows) == len(rows):
        why.append(
            "All reconciled impact rows still have listed_impact_proven=false, so promoting any row would overstate local proof.",
        )
    deduped_why: list[str] = []
    for reason in why:
        if isinstance(reason, str) and reason not in deduped_why:
            deduped_why.append(reason)

    ledger = {
        "schema": "auditooor.pr560.worker_fk.impact_proof_reconciliation_ledger.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "workspace": str(workspace),
        "promotion_allowed": bool(conservative_closure_candidates),
        "submission_posture": "CANDIDATES_REQUIRE_FINAL_GATE" if conservative_closure_candidates else "NOT_SUBMIT_READY",
        "proof_boundary": (
            "This ledger reconciles local closure evidence only. It does not set severity, authorize submission, "
            "or override scope/OOS, pre-submit, live-proof, or listed-impact gates. Proved execution means "
            "final_result=proved, impact_assertion=exploit_impact, evidence_class=executed_with_manifest, "
            "and structured status=pass/exit_code=0 command evidence."
        ),
        "inputs_consumed": inputs,
        "execution_manifest_inventory": execution_inventory,
        "diagnostics": {
            "bound_source_validation_errors": bound_source_diagnostics,
        },
        "source_proof_inventory": source_inventory,
        "summary": {
            "input_file_count": len(inputs),
            "json_input_count": sum(1 for item in inputs if item["path"].endswith(".json")),
            "markdown_input_count": sum(1 for item in inputs if item["path"].endswith(".md")),
            "reconciled_row_count": len(rows),
            "conservative_closure_candidate_count": len(conservative_closure_candidates),
            "proof_ready_row_count": len(conservative_closure_candidates),
            "non_ready_row_count": len(non_ready_rows),
            "source_and_proved_without_listed_impact_count": len(source_and_proved_without_listed),
            "route_family_counts": count_by([row["route_family"] for row in rows]),
            "tier_counts": count_by([row["tier"] for row in rows]),
        },
        "before_after_counts": before_after,
        "blocker_counts": {
            "blocked_path_execution_rows": len(blocked_path_rows),
            "source_citation_blocker_rows": len(source_blocker_rows),
            "listed_impact_blocker_rows": len(listed_impact_rows),
            "missing_proved_execution_rows": len(rows) - len(proved_rows),
            "rows_with_real_project_source_citation": len(source_rows),
            "rows_with_proved_execution_manifest": len(proved_rows),
            "proof_ready_rows": len(conservative_closure_candidates),
        },
        "proof_readiness_reason_counts": proof_readiness_reason_counts,
        "conservative_closure_candidates": conservative_closure_candidates,
        "non_ready_rows": non_ready_rows,
        "source_and_proved_without_listed_impact": source_and_proved_without_listed,
        "blocked_path_execution_rows": [
            {
                "candidate_id": row["candidate_id"],
                "route_family": row["route_family"],
                "tier": row["tier"],
                "execution_evidence": row["execution_evidence"],
                "terminal_blockers": row["terminal_blockers"],
            }
            for row in blocked_path_rows
        ],
        "source_citation_blocker_rows": [
            {
                "candidate_id": row["candidate_id"],
                "route_family": row["route_family"],
                "tier": row["tier"],
                "project_source_citation_count": row["project_source_citation_count"],
                "valid_source_citation_count": row["valid_source_citation_count"],
                "source_citation_count": row["source_citation_count"],
                "terminal_blockers": row["terminal_blockers"],
            }
            for row in source_blocker_rows
        ],
        "listed_impact_blocker_rows": [
            {
                "candidate_id": row["candidate_id"],
                "route_family": row["route_family"],
                "tier": row["tier"],
                "listed_impact_proven": row["listed_impact_proven"],
                "terminal_blockers": row["terminal_blockers"],
            }
            for row in listed_impact_rows
        ],
        "terminal_next_command_families": terminal_next_command_families,
        "terminalized_rows": rows,
        "why_no_more_local_closure_safe": deduped_why,
    }
    return ledger


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", default=os.getcwd(), help="Workspace root")
    parser.add_argument(
        "--out-json",
        default=".auditooor/pr560_worker_fk_impact_proof_reconciliation_ledger.json",
        help="Output JSON ledger path",
    )
    parser.add_argument(
        "--out-md",
        default=".auditooor/pr560_worker_fk_impact_proof_reconciliation_ledger.md",
        help="Output Markdown ledger path",
    )
    args = parser.parse_args()

    workspace = Path(args.workspace).resolve()
    ledger = build_ledger(workspace)
    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    if not out_json.is_absolute():
        out_json = workspace / out_json
    if not out_md.is_absolute():
        out_md = workspace / out_md
    write_json(out_json, ledger)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text(build_markdown(ledger), encoding="utf-8")
    print(f"wrote {rel(workspace, out_json)}")
    print(f"wrote {rel(workspace, out_md)}")
    print(
        "reconciled_rows={rows} closure_candidates={candidates} blocked_path={blocked} "
        "source_citation_blockers={source} listed_impact_blockers={listed}".format(
            rows=ledger["summary"]["reconciled_row_count"],
            candidates=ledger["summary"]["conservative_closure_candidate_count"],
            blocked=ledger["blocker_counts"]["blocked_path_execution_rows"],
            source=ledger["blocker_counts"]["source_citation_blocker_rows"],
            listed=ledger["blocker_counts"]["listed_impact_blocker_rows"],
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
