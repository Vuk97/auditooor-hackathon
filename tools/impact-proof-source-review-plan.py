#!/usr/bin/env python3
"""Build executable source-review routes for impact-proof blockers.

This helper does not promote proof. It turns the impact/source blocker ledgers
into per-row review commands, separating candidate-bound project source from
generated fixtures, scaffolds, provider text, and advisory-only semantic hints.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from execution_manifest_proof import is_strict_proved_execution_manifest, strict_terminal_blockers


SCHEMA = "auditooor.pr560.impact_proof_source_review_plan.v1"
DEFAULT_BACKFILL = ".auditooor/impact_proof_source_citation_backfill_ex.json"
DEFAULT_EXECUTOR = ".auditooor/impact_proof_project_evidence_executor_ex.json"
DEFAULT_OUT = ".auditooor/impact_proof_source_review_plan.json"
DEFAULT_OUT_MD = ".auditooor/impact_proof_source_review_plan.md"
PROOF_BOUNDARY = (
    "Source-review plan rows are executable review routes only. They do not "
    "prove listed impact, set severity, authorize submission, or override "
    "scope/OOS/pre-submit gates."
)

GENERATED_PREFIXES = (
    ".auditooor/",
    ".audit_logs/",
    "agent_outputs/",
    "benchmark_fixtures/",
    "detectors/",
    "docs/",
    "patterns/fixtures/",
    "poc-tests/",
    "poc_execution/",
    "reference/",
    "source_proofs/",
    "submissions/",
    "test_fixtures/",
)
GENERATED_FRAGMENTS = (
    "/invariants/",
    "/poc-tests/",
    "/submissions/",
    "/symbolic/",
)
SOURCE_EXTENSIONS = {".sol", ".rs", ".cairo", ".move", ".vy", ".go", ".ts", ".js"}
SOURCE_ROOTS = ("src", "contracts", "external", "projects", "examples")
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
PROOF_ARTIFACT_NAMES = {
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
FAMILY_TERMS = {
    "access_control": ("onlyowner", "onlyrole", "hasrole", "msg.sender", "auth", "authorize"),
    "asset_custody": ("transfer", "withdraw", "deposit", "balance", "custody", "vault"),
    "availability_dos": ("pause", "revert", "while", "for ", "gas", "dos"),
    "bridge_finalization": ("finalize", "message", "bridge", "relay", "withdraw", "proof"),
    "consensus_safety": ("consensus", "validator", "block", "checkpoint", "fork"),
    "governance_integrity": ("governance", "proposal", "vote", "quorum", "timelock"),
    "liquidation_solvency": ("liquidat", "collateral", "solvency", "debt", "health"),
    "node_liveness": ("node", "validator", "liveness", "heartbeat", "slashing"),
    "oracle_settlement": ("oracle", "price", "settle", "twap", "feed"),
    "proof_verification": ("verify", "proof", "verifier", "signature", "merkle"),
    "resource_consumption": ("decode", "allocate", "gas", "loop", "memory", "resource"),
    "signature_replay": ("signature", "nonce", "domain", "chainid", "ecrecover", "permit"),
}


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


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


def split_line_ref(ref: str) -> tuple[str, int | None, int | None]:
    text = ref.strip()
    match = LINE_REF_RE.match(text)
    if not match:
        return text, None, None
    start = int(match.group("line"))
    end_text = match.group("end")
    return match.group("path"), start, int(end_text) if end_text else start


def is_under(path: Path, root: Path) -> bool:
    try:
        return path == root or root in path.parents
    except RuntimeError:
        return False


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


def rel_path(workspace: Path, value: str) -> str:
    if not value:
        return ""
    path = Path(value)
    try:
        return str(path.resolve().relative_to(workspace.resolve()))
    except (OSError, ValueError):
        return str(path)


def is_project_source_path(path_text: str) -> bool:
    path = str(path_text or "").lstrip("./")
    if not path or path.startswith(GENERATED_PREFIXES):
        return False
    if any(fragment in f"/{path}" for fragment in GENERATED_FRAGMENTS):
        return False
    return Path(path).suffix.lower() in SOURCE_EXTENSIONS


def source_ref_status(workspace: Path, refs: list[str]) -> dict[str, list[str]]:
    current: list[str] = []
    stale: list[str] = []
    outside: list[str] = []
    external_or_placeholder: list[str] = []
    non_project: list[str] = []
    for ref in uniq(refs):
        path_text, start, end = split_line_ref(ref)
        path, status = workspace_ref_path(workspace, path_text)
        if status == "outside_workspace":
            outside.append(ref)
            continue
        if status != "workspace" or path is None:
            external_or_placeholder.append(ref)
            continue
        rel = rel_path(workspace, str(path))
        if not path.is_file() or not line_ref_exists(path, start, end):
            stale.append(ref)
            continue
        if not is_project_source_path(rel):
            non_project.append(ref)
            continue
        current.append(ref)
    return {
        "current": current,
        "stale": stale,
        "outside_workspace": outside,
        "external_or_placeholder": external_or_placeholder,
        "non_project": non_project,
    }


def source_refs_from_payload(payload: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    for key in SOURCE_REF_KEYS:
        refs.extend(coerce_str_list(payload.get(key)))
    for proof in payload.get("source_proofs") or []:
        if isinstance(proof, dict):
            for key in SOURCE_REF_KEYS:
                refs.extend(coerce_str_list(proof.get(key)))
    for hint in payload.get("semantic_graph_hints") or []:
        if not isinstance(hint, dict):
            continue
        for item in hint.get("citations") or []:
            if not isinstance(item, dict):
                continue
            path = str(item.get("path") or item.get("file") or "")
            line = int(item.get("line") or item.get("start_line") or 0)
            if path and line:
                refs.append(citation(path, line))
            elif path:
                refs.append(path)
    return uniq(refs)


def line_exists(workspace: Path, path_text: str, line: int) -> bool:
    if line <= 0:
        return False
    path = workspace / path_text
    if not path.is_file():
        return False
    try:
        return line <= len(path.read_text(encoding="utf-8", errors="replace").splitlines())
    except OSError:
        return False


def citation(raw_path: str, line: int) -> str:
    return f"{raw_path}:{line}" if line else raw_path


def proof_artifact_name(value: str) -> bool:
    token = normalized_token(value)
    return (
        token in PROOF_ARTIFACT_NAMES
        or "harness" in token
        or "proof" in token
        or token.endswith("execution_manifest")
    )


def proof_artifact_status(workspace: Path, payload: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    current: list[dict[str, Any]] = []
    stale: list[dict[str, Any]] = []
    outside: list[dict[str, Any]] = []
    external_or_placeholder: list[dict[str, Any]] = []
    for ref in (payload.get("local_artifacts") or {}).get("artifact_refs") or []:
        if not isinstance(ref, dict):
            continue
        artifact = str(ref.get("artifact") or "")
        path_text = str(ref.get("path") or "")
        if not proof_artifact_name(artifact) or not path_text:
            continue
        path, status = workspace_ref_path(workspace, path_text)
        rendered = {
            "artifact": artifact,
            "path": rel_path(workspace, path_text),
            "declared_exists": bool(ref.get("exists", True)),
            "evidence_class": "local_artifact_reference",
        }
        if status == "workspace" and path is not None and path.exists() and ref.get("exists", True):
            current.append(rendered)
        elif status == "outside_workspace":
            outside.append(rendered)
        elif status != "workspace":
            external_or_placeholder.append(rendered)
        else:
            stale.append(rendered)
    return {
        "current": current,
        "stale": stale,
        "outside_workspace": outside,
        "external_or_placeholder": external_or_placeholder,
    }


def execution_manifest_refs(payload: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    manifest = payload.get("execution_manifest") or {}
    if isinstance(manifest, dict) and manifest.get("path"):
        refs.append(str(manifest["path"]))
    for ref in (payload.get("local_artifacts") or {}).get("artifact_refs") or []:
        if isinstance(ref, dict) and ref.get("artifact") == "poc_execution_manifest" and ref.get("path"):
            refs.append(str(ref["path"]))
    return uniq(refs)


def execution_manifest_status(workspace: Path, payload: dict[str, Any]) -> dict[str, Any]:
    manifests: list[dict[str, Any]] = []
    stale: list[str] = []
    outside: list[str] = []
    external_or_placeholder: list[str] = []
    for ref in execution_manifest_refs(payload):
        path, status = workspace_ref_path(workspace, ref)
        if status == "outside_workspace":
            outside.append(ref)
            continue
        if status != "workspace" or path is None:
            external_or_placeholder.append(ref)
            continue
        if not path.is_file():
            stale.append(ref)
            continue
        manifest = read_json(path)
        if not isinstance(manifest, dict):
            stale.append(ref)
            continue
        manifests.append(
            {
                "path": rel_path(workspace, str(path)),
                "proved_impact": is_strict_proved_execution_manifest(manifest),
                "strict_proof_blockers": strict_terminal_blockers(manifest),
            }
        )
    return {
        "manifests": manifests,
        "strict_proved": any(item["proved_impact"] for item in manifests),
        "stale": stale,
        "outside_workspace": outside,
        "external_or_placeholder": external_or_placeholder,
    }


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


def proof_readiness(workspace: Path, backfill_row: dict[str, Any], executor_row: dict[str, Any]) -> dict[str, Any]:
    source_refs = source_refs_from_payload(backfill_row) + source_refs_from_payload(executor_row)
    source_status = source_ref_status(workspace, source_refs)
    backfill_artifacts = proof_artifact_status(workspace, backfill_row)
    executor_artifacts = proof_artifact_status(workspace, executor_row)
    current_artifacts = backfill_artifacts["current"] + executor_artifacts["current"]
    stale_artifacts = backfill_artifacts["stale"] + executor_artifacts["stale"]
    outside_artifacts = backfill_artifacts["outside_workspace"] + executor_artifacts["outside_workspace"]
    external_artifacts = backfill_artifacts["external_or_placeholder"] + executor_artifacts["external_or_placeholder"]
    manifest_status = execution_manifest_status(workspace, executor_row)
    markers = blocker_advisory_markers(backfill_row, executor_row)
    current_harness_artifacts = [
        item for item in current_artifacts if normalized_token(item.get("artifact")) != "poc_execution_manifest"
    ]
    has_concrete_proof_evidence = bool(current_harness_artifacts) or bool(manifest_status["strict_proved"])
    typed_reasons: list[str] = []
    if not source_status["current"]:
        typed_reasons.append("missing_current_workspace_source_refs")
    if source_status["stale"]:
        typed_reasons.append("stale_workspace_source_ref")
    if source_status["outside_workspace"]:
        typed_reasons.append("source_ref_outside_current_workspace")
    if source_status["non_project"]:
        typed_reasons.append("source_ref_is_not_project_source")
    if stale_artifacts or manifest_status["stale"]:
        typed_reasons.append("stale_workspace_proof_artifact")
    if outside_artifacts or manifest_status["outside_workspace"]:
        typed_reasons.append("proof_artifact_outside_current_workspace")
    if not has_concrete_proof_evidence:
        typed_reasons.append("missing_concrete_proof_evidence")
    if markers:
        typed_reasons.append("blocker_or_advisory_marker_present")
    ready = (
        bool(source_status["current"])
        and has_concrete_proof_evidence
        and not markers
        and not source_status["stale"]
        and not source_status["outside_workspace"]
        and not source_status["non_project"]
        and not stale_artifacts
        and not outside_artifacts
        and not manifest_status["stale"]
        and not manifest_status["outside_workspace"]
    )
    return {
        "proof_review_ready": ready,
        "typed_reasons": uniq(typed_reasons),
        "current_workspace_source_refs": source_status["current"],
        "stale_workspace_source_refs": source_status["stale"],
        "outside_workspace_source_refs": source_status["outside_workspace"],
        "external_or_placeholder_source_refs": source_status["external_or_placeholder"],
        "non_project_source_refs": source_status["non_project"],
        "has_concrete_proof_evidence": has_concrete_proof_evidence,
        "current_workspace_proof_evidence": current_artifacts,
        "stale_workspace_proof_evidence": stale_artifacts,
        "outside_workspace_proof_evidence": outside_artifacts,
        "external_or_placeholder_proof_evidence": external_artifacts,
        "execution_manifests": manifest_status["manifests"],
        "strict_execution_manifest_proved": manifest_status["strict_proved"],
        "stale_execution_manifests": manifest_status["stale"],
        "outside_workspace_execution_manifests": manifest_status["outside_workspace"],
        "external_or_placeholder_execution_manifests": manifest_status["external_or_placeholder"],
        "blocker_advisory_markers": markers,
    }


def semantic_project_hints(workspace: Path, row: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    project: list[dict[str, Any]] = []
    non_project: list[dict[str, Any]] = []
    for hint in row.get("semantic_graph_hints") or []:
        if not isinstance(hint, dict):
            continue
        for item in hint.get("citations") or []:
            if not isinstance(item, dict):
                continue
            path = rel_path(workspace, str(item.get("path") or ""))
            line = int(item.get("line") or item.get("start_line") or 0)
            rendered = {
                "path": path,
                "line": line,
                "raw": citation(path, line),
                "project_source": bool(is_project_source_path(path) and line_exists(workspace, path, line)),
                "source": str(hint.get("source") or ""),
                "stage": str(item.get("stage") or ""),
                "evidence": str(item.get("evidence") or ""),
                "exists": line_exists(workspace, path, line) if is_project_source_path(path) else (workspace / path).exists(),
            }
            if is_project_source_path(path) and rendered["exists"]:
                project.append(rendered)
            else:
                non_project.append(rendered)
    return project, non_project


def source_files(workspace: Path) -> list[Path]:
    found: list[Path] = []
    for root_name in SOURCE_ROOTS:
        root = workspace / root_name
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if len(found) >= 5000:
                return found
            if path.is_file() and path.suffix.lower() in SOURCE_EXTENSIONS:
                rel = rel_path(workspace, str(path))
                if is_project_source_path(rel):
                    found.append(path)
    return found


def family_scan_candidates(workspace: Path, files: list[Path], family: str, limit: int) -> list[dict[str, Any]]:
    terms = FAMILY_TERMS.get(family, ())
    if not terms:
        return []
    out: list[dict[str, Any]] = []
    lowered_terms = tuple(term.lower() for term in terms)
    for path in files:
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for idx, text in enumerate(lines, start=1):
            blob = text.lower()
            term = next((item for item in lowered_terms if item in blob), "")
            if not term:
                continue
            rel = rel_path(workspace, str(path))
            out.append(
                {
                    "path": rel,
                    "line": idx,
                    "raw": citation(rel, idx),
                    "project_source": True,
                    "matched_term": term,
                    "snippet": text.strip()[:180],
                    "exists": True,
                }
            )
            if len(out) >= limit:
                return out
    return out


def next_commands(workspace: Path, row: dict[str, Any], candidates: list[dict[str, Any]]) -> list[str]:
    candidate_id = str(row.get("candidate_id") or "")
    commands = []
    for item in candidates[:3]:
        commands.append(f"sed -n '{item['line']},{item['line']}p' {workspace / item['path']}")
    if candidates:
        first = candidates[0]["raw"]
        commands.append(
            "python3 tools/source-proof-record.py "
            f"--workspace {workspace} --candidate {candidate_id} --citation {first} "
            "--oos-status in_scope --verdict proved_source_only "
            "--notes 'reviewed candidate-bound source citation; still requires listed-impact execution proof'"
        )
    else:
        commands.append(
            "python3 tools/source-proof-record.py "
            f"--workspace {workspace} --candidate {candidate_id} "
            "--verdict blocked_missing_impact_contract "
            "--notes 'terminal source review: no candidate-bound project source citation found in scoped graph or source roots'"
        )
    commands.append(f"python3 tools/impact-proof-source-citation-backfill.py --workspace {workspace} --print-json")
    commands.append(f"python3 tools/impact-proof-project-evidence-executor.py --workspace {workspace} --print-json")
    return commands


def build_plan(args: argparse.Namespace) -> dict[str, Any]:
    workspace = args.workspace.expanduser().resolve()
    backfill_path = workspace / args.backfill
    executor_path = workspace / args.executor
    backfill_rows = rows(read_json(backfill_path))
    executor_by_candidate = {
        str(row.get("candidate_id") or ""): row for row in rows(read_json(executor_path))
    }
    files = source_files(workspace)
    scan_cache: dict[str, list[dict[str, Any]]] = {}
    planned: list[dict[str, Any]] = []
    for row in backfill_rows:
        candidate_id = str(row.get("candidate_id") or "")
        family = str(row.get("route_family") or "")
        project_hints, non_project_hints = semantic_project_hints(workspace, row)
        if family not in scan_cache:
            scan_cache[family] = family_scan_candidates(workspace, files, family, args.scan_limit)
        scanned = scan_cache[family]
        review_candidates = (project_hints + scanned)[: args.row_candidate_limit]
        executor_row = executor_by_candidate.get(candidate_id, {})
        blockers = set(str(item) for item in row.get("terminal_blockers") or [] if item)
        blockers.update(str(item) for item in executor_row.get("terminal_blockers") or [] if item)
        readiness = proof_readiness(workspace, row, executor_row)
        if project_hints:
            decision = "source_review_ready_from_project_semantic_hint"
            route_blockers = {"source_review_required_before_source_proof_record"}
        elif scanned:
            decision = "source_review_ready_from_family_grep_candidates"
            route_blockers = {"candidate_binding_required_before_source_proof_record"}
        elif non_project_hints:
            decision = "terminal_semantic_hints_not_project_source"
            route_blockers = {"semantic_hints_are_fixture_or_generated_only"}
        else:
            decision = "terminal_no_candidate_bound_project_source"
            route_blockers = {"no_candidate_bound_project_source_found"}
        if readiness["proof_review_ready"]:
            decision = "proof_review_ready"
            route_blockers = set()
            blockers = set()
        else:
            blockers.update(route_blockers)
            blockers.update(readiness["typed_reasons"])
            blockers.update(readiness["blocker_advisory_markers"])
        planned.append(
            {
                "candidate_id": candidate_id,
                "requirement_id": str(row.get("requirement_id") or ""),
                "tier": str(row.get("tier") or ""),
                "route_family": family,
                "decision": decision,
                "promotion_allowed": False,
                "submission_posture": "NOT_SUBMIT_READY",
                "proof_boundary": PROOF_BOUNDARY,
                "project_semantic_hint_count": len(project_hints),
                "non_project_semantic_hint_count": len(non_project_hints),
                "family_grep_candidate_count": len(scanned),
                "review_candidates": review_candidates,
                "non_project_hints_sample": non_project_hints[:3],
                "proof_review_ready": bool(readiness["proof_review_ready"]),
                "proof_review_status": "ready" if readiness["proof_review_ready"] else "blocked",
                "proof_review_reasons": readiness["typed_reasons"],
                "current_workspace_source_refs": readiness["current_workspace_source_refs"],
                "stale_workspace_source_refs": readiness["stale_workspace_source_refs"],
                "outside_workspace_source_refs": readiness["outside_workspace_source_refs"],
                "external_or_placeholder_source_refs": readiness["external_or_placeholder_source_refs"],
                "non_project_source_refs": readiness["non_project_source_refs"],
                "has_concrete_proof_evidence": bool(readiness["has_concrete_proof_evidence"]),
                "current_workspace_proof_evidence": readiness["current_workspace_proof_evidence"],
                "stale_workspace_proof_evidence": readiness["stale_workspace_proof_evidence"],
                "outside_workspace_proof_evidence": readiness["outside_workspace_proof_evidence"],
                "external_or_placeholder_proof_evidence": readiness["external_or_placeholder_proof_evidence"],
                "execution_manifests": readiness["execution_manifests"],
                "strict_execution_manifest_proved": bool(readiness["strict_execution_manifest_proved"]),
                "blocker_advisory_markers": readiness["blocker_advisory_markers"],
                "terminal_blockers": sorted(blockers),
                "next_local_commands": next_commands(workspace, row, review_candidates),
            }
        )
    decision_counts = Counter(row["decision"] for row in planned)
    family_counts = Counter(row["route_family"] for row in planned)
    return {
        "schema": SCHEMA,
        "generated_at": now_iso(),
        "workspace": str(workspace),
        "source_backfill": str(backfill_path),
        "source_executor": str(executor_path),
        "promotion_allowed": False,
        "submission_posture": "NOT_SUBMIT_READY",
        "proof_boundary": PROOF_BOUNDARY,
        "summary": {
            "row_count": len(planned),
            "decision_counts": dict(sorted(decision_counts.items())),
            "route_family_counts": dict(sorted(family_counts.items())),
            "project_source_review_ready_count": sum(
                1 for row in planned if row["decision"].startswith("source_review_ready")
            ),
            "proof_review_ready_count": sum(1 for row in planned if row["proof_review_ready"]),
            "terminal_no_project_source_count": sum(
                1 for row in planned if row["decision"].startswith("terminal_")
            ),
            "proof_review_reason_counts": dict(
                sorted(Counter(reason for row in planned for reason in row["proof_review_reasons"]).items())
            ),
            "source_file_count_scanned": len(files),
        },
        "rows": planned,
    }


def render_md(payload: dict[str, Any]) -> str:
    md = [
        "# Impact-Proof Source Review Plan",
        "",
        f"- Schema: `{payload['schema']}`",
        f"- Workspace: `{payload['workspace']}`",
        f"- Promotion allowed: `{payload['promotion_allowed']}`",
        f"- Submission posture: `{payload['submission_posture']}`",
        f"- Proof boundary: {payload['proof_boundary']}",
        "",
        "## Summary",
    ]
    for key, value in payload["summary"].items():
        md.append(f"- `{key}`: `{value}`")
    md.extend(
        [
            "",
            "## Rows",
            "",
            "| Candidate | Tier | Family | Decision | Proof review | Reasons | Review candidates | Next command |",
            "|---|---:|---|---|---|---|---:|---|",
        ]
    )
    for row in payload["rows"][:200]:
        cmd = row["next_local_commands"][0] if row["next_local_commands"] else ""
        md.append(
            "| `{candidate}` | `{tier}` | `{family}` | `{decision}` | `{proof_status}` | `{reasons}` | `{count}` | `{cmd}` |".format(
                candidate=row["candidate_id"],
                tier=row["tier"],
                family=row["route_family"],
                decision=row["decision"],
                proof_status=row.get("proof_review_status", "blocked"),
                reasons=", ".join(row.get("proof_review_reasons") or []) or "none",
                count=len(row["review_candidates"]),
                cmd=cmd.replace("|", "\\|"),
            )
        )
    return "\n".join(md)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--backfill", default=DEFAULT_BACKFILL)
    parser.add_argument("--executor", default=DEFAULT_EXECUTOR)
    parser.add_argument("--out", default=DEFAULT_OUT)
    parser.add_argument("--out-md", default=DEFAULT_OUT_MD)
    parser.add_argument("--scan-limit", type=int, default=12)
    parser.add_argument("--row-candidate-limit", type=int, default=8)
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args(argv)
    payload = build_plan(args)
    workspace = args.workspace.expanduser().resolve()
    write_json(workspace / args.out, payload)
    write_text(workspace / args.out_md, render_md(payload))
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
