#!/usr/bin/env python3
"""Bridge source-proof records to exact impact contracts without promotion.

This is a PR #560 closure/accounting helper.  It consumes terminal
``source_proofs/**/source_proof.json`` records, source-proof task queues,
workspace impact contracts, and scanner-autonomy outputs, then writes a bounded
300-500 item ledger under ``.auditooor/``.

The bridge is intentionally fail-closed:
* exact impact-contract rows may be attached as preconditions;
* ``listed_impact_proven=false`` remains a terminal proof blocker;
* unmatched source-proof records become terminal missing-impact-contract rows;
* no row assigns severity authority, selected-impact proof, or submit readiness.
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
    from execution_manifest_proof import is_strict_proved_execution_manifest  # noqa: E402
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


    def is_strict_proved_execution_manifest(manifest: dict[str, Any]) -> bool:
        commands = _manifest_commands(manifest)
        return (
            isinstance(manifest, dict)
            and str(manifest.get("final_result") or "") == "proved"
            and str(manifest.get("impact_assertion") or "") == "exploit_impact"
            and str(manifest.get("evidence_class") or "") == "executed_with_manifest"
            and any(
                isinstance(row, dict)
                and str(row.get("command") or "").strip()
                and str(row.get("status") or "").strip().lower() == "pass"
                and _is_zero_exit_code(row.get("exit_code"))
                for row in commands
            )
        )


SCHEMA = "auditooor.pr560.source_proof_impact_bridge.v1"
GENERATED_EVIDENCE_CLASS = "generated_hypothesis"
DEFAULT_OUT = ".auditooor/source_proof_impact_bridge.json"
DEFAULT_OUT_MD = ".auditooor/source_proof_impact_bridge.md"
DEFAULT_MIN_ITEMS = 300
DEFAULT_MAX_ITEMS = 500
PROOF_BOUNDARY = (
    "Source-proof/impact-contract bridge rows are closure accounting only; "
    "they do not prove impact or authorize submission."
)
SOURCE_REF_KEYS = ("source_citations", "source_refs", "source_ref", "citations")
IMPACT_ARTIFACT_KEYS = (
    "impact_proof_artifacts",
    "impact_artifacts",
    "proof_artifacts",
    "artifact_refs",
    "evidence_refs",
    "poc_artifacts",
    "execution_manifest",
    "poc_execution_manifest",
)
CONCRETE_IMPACT_BOOL_KEYS = (
    "before_after_assertions",
    "before_after_assertion",
    "state_transition_assertions",
    "state_transition_assertion",
    "state_transition_proof",
    "balance_delta_assertions",
    "state_delta_assertions",
)
CONCRETE_IMPACT_TEXT_RE = re.compile(r"(before[_ -]?after|state[_ -]?transition)", re.IGNORECASE)
BLOCKER_MARKER_KEYS = (
    "blockers",
    "terminal_blockers",
    "strict_proof_blockers",
    "strict_impact_blockers",
    "non_ready_reasons",
)
ADVISORY_BOOL_KEYS = ("advisory_only", "advisory_only_requirement")
ADVISORY_TEXT_RE = re.compile(r"\badvisory\b|advisory[_ -]?only", re.IGNORECASE)


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


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


def norm_candidate(candidate: str) -> str:
    value = str(candidate or "").strip()
    if value.endswith("-source-proof"):
        value = value[: -len("-source-proof")]
    return value


def slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-") or "item"


def source_proof_records(workspace: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted((workspace / "source_proofs").glob("*/source_proof.json")):
        payload = read_json(path)
        if not payload:
            continue
        candidate = str(payload.get("candidate_id") or path.parent.name)
        rows.append(
            {
                "candidate_id": candidate,
                "normalized_candidate_id": norm_candidate(candidate),
                "path": str(path),
                "final_verdict": str(payload.get("final_verdict") or ""),
                "impact_contract_linked": bool(payload.get("impact_contract_linked")),
                "valid_source_citation_count": int(payload.get("valid_source_citation_count") or 0),
                "oos_status": str(payload.get("oos_status") or ""),
                "blockers": [str(item) for item in payload.get("blockers") or []],
                "workspace": str(payload.get("workspace") or ""),
                "workspace_commit": str(payload.get("workspace_commit") or ""),
                "advisory_only": bool(payload.get("advisory_only")),
                "source_refs": collect_refs(payload, SOURCE_REF_KEYS),
                "impact_artifact_refs": collect_refs(payload, IMPACT_ARTIFACT_KEYS),
            }
        )
    return rows


def collect_refs(payload: dict[str, Any], keys: tuple[str, ...]) -> list[Any]:
    refs: list[Any] = []
    for key in keys:
        if key not in payload:
            continue
        value = payload.get(key)
        if isinstance(value, list):
            refs.extend(value)
        elif value not in (None, "", {}, []):
            refs.append(value)
    return refs


def _line_suffix(value: str) -> tuple[str, int | None, int | None]:
    match = re.match(r"^(?P<path>.+?)(?::(?P<start>[0-9]+)(?:-(?P<end>[0-9]+))?)?$", value)
    if not match:
        return value, None, None
    start = int(match.group("start")) if match.group("start") else None
    end = int(match.group("end")) if match.group("end") else start
    return match.group("path"), start, end


def _path_from_ref(ref: Any) -> tuple[str, int | None, int | None]:
    if isinstance(ref, dict):
        raw = str(
            ref.get("path")
            or ref.get("file")
            or ref.get("source_path")
            or ref.get("ref")
            or ref.get("raw")
            or ""
        ).strip()
        start = ref.get("start_line") or ref.get("line_start") or ref.get("line")
        end = ref.get("end_line") or ref.get("line_end") or start
        try:
            start_i = int(start) if start not in (None, "") else None
        except (TypeError, ValueError):
            start_i = None
        try:
            end_i = int(end) if end not in (None, "") else start_i
        except (TypeError, ValueError):
            end_i = start_i
        if raw and start_i is None:
            raw, parsed_start, parsed_end = _line_suffix(raw)
            start_i = parsed_start
            end_i = parsed_end
        return raw, start_i, end_i
    raw = str(ref or "").strip()
    if raw.startswith("workspace:"):
        raw = raw[len("workspace:") :]
    if raw.startswith("<workspace>/"):
        raw = raw[len("<workspace>/") :]
    return _line_suffix(raw)


def resolve_workspace_ref(workspace: Path, ref: Any) -> dict[str, Any]:
    raw_path, start, end = _path_from_ref(ref)
    if not raw_path:
        return {
            "raw": ref,
            "path": "",
            "resolved_path": "",
            "status": "missing_source_ref",
            "exists": False,
            "line_bounds_valid": False,
        }
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw_path):
        return {
            "raw": ref,
            "path": raw_path,
            "resolved_path": "",
            "status": "external_source_ref_not_workspace",
            "exists": False,
            "line_bounds_valid": False,
        }
    path = Path(raw_path).expanduser()
    full = path if path.is_absolute() else workspace / path
    try:
        resolved = full.resolve()
    except OSError:
        resolved = full
    try:
        resolved.relative_to(workspace)
    except ValueError:
        return {
            "raw": ref,
            "path": raw_path,
            "resolved_path": str(resolved),
            "status": "stale_workspace_source_ref",
            "exists": resolved.is_file(),
            "line_bounds_valid": False,
        }
    exists = resolved.is_file()
    line_bounds_valid = exists
    if exists and start is not None:
        try:
            line_count = len(resolved.read_text(encoding="utf-8", errors="replace").splitlines())
        except OSError:
            line_count = 0
        max_line = max(line_count, 1)
        line_bounds_valid = 1 <= start <= max_line and start <= (end or start) <= max_line
    status = "resolved" if exists and line_bounds_valid else "missing_source_ref"
    return {
        "raw": ref,
        "path": raw_path,
        "resolved_path": str(resolved),
        "status": status,
        "exists": exists,
        "line_bounds_valid": line_bounds_valid,
    }


def _iter_ref_candidates(value: Any) -> list[Any]:
    if isinstance(value, list):
        out: list[Any] = []
        for item in value:
            out.extend(_iter_ref_candidates(item))
        return out
    if isinstance(value, dict):
        if any(key in value for key in ("path", "file", "source_path", "ref", "raw")):
            return [value]
        out = []
        for item in value.values():
            out.extend(_iter_ref_candidates(item))
        return out
    if isinstance(value, str) and value.strip():
        return [value]
    return []


def resolve_artifact_ref(workspace: Path, ref: Any) -> dict[str, Any]:
    resolved = resolve_workspace_ref(workspace, ref)
    if resolved["status"] == "stale_workspace_source_ref":
        resolved["status"] = "stale_workspace_artifact_ref"
    elif resolved["status"] == "missing_source_ref":
        resolved["status"] = "missing_impact_artifact"
    return resolved


def _contains_concrete_impact_marker(value: Any) -> bool:
    if isinstance(value, dict):
        for key in CONCRETE_IMPACT_BOOL_KEYS:
            if value.get(key) is True:
                return True
        for key, item in value.items():
            if CONCRETE_IMPACT_TEXT_RE.search(str(key)) and item not in (False, None, "", [], {}):
                return True
            if _contains_concrete_impact_marker(item):
                return True
    elif isinstance(value, list):
        return any(_contains_concrete_impact_marker(item) for item in value)
    elif isinstance(value, str):
        return bool(CONCRETE_IMPACT_TEXT_RE.search(value))
    return False


def _truthy_marker_values(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if item not in (None, "", [], {})]
    if isinstance(value, dict):
        return [json.dumps(value, sort_keys=True)] if value else []
    if value not in (None, "", False, [], {}):
        return [str(value)]
    return []


def blocker_markers(payload: dict[str, Any]) -> list[str]:
    markers: list[str] = []
    for key in BLOCKER_MARKER_KEYS:
        markers.extend(_truthy_marker_values(payload.get(key)))
    return sorted(set(markers))


def advisory_marker_present(payload: dict[str, Any]) -> bool:
    if any(bool(payload.get(key)) for key in ADVISORY_BOOL_KEYS):
        return True
    verdict = str(payload.get("final_verdict") or payload.get("status") or "")
    return bool(ADVISORY_TEXT_RE.search(verdict))


def proof_verdict_is_ready(verdict: str) -> bool:
    token = str(verdict or "").strip().lower()
    return bool(token.startswith("proved")) and not ADVISORY_TEXT_RE.search(token)


def artifact_evidence_kind(payload: dict[str, Any]) -> str:
    if is_strict_proved_execution_manifest(payload):
        return "strict_execution_manifest"
    if _contains_concrete_impact_marker(payload):
        return "concrete_impact_marker"
    return ""


def concrete_impact_artifacts(workspace: Path, proof: dict[str, Any]) -> tuple[list[str], list[dict[str, Any]]]:
    refs: list[Any] = []
    for item in proof.get("impact_artifact_refs") or []:
        refs.extend(_iter_ref_candidates(item))
    candidate = str(proof.get("candidate_id") or "")
    normalized = str(proof.get("normalized_candidate_id") or "")
    for candidate_id in sorted({candidate, normalized} - {""}):
        refs.append(str(Path("poc_execution") / candidate_id / "execution_manifest.json"))

    concrete: list[str] = []
    resolutions: list[dict[str, Any]] = []
    seen: set[str] = set()
    for ref in refs:
        resolution = resolve_artifact_ref(workspace, ref)
        key = str(resolution.get("resolved_path") or resolution.get("path") or ref)
        if key in seen:
            continue
        seen.add(key)
        if resolution.get("exists"):
            payload = read_json(Path(str(resolution["resolved_path"])))
            evidence_kind = artifact_evidence_kind(payload)
            resolution["concrete_impact_artifact"] = bool(evidence_kind)
            resolution["impact_evidence_kind"] = evidence_kind
            if evidence_kind:
                concrete.append(str(resolution["resolved_path"]))
        else:
            resolution["concrete_impact_artifact"] = False
            resolution["impact_evidence_kind"] = ""
        resolutions.append(resolution)
    return sorted(set(concrete)), resolutions


def evaluate_source_proof(workspace: Path, proof: dict[str, Any]) -> dict[str, Any]:
    reasons: list[str] = []
    proof_workspace = str(proof.get("workspace") or "").strip()
    if proof_workspace:
        try:
            proof_workspace_path = Path(proof_workspace).expanduser().resolve()
        except OSError:
            proof_workspace_path = Path(proof_workspace).expanduser()
        if proof_workspace_path != workspace:
            reasons.append("stale_source")
            reasons.append("stale_workspace_source_refs")

    source_refs = proof.get("source_refs") or []
    source_ref_resolution = [resolve_workspace_ref(workspace, ref) for ref in source_refs]
    if not source_refs:
        reasons.append("missing_source_refs")
    elif any(row["status"] == "stale_workspace_source_ref" for row in source_ref_resolution):
        reasons.append("stale_source")
        reasons.append("stale_workspace_source_refs")
    elif any(row["status"] != "resolved" for row in source_ref_resolution):
        reasons.append("missing_source_refs")
    try:
        valid_source_citation_count = int(proof.get("valid_source_citation_count") or 0)
    except (TypeError, ValueError):
        valid_source_citation_count = 0
    if valid_source_citation_count <= 0:
        reasons.append("missing_source_refs")

    if advisory_marker_present(proof):
        reasons.append("advisory_only")
        reasons.append("advisory_only_source_proof")
    if not proof_verdict_is_ready(str(proof.get("final_verdict") or "")):
        reasons.append("source_proof_verdict_not_proved")
    if not proof.get("impact_contract_linked"):
        reasons.append("no_impact_linkage")
    source_blocker_markers = blocker_markers(proof)
    if source_blocker_markers:
        reasons.append("blocker_present")

    concrete_paths, artifact_resolution = concrete_impact_artifacts(workspace, proof)
    if not concrete_paths:
        reasons.append("missing_proof_evidence")
        reasons.append("missing_concrete_impact_artifact")

    proof_linked = not reasons
    return {
        "proof_path": str(proof.get("path") or ""),
        "proof_linked_impact": proof_linked,
        "non_proof_reasons": sorted(set(reasons)),
        "source_proof_blocker_markers": source_blocker_markers,
        "source_ref_resolution": source_ref_resolution,
        "impact_artifact_resolution": artifact_resolution,
        "concrete_impact_artifact_paths": concrete_paths,
    }


def aggregate_proof_evaluations(evaluations: list[dict[str, Any]]) -> dict[str, Any]:
    proof_linked = any(bool(item.get("proof_linked_impact")) for item in evaluations)
    reasons = sorted(
        {
            str(reason)
            for item in evaluations
            for reason in item.get("non_proof_reasons") or []
            if reason
        }
    )
    concrete_paths = sorted(
        {
            str(path)
            for item in evaluations
            for path in item.get("concrete_impact_artifact_paths") or []
            if path
        }
    )
    return {
        "proof_linked_impact": proof_linked,
        "proof_linkage": "proof_linked_impact" if proof_linked else "non_proof",
        "non_proof_reasons": [] if proof_linked else reasons,
        "all_non_proof_reasons": reasons,
        "concrete_impact_artifact_paths": concrete_paths,
    }


def load_source_task_refs(workspace: Path) -> tuple[list[dict[str, Any]], list[str]]:
    refs: list[dict[str, Any]] = []
    artifacts: list[str] = []
    for rel in (
        ".auditooor/source_proof_tasks.json",
        ".auditooor/agent_recall_source_proof_manifests.json",
    ):
        path = workspace / rel
        payload = read_json(path)
        if not payload:
            continue
        artifacts.append(str(path))
        for key in ("rows", "tasks", "manifests"):
            value = payload.get(key)
            if isinstance(value, list):
                for row in value:
                    if isinstance(row, dict):
                        refs.append({**row, "_source_artifact": str(path)})
                break
    return refs, artifacts


def scanner_autonomy_summary(workspace: Path) -> dict[str, Any]:
    plan_path = workspace / ".auditooor" / "scanner_autonomy_plan.json"
    execution_path = workspace / ".auditooor" / "scanner_autonomy_execution.json"
    plan = read_json(plan_path)
    execution = read_json(execution_path)
    return {
        "plan_path": str(plan_path) if plan else "",
        "execution_path": str(execution_path) if execution else "",
        "plan_task_count": int(plan.get("task_count") or len(plan.get("tasks") or [])) if plan else 0,
        "plan_lane_counts": plan.get("lane_counts") or {},
        "execution_row_count": len(execution.get("rows") or []) if execution else 0,
        "execution_status_counts": execution.get("status_counts") or {},
        "coverage_claim": plan.get("coverage_claim") or execution.get("coverage_claim") or "none_scanner_autonomy_only",
        "promotion_allowed": False,
        "submission_posture": "NOT_SUBMIT_READY",
    }


def source_proof_blockers(matches: list[dict[str, Any]]) -> list[str]:
    blockers: list[str] = []
    for proof in matches:
        verdict = str(proof.get("final_verdict") or "")
        valid_citations = int(proof.get("valid_source_citation_count") or 0)
        if verdict == "blocked_missing_project_source_citation" or valid_citations <= 0:
            blockers.append("candidate_bound_project_source_citation_missing")
        if not proof.get("impact_contract_linked"):
            blockers.append("source_proof_not_linked_to_impact_contract")
        evaluation = proof.get("strict_impact_evaluation") or {}
        for reason in evaluation.get("non_proof_reasons") or []:
            blockers.append(f"source_proof_{reason}")
        for blocker in proof.get("blockers") or []:
            if blocker:
                blockers.append(str(blocker))
    return sorted(set(blockers))


def build_bridge(workspace: Path, *, min_items: int, max_items: int) -> dict[str, Any]:
    impact_path = workspace / ".auditooor" / "impact_contracts.json"
    impact_payload = read_json(impact_path)
    contracts = [row for row in impact_payload.get("contracts") or [] if isinstance(row, dict)]
    source_records = source_proof_records(workspace)
    source_refs, source_ref_artifacts = load_source_task_refs(workspace)
    scanner_summary = scanner_autonomy_summary(workspace)

    proofs_by_candidate: dict[str, list[dict[str, Any]]] = {}
    for proof in source_records:
        proof["strict_impact_evaluation"] = evaluate_source_proof(workspace, proof)
        proofs_by_candidate.setdefault(str(proof["normalized_candidate_id"]), []).append(proof)

    rows: list[dict[str, Any]] = []
    used_proofs: set[str] = set()
    for contract in sorted(contracts, key=lambda row: str(row.get("candidate_id") or "")):
        candidate = str(contract.get("candidate_id") or "")
        if not candidate:
            continue
        exact = bool(contract.get("exact_impact_row"))
        proven = bool(contract.get("listed_impact_proven"))
        matches = proofs_by_candidate.get(norm_candidate(candidate), [])
        for proof in matches:
            used_proofs.add(str(proof["path"]))
        proof_evaluations = [proof["strict_impact_evaluation"] for proof in matches]
        proof_linkage = aggregate_proof_evaluations(proof_evaluations)
        blockers: list[str] = []
        contract_blocker_markers = blocker_markers(contract)
        contract_advisory_marker = advisory_marker_present(contract)
        if not exact:
            blockers.append("impact_contract_not_exact")
        if not proven:
            blockers.append("listed_impact_not_proven")
        blockers.extend(str(item) for item in contract.get("terminal_blockers") or [])
        blockers.extend(contract_blocker_markers)
        if contract_advisory_marker:
            blockers.append("advisory_only_marker")
        blockers.extend(source_proof_blockers(matches))
        if not matches and any(
            item in set(contract.get("required_artifacts") or [])
            for item in ("source_proof", "domain_binding_source_proof", "non_privileged_vote_path")
        ):
            blockers.append("matching_source_proof_missing")
        if matches and not proof_linkage["proof_linked_impact"]:
            blockers.extend(f"source_proof_{reason}" for reason in proof_linkage["non_proof_reasons"])
        blockers = sorted(set(blockers))
        row_proof_linked = bool(exact and proven and proof_linkage["proof_linked_impact"] and not blockers)
        row_non_proof_reasons: list[str] = []
        if not row_proof_linked:
            if not exact:
                row_non_proof_reasons.append("impact_contract_not_exact")
            if not proven:
                row_non_proof_reasons.append("listed_impact_not_proven")
            if not matches:
                row_non_proof_reasons.append("missing_source_proof_record")
            if blockers:
                row_non_proof_reasons.append("blocker_present")
            if contract_advisory_marker:
                row_non_proof_reasons.append("advisory_only")
            proof_reason_key = "non_proof_reasons"
            if proof_linkage["proof_linked_impact"]:
                proof_reason_key = "all_non_proof_reasons"
            row_non_proof_reasons.extend(proof_linkage[proof_reason_key])
        row_non_proof_reasons = sorted(set(row_non_proof_reasons))
        status = "attached_exact_contract_unproved"
        if not exact:
            status = "terminal_missing_exact_impact_contract"
        elif row_proof_linked:
            status = "attached_exact_contract_with_proof_linked_impact"
        elif proven and matches:
            status = "attached_exact_contract_with_non_proof_source_record"
        elif proven:
            status = "attached_exact_contract_without_source_proof"
        rows.append(
            {
                "bridge_id": f"SPIC-{len(rows) + 1:03d}",
                "row_type": "impact_contract_attachment",
                "candidate_id": candidate,
                "impact_contract_id": str(contract.get("impact_contract_id") or ""),
                "route_family": str(contract.get("route_family") or ""),
                "tier": str(contract.get("tier") or contract.get("severity") or ""),
                "exact_impact_row": exact,
                "listed_impact_proven": proven,
                "source_proof_paths": [str(proof["path"]) for proof in matches],
                "source_proof_verdicts": [str(proof["final_verdict"]) for proof in matches],
                "source_proof_evaluations": proof_evaluations,
                "proof_linkage": "proof_linked_impact" if row_proof_linked else "non_proof",
                "proof_linked_impact": row_proof_linked,
                "non_proof_reasons": row_non_proof_reasons,
                "concrete_impact_artifact_paths": proof_linkage["concrete_impact_artifact_paths"],
                "status": status,
                "evidence_class": GENERATED_EVIDENCE_CLASS,
                "terminal_blockers": blockers,
                "selected_impact": str(contract.get("selected_impact") or contract.get("original_selected_impact") or ""),
                "severity": "none",
                "submission_posture": "NOT_SUBMIT_READY",
                "promotion_allowed": False,
                "proof_boundary": PROOF_BOUNDARY,
            }
        )

    # Terminal records with local source evidence but no locally derivable exact
    # impact row stay visible instead of being lost behind the 384-row contract
    # ledger.
    for proof in source_records:
        if str(proof["path"]) in used_proofs:
            continue
        proof_evaluation = proof["strict_impact_evaluation"]
        rows.append(
            {
                "bridge_id": f"SPIC-{len(rows) + 1:03d}",
                "row_type": "source_proof_terminal_blocker",
                "candidate_id": str(proof["candidate_id"]),
                "impact_contract_id": "",
                "exact_impact_row": False,
                "listed_impact_proven": False,
                "source_proof_paths": [str(proof["path"])],
                "source_proof_verdicts": [str(proof["final_verdict"])],
                "source_proof_evaluations": [proof_evaluation],
                "proof_linkage": "non_proof",
                "proof_linked_impact": False,
                "non_proof_reasons": sorted(
                    set(["missing_exact_impact_contract", *list(proof_evaluation.get("non_proof_reasons") or [])])
                ),
                "concrete_impact_artifact_paths": proof_evaluation.get("concrete_impact_artifact_paths") or [],
                "status": "terminal_missing_exact_impact_contract",
                "evidence_class": GENERATED_EVIDENCE_CLASS,
                "terminal_blockers": [
                    "missing_exact_impact_contract",
                    *[
                        f"source_proof_{reason}"
                        for reason in proof_evaluation.get("non_proof_reasons") or []
                    ],
                    "source_proof_cannot_promote_without_oos_clearance"
                    if proof.get("oos_status") not in {"in_scope", "oos"}
                    else "source_proof_terminal_oos_status_recorded",
                ],
                "selected_impact": "",
                "severity": "none",
                "submission_posture": "NOT_SUBMIT_READY",
                "promotion_allowed": False,
                "proof_boundary": PROOF_BOUNDARY,
            }
        )

    for ref in source_refs:
        candidate = str(ref.get("candidate_id") or "")
        if not candidate:
            continue
        if norm_candidate(candidate) in proofs_by_candidate:
            continue
        rows.append(
            {
                "bridge_id": f"SPIC-{len(rows) + 1:03d}",
                "row_type": "source_proof_queue_blocker",
                "candidate_id": candidate,
                "impact_contract_id": "",
                "exact_impact_row": False,
                "listed_impact_proven": False,
                "source_proof_paths": [],
                "source_task_artifact": str(ref.get("_source_artifact") or ""),
                "source_proof_evaluations": [],
                "proof_linkage": "non_proof",
                "proof_linked_impact": False,
                "non_proof_reasons": ["missing_source_proof_record", "missing_exact_impact_contract"],
                "concrete_impact_artifact_paths": [],
                "status": "queued_missing_source_proof_or_impact_contract",
                "evidence_class": GENERATED_EVIDENCE_CLASS,
                "terminal_blockers": ["missing_source_proof_record", "missing_exact_impact_contract"],
                "selected_impact": "",
                "severity": "none",
                "submission_posture": "NOT_SUBMIT_READY",
                "promotion_allowed": False,
                "proof_boundary": PROOF_BOUNDARY,
            }
        )

    if not (min_items <= len(rows) <= max_items):
        status = "hard_blocker_item_target_out_of_range"
    else:
        status = "ok_terminal_blockers_recorded"

    status_counts = Counter(str(row.get("status") or "") for row in rows)
    row_type_counts = Counter(str(row.get("row_type") or "") for row in rows)
    blocker_counts = Counter(
        blocker
        for row in rows
        for blocker in row.get("terminal_blockers") or []
    )
    non_proof_reason_counts = Counter(
        reason
        for row in rows
        for reason in row.get("non_proof_reasons") or []
    )
    dp_rows = [
        row
        for row in rows
        if str(row.get("candidate_id") or "").startswith("DP-CS-LVQ-")
    ]
    payload = {
        "schema": SCHEMA,
        "generated_at": now_iso(),
        "workspace": str(workspace),
        "status": status,
        "target_range": f"{min_items}-{max_items}",
        "proof_boundary": PROOF_BOUNDARY,
        "evidence_class": GENERATED_EVIDENCE_CLASS,
        "promotion_allowed": False,
        "submission_posture": "NOT_SUBMIT_READY",
        "severity": "none",
        "selected_impact": "",
        "source_artifacts": {
            "impact_contracts": str(impact_path) if impact_payload else "",
            "source_proof_tasks": source_ref_artifacts,
            "scanner_autonomy": [
                path
                for path in (scanner_summary["plan_path"], scanner_summary["execution_path"])
                if path
            ],
        },
        "summary": {
            "row_count": len(rows),
            "impact_contract_count": len(contracts),
            "source_proof_count": len(source_records),
            "source_task_ref_count": len(source_refs),
            "dp_terminal_source_proof_count": len(dp_rows),
            "status_counts": dict(sorted(status_counts.items())),
            "row_type_counts": dict(sorted(row_type_counts.items())),
            "terminal_blocker_counts": dict(sorted(blocker_counts.items())),
            "non_proof_reason_counts": dict(sorted(non_proof_reason_counts.items())),
            "proof_linked_impact_count": sum(1 for row in rows if row.get("proof_linked_impact") is True),
            "scanner_autonomy": scanner_summary,
        },
        "rows": rows,
    }
    return payload


def render_md(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    lines = [
        "# Source Proof Impact Bridge",
        "",
        f"- Status: `{payload['status']}`",
        f"- Rows: {summary['row_count']} (target {payload['target_range']})",
        f"- Impact contracts consumed: {summary['impact_contract_count']}",
        f"- Source proofs consumed: {summary['source_proof_count']}",
        f"- DP terminal source-proof blockers: {summary['dp_terminal_source_proof_count']}",
        f"- Promotion allowed: `{str(payload['promotion_allowed']).lower()}`",
        f"- Submission posture: `{payload['submission_posture']}`",
        "",
        "## Status Counts",
        "",
    ]
    for key, value in summary["status_counts"].items():
        lines.append(f"- `{key}`: {value}")
    lines.extend(["", "## Terminal Blockers", ""])
    for key, value in summary["terminal_blocker_counts"].items():
        lines.append(f"- `{key}`: {value}")
    lines.extend(["", "## Scanner Autonomy", ""])
    scanner = summary["scanner_autonomy"]
    lines.append(f"- Plan task count: {scanner['plan_task_count']}")
    lines.append(f"- Execution row count: {scanner['execution_row_count']}")
    lines.append(f"- Coverage claim: `{scanner['coverage_claim']}`")
    lines.extend(["", "## DP Blockers", ""])
    dp_rows = [row for row in payload["rows"] if str(row.get("candidate_id") or "").startswith("DP-CS-LVQ-")]
    if not dp_rows:
        lines.append("- none")
    for row in dp_rows:
        blockers = ", ".join(f"`{item}`" for item in row.get("terminal_blockers") or [])
        lines.append(f"- `{row['candidate_id']}`: `{row['status']}` ({blockers})")
    lines.extend(["", "## Proof Boundary", "", PROOF_BOUNDARY])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-md", type=Path)
    parser.add_argument("--min-items", type=int, default=DEFAULT_MIN_ITEMS)
    parser.add_argument("--max-items", type=int, default=DEFAULT_MAX_ITEMS)
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args(argv)

    workspace = args.workspace.expanduser().resolve()
    if not workspace.is_dir():
        raise SystemExit(f"[source-proof-impact-bridge] ERR workspace not found: {workspace}")
    payload = build_bridge(workspace, min_items=args.min_items, max_items=args.max_items)
    out_json = args.out_json.expanduser().resolve() if args.out_json else workspace / DEFAULT_OUT
    out_md = args.out_md.expanduser().resolve() if args.out_md else workspace / DEFAULT_OUT_MD
    write_json(out_json, payload)
    write_text(out_md, render_md(payload))
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    print(
        f"[source-proof-impact-bridge] {payload['status']} rows={payload['summary']['row_count']} "
        f"json={out_json}"
    )
    return 2 if payload["status"] == "hard_blocker_item_target_out_of_range" else 0


if __name__ == "__main__":
    raise SystemExit(main())
