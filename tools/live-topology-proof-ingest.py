#!/usr/bin/env python3
"""Bridge offline live-topology requirements into canonical ingest artifacts.

This tool does not fabricate live proof. It turns
``.auditooor/live_topology_proof_requirements.json`` into two safe artifacts:

* a generated live-check spec whose rows preserve proof-pair metadata, ready for
  ``live-check-runner.py`` when addresses/RPC are available;
* an optional canonical ``live_topology_checks.json`` skeleton with
  ``required_not_collected`` rows, so validators can emit precise pair blockers
  instead of a coarse missing-file blocker.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.live_topology_proof_ingest.v1"
DEFAULT_LIMIT = 400
SOURCE_REF_KEYS = (
    "source_refs",
    "source_ref",
    "file_line",
    "file_lines",
    "target_file",
    "source_file",
    "source_path",
    "configured_source_refs",
)
TOPOLOGY_PATH_KEYS = (
    "topology_path",
    "topology_paths",
    "configured_topology_path",
    "configured_topology_paths",
    "deployment_topology_path",
    "deployment_topology_paths",
    "configuration_source_ref",
    "topology_source_ref",
)
TOPOLOGY_EVIDENCE_KEYS = (
    "configured_topology_evidence",
    "topology_evidence",
    "deployment_topology",
    "configuration_precondition",
    "configuration_evidence",
)
PROOF_EVIDENCE_KEYS = (
    "proof_evidence",
    "harness_evidence",
    "execution_contract",
    "execution_manifest",
    "pass_evidence_lines",
    "test_transcript",
    "proof_transcript",
)
PROOF_PATH_KEYS = (
    "proof_file",
    "proof_artifact_path",
    "poc_path",
    "test_path",
    "generated_test_path",
    "harness_path",
    "execution_manifest_path",
)
BLOCKER_FIELDS = (
    "promotion_blockers",
    "blockers",
    "blocked_by",
    "blocked_reason",
    "blocker_reason",
    "kill_reason",
    "fp_reason",
)
PROOF_ROW_FIELDS = (
    "ingested_proof_rows",
    "proof_rows",
    "executed_proof_rows",
    "live_topology_results",
)
MISSING_TEXT = {"", "n/a", "na", "none", "null", "unknown", "todo", "tbd", "advisory", "advisory_only"}
SOURCE_REF_RE = re.compile(
    r"(?P<path>(?:~|/|\.{1,2}/|[A-Za-z0-9_.-])"
    r"[A-Za-z0-9_./@%+,\-]*\."
    r"(?:json|yaml|toml|tsx|jsx|sol|vy|go|rs|move|cairo|ts|js|py|md|yml)(?![A-Za-z0-9_]))"
    r"(?:(?::|#L)(?P<line>\d+))?"
)
CONCRETE_PROOF_RE = re.compile(
    r"(--- PASS:|Suite result:\s*ok|\bok\b|forge test|go test|cargo test|pytest|unittest|"
    r"PASS\b|assert(?:Eq|Equal|True|False)?\(|before/after|harness|poc)",
    re.I | re.M,
)
BLOCKER_MARKER_RE = re.compile(
    r"\b(NOT_SUBMIT_READY|EXECUTION_BLOCKED|blocked|blocker|advisory[-_ ]?only|"
    r"operator[-_ ]?required|no[-_ ]?safe[-_ ]?writeback)\b",
    re.I,
)
ADVISORY_POSTURE = {
    "coverage_claim": "live_topology_ingest_bridge_no_live_execution",
    "advisory_only": True,
    "promotion_allowed": False,
    "severity": "none",
    "selected_impact": "",
    "submission_posture": "NOT_SUBMIT_READY",
    "impact_contract_required": True,
}


def _load_json(path: Path, label: str) -> dict[str, Any]:
    if not path.is_file():
        raise SystemExit(f"[live-topology-proof-ingest] missing {label}: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"[live-topology-proof-ingest] unreadable {label}: {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit(f"[live-topology-proof-ingest] expected object JSON for {label}: {path}")
    return payload


def _status_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        status = str(row.get("status") or "unknown")
        counts[status] = counts.get(status, 0) + 1
    return counts


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    text = str(value or "").strip().lower()
    return text in {"1", "true", "yes", "y", "blocked", "advisory", "not_submit_ready"}


def _is_placeholder(value: Any) -> bool:
    text = str(value or "").strip()
    return not text or text.lower() in MISSING_TEXT or text.startswith("<") or text.endswith(">")


def _text_values(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, (int, float)):
        return [str(value)]
    if isinstance(value, bool) or value is None:
        return []
    if isinstance(value, list):
        values: list[str] = []
        for item in value:
            values.extend(_text_values(item))
        return values
    if isinstance(value, dict):
        values: list[str] = []
        for item in value.values():
            values.extend(_text_values(item))
        return values
    return [str(value).strip()] if str(value).strip() else []


def _collect_values(payload: dict[str, Any], keys: tuple[str, ...]) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    for key in keys:
        for value in _text_values(payload.get(key)):
            if value and value not in seen:
                values.append(value)
                seen.add(value)
    return values


def _clean_ref(value: str) -> str:
    text = value.strip().strip("`'\"()[]{}<>,.;")
    if text.startswith("workspace:"):
        text = text[len("workspace:") :]
    return text.strip()


def _line_exists(path: Path, line_no: int) -> bool:
    if line_no <= 0:
        return False
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            for index, _line in enumerate(handle, 1):
                if index >= line_no:
                    return True
    except OSError:
        return False
    return False


def _resolve_workspace_ref(workspace: Path, raw_ref: str) -> dict[str, Any]:
    text = _clean_ref(raw_ref)
    match = SOURCE_REF_RE.search(text)
    if not match:
        return {"ref": raw_ref, "current": False, "reason": "missing_current_workspace_source_ref"}
    raw_path = match.group("path")
    if raw_path.startswith(f"{workspace.name}/"):
        raw_path = raw_path[len(workspace.name) + 1 :]
    path = Path(raw_path).expanduser()
    line = int(match.group("line")) if match.group("line") else None
    try:
        resolved = path.resolve(strict=False) if path.is_absolute() else (workspace / path).resolve(strict=False)
        resolved.relative_to(workspace)
    except (OSError, ValueError):
        return {
            "ref": raw_ref,
            "current": False,
            "reason": "source_ref_outside_current_workspace",
            "path": raw_path,
            "line": line,
        }
    display = str(resolved.relative_to(workspace))
    if line is not None:
        display = f"{display}:{line}"
    if not resolved.is_file() or (line is not None and not _line_exists(resolved, line)):
        return {
            "ref": raw_ref,
            "current": False,
            "reason": "stale_workspace_source_ref",
            "path": display,
            "line": line,
        }
    return {
        "ref": raw_ref,
        "current": True,
        "reason": "current_workspace_source_ref",
        "path": display,
        "line": line,
    }


def _workspace_ref_status(workspace: Path, refs: list[str]) -> dict[str, Any]:
    resolved = [_resolve_workspace_ref(workspace, ref) for ref in refs]
    return {
        "raw_refs": refs,
        "current_refs": [item for item in resolved if item["current"]],
        "stale_refs": [item for item in resolved if not item["current"]],
        "resolved_refs": resolved,
    }


def _proof_path_exists(workspace: Path, value: str) -> bool:
    text = _clean_ref(value)
    match = SOURCE_REF_RE.search(text)
    path_text = match.group("path") if match else text
    path = Path(path_text).expanduser()
    if not path.is_absolute():
        path = workspace / path
    try:
        resolved = path.resolve(strict=False)
        resolved.relative_to(workspace)
    except (OSError, ValueError):
        return False
    return resolved.is_file()


def _value_has_concrete_proof(value: Any, workspace: Path) -> bool:
    if isinstance(value, dict):
        if _truthy(value.get("advisory_only")) or _truthy(value.get("advisory")):
            return False
        if _truthy(value.get("runnable")) and str(value.get("claim") or "").strip() != "blocked_harness":
            return True
        if _truthy(value.get("ran")) and any(
            _truthy(value.get(key)) for key in ("pass", "passed", "ok", "exploit_pass", "control_pass")
        ):
            return True
        status = str(value.get("status") or value.get("verdict") or "").strip().lower()
        if status in {"pass", "passed", "ok", "proved", "proof-backed", "proof_backed"}:
            return True
        return any(_value_has_concrete_proof(item, workspace) for item in value.values())
    if isinstance(value, list):
        return any(_value_has_concrete_proof(item, workspace) for item in value)
    if not isinstance(value, str):
        return False
    text = value.strip()
    if not text or text.lower() in MISSING_TEXT:
        return False
    if CONCRETE_PROOF_RE.search(text):
        return True
    return _proof_path_exists(workspace, text)


def _contains_advisory_marker(value: Any) -> bool:
    if isinstance(value, dict):
        if _truthy(value.get("advisory_only")) or _truthy(value.get("advisory")):
            return True
        return any(_contains_advisory_marker(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_advisory_marker(item) for item in value)
    return False


def _contains_blocker_marker(value: Any) -> bool:
    if isinstance(value, str):
        return bool(BLOCKER_MARKER_RE.search(value))
    if isinstance(value, (int, float, bool)) or value is None:
        return False
    if isinstance(value, list):
        return any(_contains_blocker_marker(item) for item in value)
    if isinstance(value, dict):
        return any(_contains_blocker_marker(item) for item in value.values())
    return bool(BLOCKER_MARKER_RE.search(str(value)))


def _has_concrete_proof_or_harness(row: dict[str, Any], workspace: Path) -> bool:
    for key in PROOF_EVIDENCE_KEYS:
        if _value_has_concrete_proof(row.get(key), workspace):
            return True
    for path_value in _collect_values(row, PROOF_PATH_KEYS):
        if _proof_path_exists(workspace, path_value):
            return True
    return False


def _blocker_reasons(row: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    for field in BLOCKER_FIELDS:
        values = _text_values(row.get(field))
        if any(BLOCKER_MARKER_RE.search(value) or value.strip() for value in values):
            reasons.append("blocker_marker_present")
            break
    for field in (*PROOF_EVIDENCE_KEYS, *TOPOLOGY_EVIDENCE_KEYS):
        if _contains_blocker_marker(row.get(field)):
            reasons.append("blocker_marker_present")
            break
    for field in ("advisory_only", "not_submit_ready"):
        if _truthy(row.get(field)):
            reasons.append("advisory_only_marker")
            break
    for field in (*PROOF_EVIDENCE_KEYS, *TOPOLOGY_EVIDENCE_KEYS):
        if _contains_advisory_marker(row.get(field)):
            reasons.append("advisory_only_marker")
            break
    for field in ("submission_posture", "promotion_review_status", "writeback_status"):
        values = _text_values(row.get(field))
        if any(BLOCKER_MARKER_RE.search(value) for value in values):
            reasons.append("blocker_marker_present")
            break
    return reasons


def _review_ingested_proof_row(workspace: Path, row: dict[str, Any]) -> dict[str, Any]:
    reasons: list[str] = []
    source_refs = _collect_values(row, SOURCE_REF_KEYS)
    source_status = _workspace_ref_status(workspace, source_refs)
    if not source_refs:
        reasons.append("missing_source_refs")
    elif source_status["stale_refs"]:
        reasons.append("stale_workspace_source_refs")

    topology_paths = _collect_values(row, TOPOLOGY_PATH_KEYS)
    topology_status = _workspace_ref_status(workspace, topology_paths)
    topology_evidence = [
        value
        for value in _collect_values(row, TOPOLOGY_EVIDENCE_KEYS)
        if not _is_placeholder(value)
    ]
    if topology_paths and topology_status["stale_refs"]:
        reasons.append("stale_topology_path")
    if not topology_evidence and not topology_status["current_refs"]:
        reasons.append("missing_configured_topology_evidence")

    if not _has_concrete_proof_or_harness(row, workspace):
        reasons.append("missing_concrete_proof_or_harness_evidence")
    reasons.extend(_blocker_reasons(row))

    unique_reasons = list(dict.fromkeys(reasons))
    reviewed = dict(row)
    accepted = not unique_reasons
    reviewed["ingest_status"] = "accepted" if accepted else "rejected"
    reviewed["ingest_rejection_reasons"] = unique_reasons
    reviewed["current_workspace_source_refs"] = source_status["current_refs"]
    reviewed["source_ref_blockers"] = source_status["stale_refs"]
    reviewed["configured_topology_refs"] = topology_status["current_refs"]
    reviewed["topology_path_blockers"] = topology_status["stale_refs"]
    reviewed["configured_topology_evidence"] = topology_evidence
    reviewed["concrete_proof_or_harness_evidence"] = _has_concrete_proof_or_harness(row, workspace)
    reviewed["ingested_by"] = SCHEMA
    if accepted:
        reviewed.setdefault("generated", False)
        reviewed.setdefault("spec_source", "live-topology-proof-ingest")
    return reviewed


def _proof_rows_from_requirements(payload: dict[str, Any], *, limit: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for field in PROOF_ROW_FIELDS:
        for row in payload.get(field) or []:
            if isinstance(row, dict):
                candidate = dict(row)
                candidate.setdefault("ingest_source_field", field)
                rows.append(candidate)
    for req in payload.get("requirements") or []:
        if not isinstance(req, dict):
            continue
        for field in PROOF_ROW_FIELDS:
            for row in req.get(field) or []:
                if isinstance(row, dict):
                    candidate = dict(row)
                    candidate.setdefault("ingest_source_field", f"requirements.{field}")
                    rows.append(candidate)
    return rows[: max(0, limit)]


def _merge_results(
    skeleton_results: list[dict[str, Any]],
    accepted_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    merged = [dict(row) for row in skeleton_results]
    by_id = {str(row.get("id") or "").strip(): index for index, row in enumerate(merged)}
    for row in accepted_rows:
        row_id = str(row.get("id") or "").strip()
        canonical = dict(row)
        canonical.setdefault("evidence_class", "topology-relation")
        canonical.setdefault("status", "pass")
        canonical.setdefault("generated", False)
        canonical.setdefault("spec_source", "live-topology-proof-ingest")
        if row_id and row_id in by_id:
            merged[by_id[row_id]] = canonical
        else:
            if row_id:
                by_id[row_id] = len(merged)
            merged.append(canonical)
    return merged


def _related_angle_ids(req: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for field in ("related_angle_ids", "angle_ids"):
        for item in req.get(field) or []:
            text = str(item).strip()
            if text and text not in values:
                values.append(text)
    source_item = str(req.get("source_item_id") or "").strip()
    if source_item and source_item not in values:
        values.append(source_item)
    return values


def _check_for(req: dict[str, Any], live_row: dict[str, Any]) -> dict[str, Any]:
    row_id = str(live_row.get("id") or "").strip()
    pair_id = str(live_row.get("proof_pair_id") or req.get("required_proof_pair_id") or "").strip()
    contract = str(live_row.get("contract") or "").strip() or "UNKNOWN"
    role = str(live_row.get("requirement_role") or "topology-relation").strip()
    return {
        "id": row_id,
        "title": f"{req.get('requirement_id', '')} {role}".strip(),
        "contract": contract,
        "network": str(req.get("network") or "mainnet"),
        "enabled": True,
        "generated": True,
        "call": str(req.get("required_call") or "owner()"),
        "args": [],
        "expect": str(req.get("required_expect") or "<fill-from-deployment-topology>"),
        "block": str(req.get("required_block") or ""),
        "evidence_class": "topology-relation",
        "related_angle_ids": _related_angle_ids(req),
        "proof_pair_id": pair_id,
        "pair_id": pair_id,
        "requirement_id": str(req.get("requirement_id") or ""),
        "requirement_role": role,
        "source_item_id": str(req.get("source_item_id") or ""),
        "same_block": True,
        "spec_source": "live-topology-proof-ingest",
        "rationale": (
            "Generated from offline live-topology proof requirements. Execute with "
            "real address/RPC/block data before treating this as evidence."
        ),
        "implication_if_match": "Satisfies semantic/live topology depth accounting only; not exploit impact proof.",
    }


def _skeleton_row(req: dict[str, Any], live_row: dict[str, Any]) -> dict[str, Any]:
    pair_id = str(live_row.get("proof_pair_id") or req.get("required_proof_pair_id") or "").strip()
    return {
        "id": str(live_row.get("id") or "").strip(),
        "title": f"{req.get('requirement_id', '')} {live_row.get('requirement_role', '')}".strip(),
        "contract": str(live_row.get("contract") or "UNKNOWN"),
        "network": str(req.get("network") or "mainnet"),
        "block": None,
        "block_source": "not-collected",
        "address": None,
        "address_source": "not-collected",
        "rpc_source": None,
        "execution_mode": "not_collected",
        "status": "required_not_collected",
        "check": {
            "call": str(req.get("required_call") or "owner()"),
            "args": [],
            "expect": "<fill-from-deployment-topology>",
            "expect_source": "not-collected",
            "block": None,
            "block_source": "not-collected",
            "expression": str(req.get("required_call") or "owner()"),
        },
        "rationale": "Requirement skeleton only; no live execution has occurred.",
        "evidence_class": "topology-relation",
        "related_angle_ids": _related_angle_ids(req),
        "implication_if_match": "Depth-accounting topology relation only.",
        "spec_source": "live-topology-proof-ingest",
        "generated": True,
        "proof_pair_id": pair_id,
        "pair_id": pair_id,
        "requirement_id": str(req.get("requirement_id") or ""),
        "requirement_role": str(live_row.get("requirement_role") or ""),
        "source_item_id": str(req.get("source_item_id") or ""),
        **ADVISORY_POSTURE,
    }


def _pair_for(
    req: dict[str, Any],
    row_ids: list[str],
    accepted_by_id: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    pair_id = str(req.get("required_proof_pair_id") or "").strip()
    accepted_by_id = accepted_by_id or {}
    accepted_rows = [accepted_by_id[row_id] for row_id in row_ids if row_id in accepted_by_id]
    row_statuses = {row_id: "required_not_collected" for row_id in row_ids}
    for row in accepted_rows:
        row_id = str(row.get("id") or "").strip()
        if row_id:
            row_statuses[row_id] = str(row.get("status") or "pass").strip() or "pass"
    blocks = sorted(
        {
            str(row.get("block") or "").strip()
            for row in accepted_rows
            if str(row.get("block") or "").strip()
        }
    )
    passed = [
        row for row in accepted_rows
        if str(row.get("status") or "pass").strip().lower() in {"pass", "passed", "ok", "proved"}
    ]
    failed = [
        row for row in accepted_rows
        if str(row.get("status") or "").strip().lower() in {"fail", "failed", "error"}
    ]
    if len(accepted_rows) < 2:
        status = "required_not_collected"
    elif failed:
        status = "failed"
    elif len(passed) < 2:
        status = "partial"
    elif len(blocks) != 1:
        status = "conflicting"
    else:
        status = "proved"
    return {
        "id": pair_id,
        "angle_id": ", ".join(_related_angle_ids(req)) or None,
        "kind": "topology-same-block",
        "required_for_angle_ids": _related_angle_ids(req),
        "row_ids": row_ids,
        "status": status,
        "same_block_required": True,
        "shared_block": blocks[0] if len(blocks) == 1 else None,
        "pair_blocks": blocks,
        "row_statuses": row_statuses,
        "block_mismatch": len(blocks) > 1,
        "missing_rows": [row_id for row_id in row_ids if row_id not in accepted_by_id],
        "executed_row_ids": [
            str(row.get("id") or "").strip()
            for row in accepted_rows
            if str(row.get("id") or "").strip()
        ],
        "passed_row_ids": [
            str(row.get("id") or "").strip()
            for row in passed
            if str(row.get("id") or "").strip()
        ],
        "failed_row_ids": [
            str(row.get("id") or "").strip()
            for row in failed
            if str(row.get("id") or "").strip()
        ],
        "notes": (
            "Generated requirement skeleton only; execute/import real same-block rows before closure."
            if status == "required_not_collected"
            else "Accepted ingested proof rows passed strict source, topology, and proof evidence review."
        ),
        "provenance": {"kind": "live-topology-proof-ingest"},
    }


def _summarize_pairs(pairs: list[dict[str, Any]]) -> dict[str, int]:
    counts = {
        "declared": len(pairs),
        "proved": 0,
        "partial": 0,
        "missing": 0,
        "conflicting": 0,
        "failed": 0,
        "required_not_collected": 0,
    }
    for pair in pairs:
        status = str(pair.get("status") or "")
        if status in counts:
            counts[status] += 1
    return counts


def build_ingest(workspace: Path, requirements_payload: dict[str, Any], *, limit: int) -> dict[str, Any]:
    requirements = [
        row for row in requirements_payload.get("requirements") or [] if isinstance(row, dict)
    ][: max(0, limit)]
    reviewed_proof_rows = [
        _review_ingested_proof_row(workspace, row)
        for row in _proof_rows_from_requirements(requirements_payload, limit=limit)
    ]
    accepted_proof_rows = [
        row for row in reviewed_proof_rows if row.get("ingest_status") == "accepted"
    ]
    rejected_proof_rows = [
        row for row in reviewed_proof_rows if row.get("ingest_status") == "rejected"
    ]
    accepted_by_id = {
        str(row.get("id") or "").strip(): row
        for row in accepted_proof_rows
        if str(row.get("id") or "").strip()
    }
    checks: list[dict[str, Any]] = []
    skeleton_results: list[dict[str, Any]] = []
    pairs: list[dict[str, Any]] = []
    for req in requirements:
        live_rows = [row for row in req.get("required_live_rows") or [] if isinstance(row, dict)]
        row_ids: list[str] = []
        for live_row in live_rows:
            row_id = str(live_row.get("id") or "").strip()
            if not row_id:
                continue
            row_ids.append(row_id)
            checks.append(_check_for(req, live_row))
            skeleton_results.append(_skeleton_row(req, live_row))
        pairs.append(_pair_for(req, row_ids, accepted_by_id))
    live_results = _merge_results(skeleton_results, accepted_proof_rows)
    rejection_reason_counts: dict[str, int] = {}
    for row in rejected_proof_rows:
        for reason in row.get("ingest_rejection_reasons") or []:
            rejection_reason_counts[str(reason)] = rejection_reason_counts.get(str(reason), 0) + 1
    spec = {
        "schema": "auditooor.live_check_spec.v1",
        "generated_by": SCHEMA,
        "workspace": str(workspace),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "checks": checks,
        **ADVISORY_POSTURE,
    }
    live_topology = {
        "schema": "auditooor.live_topology_checks.v1",
        "workspace": str(workspace),
        "spec": str(workspace / "monitoring" / "live_topology_proof_requirements.generated.json"),
        "generated_by": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": _status_counts(live_results),
        "proof_pairs": pairs,
        "proof_pair_summary": _summarize_pairs(pairs),
        "proof_contradictions": [],
        "results": live_results,
        "ingested_proof_rows": reviewed_proof_rows,
        "accepted_ingested_proof_rows": accepted_proof_rows,
        "rejected_ingested_proof_rows": rejected_proof_rows,
        "ingested_proof_rejection_reason_counts": dict(sorted(rejection_reason_counts.items())),
        **ADVISORY_POSTURE,
    }
    return {
        "schema": SCHEMA,
        "workspace": str(workspace),
        "source_requirements_artifact": str(workspace / ".auditooor" / "live_topology_proof_requirements.json"),
        "requirement_count": len(requirements),
        "generated_check_count": len(checks),
        "generated_skeleton_row_count": len(skeleton_results),
        "generated_pair_count": len(pairs),
        "ingested_proof_row_count": len(reviewed_proof_rows),
        "accepted_ingested_proof_row_count": len(accepted_proof_rows),
        "rejected_ingested_proof_row_count": len(rejected_proof_rows),
        "ingested_proof_rows": reviewed_proof_rows,
        "accepted_ingested_proof_rows": accepted_proof_rows,
        "rejected_ingested_proof_rows": rejected_proof_rows,
        "ingested_proof_rejection_reason_counts": dict(sorted(rejection_reason_counts.items())),
        "status_counts": _status_counts(live_results),
        "spec": spec,
        "live_topology_skeleton": live_topology,
        "next_actions": [
            "Run live-check-runner with the generated spec when real addresses/RPC/block data are available.",
            "Only accepted ingested proof rows with current source refs, topology evidence, and proof evidence are merged.",
            "Use the skeleton only to get exact not-collected blockers; it is not live proof.",
            "Re-run live-topology-proof-executor after importing executed same-block rows.",
        ],
        **ADVISORY_POSTURE,
    }


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Live Topology Proof Ingest",
        "",
        "Bridge artifact for converting offline same-block topology requirements into canonical ingest surfaces.",
        "This artifact does not contain live execution proof.",
        "",
        f"- schema: `{payload['schema']}`",
        f"- requirements processed: {payload['requirement_count']}",
        f"- generated checks: {payload['generated_check_count']}",
        f"- skeleton rows: {payload['generated_skeleton_row_count']}",
        f"- proof pairs: {payload['generated_pair_count']}",
        f"- submission posture: `{payload['submission_posture']}`",
        "",
        "## Status Counts",
        "",
    ]
    for status, count in sorted((payload.get("status_counts") or {}).items()):
        lines.append(f"- `{status}`: {count}")
    lines.extend([
        "",
        "## Next Actions",
        "",
    ])
    for action in payload.get("next_actions") or []:
        lines.append(f"- {action}")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--requirements", type=Path)
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    parser.add_argument("--write-canonical-skeleton", action="store_true")
    parser.add_argument("--force", action="store_true", help="Overwrite an existing live_topology_checks.json skeleton")
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-md", type=Path)
    parser.add_argument("--out-spec", type=Path)
    parser.add_argument("--out-skeleton", type=Path)
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args()

    workspace = args.workspace.expanduser().resolve()
    if not workspace.is_dir():
        print(f"[live-topology-proof-ingest] workspace not found: {workspace}", file=sys.stderr)
        return 2
    audit_dir = workspace / ".auditooor"
    requirements_path = (args.requirements or audit_dir / "live_topology_proof_requirements.json").expanduser().resolve()
    requirements = _load_json(requirements_path, "live topology proof requirements")
    payload = build_ingest(workspace, requirements, limit=max(0, args.limit))

    out_json = args.out_json or audit_dir / "live_topology_proof_ingest.json"
    out_md = args.out_md or audit_dir / "live_topology_proof_ingest.md"
    out_spec = args.out_spec or workspace / "monitoring" / "live_topology_proof_requirements.generated.json"
    out_skeleton = args.out_skeleton or workspace / "live_topology_checks.json"

    for path in (out_json, out_md, out_spec):
        path.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps({k: v for k, v in payload.items() if k not in {"spec", "live_topology_skeleton"}}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(payload), encoding="utf-8")
    out_spec.write_text(json.dumps(payload["spec"], indent=2, sort_keys=True) + "\n", encoding="utf-8")

    wrote_skeleton = False
    if args.write_canonical_skeleton:
        if out_skeleton.exists() and not args.force:
            print(
                f"[live-topology-proof-ingest] refusing to overwrite existing live topology: {out_skeleton}",
                file=sys.stderr,
            )
            return 3
        out_skeleton.parent.mkdir(parents=True, exist_ok=True)
        out_skeleton.write_text(json.dumps(payload["live_topology_skeleton"], indent=2, sort_keys=True) + "\n", encoding="utf-8")
        wrote_skeleton = True

    if args.print_json:
        print(json.dumps({k: v for k, v in payload.items() if k not in {"spec", "live_topology_skeleton"}}, indent=2, sort_keys=True))
    print(
        "[live-topology-proof-ingest] OK "
        f"requirements={payload['requirement_count']} checks={payload['generated_check_count']} "
        f"spec={out_spec} skeleton_written={wrote_skeleton}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
