#!/usr/bin/env python3
"""Validate whether execution-manifest proof units are actually provable.

This reducer sits after ``impact-binding-next-input-validator.py``.  It focuses
only on rows that still require a proved exploit-impact execution manifest and
splits the remaining proof gap into exact, machine-readable blockers.
"""

from __future__ import annotations

import argparse
import json
import re
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
    command_status_counts,
    is_strict_proved_execution_manifest,
    strict_proof_blockers,
)


SCHEMA = "auditooor.pr560.execution_manifest_proof_readiness.v1"
DEFAULT_INPUT = ".auditooor/impact_binding_next_input_validator.json"
DEFAULT_PROJECT_SOURCE_READINESS = ".auditooor/project_source_root_readiness.json"
DEFAULT_SOURCE_IMPORT_READINESS = ".auditooor/impact_binding_source_import_readiness.json"
DEFAULT_OUT = ".auditooor/execution_manifest_proof_readiness.json"
DEFAULT_OUT_MD = ".auditooor/execution_manifest_proof_readiness.md"
DEFAULT_BUNDLE_DIR = ".auditooor/execution_manifest_proof_readiness_units"
WORKER_LEDGER_JSON = ".auditooor/pr560_worker_execution_manifest_proof_readiness.json"
WORKER_LEDGER_MD = ".auditooor/pr560_worker_execution_manifest_proof_readiness.md"
PROOF_BOUNDARY = (
    "Readiness rows do not prove exploit impact by themselves. A row is proof "
    "only when a matching poc_execution/**/execution_manifest.json records "
    "final_result=proved, impact_assertion=exploit_impact, "
    "evidence_class=executed_with_manifest, and at least one structured "
    "commands_attempted row with a non-empty command, status=pass, and exit_code=0. "
    "Proof-ready rows also require current-workspace source references and no "
    "blocker or advisory-only markers in the consumed proof artifacts."
)
SOURCE_REF_RE = re.compile(r"^(?P<file>.+?):L?(?P<line>[1-9][0-9]*)$")
BLOCKER_LIST_KEYS = {
    "blockers",
    "blocking_unknowns",
    "errors",
    "failures",
    "proof_blockers",
    "promotion_blockers",
    "terminal_blockers",
}
BLOCKER_BOOL_KEYS = {"blocked", "blocking"}
ADVISORY_BOOL_KEYS = {"advisory", "advisory_only"}
ADVISORY_STATUS_KEYS = {"claim", "status", "submission_posture", "verdict"}
ADVISORY_STATUS_VALUES = {"advisory", "advisory_only"}


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError as exc:
        raise SystemExit(f"[execution-proof-readiness] ERR invalid JSON in {path}: {exc}") from None


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.rstrip() + "\n", encoding="utf-8")


def is_truthy_marker(value: object) -> bool:
    if value is True:
        return True
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "on"}
    if isinstance(value, int) and not isinstance(value, bool):
        return value != 0
    return False


def has_items(value: object) -> bool:
    if isinstance(value, (list, tuple, set, dict)):
        return bool(value)
    if isinstance(value, str):
        return bool(value.strip())
    return value is not None


def compact_marker_value(value: object) -> object:
    if isinstance(value, list):
        return [str(item) for item in value[:5]]
    if isinstance(value, dict):
        return {str(key): value[key] for key in list(value)[:5]}
    return value


def blocker_advisory_markers(value: object, *, prefix: str = "") -> list[dict[str, Any]]:
    markers: list[dict[str, Any]] = []
    if isinstance(value, dict):
        for key, item in value.items():
            key_text = str(key)
            lowered = key_text.lower()
            path = f"{prefix}.{key_text}" if prefix else key_text
            if lowered in BLOCKER_LIST_KEYS and has_items(item):
                markers.append(
                    {
                        "kind": "blocker",
                        "path": path,
                        "value": compact_marker_value(item),
                    }
                )
                continue
            if lowered in BLOCKER_BOOL_KEYS and is_truthy_marker(item):
                markers.append({"kind": "blocker", "path": path, "value": item})
                continue
            if lowered in ADVISORY_BOOL_KEYS and is_truthy_marker(item):
                markers.append({"kind": "advisory_only", "path": path, "value": item})
                continue
            if lowered in ADVISORY_STATUS_KEYS and str(item).strip().lower() in ADVISORY_STATUS_VALUES:
                markers.append({"kind": "advisory_only", "path": path, "value": item})
                continue
            markers.extend(blocker_advisory_markers(item, prefix=path))
    elif isinstance(value, list):
        for idx, item in enumerate(value[:200]):
            path = f"{prefix}[{idx}]" if prefix else f"[{idx}]"
            markers.extend(blocker_advisory_markers(item, prefix=path))
    return markers


def parse_source_ref(value: object) -> dict[str, Any] | None:
    if isinstance(value, dict):
        file_text = value.get("file") or value.get("path") or value.get("source_file")
        line_value = value.get("line") or value.get("line_no") or value.get("line_number")
        try:
            line = int(line_value)
        except (TypeError, ValueError):
            line = 0
        if file_text and line > 0:
            return {"file": str(file_text), "line": line, "raw": value}
        return None
    if not isinstance(value, str):
        return None
    text = value.strip()
    match = SOURCE_REF_RE.match(text)
    if not match:
        return None
    return {"file": match.group("file"), "line": int(match.group("line")), "raw": text}


def validate_source_ref(workspace: Path, ref: dict[str, Any]) -> dict[str, Any]:
    file_text = str(ref["file"])
    raw_path = Path(file_text).expanduser()
    workspace_resolved = workspace.resolve()
    path = raw_path if raw_path.is_absolute() else workspace_resolved / raw_path
    try:
        resolved = path.resolve()
        rel = resolved.relative_to(workspace_resolved).as_posix()
    except (OSError, ValueError):
        return {
            "raw": ref["raw"],
            "file": file_text,
            "line": ref["line"],
            "valid": False,
            "reason": "source_ref_outside_current_workspace",
        }
    try:
        with resolved.open("r", encoding="utf-8", errors="ignore") as handle:
            line_count = sum(1 for _ in handle)
    except OSError:
        return {
            "raw": ref["raw"],
            "file": rel,
            "line": ref["line"],
            "valid": False,
            "reason": "source_ref_file_missing",
        }
    if int(ref["line"]) > line_count:
        return {
            "raw": ref["raw"],
            "file": rel,
            "line": ref["line"],
            "valid": False,
            "reason": "source_ref_line_missing",
            "line_count": line_count,
        }
    return {"raw": ref["raw"], "file": rel, "line": ref["line"], "valid": True}


def current_workspace_source_ref_status(
    workspace: Path,
    source_harness: dict[str, Any],
    source_import: dict[str, Any],
) -> dict[str, Any]:
    source_harness_refs = [
        parsed
        for parsed in (
            parse_source_ref(value)
            for value in source_harness.get("candidate_bound_project_source_citations") or []
        )
        if parsed
    ]
    source_import_refs = [
        parsed
        for parsed in (parse_source_ref(value) for value in source_import.get("source_line_hits") or [])
        if parsed
    ]
    harness_import_refs = [
        parsed
        for parsed in (parse_source_ref(value) for value in source_import.get("harness_line_hits") or [])
        if parsed
    ]
    missing_inputs: list[str] = []
    if not source_harness_refs:
        missing_inputs.append("candidate_bound_project_source_citation")
    if not source_import_refs:
        missing_inputs.append("candidate_bound_source_line_hit")
    if not harness_import_refs:
        missing_inputs.append("project_harness_line_hit")

    all_refs = source_harness_refs + source_import_refs + harness_import_refs
    validation = [validate_source_ref(workspace, ref) for ref in all_refs]
    stale_refs = [item for item in validation if not item["valid"]]
    if missing_inputs:
        status = "missing_source_refs"
    elif stale_refs:
        status = "stale_source_refs"
    else:
        status = "current_workspace_source_refs_ready"
    return {
        "status": status,
        "source_harness_ref_count": len(source_harness_refs),
        "source_import_ref_count": len(source_import_refs),
        "harness_import_ref_count": len(harness_import_refs),
        "valid_ref_count": sum(1 for item in validation if item["valid"]),
        "stale_ref_count": len(stale_refs),
        "stale_refs": stale_refs[:10],
        "missing_inputs": missing_inputs,
    }


def non_ready_reason(code: str, detail: dict[str, Any]) -> dict[str, Any]:
    return {"code": code, "detail": detail}


def manifest_status(workspace: Path, candidate_id: str) -> dict[str, Any]:
    path = workspace / "poc_execution" / candidate_id / "execution_manifest.json"
    payload = load_json(path)
    if not payload:
        return {
            "status": "missing_execution_manifest",
            "path": str(path),
            "proved": False,
            "missing_inputs": ["execution_manifest_json"],
            "blocker_markers": [],
        }
    markers = blocker_advisory_markers(payload)
    bound_sources = bound_source_validation(payload, workspace)
    bound_source_errors = list(bound_sources.get("errors") or [])
    if is_strict_proved_execution_manifest(payload) and bound_sources.get("valid"):
        commands = payload.get("commands_attempted")
        counts = command_evidence_counts(payload)
        command_count = len(commands) if isinstance(commands, list) else 0
        return {
            "status": "proved_exploit_impact_manifest_present",
            "path": str(path),
            "proved": True,
            "final_result": payload.get("final_result"),
            "impact_assertion": payload.get("impact_assertion"),
            "evidence_class": payload.get("evidence_class"),
            "commands_attempted_count": command_count,
            "structured_command_count": counts["structured_command_count"],
            "unstructured_command_count": counts["unstructured_command_count"],
            "command_with_text_count": counts["command_with_text_count"],
            "passing_command_count": counts["passing_command_count"],
            "missing_exit_code_count": counts["missing_exit_code_count"],
            "bool_exit_code_count": counts["bool_exit_code_count"],
            "command_status_counts": command_status_counts(payload),
            "missing_inputs": [],
            "blocker_markers": markers,
            "bound_sources": bound_sources,
        }
    commands = payload.get("commands_attempted")
    counts = command_evidence_counts(payload)
    command_count = len(commands) if isinstance(commands, list) else 0
    return {
        "status": "terminal_execution_manifest_not_proved",
        "path": str(path),
        "proved": False,
        "final_result": payload.get("final_result"),
        "impact_assertion": payload.get("impact_assertion"),
        "evidence_class": payload.get("evidence_class"),
        "commands_attempted_count": command_count,
        "structured_command_count": counts["structured_command_count"],
        "unstructured_command_count": counts["unstructured_command_count"],
        "command_with_text_count": counts["command_with_text_count"],
        "passing_command_count": counts["passing_command_count"],
        "missing_exit_code_count": counts["missing_exit_code_count"],
        "bool_exit_code_count": counts["bool_exit_code_count"],
        "command_status_counts": command_status_counts(payload),
        "missing_inputs": strict_proof_blockers(payload) + bound_source_errors,
        "blocker_markers": markers,
        "bound_sources": bound_sources,
    }


def ready_project_source_roots(readiness: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        root
        for root in readiness.get("roots") or []
        if isinstance(root, dict) and root.get("usable")
    ]


def source_harness_status(workspace: Path, candidate_id: str) -> dict[str, Any]:
    discovery = load_json(workspace / ".auditooor" / "impact_binding_source_harness_discovery.json")
    rows = [
        row
        for row in discovery.get("reductions") or []
        if isinstance(row, dict) and row.get("candidate_id") == candidate_id
    ]
    statuses = sorted({str(row.get("discovery_status") or "") for row in rows if row.get("discovery_status")})
    source_citations = [
        row.get("candidate_bound_project_source_citation")
        or row.get("source_citation")
        or row.get("source_proof_record")
        for row in rows
        if row.get("candidate_bound_project_source_citation")
        or row.get("source_citation")
        or row.get("source_proof_record")
    ]
    harness_bindings = [
        row.get("project_harness_binding")
        or row.get("harness_binding")
        or row.get("project_harness_command")
        for row in rows
        if row.get("project_harness_binding")
        or row.get("harness_binding")
        or row.get("project_harness_command")
    ]
    if not rows:
        return {
            "status": "missing_source_harness_discovery_row",
            "statuses": [],
            "missing_inputs": ["source_harness_discovery_row"],
            "blocker_markers": [],
        }
    markers = blocker_advisory_markers(rows)
    if any(status in {"source_harness_binding_ready", "project_source_and_harness_ready"} for status in statuses):
        missing_ready_inputs: list[str] = []
        if not source_citations:
            missing_ready_inputs.append("candidate_bound_project_source_citation")
        if not harness_bindings:
            missing_ready_inputs.append("project_harness_binding")
        if missing_ready_inputs:
            return {
                "status": "source_harness_ready_status_missing_evidence",
                "statuses": statuses,
                "candidate_bound_project_source_citations": source_citations,
                "project_harness_bindings": harness_bindings,
                "missing_inputs": missing_ready_inputs,
                "blocker_markers": markers,
            }
        return {
            "status": "source_harness_binding_ready",
            "statuses": statuses,
            "candidate_bound_project_source_citations": source_citations,
            "project_harness_bindings": harness_bindings,
            "missing_inputs": [],
            "blocker_markers": markers,
        }
    if any(status in {"candidate_project_source_hints_require_manual_citation", "harness_binding_hints_require_project_setup"} for status in statuses):
        return {
            "status": "source_or_harness_hints_require_manual_binding",
            "statuses": statuses,
            "missing_inputs": ["candidate_bound_project_source_citation", "project_harness_binding"],
            "blocker_markers": markers,
        }
    if any(status.startswith("terminal_") for status in statuses):
        missing = ["candidate_bound_project_source_citation", "project_harness_binding"]
        if any("no_project_source_roots" in status for status in statuses):
            missing.append("project_source_root")
        return {
            "status": "terminal_source_or_harness_blocked",
            "statuses": statuses,
            "missing_inputs": sorted(set(missing)),
            "blocker_markers": markers,
        }
    return {
        "status": "source_harness_status_unknown",
        "statuses": statuses,
        "missing_inputs": ["manual_review"],
        "blocker_markers": markers,
    }


def source_import_status(workspace: Path, candidate_id: str) -> dict[str, Any]:
    payload = load_json(workspace / DEFAULT_SOURCE_IMPORT_READINESS)
    rows = [
        row
        for row in payload.get("units") or []
        if isinstance(row, dict) and row.get("candidate_id") == candidate_id
    ]
    if not rows:
        return {
            "status": "missing_source_import_readiness_row",
            "source_line_hit_count": 0,
            "harness_line_hit_count": 0,
            "missing_inputs": ["source_import_line_hit_unit"],
            "blocker_markers": [],
        }
    markers = blocker_advisory_markers(rows)

    source_hits = [
        row
        for row in rows
        if row.get("requirement") == "candidate_bound_project_source_citation"
        and int(row.get("line_hit_count") or 0) > 0
    ]
    harness_hits = [
        row
        for row in rows
        if row.get("requirement") == "project_specific_harness_execution"
        and int(row.get("line_hit_count") or 0) > 0
    ]
    missing: list[str] = []
    if not source_hits:
        missing.append("candidate_bound_source_line_hit")
    if not harness_hits:
        missing.append("project_harness_line_hit")
    if missing:
        return {
            "status": "source_import_line_hits_missing",
            "source_import_statuses": sorted({str(row.get("source_import_status") or "") for row in rows}),
            "source_line_hit_count": 0,
            "harness_line_hit_count": 0,
            "missing_inputs": missing,
            "blocker_markers": markers,
        }
    return {
        "status": "source_import_line_hits_ready",
        "source_import_statuses": sorted({str(row.get("source_import_status") or "") for row in rows}),
        "source_line_hit_count": sum(int(row.get("line_hit_count") or 0) for row in source_hits),
        "harness_line_hit_count": sum(int(row.get("line_hit_count") or 0) for row in harness_hits),
        "source_line_hits": [hit for row in source_hits for hit in row.get("line_hits") or []][:10],
        "harness_line_hits": [hit for row in harness_hits for hit in row.get("line_hits") or []][:10],
        "missing_inputs": [],
        "blocker_markers": markers,
    }


def classify_unit(workspace: Path, unit: dict[str, Any], source_roots: list[dict[str, Any]]) -> dict[str, Any]:
    candidate_id = str(unit.get("candidate_id") or "")
    manifest = manifest_status(workspace, candidate_id)
    source_harness = source_harness_status(workspace, candidate_id)
    source_import = source_import_status(workspace, candidate_id)
    source_refs = current_workspace_source_ref_status(workspace, source_harness, source_import)
    blocker_markers = (
        blocker_advisory_markers(unit)
        + manifest.get("blocker_markers", [])
        + source_harness.get("blocker_markers", [])
        + source_import.get("blocker_markers", [])
    )
    non_ready_reasons: list[dict[str, Any]] = []
    missing = set(manifest.get("missing_inputs") or [])
    missing.update(source_harness.get("missing_inputs") or [])
    missing.update(source_import.get("missing_inputs") or [])
    missing.update(source_refs.get("missing_inputs") or [])
    if not source_roots:
        missing.add("project_source_root")
    if manifest["status"] == "missing_execution_manifest":
        non_ready_reasons.append(
            non_ready_reason("missing_execution_evidence", {"status": manifest["status"], "missing_inputs": manifest["missing_inputs"]})
        )
    elif not manifest["proved"]:
        non_ready_reasons.append(
            non_ready_reason("missing_execution_evidence", {"status": manifest["status"], "missing_inputs": manifest["missing_inputs"]})
        )
    bound_source_errors = list(manifest.get("bound_sources", {}).get("errors") or [])
    if bound_source_errors:
        missing.update(bound_source_errors)
        non_ready_reasons.append(
            non_ready_reason("bound_source_validation", {"errors": bound_source_errors})
        )
    if source_refs["status"] == "missing_source_refs":
        missing.add("missing_source_refs")
        non_ready_reasons.append(
            non_ready_reason("missing_source_refs", {"missing_inputs": source_refs["missing_inputs"]})
        )
    elif source_refs["status"] == "stale_source_refs":
        missing.add("stale_source_refs")
        non_ready_reasons.append(
            non_ready_reason("stale_source_refs", {"stale_refs": source_refs["stale_refs"]})
        )
    if blocker_markers:
        missing.add("blocker_or_advisory_marker")
        non_ready_reasons.append(
            non_ready_reason("blocker_or_advisory_marker", {"markers": blocker_markers[:20]})
        )

    if manifest["proved"] and not missing:
        readiness_status = "execution_proof_ready"
    elif not source_roots:
        readiness_status = "terminal_no_project_source_root_for_execution_proof"
    elif source_harness["status"].startswith("terminal_"):
        readiness_status = "terminal_source_or_harness_blocked_for_execution_proof"
    elif source_refs["status"] == "stale_source_refs":
        readiness_status = "stale_current_workspace_source_refs"
    elif blocker_markers:
        readiness_status = "blocked_by_blocker_or_advisory_marker"
    elif manifest["status"] == "missing_execution_manifest":
        readiness_status = "missing_execution_manifest_after_binding"
    elif manifest["status"] == "terminal_execution_manifest_not_proved":
        readiness_status = "terminal_execution_manifest_not_proved"
    else:
        readiness_status = "blocked_project_binding_or_manual_review"

    next_commands = [
        unit.get("next_command") or (
            f"make poc-execution-record WS={workspace} CANDIDATE_ID={candidate_id} "
            "BRIEF=<brief.md> CMD='<project-specific harness command>' RESULT=proved IMPACT=exploit_impact"
        )
    ]
    if "project_source_root" in missing:
        next_commands.insert(
            0,
            f"make project-source-root-declaration WS={workspace} ENTRY='<label>=<target-project-source-root>'",
        )
    if "project_harness_binding" in missing or "candidate_bound_project_source_citation" in missing:
        next_commands.insert(
            0,
            f"make impact-binding-source-harness-discovery WS={workspace} JSON=1",
        )

    return {
        "candidate_id": candidate_id,
        "impact_contract_id": str(unit.get("impact_contract_id") or ""),
        "route_family": str(unit.get("route_family") or ""),
        "tier": str(unit.get("tier") or ""),
        "readiness_status": readiness_status,
        "manifest_status": manifest,
        "source_harness_status": source_harness,
        "source_import_status": source_import,
        "current_workspace_source_ref_status": source_refs,
        "blocker_advisory_markers": blocker_markers[:50],
        "non_ready_reasons": non_ready_reasons,
        "missing_inputs": sorted(missing),
        "ready_project_source_root_count": len(source_roots),
        "next_commands": next_commands,
        "proof_ready": readiness_status == "execution_proof_ready",
        "execution_proof_ready": readiness_status == "execution_proof_ready",
        "promotion_allowed": False,
        "submission_posture": "NOT_SUBMIT_READY",
        "proof_boundary": PROOF_BOUNDARY,
    }


def build_payload(
    workspace: Path,
    *,
    input_path: Path | None = None,
    project_source_readiness_path: Path | None = None,
    bundle_dir: Path | None = None,
) -> dict[str, Any]:
    source = load_json(input_path or workspace / DEFAULT_INPUT)
    readiness = load_json(project_source_readiness_path or workspace / DEFAULT_PROJECT_SOURCE_READINESS)
    source_roots = ready_project_source_roots(readiness if isinstance(readiness, dict) else {})
    units = [
        unit
        for unit in source.get("units") or []
        if isinstance(unit, dict) and unit.get("requirement") == "proved_exploit_impact_execution_manifest"
    ]
    rows = [classify_unit(workspace, unit, source_roots) for unit in units]
    by_family: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_family[row["route_family"]].append(row)
    proof_ready = [row for row in rows if row["proof_ready"]]
    payload = {
        "schema": SCHEMA,
        "generated_at_unix": int(time.time()),
        "workspace": str(workspace),
        "source_units_path": str(input_path or workspace / DEFAULT_INPUT),
        "project_source_readiness_path": str(project_source_readiness_path or workspace / DEFAULT_PROJECT_SOURCE_READINESS),
        "source_import_readiness_path": str(workspace / DEFAULT_SOURCE_IMPORT_READINESS),
        "proved_execution_requirement_count": len(rows),
        "proof_ready_count": len(proof_ready),
        "proved_manifest_ready_count": len(proof_ready),
        "closed_proof_count": len(proof_ready),
        "promotion_allowed": False,
        "submission_posture": "NOT_SUBMIT_READY",
        "proof_boundary": PROOF_BOUNDARY,
        "summary": {
            "readiness_status_counts": dict(sorted(Counter(row["readiness_status"] for row in rows).items())),
            "route_family_counts": dict(sorted(Counter(row["route_family"] for row in rows).items())),
            "missing_input_counts": dict(sorted(Counter(item for row in rows for item in row["missing_inputs"]).items())),
            "manifest_status_counts": dict(sorted(Counter(row["manifest_status"]["status"] for row in rows).items())),
            "source_harness_status_counts": dict(sorted(Counter(row["source_harness_status"]["status"] for row in rows).items())),
            "source_import_status_counts": dict(sorted(Counter(row["source_import_status"]["status"] for row in rows).items())),
        },
        "family_manifests": {
            family: {
                "row_count": len(items),
                "proof_ready_count": sum(1 for item in items if item["proof_ready"]),
                "readiness_status_counts": dict(sorted(Counter(item["readiness_status"] for item in items).items())),
                "missing_input_counts": dict(sorted(Counter(missing for item in items for missing in item["missing_inputs"]).items())),
            }
            for family, items in sorted(by_family.items())
        },
        "rows": rows,
    }
    if bundle_dir:
        bundle_dir.mkdir(parents=True, exist_ok=True)
        for family, items in sorted(by_family.items()):
            write_json(
                bundle_dir / f"{family}.json",
                {
                    "schema": "auditooor.pr560.execution_manifest_proof_readiness_family.v1",
                    "workspace": str(workspace),
                    "route_family": family,
                    "row_count": len(items),
                    "proof_ready_count": sum(1 for item in items if item["proof_ready"]),
                    "promotion_allowed": False,
                    "submission_posture": "NOT_SUBMIT_READY",
                    "proof_boundary": PROOF_BOUNDARY,
                    "rows": items,
                },
            )
    return payload


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Execution Manifest Proof Readiness",
        "",
        PROOF_BOUNDARY,
        "",
        "## Summary",
        "",
        f"- Proved-execution requirement rows: `{payload['proved_execution_requirement_count']}`",
        f"- Proof-ready rows: `{payload['proof_ready_count']}`",
        f"- Promotion allowed: `{payload['promotion_allowed']}`",
        "",
        "## Readiness Status Counts",
        "",
    ]
    for key, value in payload["summary"]["readiness_status_counts"].items():
        lines.append(f"- `{key}`: {value}")
    lines.extend(["", "## Missing Inputs", ""])
    for key, value in payload["summary"]["missing_input_counts"].items():
        lines.append(f"- `{key}`: {value}")
    lines.extend(["", "## First Rows", ""])
    for row in payload["rows"][:30]:
        lines.append(
            f"- `{row['candidate_id']}` / `{row['route_family']}`: "
            f"`{row['readiness_status']}`; missing={row['missing_inputs']}"
        )
    return "\n".join(lines)


def worker_ledger(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": "auditooor.pr560.worker.execution_manifest_proof_readiness.v1",
        "generated_at_unix": payload["generated_at_unix"],
        "workspace": payload["workspace"],
        "changed_tool": "tools/execution-manifest-proof-readiness.py",
        "artifact": DEFAULT_OUT,
        "exact_reduction": {
            "proved_execution_requirement_rows": payload["proved_execution_requirement_count"],
            "proof_ready_rows": payload["proof_ready_count"],
            "readiness_status_counts": payload["summary"]["readiness_status_counts"],
            "missing_input_counts": payload["summary"]["missing_input_counts"],
        },
        "closed_rows": [],
        "blockers_left": payload["summary"]["missing_input_counts"],
        "proof_boundary": PROOF_BOUNDARY,
    }


def render_worker_markdown(payload: dict[str, Any]) -> str:
    reduction = payload["exact_reduction"]
    lines = [
        "# PR560 Execution Manifest Proof Readiness Worker",
        "",
        PROOF_BOUNDARY,
        "",
        "## Exact Reduction",
        "",
        f"- Proved-execution requirement rows: `{reduction['proved_execution_requirement_rows']}`",
        f"- Proof-ready rows: `{reduction['proof_ready_rows']}`",
        "",
        "## Readiness Status Counts",
        "",
    ]
    for key, value in reduction["readiness_status_counts"].items():
        lines.append(f"- `{key}`: {value}")
    lines.extend(["", "## Blockers Left", ""])
    for key, value in reduction["missing_input_counts"].items():
        lines.append(f"- `{key}`: {value}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--input-json", type=Path)
    parser.add_argument("--project-source-readiness", type=Path)
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-md", type=Path)
    parser.add_argument("--bundle-dir", type=Path)
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args(argv)

    workspace = args.workspace.expanduser().resolve()
    payload = build_payload(
        workspace,
        input_path=(args.input_json.expanduser().resolve() if args.input_json else None),
        project_source_readiness_path=(
            args.project_source_readiness.expanduser().resolve() if args.project_source_readiness else None
        ),
        bundle_dir=(args.bundle_dir or workspace / DEFAULT_BUNDLE_DIR).expanduser().resolve(),
    )
    out_json = (args.out_json or workspace / DEFAULT_OUT).expanduser().resolve()
    out_md = (args.out_md or workspace / DEFAULT_OUT_MD).expanduser().resolve()
    write_json(out_json, payload)
    write_text(out_md, render_markdown(payload))
    ledger = worker_ledger(payload)
    write_json(workspace / WORKER_LEDGER_JSON, ledger)
    write_text(workspace / WORKER_LEDGER_MD, render_worker_markdown(ledger))
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    print(
        "[execution-proof-readiness] OK "
        f"rows={payload['proved_execution_requirement_count']} proof_ready={payload['proof_ready_count']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
