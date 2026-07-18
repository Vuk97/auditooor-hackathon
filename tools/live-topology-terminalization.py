#!/usr/bin/env python3
"""Terminalize live-topology proof-pair blockers without fabricating proof.

This is an accounting layer for the FL lane. It consumes FD/EW/closure/live
artifacts and groups each proof pair by the exact local terminal reason that
prevents same-block closure. Closure candidates are counted only when the
canonical live dossier contains real imported manual-proof rows that pass at
one shared block.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.live_topology_terminalization_fl.v1"
DEFAULT_FD_PLAN = ".auditooor/live_topology_manual_proof_plan_fd.json"
DEFAULT_FD_TEMPLATES = ".auditooor/live_topology_manual_proof_templates_fd"
DEFAULT_EW_RESOLUTION = ".auditooor/live_topology_address_resolution_ew.json"
DEFAULT_LIVE_TOPOLOGY = "live_topology_checks.json"
DEFAULT_OUT_JSON = ".auditooor/live_topology_terminalization_fl.json"
DEFAULT_OUT_MD = ".auditooor/live_topology_terminalization_fl.md"

ADDRESSABLE_STATUSES = {"candidate_address_found_not_applied"}
FIXTURE_STATUSES = {
    "terminal_fixture_or_corpus_only_no_live_address",
    "terminal_test_or_script_label_no_live_address",
}
INTERFACE_OR_NON_CONTRACT_STATUSES = {
    "terminal_interface_type_no_address",
    "terminal_semantic_stage_not_contract",
}
EXECUTED_STATUSES = {"pass", "fail"}
SOURCE_REF_KEYS = (
    "source_refs",
    "source_ref",
    "file_line",
    "file_lines",
    "target_file",
    "source_file",
    "source_path",
    "workspace_source_refs",
    "configured_source_refs",
    "current_workspace_source_refs",
)
SOURCE_REF_BLOCKER_KEYS = (
    "source_ref_blockers",
    "source_ref_errors",
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
    "configured_topology_refs",
)
TOPOLOGY_REF_BLOCKER_KEYS = (
    "topology_path_blockers",
    "configured_topology_ref_blockers",
)
TOPOLOGY_EVIDENCE_KEYS = (
    "configured_topology_evidence",
    "topology_evidence",
    "deployment_topology",
    "deployment_topology_evidence",
    "configuration_precondition",
    "configuration_evidence",
)
PROOF_COMMAND_KEYS = (
    "proof_command",
    "proof_commands",
    "exact_proof_command",
    "harness_command",
    "gating_test",
    "capture_command",
    "test_command",
)
PROOF_EVIDENCE_KEYS = (
    "proof_evidence",
    "harness_evidence",
    "execution_contract",
    "execution_manifest",
    "pass_evidence_lines",
    "test_transcript",
    "proof_transcript",
    "proof_artifacts",
    "execution_evidence",
    "capture_artifact",
)
PROOF_PATH_KEYS = (
    "proof_file",
    "proof_artifact",
    "proof_artifacts",
    "proof_artifact_path",
    "poc_path",
    "test_path",
    "generated_test_path",
    "harness_path",
    "execution_manifest_path",
)
PROOF_REF_BLOCKER_KEYS = (
    "proof_artifact_blockers",
)
BLOCKER_KEYS = (
    "blockers",
    "blocked_by",
    "blocked_reason",
    "blocker_reason",
    "promotion_blockers",
    "proof_blockers",
    "terminal_blockers",
    "required_unblockers",
    "kill_reason",
    "fp_reason",
)
MARKER_STATUS_KEYS = (
    "submission_posture",
    "promotion_review_status",
    "writeback_status",
)
MISSING_TEXT = {"", "n/a", "na", "none", "null", "unknown", "todo", "tbd", "advisory", "advisory_only"}
SOURCE_REF_RE = re.compile(
    r"(?P<path>(?:~|/|\.{1,2}/|[A-Za-z0-9_.-])"
    r"[A-Za-z0-9_./@%+,\-]*\."
    r"(?:sol|vy|go|rs|move|cairo|tsx|ts|jsx|json|js|py|md|yaml|yml|toml|txt|log))"
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
    "coverage_claim": "live_topology_terminalization_accounting_only",
    "advisory_only": True,
    "promotion_allowed": False,
    "severity": "none",
    "selected_impact": "",
    "submission_posture": "NOT_SUBMIT_READY",
    "impact_contract_required": True,
}


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def load_json(path: Path, label: str, *, required: bool = True) -> dict[str, Any]:
    if not path.is_file():
        if required:
            raise SystemExit(f"[live-topology-terminalization] missing {label}: {path}")
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"[live-topology-terminalization] unreadable {label}: {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit(f"[live-topology-terminalization] expected object JSON for {label}: {path}")
    return payload


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def workspace_path(workspace: Path, path: Path | None, default: str) -> Path:
    candidate = path or Path(default)
    candidate = candidate.expanduser()
    if not candidate.is_absolute():
        candidate = workspace / candidate
    return candidate.resolve()


def status_counts(rows: list[dict[str, Any]], field: str = "status") -> dict[str, int]:
    counts: Counter[str] = Counter()
    for row in rows:
        counts[str(row.get(field) or "unknown")] += 1
    return dict(sorted(counts.items()))


def is_trueish(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return str(value or "").strip().lower() in {
        "1",
        "true",
        "yes",
        "y",
        "advisory",
        "advisory_only",
        "not_submit_ready",
    }


def is_placeholder(value: Any) -> bool:
    text = str(value or "").strip()
    return not text or text.lower() in MISSING_TEXT or text.startswith("<") or text.endswith(">")


def text_values(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return [str(value)]
    if isinstance(value, bool) or value is None:
        return []
    if isinstance(value, list):
        values: list[str] = []
        for item in value:
            values.extend(text_values(item))
        return values
    if isinstance(value, dict):
        values: list[str] = []
        for item in value.values():
            values.extend(text_values(item))
        return values
    text = str(value).strip()
    return [text] if text else []


def collect_values(payloads: list[dict[str, Any]], keys: tuple[str, ...]) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    for payload in payloads:
        for key in keys:
            for value in text_values(payload.get(key)):
                if value and value not in seen:
                    values.append(value)
                    seen.add(value)
    return values


def ref_text_values(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, list):
        values: list[str] = []
        for item in value:
            values.extend(ref_text_values(item))
        return values
    if isinstance(value, dict):
        values: list[str] = []
        ref_keys = (
            "ref",
            "path",
            "source_ref",
            "source_path",
            "file_line",
            "file",
            "topology_path",
            "proof_artifact",
            "proof_artifact_path",
        )
        for key in ref_keys:
            if key in value:
                values.extend(ref_text_values(value.get(key)))
        if values or any(key in value for key in ("current", "reason", "line")):
            return values
        for item in value.values():
            values.extend(ref_text_values(item))
        return values
    return []


def collect_ref_values(payloads: list[dict[str, Any]], keys: tuple[str, ...]) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    for payload in payloads:
        for key in keys:
            for value in ref_text_values(payload.get(key)):
                if value and value not in seen:
                    values.append(value)
                    seen.add(value)
    return values


def clean_ref(value: str) -> str:
    text = value.strip().strip("`'\"()[]{}<>,.;")
    if text.startswith("workspace:"):
        text = text[len("workspace:") :]
    return text.strip()


def line_exists(path: Path, line_no: int) -> bool:
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


def resolve_workspace_ref(workspace: Path, raw_ref: str) -> dict[str, Any]:
    text = clean_ref(raw_ref)
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
    if not resolved.is_file() or (line is not None and not line_exists(resolved, line)):
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


def workspace_ref_status(workspace: Path, refs: list[str]) -> dict[str, Any]:
    resolved = [resolve_workspace_ref(workspace, ref) for ref in refs]
    return {
        "raw_refs": refs,
        "current_refs": [item for item in resolved if item["current"]],
        "stale_refs": [item for item in resolved if not item["current"]],
        "resolved_refs": resolved,
    }


def proof_path_status(workspace: Path, raw_path: str) -> dict[str, Any]:
    text = clean_ref(raw_path)
    match = SOURCE_REF_RE.search(text)
    path_text = match.group("path") if match else text
    path = Path(path_text).expanduser()
    try:
        resolved = path.resolve(strict=False) if path.is_absolute() else (workspace / path).resolve(strict=False)
        resolved.relative_to(workspace)
    except (OSError, ValueError):
        return {
            "ref": raw_path,
            "current": False,
            "reason": "proof_artifact_outside_current_workspace",
            "path": path_text,
        }
    return {
        "ref": raw_path,
        "current": resolved.is_file(),
        "reason": "current_workspace_proof_artifact" if resolved.is_file() else "stale_workspace_proof_artifact",
        "path": str(resolved.relative_to(workspace)),
    }


def has_concrete_proof(value: Any, workspace: Path) -> bool:
    if isinstance(value, dict):
        if is_trueish(value.get("advisory_only")) or is_trueish(value.get("advisory")):
            return False
        if is_trueish(value.get("runnable")) and str(value.get("claim") or "").strip() != "blocked_harness":
            return True
        if is_trueish(value.get("ran")) and any(
            is_trueish(value.get(key)) for key in ("pass", "passed", "ok", "exploit_pass", "control_pass")
        ):
            return True
        status = str(value.get("status") or value.get("verdict") or "").strip().lower()
        if status in {"pass", "passed", "ok", "proved", "proof-backed", "proof_backed"}:
            return True
        return any(has_concrete_proof(item, workspace) for item in value.values())
    if isinstance(value, list):
        return any(has_concrete_proof(item, workspace) for item in value)
    if not isinstance(value, str):
        return False
    text = value.strip()
    if is_placeholder(text):
        return False
    if CONCRETE_PROOF_RE.search(text):
        return True
    return proof_path_status(workspace, text)["current"]


def contains_advisory_marker(value: Any) -> bool:
    if isinstance(value, dict):
        if is_trueish(value.get("advisory_only")) or is_trueish(value.get("advisory")):
            return True
        return any(contains_advisory_marker(item) for item in value.values())
    if isinstance(value, list):
        return any(contains_advisory_marker(item) for item in value)
    if isinstance(value, str):
        return "advisory only" in value.lower() or "advisory_only" in value.lower()
    return False


def contains_blocker_marker(value: Any) -> bool:
    if isinstance(value, str):
        return bool(BLOCKER_MARKER_RE.search(value))
    if isinstance(value, (int, float, bool)) or value is None:
        return False
    if isinstance(value, list):
        return any(contains_blocker_marker(item) for item in value)
    if isinstance(value, dict):
        return any(contains_blocker_marker(item) for item in value.values())
    return bool(BLOCKER_MARKER_RE.search(str(value)))


def blocker_values(payloads: list[dict[str, Any]]) -> list[str]:
    blockers: list[str] = []
    for payload in payloads:
        for key in BLOCKER_KEYS:
            for value in text_values(payload.get(key)):
                if not is_placeholder(value):
                    blockers.append(value)
        for key in MARKER_STATUS_KEYS:
            for value in text_values(payload.get(key)):
                if BLOCKER_MARKER_RE.search(value):
                    blockers.append(value)
        for key in (*TOPOLOGY_EVIDENCE_KEYS, *PROOF_EVIDENCE_KEYS):
            if contains_blocker_marker(payload.get(key)):
                blockers.append(f"{key}:blocker_marker_present")
    return sorted(set(blockers))


def strict_row_readiness(workspace: Path, payloads: list[dict[str, Any]]) -> dict[str, Any]:
    reasons: list[str] = []
    source_refs = collect_ref_values(payloads, SOURCE_REF_KEYS)
    source_status = workspace_ref_status(workspace, source_refs)
    source_ref_blockers = collect_values(payloads, SOURCE_REF_BLOCKER_KEYS)
    if not source_refs:
        reasons.append("missing_source_refs")
    if source_status["stale_refs"] or source_ref_blockers:
        reasons.append("stale_source")

    topology_refs = collect_ref_values(payloads, TOPOLOGY_PATH_KEYS)
    topology_status = workspace_ref_status(workspace, topology_refs)
    topology_ref_blockers = collect_values(payloads, TOPOLOGY_REF_BLOCKER_KEYS)
    topology_evidence = [
        value for value in collect_values(payloads, TOPOLOGY_EVIDENCE_KEYS) if not is_placeholder(value)
    ]
    if topology_status["stale_refs"] or topology_ref_blockers:
        reasons.append("stale_source")
    if not topology_evidence and not topology_status["current_refs"]:
        reasons.append("missing_topology_evidence")

    proof_commands = [
        value for value in collect_values(payloads, PROOF_COMMAND_KEYS) if not is_placeholder(value)
    ]
    proof_artifact_checks = [
        proof_path_status(workspace, value)
        for value in collect_ref_values(payloads, PROOF_PATH_KEYS)
        if not is_placeholder(value)
    ]
    current_proof_artifacts = [item for item in proof_artifact_checks if item["current"]]
    stale_proof_artifacts = [item for item in proof_artifact_checks if not item["current"]]
    proof_ref_blockers = collect_values(payloads, PROOF_REF_BLOCKER_KEYS)
    proof_evidence_present = any(has_concrete_proof(payload.get(key), workspace) for payload in payloads for key in PROOF_EVIDENCE_KEYS)
    proof_command_present = any(CONCRETE_PROOF_RE.search(command) for command in proof_commands)
    if stale_proof_artifacts or proof_ref_blockers:
        reasons.append("stale_source")
    if not proof_evidence_present and not proof_command_present and not current_proof_artifacts:
        reasons.append("missing_proof_evidence")

    blockers = blocker_values(payloads)
    if blockers:
        reasons.append("blocker_present")
    advisory = any(
        is_trueish(payload.get("advisory_only"))
        or is_trueish(payload.get("manual_proof_advisory_only"))
        or is_trueish(payload.get("not_submit_ready"))
        or contains_advisory_marker(payload)
        for payload in payloads
    )
    if advisory:
        reasons.append("advisory_only")

    unique_reasons = sorted(set(reasons))
    return {
        "ready": not unique_reasons,
        "reasons": unique_reasons,
        "source_refs": source_status["current_refs"],
        "source_ref_blockers": source_status["stale_refs"],
        "source_ref_marker_blockers": source_ref_blockers,
        "configured_topology_refs": topology_status["current_refs"],
        "configured_topology_ref_blockers": topology_status["stale_refs"],
        "configured_topology_marker_blockers": topology_ref_blockers,
        "configured_topology_evidence": topology_evidence,
        "proof_commands": proof_commands,
        "proof_evidence_present": proof_evidence_present or proof_command_present or bool(current_proof_artifacts),
        "proof_artifacts": current_proof_artifacts,
        "proof_artifact_blockers": stale_proof_artifacts,
        "proof_marker_blockers": proof_ref_blockers,
        "blocking_markers": blockers,
        "advisory_only": advisory,
    }


def list_rows(payload: dict[str, Any], key: str) -> list[dict[str, Any]]:
    return [row for row in payload.get(key) or [] if isinstance(row, dict)]


def row_id(row: dict[str, Any]) -> str:
    return str(row.get("row_id") or row.get("id") or "").strip()


def pair_id(row: dict[str, Any]) -> str:
    return str(row.get("proof_pair_id") or row.get("pair_id") or "").strip()


def rpc_env_var(network: str) -> str:
    return {
        "mainnet": "MAINNET_RPC_URL",
        "polygon": "POLYGON_RPC_URL",
        "arbitrum": "ARBITRUM_RPC_URL",
        "optimism": "OPTIMISM_RPC_URL",
        "base": "BASE_RPC_URL",
    }.get(network.lower(), f"{network.upper()}_RPC_URL")


def parse_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return values
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key:
            values[key] = value.strip().strip("'").strip('"')
    return values


def workspace_env(workspace: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    candidates = [
        workspace / ".env",
        workspace / ".env.local",
        workspace / "env" / ".env",
        workspace / "env" / ".env.local",
    ]
    env_dir = workspace / "env"
    if env_dir.is_dir():
        candidates.extend(sorted(env_dir.glob("*.env")))
    for candidate in candidates:
        if candidate.is_file():
            values.update(parse_env_file(candidate))
    return values


def rpc_available(network: str, env_values: dict[str, str]) -> bool:
    env_key = rpc_env_var(network)
    return bool(os.environ.get(env_key) or env_values.get(env_key))


def manual_proof_row_ids(workspace: Path) -> tuple[set[str], list[str], list[dict[str, str]]]:
    proof_dir = workspace / "manual_proofs"
    if not proof_dir.is_dir():
        return set(), [], []
    discovered: set[str] = set()
    files: list[str] = []
    errors: list[dict[str, str]] = []
    for path in sorted(proof_dir.glob("*.json")):
        files.append(str(path))
        discovered.add(path.stem)
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            errors.append({"path": str(path), "error": str(exc)})
            continue
        rows = payload.get("results") if isinstance(payload, dict) else None
        if not isinstance(rows, list):
            continue
        for raw in rows:
            if isinstance(raw, dict):
                discovered_id = str(raw.get("id") or "").strip()
                if discovered_id:
                    discovered.add(discovered_id)
    return discovered, files, errors


def template_index(template_dir: Path) -> dict[str, str]:
    if not template_dir.is_dir():
        return {}
    return {path.stem: str(path) for path in sorted(template_dir.glob("*.json"))}


def closure_artifact_summaries(paths: list[Path]) -> list[dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    for path in paths:
        payload = load_json(path, f"execution closure {path.name}", required=False)
        closure = payload.get("closure") if isinstance(payload.get("closure"), dict) else {}
        groups = payload.get("groups") if isinstance(payload.get("groups"), dict) else {}
        summaries.append(
            {
                "path": str(path),
                "exists": path.is_file(),
                "schema": payload.get("schema"),
                "closed_requirement_count": int(closure.get("closed_requirement_count") or 0),
                "reduced_requirement_count": int(closure.get("reduced_requirement_count") or 0),
                "row_attempt_count": int(closure.get("row_attempt_count") or 0),
                "terminal_blocker_counts": closure.get("terminal_blocker_counts") or {},
                "missing_address_rows": int((groups.get("missing_address") or {}).get("row_count") or 0),
                "missing_block_requirements": int((groups.get("missing_block") or {}).get("requirement_count") or 0),
                "missing_manual_proof_rows": int((groups.get("missing_manual_proof_id") or {}).get("row_count") or 0),
            }
        )
    return summaries


def is_imported_manual_row(row: dict[str, Any]) -> bool:
    provenance = row.get("provenance") if isinstance(row.get("provenance"), dict) else {}
    return any(
        [
            str(row.get("manual_proof_source") or "").strip(),
            str(row.get("spec_source") or "").strip() == "manual-proof-import",
            str(row.get("address_source") or "").strip() == "manual-proof-import",
            str(row.get("block_source") or "").strip() == "manual-proof-import",
            str(provenance.get("kind") or "").strip() == "manual-proof-import",
        ]
    )


def is_real_imported_same_block_closure(
    pair: dict[str, Any] | None,
    live_rows: list[dict[str, Any]],
    terminal_rows: list[dict[str, Any]],
) -> tuple[bool, list[str]]:
    blockers: list[str] = []
    if not pair:
        blockers.append("proof pair missing from live_topology_checks.json")
    elif str(pair.get("status") or "").strip() != "proved":
        blockers.append("proof pair status is not proved")
    if len(live_rows) < 2:
        blockers.append("fewer than two live rows in proof pair")

    passed = [row for row in live_rows if str(row.get("status") or "").strip() == "pass"]
    failed = [row for row in live_rows if str(row.get("status") or "").strip() == "fail"]
    executed = [row for row in live_rows if str(row.get("status") or "").strip() in EXECUTED_STATUSES]
    if len(executed) < 2:
        blockers.append("fewer than two executed rows")
    if len(passed) < 2:
        blockers.append("fewer than two passing rows")
    if failed:
        blockers.append("failing rows present: " + ",".join(sorted(row_id(row) for row in failed if row_id(row))))
    if any(str(row.get("evidence_class") or "").strip() != "topology-relation" for row in live_rows):
        blockers.append("not all rows are topology-relation evidence")
    blocks = sorted({str(row.get("block") or "").strip() for row in passed if str(row.get("block") or "").strip()})
    if len(blocks) != 1:
        blockers.append("passing rows are not pinned to one shared block")
    missing_import = [row_id(row) for row in passed if not is_imported_manual_row(row)]
    if missing_import:
        blockers.append("passing rows are not imported manual proofs: " + ",".join(sorted(missing_import)))
    advisory_rows = [row_id(row) for row in passed if row.get("manual_proof_advisory_only") is True]
    if advisory_rows:
        blockers.append("manual proof rows are advisory-only: " + ",".join(sorted(advisory_rows)))
    incomplete_rows = [
        f"{row.get('row_id')}:{','.join(row.get('proof_terminal_reasons') or [])}"
        for row in terminal_rows
        if row.get("proof_terminal_reasons")
    ]
    if incomplete_rows:
        blockers.append("rows are not proof complete: " + ";".join(sorted(incomplete_rows)))
    return not blockers, sorted(set(blockers))


def classify_row(
    *,
    workspace: Path,
    ew_row: dict[str, Any],
    live_row: dict[str, Any],
    template_paths: dict[str, str],
    manual_ids: set[str],
    env_values: dict[str, str],
) -> dict[str, Any]:
    rid = row_id(ew_row) or row_id(live_row)
    network = str(ew_row.get("network") or live_row.get("network") or "mainnet").strip() or "mainnet"
    address_status = str(ew_row.get("address_resolution_status") or "").strip()
    live_status = str(live_row.get("status") or "").strip() or None
    candidate_addresses = ew_row.get("candidate_addresses") or live_row.get("candidate_addresses") or []
    if not isinstance(candidate_addresses, list):
        candidate_addresses = []
    addressable = bool(
        address_status in ADDRESSABLE_STATUSES
        or str(ew_row.get("address") or live_row.get("address") or "").strip()
        or candidate_addresses
    )
    terminal_categories: list[str] = []
    if addressable:
        terminal_categories.append("addressable_candidate")
    if address_status in FIXTURE_STATUSES:
        terminal_categories.append("fixture_or_corpus_only_contract")
    if address_status in INTERFACE_OR_NON_CONTRACT_STATUSES:
        terminal_categories.append("interface_or_non_contract_label")
    if not rpc_available(network, env_values):
        terminal_categories.append("missing_rpc")
    if rid not in manual_ids:
        terminal_categories.append("missing_manual_proof")
    if not str(live_row.get("block") or "").strip():
        terminal_categories.append("missing_block")
    strict = strict_row_readiness(workspace, [ew_row, live_row])
    imported_manual = is_imported_manual_row(live_row)
    proof_reasons = list(strict["reasons"])
    if live_status != "pass":
        proof_reasons.append("missing_live_pass")
    if not imported_manual:
        proof_reasons.append("missing_manual_proof")
    if not str(live_row.get("block") or "").strip():
        proof_reasons.append("missing_block")
    proof_reasons = sorted(set(proof_reasons))
    terminal_categories.extend(proof_reasons)
    proof_complete = not proof_reasons
    return {
        "row_id": rid,
        "contract": str(ew_row.get("contract") or live_row.get("contract") or "UNKNOWN"),
        "requirement_id": str(ew_row.get("requirement_id") or live_row.get("requirement_id") or ""),
        "requirement_role": ew_row.get("requirement_role") or live_row.get("requirement_role"),
        "network": network,
        "rpc_env_var": rpc_env_var(network),
        "rpc_available": rpc_available(network, env_values),
        "address_resolution_status": address_status or None,
        "status_after_ew": ew_row.get("status_after_ew"),
        "address": ew_row.get("address") or live_row.get("address"),
        "candidate_addresses": candidate_addresses,
        "template_path": template_paths.get(rid),
        "manual_proof_present": rid in manual_ids,
        "live_status": live_status,
        "live_block": live_row.get("block"),
        "live_evidence_class": live_row.get("evidence_class"),
        "imported_manual_proof_row": imported_manual,
        "proof_complete": proof_complete,
        "proof_terminal_status": "proof_complete" if proof_complete else "non_terminal",
        "proof_terminal_reasons": proof_reasons,
        "strict_evidence": {
            key: value
            for key, value in strict.items()
            if key not in {"ready", "reasons"}
        },
        "terminal_categories": sorted(set(terminal_categories)),
    }


def build_payload(
    *,
    workspace: Path,
    fd_plan: dict[str, Any],
    template_dir: Path,
    ew_resolution: dict[str, Any],
    live_topology: dict[str, Any],
    closure_paths: list[Path],
) -> dict[str, Any]:
    env_values = workspace_env(workspace)
    manual_ids, manual_files, manual_errors = manual_proof_row_ids(workspace)
    templates = template_index(template_dir)
    fd_pairs = list_rows(fd_plan, "proof_pairs")
    fd_by_pair = {str(pair.get("proof_pair_id") or pair.get("id") or "").strip(): pair for pair in fd_pairs}
    ew_rows = list_rows(ew_resolution, "rows")
    ew_by_id = {row_id(row): row for row in ew_rows if row_id(row)}
    live_rows = list_rows(live_topology, "results")
    live_by_id = {row_id(row): row for row in live_rows if row_id(row)}
    live_pairs = list_rows(live_topology, "proof_pairs")
    live_pair_by_id = {str(pair.get("id") or pair.get("proof_pair_id") or "").strip(): pair for pair in live_pairs}

    pair_ids = sorted(
        {
            pair_id(row)
            for row in ew_rows
            if pair_id(row)
        }
        | {
            str(pair.get("proof_pair_id") or pair.get("id") or "").strip()
            for pair in fd_pairs
            if str(pair.get("proof_pair_id") or pair.get("id") or "").strip()
        }
        | {
            str(pair.get("id") or pair.get("proof_pair_id") or "").strip()
            for pair in live_pairs
            if str(pair.get("id") or pair.get("proof_pair_id") or "").strip()
        }
    )

    ew_rows_by_pair: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in ew_rows:
        pid = pair_id(row)
        if pid:
            ew_rows_by_pair[pid].append(row)

    live_rows_by_pair: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in live_rows:
        pid = pair_id(row)
        if pid:
            live_rows_by_pair[pid].append(row)

    group_items: dict[str, list[dict[str, Any]]] = {
        "closure_candidates_real_imported_same_block": [],
        "addressable_candidate": [],
        "fixture_or_corpus_only_contract": [],
        "interface_or_non_contract_label": [],
        "missing_rpc": [],
        "missing_block": [],
        "missing_manual_proof": [],
        "stale_source": [],
        "missing_source_refs": [],
        "missing_topology_evidence": [],
        "missing_proof_evidence": [],
        "blocker_present": [],
        "advisory_only": [],
        "not_real_imported_same_block": [],
    }
    pair_terminalization: list[dict[str, Any]] = []

    for pid in pair_ids:
        fd_pair = fd_by_pair.get(pid, {})
        live_pair = live_pair_by_id.get(pid)
        row_ids = [
            str(item).strip()
            for item in fd_pair.get("row_ids") or (live_pair or {}).get("row_ids") or []
            if str(item).strip()
        ]
        if not row_ids:
            row_ids = sorted({row_id(row) for row in ew_rows_by_pair.get(pid, []) if row_id(row)})
        pair_rows: list[dict[str, Any]] = []
        for rid in row_ids:
            pair_rows.append(
                classify_row(
                    workspace=workspace,
                    ew_row=ew_by_id.get(rid, {}),
                    live_row=live_by_id.get(rid, {}),
                    template_paths=templates,
                    manual_ids=manual_ids,
                    env_values=env_values,
                )
            )
        live_pair_rows = [live_by_id[rid] for rid in row_ids if rid in live_by_id]
        closure_candidate, closure_blockers = is_real_imported_same_block_closure(live_pair, live_pair_rows, pair_rows)
        row_buckets = sorted({bucket for row in pair_rows for bucket in row.get("terminal_categories") or []})
        pair_buckets = [bucket for bucket in row_buckets if bucket in group_items and bucket != "not_real_imported_same_block"]
        if not closure_candidate and "not_real_imported_same_block" not in pair_buckets:
            pair_buckets.append("not_real_imported_same_block")

        contracts = sorted({str(row.get("contract") or "UNKNOWN") for row in pair_rows if row.get("contract")})
        networks = sorted({str(row.get("network") or "mainnet") for row in pair_rows})
        terminal_blockers = sorted(
            set(fd_pair.get("terminal_blockers") or [])
            | {
                f"{bucket}:{pid}"
                for bucket in pair_buckets
                if bucket in {"missing_rpc", "missing_block", "missing_manual_proof", "not_real_imported_same_block"}
            }
            | set(closure_blockers)
        )
        item = {
            "proof_pair_id": pid,
            "row_ids": row_ids,
            "contracts": contracts,
            "networks": networks,
            "live_pair_status": (live_pair or {}).get("status"),
            "live_shared_block": (live_pair or {}).get("shared_block"),
            "live_pair_blocks": (live_pair or {}).get("pair_blocks") or [],
            "closure_candidate_real_imported_same_block": closure_candidate,
            "terminal_buckets": [] if closure_candidate else sorted(pair_buckets),
            "closure_blockers": [] if closure_candidate else closure_blockers,
            "terminal_blockers": [] if closure_candidate else terminal_blockers,
            "row_terminalization": pair_rows,
            "import_command_after_capture": fd_pair.get("import_command_after_capture"),
            "executor_command_after_import": fd_pair.get("executor_command_after_import"),
        }
        pair_terminalization.append(item)
        if closure_candidate:
            group_items["closure_candidates_real_imported_same_block"].append(item)
        else:
            for bucket in sorted(pair_buckets):
                group_items[bucket].append(item)

    address_counts = Counter(str(row.get("address_resolution_status") or "unknown") for row in ew_rows)
    live_status_counts = live_topology.get("summary") or status_counts(live_rows)
    closure_summaries = closure_artifact_summaries(closure_paths)
    unclassified = [
        item
        for item in pair_terminalization
        if not item["closure_candidate_real_imported_same_block"] and not item["terminal_buckets"]
    ]
    missing_templates = sorted({row_id(row) for row in ew_rows if row_id(row)} - set(templates))
    terminal_pair_count = len(pair_terminalization) - len(group_items["closure_candidates_real_imported_same_block"])
    after_group_counts = {
        name: len(items)
        for name, items in group_items.items()
    }
    row_reason_counts: Counter[str] = Counter()
    proof_complete_row_count = 0
    non_terminal_rows: list[dict[str, Any]] = []
    for item in pair_terminalization:
        for row in item.get("row_terminalization") or []:
            if row.get("proof_complete"):
                proof_complete_row_count += 1
                continue
            non_terminal_rows.append(
                {
                    "proof_pair_id": item.get("proof_pair_id"),
                    "row_id": row.get("row_id"),
                    "contract": row.get("contract"),
                    "network": row.get("network"),
                    "reasons": row.get("proof_terminal_reasons") or [],
                }
            )
            for reason in row.get("proof_terminal_reasons") or []:
                row_reason_counts[str(reason)] += 1
    return {
        "schema": SCHEMA,
        "workspace": str(workspace),
        "generated_at": now_iso(),
        "inputs": {
            "fd_manual_proof_plan": str(workspace / DEFAULT_FD_PLAN),
            "fd_manual_proof_templates_dir": str(template_dir),
            "ew_address_resolution": str(workspace / DEFAULT_EW_RESOLUTION),
            "execution_closure_artifacts": [str(path) for path in closure_paths],
            "canonical_live_topology": str(workspace / DEFAULT_LIVE_TOPOLOGY),
        },
        "before_counts": {
            "fd_source_rows": int((fd_plan.get("before_counts") or {}).get("source_rows") or len(ew_rows)),
            "fd_source_proof_pairs": int((fd_plan.get("before_counts") or {}).get("source_proof_pairs") or len(fd_pairs)),
            "fd_closure_candidates": int((fd_plan.get("after_counts") or {}).get("closure_candidates") or 0),
            "fd_terminal_proof_pairs": int((fd_plan.get("after_counts") or {}).get("terminal_proof_pairs") or len(fd_pairs)),
            "ew_rows": len(ew_rows),
            "ew_requirements": len(list_rows(ew_resolution, "requirements")),
            "ew_closed_rows": len(list_rows(ew_resolution, "closed_rows")),
            "ew_closed_requirements": len(list_rows(ew_resolution, "closed_requirements")),
            "live_rows": len(live_rows),
            "live_proof_pairs": len(live_pairs),
            "live_status_counts": live_status_counts,
            "live_proof_pair_summary": live_topology.get("proof_pair_summary") or {},
            "address_resolution_counts": dict(sorted(address_counts.items())),
            "fd_template_files": len(templates),
            "manual_proof_files": len(manual_files),
            "manual_proof_row_ids": len(manual_ids),
            "execution_closure_artifacts": len(closure_summaries),
            "execution_closure_closed_requirements": sum(item["closed_requirement_count"] for item in closure_summaries),
            "execution_closure_reduced_requirements": max(
                [item["reduced_requirement_count"] for item in closure_summaries] or [0]
            ),
        },
        "after_counts": {
            "proof_pairs_total": len(pair_terminalization),
            "terminal_pair_count": terminal_pair_count,
            "closure_candidates_real_imported_same_block": len(group_items["closure_candidates_real_imported_same_block"]),
            "addressable_candidate_pairs": len(group_items["addressable_candidate"]),
            "fixture_or_corpus_only_pairs": len(group_items["fixture_or_corpus_only_contract"]),
            "interface_or_non_contract_pairs": len(group_items["interface_or_non_contract_label"]),
            "missing_rpc_pairs": len(group_items["missing_rpc"]),
            "missing_block_pairs": len(group_items["missing_block"]),
            "missing_manual_proof_pairs": len(group_items["missing_manual_proof"]),
            "stale_source_pairs": len(group_items["stale_source"]),
            "missing_source_refs_pairs": len(group_items["missing_source_refs"]),
            "missing_topology_evidence_pairs": len(group_items["missing_topology_evidence"]),
            "missing_proof_evidence_pairs": len(group_items["missing_proof_evidence"]),
            "blocker_present_pairs": len(group_items["blocker_present"]),
            "advisory_only_pairs": len(group_items["advisory_only"]),
            "not_real_imported_same_block_pairs": len(group_items["not_real_imported_same_block"]),
            "unclassified_pairs": len(unclassified),
            "all_pairs_accounted": not unclassified,
            "fd_template_missing_rows": len(missing_templates),
            "proof_complete_row_count": proof_complete_row_count,
            "non_terminal_row_count": len(non_terminal_rows),
            "non_terminal_row_reason_counts": dict(sorted(row_reason_counts.items())),
        },
        "group_counts": after_group_counts,
        "groups": {
            name: {
                "pair_count": len(items),
                "items": items,
            }
            for name, items in group_items.items()
        },
        "unclassified_pairs": unclassified,
        "non_terminal_rows": non_terminal_rows,
        "pair_terminalization": pair_terminalization,
        "fd_template_missing_row_ids": missing_templates,
        "manual_proofs": {
            "path": str(workspace / "manual_proofs"),
            "files": manual_files,
            "row_ids": sorted(manual_ids),
            "errors": manual_errors,
        },
        "execution_closure_artifacts": closure_summaries,
        "why_no_more_local_closure_safe": (
            "Closure requires two passing topology-relation rows imported from real manual proofs, "
            "with preserved proof_pair_id and one shared block. The local corpus currently has no "
            "manual_proofs cache and the canonical live dossier contains only not-collected or "
            "unresolved rows, so promoting any FD template, dry-run, fixture label, interface label, "
            "or address candidate would fabricate live evidence."
        ),
        "commands_replayable": [
            "python3 tools/live-topology-terminalization.py --workspace .",
            "python3 tools/live-check-runner.py . --import-manual-proofs --out-json live_topology_checks.json --out-md LIVE_TOPOLOGY.md",
            "python3 tools/live-topology-proof-executor.py --workspace . --requirements .auditooor/live_topology_proof_requirements.json --live-topology live_topology_checks.json",
        ],
        **ADVISORY_POSTURE,
    }


def render_markdown(payload: dict[str, Any]) -> str:
    before = payload["before_counts"]
    after = payload["after_counts"]
    lines = [
        "# Live Topology Terminalization FL",
        "",
        "Terminal blocker accounting for proof pairs. This artifact does not contain live proof.",
        "",
        f"- schema: `{payload['schema']}`",
        f"- proof pairs total: `{after['proof_pairs_total']}`",
        f"- terminal pairs: `{after['terminal_pair_count']}`",
        f"- real imported same-block closure candidates: `{after['closure_candidates_real_imported_same_block']}`",
        f"- all pairs accounted: `{after['all_pairs_accounted']}`",
        f"- submission posture: `{payload['submission_posture']}`",
        "",
        "## Before / After",
        "",
        f"- FD source rows: `{before['fd_source_rows']}`; FD proof pairs: `{before['fd_source_proof_pairs']}`",
        f"- FD templates: `{before['fd_template_files']}`; missing template rows after FL: `{after['fd_template_missing_rows']}`",
        f"- live rows before: `{before['live_rows']}`; live proof pairs before: `{before['live_proof_pairs']}`",
        f"- live statuses before: `{json.dumps(before['live_status_counts'], sort_keys=True)}`",
        f"- live pair summary before: `{json.dumps(before['live_proof_pair_summary'], sort_keys=True)}`",
        f"- execution closure reduced requirements: `{before['execution_closure_reduced_requirements']}`",
        "",
        "## Terminal Groups",
        "",
        "| Group | Pairs |",
        "|---|---:|",
    ]
    for key in (
        "addressable_candidate_pairs",
        "fixture_or_corpus_only_pairs",
        "interface_or_non_contract_pairs",
        "missing_rpc_pairs",
        "missing_block_pairs",
        "missing_manual_proof_pairs",
        "stale_source_pairs",
        "missing_source_refs_pairs",
        "missing_topology_evidence_pairs",
        "missing_proof_evidence_pairs",
        "blocker_present_pairs",
        "advisory_only_pairs",
        "not_real_imported_same_block_pairs",
        "unclassified_pairs",
    ):
        lines.append(f"| `{key}` | {after[key]} |")
    lines.extend([
        "",
        "## Non Terminal Row Reasons",
        "",
    ])
    for reason, count in sorted((after.get("non_terminal_row_reason_counts") or {}).items()):
        lines.append(f"- `{reason}`: {count}")
    lines.extend([
        "",
        "## Address Resolution Counts",
        "",
    ])
    for status, count in sorted((before.get("address_resolution_counts") or {}).items()):
        lines.append(f"- `{status}`: {count}")
    lines.extend([
        "",
        "## Sample Pairs",
        "",
        "| Pair | Buckets | Contracts | Rows |",
        "|---|---|---|---|",
    ])
    for item in payload.get("pair_terminalization", [])[:25]:
        lines.append(
            "| `{}` | `{}` | `{}` | `{}` |".format(
                item.get("proof_pair_id", ""),
                ",".join(item.get("terminal_buckets") or ["closure-candidate"]),
                ",".join(item.get("contracts") or []),
                ",".join(item.get("row_ids") or []),
            )
        )
    lines.extend([
        "",
        "## Why No More Local Closure Was Safe",
        "",
        payload["why_no_more_local_closure_safe"],
        "",
        "## Replay Commands",
        "",
    ])
    for command in payload.get("commands_replayable") or []:
        lines.append(f"- `{command}`")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--fd-plan", type=Path)
    parser.add_argument("--fd-template-dir", type=Path)
    parser.add_argument("--ew-resolution", type=Path)
    parser.add_argument("--live-topology", type=Path)
    parser.add_argument("--closure-glob", default=".auditooor/live_topology_execution_closure_*.json")
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-md", type=Path)
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args()

    workspace = args.workspace.expanduser().resolve()
    if not workspace.is_dir():
        print(f"[live-topology-terminalization] workspace not found: {workspace}")
        return 2

    fd_plan_path = workspace_path(workspace, args.fd_plan, DEFAULT_FD_PLAN)
    template_dir = workspace_path(workspace, args.fd_template_dir, DEFAULT_FD_TEMPLATES)
    ew_path = workspace_path(workspace, args.ew_resolution, DEFAULT_EW_RESOLUTION)
    live_path = workspace_path(workspace, args.live_topology, DEFAULT_LIVE_TOPOLOGY)
    closure_pattern = (
        str((workspace / args.closure_glob).resolve())
        if not Path(args.closure_glob).is_absolute()
        else args.closure_glob
    )
    closure_paths = sorted(Path(path) for path in glob.glob(closure_pattern) if Path(path).is_file())

    payload = build_payload(
        workspace=workspace,
        fd_plan=load_json(fd_plan_path, "FD manual-proof plan"),
        template_dir=template_dir,
        ew_resolution=load_json(ew_path, "EW address resolution"),
        live_topology=load_json(live_path, "canonical live topology"),
        closure_paths=closure_paths,
    )
    out_json = workspace_path(workspace, args.out_json, DEFAULT_OUT_JSON)
    out_md = workspace_path(workspace, args.out_md, DEFAULT_OUT_MD)
    write_json(out_json, payload)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text(render_markdown(payload), encoding="utf-8")
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    print(
        "[live-topology-terminalization] OK "
        f"pairs={payload['after_counts']['proof_pairs_total']} "
        f"terminal={payload['after_counts']['terminal_pair_count']} "
        f"closure_candidates={payload['after_counts']['closure_candidates_real_imported_same_block']} "
        f"json={out_json}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
