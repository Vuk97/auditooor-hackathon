#!/usr/bin/env python3
"""Summarize audit-deep manifests and downstream handoff outputs.

This is a read-only companion to ``make audit-deep``. It does not run the
audit flow. It inspects the durable artifacts that the deep-audit path writes
and renders a compact report that is easier to verify mechanically:

* Solidity deep-audit manifests under ``.auditooor/solidity-deep-audit/``
* Solidity all-harness manifests under ``.audit_logs/``
* Non-Solidity deep-audit reports/manifests under ``.audit_logs/``
* Bridge-adjacent outputs for ``hacker-brief``, ``brain-prime``, and
  ``high-impact-execution-bridge``

The normal mode prints the rendered report to stdout and also writes it to a
default workspace-local file unless ``--out`` is supplied.

The ``--check-fresh`` mode is the P0 completion gate for ``make
audit-run-full``. It checks source deep-engine manifests directly, not this
tool's summary report, so a freshly rendered summary cannot mask stale engines.
It accepts either a manifest from the current run or the existing typed
``NO_AUDIT_DEEP_REASON`` skip reason. When invoked by ``audit-run-full``, it
also appends the deep-freshness pass and complete rows so accepted skip reasons
are recorded in the run manifest.

RELATED TOOLS:
* ``tools/audit-completeness-check.py`` checks that deep artifacts exist, but
  does not prove they were emitted by the current run.
* ``tools/audit-closeout-check.py`` defines the typed stage skip precedent used
  here for ``NO_AUDIT_DEEP_REASON``.
* ``tools/audit-deep.sh`` emits the non-Solidity
  ``.audit_logs/audit_deep_all_manifest.json`` source manifest.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.audit_deep_manifest_summary.v1"
FRESHNESS_SCHEMA = "auditooor.audit_deep_manifest_freshness_check.v1"
DEFAULT_MARKDOWN_OUT = ".audit_logs/audit_deep_manifest_report.md"
DEFAULT_JSON_OUT = ".audit_logs/audit_deep_manifest_report.json"
DEFAULT_AUDIT_RUN_MANIFEST = ".auditooor/audit_run_full_manifest.jsonl"
DEFAULT_SKIP_KEY = "NO_AUDIT_DEEP_REASON"
PER_FUNCTION_HALMOS_MANIFEST = ".audit_logs/solidity_per_function_halmos_manifest.json"
SOURCE_MANIFESTS = (
    (".auditooor/solidity-deep-audit/manifest.json", "solidity-deep-audit"),
    (".audit_logs/audit_deep_all_manifest.json", "audit-deep-all-manifest"),
    (".audit_logs/solidity_deep_all_harnesses_manifest.json", "solidity-deep-all-harnesses"),
    (".auditooor/rust_source_graph.json", "rust-source-graph"),
    (".auditooor/rust_cross_crate_graph.json", "rust-cross-crate-graph"),
    (".audit_logs/go_dlt_audit_enforcement.json", "go-dlt-audit-enforcement"),
    (".audit_logs/audit_deep_manifest.json", "legacy-audit-deep-manifest"),
)
CURRENT_RUN_COMPLETION_SOURCE_KINDS = {
    "audit-deep-all-manifest",
    "solidity-deep-audit",
    "solidity-deep-all-harnesses",
    "rust-source-graph",
    "rust-cross-crate-graph",
    "go-dlt-audit-enforcement",
}
RUN_ID_REQUIRED_COMPLETION_SOURCE_KINDS = {
    "audit-deep-all-manifest",
    "rust-source-graph",
    "rust-cross-crate-graph",
    "go-dlt-audit-enforcement",
}
CURRENT_RUN_COMPLETION_SOURCE_PATHS = {
    rel for rel, kind in SOURCE_MANIFESTS if kind in CURRENT_RUN_COMPLETION_SOURCE_KINDS
}
SOURCE_MANIFEST_SCHEMAS = {
    "solidity-deep-audit": "auditooor.solidity_deep_audit.v1",
    "solidity-deep-all-harnesses": "auditooor.solidity_deep_all_harnesses.v1",
    "audit-deep-all-manifest": "auditooor.audit_deep_all.v1",
    "rust-source-graph": "auditooor.rust_source_graph.v1",
    "rust-cross-crate-graph": "auditooor.rust_cross_crate_graph.v1",
    "go-dlt-audit-enforcement": "auditooor.go_dlt_audit_enforcement.v1",
}
TIMESTAMP_FIELDS = ("generated_at_utc", "generated_at", "timestamp_utc", "created_at")
SOLIDITY_DEEP_ENGINE_TOOLS = {
    "halmos-runner",
    "echidna-campaign",
    "medusa-fuzz",
    "foundry-invariant-runner",
    "universal-fp-runner",
}
SOLIDITY_PROOF_ENGINE_TOOLS = {
    "halmos-runner",
    "echidna-campaign",
    "medusa-fuzz",
    "foundry-invariant-runner",
}
SOLIDITY_RUNNER_ENGINE_ARTIFACTS = {
    "halmos-runner": ".auditooor/halmos/artifact.json",
    "echidna-campaign": ".auditooor/echidna/artifact.json",
    "medusa-fuzz": ".auditooor/medusa/artifact.json",
}
SOLIDITY_ALL_HARNESS_ENGINES = {"halmos", "echidna", "medusa"}
SOLIDITY_STEP_SCHEMA = "auditooor.solidity_deep_audit.step.v1"
DEEP_ENGINE_ARTIFACT_SCHEMA = "auditooor.deep_engine_artifact.v1"
DEEP_ENGINE_NO_TARGET_MARKERS = (
    "no-target",
    "no target",
    "no tests found",
    "no tests with",
    "no callable",
    "no assertion",
    "no property",
    "no invariant",
    "found no",
)
SUCCESS_STATES = {"ok", "pass", "passed", "success", "succeeded", "complete", "completed"}
FAILED_STATES = {
    "fail",
    "failed",
    "failure",
    "error",
    "engine_error",
    "blocked",
    "crashed",
    "cancelled",
    "canceled",
    "killed",
    "oom",
    "partial",
    "interrupted",
}
SKIPPED_STATES = {
    "skip",
    "skipped",
    "skipped_budget",
    "planned",
    "not_run",
    "not-run",
    "not_applicable",
    "disabled",
    "dry_run",
    "env_skip",
    "tool_unavailable",
}
# Runner artifacts with status "no-execution" mean the engine binary ran and
# returned rc=0 but did not execute any symbolic checks or fuzz tests (the
# execution floor was not met). This is NOT a success - the artifact provides
# no certification evidence. It is a recognised state so the manifest check
# emits a clear "status_no_execution" reason rather than the catch-all
# "status_unknown". Deep-freshness certification MUST reject these artifacts.
# "timeout" / "timed_out" are also no-execution-class: the runner killed the
# engine after the per-harness timeout elapsed.  The audit-run-full loop MUST
# continue to the next harness (runners exit 0 on timeout), but the artifact
# does NOT certify as a successful deep-engine run.
NO_EXECUTION_STATES = {
    "no-execution",
    "no_execution",
    "no-exec",
    "no_exec",
    "timeout",
    "timed_out",
}
KNOWN_EXECUTION_STATES = SUCCESS_STATES | FAILED_STATES | SKIPPED_STATES | NO_EXECUTION_STATES


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _rel(path: Path, workspace: Path) -> str:
    try:
        return path.resolve(strict=False).relative_to(workspace.resolve(strict=False)).as_posix()
    except ValueError:
        return path.as_posix()


def _workspace_path_error(path: Path, workspace: Path | None) -> str | None:
    if workspace is None:
        return None
    try:
        path.resolve(strict=False).relative_to(workspace.resolve(strict=False))
    except ValueError:
        return "outside_workspace"
    except OSError as exc:
        return f"resolve_error:{exc.__class__.__name__}"
    return None


def _load_json(path: Path) -> tuple[Any | None, str | None]:
    try:
        return json.loads(path.read_text(encoding="utf-8")), None
    except FileNotFoundError:
        return None, "missing"
    except json.JSONDecodeError as exc:
        return None, f"invalid_json:{exc.lineno}:{exc.colno}"
    except OSError as exc:
        return None, f"read_error:{exc.__class__.__name__}"


def _parse_timestamp(raw: Any) -> datetime | None:
    if not isinstance(raw, str) or not raw.strip():
        return None
    value = raw.strip()
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _format_timestamp(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _workspace_matches(raw_workspace: Any, workspace: Path) -> bool:
    if raw_workspace is None:
        return False
    raw = str(raw_workspace).strip()
    if not raw:
        return False
    expanded = Path(raw).expanduser()
    if raw == str(workspace) or raw == workspace.as_posix():
        return True
    try:
        return expanded.resolve(strict=False) == workspace.resolve(strict=False)
    except OSError:
        return False


def _meta_dict(payload: dict[str, Any]) -> dict[str, Any]:
    meta = payload.get("_meta")
    return meta if isinstance(meta, dict) else {}


def _manifest_schema(payload: dict[str, Any]) -> Any:
    meta = _meta_dict(payload)
    return (
        payload.get("schema")
        or payload.get("schema_version")
        or meta.get("schema")
        or meta.get("schema_version")
    )


def _manifest_workspace(payload: dict[str, Any]) -> Any:
    meta = _meta_dict(payload)
    return payload.get("workspace") or meta.get("workspace")


def _manifest_run_id(payload: dict[str, Any]) -> Any:
    meta = _meta_dict(payload)
    return (
        payload.get("run_id")
        or payload.get("audit_run_id")
        or meta.get("run_id")
        or meta.get("audit_run_id")
    )


def _completion_source_eligible(kind: str, manifest_run_id: Any, requested_run_id: Any) -> bool:
    if kind not in CURRENT_RUN_COMPLETION_SOURCE_KINDS:
        return False
    if (
        kind in RUN_ID_REQUIRED_COMPLETION_SOURCE_KINDS
        and requested_run_id
        and not manifest_run_id
    ):
        return False
    return True


def _latest_audit_run_start(
    manifest_path: Path,
    workspace: Path,
    *,
    run_id: str | None = None,
) -> dict[str, Any]:
    latest: dict[str, Any] | None = None
    target_run_id = str(run_id) if run_id else None
    try:
        lines = manifest_path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return {"error": "missing"}
    except OSError as exc:
        return {"error": f"read_error:{exc.__class__.__name__}"}

    for line_no, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(row, dict) or row.get("event") != "start":
            continue
        if not _workspace_matches(row.get("workspace"), workspace):
            continue
        row_run_id = row.get("run_id") or row.get("audit_run_id")
        if target_run_id is not None and str(row_run_id or "") != target_run_id:
            continue
        started_at = _parse_timestamp(row.get("timestamp_utc"))
        if started_at is None:
            continue
        if latest is None or started_at >= latest["started_at"]:
            latest = {
                "started_at": started_at,
                "line_no": line_no,
                "run_id": row_run_id,
                "raw": row,
            }

    if latest is None:
        if target_run_id is not None:
            return {"error": "no_start_event_for_run_id", "run_id": target_run_id}
        return {"error": "no_start_event"}
    return latest


def _normalize_full_max_functions(max_functions: Any) -> str:
    value = "" if max_functions is None else str(max_functions).strip()
    if not value:
        raise ValueError("refusing to append full audit-run complete event without max_functions")
    if not re.fullmatch(r"[0-9]+", value):
        raise ValueError("refusing to append full audit-run complete event with non-integer max_functions")
    parsed = int(value, 10)
    if parsed != 0:
        raise ValueError("refusing to append full audit-run complete event for a bounded start row")
    return "0"


def _file_mtime(path: Path) -> datetime | None:
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
    except OSError:
        return None


def _typed_skip_reason(
    workspace: Path,
    skip_key: str,
    run_start: datetime,
    run_id: str | None = None,
) -> dict[str, Any] | None:
    skip_json = workspace / ".auditooor" / "stage_skips.json"
    payload, error = _load_json(skip_json)
    if isinstance(payload, dict):
        entry = payload.get(skip_key)
        if isinstance(entry, dict):
            reason = str(entry.get("reason") or entry.get("skip_reason") or "").strip()
            timestamp_field, timestamp = _manifest_timestamp(entry)
            entry_run_id = str(entry.get("run_id") or entry.get("audit_run_id") or "").strip()
            run_id_mismatch = bool(run_id and entry_run_id and entry_run_id != str(run_id))
            run_id_missing = bool(run_id and not entry_run_id)
            freshness_error = (
                "stage_skips.json skip entry lacks run_id/audit_run_id"
                if run_id_missing
                else None
            )
            if reason:
                return {
                    "path": _rel(skip_json, workspace),
                    "key": skip_key,
                    "reason": reason,
                    "source": "stage_skips.json",
                    "timestamp_field": timestamp_field,
                    "timestamp_utc": _format_timestamp(timestamp),
                    "run_id": entry_run_id or None,
                    "run_id_mismatch": run_id_mismatch,
                    "run_id_missing": run_id_missing,
                    "fresh_for_run": bool(
                        timestamp is not None
                        and timestamp >= run_start
                        and not run_id_mismatch
                        and not run_id_missing
                    ),
                    **({"freshness_error": freshness_error} if freshness_error else {}),
                }
        elif isinstance(entry, str) and entry.strip():
            return {
                "path": _rel(skip_json, workspace),
                "key": skip_key,
                "reason": entry.strip(),
                "source": "stage_skips.json",
                "fresh_for_run": False,
                "freshness_error": "stage_skips.json skip entry lacks per-skip timestamp",
            }
    elif error not in {None, "missing"}:
        return {
            "path": _rel(skip_json, workspace),
            "key": skip_key,
            "reason": "",
            "source": "stage_skips.json",
            "error": error,
        }

    skip_md = workspace / ".auditooor" / f"{skip_key}.md"
    text, read_error = _read_text(skip_md)
    if isinstance(text, str) and text.strip():
        mtime = _file_mtime(skip_md)
        fresh_by_mtime = bool(mtime is not None and mtime >= run_start)
        freshness_error = None
        fresh_for_run = fresh_by_mtime
        if run_id:
            fresh_for_run = False
            freshness_error = (
                f"{skip_key}.md skip entry lacks run_id; use stage_skips.json "
                "with per-skip timestamp and run_id"
            )
        return {
            "path": _rel(skip_md, workspace),
            "key": skip_key,
            "reason": text.strip().splitlines()[0],
            "source": f"{skip_key}.md",
            "mtime_utc": _format_timestamp(mtime),
            "timestamp_field": "file_mtime",
            "fresh_by_mtime": fresh_by_mtime,
            "fresh_for_run": fresh_for_run,
            **({"freshness_error": freshness_error} if freshness_error else {}),
        }
    if read_error not in {None, "missing"}:
        return {
            "path": _rel(skip_md, workspace),
            "key": skip_key,
            "reason": "",
            "source": f"{skip_key}.md",
            "error": read_error,
        }
    return None


def _manifest_timestamp(payload: dict[str, Any]) -> tuple[str | None, datetime | None]:
    meta = _meta_dict(payload)
    for field in TIMESTAMP_FIELDS:
        parsed = _parse_timestamp(payload.get(field))
        if parsed is not None:
            return field, parsed
        parsed = _parse_timestamp(meta.get(field))
        if parsed is not None:
            return f"_meta.{field}", parsed
    return None, None


def _state(raw: Any) -> str:
    return str(raw or "").strip().lower().replace(" ", "_").replace("-", "_")


def _exit_code(row: dict[str, Any]) -> int | None:
    for key in ("exit_code", "returncode", "return_code", "rc", "engine_rc"):
        if key not in row or row.get(key) in {None, ""}:
            continue
        try:
            return int(row.get(key))
        except (TypeError, ValueError):
            return None
    return None


def _deep_engine_no_target_reasons(payload: dict[str, Any]) -> list[str]:
    text_parts = [
        str(payload.get(key) or "")
        for key in (
            "reason",
            "stdout",
            "stderr",
            "stdout_tail",
            "stderr_tail",
            "message",
            "error",
        )
    ]
    lowered = "\n".join(text_parts).lower()
    return sorted(marker for marker in DEEP_ENGINE_NO_TARGET_MARKERS if marker in lowered)


def _engine_harness_proof_check(workspace: Path | None) -> dict[str, Any] | None:
    if workspace is None:
        return None
    tool = Path(__file__).resolve().with_name("engine-harness-proof-check.py")
    try:
        spec = importlib.util.spec_from_file_location("engine_harness_proof_check", tool)
        if spec is None or spec.loader is None:
            raise RuntimeError("module spec unavailable")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        payload = module.evaluate(workspace)
    except Exception as exc:
        return {
            "verdict": "error",
            "reason": f"engine-harness-proof-check failed: {exc}",
        }
    if not isinstance(payload, dict):
        return {
            "verdict": "error",
            "reason": "engine-harness-proof-check returned a non-object payload",
        }
    return payload


def _optional_int(row: dict[str, Any], key: str) -> int | None:
    if key not in row or row.get(key) in {None, ""}:
        return None
    try:
        return int(row.get(key))
    except (TypeError, ValueError):
        return None


def _with_per_function_halmos_denominator(
    payload: dict[str, Any],
    *,
    workspace: Path | None,
    run_id: str | None,
    run_start: datetime | None,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    if workspace is None:
        return payload, None
    manifest_path = workspace / PER_FUNCTION_HALMOS_MANIFEST
    per_fn_payload, load_error = _load_json(manifest_path)
    rel_manifest = _rel(manifest_path, workspace)
    if not isinstance(per_fn_payload, dict):
        return payload, {"path": rel_manifest, "exists": False, "error": load_error or "not_json_object"}

    timestamp_field, timestamp = _manifest_timestamp(per_fn_payload)
    expected = _optional_int(per_fn_payload, "expected_invocation_count")
    executed = _optional_int(per_fn_payload, "executed_invocation_count")
    ok = _optional_int(per_fn_payload, "ok_invocation_count")
    status = _state(per_fn_payload.get("status"))
    generated = _optional_int(payload, "generated_per_function_harness_count")
    sidecar_run_id = per_fn_payload.get("run_id") or per_fn_payload.get("audit_run_id")
    errors: list[str] = []
    if per_fn_payload.get("schema") != "auditooor.solidity_per_function_halmos.v1":
        errors.append("schema_mismatch")
    if not _workspace_matches(per_fn_payload.get("workspace"), workspace):
        errors.append("workspace_mismatch")
    if run_id and str(sidecar_run_id or "") != str(run_id):
        errors.append("run_id_mismatch")
    if run_start is not None and (timestamp is None or timestamp < run_start):
        errors.append("stale_or_missing_timestamp")
    if status != "ok":
        errors.append("status_not_ok")
    if generated is not None and expected is not None and generated != expected:
        errors.append("expected_count_mismatch")

    invocations = per_fn_payload.get("invocations")
    invocation_rows = invocations if isinstance(invocations, list) else []
    invocation_artifact_checks: list[dict[str, Any]] = []
    invocation_artifact_errors: list[dict[str, Any]] = []
    if not isinstance(invocations, list):
        errors.append("invocations_not_list")
    elif expected is not None and len(invocations) != expected:
        errors.append("invocation_count_mismatch")

    for idx, row in enumerate(invocation_rows):
        if not isinstance(row, dict):
            invocation_artifact_errors.append({
                "index": idx,
                "reason": "malformed_invocation_row",
            })
            continue
        status_row = _state(row.get("status"))
        code_row = _exit_code(row)
        artifact_path = _resolve_artifact_path(
            row.get("artifact"),
            manifest_path=manifest_path,
            workspace=workspace,
        )
        check: dict[str, Any] = {
            "index": row.get("index", idx),
            "selector": row.get("selector"),
            "harness_contract": row.get("harness_contract"),
            "status": status_row or "<missing>",
            "returncode": code_row,
            "artifact": None,
        }
        reasons: list[str] = []
        if status_row not in KNOWN_EXECUTION_STATES:
            reasons.append("invocation_status_unknown")
        elif status_row not in SUCCESS_STATES:
            reasons.append("invocation_status_not_success")
        if status_row in SUCCESS_STATES and code_row != 0:
            reasons.append("invocation_nonzero_or_missing_returncode")
        if artifact_path is None:
            reasons.append("missing_artifact_path")
            invocation_artifact_errors.append({**check, "reasons": reasons})
            continue
        rel_artifact = _rel(artifact_path, workspace)
        check["artifact"] = rel_artifact
        workspace_error = _workspace_path_error(artifact_path, workspace)
        if workspace_error is not None:
            reasons.append(workspace_error)
            invocation_artifact_errors.append({**check, "reasons": reasons})
            continue
        artifact_payload, artifact_load_error = _load_json(artifact_path)
        if not isinstance(artifact_payload, dict):
            reasons.append(artifact_load_error or "not_json_object")
            invocation_artifact_errors.append({**check, "reasons": reasons})
            continue
        artifact_status = _state(artifact_payload.get("status"))
        artifact_code = _exit_code(artifact_payload)
        timestamp_field_artifact, artifact_timestamp = _manifest_timestamp(artifact_payload)
        artifact_run_id = artifact_payload.get("run_id") or artifact_payload.get("audit_run_id")
        artifact_engine = str(artifact_payload.get("engine") or "").strip()
        no_target_reasons = _deep_engine_no_target_reasons(artifact_payload)
        check.update({
            "artifact_status": artifact_status or "<missing>",
            "artifact_exit_code": artifact_code,
            "artifact_engine": artifact_engine or None,
            "artifact_workspace": artifact_payload.get("workspace"),
            "artifact_run_id": artifact_run_id,
            "timestamp_field": timestamp_field_artifact,
            "timestamp_utc": _format_timestamp(artifact_timestamp),
            "no_target_reasons": no_target_reasons,
        })
        if artifact_payload.get("schema_version") != DEEP_ENGINE_ARTIFACT_SCHEMA:
            reasons.append("artifact_schema_mismatch")
        if not _workspace_matches(artifact_payload.get("workspace"), workspace):
            reasons.append("artifact_workspace_mismatch")
        if artifact_engine and artifact_engine != "halmos":
            reasons.append("artifact_engine_mismatch")
        if artifact_status not in KNOWN_EXECUTION_STATES:
            reasons.append("artifact_status_unknown")
        elif artifact_status not in SUCCESS_STATES:
            reasons.append("artifact_status_not_success")
        if artifact_status in SUCCESS_STATES and artifact_code != 0:
            reasons.append("artifact_nonzero_or_missing_exit_code")
        if run_id and str(artifact_run_id or "") != str(run_id):
            reasons.append("artifact_run_id_mismatch")
        if run_start is not None and (
            artifact_timestamp is None or artifact_timestamp < run_start
        ):
            reasons.append("artifact_stale_or_missing_timestamp")
        if no_target_reasons:
            reasons.append("artifact_no_target")
        invocation_artifact_checks.append(check)
        if reasons:
            invocation_artifact_errors.append({**check, "reasons": reasons})

    if invocation_artifact_errors:
        errors.append("invocation_artifact_errors")

    detail = {
        "path": rel_manifest,
        "exists": True,
        "status": status or None,
        "run_id": sidecar_run_id,
        "timestamp_field": timestamp_field,
        "timestamp_utc": _format_timestamp(timestamp),
        "expected_invocation_count": expected,
        "executed_invocation_count": executed,
        "ok_invocation_count": ok,
        "invocation_count": len(invocation_rows),
        "invocation_artifact_check_count": len(invocation_artifact_checks),
        "invocation_artifact_checks": invocation_artifact_checks,
        "invocation_artifact_error_count": len(invocation_artifact_errors),
        "invocation_artifact_errors": invocation_artifact_errors,
        "all_invocation_artifacts_valid": bool(
            expected is not None
            and expected > 0
            and len(invocation_rows) == expected
            and len(invocation_artifact_errors) == 0
        ),
        "errors": errors,
    }
    if errors:
        return payload, detail

    augmented = dict(payload)
    if generated is None and expected is not None:
        augmented["generated_per_function_harness_count"] = expected
    if ok is not None:
        augmented["executed_generated_harness_count"] = ok
    return augmented, detail


INVARIANT_DENOMINATOR_PAIRS = (
    (
        "generated_per_function_harness_count",
        "executed_generated_harness_count",
        "generated per-function harnesses",
    ),
    (
        "available_engine_harness_count",
        "executed_engine_harness_count",
        "available engine harness roots",
    ),
)


def _invariant_denominator_assessment(
    payload: dict[str, Any],
    *,
    require_full_invariant_denominator: bool,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    checks: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    for denominator_field, executed_field, label in INVARIANT_DENOMINATOR_PAIRS:
        denominator = _optional_int(payload, denominator_field)
        executed = _optional_int(payload, executed_field)
        check = {
            "label": label,
            "denominator_field": denominator_field,
            "denominator_count": denominator,
            "executed_field": executed_field,
            "executed_count": executed,
            "strict_required": require_full_invariant_denominator,
        }
        checks.append(check)
        reason = None
        if require_full_invariant_denominator:
            if denominator is None:
                reason = "denominator_count_missing"
            elif denominator > 0 and executed is None:
                reason = "executed_count_missing"
            elif executed is not None and denominator > executed:
                reason = "denominator_exceeds_executed"
        if reason is not None:
            error = dict(check)
            error["reason"] = reason
            errors.append(error)
    return checks, errors


def _resolve_artifact_path(raw: Any, manifest_path: Path | None, workspace: Path | None) -> Path | None:
    if not isinstance(raw, str) or not raw.strip():
        return None
    candidate = Path(raw.strip()).expanduser()
    if candidate.is_absolute():
        return candidate
    if manifest_path is not None:
        return manifest_path.parent / candidate
    if workspace is not None:
        return workspace / candidate
    return candidate


def _backed_evidence_status(
    raw: Any,
    *,
    manifest_path: Path | None,
    workspace: Path | None,
    run_start: datetime | None,
) -> tuple[bool, dict[str, Any] | None]:
    path = _resolve_artifact_path(raw, manifest_path, workspace)
    if path is None:
        return False, None
    rel_path = _rel(path, workspace) if workspace is not None else path.as_posix()
    info: dict[str, Any] = {"path": rel_path}
    workspace_error = _workspace_path_error(path, workspace)
    if workspace_error is not None:
        info["error"] = workspace_error
        return False, info
    try:
        stat = path.stat()
    except FileNotFoundError:
        info["error"] = "missing"
        return False, info
    except OSError as exc:
        info["error"] = f"stat_error:{exc.__class__.__name__}"
        return False, info
    mtime = datetime.fromtimestamp(stat.st_mtime, timezone.utc)
    info["size_bytes"] = stat.st_size
    info["mtime_utc"] = _format_timestamp(mtime)
    if not path.is_file():
        info["error"] = "not_regular_file"
        return False, info
    if stat.st_size <= 0:
        info["error"] = "empty"
        return False, info
    if run_start is not None and mtime < run_start:
        info["error"] = "stale"
        return False, info
    return True, info


def _manifest_execution_assessment(
    payload: dict[str, Any],
    kind: str,
    *,
    manifest_path: Path | None = None,
    workspace: Path | None = None,
    run_start: datetime | None = None,
    run_id: Any = None,
    require_full_invariant_denominator: bool = False,
) -> tuple[bool, str, dict[str, Any]]:
    if payload.get("dry_run") is True:
        return False, "dry-run manifest cannot satisfy deep-engine freshness", {"dry_run": True}

    if kind == "rust-source-graph":
        meta = _meta_dict(payload)
        crate_count = meta.get("crate_count", payload.get("crate_count"))
        ok = isinstance(crate_count, int) and crate_count >= 0
        detail = {"crate_count": crate_count}
        if not ok:
            return False, "rust source graph manifest has invalid crate_count", detail
        return True, "rust source graph manifest is well formed", detail

    if kind == "rust-cross-crate-graph":
        meta = _meta_dict(payload)
        crate_count = meta.get("crate_count", payload.get("crate_count"))
        edge_count = meta.get("edge_count", payload.get("edge_count"))
        detail = {"crate_count": crate_count, "edge_count": edge_count}
        if not isinstance(crate_count, int) or crate_count < 0:
            return False, "rust cross-crate graph manifest has invalid crate_count", detail
        if not isinstance(edge_count, int) or edge_count < 0:
            return False, "rust cross-crate graph manifest has invalid edge_count", detail
        return True, "rust cross-crate graph manifest is well formed", detail

    if kind == "go-dlt-audit-enforcement":
        status = _state(payload.get("status") or payload.get("verdict"))
        completion = payload.get("audit_completion")
        completion = completion if isinstance(completion, dict) else {}
        completion_exists = completion.get("exists")
        completion_rc = completion.get("check_rc")
        detail = {
            "status": status or None,
            "audit_completion_exists": completion_exists,
            "audit_completion_check_rc": completion_rc,
        }
        if status not in SUCCESS_STATES:
            return False, "go DLT audit enforcement manifest status is not successful", detail
        if completion_exists is not True:
            return False, "go DLT audit enforcement manifest lacks audit completion evidence", detail
        try:
            rc = int(completion_rc)
        except (TypeError, ValueError):
            return False, "go DLT audit enforcement manifest has invalid audit completion check_rc", detail
        if rc != 0:
            return False, "go DLT audit enforcement manifest audit completion check failed", detail
        return True, "go DLT audit enforcement manifest succeeded", detail

    if kind == "audit-deep-all-manifest":
        profiles = payload.get("profiles")
        if not isinstance(profiles, list) or not profiles:
            return False, "audit-deep-all manifest has no profile executions", {"profile_count": 0}
        malformed_count = sum(1 for row in profiles if not isinstance(row, dict))
        statuses = [_state(row.get("status")) for row in profiles if isinstance(row, dict)]
        profile_names = [
            str(row.get("profile") or "").strip()
            for row in profiles
            if isinstance(row, dict) and str(row.get("profile") or "").strip()
        ]
        raw_expected_profiles = payload.get("expected_profiles")
        if isinstance(raw_expected_profiles, str):
            expected_profiles = [
                item.strip() for item in raw_expected_profiles.split() if item.strip()
            ]
        elif isinstance(raw_expected_profiles, list):
            expected_profiles = [
                str(item).strip() for item in raw_expected_profiles if str(item).strip()
            ]
        else:
            expected_profiles = []
        missing_expected_profiles = [
            profile for profile in expected_profiles if profile not in set(profile_names)
        ]
        unexpected_profiles = [
            profile for profile in profile_names if expected_profiles and profile not in set(expected_profiles)
        ]
        missing_profile_names = [
            idx
            for idx, row in enumerate(profiles)
            if isinstance(row, dict) and not str(row.get("profile") or "").strip()
        ]
        missing_or_invalid_exit_codes = [
            idx
            for idx, row in enumerate(profiles)
            if isinstance(row, dict) and _exit_code(row) is None
        ]
        report_ok, report_info = _backed_evidence_status(
            payload.get("report"),
            manifest_path=manifest_path,
            workspace=workspace,
            run_start=run_start,
        )
        if report_info is None:
            report_info = {"error": "missing_report_path"}
        nonzero_exit_codes = [
            {"profile": str(row.get("profile") or ""), "exit_code": _exit_code(row)}
            for row in profiles
            if isinstance(row, dict) and _exit_code(row) not in {None, 0}
        ]
        profile_evidence_errors: list[dict[str, Any]] = []
        backed_profile_count = 0
        evidence_fields = ("log", "captured_report", "artifact", "artifact_path")
        for idx, row in enumerate(profiles):
            if not isinstance(row, dict) or _state(row.get("status")) not in SUCCESS_STATES:
                continue
            profile_name = str(row.get("profile") or "").strip()
            checked: list[dict[str, Any]] = []
            backed = False
            for field in evidence_fields:
                ok, info = _backed_evidence_status(
                    row.get(field),
                    manifest_path=manifest_path,
                    workspace=workspace,
                    run_start=run_start,
                )
                if info is not None:
                    info["field"] = field
                    checked.append(info)
                if ok:
                    backed = True
            if backed:
                backed_profile_count += 1
            else:
                profile_evidence_errors.append({
                    "profile": profile_name or f"<row-{idx}>",
                    "status": _state(row.get("status")) or "<missing>",
                    "exit_code": _exit_code(row),
                    "evidence_fields_checked": list(evidence_fields),
                    "checked_paths": checked,
                    "reason": "successful audit-deep-all profile has no readable fresh evidence path",
                })
        success_count = sum(1 for status in statuses if status in SUCCESS_STATES)
        failed = [status for status in statuses if status in FAILED_STATES]
        skipped = [status for status in statuses if status in SKIPPED_STATES]
        unknown = [status or "<missing>" for status in statuses if status not in KNOWN_EXECUTION_STATES]
        detail = {
            "profile_count": len(profiles),
            "expected_profile_count": len(expected_profiles),
            "expected_profiles": expected_profiles,
            "profile_names": profile_names,
            "missing_expected_profile_count": len(missing_expected_profiles),
            "missing_expected_profiles": missing_expected_profiles,
            "unexpected_profile_count": len(unexpected_profiles),
            "unexpected_profiles": unexpected_profiles,
            "profile_status_count": len(statuses),
            "profile_success_count": success_count,
            "profile_failed_count": len(failed),
            "profile_skipped_count": len(skipped),
            "profile_unknown_count": len(unknown),
            "malformed_profile_count": malformed_count,
            "missing_profile_name_count": len(missing_profile_names),
            "missing_or_invalid_exit_code_count": len(missing_or_invalid_exit_codes),
            "nonzero_exit_code_count": len(nonzero_exit_codes),
            "nonzero_exit_codes": nonzero_exit_codes,
            "report_evidence_ok": report_ok,
            "report_evidence": report_info,
            "unknown_profile_statuses": unknown,
            "profile_evidence_error_count": len(profile_evidence_errors),
            "profile_evidence_errors": profile_evidence_errors,
            "backed_profile_count": backed_profile_count,
            "missing_profile_evidence_count": len(profile_evidence_errors),
        }
        if malformed_count:
            return False, "audit-deep-all manifest contains malformed profile rows", detail
        if missing_profile_names:
            return False, "audit-deep-all manifest contains profile rows without names", detail
        if missing_or_invalid_exit_codes:
            return False, "audit-deep-all manifest contains profile rows without valid exit codes", detail
        if failed:
            return False, "audit-deep-all manifest contains failed profiles", detail
        if skipped:
            return False, "audit-deep-all manifest contains skipped profiles", detail
        if unknown:
            return False, "audit-deep-all manifest contains unknown profile statuses", detail
        if nonzero_exit_codes:
            return False, "audit-deep-all manifest contains nonzero profile exit codes", detail
        if success_count < 1:
            return False, "audit-deep-all manifest has no successful profiles", detail
        if profile_evidence_errors:
            return False, "audit-deep-all manifest has successful profiles without backed evidence", detail
        if not expected_profiles:
            return False, "audit-deep-all manifest does not declare expected profiles", detail
        if missing_expected_profiles:
            return False, "audit-deep-all manifest is missing expected profiles", detail
        if unexpected_profiles:
            return False, "audit-deep-all manifest contains unexpected profiles", detail
        if not report_ok:
            return False, "audit-deep-all manifest has invalid top-level report path", detail
        return True, "audit-deep-all profile execution succeeded", detail

    if kind == "solidity-deep-all-harnesses":
        harnesses = payload.get("harnesses")
        if not isinstance(harnesses, list) or not harnesses:
            return False, "solidity all-harness manifest has no harness executions", {
                "harness_count": 0,
                "expected_harness_count": _optional_int(payload, "expected_harness_count"),
                "executed_harness_count": _optional_int(payload, "executed_harness_count"),
            }

        status = _state(payload.get("status"))
        try:
            expected_harness_count = int(payload.get("expected_harness_count"))
        except (TypeError, ValueError):
            expected_harness_count = None
        try:
            executed_harness_count = int(payload.get("executed_harness_count"))
        except (TypeError, ValueError):
            executed_harness_count = None
        try:
            blocked_harness_count = int(payload.get("blocked_harness_count"))
        except (TypeError, ValueError):
            blocked_harness_count = None
        invariant_denominator_checks, invariant_denominator_errors = _invariant_denominator_assessment(
            payload,
            require_full_invariant_denominator=require_full_invariant_denominator,
        )

        malformed_harness_count = sum(1 for row in harnesses if not isinstance(row, dict))
        harness_status_errors: list[dict[str, Any]] = []
        harness_manifest_errors: list[dict[str, Any]] = []
        harness_step_errors: list[dict[str, Any]] = []
        missing_engine_errors: list[dict[str, Any]] = []
        engine_status_errors: list[dict[str, Any]] = []
        engine_exit_code_errors: list[dict[str, Any]] = []
        engine_artifact_errors: list[dict[str, Any]] = []
        checked_engine_artifacts: list[dict[str, Any]] = []
        ok_harness_count = 0
        ok_engine_count = 0
        successful_step_slugs: set[str] = set()
        successful_engine_slugs: set[str] = set()

        for idx, harness in enumerate(harnesses):
            if not isinstance(harness, dict):
                continue
            slug = str(harness.get("slug") or f"<row-{idx}>")
            harness_status = _state(harness.get("status"))
            if harness_status in SUCCESS_STATES:
                ok_harness_count += 1
            elif harness_status not in KNOWN_EXECUTION_STATES:
                harness_status_errors.append({
                    "slug": slug,
                    "reason": "harness_status_unknown",
                    "status": harness_status or "<missing>",
                })
            else:
                harness_status_errors.append({
                    "slug": slug,
                    "reason": "harness_status_not_success",
                    "status": harness_status or "<missing>",
                })

            harness_manifest_path = _resolve_artifact_path(
                harness.get("manifest_path"),
                manifest_path=manifest_path,
                workspace=workspace,
            )
            if harness_manifest_path is None:
                harness_manifest_errors.append({
                    "slug": slug,
                    "reason": "missing_manifest_path",
                })
            else:
                rel_harness_manifest = (
                    _rel(harness_manifest_path, workspace)
                    if workspace is not None
                    else harness_manifest_path.as_posix()
                )
                workspace_error = _workspace_path_error(harness_manifest_path, workspace)
                if workspace_error is not None:
                    harness_manifest_errors.append({
                        "slug": slug,
                        "manifest": rel_harness_manifest,
                        "reason": workspace_error,
                    })
                else:
                    harness_payload, harness_error = _load_json(harness_manifest_path)
                    if not isinstance(harness_payload, dict):
                        harness_manifest_errors.append({
                            "slug": slug,
                            "manifest": rel_harness_manifest,
                            "reason": harness_error or "not_json_object",
                        })
                    else:
                        if harness_payload.get("schema") != SOURCE_MANIFEST_SCHEMAS["solidity-deep-audit"]:
                            harness_manifest_errors.append({
                                "slug": slug,
                                "manifest": rel_harness_manifest,
                                "reason": "schema_mismatch",
                                "schema": harness_payload.get("schema"),
                            })
                        if not _workspace_matches(harness_payload.get("workspace"), workspace) if workspace is not None else False:
                            harness_manifest_errors.append({
                                "slug": slug,
                                "manifest": rel_harness_manifest,
                                "reason": "workspace_mismatch",
                                "workspace": harness_payload.get("workspace"),
                            })
                        timestamp_field, harness_timestamp = _manifest_timestamp(harness_payload)
                        if run_start is not None and (
                            harness_timestamp is None or harness_timestamp < run_start
                        ):
                            harness_manifest_errors.append({
                                "slug": slug,
                                "manifest": rel_harness_manifest,
                                "reason": "stale_or_missing_timestamp",
                                "timestamp_field": timestamp_field,
                                "timestamp_utc": _format_timestamp(harness_timestamp),
                            })
                        if run_id:
                            harness_run_id = harness_payload.get("run_id") or harness_payload.get("audit_run_id")
                            if str(harness_run_id or "") != str(run_id):
                                harness_manifest_errors.append({
                                    "slug": slug,
                                    "manifest": rel_harness_manifest,
                                    "reason": "run_id_mismatch",
                                    "run_id": harness_run_id,
                                    "expected_run_id": str(run_id),
                                })
                        step_rows = harness_payload.get("artifacts")
                        if not isinstance(step_rows, list) or not step_rows:
                            harness_step_errors.append({
                                "slug": slug,
                                "manifest": rel_harness_manifest,
                                "reason": "no_artifact_executions",
                            })
                        else:
                            ok_proof_steps: set[str] = set()
                            for step_row in step_rows:
                                if not isinstance(step_row, dict):
                                    harness_step_errors.append({
                                        "slug": slug,
                                        "manifest": rel_harness_manifest,
                                        "reason": "malformed_step_row",
                                    })
                                    continue
                                tool = str(step_row.get("tool") or "").strip()
                                if tool not in SOLIDITY_DEEP_ENGINE_TOOLS:
                                    continue
                                step_status = _state(step_row.get("status"))
                                step_code = _exit_code(step_row)
                                if tool in SOLIDITY_PROOF_ENGINE_TOOLS and step_status in SUCCESS_STATES:
                                    ok_proof_steps.add(tool)
                                if step_status not in KNOWN_EXECUTION_STATES:
                                    harness_step_errors.append({
                                        "slug": slug,
                                        "manifest": rel_harness_manifest,
                                        "tool": tool,
                                        "reason": "step_status_unknown",
                                        "status": step_status or "<missing>",
                                    })
                                elif step_status not in SUCCESS_STATES:
                                    harness_step_errors.append({
                                        "slug": slug,
                                        "manifest": rel_harness_manifest,
                                        "tool": tool,
                                        "reason": "step_status_not_success",
                                        "status": step_status or "<missing>",
                                    })
                                if step_status in SUCCESS_STATES and step_code not in {None, 0}:
                                    harness_step_errors.append({
                                        "slug": slug,
                                        "manifest": rel_harness_manifest,
                                        "tool": tool,
                                        "reason": "step_nonzero_exit_code",
                                        "exit_code": step_code,
                                    })
                                step_artifact_path = _resolve_artifact_path(
                                    step_row.get("artifact"),
                                    manifest_path=harness_manifest_path,
                                    workspace=workspace,
                                )
                                if step_artifact_path is None:
                                    harness_step_errors.append({
                                        "slug": slug,
                                        "manifest": rel_harness_manifest,
                                        "tool": tool,
                                        "reason": "missing_step_artifact_path",
                                    })
                                    continue
                                rel_step_artifact = (
                                    _rel(step_artifact_path, workspace)
                                    if workspace is not None
                                    else step_artifact_path.as_posix()
                                )
                                workspace_error = _workspace_path_error(step_artifact_path, workspace)
                                if workspace_error is not None:
                                    harness_step_errors.append({
                                        "slug": slug,
                                        "manifest": rel_harness_manifest,
                                        "tool": tool,
                                        "artifact": rel_step_artifact,
                                        "reason": workspace_error,
                                    })
                                    continue
                                step_payload, step_error = _load_json(step_artifact_path)
                                if not isinstance(step_payload, dict):
                                    harness_step_errors.append({
                                        "slug": slug,
                                        "manifest": rel_harness_manifest,
                                        "tool": tool,
                                        "artifact": rel_step_artifact,
                                        "reason": step_error or "not_json_object",
                                    })
                                    continue
                                step_payload_status = _state(step_payload.get("status"))
                                step_payload_code = _exit_code(step_payload)
                                step_timestamp_field, step_timestamp = _manifest_timestamp(step_payload)
                                if step_payload.get("schema") != SOLIDITY_STEP_SCHEMA:
                                    harness_step_errors.append({
                                        "slug": slug,
                                        "manifest": rel_harness_manifest,
                                        "tool": tool,
                                        "artifact": rel_step_artifact,
                                        "reason": "step_schema_mismatch",
                                        "schema": step_payload.get("schema"),
                                    })
                                step_payload_tool = str(step_payload.get("tool") or "").strip()
                                if step_payload_tool and step_payload_tool != tool:
                                    harness_step_errors.append({
                                        "slug": slug,
                                        "manifest": rel_harness_manifest,
                                        "tool": tool,
                                        "artifact": rel_step_artifact,
                                        "reason": "step_tool_mismatch",
                                        "step_tool": step_payload_tool,
                                    })
                                if step_payload_status not in KNOWN_EXECUTION_STATES:
                                    harness_step_errors.append({
                                        "slug": slug,
                                        "manifest": rel_harness_manifest,
                                        "tool": tool,
                                        "artifact": rel_step_artifact,
                                        "reason": "step_artifact_status_unknown",
                                        "status": step_payload_status or "<missing>",
                                    })
                                elif step_payload_status not in SUCCESS_STATES:
                                    harness_step_errors.append({
                                        "slug": slug,
                                        "manifest": rel_harness_manifest,
                                        "tool": tool,
                                        "artifact": rel_step_artifact,
                                        "reason": "step_artifact_status_not_success",
                                        "status": step_payload_status or "<missing>",
                                    })
                                if step_payload_status in SUCCESS_STATES and step_payload_code != 0:
                                    harness_step_errors.append({
                                        "slug": slug,
                                        "manifest": rel_harness_manifest,
                                        "tool": tool,
                                        "artifact": rel_step_artifact,
                                        "reason": "step_artifact_nonzero_or_missing_exit_code",
                                        "exit_code": step_payload_code,
                                    })
                                if run_start is not None and (
                                    step_timestamp is None or step_timestamp < run_start
                                ):
                                    harness_step_errors.append({
                                        "slug": slug,
                                        "manifest": rel_harness_manifest,
                                        "tool": tool,
                                        "artifact": rel_step_artifact,
                                        "reason": "step_artifact_stale_or_missing_timestamp",
                                        "timestamp_field": step_timestamp_field,
                                        "timestamp_utc": _format_timestamp(step_timestamp),
                                    })
                                if run_id:
                                    step_run_id = step_payload.get("run_id") or step_payload.get("audit_run_id")
                                    if str(step_run_id or "") != str(run_id):
                                        harness_step_errors.append({
                                            "slug": slug,
                                            "manifest": rel_harness_manifest,
                                            "tool": tool,
                                            "artifact": rel_step_artifact,
                                            "reason": "step_artifact_run_id_mismatch",
                                            "run_id": step_run_id,
                                            "expected_run_id": str(run_id),
                                        })
                            if not ok_proof_steps:
                                harness_step_errors.append({
                                    "slug": slug,
                                    "manifest": rel_harness_manifest,
                                    "reason": "no_successful_proof_engine_step",
                                })
                            else:
                                successful_step_slugs.add(slug)

            engines = harness.get("engines")
            if not isinstance(engines, list):
                missing_engine_errors.append({
                    "slug": slug,
                    "missing_engines": sorted(SOLIDITY_ALL_HARNESS_ENGINES),
                    "reason": "missing_engine_rows",
                })
                continue

            engine_names = {
                str(engine.get("engine") or "").strip()
                for engine in engines
                if isinstance(engine, dict)
            }
            missing_engines = sorted(SOLIDITY_ALL_HARNESS_ENGINES - engine_names)
            if missing_engines:
                missing_engine_errors.append({
                    "slug": slug,
                    "missing_engines": missing_engines,
                    "reason": "missing_required_engine_rows",
                })

            for engine in engines:
                if not isinstance(engine, dict):
                    engine_artifact_errors.append({
                        "slug": slug,
                        "reason": "malformed_engine_row",
                    })
                    continue
                engine_name = str(engine.get("engine") or "").strip()
                engine_status = _state(engine.get("status"))
                engine_code = _exit_code(engine)
                if engine_status not in KNOWN_EXECUTION_STATES:
                    engine_status_errors.append({
                        "slug": slug,
                        "engine": engine_name or "<missing>",
                        "reason": "engine_status_unknown",
                        "status": engine_status or "<missing>",
                    })
                elif engine_status not in SUCCESS_STATES:
                    engine_status_errors.append({
                        "slug": slug,
                        "engine": engine_name or "<missing>",
                        "reason": "engine_status_not_success",
                        "status": engine_status or "<missing>",
                    })
                if engine_status in SUCCESS_STATES and engine_code != 0:
                    engine_exit_code_errors.append({
                        "slug": slug,
                        "engine": engine_name or "<missing>",
                        "exit_code": engine_code,
                    })

                artifact_path = _resolve_artifact_path(
                    engine.get("artifact"),
                    manifest_path=manifest_path,
                    workspace=workspace,
                )
                if artifact_path is None:
                    engine_artifact_errors.append({
                        "slug": slug,
                        "engine": engine_name or "<missing>",
                        "reason": "missing_artifact_path",
                    })
                    continue
                rel_artifact = (
                    _rel(artifact_path, workspace)
                    if workspace is not None
                    else artifact_path.as_posix()
                )
                workspace_error = _workspace_path_error(artifact_path, workspace)
                if workspace_error is not None:
                    engine_artifact_errors.append({
                        "slug": slug,
                        "engine": engine_name or "<missing>",
                        "artifact": rel_artifact,
                        "reason": workspace_error,
                    })
                    continue
                artifact_payload, artifact_error = _load_json(artifact_path)
                if not isinstance(artifact_payload, dict):
                    engine_artifact_errors.append({
                        "slug": slug,
                        "engine": engine_name or "<missing>",
                        "artifact": rel_artifact,
                        "reason": artifact_error or "not_json_object",
                    })
                    continue
                artifact_status = _state(artifact_payload.get("status"))
                artifact_code = _exit_code(artifact_payload)
                timestamp_field, artifact_timestamp = _manifest_timestamp(artifact_payload)
                artifact_engine = str(artifact_payload.get("engine") or "").strip()
                check = {
                    "slug": slug,
                    "engine": engine_name or "<missing>",
                    "artifact": rel_artifact,
                    "status": artifact_status or "<missing>",
                    "exit_code": artifact_code,
                    "timestamp_field": timestamp_field,
                    "timestamp_utc": _format_timestamp(artifact_timestamp),
                    "workspace": artifact_payload.get("workspace"),
                    "run_id": artifact_payload.get("run_id") or artifact_payload.get("audit_run_id"),
                }
                checked_engine_artifacts.append(check)
                reasons: list[str] = []
                if artifact_payload.get("schema_version") != DEEP_ENGINE_ARTIFACT_SCHEMA:
                    reasons.append("schema_mismatch")
                if workspace is not None and not _workspace_matches(artifact_payload.get("workspace"), workspace):
                    reasons.append("workspace_mismatch")
                if engine_name and artifact_engine and artifact_engine != engine_name:
                    reasons.append("engine_mismatch")
                if artifact_status not in KNOWN_EXECUTION_STATES:
                    reasons.append("status_unknown")
                if artifact_status in FAILED_STATES:
                    reasons.append("status_failed")
                if artifact_status in SKIPPED_STATES:
                    reasons.append("status_skipped")
                if artifact_status in NO_EXECUTION_STATES:
                    # Engine ran but execution floor unmet: no symbolic checks or
                    # fuzz tests ran. Not a success; provides no evidence.
                    reasons.append("status_no_execution")
                if artifact_status in SUCCESS_STATES and artifact_code != 0:
                    reasons.append("nonzero_or_missing_exit_code")
                artifact_run_id = artifact_payload.get("run_id") or artifact_payload.get("audit_run_id")
                if run_id and str(artifact_run_id or "") != str(run_id):
                    reasons.append("run_id_mismatch")
                if run_start is not None and (
                    artifact_timestamp is None or artifact_timestamp < run_start
                ):
                    reasons.append("stale_or_missing_timestamp")
                if reasons:
                    error = dict(check)
                    error["reasons"] = reasons
                    engine_artifact_errors.append(error)
                else:
                    ok_engine_count += 1
                    successful_engine_slugs.add(slug)

        advisory_harness_step_errors = [
            error
            for error in harness_step_errors
            if str(error.get("slug") or "") in successful_step_slugs
            and str(error.get("reason") or "")
            in {"step_status_not_success", "step_artifact_status_not_success"}
        ]
        hard_harness_step_errors = [
            error for error in harness_step_errors if error not in advisory_harness_step_errors
        ]
        advisory_engine_status_errors: list[dict[str, Any]] = []
        hard_engine_status_errors = list(engine_status_errors)
        advisory_engine_artifact_errors: list[dict[str, Any]] = []
        hard_engine_artifact_errors = list(engine_artifact_errors)

        detail = {
            "status": status or None,
            "expected_harness_count": expected_harness_count,
            "executed_harness_count": executed_harness_count,
            "blocked_harness_count": blocked_harness_count,
            "status_counts": payload.get("status_counts") if isinstance(payload.get("status_counts"), dict) else None,
            "generated_per_function_harness_count": _optional_int(
                payload, "generated_per_function_harness_count"
            ),
            "executed_generated_harness_count": _optional_int(
                payload, "executed_generated_harness_count"
            ),
            "available_engine_harness_count": _optional_int(
                payload, "available_engine_harness_count"
            ),
            "executed_engine_harness_count": _optional_int(
                payload, "executed_engine_harness_count"
            ),
            "invariant_denominator_check_count": len(invariant_denominator_checks),
            "invariant_denominator_checks": invariant_denominator_checks,
            "invariant_denominator_error_count": len(invariant_denominator_errors),
            "invariant_denominator_errors": invariant_denominator_errors,
            "harness_count": len(harnesses),
            "ok_harness_count": ok_harness_count,
            "ok_engine_count": ok_engine_count,
            "malformed_harness_count": malformed_harness_count,
            "harness_status_error_count": len(harness_status_errors),
            "harness_status_errors": harness_status_errors,
            "harness_manifest_error_count": len(harness_manifest_errors),
            "harness_manifest_errors": harness_manifest_errors,
            "harness_step_error_count": len(hard_harness_step_errors),
            "harness_step_errors": hard_harness_step_errors,
            "advisory_harness_step_error_count": len(advisory_harness_step_errors),
            "advisory_harness_step_errors": advisory_harness_step_errors,
            "missing_engine_error_count": len(missing_engine_errors),
            "missing_engine_errors": missing_engine_errors,
            "engine_status_error_count": len(hard_engine_status_errors),
            "engine_status_errors": hard_engine_status_errors,
            "advisory_engine_status_error_count": len(advisory_engine_status_errors),
            "advisory_engine_status_errors": advisory_engine_status_errors,
            "engine_exit_code_error_count": len(engine_exit_code_errors),
            "engine_exit_code_errors": engine_exit_code_errors,
            "engine_artifact_check_count": len(checked_engine_artifacts),
            "engine_artifact_checks": checked_engine_artifacts,
            "engine_artifact_error_count": len(hard_engine_artifact_errors),
            "engine_artifact_errors": hard_engine_artifact_errors,
            "advisory_engine_artifact_error_count": len(advisory_engine_artifact_errors),
            "advisory_engine_artifact_errors": advisory_engine_artifact_errors,
        }
        if status not in KNOWN_EXECUTION_STATES:
            return False, "solidity all-harness manifest status is unknown", detail
        if status not in SUCCESS_STATES:
            return False, "solidity all-harness manifest status is not successful", detail
        if blocked_harness_count is not None and blocked_harness_count > 0:
            return False, "solidity all-harness manifest contains blocked harnesses", detail
        if expected_harness_count == 0:
            return False, "solidity all-harness manifest has no harness executions", detail
        if expected_harness_count is None or expected_harness_count < 0:
            return False, "solidity all-harness manifest has invalid expected harness count", detail
        if executed_harness_count is None or executed_harness_count != expected_harness_count:
            return False, "solidity all-harness manifest did not execute every expected harness", detail
        if len(harnesses) != expected_harness_count:
            return False, "solidity all-harness manifest row count does not match expected harness count", detail
        if malformed_harness_count:
            return False, "solidity all-harness manifest contains malformed harness rows", detail
        if harness_status_errors:
            return False, "solidity all-harness manifest contains non-success harness rows", detail
        if harness_manifest_errors:
            return False, "solidity all-harness manifest has invalid per-harness manifests", detail
        if hard_harness_step_errors:
            return False, "solidity all-harness manifest has invalid per-harness step artifacts", detail
        if missing_engine_errors:
            return False, "solidity all-harness manifest is missing required engine rows", detail
        if hard_engine_status_errors:
            return False, "solidity all-harness manifest contains non-success engine rows", detail
        if engine_exit_code_errors:
            return False, "solidity all-harness manifest contains nonzero engine exit codes", detail
        if hard_engine_artifact_errors:
            return False, "solidity all-harness manifest has invalid engine artifacts", detail
        if invariant_denominator_errors:
            return False, "solidity all-harness manifest invariant harness denominator exceeds executed counts", detail
        if ok_engine_count < 1:
            return False, "solidity all-harness manifest has no successful engine artifact", detail
        return True, "solidity all-harness engine artifacts succeeded", detail

    if kind == "solidity-deep-audit":
        artifacts = payload.get("artifacts")
        if not isinstance(artifacts, list) or not artifacts:
            return False, "solidity deep manifest has no artifact executions", {"artifact_count": 0}
        payload, per_function_halmos_detail = _with_per_function_halmos_denominator(
            payload,
            workspace=workspace,
            run_id=run_id,
            run_start=run_start,
        )
        invariant_denominator_checks, invariant_denominator_errors = _invariant_denominator_assessment(
            payload,
            require_full_invariant_denominator=require_full_invariant_denominator,
        )
        engine_statuses: dict[str, str] = {}
        nonzero_engine_exit_codes: list[dict[str, Any]] = []
        step_schema_errors: list[dict[str, Any]] = []
        step_status_errors: list[dict[str, Any]] = []
        step_exit_code_errors: list[dict[str, Any]] = []
        step_freshness_errors: list[dict[str, Any]] = []
        step_run_id_errors: list[dict[str, Any]] = []
        missing_step_artifacts: list[dict[str, Any]] = []
        runner_artifact_checks: list[dict[str, Any]] = []
        runner_artifact_errors: list[dict[str, Any]] = []
        runner_artifact_no_target: list[dict[str, Any]] = []
        step_artifact_no_target: list[dict[str, Any]] = []
        valid_runner_proof_engines: set[str] = set()
        valid_step_only_proof_engines: set[str] = set()
        for artifact in artifacts:
            if not isinstance(artifact, dict):
                continue
            tool = str(artifact.get("tool") or "").strip()
            if tool in SOLIDITY_DEEP_ENGINE_TOOLS:
                status = _state(artifact.get("status"))
                engine_statuses[tool] = status
                code = _exit_code(artifact)
                if status not in KNOWN_EXECUTION_STATES:
                    step_status_errors.append({
                        "tool": tool,
                        "artifact": artifact.get("artifact"),
                        "status": status or "<missing>",
                        "reason": "manifest_engine_status_unknown",
                    })
                elif status not in SUCCESS_STATES:
                    step_status_errors.append({
                        "tool": tool,
                        "artifact": artifact.get("artifact"),
                        "status": status or "<missing>",
                        "reason": "manifest_engine_status_not_success",
                    })
                if status in SUCCESS_STATES and code not in {None, 0}:
                    nonzero_engine_exit_codes.append({"tool": tool, "exit_code": code})
                artifact_path = _resolve_artifact_path(artifact.get("artifact"), manifest_path, workspace)
                if artifact_path is None:
                    if status in KNOWN_EXECUTION_STATES:
                        missing_step_artifacts.append({
                            "tool": tool,
                            "status": status or "<missing>",
                            "exit_code": code,
                            "reason": "recognized Solidity deep-engine row has no artifact path",
                        })
                    continue
                rel_artifact = (
                    _rel(artifact_path, workspace)
                    if workspace is not None
                    else artifact_path.as_posix()
                )
                workspace_error = _workspace_path_error(artifact_path, workspace)
                if workspace_error is not None:
                    step_schema_errors.append({
                        "tool": tool,
                        "artifact": rel_artifact,
                        "error": workspace_error,
                    })
                    continue
                step_payload, step_error = _load_json(artifact_path)
                if not isinstance(step_payload, dict):
                    step_schema_errors.append({
                        "tool": tool,
                        "artifact": rel_artifact,
                        "error": step_error or "not_json_object",
                    })
                    continue
                step_schema = step_payload.get("schema")
                if step_schema != SOLIDITY_STEP_SCHEMA:
                    step_schema_errors.append({
                        "tool": tool,
                        "artifact": rel_artifact,
                        "schema": step_schema,
                        "expected_schema": SOLIDITY_STEP_SCHEMA,
                    })
                step_tool = str(step_payload.get("tool") or "").strip()
                if step_tool and step_tool != tool:
                    step_schema_errors.append({
                        "tool": tool,
                        "artifact": rel_artifact,
                        "step_tool": step_tool,
                        "expected_tool": tool,
                    })
                step_status = _state(step_payload.get("status"))
                if step_status not in KNOWN_EXECUTION_STATES:
                    step_status_errors.append({
                        "tool": tool,
                        "artifact": rel_artifact,
                        "status": step_status or "<missing>",
                        "reason": "step_status_unknown",
                    })
                elif step_status not in SUCCESS_STATES:
                    step_status_errors.append({
                        "tool": tool,
                        "artifact": rel_artifact,
                        "status": step_status or "<missing>",
                        "reason": "step_status_not_success",
                    })
                step_code = _exit_code(step_payload)
                if step_status in SUCCESS_STATES and step_code != 0:
                    step_exit_code_errors.append({
                        "tool": tool,
                        "artifact": rel_artifact,
                        "exit_code": step_code,
                    })
                step_no_target_reasons = _deep_engine_no_target_reasons(step_payload)
                if step_no_target_reasons and tool in SOLIDITY_PROOF_ENGINE_TOOLS:
                    step_artifact_no_target.append({
                        "tool": tool,
                        "artifact": rel_artifact,
                        "reasons": step_no_target_reasons,
                    })
                if run_start is not None:
                    timestamp_field, step_timestamp = _manifest_timestamp(step_payload)
                    if step_timestamp is None or step_timestamp < run_start:
                        step_freshness_errors.append({
                            "tool": tool,
                            "artifact": rel_artifact,
                            "timestamp_field": timestamp_field,
                            "timestamp_utc": _format_timestamp(step_timestamp),
                        })
                if run_id:
                    step_run_id = step_payload.get("run_id") or step_payload.get("audit_run_id")
                    if str(step_run_id or "") != str(run_id):
                        step_run_id_errors.append({
                            "tool": tool,
                            "artifact": rel_artifact,
                            "run_id": step_run_id,
                            "expected_run_id": str(run_id),
                        })
                runner_rel = SOLIDITY_RUNNER_ENGINE_ARTIFACTS.get(tool)
                if runner_rel and status in SUCCESS_STATES and step_status in SUCCESS_STATES:
                    runner_error: dict[str, Any] | None = None
                    if workspace is None:
                        runner_error = {
                            "tool": tool,
                            "artifact": runner_rel,
                            "reason": "workspace_required",
                        }
                    else:
                        runner_path = workspace / runner_rel
                        rel_runner = _rel(runner_path, workspace)
                        workspace_error = _workspace_path_error(runner_path, workspace)
                        if workspace_error is not None:
                            runner_error = {
                                "tool": tool,
                                "artifact": rel_runner,
                                "reason": workspace_error,
                            }
                        else:
                            runner_payload, runner_load_error = _load_json(runner_path)
                            if not isinstance(runner_payload, dict):
                                runner_error = {
                                    "tool": tool,
                                    "artifact": rel_runner,
                                    "reason": runner_load_error or "not_json_object",
                                }
                            else:
                                runner_status = _state(runner_payload.get("status"))
                                runner_code = _exit_code(runner_payload)
                                timestamp_field, runner_timestamp = _manifest_timestamp(runner_payload)
                                runner_run_id = runner_payload.get("run_id") or runner_payload.get("audit_run_id")
                                runner_engine = str(runner_payload.get("engine") or "").strip()
                                no_target_reasons = _deep_engine_no_target_reasons(runner_payload)
                                check = {
                                    "tool": tool,
                                    "artifact": rel_runner,
                                    "schema_version": runner_payload.get("schema_version"),
                                    "engine": runner_engine or None,
                                    "status": runner_status or "<missing>",
                                    "exit_code": runner_code,
                                    "workspace": runner_payload.get("workspace"),
                                    "run_id": runner_run_id,
                                    "timestamp_field": timestamp_field,
                                    "timestamp_utc": _format_timestamp(runner_timestamp),
                                    "no_target_reasons": no_target_reasons,
                                }
                                runner_artifact_checks.append(check)
                                reasons: list[str] = []
                                if runner_payload.get("schema_version") != DEEP_ENGINE_ARTIFACT_SCHEMA:
                                    reasons.append("schema_mismatch")
                                if not _workspace_matches(runner_payload.get("workspace"), workspace):
                                    reasons.append("workspace_mismatch")
                                expected_engine = tool.split("-", 1)[0]
                                if runner_engine and runner_engine != expected_engine:
                                    reasons.append("engine_mismatch")
                                if runner_status not in KNOWN_EXECUTION_STATES:
                                    reasons.append("status_unknown")
                                if runner_status in FAILED_STATES:
                                    reasons.append("status_failed")
                                if runner_status in SKIPPED_STATES:
                                    reasons.append("status_skipped")
                                if runner_status in NO_EXECUTION_STATES:
                                    # Engine ran (rc=0) but the execution floor was
                                    # not met: no symbolic checks for halmos, no
                                    # property/fuzz calls for echidna/medusa. This
                                    # is not a success - it provides no evidence.
                                    reasons.append("status_no_execution")
                                if runner_status in SUCCESS_STATES and runner_code != 0:
                                    reasons.append("nonzero_or_missing_exit_code")
                                if run_start is not None and (
                                    runner_timestamp is None or runner_timestamp < run_start
                                ):
                                    reasons.append("stale_or_missing_timestamp")
                                if run_id and str(runner_run_id or "") != str(run_id):
                                    reasons.append("run_id_mismatch")
                                if reasons:
                                    runner_error = dict(check)
                                    runner_error["reasons"] = reasons
                                elif no_target_reasons:
                                    runner_artifact_no_target.append(dict(check))
                                elif tool in SOLIDITY_PROOF_ENGINE_TOOLS:
                                    valid_runner_proof_engines.add(tool)
                    if runner_error is not None:
                        runner_artifact_errors.append(runner_error)
                elif (
                    tool in SOLIDITY_PROOF_ENGINE_TOOLS
                    and status in SUCCESS_STATES
                    and step_status in SUCCESS_STATES
                    and step_code == 0
                    and not step_no_target_reasons
                ):
                    valid_step_only_proof_engines.add(tool)
        ok_engines = sorted(
            tool for tool, status in engine_statuses.items() if status in SUCCESS_STATES
        )
        failed_engines = sorted(
            tool for tool, status in engine_statuses.items() if status in FAILED_STATES
        )
        skipped_engines = sorted(
            tool for tool, status in engine_statuses.items() if status in SKIPPED_STATES
        )
        unknown_engines = sorted(
            tool for tool, status in engine_statuses.items() if status not in KNOWN_EXECUTION_STATES
        )
        ok_proof_engines = sorted(
            tool
            for tool, status in engine_statuses.items()
            if tool in SOLIDITY_PROOF_ENGINE_TOOLS and status in SUCCESS_STATES
        )
        valid_proof_engines = sorted(valid_runner_proof_engines | valid_step_only_proof_engines)
        # Raw per-function Halmos execution is only a diagnostic precondition.
        # Proof credit requires per_function_halmos_proof_ok below.
        per_function_halmos_execution_ok = bool(
            isinstance(per_function_halmos_detail, dict)
            and per_function_halmos_detail.get("errors") == []
            and per_function_halmos_detail.get("expected_invocation_count") is not None
            and int(per_function_halmos_detail.get("expected_invocation_count") or 0) > 0
            and per_function_halmos_detail.get("executed_invocation_count")
            == per_function_halmos_detail.get("expected_invocation_count")
            and per_function_halmos_detail.get("ok_invocation_count")
            == per_function_halmos_detail.get("expected_invocation_count")
            and per_function_halmos_detail.get("all_invocation_artifacts_valid") is True
        )
        proof_gate_detail = _engine_harness_proof_check(workspace)
        proof_gate_proven = (
            proof_gate_detail.get("proven", [])
            if isinstance(proof_gate_detail, dict)
            else []
        )
        proof_gate_passed_per_function = bool(
            isinstance(proof_gate_detail, dict)
            and proof_gate_detail.get("verdict") == "pass-engine-harness-proof"
            and any(
                str(label).startswith("solidity-per-function-halmos:")
                for label in proof_gate_proven
            )
        )
        per_function_halmos_proof_ok = bool(
            per_function_halmos_execution_ok
            and proof_gate_passed_per_function
        )
        # Honest partial-proof path: the full denominator did NOT complete (some
        # per-function harnesses could not build, and/or the aggregate engine
        # root failed to compile), but the proof gate confirms a real,
        # non-advisory, gate-proven floor of symbolic invocations executed
        # successfully. The proof gate sets `partial=True` ONLY when at least one
        # genuinely-proven (non-`assert(true)`-scaffold) invocation ran, so this
        # never certifies a workspace whose only "ok" runs are advisory skeletons.
        per_function_halmos_proof_partial_ok = bool(
            proof_gate_passed_per_function
            and isinstance(proof_gate_detail, dict)
            and proof_gate_detail.get("partial") is True
        )
        detail = {
            "artifact_count": len(artifacts),
            "per_function_halmos_manifest": per_function_halmos_detail,
            "per_function_halmos_execution_ok": per_function_halmos_execution_ok,
            "per_function_halmos_proof_gate": proof_gate_detail,
            "per_function_halmos_proof_ok": per_function_halmos_proof_ok,
            "per_function_halmos_proof_partial_ok": per_function_halmos_proof_partial_ok,
            "generated_per_function_harness_count": _optional_int(
                payload, "generated_per_function_harness_count"
            ),
            "executed_generated_harness_count": _optional_int(
                payload, "executed_generated_harness_count"
            ),
            "available_engine_harness_count": _optional_int(
                payload, "available_engine_harness_count"
            ),
            "executed_engine_harness_count": _optional_int(
                payload, "executed_engine_harness_count"
            ),
            "invariant_denominator_check_count": len(invariant_denominator_checks),
            "invariant_denominator_checks": invariant_denominator_checks,
            "invariant_denominator_error_count": len(invariant_denominator_errors),
            "invariant_denominator_errors": invariant_denominator_errors,
            "engine_statuses": engine_statuses,
            "ok_deep_engines": ok_engines,
            "ok_proof_engines": ok_proof_engines,
            "valid_load_bearing_proof_engines": valid_proof_engines,
            "valid_load_bearing_proof_engine_count": len(valid_proof_engines),
            "failed_deep_engines": failed_engines,
            "skipped_deep_engines": skipped_engines,
            "unknown_deep_engines": unknown_engines,
            "nonzero_engine_exit_code_count": len(nonzero_engine_exit_codes),
            "nonzero_engine_exit_codes": nonzero_engine_exit_codes,
            "step_schema_error_count": len(step_schema_errors),
            "step_schema_errors": step_schema_errors,
            "step_status_error_count": len(step_status_errors),
            "step_status_errors": step_status_errors,
            "step_exit_code_error_count": len(step_exit_code_errors),
            "step_exit_code_errors": step_exit_code_errors,
            "step_freshness_error_count": len(step_freshness_errors),
            "step_freshness_errors": step_freshness_errors,
            "step_run_id_error_count": len(step_run_id_errors),
            "step_run_id_errors": step_run_id_errors,
            "step_no_target_count": len(step_artifact_no_target),
            "step_no_target_artifacts": step_artifact_no_target,
            "missing_step_artifact_count": len(missing_step_artifacts),
            "missing_step_artifacts": missing_step_artifacts,
            "runner_artifact_check_count": len(runner_artifact_checks),
            "runner_artifact_checks": runner_artifact_checks,
            "runner_artifact_error_count": len(runner_artifact_errors),
            "runner_artifact_errors": runner_artifact_errors,
            "runner_artifact_no_target_count": len(runner_artifact_no_target),
            "runner_artifact_no_target": runner_artifact_no_target,
        }
        # Partial-execution tolerance: when the per-function Halmos proof gate
        # has confirmed a REAL (non-advisory, gate-proven) floor of symbolic
        # invocations executed successfully, the *build/engine-error* failures of
        # the aggregate engine roots and any blocked/failed deep-engine step (the
        # aggregate harness root could not compile) are tolerable - genuine deep
        # symbolic execution still happened. INTEGRITY violations (stale
        # artifacts, run-id mismatch, schema mismatch, nonzero exit codes on a
        # claimed-success artifact) are NEVER tolerable: those indicate fabricated
        # or cross-run evidence, not an honest build failure. This keeps the cert
        # honest: it certifies real partial execution but refuses tampered state.
        partial_ok = bool(per_function_halmos_proof_partial_ok)

        def _runner_errors_are_build_class(errs: list[dict[str, Any]]) -> bool:
            integrity_reasons = {
                "stale_or_missing_timestamp",
                "run_id_mismatch",
                "schema_mismatch",
                "workspace_mismatch",
                "engine_mismatch",
                "nonzero_or_missing_exit_code",
                "not_json_object",
            }
            for err in errs:
                reasons = err.get("reasons") or []
                if isinstance(reasons, str):
                    reasons = [reasons]
                # An empty reason set (bare runner_error from load failure) is
                # treated as build-class only when it carries no integrity flag.
                if any(r in integrity_reasons for r in reasons):
                    return False
            return True

        if step_schema_errors:
            return False, "solidity deep manifest has invalid deep-engine step artifacts", detail
        if step_status_errors and not partial_ok:
            return False, "solidity deep manifest step artifacts did not all succeed", detail
        if step_exit_code_errors:
            return False, "solidity deep manifest step artifacts have nonzero or missing exit codes", detail
        if step_freshness_errors:
            return False, "solidity deep manifest step artifacts are stale", detail
        if step_run_id_errors:
            return False, "solidity deep manifest step artifacts are not from the current run", detail
        if nonzero_engine_exit_codes:
            return False, "solidity deep manifest contains nonzero deep-engine exit codes", detail
        if failed_engines and not partial_ok:
            return False, "solidity deep manifest contains failed deep-engine artifacts", detail
        if skipped_engines and not partial_ok:
            return False, "solidity deep manifest contains skipped deep-engine artifacts", detail
        if unknown_engines:
            return False, "solidity deep manifest contains unknown deep-engine artifact statuses", detail
        if missing_step_artifacts and not partial_ok:
            return False, "solidity deep manifest has deep-engine rows without backed step artifacts", detail
        if runner_artifact_errors and not (
            partial_ok and _runner_errors_are_build_class(runner_artifact_errors)
        ):
            return False, "solidity deep manifest runner artifacts did not all succeed", detail
        if invariant_denominator_errors:
            return False, "solidity deep manifest invariant harness denominator exceeds executed counts", detail
        if (
            not valid_proof_engines
            and not per_function_halmos_proof_ok
            and not per_function_halmos_proof_partial_ok
        ):
            return (
                False,
                "solidity deep manifest has no load-bearing proof artifact; "
                "per-function Halmos requires engine-harness-proof-check pass",
                detail,
            )
        if partial_ok and not (valid_proof_engines or per_function_halmos_proof_ok):
            return (
                True,
                "solidity deep-engine partial proof: real per-function symbolic "
                "execution succeeded (aggregate engine root build incomplete)",
                detail,
            )
        return True, "solidity deep-engine artifacts succeeded", detail

    status = _state(payload.get("status") or payload.get("overall_status"))
    if status in FAILED_STATES:
        return False, f"manifest status is {status}", {"status": status}
    if status in NO_EXECUTION_STATES:
        return False, f"manifest status is {status} (non-certifying, execution floor not met)", {"status": status}
    if status in SKIPPED_STATES:
        return False, f"manifest status is {status}", {"status": status}
    if status and status not in KNOWN_EXECUTION_STATES:
        return False, f"manifest status is unknown: {status}", {"status": status}
    return True, "legacy manifest has no failure marker", {"status": status or None}


def _source_manifest_status(
    path: Path,
    kind: str,
    workspace: Path,
    run_start: datetime,
    run_id: Any,
    *,
    require_full_invariant_denominator: bool = False,
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "kind": kind,
        "path": _rel(path, workspace),
        "exists": path.is_file(),
        "workspace_matches": None,
        "timestamp_field": None,
        "timestamp_utc": None,
        "mtime_utc": None,
        "fresh_by_timestamp": False,
        "fresh_by_mtime": False,
        "fresh_by_run_id": False,
        "fresh": False,
    }
    try:
        stat = path.stat()
    except FileNotFoundError:
        row["error"] = "missing"
        return row
    except OSError as exc:
        row["error"] = f"stat_error:{exc.__class__.__name__}"
        return row

    mtime = datetime.fromtimestamp(stat.st_mtime, timezone.utc)
    row["mtime_utc"] = _format_timestamp(mtime)
    payload, error = _load_json(path)
    if not isinstance(payload, dict):
        row["error"] = error or "not_json_object"
        return row

    manifest_schema = _manifest_schema(payload)
    row["schema"] = manifest_schema
    expected_schema = SOURCE_MANIFEST_SCHEMAS.get(kind)
    row["expected_schema"] = expected_schema
    row["schema_matches"] = bool(expected_schema is None or manifest_schema == expected_schema)
    manifest_workspace = _manifest_workspace(payload)
    row["workspace"] = manifest_workspace
    row["workspace_matches"] = _workspace_matches(manifest_workspace, workspace)
    field, timestamp = _manifest_timestamp(payload)
    row["timestamp_field"] = field
    row["timestamp_utc"] = _format_timestamp(timestamp)
    manifest_run_id = _manifest_run_id(payload)
    row["run_id"] = manifest_run_id
    row["fresh_by_timestamp"] = bool(timestamp is not None and timestamp >= run_start)
    row["fresh_by_mtime"] = bool(timestamp is None and mtime >= run_start)
    row["run_id_matches_current"] = bool(
        run_id
        and manifest_run_id
        and str(run_id) == str(manifest_run_id)
    )
    row["fresh_by_run_id"] = bool(
        timestamp is None
        and row["run_id_matches_current"]
    )
    row["run_id_mismatch"] = bool(run_id and manifest_run_id and str(run_id) != str(manifest_run_id))
    row["run_id_missing"] = bool(run_id and not manifest_run_id)
    if not row["schema_matches"]:
        execution_ok = False
        execution_reason = "source manifest schema mismatch"
        execution_detail = {
            "schema": manifest_schema,
            "expected_schema": expected_schema,
        }
    else:
        execution_ok, execution_reason, execution_detail = _manifest_execution_assessment(
            payload,
            kind,
            manifest_path=path,
            workspace=workspace,
            run_start=run_start,
            run_id=run_id,
            require_full_invariant_denominator=require_full_invariant_denominator,
        )
    row["execution_ok"] = execution_ok
    row["execution_reason"] = execution_reason
    row["execution_detail"] = execution_detail
    row["completion_source_eligible"] = _completion_source_eligible(kind, manifest_run_id, run_id)
    row["fresh"] = bool(
        row["completion_source_eligible"]
        and row["workspace_matches"]
        and row["execution_ok"]
        and not row["run_id_mismatch"]
        and not row["run_id_missing"]
        and (row["fresh_by_timestamp"] or row["fresh_by_mtime"])
    )
    return row


def _source_manifest_blocks_fresh_pass(row: dict[str, Any]) -> bool:
    if not row.get("exists") or not row.get("workspace_matches"):
        return False
    if not row.get("completion_source_eligible"):
        return False
    if row.get("kind") == "legacy-audit-deep-manifest":
        return False
    if row.get("fresh"):
        return False
    if row.get("kind") == "solidity-deep-all-harnesses":
        detail = row.get("execution_detail")
        if (
            isinstance(detail, dict)
            and detail.get("expected_harness_count") == 0
            and row.get("execution_reason") == "solidity all-harness manifest has no harness executions"
        ):
            return False
    current_signal = bool(
        row.get("fresh_by_timestamp")
        or row.get("fresh_by_mtime")
        or row.get("fresh_by_run_id")
    )
    if (
        row.get("completion_source_eligible")
        and row.get("run_id_matches_current")
        and not (row.get("fresh_by_timestamp") or row.get("fresh_by_mtime"))
    ):
        return True
    if not current_signal:
        if row.get("run_id_matches_current") and not row.get("execution_ok"):
            reason = str(row.get("execution_reason") or "").lower()
            return any(
                token in reason
                for token in (
                    "failed",
                    "failure",
                    "timeout",
                    "nonzero",
                    "schema mismatch",
                    "unknown",
                    "skipped",
                    "status",
                )
            )
        return False
    return bool(
        not row.get("execution_ok")
        or row.get("run_id_mismatch")
        or row.get("run_id_missing")
    )


# Build-class / partial-execution tolerance (G9-honest). A source deep-engine
# manifest that PHYSICALLY ran this run (fresh-by-timestamp/mtime + matching
# run_id) but failed for build/partial reasons (harness root unbuildable, no
# harness executions, some per-function invariants partial) is HONEST partial
# coverage - not fabricated, cross-run, or stale evidence. Such a row may be
# tolerated as a non-fatal advisory so the pipeline completes and the hunt/queue
# findings stand. INTEGRITY violations (run_id/schema/workspace/exit-code
# mismatch, stale reuse) are NEVER tolerated. Whitelist semantics: anything not
# clearly ran-this-run-build-class stays blocking.
_BUILD_CLASS_FAILURE_TOKENS = (
    "did not all succeed",
    "no harness executions",
    "has no harness",
    "blocked",
    "partial",
    "engine-error",
    "engine error",
    "build",
    "compile",
    "no execution",
    "no-execution",
    "unbuildable",
    "timeout",
)
_INTEGRITY_FAILURE_TOKENS = (
    "schema",
    "workspace",
    "run_id",
    "run id",
    "exit code",
    "exit-code",
    "returncode",
    "nonzero",
    "mismatch",
    "stale",
)


def _row_failure_is_build_class_ran_this_run(row: dict[str, Any]) -> bool:
    """True iff the row physically ran this run and failed only for build/partial
    reasons (no integrity violation)."""
    if not (row.get("fresh_by_timestamp") or row.get("fresh_by_mtime")):
        return False
    if not row.get("run_id_matches_current"):
        return False
    if row.get("run_id_mismatch") or row.get("run_id_missing"):
        return False
    if row.get("schema_matches") is False:
        return False
    if row.get("workspace_matches") is False:
        return False
    reason = str(row.get("execution_reason") or "").lower()
    if any(tok in reason for tok in _INTEGRITY_FAILURE_TOKENS):
        return False
    return any(tok in reason for tok in _BUILD_CLASS_FAILURE_TOKENS)


def check_freshness(
    workspace: Path,
    *,
    audit_run_manifest: Path,
    require_fresh_since: str | None = None,
    allow_skip_key: str = DEFAULT_SKIP_KEY,
    run_id: str | None = None,
    require_full_invariant_denominator: bool = False,
    tolerate_build_class_partial: bool = False,
) -> dict[str, Any]:
    explicit_start = _parse_timestamp(require_fresh_since) if require_fresh_since else None
    requested_run_id = str(run_id) if run_id else None
    start_meta: dict[str, Any] = {}
    if explicit_start is None:
        start_meta = _latest_audit_run_start(
            audit_run_manifest,
            workspace,
            run_id=requested_run_id,
        )
        run_start = start_meta.get("started_at")
        if not isinstance(run_start, datetime):
            verdict = (
                "fail-current-run-start-not-found"
                if requested_run_id
                else "fail-no-current-run-start"
            )
            return {
                "schema": FRESHNESS_SCHEMA,
                "workspace": str(workspace),
                "verdict": verdict,
                "ok": False,
                "audit_run_manifest": _rel(audit_run_manifest, workspace),
                "reason": start_meta.get("error", "no_start_event"),
                "run_id": requested_run_id,
                "source_manifests": [],
                "skip": None,
            }
        run_id = start_meta.get("run_id")
        start_line = start_meta.get("line_no")
        if not run_id:
            return {
                "schema": FRESHNESS_SCHEMA,
                "workspace": str(workspace),
                "verdict": "fail-current-run-missing-run-id",
                "ok": False,
                "audit_run_manifest": _rel(audit_run_manifest, workspace),
                "reason": "latest audit-run-full start row has no run_id; current-run deep freshness cannot be proven",
                "run_start_utc": _format_timestamp(run_start),
                "run_start_line": start_line,
                "run_id": None,
                "source_manifests": [],
                "skip": None,
            }
    else:
        if requested_run_id is None:
            return {
                "schema": FRESHNESS_SCHEMA,
                "workspace": str(workspace),
                "verdict": "fail-current-run-missing-run-id",
                "ok": False,
                "audit_run_manifest": _rel(audit_run_manifest, workspace),
                "reason": "--require-fresh-since requires --run-id; current-run deep freshness cannot be proven",
                "run_start_utc": _format_timestamp(explicit_start),
                "run_start_line": None,
                "run_id": None,
                "source_manifests": [],
                "skip": None,
            }
        run_start = explicit_start
        run_id = requested_run_id
        start_line = None

    source_manifests = [
        _source_manifest_status(
            workspace / rel,
            kind,
            workspace,
            run_start,
            run_id,
            require_full_invariant_denominator=require_full_invariant_denominator,
        )
        for rel, kind in SOURCE_MANIFESTS
    ]
    fresh = [row for row in source_manifests if row.get("fresh")]
    blocking_source_manifests = [
        row for row in source_manifests if _source_manifest_blocks_fresh_pass(row)
    ]
    skip = _typed_skip_reason(workspace, allow_skip_key, run_start, run_id) if allow_skip_key else None
    valid_skip = (
        skip is not None
        and bool(skip.get("reason"))
        and not skip.get("error")
        and bool(skip.get("fresh_for_run"))
    )
    if valid_skip:
        for row in source_manifests:
            if (
                row.get("exists")
                and row.get("workspace_matches")
                and row.get("kind") != "legacy-audit-deep-manifest"
                and not row.get("fresh")
                and row.get("run_id_matches_current")
                and not row.get("execution_ok")
                and row not in blocking_source_manifests
            ):
                blocking_source_manifests.append(row)

    if tolerate_build_class_partial:
        build_class_blocking = [
            row for row in blocking_source_manifests
            if _row_failure_is_build_class_ran_this_run(row)
        ]
    else:
        build_class_blocking = []
    genuine_blocking = [
        row for row in blocking_source_manifests if row not in build_class_blocking
    ]
    ran_this_run_any = any(
        (row.get("fresh_by_timestamp") or row.get("fresh_by_mtime"))
        and row.get("run_id_matches_current")
        for row in source_manifests
    )

    if fresh and not blocking_source_manifests:
        verdict = "pass-fresh-deep-manifest"
        ok = True
        reason = "fresh source deep-engine manifest found"
    elif genuine_blocking:
        verdict = "fail-conflicting-deep-manifest"
        ok = False
        reason = "an existing source deep-engine manifest is not current and successful"
    elif build_class_blocking and ran_this_run_any:
        verdict = "pass-deep-manifest-ran-partial-advisory"
        ok = True
        reason = (
            "deep-engine manifests ran this run but coverage was partial/build-incomplete ("
            + "; ".join(
                f"{row.get('kind')}: {row.get('execution_reason')}"
                for row in build_class_blocking
            )
            + ") - no integrity violation; recorded as honest partial coverage, "
            "NOT a full-proof certificate"
        )
    elif valid_skip:
        verdict = "pass-explicit-deep-skip"
        ok = True
        reason = "typed deep-engine skip reason present"
    else:
        existing = [row for row in source_manifests if row.get("exists")]
        if not existing:
            verdict = "fail-no-deep-manifest"
            reason = "no source deep-engine manifest found"
        elif skip is not None and skip.get("error"):
            verdict = "fail-invalid-skip-reason"
            reason = str(skip.get("error"))
        else:
            verdict = "fail-stale-deep-manifest"
            reason = "source deep-engine manifests are older than the current audit-run-full start"
        ok = False

    return {
        "schema": FRESHNESS_SCHEMA,
        "workspace": str(workspace),
        "verdict": verdict,
        "ok": ok,
        "reason": reason,
        "audit_run_manifest": _rel(audit_run_manifest, workspace),
        "run_start_utc": _format_timestamp(run_start),
        "run_start_line": start_line,
        "run_id": run_id,
        "fresh_manifest_paths": [row["path"] for row in fresh],
        "blocking_manifest_paths": [row["path"] for row in blocking_source_manifests],
        "source_manifests": source_manifests,
        "skip": skip,
    }


def append_audit_run_success_events(
    *,
    audit_run_manifest: Path,
    result: dict[str, Any],
    workspace: Path,
    run_id: str,
    terminal_event: str = "complete",
    terminal_fields: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Append deep-freshness success and terminal rows to audit-run-full manifest."""

    if terminal_event not in {"complete", "bounded-complete"}:
        raise ValueError(f"unsupported audit-run terminal event: {terminal_event}")
    verdict = str(result.get("verdict") or "")
    skip = result.get("skip") if isinstance(result.get("skip"), dict) else None
    fresh_paths = [str(path) for path in (result.get("fresh_manifest_paths") or [])]
    if result.get("ok") is not True:
        raise ValueError("refusing to append audit-run success events for a failed freshness result")
    if not str(run_id or "").strip():
        raise ValueError("refusing to append audit-run success events without a run_id")
    result_run_id = result.get("run_id")
    if result_run_id is None:
        raise ValueError("refusing to append audit-run success events without result run_id")
    if str(result_run_id) != str(run_id):
        raise ValueError("refusing to append audit-run success events for mismatched result run_id")
    result_workspace = result.get("workspace")
    if result_workspace is None:
        raise ValueError("refusing to append audit-run success events without result workspace")
    if not _workspace_matches(result_workspace, workspace):
        raise ValueError("refusing to append audit-run success events for mismatched result workspace")
    if result.get("schema") != FRESHNESS_SCHEMA:
        raise ValueError("refusing to append audit-run success events without a valid freshness result schema")
    start_meta = _latest_audit_run_start(audit_run_manifest, workspace, run_id=run_id)
    if not isinstance(start_meta.get("started_at"), datetime):
        raise ValueError("refusing to append audit-run success events without a matching start row")
    start_line = start_meta.get("line_no")
    if not isinstance(start_line, int):
        raise ValueError("refusing to append audit-run success events without a matching start row")
    if result.get("run_start_utc") != _format_timestamp(start_meta.get("started_at")):
        raise ValueError("refusing to append audit-run success events for mismatched result start timestamp")
    if result.get("run_start_line") != start_line:
        raise ValueError("refusing to append audit-run success events for mismatched result start line")
    raw_start_max_functions = (start_meta.get("raw") or {}).get("max_functions")
    start_max_functions = "" if raw_start_max_functions is None else str(raw_start_max_functions).strip()
    if terminal_event == "complete":
        _normalize_full_max_functions(start_max_functions)
    elif terminal_event == "bounded-complete":
        terminal_max_functions = str((terminal_fields or {}).get("max_functions") or "").strip()
        if _normalize_bounded_max_functions(terminal_max_functions) != _normalize_bounded_max_functions(start_max_functions):
            raise ValueError("refusing to append bounded audit-run success events for mismatched max_functions")
    run_start = start_meta["started_at"]
    actual_source_manifests = [
        _source_manifest_status(
            workspace / rel,
            kind,
            workspace,
            run_start,
            run_id,
            require_full_invariant_denominator=True,
        )
        for rel, kind in SOURCE_MANIFESTS
    ]
    blocking_source_manifests = [
        row for row in actual_source_manifests if _source_manifest_blocks_fresh_pass(row)
    ]
    genuine_blocking = [
        row for row in blocking_source_manifests
        if not _row_failure_is_build_class_ran_this_run(row)
    ]
    if genuine_blocking:
        raise ValueError("refusing to append audit-run success events with a conflicting source manifest")
    if blocking_source_manifests and verdict != "pass-deep-manifest-ran-partial-advisory":
        # build-class (ran-this-run partial) blocking is only acceptable under the
        # explicit partial-advisory verdict; any other verdict must be conflict-free.
        raise ValueError("refusing to append audit-run success events with a conflicting source manifest")
    try:
        manifest_lines = audit_run_manifest.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError as exc:
        raise ValueError("refusing to append audit-run success events without a matching start row") from exc
    except OSError as exc:
        raise ValueError(
            f"refusing to append audit-run success events: manifest read failed: {exc.__class__.__name__}"
        ) from exc
    stage_starts: dict[str, int] = {}
    stage_terminal_events: dict[str, str] = {}
    deep_freshness_started = False
    for line_no, line in enumerate(manifest_lines, 1):
        if line_no <= start_line or not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(row, dict):
            continue
        row_run_id = row.get("run_id") or row.get("audit_run_id")
        if str(row_run_id or "") != str(run_id):
            continue
        event = str(row.get("event") or "")
        if event in {"complete", "bounded-complete"}:
            raise ValueError("refusing to append duplicate audit-run terminal event")
        stage = str(row.get("stage") or "").strip()
        if event in {"stage-fail", "fail"} and not stage:
            raise ValueError("refusing to append audit-run success events after a prior stage failure")
        if event == "stage-start" and stage:
            if stage == "deep-freshness":
                deep_freshness_started = True
            else:
                stage_starts[stage] = line_no
                stage_terminal_events.pop(stage, None)
        elif event in {"stage-pass", "stage-warn", "stage-fail", "fail"} and stage:
            stage_terminal_events[stage] = event

    failed_stages = sorted(
        stage
        for stage, event in stage_terminal_events.items()
        if event in {"stage-fail", "fail"}
    )
    if failed_stages:
        joined = ", ".join(failed_stages)
        raise ValueError(
            "refusing to append audit-run success events after a prior stage failure "
            f"with no later pass/warn: {joined}"
        )

    eligible_fresh_paths = {
        str(row.get("path"))
        for row in actual_source_manifests
        if isinstance(row, dict)
        and row.get("fresh") is True
        and row.get("completion_source_eligible") is True
        and row.get("workspace_matches") is True
        and row.get("schema_matches") is True
        and row.get("execution_ok") is True
        and row.get("exists") is True
        and row.get("run_id_mismatch") is not True
        and row.get("run_id_missing") is not True
        and str(row.get("run_id") or "") == str(run_id)
        and str(row.get("path")) in CURRENT_RUN_COMPLETION_SOURCE_PATHS
    }
    if verdict == "pass-explicit-deep-skip":
        if not skip or not str(skip.get("reason") or "").strip():
            raise ValueError("refusing to append deep skip success events without a typed skip reason")
        skip_key = str(skip.get("key") or DEFAULT_SKIP_KEY)
        actual_skip = _typed_skip_reason(workspace, skip_key, run_start, run_id)
        if not actual_skip or actual_skip.get("error") or not str(actual_skip.get("reason") or "").strip():
            raise ValueError("refusing to append deep skip success events without a backed typed skip reason")
        if actual_skip.get("fresh_for_run") is not True:
            raise ValueError("refusing to append deep skip success events for a stale skip reason")
        if str(actual_skip.get("reason") or "") != str(skip.get("reason") or ""):
            raise ValueError("refusing to append deep skip success events for mismatched skip reason")
        skip = actual_skip
    elif verdict == "pass-fresh-deep-manifest":
        if not fresh_paths:
            raise ValueError("refusing to append deep manifest success events without fresh manifest paths")
        if set(fresh_paths) != eligible_fresh_paths:
            raise ValueError(
                "refusing to append deep manifest success events without matching backed source manifest paths"
            )
    elif verdict == "pass-deep-manifest-ran-partial-advisory":
        # Honest partial coverage: engines ran this run, build/partial-incomplete.
        # Re-assert no integrity violation and require at least one source manifest
        # that physically ran this run before recording the advisory completion.
        ran_rows = [
            row
            for row in actual_source_manifests
            if isinstance(row, dict)
            and (row.get("fresh_by_timestamp") or row.get("fresh_by_mtime"))
            and row.get("run_id_matches_current") is True
            and row.get("run_id_mismatch") is not True
            and row.get("schema_matches") is not False
            and row.get("workspace_matches") is not False
        ]
        if not ran_rows:
            raise ValueError(
                "refusing to append partial-advisory success events without a source manifest that ran this run"
            )
    else:
        raise ValueError(f"refusing to append audit-run success events for unsupported verdict: {verdict}")

    if not deep_freshness_started:
        raise ValueError("refusing to append audit-run complete event without a deep-freshness stage-start row")
    if not stage_starts:
        raise ValueError("refusing to append audit-run complete event without prior audit-run stages")
    terminal_stages = {
        stage
        for stage, event in stage_terminal_events.items()
        if event in {"stage-pass", "stage-warn"}
    }
    incomplete_stages = sorted(stage for stage in stage_starts if stage not in terminal_stages)
    if incomplete_stages:
        joined = ", ".join(incomplete_stages)
        raise ValueError(
            "refusing to append audit-run complete event with incomplete prior stages: "
            f"{joined}"
        )

    timestamp = _utc_now()
    stage_pass: dict[str, Any] = {
        "schema": "auditooor.audit_run_full_manifest.v1",
        "event": "stage-pass",
        "stage": "deep-freshness",
        "run_id": run_id,
        "deep_engine_freshness_verdict": verdict,
        "timestamp_utc": timestamp,
    }
    complete: dict[str, Any] = {
        "schema": "auditooor.audit_run_full_manifest.v1",
        "event": terminal_event,
        "run_id": run_id,
        "workspace": str(workspace),
        "deep_engine_freshness_verdict": verdict,
        "timestamp_utc": timestamp,
    }
    if terminal_fields:
        complete.update(terminal_fields)

    if verdict == "pass-explicit-deep-skip" and skip:
        for event in (stage_pass, complete):
            event["deep_engine_completion_mode"] = "typed-skip"
            event["deep_engine_skip_reason"] = str(skip.get("reason") or "")
            event["deep_engine_skip_key"] = str(skip.get("key") or "")
            event["deep_engine_skip_source"] = str(skip.get("source") or "")
            event["deep_engine_skip_path"] = str(skip.get("path") or "")
    elif verdict == "pass-fresh-deep-manifest":
        stage_pass["deep_engine_completion_mode"] = "fresh-manifest"
        complete["deep_engine_completion_mode"] = "fresh-manifest"
        stage_pass["fresh_manifest_paths"] = fresh_paths
        complete["fresh_manifest_paths"] = fresh_paths
    elif verdict == "pass-deep-manifest-ran-partial-advisory":
        for event in (stage_pass, complete):
            event["deep_engine_completion_mode"] = "partial-build-class-advisory"
            event["deep_engine_partial_coverage"] = True
            event["fresh_manifest_paths"] = fresh_paths

    events = [stage_pass, complete]
    audit_run_manifest.parent.mkdir(parents=True, exist_ok=True)
    with audit_run_manifest.open("a", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event, sort_keys=True) + "\n")
    return events


def append_audit_run_bounded_success_events(
    *,
    audit_run_manifest: Path,
    result: dict[str, Any],
    workspace: Path,
    run_id: str,
    max_functions: str,
) -> list[dict[str, Any]]:
    """Append deep-freshness success and bounded terminal rows."""

    max_functions_value = _normalize_bounded_max_functions(max_functions)
    return append_audit_run_success_events(
        audit_run_manifest=audit_run_manifest,
        result=result,
        workspace=workspace,
        run_id=run_id,
        terminal_event="bounded-complete",
        terminal_fields={
            "full_hunt_denominator": "bounded",
            "max_functions": max_functions_value,
        },
    )


def _normalize_bounded_max_functions(max_functions: str | None) -> str:
    value = "" if max_functions is None else str(max_functions).strip()
    if not value:
        raise ValueError("refusing to append bounded audit-run success events without max_functions")
    if not re.fullmatch(r"[0-9]+", value):
        raise ValueError("refusing to append bounded audit-run success events with non-integer max_functions")
    parsed = int(value, 10)
    if parsed <= 0:
        raise ValueError(
            "refusing to append bounded audit-run success events without a positive max_functions bound"
        )
    return str(parsed)


def build_deep_provenance_stage_pass(
    *,
    result: dict[str, Any],
    stage: str,
    run_id: str,
    timestamp: str | None = None,
) -> dict[str, Any]:
    """Build a stage-pass row that carries the freshness proof used to pass it."""

    verdict = str(result.get("verdict") or "")
    skip = result.get("skip") if isinstance(result.get("skip"), dict) else None
    event: dict[str, Any] = {
        "schema": "auditooor.audit_run_full_manifest.v1",
        "event": "stage-pass",
        "run_id": run_id,
        "stage": stage,
        "deep_engine_freshness_verdict": verdict,
        "timestamp_utc": timestamp or _utc_now(),
    }
    if verdict == "pass-explicit-deep-skip" and skip:
        event["deep_engine_completion_mode"] = "typed-skip"
        event["deep_engine_skip_reason"] = str(skip.get("reason") or "")
        event["deep_engine_skip_key"] = str(skip.get("key") or "")
        event["deep_engine_skip_source"] = str(skip.get("source") or "")
        event["deep_engine_skip_path"] = str(skip.get("path") or "")
    elif verdict == "pass-fresh-deep-manifest":
        event["deep_engine_completion_mode"] = "fresh-manifest"
        event["fresh_manifest_paths"] = [
            str(path) for path in (result.get("fresh_manifest_paths") or [])
        ]
    elif verdict == "pass-deep-manifest-ran-partial-advisory":
        event["deep_engine_completion_mode"] = "partial-build-class-advisory"
        event["deep_engine_partial_coverage"] = True
        event["fresh_manifest_paths"] = [
            str(path) for path in (result.get("fresh_manifest_paths") or [])
        ]
    else:
        raise ValueError(f"unsupported deep provenance verdict for stage pass: {verdict}")
    return event


def _read_text(path: Path) -> tuple[str | None, str | None]:
    try:
        return path.read_text(encoding="utf-8", errors="replace"), None
    except FileNotFoundError:
        return None, "missing"
    except OSError as exc:
        return None, f"read_error:{exc.__class__.__name__}"


def _normalize_state(raw: str | None) -> str:
    value = (raw or "").strip().lower().replace("-", "_")
    if value in {"ok", "executed", "success", "succeeded", "pass", "passed", "done", "proved"}:
        return "ran"
    if value in {"blocked", "failed", "failure", "error"}:
        return "failed"
    if value in {"planned", "skipped", "skipped_budget", "dry_run", "dryrun", "partial"}:
        return "skipped"
    if not value:
        return "unknown"
    return "other"


def _state_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    counts = Counter(row["state"] for row in rows)
    return {state: counts[state] for state in sorted(counts)}


def _summarize_solidity_manifest(path: Path, workspace: Path) -> dict[str, Any]:
    payload, error = _load_json(path)
    if payload is None:
        return {
            "kind": "solidity-deep-audit",
            "path": _rel(path, workspace),
            "error": error,
            "rows": [],
            "counts": {},
            "raw_counts": {},
        }

    rows: list[dict[str, Any]] = []
    for item in payload.get("artifacts", []):
        if not isinstance(item, dict):
            continue
        artifact_text = str(item.get("artifact") or "").strip()
        artifact_path = Path(artifact_text) if artifact_text else None
        step_payload, step_error = (None, "missing") if artifact_path is None else _load_json(artifact_path)
        tool = str(item.get("tool") or (step_payload.get("tool") if isinstance(step_payload, dict) else "")).strip()
        raw_status_source = step_payload.get("status") if isinstance(step_payload, dict) else item.get("status")
        raw_status = str(raw_status_source or "").strip().lower()
        rows.append(
            {
                "tool": tool or "(unknown)",
                "raw_status": raw_status or "unknown",
                "state": _normalize_state(raw_status),
                "detail": (
                    step_payload.get("reason")
                    if isinstance(step_payload, dict) and step_payload.get("reason")
                    else item.get("artifact")
                ),
                "artifact": _rel(artifact_path, workspace) if artifact_path else None,
                "stdout_log": _rel(Path(step_payload["stdout_log"]), workspace)
                if isinstance(step_payload, dict) and step_payload.get("stdout_log")
                else None,
                "stderr_log": _rel(Path(step_payload["stderr_log"]), workspace)
                if isinstance(step_payload, dict) and step_payload.get("stderr_log")
                else None,
                "returncode": step_payload.get("returncode") if isinstance(step_payload, dict) else None,
                "error": step_error,
            }
        )

    raw_counts = Counter(row["raw_status"] for row in rows)
    return {
        "kind": "solidity-deep-audit",
        "path": _rel(path, workspace),
        "schema": payload.get("schema"),
        "workspace": payload.get("workspace"),
        "generated_at": payload.get("generated_at"),
        "detection": payload.get("detection", {}),
        "rows": rows,
        "counts": _state_counts(rows),
        "raw_counts": {state: raw_counts[state] for state in sorted(raw_counts)},
    }


def _parse_report_table(report_text: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    in_table = False
    for raw_line in report_text.splitlines():
        line = raw_line.strip()
        if line == "| tool | state | detail |":
            in_table = True
            continue
        if in_table:
            if not line.startswith("|"):
                if line:
                    break
                continue
            if line.startswith("|---"):
                continue
            cells = [cell.strip() for cell in line.strip("|").split("|")]
            if len(cells) != 3:
                continue
            rows.append({"tool": cells[0], "raw_status": cells[1], "detail": cells[2]})
    return rows


def _parse_summary_lines(report_text: str) -> dict[str, list[str]]:
    values: dict[str, list[str]] = {"ran": [], "skipped": [], "failed": []}
    for raw_line in report_text.splitlines():
        line = raw_line.strip()
        for key in values:
            prefix = f"- {key}:"
            if line.startswith(prefix):
                payload = line[len(prefix) :].strip()
                if payload and payload != "(none)":
                    values[key] = payload.split()
                else:
                    values[key] = []
                break
    return values


def _summarize_audit_deep_report(path: Path, workspace: Path) -> dict[str, Any]:
    report_text, error = _read_text(path)
    if report_text is None:
        return {
            "kind": "audit-deep-report",
            "path": _rel(path, workspace),
            "error": error,
            "rows": [],
            "counts": {},
            "summary": {"ran": [], "skipped": [], "failed": []},
            "pointers": {},
        }

    rows = []
    for row in _parse_report_table(report_text):
        rows.append(
            {
                "tool": row["tool"],
                "raw_status": row["raw_status"],
                "state": _normalize_state(row["raw_status"]),
                "detail": row["detail"],
            }
        )
    summary = _parse_summary_lines(report_text)
    pointers: dict[str, str] = {}
    for raw_line in report_text.splitlines():
        line = raw_line.strip()
        if not line.startswith("- "):
            continue
        label, _, value = line[2:].partition(":")
        if not value:
            continue
        label = label.strip().lower().replace(" ", "_").replace("-", "_")
        value = value.strip().strip("`")
        if label in {"per_run_log", "canonical_latest", "symbolic_per_run_manifest_dir", "fuzz_per_run_manifest_dir", "go/dlt_audit_enforcement_manifest", "go_txid_chain_truth_advisory_scan", "go_refund/key_tweak_survivability_advisory_scan", "anchor_backend_findings", "reth_backend_findings", "rust_source_graph", "rust_cross_crate_graph", "state_root_parity_scaffold", "invariant_ledger_summary", "invariant_ledger_manifest"}:
            pointers[label] = value

    return {
        "kind": "audit-deep-report",
        "path": _rel(path, workspace),
        "rows": rows,
        "counts": _state_counts(rows),
        "summary": summary,
        "pointers": pointers,
    }


def _summarize_audit_deep_all_manifest(path: Path, workspace: Path) -> dict[str, Any]:
    payload, error = _load_json(path)
    if payload is None:
        return {
            "kind": "audit-deep-all-manifest",
            "path": _rel(path, workspace),
            "error": error,
            "rows": [],
            "counts": {},
            "pointers": {},
        }

    rows = []
    for item in payload.get("profiles", []):
        if not isinstance(item, dict):
            continue
        raw_status = str(item.get("status") or "").strip().lower()
        rows.append(
            {
                "tool": str(item.get("profile") or "(unknown)"),
                "raw_status": raw_status or "unknown",
                "state": _normalize_state(raw_status),
                "detail": f"exit_code={item.get('exit_code')}",
                "log": _rel(Path(item["log"]), workspace) if item.get("log") else None,
                "captured_report": _rel(Path(item["captured_report"]), workspace) if item.get("captured_report") else None,
            }
        )

    pointers = {
        "report": _rel(Path(payload["report"]), workspace) if payload.get("report") else None,
        "typed_candidate_promotion": _rel(Path(payload["typed_candidate_promotion"]), workspace) if payload.get("typed_candidate_promotion") else None,
        "cross_lane_correlations": _rel(Path(payload["cross_lane_correlations"]), workspace) if payload.get("cross_lane_correlations") else None,
        "deep_counterexample_collection": _rel(Path(payload["deep_counterexample_collection"]), workspace) if payload.get("deep_counterexample_collection") else None,
        "deep_counterexample_queue": _rel(Path(payload["deep_counterexample_queue"]), workspace) if payload.get("deep_counterexample_queue") else None,
    }
    return {
        "kind": "audit-deep-all-manifest",
        "path": _rel(path, workspace),
        "schema": payload.get("schema"),
        "timestamp_utc": payload.get("timestamp_utc"),
        "dry_run": payload.get("dry_run"),
        "budget_seconds": payload.get("budget_seconds"),
        "rows": rows,
        "counts": _state_counts(rows),
        "pointers": {key: value for key, value in pointers.items() if value},
    }


def _present(path: Path) -> str:
    return "present" if path.exists() else "missing"


def _bridge_outputs(workspace: Path) -> dict[str, list[dict[str, Any]]]:
    entries: dict[str, list[dict[str, Any]]] = {
        "hacker-brief": [],
        "hackerman-novel-vectors": [],
        "brain-prime": [],
        "high-impact-execution-bridge": [],
        "audit-deep-handoff": [],
    }

    hacker_brief_paths = [
        (workspace / ".auditooor" / "hacker_brief.md", "lane-scoped human brief"),
        (workspace / ".auditooor" / "hacker_brief.md.json", "structured brief companion"),
        (workspace / ".auditooor" / "hacker_brief.hackerman.json", "Hackerman projection"),
    ]
    for path, purpose in hacker_brief_paths:
        entries["hacker-brief"].append(
            {
                "path": _rel(path, workspace),
                "status": _present(path),
                "purpose": purpose,
            }
        )

    novel_vector_paths = [
        (workspace / ".auditooor" / "novel_vectors.jsonl", "audit-deep advisory novel-vector worklist"),
        (workspace / ".auditooor" / "novel_vectors.summary.json", "novel-vector target/filter summary"),
        (workspace / ".auditooor" / "novel_vectors.mcp_context.jsonl", "MCP context sidecar for novel-vector adoption proof"),
    ]
    for path, purpose in novel_vector_paths:
        entries["hackerman-novel-vectors"].append(
            {
                "path": _rel(path, workspace),
                "status": _present(path),
                "purpose": purpose,
            }
        )

    brain_receipt = workspace / ".auditooor" / "brain_prime_receipt.json"
    entries["brain-prime"].append(
        {
            "path": _rel(brain_receipt, workspace),
            "status": _present(brain_receipt),
            "purpose": "first-hunt receipt for the next dispatch pass",
        }
    )

    high_bridge_paths = [
        (workspace / ".auditooor" / "high_impact_execution_bridge.json", "bridge manifest"),
        (workspace / ".auditooor" / "high_impact_execution_bridge.md", "bridge narrative"),
        (workspace / ".auditooor" / "high_impact_execution_bridge" / "briefs", "per-row handoff briefs"),
    ]
    for path, purpose in high_bridge_paths:
        entries["high-impact-execution-bridge"].append(
            {
                "path": _rel(path, workspace),
                "status": _present(path),
                "purpose": purpose,
            }
        )

    audit_deep_handoff_paths = [
        (workspace / ".audit_logs" / "audit_deep_report.md", "canonical audit-deep report"),
        (workspace / ".audit_logs" / "audit_deep_all_manifest.json", "bounded all-profile handoff packet"),
        (workspace / ".audit_logs" / "cross_lane_correlations.json", "cross-lane bridge input"),
        (workspace / ".audit_logs" / "cross_lane_correlations.md", "cross-lane narrative"),
        (workspace / ".audit_logs" / "typed_candidate_promotions.json", "typed promotion gate input"),
        (workspace / ".audit_logs" / "typed_candidate_promotions.md", "typed promotion narrative"),
        (workspace / "deep_counterexamples" / "collection_manifest.json", "counterexample collection queue"),
        (workspace / "deep_counterexamples" / "execution_queue.json", "counterexample execution queue"),
        (workspace / "deep_counterexamples" / "execution_queue.md", "counterexample execution narrative"),
        (workspace / ".audit_logs" / "invariant_ledger_manifest.json", "high-impact bridge input"),
        (workspace / ".audit_logs" / "invariant_ledger_summary.md", "high-impact bridge summary"),
    ]
    for path, purpose in audit_deep_handoff_paths:
        entries["audit-deep-handoff"].append(
            {
                "path": _rel(path, workspace),
                "status": _present(path),
                "purpose": purpose,
            }
        )

    return entries


def build_summary(workspace: Path) -> dict[str, Any]:
    sources: list[dict[str, Any]] = []
    solidity_manifest = workspace / ".auditooor" / "solidity-deep-audit" / "manifest.json"
    audit_report = workspace / ".audit_logs" / "audit_deep_report.md"
    all_manifest = workspace / ".audit_logs" / "audit_deep_all_manifest.json"

    if solidity_manifest.exists():
        sources.append(_summarize_solidity_manifest(solidity_manifest, workspace))
    if audit_report.exists():
        sources.append(_summarize_audit_deep_report(audit_report, workspace))
    if all_manifest.exists():
        sources.append(_summarize_audit_deep_all_manifest(all_manifest, workspace))

    counts = Counter()
    for source in sources:
        counts.update(source.get("counts", {}))

    inputs = {
        "solidity_manifest": _rel(solidity_manifest, workspace) if solidity_manifest.exists() else None,
        "audit_deep_report": _rel(audit_report, workspace) if audit_report.exists() else None,
        "audit_deep_all_manifest": _rel(all_manifest, workspace) if all_manifest.exists() else None,
    }
    return {
        "schema": SCHEMA,
        "workspace": str(workspace),
        "generated_at_utc": _utc_now(),
        "inputs": {key: value for key, value in inputs.items() if value},
        "sources": sources,
        "source_count": len(sources),
        "counts": {state: counts[state] for state in sorted(counts)},
        "bridge_outputs": _bridge_outputs(workspace),
    }


def _render_markdown(summary: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("# audit-deep manifest summary")
    lines.append("")
    lines.append(f"- schema: `{summary['schema']}`")
    lines.append(f"- workspace: `{summary['workspace']}`")
    lines.append(f"- generated_at_utc: {summary['generated_at_utc']}")
    if summary.get("inputs"):
        lines.append("- inputs:")
        for key, value in summary["inputs"].items():
            lines.append(f"  - {key}: `{value}`")
    lines.append("")
    lines.append("## Source summaries")
    lines.append("")
    if not summary["sources"]:
        lines.append("- no audit-deep artifacts found")
    for source in summary["sources"]:
        lines.append(f"### {source['kind']}")
        lines.append("")
        lines.append(f"- path: `{source['path']}`")
        if source.get("error"):
            lines.append(f"- error: `{source['error']}`")
        if source.get("schema"):
            lines.append(f"- schema: `{source['schema']}`")
        if source.get("timestamp_utc"):
            lines.append(f"- timestamp_utc: {source['timestamp_utc']}")
        if source.get("dry_run") is not None:
            lines.append(f"- dry_run: `{source['dry_run']}`")
        if source.get("budget_seconds") is not None:
            lines.append(f"- budget_seconds: `{source['budget_seconds']}`")
        if source.get("detection"):
            lines.append(f"- detection: `{json.dumps(source['detection'], sort_keys=True)}`")
        if source.get("summary"):
            lines.append(f"- summary.ran: {', '.join(source['summary'].get('ran', [])) or '(none)'}")
            lines.append(f"- summary.skipped: {', '.join(source['summary'].get('skipped', [])) or '(none)'}")
            lines.append(f"- summary.failed: {', '.join(source['summary'].get('failed', [])) or '(none)'}")
        if source.get("counts"):
            counts = ", ".join(f"{k}={v}" for k, v in source["counts"].items())
            lines.append(f"- normalized counts: {counts}")
        if source.get("raw_counts"):
            raw_counts = ", ".join(f"{k}={v}" for k, v in source["raw_counts"].items())
            lines.append(f"- raw counts: {raw_counts}")
        if source.get("pointers"):
            lines.append("- pointers:")
            for key, value in source["pointers"].items():
                if value is None:
                    continue
                lines.append(f"  - {key}: `{value}`")
        rows = source.get("rows", [])
        if rows:
            lines.append("")
            lines.append("| tool | raw status | normalized | detail | artifact/log |")
            lines.append("|---|---|---|---|---|")
            for row in rows:
                artifact = row.get("artifact") or row.get("log") or row.get("captured_report") or ""
                lines.append(
                    "| {tool} | {raw} | {state} | {detail} | {artifact} |".format(
                        tool=row.get("tool", ""),
                        raw=row.get("raw_status", ""),
                        state=row.get("state", ""),
                        detail=str(row.get("detail", "")).replace("|", "\\|"),
                        artifact=artifact,
                    )
                )
        lines.append("")

    lines.append("## Bridge outputs")
    lines.append("")
    for bridge, entries in summary["bridge_outputs"].items():
        lines.append(f"### {bridge}")
        lines.append("")
        lines.append("| path | status | purpose |")
        lines.append("|---|---|---|")
        for entry in entries:
            lines.append(f"| `{entry['path']}` | {entry['status']} | {entry['purpose']} |")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def _render_json(summary: dict[str, Any]) -> str:
    return json.dumps(summary, indent=2, sort_keys=True) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, help="Workspace to summarize")
    parser.add_argument("--out", help="Optional output path (defaults under <ws>/.audit_logs/)")
    parser.add_argument("--json", action="store_true", help="Render JSON instead of Markdown")
    parser.add_argument(
        "--check-fresh",
        action="store_true",
        help="Validate source deep-engine manifests are fresh for the current audit-run-full run",
    )
    parser.add_argument(
        "--audit-run-manifest",
        help=f"Audit-run-full JSONL manifest path (default: <ws>/{DEFAULT_AUDIT_RUN_MANIFEST})",
    )
    parser.add_argument(
        "--require-fresh-since",
        help="Explicit ISO timestamp to compare source deep manifests against instead of reading audit-run-full start",
    )
    parser.add_argument(
        "--allow-skip-key",
        default=DEFAULT_SKIP_KEY,
        help=f"Typed stage skip key that permits no fresh deep manifest (default: {DEFAULT_SKIP_KEY})",
    )
    parser.add_argument(
        "--run-id",
        help="Audit-run-full run_id to record when appending success events",
    )
    parser.add_argument(
        "--append-audit-run-success-events",
        action="store_true",
        help="Append deep-freshness stage-pass and complete events after a successful freshness check",
    )
    parser.add_argument(
        "--append-audit-run-bounded-success-events",
        action="store_true",
        help="Append deep-freshness stage-pass and bounded-complete events after a successful freshness check",
    )
    parser.add_argument(
        "--bounded-max-functions",
        help="MAX_FUNCTIONS value to record with --append-audit-run-bounded-success-events",
    )
    parser.add_argument(
        "--emit-provenance-stage-pass",
        help="Emit one stage-pass JSON row with the successful deep freshness provenance",
    )
    parser.add_argument(
        "--require-full-invariant-denominator",
        action="store_true",
        help=(
            "Require standard Solidity deep manifests to prove every generated or available "
            "invariant harness denominator was executed"
        ),
    )
    parser.add_argument(
        "--tolerate-build-class-partial",
        action="store_true",
        help=(
            "G9-honest opt-in: tolerate a source deep-engine manifest that PHYSICALLY ran this "
            "run (fresh-by-timestamp/mtime + matching run_id) but failed only for build/partial "
            "reasons (harness root unbuildable, no harness executions, partial per-function "
            "coverage), emitting pass-deep-manifest-ran-partial-advisory instead of "
            "fail-conflicting-deep-manifest. INTEGRITY violations (run_id/schema/workspace/"
            "exit-code mismatch, stale reuse) are NEVER tolerated. Used by the audit-run-full "
            "completion cert so the pipeline finishes and the hunt/queue findings stand."
        ),
    )
    args = parser.parse_args()

    workspace = Path(args.workspace).expanduser().resolve()
    if not workspace.is_dir():
        raise SystemExit(f"[audit-deep-manifest] ERR workspace not found or not a directory: {workspace}")
    if args.append_audit_run_success_events and args.append_audit_run_bounded_success_events:
        raise SystemExit(
            "[audit-deep-manifest] ERR append modes are mutually exclusive"
        )
    if (
        args.append_audit_run_success_events
        or args.append_audit_run_bounded_success_events
    ) and args.require_fresh_since:
        raise SystemExit(
            "[audit-deep-manifest] ERR audit-run append modes cannot be used "
            "with --require-fresh-since; append mode must prove freshness against an audit-run start row"
        )
    bounded_max_functions: str | None = None
    if args.append_audit_run_bounded_success_events:
        try:
            bounded_max_functions = _normalize_bounded_max_functions(args.bounded_max_functions)
        except ValueError as exc:
            raise SystemExit(f"[audit-deep-manifest] ERR {exc}") from exc

    if args.check_fresh:
        audit_run_manifest = Path(args.audit_run_manifest or DEFAULT_AUDIT_RUN_MANIFEST).expanduser()
        if not audit_run_manifest.is_absolute():
            audit_run_manifest = workspace / audit_run_manifest
        result = check_freshness(
            workspace,
            audit_run_manifest=audit_run_manifest.resolve(strict=False),
            require_fresh_since=args.require_fresh_since,
            allow_skip_key=args.allow_skip_key,
            run_id=args.run_id,
            require_full_invariant_denominator=args.require_full_invariant_denominator,
            tolerate_build_class_partial=args.tolerate_build_class_partial,
        )
        append_error: str | None = None
        if args.append_audit_run_success_events and result.get("ok"):
            run_id = args.run_id or result.get("run_id")
            if not run_id:
                raise SystemExit(
                    "[audit-deep-manifest] ERR --append-audit-run-success-events requires --run-id "
                    "or a run_id from the audit-run manifest"
                )
            try:
                result["appended_events"] = append_audit_run_success_events(
                    audit_run_manifest=audit_run_manifest.resolve(strict=False),
                    result=result,
                    workspace=workspace,
                    run_id=str(run_id),
                )
            except ValueError as exc:
                append_error = str(exc)
        if args.append_audit_run_bounded_success_events and result.get("ok"):
            run_id = args.run_id or result.get("run_id")
            if not run_id:
                raise SystemExit(
                    "[audit-deep-manifest] ERR --append-audit-run-bounded-success-events requires --run-id "
                    "or a run_id from the audit-run manifest"
                )
            try:
                result["appended_events"] = append_audit_run_bounded_success_events(
                    audit_run_manifest=audit_run_manifest.resolve(strict=False),
                    result=result,
                    workspace=workspace,
                    run_id=str(run_id),
                    max_functions=str(bounded_max_functions),
                )
            except ValueError as exc:
                append_error = str(exc)
        if append_error:
            result["ok"] = False
            result["append_error"] = append_error
            result["verdict"] = "fail-audit-run-success-append"
        if args.emit_provenance_stage_pass and result.get("ok"):
            run_id = args.run_id or result.get("run_id")
            if not run_id:
                raise SystemExit(
                    "[audit-deep-manifest] ERR --emit-provenance-stage-pass requires --run-id "
                    "or a run_id from the audit-run manifest"
                )
            result["provenance_stage_pass"] = build_deep_provenance_stage_pass(
                result=result,
                stage=str(args.emit_provenance_stage_pass),
                run_id=str(run_id),
            )
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print(f"[audit-deep-manifest] freshness verdict: {result['verdict']}")
            print(f"[audit-deep-manifest] reason: {result['reason']}")
            print(f"[audit-deep-manifest] run_start_utc: {result.get('run_start_utc')}")
            if result.get("fresh_manifest_paths"):
                print(
                    "[audit-deep-manifest] fresh manifests: "
                    + ", ".join(str(path) for path in result["fresh_manifest_paths"])
                )
            if result.get("skip") and result["skip"].get("reason"):
                print(
                    "[audit-deep-manifest] skip reason: "
                    + str(result["skip"].get("reason"))
                )
        return 0 if result.get("ok") else 1

    summary = build_summary(workspace)
    rendered = _render_json(summary) if args.json else _render_markdown(summary)

    default_out = DEFAULT_JSON_OUT if args.json else DEFAULT_MARKDOWN_OUT
    out_path = Path(args.out).expanduser().resolve() if args.out else (workspace / default_out).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    print(f"[audit-deep-manifest] wrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
