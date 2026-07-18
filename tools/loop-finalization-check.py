#!/usr/bin/env python3
"""Offline loop-finalization gate for per-slice closeout manifests."""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.loop_finalization_check.v1"
HACKER_QUESTIONS_SCHEMA = "auditooor.hacker_question.v1"
NO_HACKER_QUESTIONS_MARKER = "NO_HACKER_QUESTIONS"
_PLACEHOLDER_VALUES = {
    "",
    "???",
    "-",
    "in_progress",
    "n/a",
    "na",
    "none",
    "null",
    "pending",
    "tbd",
    "todo",
    "unknown",
    "wip",
    "xxxxx",
    "`tbd`",
    "`todo`",
}

SOURCE_REVIEW_EXTENSIONS = {
    ".cairo",
    ".go",
    ".json",
    ".js",
    ".move",
    ".rs",
    ".sol",
    ".toml",
    ".ts",
    ".vy",
    ".yaml",
    ".yml",
}
NON_TARGET_ARTIFACT_PREFIXES = (
    ".github/",
    "auditooor/",
    "agent_outputs/",
    "audit/corpus_tags/",
    "docs/",
    "reports/",
    "reference/",
    "tools/",
)
HIGH_PLUS_DRAFT_RE = re.compile(
    r"\b(?:severity|impact|risk)\s*[:=]\s*(critical|high)\b",
    flags=re.IGNORECASE,
)


def _is_non_empty_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _is_non_empty_string_list(value: Any) -> bool:
    return isinstance(value, list) and bool(value) and all(_is_non_empty_text(item) for item in value)


def _is_placeholder_text(value: Any) -> bool:
    if not isinstance(value, str):
        return True
    cleaned = value.strip().strip("`").strip().lower()
    return cleaned in _PLACEHOLDER_VALUES


def _structured_evidence_present(value: Any) -> bool:
    if _is_non_empty_text(value):
        return True
    if _is_non_empty_string_list(value):
        return True
    if not isinstance(value, dict) or not value:
        return False
    for nested in value.values():
        if _is_non_empty_text(nested) or _is_non_empty_string_list(nested):
            return True
        if isinstance(nested, dict) and _structured_evidence_present(nested):
            return True
    return False


def _is_target_source_artifact(path_text: str) -> bool:
    text = path_text.strip()
    if not text:
        return False
    normalized = text.replace("\\", "/").lstrip("./")
    if normalized.startswith(NON_TARGET_ARTIFACT_PREFIXES):
        return False
    return Path(normalized).suffix.lower() in SOURCE_REVIEW_EXTENSIONS


def _infer_source_review_relevant(manifest: dict[str, Any]) -> bool:
    changed_artifacts = manifest.get("changed_artifacts")
    if not isinstance(changed_artifacts, list):
        return False
    return any(isinstance(item, str) and _is_target_source_artifact(item) for item in changed_artifacts)


def _read_jsonl_rows(path: Path) -> tuple[list[dict[str, Any]], list[str]]:
    if not path.is_file():
        return [], []
    rows: list[dict[str, Any]] = []
    errors: list[str] = []
    for line_no, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            errors.append(f"{path}:{line_no}: invalid JSON: {exc.msg}")
            continue
        if not isinstance(value, dict):
            errors.append(f"{path}:{line_no}: line is not a JSON object")
            continue
        rows.append(value)
    return rows, errors


def _summarize_agent_cycle_log(path: Path) -> dict[str, Any]:
    rows, errors = _read_jsonl_rows(path)
    event_counts: dict[str, int] = {}
    agent_counts: dict[str, int] = {}
    task_counts: dict[str, int] = {}
    latest_ts: str | None = None

    def _normalized_text(value: Any) -> str:
        return str(value).strip() or "_unknown"

    for row in rows:
        event = _normalized_text(row.get("event"))
        agent = _normalized_text(row.get("agent"))
        task = _normalized_text(row.get("task"))
        event_counts[event] = event_counts.get(event, 0) + 1
        agent_counts[agent] = agent_counts.get(agent, 0) + 1
        task_counts[task] = task_counts.get(task, 0) + 1
        ts = row.get("ts") or row.get("timestamp") or row.get("updated_at")
        if isinstance(ts, str) and ts.strip():
            latest_ts = ts.strip()

    return {
        "status": "missing" if not path.is_file() else ("error" if errors and not rows else "present"),
        "path": str(path),
        "rows": len(rows),
        "malformed_rows": len(errors),
        "last_updated": latest_ts,
        "by_event": {key: event_counts[key] for key in sorted(event_counts)},
        "by_agent": {key: agent_counts[key] for key in sorted(agent_counts)},
        "by_task": {key: task_counts[key] for key in sorted(task_counts)},
        "errors": errors[:8],
    }


def _check_agent_cycle_log_field(manifest: dict[str, Any], *, manifest_path: Path | None = None) -> dict[str, Any]:
    value = manifest.get("agent_cycle_log")
    fallback_path = manifest.get("agent_cycle_log_path")
    if value is None and fallback_path is None:
        return {"present": False, "status": "missing"}

    payload: dict[str, Any] = {}
    if isinstance(value, dict):
        payload.update(value)
    elif value is not None:
        payload["path"] = value
        payload["status"] = "advisory_only"
        payload["note"] = "agent_cycle_log should be an object with a path and optional counts"
    if fallback_path is not None and "path" not in payload:
        payload["path"] = fallback_path

    raw_path = payload.get("path")
    if not isinstance(raw_path, str) or not raw_path.strip():
        return {
            "present": True,
            "status": "error",
            "path": None,
            "rows": 0,
            "malformed_rows": 0,
            "last_updated": None,
            "by_event": {},
            "by_agent": {},
            "by_task": {},
            "errors": ["agent_cycle_log.path must be a non-empty string when present"],
        }

    path = Path(raw_path).expanduser()
    if not path.is_absolute():
        if manifest_path is not None:
            path = manifest_path.parent / path
        else:
            path = path.resolve()
    return {"present": True, **_summarize_agent_cycle_log(path)}


def _load_manifest(path: Path) -> tuple[dict[str, Any] | None, list[str]]:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        return None, [f"unable to read manifest: {exc}"]
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        return None, [f"manifest is not valid JSON: {exc.msg} at line {exc.lineno} column {exc.colno}"]
    if not isinstance(payload, dict):
        return None, ["manifest root must be a JSON object"]
    return payload, []


def _load_hacker_question_obligations_module() -> Any | None:
    tool_path = Path(__file__).resolve().with_name("hacker-question-obligations.py")
    spec = importlib.util.spec_from_file_location("_hacker_question_obligations_lfc", tool_path)
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception:
        return None
    return mod


# r36-rebuttal: lane-HUNT-DEDUP-FIRST-ORCH registered in .auditooor/agent_pathspec.json
# --- L36 hunt-completeness BLOCKING gate ------------------------------------
# A manifest that declares the workspace HUNT done / exhausted MUST pass
# hunt-completeness-check.py (which now includes the L36 dedup-first signal).
# No slice may be marked exhausted/done without the completeness gate at rc=0.
_HUNT_DONE_FIELDS = ("hunt_status", "loop_status", "status", "slice_status")
_HUNT_DONE_VALUES = {"exhausted", "done", "hunt-complete", "hunt_complete", "complete", "completed"}
_HUNT_DONE_FLAGS = ("hunt_done", "hunt_exhausted", "loop_exhausted")


def _load_hunt_completeness_module() -> Any | None:
    # r36-rebuttal: lane-HUNT-DEDUP-FIRST-ORCH registered
    import sys as _sys
    tool_path = Path(__file__).resolve().with_name("hunt-completeness-check.py")
    spec = importlib.util.spec_from_file_location("_hunt_completeness_lfc", tool_path)
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    # Register before exec so dataclass field() introspection (Python 3.14)
    # can resolve the module dict for SignalResult's default_factory fields.
    _sys.modules["_hunt_completeness_lfc"] = mod
    try:
        spec.loader.exec_module(mod)
    except Exception:
        return None
    return mod


def _hunt_done_declared(manifest: dict[str, Any]) -> bool:
    for flag in _HUNT_DONE_FLAGS:
        if manifest.get(flag) is True:
            return True
    for field_name in _HUNT_DONE_FIELDS:
        val = manifest.get(field_name)
        if isinstance(val, str) and val.strip().lower().replace(" ", "-") in _HUNT_DONE_VALUES:
            return True
    return False


def _check_hunt_completeness_when_done(
    manifest: dict[str, Any],
    *,
    malformed: list[str],
    policy_failures: list[str],
    manifest_path: Path | None,
) -> dict[str, Any]:
    """BLOCKING: when a manifest declares the workspace HUNT done/exhausted,
    it must pass hunt-completeness-check (incl. the L36 dedup-first signal).
    Not relevant for non-hunt-closeout slices (mode=not_required)."""
    if not _hunt_done_declared(manifest):
        return {"ok": True, "relevant": False, "mode": "not_required"}

    ws_text = manifest.get("workspace_path") or manifest.get("workspace")
    if not _is_non_empty_text(ws_text):
        policy_failures.append(
            "hunt-done manifest requires workspace_path for the hunt-completeness gate"
        )
        return {"ok": False, "relevant": True, "mode": "missing_workspace_path"}

    ws = _resolve_manifest_path(str(ws_text), manifest, manifest_path)
    if not ws.is_dir():
        # Allow an as-is absolute path that exists outside manifest dir.
        alt = Path(str(ws_text)).expanduser()
        ws = alt if alt.is_dir() else ws
    if not ws.is_dir():
        policy_failures.append(
            f"hunt-done manifest workspace_path not a directory: {ws_text}"
        )
        return {"ok": False, "relevant": True, "mode": "bad_workspace_path"}

    mod = _load_hunt_completeness_module()
    if mod is None or not hasattr(mod, "evaluate"):
        malformed.append("unable to load hunt-completeness-check helper")
        return {"ok": False, "relevant": True, "mode": "gate_error"}

    try:
        result = mod.evaluate(ws.resolve())
    except Exception as exc:  # pragma: no cover (defensive)
        malformed.append(f"hunt-completeness gate raised: {exc}")
        return {"ok": False, "relevant": True, "mode": "gate_error"}

    verdict = result.get("verdict")
    if verdict == "pass-hunt-complete":
        return {"ok": True, "relevant": True, "mode": "hunt_complete", "verdict": verdict}

    failures = result.get("failures", [])
    policy_failures.append(
        "hunt-done manifest BLOCKED by hunt-completeness gate: "
        f"verdict={verdict} ({', '.join(failures) if failures else result.get('reason', '')})"
    )
    return {
        "ok": False, "relevant": True, "mode": "hunt_incomplete",
        "verdict": verdict, "failures": failures,
    }


# r36-rebuttal: lane-L37-AUDIT-COMPLETENESS registered in .auditooor/agent_pathspec.json
# --- L37 audit-completeness BLOCKING gate -----------------------------------
# A manifest that declares the workspace AUDIT done / audited MUST pass
# audit-completeness-check.py (the WHOLE documented pipeline ran with evidence).
# No slice may be marked audit-done without the L37 completeness gate at rc=0.
# This is the AUDIT-level peer of the L36 hunt-completeness gate above; the two
# compose (audit-done implies the hunt half too, which L37 itself delegates to).
# Inherited automatically: L37's whole-workspace honesty signal (it delegates to
# audit-honesty-check.py and returns fail-hollow-not-genuinely-audited on a
# hollow / fake-coverage / mock-only workspace) flows through here as just
# another non-"pass-audit-complete" verdict, so an audit-done manifest over a
# hollow workspace is BLOCKED with no extra wiring below.
_AUDIT_DONE_FIELDS = ("audit_status",)
_AUDIT_DONE_VALUES = {"audited", "audit-complete", "audit_complete", "done", "complete", "completed"}
_AUDIT_DONE_FLAGS = ("audit_done", "audit_complete", "audited")


def _load_audit_completeness_module() -> Any | None:
    # r36-rebuttal: lane-L37-AUDIT-COMPLETENESS registered
    import sys as _sys
    tool_path = Path(__file__).resolve().with_name("audit-completeness-check.py")
    spec = importlib.util.spec_from_file_location("_audit_completeness_lfc", tool_path)
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    _sys.modules["_audit_completeness_lfc"] = mod
    try:
        spec.loader.exec_module(mod)
    except Exception:
        return None
    return mod


def _audit_done_declared(manifest: dict[str, Any]) -> bool:
    for flag in _AUDIT_DONE_FLAGS:
        if manifest.get(flag) is True:
            return True
    for field_name in _AUDIT_DONE_FIELDS:
        val = manifest.get(field_name)
        if isinstance(val, str) and val.strip().lower().replace(" ", "-") in _AUDIT_DONE_VALUES:
            return True
    return False


def _check_audit_completeness_when_done(
    manifest: dict[str, Any],
    *,
    malformed: list[str],
    policy_failures: list[str],
    manifest_path: Path | None,
) -> dict[str, Any]:
    """BLOCKING: when a manifest declares the workspace AUDIT done/audited,
    it must pass the L37 audit-completeness gate (whole pipeline w/ evidence).
    Not relevant for non-audit-closeout slices (mode=not_required)."""
    if not _audit_done_declared(manifest):
        return {"ok": True, "relevant": False, "mode": "not_required"}

    ws_text = manifest.get("workspace_path") or manifest.get("workspace")
    if not _is_non_empty_text(ws_text):
        policy_failures.append(
            "audit-done manifest requires workspace_path for the audit-completeness gate"
        )
        return {"ok": False, "relevant": True, "mode": "missing_workspace_path"}

    ws = _resolve_manifest_path(str(ws_text), manifest, manifest_path)
    if not ws.is_dir():
        alt = Path(str(ws_text)).expanduser()
        ws = alt if alt.is_dir() else ws
    if not ws.is_dir():
        policy_failures.append(
            f"audit-done manifest workspace_path not a directory: {ws_text}"
        )
        return {"ok": False, "relevant": True, "mode": "bad_workspace_path"}

    mod = _load_audit_completeness_module()
    if mod is None or not hasattr(mod, "evaluate"):
        malformed.append("unable to load audit-completeness-check helper")
        return {"ok": False, "relevant": True, "mode": "gate_error"}

    try:
        result = mod.evaluate(ws.resolve())
    except Exception as exc:  # pragma: no cover (defensive)
        malformed.append(f"audit-completeness gate raised: {exc}")
        return {"ok": False, "relevant": True, "mode": "gate_error"}

    verdict = result.get("verdict")
    if verdict == "pass-audit-complete":
        return {"ok": True, "relevant": True, "mode": "audit_complete", "verdict": verdict}

    failures = result.get("failures", [])
    policy_failures.append(
        "audit-done manifest BLOCKED by audit-completeness gate: "
        f"verdict={verdict} ({', '.join(failures) if failures else result.get('reason', '')})"
    )
    return {
        "ok": False, "relevant": True, "mode": "audit_incomplete",
        "verdict": verdict, "failures": failures,
    }


def _check_artifacts(
    manifest: dict[str, Any],
    *,
    allow_no_artifact: bool,
    malformed: list[str],
    policy_failures: list[str],
) -> dict[str, Any]:
    changed_artifacts = manifest.get("changed_artifacts")
    no_artifact_reason = manifest.get("no_artifact_reason")

    if changed_artifacts is not None and not isinstance(changed_artifacts, list):
        malformed.append("changed_artifacts must be a list of non-empty strings when present")
        return {"ok": False}
    if isinstance(changed_artifacts, list) and changed_artifacts and not _is_non_empty_string_list(changed_artifacts):
        malformed.append("changed_artifacts must contain only non-empty strings")
        return {"ok": False}
    if no_artifact_reason is not None and not _is_non_empty_text(no_artifact_reason):
        malformed.append("no_artifact_reason must be a non-empty string when present")
        return {"ok": False}

    if _is_non_empty_string_list(changed_artifacts):
        return {"ok": True, "mode": "changed_artifacts", "artifacts": changed_artifacts}
    if _is_non_empty_text(no_artifact_reason):
        if allow_no_artifact:
            return {"ok": True, "mode": "no_artifact_reason", "reason": no_artifact_reason}
        policy_failures.append("no_artifact_reason requires --allow-no-artifact")
        return {"ok": False, "mode": "no_artifact_reason", "reason": no_artifact_reason}

    policy_failures.append("changed_artifacts or no_artifact_reason is required")
    return {"ok": False}


def _check_required_evidence_field(
    manifest: dict[str, Any],
    field_name: str,
    malformed: list[str],
    policy_failures: list[str],
) -> dict[str, Any]:
    value = manifest.get(field_name)
    if value is None:
        policy_failures.append(f"{field_name} is required")
        return {"ok": False}
    if not isinstance(value, (str, list, dict)):
        malformed.append(f"{field_name} must be a non-empty string, list, or object")
        return {"ok": False}
    if _structured_evidence_present(value):
        return {"ok": True, "evidence": value}
    policy_failures.append(f"{field_name} must contain non-empty evidence")
    return {"ok": False, "evidence": value}


def _resolve_manifest_path(path_text: str, manifest: dict[str, Any], manifest_path: Path | None) -> Path:
    path = Path(path_text).expanduser()
    if path.is_absolute():
        return path
    workspace = manifest.get("workspace_path")
    if isinstance(workspace, str) and workspace.strip():
        return Path(workspace).expanduser() / path
    if manifest_path is not None:
        return manifest_path.parent / path
    return path


def _is_high_plus_draft_text(text: str) -> bool:
    return bool(HIGH_PLUS_DRAFT_RE.search(text))


def _check_open_hacker_question_obligations(
    manifest: dict[str, Any],
    malformed: list[str],
    policy_failures: list[str],
    *,
    manifest_path: Path | None = None,
) -> dict[str, Any]:
    changed_artifacts = manifest.get("changed_artifacts")
    if not isinstance(changed_artifacts, list):
        return {"ok": True, "mode": "not_applicable", "draft_count": 0}

    draft_rows: list[dict[str, Any]] = []
    high_plus_rows: list[dict[str, Any]] = []
    for artifact in changed_artifacts:
        if not isinstance(artifact, str) or not artifact.strip().lower().endswith(".md"):
            continue
        draft_path = _resolve_manifest_path(artifact, manifest, manifest_path)
        if not draft_path.is_file():
            continue
        text = draft_path.read_text(encoding="utf-8", errors="replace")
        is_high_plus = _is_high_plus_draft_text(text)
        row = {
            "artifact": artifact,
            "draft_path": str(draft_path),
            "high_plus": is_high_plus,
        }
        draft_rows.append(row)
        if is_high_plus:
            high_plus_rows.append({**row, "text": text})

    if not high_plus_rows:
        return {
            "ok": True,
            "mode": "no_high_critical_drafts",
            "draft_count": len(draft_rows),
            "high_plus_draft_count": 0,
            "blocking_count": 0,
            "blocking_obligations": [],
        }

    workspace_raw = manifest.get("workspace_path")
    if not isinstance(workspace_raw, str) or not workspace_raw.strip():
        policy_failures.append(
            "High/Critical draft finalization requires workspace_path for hacker-question obligation gate"
        )
        return {
            "ok": False,
            "mode": "missing_workspace_path",
            "draft_count": len(draft_rows),
            "high_plus_draft_count": len(high_plus_rows),
            "blocking_count": 0,
            "blocking_obligations": [],
        }

    mod = _load_hacker_question_obligations_module()
    if mod is None or not hasattr(mod, "matching_open_obligations_for_text"):
        malformed.append("unable to load hacker-question-obligations helper")
        return {"ok": False, "mode": "helper_unavailable", "blocking_count": 0}

    ws = Path(workspace_raw).expanduser().resolve()
    blocking: list[dict[str, Any]] = []
    for row in high_plus_rows:
        matches = mod.matching_open_obligations_for_text(
            ws,
            str(row.get("text", "")),
            changed_artifacts=[str(row.get("artifact", ""))],
        )
        for match in matches:
            blocking.append(
                {
                    "draft_path": row["draft_path"],
                    **match,
                }
            )

    if blocking:
        policy_failures.append(
            f"{len(blocking)} open hacker-question obligation(s) still match High/Critical draft(s)"
        )
        return {
            "ok": False,
            "mode": "blocking_open_obligations",
            "draft_count": len(draft_rows),
            "high_plus_draft_count": len(high_plus_rows),
            "blocking_count": len(blocking),
            "blocking_obligations": blocking[:10],
        }

    return {
        "ok": True,
        "mode": "no_matching_open_obligations",
        "draft_count": len(draft_rows),
        "high_plus_draft_count": len(high_plus_rows),
        "blocking_count": 0,
        "blocking_obligations": [],
    }


def _high_plus_draft_rows(
    manifest: dict[str, Any],
    *,
    manifest_path: Path | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    changed_artifacts = manifest.get("changed_artifacts")
    if not isinstance(changed_artifacts, list):
        return [], []

    draft_rows: list[dict[str, Any]] = []
    high_plus_rows: list[dict[str, Any]] = []
    for artifact in changed_artifacts:
        if not isinstance(artifact, str) or not artifact.strip().lower().endswith(".md"):
            continue
        draft_path = _resolve_manifest_path(artifact, manifest, manifest_path)
        if not draft_path.is_file():
            continue
        text = draft_path.read_text(encoding="utf-8", errors="replace")
        row = {
            "artifact": artifact,
            "draft_path": str(draft_path),
            "high_plus": _is_high_plus_draft_text(text),
            "text": text,
        }
        draft_rows.append({k: v for k, v in row.items() if k != "text"})
        if row["high_plus"]:
            high_plus_rows.append(row)
    return draft_rows, high_plus_rows


def _check_source_read_receipts_for_high_plus_drafts(
    manifest: dict[str, Any],
    malformed: list[str],
    policy_failures: list[str],
    *,
    manifest_path: Path | None = None,
) -> dict[str, Any]:
    """Fail High/Critical draft finalization if cited source lacks receipts.

    This reuses the canonical hacker-question-obligations helper so pre-submit,
    paste-ready, and loop finalization apply the same source-read receipt
    semantics: a cited production source file must have either a current
    source-read receipt or a hacker-question obligation row.
    """
    draft_rows, high_plus_rows = _high_plus_draft_rows(manifest, manifest_path=manifest_path)
    if not high_plus_rows:
        return {
            "ok": True,
            "status": "pass",
            "mode": "no_high_critical_drafts",
            "draft_count": len(draft_rows),
            "high_plus_draft_count": 0,
            "missing_receipts": [],
            "stale_receipts": [],
        }

    workspace_raw = manifest.get("workspace_path")
    if not isinstance(workspace_raw, str) or not workspace_raw.strip():
        policy_failures.append(
            "High/Critical draft finalization requires workspace_path for source-read receipt gate"
        )
        return {
            "ok": False,
            "status": "fail",
            "mode": "missing_workspace_path",
            "draft_count": len(draft_rows),
            "high_plus_draft_count": len(high_plus_rows),
            "missing_receipts": [],
            "stale_receipts": [],
        }

    mod = _load_hacker_question_obligations_module()
    if mod is None or not hasattr(mod, "gate_draft_source_read_receipts"):
        malformed.append("unable to load source-read receipt gate helper")
        return {
            "ok": False,
            "status": "fail",
            "mode": "helper_unavailable",
            "draft_count": len(draft_rows),
            "high_plus_draft_count": len(high_plus_rows),
            "missing_receipts": [],
            "stale_receipts": [],
        }

    ws = Path(workspace_raw).expanduser().resolve()
    changed_source_files = [
        str(item)
        for item in manifest.get("changed_artifacts", [])
        if isinstance(item, str) and _is_target_source_artifact(item)
    ]
    draft_results: list[dict[str, Any]] = []
    missing: list[dict[str, str]] = []
    stale: list[dict[str, str]] = []
    errors: list[dict[str, Any]] = []
    for row in high_plus_rows:
        draft_path = Path(str(row["draft_path"]))
        result = mod.gate_draft_source_read_receipts(
            ws,
            draft_path,
            extra_source_files=changed_source_files,
        )
        draft_results.append(
            {
                "draft_path": str(draft_path),
                "status": str(result.get("status", "")),
                "counts": result.get("counts", {}),
                "cited_source_files": result.get("cited_source_files", [])[:20],
            }
        )
        for item in result.get("missing_receipts", []) or []:
            missing.append({"draft_path": str(draft_path), "file": str(item)})
        for item in result.get("stale_receipts", []) or []:
            stale.append({"draft_path": str(draft_path), "file": str(item)})
        for item in result.get("errors", []) or []:
            if isinstance(item, dict):
                errors.append({"draft_path": str(draft_path), **item})
            else:
                errors.append({"draft_path": str(draft_path), "message": str(item)})

    if errors:
        malformed.append("source-read receipt gate returned errors")
        return {
            "ok": False,
            "status": "fail",
            "mode": "gate_error",
            "draft_count": len(draft_rows),
            "high_plus_draft_count": len(high_plus_rows),
            "changed_source_files": changed_source_files,
            "missing_receipts": missing[:20],
            "stale_receipts": stale[:20],
            "errors": errors[:10],
            "draft_results": draft_results,
        }

    if missing or stale:
        bits: list[str] = []
        if missing:
            bits.append(f"{len(missing)} missing source-read receipt(s)")
        if stale:
            bits.append(f"{len(stale)} stale source-read receipt(s)")
        policy_failures.append(
            "High/Critical draft source-read receipt gate failed: " + ", ".join(bits)
        )
        return {
            "ok": False,
            "status": "fail",
            "mode": "blocking_missing_or_stale_receipts",
            "draft_count": len(draft_rows),
            "high_plus_draft_count": len(high_plus_rows),
            "changed_source_files": changed_source_files,
            "missing_receipts": missing[:20],
            "stale_receipts": stale[:20],
            "draft_results": draft_results,
        }

    return {
        "ok": True,
        "status": "pass",
        "mode": "all_cited_sources_have_receipts",
        "draft_count": len(draft_rows),
        "high_plus_draft_count": len(high_plus_rows),
        "changed_source_files": changed_source_files,
        "missing_receipts": [],
        "stale_receipts": [],
        "draft_results": draft_results,
    }


def _check_tests_or_logs_linked(
    manifest: dict[str, Any],
    malformed: list[str],
    policy_failures: list[str],
    *,
    manifest_path: Path | None = None,
) -> dict[str, Any]:
    result = _check_required_evidence_field(manifest, "tests_or_logs_linked", malformed, policy_failures)
    if not result.get("ok"):
        return result

    value = manifest.get("tests_or_logs_linked")
    if not isinstance(value, dict):
        return result
    logs = value.get("logs")
    workspace = manifest.get("workspace_path")
    if logs is None or not isinstance(workspace, str) or not workspace.strip():
        return result
    if not isinstance(logs, list) or not all(isinstance(item, str) and item.strip() for item in logs):
        malformed.append("tests_or_logs_linked.logs must be a string list when present")
        result["ok"] = False
        return result

    missing_logs = [
        log for log in logs if not _resolve_manifest_path(log, manifest, manifest_path).is_file()
    ]
    if missing_logs:
        policy_failures.append(
            "tests_or_logs_linked.logs must exist when workspace_path is present: "
            + ", ".join(missing_logs[:5])
        )
        result["ok"] = False
        result["missing_logs"] = missing_logs
    return result


def _check_mcp_context_evidence_field(
    manifest: dict[str, Any],
    malformed: list[str],
    policy_failures: list[str],
) -> dict[str, Any]:
    value = manifest.get("mcp_context_evidence")
    if value is None:
        return {"ok": True, "present": False}
    if not isinstance(value, dict):
        malformed.append("mcp_context_evidence must be an object when present")
        return {"ok": False, "present": True}

    context_pack_id = value.get("context_pack_id")
    context_pack_hash = value.get("context_pack_hash")
    source_refs = value.get("source_refs")
    placeholders: list[str] = []
    if _is_placeholder_text(context_pack_id):
        placeholders.append("context_pack_id")
    if _is_placeholder_text(context_pack_hash):
        placeholders.append("context_pack_hash")
    if not _is_non_empty_string_list(source_refs):
        placeholders.append("source_refs")
    if placeholders:
        policy_failures.append(
            "mcp_context_evidence contains missing or placeholder fields: "
            + ", ".join(placeholders)
        )
        return {"ok": False, "present": True, "missing_or_placeholder": placeholders}
    return {
        "ok": True,
        "present": True,
        "context_pack_id": context_pack_id,
        "context_pack_hash": context_pack_hash,
        "source_refs": source_refs,
    }


def _check_mcp_memory_field(
    manifest: dict[str, Any],
    malformed: list[str],
    policy_failures: list[str],
) -> dict[str, Any]:
    value = manifest.get("mcp_memory_updated_when_relevant")
    if value is None:
        policy_failures.append("mcp_memory_updated_when_relevant is required")
        return {"ok": False}
    if not isinstance(value, dict):
        malformed.append("mcp_memory_updated_when_relevant must be an object")
        return {"ok": False}

    relevant = value.get("relevant")
    updated = value.get("updated")
    if not isinstance(relevant, bool):
        malformed.append("mcp_memory_updated_when_relevant.relevant must be a boolean")
        return {"ok": False}
    if relevant and not isinstance(updated, bool):
        malformed.append("mcp_memory_updated_when_relevant.updated must be a boolean when relevant is true")
        return {"ok": False}
    if not relevant:
        return {"ok": True, "relevant": False}
    if not updated:
        policy_failures.append("mcp memory was relevant but not updated")
        return {"ok": False, "relevant": True, "updated": False}

    evidence_only = {
        key: nested
        for key, nested in value.items()
        if key not in {"relevant", "updated"}
    }
    if _structured_evidence_present(evidence_only):
        return {"ok": True, "relevant": True, "updated": True, "evidence": evidence_only}

    policy_failures.append(
        "mcp_memory_updated_when_relevant must include non-empty evidence when relevant is true"
    )
    return {"ok": False, "relevant": True, "updated": True}


def _check_hacker_questions_field(
    manifest: dict[str, Any],
    malformed: list[str],
    policy_failures: list[str],
) -> dict[str, Any]:
    value = manifest.get("hacker_questions")
    if value is not None and not isinstance(value, dict):
        malformed.append("hacker_questions must be an object when present")
        return {"ok": False}
    payload = dict(value or {})

    explicit_relevant = payload.get("source_review_relevant", manifest.get("source_review_relevant"))
    if explicit_relevant is not None and not isinstance(explicit_relevant, bool):
        malformed.append("hacker_questions.source_review_relevant must be a boolean when present")
        return {"ok": False}

    inferred_relevant = _infer_source_review_relevant(manifest)
    relevant = bool(explicit_relevant) if explicit_relevant is not None else inferred_relevant
    result: dict[str, Any] = {
        "ok": True,
        "relevant": relevant,
        "inferred_from_changed_artifacts": inferred_relevant,
    }
    if not relevant:
        result["mode"] = "not_required"
        return result

    artifacts = payload.get("artifacts", manifest.get("hacker_questions_artifacts"))
    schemas = payload.get("schemas", manifest.get("hacker_question_schemas"))
    reason = payload.get("no_hacker_questions_reason", manifest.get("no_hacker_questions_reason"))

    if artifacts is not None and not _is_non_empty_string_list(artifacts):
        malformed.append("hacker_questions.artifacts must be a non-empty string list when present")
        return {"ok": False, "relevant": True}
    if schemas is not None and not _is_non_empty_string_list(schemas):
        malformed.append("hacker_questions.schemas must be a non-empty string list when present")
        return {"ok": False, "relevant": True}
    if reason is not None and not _is_non_empty_text(reason):
        malformed.append("hacker_questions.no_hacker_questions_reason must be a non-empty string when present")
        return {"ok": False, "relevant": True}

    if _is_non_empty_string_list(artifacts):
        result.update({"mode": "artifact", "artifacts": artifacts})
        if not _is_non_empty_string_list(schemas):
            policy_failures.append(
                f"hacker_questions.schemas must include {HACKER_QUESTIONS_SCHEMA}"
            )
            result["ok"] = False
            return result
        result["schemas"] = schemas
        if HACKER_QUESTIONS_SCHEMA not in schemas:
            policy_failures.append(
                f"hacker_questions.schemas must include {HACKER_QUESTIONS_SCHEMA}"
            )
            result["ok"] = False
        return result

    if _is_non_empty_text(reason):
        result.update({"mode": "no_hacker_questions_reason", "reason": reason})
        if NO_HACKER_QUESTIONS_MARKER not in reason:
            policy_failures.append(
                f"hacker_questions.no_hacker_questions_reason must include {NO_HACKER_QUESTIONS_MARKER}"
            )
            result["ok"] = False
        return result

    policy_failures.append(
        "source-review slices require hacker_questions.artifacts or NO_HACKER_QUESTIONS reason"
    )
    result["ok"] = False
    return result


def _check_k6_learning_gate_field(
    manifest: dict[str, Any],
    malformed: list[str],
    policy_failures: list[str],
) -> dict[str, Any]:
    """K6 - finalization manifests must include learning_ledger_path,
    learning_gate_status, and unclassified_artifact_count, OR a typed
    NO_AGENT_ARTIFACTS_REASON.

    Advisory for low/no-draft slices; mandatory for High/Critical slices
    (detected via changed_artifacts severity scan).
    """
    # Check if the slice has High/Critical drafts.
    changed_artifacts = manifest.get("changed_artifacts")
    has_hc_drafts = False
    if isinstance(changed_artifacts, list):
        for artifact in changed_artifacts:
            if not isinstance(artifact, str) or not artifact.strip().lower().endswith(".md"):
                continue
            draft_path = _resolve_manifest_path(artifact, manifest, None)
            if draft_path.is_file():
                text = draft_path.read_text(encoding="utf-8", errors="replace")
                if _is_high_plus_draft_text(text):
                    has_hc_drafts = True
                    break

    no_reason = manifest.get("NO_AGENT_ARTIFACTS_REASON") or manifest.get("no_agent_artifacts_reason")
    if _is_non_empty_text(no_reason):
        return {
            "ok": True,
            "mode": "no_agent_artifacts_reason",
            "reason": str(no_reason).strip(),
            "has_hc_drafts": has_hc_drafts,
        }

    # Check for the three K6 fields.
    learning_ledger_path = manifest.get("learning_ledger_path")
    learning_gate_status = manifest.get("learning_gate_status")
    unclassified_count = manifest.get("unclassified_artifact_count")

    present_fields = []
    missing_fields = []
    for field_name, value in (
        ("learning_ledger_path", learning_ledger_path),
        ("learning_gate_status", learning_gate_status),
        ("unclassified_artifact_count", unclassified_count),
    ):
        if value is not None and not _is_placeholder_text(value):
            present_fields.append(field_name)
        else:
            missing_fields.append(field_name)

    if not missing_fields:
        return {
            "ok": True,
            "mode": "k6_fields_present",
            "learning_ledger_path": learning_ledger_path,
            "learning_gate_status": learning_gate_status,
            "unclassified_artifact_count": unclassified_count,
            "has_hc_drafts": has_hc_drafts,
        }

    # Missing K6 fields.  Surface as advisory here; hard enforcement lives in
    # audit-closeout-check.py check_learning_gate() (STRICT=1 gate).
    # loop-finalization-check reports but does not block on K6 absence so that
    # existing slices that pre-date K6 are not retroactively broken.
    summary = f"missing K6 learning-gate fields: {', '.join(missing_fields)}"
    advisory_note = summary + (
        " (High/Critical slice - add fields or NO_AGENT_ARTIFACTS_REASON; "
        "blocked in STRICT=1 audit-closeout)" if has_hc_drafts
        else " (advisory for non-H/C slices)"
    )
    return {
        "ok": True,
        "mode": "advisory_missing_k6_fields",
        "missing_fields": missing_fields,
        "present_fields": present_fields,
        "has_hc_drafts": has_hc_drafts,
        "advisory": advisory_note,
    }


def evaluate_manifest(
    manifest: dict[str, Any],
    *,
    allow_no_artifact: bool,
    manifest_path: Path | None = None,
) -> dict[str, Any]:
    malformed: list[str] = []
    policy_failures: list[str] = []
    advisory_checks = {
        "agent_cycle_log": _check_agent_cycle_log_field(manifest, manifest_path=manifest_path),
    }
    checks = {
        "artifact_evidence": _check_artifacts(
            manifest,
            allow_no_artifact=allow_no_artifact,
            malformed=malformed,
            policy_failures=policy_failures,
        ),
        "handoff_or_ledger_updated": _check_required_evidence_field(
            manifest, "handoff_or_ledger_updated", malformed, policy_failures
        ),
        "agent_outputs_collected": _check_required_evidence_field(
            manifest, "agent_outputs_collected", malformed, policy_failures
        ),
        "mcp_memory_updated_when_relevant": _check_mcp_memory_field(
            manifest, malformed, policy_failures
        ),
        "hacker_questions": _check_hacker_questions_field(
            manifest, malformed, policy_failures
        ),
    }
    checks["hacker_question_obligations"] = _check_open_hacker_question_obligations(
        manifest, malformed, policy_failures, manifest_path=manifest_path
    )
    checks["source_read_receipts"] = _check_source_read_receipts_for_high_plus_drafts(
        manifest, malformed, policy_failures, manifest_path=manifest_path
    )
    checks["tests_or_logs_linked"] = _check_tests_or_logs_linked(
        manifest, malformed, policy_failures, manifest_path=manifest_path
    )
    checks["mcp_context_evidence"] = _check_mcp_context_evidence_field(
        manifest, malformed, policy_failures
    )
    # K6 - learning-gate fields required for H/C draft slices.
    checks["k6_learning_gate"] = _check_k6_learning_gate_field(
        manifest, malformed, policy_failures
    )
    # r36-rebuttal: lane-HUNT-DEDUP-FIRST-ORCH registered in .auditooor/agent_pathspec.json
    # L36 - hunt-completeness BLOCKING gate: no exhausted/done slice without rc=0.
    checks["hunt_completeness"] = _check_hunt_completeness_when_done(
        manifest, malformed=malformed, policy_failures=policy_failures, manifest_path=manifest_path
    )
    # r36-rebuttal: lane-L37-AUDIT-COMPLETENESS registered in .auditooor/agent_pathspec.json
    # L37 - audit-completeness BLOCKING gate: no audit-done slice without rc=0.
    checks["audit_completeness"] = _check_audit_completeness_when_done(
        manifest, malformed=malformed, policy_failures=policy_failures, manifest_path=manifest_path
    )

    if malformed:
        status = "malformed_input"
        passed = False
    elif policy_failures:
        status = "policy_fail"
        passed = False
    else:
        status = "pass"
        passed = True
    return {
        "schema": SCHEMA,
        "status": status,
        "passed": passed,
        "allow_no_artifact": allow_no_artifact,
        "checks": checks,
        "advisory_checks": advisory_checks,
        "policy_failures": policy_failures,
        "malformed_reasons": malformed,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, help="Path to the loop finalization manifest JSON")
    parser.add_argument("--json", action="store_true", help="Emit the full evaluation result as JSON")
    parser.add_argument(
        "--allow-no-artifact",
        action="store_true",
        help="Allow a no_artifact_reason in place of changed_artifacts",
    )
    return parser


def _render_text(result: dict[str, Any]) -> str:
    status = str(result["status"]).upper()
    if result["passed"]:
        return "[loop-finalization-check] PASS: all required finalization proofs are present"
    failures = result["malformed_reasons"] if result["status"] == "malformed_input" else result["policy_failures"]
    return f"[loop-finalization-check] {status}: " + "; ".join(failures)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    manifest_path = Path(args.manifest).expanduser().resolve()
    manifest, load_errors = _load_manifest(manifest_path)
    if load_errors:
        result = {
            "schema": SCHEMA,
            "status": "malformed_input",
            "passed": False,
            "allow_no_artifact": args.allow_no_artifact,
            "manifest_path": str(manifest_path),
            "checks": {},
            "policy_failures": [],
            "malformed_reasons": load_errors,
        }
    else:
        result = evaluate_manifest(manifest, allow_no_artifact=args.allow_no_artifact, manifest_path=manifest_path)
        result["manifest_path"] = str(manifest_path)

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(_render_text(result))

    if result["status"] == "pass":
        return 0
    if result["status"] == "policy_fail":
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
