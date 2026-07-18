#!/usr/bin/env python3
"""Write proof-obligation queue freshness state after bridge runs.

This marker is advisory control-plane state. It never proves exploitability,
impact, severity, or submission readiness.
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.proof_queue_freshness_marker.v1"
DEFAULT_QUEUE_REL = ".auditooor/proof_obligation_queue.json"
DEFAULT_MARKER_REL = ".auditooor/proof_obligation_queue.freshness.json"
DEFAULT_MD_REL = ".auditooor/proof_obligation_queue.freshness.md"


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _is_under(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def _workspace_path(workspace: Path, raw: str | Path) -> Path:
    candidate = Path(raw).expanduser()
    if not candidate.is_absolute():
        candidate = workspace / candidate
    resolved = candidate.resolve()
    if not _is_under(resolved, workspace):
        raise ValueError(f"path escapes workspace: {raw}")
    return resolved


def _source_ref(path: Path, workspace: Path) -> str:
    try:
        return "<workspace>/" + path.resolve().relative_to(workspace.resolve()).as_posix()
    except ValueError:
        return "<external-input>"


def _mtime_utc(path: Path) -> str:
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except OSError:
        return ""


def _mtime_epoch(path: Path) -> float | None:
    try:
        return float(path.stat().st_mtime)
    except OSError:
        return None


def _load_queue_metadata(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {
            "exists": False,
            "json_valid": False,
            "schema": "",
            "status": "",
            "context_pack_id": "",
            "task_count": None,
            "generated_at_utc": "",
            "mtime_utc": "",
            "mtime_epoch": None,
        }
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        valid = isinstance(payload, dict)
    except (OSError, json.JSONDecodeError):
        payload = {}
        valid = False
    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    return {
        "exists": True,
        "json_valid": valid,
        "schema": str(payload.get("schema") or "") if valid else "",
        "status": str(payload.get("status") or "") if valid else "",
        "context_pack_id": str(payload.get("context_pack_id") or "") if valid else "",
        "task_count": summary.get("task_count") if valid else None,
        "generated_at_utc": str(payload.get("generated_at_utc") or "") if valid else "",
        "mtime_utc": _mtime_utc(path),
        "mtime_epoch": _mtime_epoch(path),
    }


def _load_queue_payload(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _coerce_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _ref_to_path(workspace: Path, ref: Any) -> tuple[Path | None, str]:
    raw = str(ref or "").strip()
    if not raw:
        return None, "empty_source_ref"
    if raw.startswith("<workspace>/"):
        raw = raw.removeprefix("<workspace>/")
    elif raw == "<workspace>":
        raw = "."
    elif raw.startswith("workspace:"):
        raw = raw.removeprefix("workspace:")
    elif raw.startswith(("http://", "https://", "repo:", "solodit:", "cantina:", "immunefi:", "sherlock:")):
        return None, "source_ref_not_workspace_scoped"
    candidate = Path(raw).expanduser()
    if not candidate.is_absolute():
        candidate = workspace / candidate
    if not _is_under(candidate, workspace):
        return None, "source_ref_workspace_mismatch"
    if not candidate.exists():
        text = str(candidate)
        if ":" in text:
            without_line = text.rsplit(":", 1)[0]
            if without_line and without_line != text:
                alt = Path(without_line)
                if _is_under(alt, workspace) and alt.exists():
                    return alt, ""
        return candidate, "source_ref_missing"
    return candidate, ""


def _task_source_refs(task: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    for key in ("source_ref", "source_refs", "source_paths"):
        for ref in _coerce_list(task.get(key)):
            text = str(ref or "").strip()
            if text:
                refs.append(text)
    return list(dict.fromkeys(refs))


def _has_concrete_evidence(task: dict[str, Any]) -> bool:
    evidence_keys = (
        "execution_manifest",
        "poc_execution_manifest",
        "proof_manifest",
        "proof_evidence",
        "harness_evidence",
        "runtime_evidence",
        "poc_evidence",
        "commands_attempted",
    )
    if any(bool(task.get(key)) for key in evidence_keys):
        return True
    concrete_values = {
        "proved",
        "proved_impact_evidence",
        "executed",
        "executed_with_manifest",
        "harness_passed",
        "runtime_poc_passed",
        "poc_passed",
        "proof_passed",
    }
    for key in ("execution_evidence", "proof_readiness", "proof_status", "evidence_class", "harness_status"):
        if str(task.get(key) or "").strip() in concrete_values:
            return True
    return False


def _workspace_matches(queue_payload: dict[str, Any], workspace: Path) -> bool:
    declared = str(queue_payload.get("workspace") or "").strip()
    if not declared or declared == "<workspace>":
        return True
    candidate = Path(declared).expanduser()
    if not candidate.is_absolute():
        return False
    try:
        return candidate.resolve() == workspace.resolve()
    except OSError:
        return False


def _evaluate_queue_freshness(workspace: Path, proof_queue: Path) -> dict[str, Any]:
    meta = _load_queue_metadata(proof_queue)
    reasons: list[str] = []
    task_results: list[dict[str, Any]] = []
    if not meta["exists"]:
        return {
            "fresh": False,
            "non_fresh_reasons": ["queue_missing"],
            "task_results": [],
            "checked_task_count": 0,
        }
    payload = _load_queue_payload(proof_queue)
    if payload is None:
        return {
            "fresh": False,
            "non_fresh_reasons": ["queue_json_invalid"],
            "task_results": [],
            "checked_task_count": 0,
        }
    if str(payload.get("schema") or "") != "auditooor.proof_obligation_queue.v1":
        reasons.append("queue_schema_mismatch")
    if not _workspace_matches(payload, workspace):
        reasons.append("queue_workspace_mismatch")
    queue_status = str(payload.get("status") or "").strip()
    if queue_status and queue_status != "ready":
        reasons.append("queue_status_not_ready")
    if bool(payload.get("blocked")):
        reasons.append("queue_blocked")
    if bool(payload.get("degraded")):
        reasons.append("queue_degraded")
    tasks = payload.get("tasks") if isinstance(payload.get("tasks"), list) else []
    if not tasks:
        reasons.append("queue_has_no_tasks")
    queue_mtime = meta.get("mtime_epoch")
    for idx, task in enumerate(tasks, start=1):
        if not isinstance(task, dict):
            reasons.append("task_not_object")
            task_results.append({"index": idx, "task_id": "", "fresh": False, "reasons": ["task_not_object"]})
            continue
        task_id = str(task.get("task_id") or f"task-{idx}").strip()
        task_reasons: list[str] = []
        if bool(task.get("advisory_only")):
            task_reasons.append("task_advisory_only")
        blocker_values = [str(task.get("blocker") or "").strip()]
        blocker_values.extend(str(item or "").strip() for item in _coerce_list(task.get("blockers")))
        blocker_values = [item for item in blocker_values if item]
        if blocker_values:
            task_reasons.append("task_has_blockers")
        refs = _task_source_refs(task)
        checked_refs: list[dict[str, Any]] = []
        if not refs:
            task_reasons.append("task_missing_source_refs")
        for ref in refs:
            ref_path, ref_error = _ref_to_path(workspace, ref)
            ref_result: dict[str, Any] = {"ref": ref}
            if ref_error:
                task_reasons.append(ref_error)
                ref_result["status"] = ref_error
            elif ref_path is not None:
                ref_result["status"] = "ok"
                ref_result["path"] = _source_ref(ref_path, workspace)
                ref_mtime = _mtime_epoch(ref_path)
                if queue_mtime is not None and ref_mtime is not None and ref_mtime > float(queue_mtime):
                    task_reasons.append("source_ref_newer_than_queue")
                    ref_result["status"] = "source_ref_newer_than_queue"
            checked_refs.append(ref_result)
        if not _has_concrete_evidence(task):
            task_reasons.append("task_missing_concrete_proof_or_harness_evidence")
        task_reasons = list(dict.fromkeys(task_reasons))
        reasons.extend(task_reasons)
        task_results.append(
            {
                "index": idx,
                "task_id": task_id,
                "fresh": not task_reasons,
                "reasons": task_reasons,
                "source_refs": checked_refs,
                "blockers": blocker_values,
            }
        )
    reasons = list(dict.fromkeys(reasons))
    return {
        "fresh": not reasons,
        "non_fresh_reasons": reasons,
        "task_results": task_results,
        "checked_task_count": len(tasks),
    }


def build_marker(
    *,
    workspace: Path,
    mode: str,
    reason: str,
    bridge_rc: int,
    proof_queue: Path,
    generated_at: str = "",
) -> dict[str, Any]:
    queue_meta = _load_queue_metadata(proof_queue)
    freshness = _evaluate_queue_freshness(workspace, proof_queue)
    if mode == "mark-stale":
        status = "stale_existing_proof_queue" if queue_meta["exists"] else "no_existing_proof_queue"
        stale = True
    elif mode == "mark-fresh":
        status = "fresh_bridge_completed" if freshness["fresh"] else "non_fresh_proof_queue"
        stale = not bool(freshness["fresh"])
    else:
        raise ValueError(f"unknown mode: {mode}")
    return {
        "schema": SCHEMA,
        "workspace": "<workspace>",
        "advisory_only": True,
        "status": status,
        "fresh": bool(freshness["fresh"]) and mode == "mark-fresh",
        "stale": stale,
        "non_fresh_reasons": freshness["non_fresh_reasons"] if stale else [],
        "freshness": freshness,
        "mode": mode,
        "reason": reason,
        "bridge_rc": int(bridge_rc),
        "generated_at_utc": generated_at or _utc_now(),
        "proof_queue": {
            "path": _source_ref(proof_queue, workspace),
            **queue_meta,
        },
        "remediation": (
            "Rerun make audit-hacker-logic-bridge or make proof-obligation-queue after current audit artifacts are fixed; "
            "do not route workers from a stale proof queue."
            if stale
            else "Proof queue freshness marker is informational; queue rows remain advisory and require source/PoC proof."
        ),
        "claim_boundary": "Freshness marker only; not exploit proof, severity proof, duplicate status, OOS status, or submission readiness.",
    }


def render_markdown(marker: dict[str, Any]) -> str:
    queue = marker.get("proof_queue") if isinstance(marker.get("proof_queue"), dict) else {}
    reasons = marker.get("non_fresh_reasons") if isinstance(marker.get("non_fresh_reasons"), list) else []
    return "\n".join(
        [
            "# Proof Obligation Queue Freshness",
            "",
            f"- Status: `{marker.get('status', '')}`",
            f"- Fresh: `{marker.get('fresh', False)}`",
            f"- Stale: `{marker.get('stale', False)}`",
            f"- Mode: `{marker.get('mode', '')}`",
            f"- Bridge rc: `{marker.get('bridge_rc', '')}`",
            f"- Reason: {marker.get('reason', '')}",
            f"- Non-fresh reasons: `{', '.join(str(item) for item in reasons)}`",
            f"- Proof queue: `{queue.get('path', '')}`",
            f"- Queue exists: `{queue.get('exists', False)}`",
            f"- Queue JSON valid: `{queue.get('json_valid', False)}`",
            f"- Queue status: `{queue.get('status', '')}`",
            "",
            marker.get("claim_boundary", ""),
            "",
        ]
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, help="Workspace root")
    parser.add_argument("--mode", choices=("mark-stale", "mark-fresh"), required=True)
    parser.add_argument("--reason", default="")
    parser.add_argument("--bridge-rc", type=int, default=0)
    parser.add_argument("--proof-queue", default=DEFAULT_QUEUE_REL)
    parser.add_argument("--marker-out", default=DEFAULT_MARKER_REL)
    parser.add_argument("--md-out", default=DEFAULT_MD_REL)
    parser.add_argument("--generated-at", default="")
    parser.add_argument("--print-json", action="store_true")
    return parser.parse_args(argv)


def run(argv: list[str] | None = None) -> dict[str, Any]:
    args = parse_args(argv)
    workspace = Path(args.workspace).expanduser().resolve()
    if not workspace.is_dir():
        raise SystemExit(f"[proof-queue-freshness-marker] ERR workspace not found: {workspace}")
    proof_queue = _workspace_path(workspace, args.proof_queue)
    marker_out = _workspace_path(workspace, args.marker_out)
    md_out = _workspace_path(workspace, args.md_out)
    marker = build_marker(
        workspace=workspace,
        mode=args.mode,
        reason=args.reason,
        bridge_rc=args.bridge_rc,
        proof_queue=proof_queue,
        generated_at=args.generated_at,
    )
    marker_out.parent.mkdir(parents=True, exist_ok=True)
    marker_out.write_text(json.dumps(marker, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_out.parent.mkdir(parents=True, exist_ok=True)
    md_out.write_text(render_markdown(marker), encoding="utf-8")
    if args.print_json:
        print(json.dumps(marker, indent=2, sort_keys=True))
    return marker


def main() -> int:
    try:
        run()
    except ValueError as exc:
        raise SystemExit(f"[proof-queue-freshness-marker] ERR {exc}") from None
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
