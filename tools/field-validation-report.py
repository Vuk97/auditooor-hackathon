#!/usr/bin/env python3
"""Offline V3 field-validation readiness report.

This report is intentionally conservative. It summarizes whether a workspace
or campaign has enough local evidence to evaluate field validation readiness:

* pre-filing accuracy signals from provider/local-verification artifacts;
* conversion/proof execution signals from exploit queues and PoC manifests;
* triage survival/outcome signals when outcome artifacts exist;
* explicit unknowns when artifacts are missing or too thin.

It never claims payout, acceptance, submission readiness, or exploitability.
All rows are local/offline artifact summaries.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTCOMES = ROOT / "reference" / "outcomes.jsonl"
SCHEMA = "auditooor.field_validation_report.v1"
PENDING_FILED_WITHOUT_PLATFORM_ID_NAME = "pending_filed_without_platform_id.jsonl"

POSITIVE_OUTCOME_WORDS = {"accepted", "paid", "rewarded", "valid", "confirmed"}
NEGATIVE_OUTCOME_WORDS = {
    "rejected",
    "duplicate",
    "duplicate_of_accepted",
    "duplicate_of_rejected",
    "oos",
    "out_of_scope",
    "withdrawn",
    "invalid",
}
PENDING_OUTCOME_WORDS = {"pending", "submitted", "in_review", "triage", "open"}


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _read_json_object(path: Path) -> dict[str, Any]:
    data = _read_json(path)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected JSON object")
    return data


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    rows: list[dict[str, Any]] = []
    for line_no, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError as exc:
            rows.append({"_parse_error": True, "_path": str(path), "_line": line_no, "_error": str(exc)})
            continue
        if isinstance(data, dict):
            rows.append(data)
        else:
            rows.append({"_parse_error": True, "_path": str(path), "_line": line_no, "_error": "expected object"})
    return rows


def _safe_rel(path: Path, base: Path) -> str:
    try:
        return path.resolve().relative_to(base.resolve()).as_posix()
    except ValueError:
        return str(path)


def _workspace_cmd(workspace: Path, target: str, *args: str) -> str:
    suffix = " ".join(arg for arg in args if arg)
    return f"make {target} WS={workspace}{(' ' + suffix) if suffix else ''}"


def _campaign_hint(campaign_id: str | None) -> str:
    return campaign_id or "<campaign-id>"


def _missing_artifact(name: str, *, expected_paths: list[str], next_commands: list[str], reason: str) -> dict[str, Any]:
    return {
        "artifact": name,
        "status": "missing_or_insufficient",
        "reason": reason,
        "expected_paths": expected_paths,
        "next_commands": next_commands,
    }


def _dedupe_dicts(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for row in rows:
        key = json.dumps(row, sort_keys=True, default=str)
        if key in seen:
            continue
        seen.add(key)
        out.append(row)
    return out


def _field_loop_next_steps(sections: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    for section in sections:
        for artifact in section.get("missing_artifacts", []) or []:
            if not isinstance(artifact, dict):
                continue
            steps.append(
                {
                    "artifact": artifact.get("artifact") or "",
                    "reason": artifact.get("reason") or "",
                    "expected_paths": artifact.get("expected_paths") or [],
                    "next_commands": artifact.get("next_commands") or [],
                }
            )
    return _dedupe_dicts(steps)


def _section_next_commands(missing_artifacts: Iterable[dict[str, Any]]) -> list[str]:
    commands: list[str] = []
    for artifact in missing_artifacts:
        for command in artifact.get("next_commands", []) or []:
            if isinstance(command, str) and command and command not in commands:
                commands.append(command)
    return commands


def _campaign_roots(workspace: Path, campaign_id: str | None) -> list[Path]:
    provider_root = workspace / ".auditooor" / "provider_fanout"
    if campaign_id:
        return [provider_root / campaign_id]
    if not provider_root.is_dir():
        return []
    return sorted((p for p in provider_root.iterdir() if p.is_dir()), key=lambda p: p.name)


def _iter_json_files(paths: Iterable[Path], pattern: str) -> list[Path]:
    out: list[Path] = []
    for root in paths:
        if root.is_dir():
            out.extend(sorted(root.glob(pattern), key=lambda p: str(p)))
    return out


def _flatten(value: Any) -> Iterable[Any]:
    if isinstance(value, dict):
        for key, child in value.items():
            yield key
            yield from _flatten(child)
    elif isinstance(value, list):
        for child in value:
            yield from _flatten(child)
    else:
        yield value


def _text_blob(value: Any, *, limit: int = 20000) -> str:
    pieces: list[str] = []
    for item in _flatten(value):
        if item is None or isinstance(item, bool):
            continue
        pieces.append(str(item))
        if sum(len(p) for p in pieces) > limit:
            break
    return " ".join(pieces).lower()


def _count_statuses(rows: Iterable[dict[str, Any]], keys: tuple[str, ...] = ("status", "route", "final_result", "outcome")) -> Counter[str]:
    counts: Counter[str] = Counter()
    for row in rows:
        for key in keys:
            value = row.get(key)
            if isinstance(value, str) and value.strip():
                counts[value.strip().lower()] += 1
                break
    return counts


def _local_verification_rows(workspace: Path, campaign_id: str | None) -> tuple[list[dict[str, Any]], list[str]]:
    roots = [workspace / ".auditooor"]
    roots.extend(_campaign_roots(workspace, campaign_id))
    paths = sorted(set(_iter_json_files(roots, "**/*local*verification*queue*.json")), key=lambda p: str(p))
    rows: list[dict[str, Any]] = []
    sources: list[str] = []
    for path in paths:
        try:
            data = _read_json(path)
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        sources.append(_safe_rel(path, workspace))
        if isinstance(data, dict):
            for key in ("local_grep_tasks", "fixture_needed_tasks", "source_review_tasks", "killed_rows", "rows", "tasks", "queue"):
                value = data.get(key)
                if isinstance(value, list):
                    rows.extend(item for item in value if isinstance(item, dict))
        elif isinstance(data, list):
            rows.extend(item for item in data if isinstance(item, dict))
    return rows, sorted(set(sources))


def _closeout_rows(workspace: Path, campaign_id: str | None) -> tuple[list[dict[str, Any]], list[str]]:
    paths = _iter_json_files(_campaign_roots(workspace, campaign_id), "runs/*/fanout_closeout.json")
    rows: list[dict[str, Any]] = []
    sources: list[str] = []
    for path in paths:
        try:
            data = _read_json_object(path)
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        sources.append(_safe_rel(path, workspace))
        for key in ("rows", "results", "tasks", "verdicts"):
            value = data.get(key)
            if isinstance(value, list):
                rows.extend(item for item in value if isinstance(item, dict))
        summary = data.get("summary")
        if isinstance(summary, dict):
            rows.append({"status": "summary", **summary})
    return rows, sorted(set(sources))


def _build_pre_filing(workspace: Path, campaign_id: str | None) -> dict[str, Any]:
    queue_rows, queue_sources = _local_verification_rows(workspace, campaign_id)
    closeout_rows, closeout_sources = _closeout_rows(workspace, campaign_id)
    rows = queue_rows + closeout_rows
    blob = _text_blob(rows)
    status_counts = _count_statuses(rows)
    killed = sum(1 for row in rows if "kill" in _text_blob(row, limit=1000) or str(row.get("route", "")).startswith("kill"))
    local_review = sum(
        1
        for row in rows
        if any(token in _text_blob(row, limit=1000) for token in ("local_source_review", "local_grep", "fixture_needed", "source_review"))
    )
    source_artifacts = sorted(set(queue_sources + closeout_sources))
    unknowns: list[str] = []
    if not source_artifacts:
        unknowns.append("no provider/local-verification campaign artifacts found")
    if rows and local_review == 0 and killed == 0:
        unknowns.append("provider rows found but no recognizable local-review or kill signals")
    campaign = _campaign_hint(campaign_id)
    missing_artifacts: list[dict[str, Any]] = []
    if not queue_sources:
        missing_artifacts.append(
            _missing_artifact(
                "provider local-verification queue",
                expected_paths=[
                    f".auditooor/provider_fanout/{campaign}/runs/<run>/v3_provider_local_verification_queue.json",
                    f".auditooor/provider_fanout/{campaign}/runs/<run>/local_verification_queue.json",
                ],
                next_commands=[
                    _workspace_cmd(workspace, "v3-provider-fanout-queue", f"CAMPAIGN_ID={campaign}"),
                    _workspace_cmd(workspace, "v3-provider-fanout-closeout", f"CAMPAIGN_ID={campaign}"),
                    _workspace_cmd(workspace, "v3-provider-local-verification-queue", f"CAMPAIGN_ID={campaign}"),
                ],
                reason="no local-verification queue artifacts were found for this workspace/campaign",
            )
        )
    if not closeout_sources:
        missing_artifacts.append(
            _missing_artifact(
                "provider fanout closeout",
                expected_paths=[f".auditooor/provider_fanout/{campaign}/runs/<run>/fanout_closeout.json"],
                next_commands=[
                    _workspace_cmd(workspace, "v3-provider-fanout-run", f"CAMPAIGN_ID={campaign}", "DRY_RUN=1"),
                    _workspace_cmd(workspace, "v3-provider-fanout-closeout", f"CAMPAIGN_ID={campaign}"),
                ],
                reason="no fanout closeout artifact was found to summarize provider rows before local review",
            )
        )
    if rows and local_review + killed == 0:
        missing_artifacts.append(
            _missing_artifact(
                "local review or negative filtering rows",
                expected_paths=[
                    f".auditooor/provider_fanout/{campaign}/runs/<run>/v3_provider_local_verification_result.json",
                    f".auditooor/provider_fanout/{campaign}/runs/<run>/fanout_closeout.json",
                ],
                next_commands=[
                    _workspace_cmd(workspace, "v3-provider-local-verify", f"CAMPAIGN_ID={campaign}"),
                    _workspace_cmd(workspace, "v3-provider-fanout-closeout", f"CAMPAIGN_ID={campaign}"),
                ],
                reason="provider artifacts exist but do not show local_source_review, local_grep, fixture_needed, source_review, or kill signals",
            )
        )
    return {
        "status": _section_status(bool(source_artifacts), local_review + killed),
        "source_artifacts": source_artifacts,
        "counts": {
            "artifact_count": len(source_artifacts),
            "rows_considered": len(rows),
            "local_review_rows": local_review,
            "killed_or_negative_prefiling_rows": killed,
            "status_counts": dict(sorted(status_counts.items())),
        },
        "signals": [
            "local verification artifacts present" if queue_sources else "",
            "provider fanout closeout artifacts present" if closeout_sources else "",
            "pre-filing rows include local review or kill signals" if local_review + killed else "",
        ],
        "unknowns": unknowns,
        "missing_artifacts": missing_artifacts,
        "next_commands": _section_next_commands(missing_artifacts),
        "raw_positive_claim_terms_seen": any(word in blob for word in POSITIVE_OUTCOME_WORDS),
    }


def _execution_manifests(workspace: Path) -> tuple[list[dict[str, Any]], list[str]]:
    paths = sorted((workspace / "poc_execution").glob("**/execution_manifest.json"), key=lambda p: str(p))
    rows: list[dict[str, Any]] = []
    sources: list[str] = []
    for path in paths:
        try:
            data = _read_json_object(path)
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        rows.append(data)
        sources.append(_safe_rel(path, workspace))
    return rows, sources


def _optional_object(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    if not path.is_file():
        return None, None
    try:
        return _read_json_object(path), str(path)
    except (OSError, ValueError, json.JSONDecodeError):
        return None, str(path)


def _expected_execution_manifest_path(workspace: Path, row_id: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", row_id.strip().lower()).strip("-") or "candidate"
    return _safe_rel(workspace / "poc_execution" / safe / "execution_manifest.json", workspace)


def _conversion_actionable_gaps(
    workspace: Path,
    bridge: dict[str, Any] | None,
    harness_queue: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    gaps: list[dict[str, Any]] = []
    if isinstance(bridge, dict):
        for row in bridge.get("rows") or []:
            if not isinstance(row, dict):
                continue
            row_id = str(row.get("row_id") or row.get("queue_item_id") or "").strip()
            blocked_reason = str(
                row.get("poc_execution_record_blocked_reason")
                or row.get("bridge_status")
                or row.get("poc_execution_record_status")
                or ""
            ).strip()
            if not row_id or (blocked_reason and "blocked" not in blocked_reason and "missing" not in blocked_reason):
                continue
            expected_manifest = row.get("poc_execution_record_path") or _expected_execution_manifest_path(workspace, row_id)
            gaps.append(
                {
                    "source": "high_impact_execution_bridge",
                    "row_id": row_id,
                    "status": row.get("bridge_status") or row.get("poc_execution_record_status") or "blocked",
                    "blocker": blocked_reason or "missing_execution_manifest",
                    "expected_execution_manifest_path": expected_manifest,
                    "next_commands": [
                        cmd
                        for cmd in (
                            row.get("impact_contract_command"),
                            row.get("impact_contract_skeleton_command"),
                            row.get("poc_execution_record_command"),
                        )
                        if isinstance(cmd, str) and cmd.strip()
                    ],
                    "skeleton_path": row.get("impact_contract_skeleton_path") or "",
                    "counts_as_proof": False,
                }
            )
    if isinstance(harness_queue, dict):
        for row in harness_queue.get("rows") or []:
            if not isinstance(row, dict):
                continue
            row_id = str(row.get("row_id") or "").strip()
            status = str(row.get("status") or "").strip()
            if not row_id or "blocked" not in status:
                continue
            gaps.append(
                {
                    "source": "harness_execution_queue_from_exploit_queue",
                    "row_id": row_id,
                    "status": status,
                    "blocker": ",".join(str(item) for item in row.get("blockers") or []) or status,
                    "missing_inputs": [str(item) for item in row.get("missing_inputs") or []],
                    "expected_next_action": row.get("expected_next_action") or "",
                    "expected_execution_manifest_path": _expected_execution_manifest_path(workspace, row_id),
                    "next_commands": [str(cmd) for cmd in row.get("safe_local_prereq_commands") or []],
                    "counts_as_proof": False,
                }
            )
    return gaps


def _non_counting_execution_context(workspace: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted((workspace / "poc_execution").glob("**/*.json"), key=lambda p: str(p)):
        if path.name == "execution_manifest.json":
            continue
        try:
            data = _read_json_object(path)
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        execution = data.get("execution") if isinstance(data.get("execution"), dict) else {}
        preflight = data.get("preflight") if isinstance(data.get("preflight"), dict) else {}
        rows.append(
            {
                "path": _safe_rel(path, workspace),
                "schema": data.get("schema") or "",
                "candidate_id": data.get("candidate_id") or "",
                "status": execution.get("status") or data.get("status") or "",
                "attempted": execution.get("attempted") if "attempted" in execution else data.get("attempted"),
                "execution_allowed": preflight.get("execution_allowed"),
                "runtime_proof_claimed": data.get("runtime_proof_claimed"),
                "submission_posture": data.get("submission_posture") or "",
                "counts_as_proof": False,
            }
        )
    return rows[:20]


def _build_conversion(workspace: Path) -> dict[str, Any]:
    manifests, manifest_sources = _execution_manifests(workspace)
    exploit_queue, exploit_source = _optional_object(workspace / ".auditooor" / "exploit_queue.json")
    bridge, bridge_source = _optional_object(workspace / ".auditooor" / "high_impact_execution_bridge.json")
    harness_queue, harness_source = _optional_object(workspace / ".auditooor" / "harness_execution_queue_from_exploit_queue.json")
    proof_like = [
        row
        for row in manifests
        if row.get("evidence_class") == "executed_with_manifest"
        or row.get("final_result") in {"proved", "disproved"}
        or any(isinstance(cmd, dict) and cmd.get("status") in {"pass", "fail"} for cmd in row.get("commands_attempted", []) or [])
    ]
    source_artifacts = list(manifest_sources)
    if exploit_source:
        source_artifacts.append(_safe_rel(Path(exploit_source), workspace))
    if bridge_source:
        source_artifacts.append(_safe_rel(Path(bridge_source), workspace))
    if harness_source:
        source_artifacts.append(_safe_rel(Path(harness_source), workspace))
    exploit_rows = exploit_queue.get("queue", []) if isinstance(exploit_queue, dict) else []
    if not isinstance(exploit_rows, list):
        exploit_rows = exploit_queue.get("rows", []) if isinstance(exploit_queue, dict) and isinstance(exploit_queue.get("rows"), list) else []
    bridge_rows = bridge.get("rows", []) if isinstance(bridge, dict) and isinstance(bridge.get("rows"), list) else []
    harness_rows = harness_queue.get("rows", []) if isinstance(harness_queue, dict) and isinstance(harness_queue.get("rows"), list) else []
    actionable_gaps = _conversion_actionable_gaps(workspace, bridge, harness_queue) if source_artifacts and not proof_like else []
    non_counting_context = _non_counting_execution_context(workspace) if source_artifacts and not proof_like else []
    unknowns: list[str] = []
    if not source_artifacts:
        unknowns.append("no exploit queue, execution manifest, or execution bridge artifacts found")
    if source_artifacts and not proof_like:
        unknowns.append("conversion artifacts exist but no executed manifest/proof-like row was found")
    missing_artifacts: list[dict[str, Any]] = []
    if not exploit_source:
        missing_artifacts.append(
            _missing_artifact(
                "exploit queue",
                expected_paths=[".auditooor/exploit_queue.json"],
                next_commands=[_workspace_cmd(workspace, "exploit-queue", "JSON=1")],
                reason="no exploit queue was found to select real hunt candidates",
            )
        )
    if not bridge_source:
        missing_artifacts.append(
            _missing_artifact(
                "high-impact execution bridge",
                expected_paths=[".auditooor/high_impact_execution_bridge.json"],
                next_commands=[_workspace_cmd(workspace, "high-impact-execution-bridge", "JSON=1")],
                reason="no bridge artifact was found to map candidates to proof obligations and execution handoffs",
            )
        )
    if not harness_source:
        missing_artifacts.append(
            _missing_artifact(
                "harness execution queue from exploit queue",
                expected_paths=[".auditooor/harness_execution_queue_from_exploit_queue.json"],
                next_commands=[
                    _workspace_cmd(workspace, "prove-top-leads", "TOP_N=10", "EXECUTE_READY=0", "JSON=1"),
                    _workspace_cmd(workspace, "exploit-conversion-loop", "TOP_N=10", "EXECUTE_READY=0", "JSON=1"),
                ],
                reason="no harness queue was found to show which proof commands are runnable or blocked",
            )
        )
    if not proof_like:
        missing_artifacts.append(
            _missing_artifact(
                "executed PoC manifest",
                expected_paths=["poc_execution/<candidate-id>/execution_manifest.json"],
                next_commands=[
                    _workspace_cmd(
                        workspace,
                        "poc-execution-record",
                        "BRIEF=<brief.md>",
                        "CMD='<local proof command>'",
                        "RESULT=<proved|disproved|blocked_env|blocked_path|needs_human>",
                        "JSON=1",
                    )
                ],
                reason="no execution manifest with executed_with_manifest, proved/disproved final_result, or pass/fail command status was found",
            )
        )
    return {
        "status": _section_status(bool(source_artifacts), len(proof_like)),
        "source_artifacts": sorted(set(source_artifacts)),
        "counts": {
            "execution_manifest_count": len(manifests),
            "executed_manifest_count": len(proof_like),
            "exploit_queue_rows": len([r for r in exploit_rows if isinstance(r, dict)]),
            "bridge_rows": len([r for r in bridge_rows if isinstance(r, dict)]),
            "harness_queue_rows": len([r for r in harness_rows if isinstance(r, dict)]),
            "actionable_gap_count": len(actionable_gaps),
            "non_counting_execution_context_count": len(non_counting_context),
            "final_result_counts": dict(sorted(_count_statuses(manifests, ("final_result",)).items())),
        },
        "actionable_gaps": actionable_gaps,
        "non_counting_execution_context": non_counting_context,
        "signals": [
            "execution manifests present" if manifests else "",
            "executed manifest/proof-like rows present" if proof_like else "",
            "exploit queue present" if exploit_queue else "",
            "high-impact execution bridge present" if bridge else "",
            "harness execution queue present" if harness_queue else "",
            "blocked conversion rows surfaced as actionable gaps" if actionable_gaps else "",
            "non-counting execution context surfaced" if non_counting_context else "",
        ],
        "unknowns": unknowns,
        "missing_artifacts": missing_artifacts,
        "next_commands": _section_next_commands(missing_artifacts),
    }


def _workspace_matches(row: dict[str, Any], workspace: Path, campaign_id: str | None) -> bool:
    needles = {workspace.name.lower(), str(workspace).lower()}
    if campaign_id:
        needles.add(campaign_id.lower())
    for key in ("workspace", "engagement", "campaign", "campaign_id", "source_ref"):
        value = row.get(key)
        if isinstance(value, str):
            low = value.lower()
            if any(needle and needle in low for needle in needles):
                return True
    return False


def _outcome_bucket(row: dict[str, Any]) -> str:
    text = " ".join(str(row.get(k, "")) for k in ("outcome", "status", "outcome_class", "triager_outcome")).strip().lower()
    if any(word in text for word in POSITIVE_OUTCOME_WORDS):
        return "positive_terminal"
    if any(word in text for word in NEGATIVE_OUTCOME_WORDS):
        return "non_positive_terminal"
    if any(word in text for word in PENDING_OUTCOME_WORDS):
        return "pending_or_unresolved"
    return "unknown"


def _submission_status_counts(workspace: Path) -> tuple[Counter[str], list[str]]:
    candidates = [workspace / "submissions" / "SUBMISSIONS.md", workspace / "SUBMISSIONS.md"]
    for path in candidates:
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace").lower()
        counts: Counter[str] = Counter()
        for token in ("submitted", "filed", "rejected", "duplicate", "oos", "withdrawn", "pending"):
            counts[token] = len(re.findall(rf"\b{re.escape(token)}\b", text))
        return counts, [_safe_rel(path, workspace)]
    return Counter(), []


def _pending_filed_without_platform_id_rows(workspace: Path, campaign_id: str | None) -> tuple[list[dict[str, Any]], list[str]]:
    path = workspace / "reference" / PENDING_FILED_WITHOUT_PLATFORM_ID_NAME
    rows = [row for row in _read_jsonl(path) if not row.get("_parse_error")]
    matched = [row for row in rows if _workspace_matches(row, workspace, campaign_id)]
    if rows and not matched and not campaign_id:
        matched = rows
    return matched, [_safe_rel(path, workspace)] if path.is_file() else []


def _build_outcomes(workspace: Path, campaign_id: str | None, outcomes_path: Path) -> dict[str, Any]:
    rows = [row for row in _read_jsonl(outcomes_path) if not row.get("_parse_error")]
    matched = [row for row in rows if _workspace_matches(row, workspace, campaign_id)]
    bucket_counts = Counter(_outcome_bucket(row) for row in matched)
    submission_counts, submission_sources = _submission_status_counts(workspace)
    pending_rows, pending_sources = _pending_filed_without_platform_id_rows(workspace, campaign_id)
    source_artifacts: list[str] = []
    if outcomes_path.is_file():
        source_artifacts.append(str(outcomes_path))
    source_artifacts.extend(submission_sources)
    source_artifacts.extend(pending_sources)
    evidence_count = len(matched)
    unknowns: list[str] = []
    if not source_artifacts:
        unknowns.append("no outcome ledger or SUBMISSIONS.md artifact found")
    elif not evidence_count:
        if pending_rows:
            unknowns.append(
                "pending filed-without-platform-id rows exist but do not count as outcome evidence until real platform IDs/URLs are backfilled"
            )
        else:
            unknowns.append("outcome artifacts exist but no structured rows matched this workspace/campaign")
    missing_artifacts: list[dict[str, Any]] = []
    if not outcomes_path.is_file():
        missing_artifacts.append(
            _missing_artifact(
                "outcome ledger",
                expected_paths=[str(outcomes_path)],
                next_commands=[_workspace_cmd(workspace, "validate-outcome-ledger", "JSON=1")],
                reason="no outcome ledger file was found",
            )
        )
    if not submission_sources:
        missing_artifacts.append(
            _missing_artifact(
                "workspace submission tracker",
                expected_paths=["submissions/SUBMISSIONS.md", "SUBMISSIONS.md"],
                next_commands=[f"make submission-sync WORKSPACE={workspace}"],
                reason="no workspace SUBMISSIONS.md tracker was found",
            )
        )
    if source_artifacts and not evidence_count:
        missing_artifacts.append(
            _missing_artifact(
                "workspace/campaign outcome row",
                expected_paths=[
                    str(outcomes_path),
                    "submissions/SUBMISSIONS.md",
                    "SUBMISSIONS.md",
                    f"reference/{PENDING_FILED_WITHOUT_PLATFORM_ID_NAME}",
                ],
                next_commands=[
                    _workspace_cmd(
                        workspace,
                        "record-submission",
                        "PLATFORM=<platform>",
                        "URL=<real-platform-url>",
                        "ID=<real-platform-id>",
                        "TITLE=<finding-title>",
                        "SEVERITY=<severity>",
                    ),
                    _workspace_cmd(
                        workspace,
                        "record-pending-filed-without-platform-id",
                        "LOCAL_ID=<local-row-id>",
                        "PLATFORM=<platform>",
                        "TITLE=<finding-title>",
                        "SOURCE_PATH=submissions/SUBMISSIONS.md",
                    ),
                    _workspace_cmd(
                        workspace,
                        "record-outcome",
                        "ID=<real-platform-id>",
                        "STATE=<accepted|paid|duplicate|rejected|duplicate_of_accepted|duplicate_of_rejected|withdrawn>",
                    ),
                    _workspace_cmd(workspace, "validate-outcome-ledger", "JSON=1"),
                ],
                reason=(
                    "outcome artifacts exist but no structured row matched this workspace/campaign; "
                    "create a pending submission row only after a real platform filing, "
                    "then update it with record-outcome after a real triager/platform decision; "
                    "filed rows without platform IDs may be tracked separately as pending only"
                ),
            )
        )
    status = _section_status(bool(source_artifacts), evidence_count)
    if pending_rows and evidence_count == 0:
        status = "artifact_present_pending"
    return {
        "status": status,
        "source_artifacts": source_artifacts,
        "counts": {
            "ledger_rows_total": len(rows),
            "ledger_rows_matched": len(matched),
            "outcome_bucket_counts": dict(sorted(bucket_counts.items())),
            "submission_text_status_mentions": dict(sorted((k, v) for k, v in submission_counts.items() if v)),
            "submission_text_status_mentions_counted_as_outcome_evidence": False,
            "pending_filed_without_platform_id_rows": len(pending_rows),
            "pending_filed_without_platform_id_counted_as_outcome_evidence": False,
            "pending_filed_without_platform_id_counted_as_submission_evidence": False,
        },
        "signals": [
            "outcome ledger present" if outcomes_path.is_file() else "",
            "workspace/campaign outcome rows matched" if matched else "",
            "SUBMISSIONS.md tracker present (status text is advisory only)" if submission_sources else "",
            "pending filed-without-platform-id tracker present (pending only)" if pending_rows else "",
        ],
        "unknowns": unknowns,
        "missing_artifacts": missing_artifacts,
        "next_commands": _section_next_commands(missing_artifacts),
    }


def _section_status(has_artifact: bool, signal_count: int) -> str:
    if not has_artifact:
        return "unknown"
    if signal_count > 0:
        return "ready_for_evaluation"
    return "artifact_present_no_signal"


def _compact_signals(section: dict[str, Any]) -> None:
    section["signals"] = [s for s in section.get("signals", []) if s]


def _readiness(pre: dict[str, Any], conv: dict[str, Any], outcomes: dict[str, Any]) -> dict[str, Any]:
    sections = [pre, conv, outcomes]
    ready = sum(1 for section in sections if section.get("status") == "ready_for_evaluation")
    present = sum(1 for section in sections if section.get("status") != "unknown")
    if ready == 3:
        status = "field_validation_ready_for_evaluation"
    elif ready >= 2 and present == 3:
        status = "partial_with_outcome_gap"
    elif ready >= 1:
        status = "insufficient_needs_more_artifacts"
    else:
        status = "unknown_no_evaluable_signals"
    return {
        "status": status,
        "ready_sections": ready,
        "artifact_sections_present": present,
        "score": round(ready / 3, 4),
        "definition_of_done": [
            "pre-filing rows show local verification or negative filtering signals",
            "conversion rows include executed manifest/proof-like evidence",
            "triage survival/outcome artifacts are present and match the workspace/campaign",
            "unknowns are explicitly enumerated",
        ],
        "blocking_unknowns": pre.get("unknowns", []) + conv.get("unknowns", []) + outcomes.get("unknowns", []),
        "field_loop_next_steps": _field_loop_next_steps(sections),
    }


def build_report(workspace: Path, *, campaign_id: str | None = None, outcomes_path: Path = DEFAULT_OUTCOMES) -> dict[str, Any]:
    ws = workspace.expanduser().resolve()
    if not ws.is_dir():
        raise SystemExit(f"[field-validation-report] workspace not found: {ws}")
    outcomes_path = outcomes_path.expanduser().resolve()
    pre = _build_pre_filing(ws, campaign_id)
    conv = _build_conversion(ws)
    outcomes = _build_outcomes(ws, campaign_id, outcomes_path)
    for section in (pre, conv, outcomes):
        _compact_signals(section)
    report = {
        "schema": SCHEMA,
        "generated_at": _utc_now(),
        "workspace": str(ws),
        "campaign_id": campaign_id or "",
        "offline_only": True,
        "claims_boundary": {
            "no_reward_assertion": True,
            "no_positive_terminal_assertion": True,
            "does_not_claim_submission_ready": True,
            "does_not_claim_exploitability": True,
        },
        "readiness": _readiness(pre, conv, outcomes),
        "signal_groups": {
            "pre_filing_accuracy": pre,
            "conversion_proof_execution": conv,
            "triage_survival_outcome": outcomes,
        },
        "explicit_unknowns": sorted(set(pre.get("unknowns", []) + conv.get("unknowns", []) + outcomes.get("unknowns", []))),
    }
    return report


def render_markdown(report: dict[str, Any]) -> str:
    readiness = report["readiness"]
    groups = report["signal_groups"]
    lines = [
        "# Field Validation Report",
        "",
        f"- Schema: `{report['schema']}`",
        f"- Workspace: `{report['workspace']}`",
        f"- Campaign: `{report.get('campaign_id') or 'not specified'}`",
        f"- Readiness: `{readiness['status']}` ({readiness['ready_sections']}/3 sections ready)",
        "",
        "## Boundary",
        "",
        "- Offline/local artifacts only.",
        "- No reward, positive terminal outcome, submission-ready, or exploitability claim is made.",
        "",
    ]
    for title, key in (
        ("Pre-Filing Accuracy", "pre_filing_accuracy"),
        ("Conversion / Proof Execution", "conversion_proof_execution"),
        ("Triage Survival / Outcome", "triage_survival_outcome"),
    ):
        section = groups[key]
        lines.extend([f"## {title}", "", f"- Status: `{section['status']}`"])
        counts = section.get("counts", {})
        for count_key, value in counts.items():
            lines.append(f"- {count_key}: `{value}`")
        if section.get("unknowns"):
            for unknown in section["unknowns"]:
                lines.append(f"- Unknown: {unknown}")
        if section.get("missing_artifacts"):
            lines.append("- Missing artifacts:")
            for artifact in section["missing_artifacts"]:
                lines.append(f"  - `{artifact.get('artifact')}`: {artifact.get('reason')}")
                paths = artifact.get("expected_paths") or []
                if paths:
                    lines.append(f"    - Expected paths: {', '.join(f'`{path}`' for path in paths)}")
                commands = artifact.get("next_commands") or []
                if commands:
                    lines.append(f"    - Next commands: {'; '.join(f'`{command}`' for command in commands)}")
        lines.append("")
    if report.get("explicit_unknowns"):
        lines.extend(["## Explicit Unknowns", ""])
        lines.extend(f"- {item}" for item in report["explicit_unknowns"])
        lines.append("")
    if readiness.get("field_loop_next_steps"):
        lines.extend(["## Field Loop Next Steps", ""])
        for step in readiness["field_loop_next_steps"]:
            lines.append(f"- `{step.get('artifact')}`: {step.get('reason')}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--campaign-id", "--campaign", dest="campaign_id", default="")
    parser.add_argument("--outcomes", type=Path, default=DEFAULT_OUTCOMES)
    parser.add_argument("--out", type=Path, help="JSON output path.")
    parser.add_argument("--md-out", type=Path, help="Optional Markdown output path.")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit 1 unless all three field-validation sections are ready for evaluation.",
    )
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args(argv)

    report = build_report(args.workspace, campaign_id=args.campaign_id or None, outcomes_path=args.outcomes)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.md_out:
        args.md_out.parent.mkdir(parents=True, exist_ok=True)
        args.md_out.write_text(render_markdown(report), encoding="utf-8")
    if args.print_json or not args.out:
        print(json.dumps(report, indent=2, sort_keys=True))
    if args.strict and report.get("readiness", {}).get("status") != "field_validation_ready_for_evaluation":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
