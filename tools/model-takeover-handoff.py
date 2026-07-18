#!/usr/bin/env python3
"""Build bounded provider handoff packets from model takeover readiness inputs."""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.model_takeover_provider_handoff.v1"
DEFAULT_DATE = "2026-05-05"
DEFAULT_REPORT = f"reports/model_takeover_readiness_{DEFAULT_DATE}.json"
DEFAULT_DOC = f"docs/MODEL_TAKEOVER_READINESS_{DEFAULT_DATE}.md"
DEFAULT_JSON_OUT = f"reports/model_takeover_provider_handoff_{DEFAULT_DATE}.json"
DEFAULT_DOC_OUT = f"docs/MODEL_TAKEOVER_PROVIDER_HANDOFF_{DEFAULT_DATE}.md"
READY = "READY"
WARN = "WARN"
BLOCKED = "BLOCKED"
PROVIDER_ORDER = ("claude", "kimi", "minimax")
DISPLAY_TO_PROVIDER = {
    "claude": "claude",
    "kimi": "kimi",
    "minimax": "minimax",
}
DEFAULT_MAX_ARTIFACTS = 5
DEFAULT_MAX_ITEMS = 2
DEFAULT_MAX_TEXT = 180
PROOF_BOUNDARY = (
    "Only executed local commands and durable local artifacts count as proof. "
    "This handoff packet is bounded operator context, not exploit, coverage, or "
    "submission evidence."
)
COMPACT_CHECK_MODE = "compact-check"
FULL_MODE = "full"
BLOCKED_WORKTREE_PATH = "/Users/wolf/auditooor-worktrees/continuation-plan-update"
RECOVERY_BRANCH_SAFETY_WARNING = (
    "Use a recovery-derived worktree for takeover state and do not treat "
    f"{BLOCKED_WORKTREE_PATH} as live loop state."
)
DISALLOWED_BROAD_DOCS = (
    "README.md",
    "docs/README.md",
    "docs/CURRENT_STATE.md",
    "docs/CONTINUATION_PLAN.md",
    "docs/NEXT_10_LOOPS_2026-05-05.md",
    "docs/NEXT_50_LOOPS_2026-05-05.md",
)
BOOTSTRAP_QUERY_PATTERNS = (
    "agent_briefs/AGENT_BOOTSTRAP_QUERY*.md",
    "agent_briefs/agent_bootstrap_query*.md",
    "docs/AGENT_BOOTSTRAP_QUERY*.md",
    "docs/agent_bootstrap_query*.md",
    "reports/agent_bootstrap_query*.json",
    "reports/agent-bootstrap-query*.json",
)


@dataclass(frozen=True)
class Bounds:
    max_artifacts: int = DEFAULT_MAX_ARTIFACTS
    max_items_per_artifact: int = DEFAULT_MAX_ITEMS
    max_text_chars: int = DEFAULT_MAX_TEXT

    @classmethod
    def from_values(
        cls, *, max_artifacts: int, max_items_per_artifact: int, max_text_chars: int
    ) -> "Bounds":
        return cls(
            max(1, max_artifacts),
            max(1, max_items_per_artifact),
            max(80, max_text_chars),
        )


COMPACT_BOUNDS = Bounds(max_artifacts=3, max_items_per_artifact=1, max_text_chars=120)


def utc_now() -> str:
    return datetime.now(tz=timezone.utc).replace(microsecond=0).isoformat()


def _bounded_text(value: Any, limit: int) -> str:
    text = " ".join(str(value).split())
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."


def _load_json(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    if not path.is_file():
        return None, "missing file"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return None, f"invalid JSON: {exc}"
    if not isinstance(payload, dict):
        return None, "top-level JSON packet must be an object"
    return payload, None


def _load_text(path: Path) -> tuple[str | None, str | None]:
    if not path.is_file():
        return None, "missing file"
    try:
        return path.read_text(encoding="utf-8"), None
    except OSError as exc:
        return None, _bounded_text(exc, DEFAULT_MAX_TEXT)


def _provider_rows_from_doc(text: str) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    pattern = re.compile(
        r"^\|\s*(Claude|Kimi|Minimax)\s*\|\s*(READY|WARN|BLOCKED)\s*\|\s*(\d+)%\s*\|\s*(\d+)\s*\|$",
        re.MULTILINE,
    )
    for display_name, status, readiness, tokens in pattern.findall(text):
        key = DISPLAY_TO_PROVIDER[display_name.lower()]
        rows[key] = {
            "display_name": display_name,
            "status": status,
            "readiness_estimate_percent": int(readiness),
            "target_packet_tokens": int(tokens),
        }
    return rows


def _iter_strings(value: Any) -> list[str]:
    out: list[str] = []
    stack = [value]
    while stack:
        current = stack.pop()
        if isinstance(current, str):
            out.append(current)
        elif isinstance(current, dict):
            stack.extend(current.values())
        elif isinstance(current, list):
            stack.extend(current)
    return out


def _discover_bootstrap_query(repo_root: Path) -> str | None:
    for pattern in BOOTSTRAP_QUERY_PATTERNS:
        matches = sorted(path for path in repo_root.glob(pattern) if path.is_file())
        if matches:
            return str(matches[0].relative_to(repo_root))
    return None


def _append_policy_result(
    results: list[dict[str, Any]],
    *,
    key: str,
    status: str,
    message: str,
    evidence: str | None = None,
) -> None:
    row = {"key": key, "status": status, "message": message}
    if evidence:
        row["evidence"] = evidence
    results.append(row)


def _validate_compact_policy(
    repo_root: Path,
    report: dict[str, Any] | None,
    doc_text: str | None,
    fail_closed_blockers: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    results: list[dict[str, Any]] = []
    bootstrap_query = _discover_bootstrap_query(repo_root)
    bootstrap = {
        "present": bootstrap_query is not None,
        "path": bootstrap_query,
        "message": (
            f"Use `{bootstrap_query}` as the bootstrap query seed before broad artifact review."
            if bootstrap_query
            else "No dedicated agent-bootstrap query artifact was found."
        ),
    }
    if bootstrap_query:
        _append_policy_result(
            results,
            key="bootstrap_query",
            status=READY,
            message="Bootstrap query artifact available for compact takeover.",
            evidence=bootstrap_query,
        )
    else:
        _append_policy_result(
            results,
            key="bootstrap_query",
            status=WARN,
            message="No dedicated agent-bootstrap query artifact found; compact mode falls back to bounded artifact focus.",
        )

    report_root = report.get("root") if isinstance(report, dict) else None
    if isinstance(report_root, str) and report_root == str(repo_root):
        _append_policy_result(
            results,
            key="recovery_branch_safety",
            status=READY,
            message=RECOVERY_BRANCH_SAFETY_WARNING,
        )
    else:
        _append_policy_result(
            results,
            key="recovery_branch_safety",
            status=BLOCKED,
            message=(
                "Readiness report root does not match the current worktree. "
                "Regenerate readiness from the recovery-derived branch before handoff."
            ),
            evidence=str(report_root) if isinstance(report_root, str) else "missing report root",
        )
        _append_unique(
            fail_closed_blockers,
            "recovery_branch_safety",
            "readiness report root must match the current worktree before takeover handoff",
        )

    scanned_strings = "\n".join(_iter_strings(report) + ([doc_text] if doc_text else []))
    lowered = scanned_strings.lower()
    if "deepseek" in lowered:
        _append_policy_result(
            results,
            key="no_deepseek",
            status=BLOCKED,
            message="DeepSeek references are not allowed in compact takeover state.",
        )
        _append_unique(
            fail_closed_blockers,
            "no_deepseek",
            "compact takeover state must not reference DeepSeek",
        )
    else:
        _append_policy_result(
            results,
            key="no_deepseek",
            status=READY,
            message="No DeepSeek references found in readiness inputs.",
        )

    dispatch_tokens = ("llm-dispatch.py", "dispatch-preflight.py", "semantic-provider-batch.py")
    bad_dispatch = next((token for token in dispatch_tokens if token in scanned_strings), None)
    if bad_dispatch:
        _append_policy_result(
            results,
            key="no_dispatch",
            status=BLOCKED,
            message="Compact takeover state must stay local-only and not route through provider dispatch.",
            evidence=bad_dispatch,
        )
        _append_unique(
            fail_closed_blockers,
            "no_dispatch",
            "compact takeover state must not reference llm-dispatch, dispatch-preflight, or semantic-provider-batch",
        )
    else:
        _append_policy_result(
            results,
            key="no_dispatch",
            status=READY,
            message="No provider dispatch references found in readiness inputs.",
        )

    blocked_root_seen = BLOCKED_WORKTREE_PATH in scanned_strings
    if blocked_root_seen:
        _append_policy_result(
            results,
            key="blocked_worktree_state",
            status=BLOCKED,
            message="Compact takeover state still points at the blocked continuation-plan-update worktree.",
            evidence=BLOCKED_WORKTREE_PATH,
        )
        _append_unique(
            fail_closed_blockers,
            "blocked_worktree_state",
            "compact takeover state must not point at continuation-plan-update",
        )
    else:
        _append_policy_result(
            results,
            key="blocked_worktree_state",
            status=READY,
            message="No blocked worktree paths detected in readiness inputs.",
        )

    artifacts = report.get("artifacts") if isinstance(report, dict) else []
    broad_doc = None
    if isinstance(artifacts, list):
        for artifact in artifacts:
            if not isinstance(artifact, dict):
                continue
            path = artifact.get("path")
            if isinstance(path, str) and path in DISALLOWED_BROAD_DOCS:
                broad_doc = path
                break
    if broad_doc:
        _append_policy_result(
            results,
            key="broad_docs_not_live_state",
            status=BLOCKED,
            message="Broad docs must not be treated as live loop state in compact takeover packets.",
            evidence=broad_doc,
        )
        _append_unique(
            fail_closed_blockers,
            "broad_docs_not_live_state",
            "broad docs cannot be consumed as live loop state for compact takeover",
        )
    else:
        _append_policy_result(
            results,
            key="broad_docs_not_live_state",
            status=READY,
            message="No broad docs were consumed as live loop state.",
        )

    return results, bootstrap


def _append_unique(blockers: list[dict[str, Any]], scope: str, message: str) -> None:
    row = {"scope": scope, "message": message}
    if row not in blockers:
        blockers.append(row)


def _category_rank(status: str) -> int:
    if status == BLOCKED:
        return 0
    if status == WARN:
        return 1
    return 2


def _artifact_rank(artifact: dict[str, Any]) -> tuple[int, int, int, str]:
    category = str(artifact.get("category") or "")
    required = 0 if artifact.get("required") else 1
    present = 0 if artifact.get("present") else 1
    category_bias = 0 if category == "context" else 1
    return (category_bias, required, present, str(artifact.get("key") or ""))


def _item_rank(item: dict[str, Any]) -> tuple[int, int]:
    status = str(item.get("status") or "").lower()
    if any(token in status for token in ("fail", "error", "blocked", "missing", "invalid")):
        severity = 0
    elif any(token in status for token in ("warn", "partial", "open")):
        severity = 1
    elif status:
        severity = 2
    else:
        severity = 3
    return (severity, int(item.get("index") or 0))


def _select_category_focus(categories: dict[str, dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if "context" in categories:
        category = categories["context"]
        rows.append(
            {
                "key": "context",
                "label": category.get("label") or "Context transfer",
                "status": category.get("status") or "unknown",
                "blockers": _bounded_list(category.get("blockers"), 2, DEFAULT_MAX_TEXT),
                "warnings": _bounded_list(category.get("warnings"), 2, DEFAULT_MAX_TEXT),
            }
        )
    remaining = [
        (key, value)
        for key, value in categories.items()
        if key != "context"
    ]
    remaining.sort(key=lambda item: (_category_rank(str(item[1].get("status") or "")), item[0]))
    for key, category in remaining:
        rows.append(
            {
                "key": key,
                "label": category.get("label") or key,
                "status": category.get("status") or "unknown",
                "blockers": _bounded_list(category.get("blockers"), 2, DEFAULT_MAX_TEXT),
                "warnings": _bounded_list(category.get("warnings"), 2, DEFAULT_MAX_TEXT),
            }
        )
    return rows[:limit]


def _bounded_list(value: Any, limit: int, max_text_chars: int) -> list[str]:
    if isinstance(value, list):
        items = value
    elif value is None:
        items = []
    else:
        items = [value]
    out: list[str] = []
    for item in items:
        text = _bounded_text(item, max_text_chars)
        if text and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _select_artifact_focus(
    artifacts: list[dict[str, Any]],
    categories: dict[str, dict[str, Any]],
    bounds: Bounds,
) -> list[dict[str, Any]]:
    category_order = ["context"]
    for key in ("harness", "known_limitation_burndown", "limits"):
        if key in categories and key not in category_order:
            category_order.append(key)
    problem_categories = [
        key
        for key, value in sorted(
            categories.items(),
            key=lambda item: (_category_rank(str(item[1].get("status") or "")), item[0]),
        )
        if key not in category_order and str(value.get("status") or "") != READY
    ]
    category_order.extend(problem_categories)
    for key in ("commit_mining", "source"):
        if key not in category_order and key in categories:
            category_order.append(key)

    by_category: dict[str, list[dict[str, Any]]] = {}
    for artifact in artifacts:
        by_category.setdefault(str(artifact.get("category") or ""), []).append(artifact)
    for rows in by_category.values():
        rows.sort(key=_artifact_rank)

    selected: list[dict[str, Any]] = []
    selected_keys: set[str] = set()
    max_depth = max((len(rows) for rows in by_category.values()), default=0)
    for depth in range(max_depth):
        for category in category_order:
            category_rows = by_category.get(category, [])
            if depth >= len(category_rows):
                continue
            artifact = category_rows[depth]
            key = str(artifact.get("key") or "")
            if key in selected_keys:
                continue
            selected_keys.add(key)
            bounded_items = sorted(artifact.get("bounded_items") or [], key=_item_rank)
            selected.append(
                {
                    "key": key,
                    "label": artifact.get("label") or key,
                    "category": category,
                    "required": bool(artifact.get("required")),
                    "present": bool(artifact.get("present")),
                    "path": artifact.get("path"),
                    "format": artifact.get("format"),
                    "parse_error": artifact.get("parse_error"),
                    "status_counts": artifact.get("status_counts") or {},
                    **(
                        {"snapshot_summary": artifact.get("snapshot_summary")}
                        if isinstance(artifact.get("snapshot_summary"), dict)
                        else {}
                    ),
                    "bounded_items": [
                        {
                            "index": item.get("index"),
                            "status": item.get("status"),
                            "summary": _bounded_text(
                                item.get("summary"),
                                bounds.max_text_chars,
                            ),
                            **(
                                {"worker_slot": item.get("worker_slot")}
                                if isinstance(item.get("worker_slot"), dict)
                                else {}
                            ),
                        }
                        for item in bounded_items[: bounds.max_items_per_artifact]
                    ],
                }
            )
            if len(selected) >= bounds.max_artifacts:
                return selected
    return selected


def _provider_posture(status: str, packet_blockers: list[dict[str, Any]]) -> tuple[str, bool]:
    if packet_blockers:
        return "fail_closed_inputs", False
    if status == BLOCKED:
        return "blocked_until_repairs", False
    if status == WARN:
        return "bounded_warn_handoff_only", True
    if status == READY:
        return "bounded_takeover_ready", True
    return "unknown", False


def _provider_focus_notes(
    provider: str,
    gate: dict[str, Any],
    category_focus: list[dict[str, Any]],
) -> list[str]:
    notes = [
        "Start with context artifacts, then inspect every non-ready category listed below before editing code.",
        "Do not promote warning rows into proof; reopen the named local artifact before making readiness or submission claims.",
    ]
    if str(gate.get("status") or "") == WARN:
        notes.append(
            "This provider is warn-only because takeover inputs still contain blocked or failing category rows."
        )
    elif str(gate.get("status") or "") == BLOCKED:
        notes.append("Do not continue takeover until the fail-closed blockers are repaired locally.")
    for category in category_focus:
        if category["status"] != READY:
            notes.append(
                f"Priority category for {provider}: {category['label']} ({category['status']})."
            )
            break
    return notes[:4]


def _provider_commands(repo_root: Path) -> list[dict[str, str]]:
    ws = str(repo_root)
    return [
        {
            "reason": "Rebuild the bounded provider handoff after local state changes.",
            "command": "python3 tools/model-takeover-handoff.py --root . --stdout-format summary",
        },
        {
            "reason": "Rebuild takeover readiness if any consumed artifact changed.",
            "command": "python3 tools/model-takeover-readiness.py --root .",
        },
        {
            "reason": "Limit proof claims to durable local outputs under this workspace.",
            "command": f"cd {ws}",
        },
    ]


def build_packet(
    repo_root: Path,
    *,
    readiness_report: str = DEFAULT_REPORT,
    readiness_doc: str = DEFAULT_DOC,
    providers: list[str] | None = None,
    bounds: Bounds | None = None,
    mode: str = FULL_MODE,
) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    bounds = bounds or Bounds()
    selected_providers = providers or list(PROVIDER_ORDER)
    fail_closed_blockers: list[dict[str, Any]] = []

    report_path = repo_root / readiness_report
    doc_path = repo_root / readiness_doc
    report, report_error = _load_json(report_path)
    doc_text, doc_error = _load_text(doc_path)
    if report_error:
        _append_unique(
            fail_closed_blockers,
            "readiness_report",
            f"{readiness_report}: {report_error}",
        )
    if doc_error:
        _append_unique(
            fail_closed_blockers,
            "readiness_doc",
            f"{readiness_doc}: {doc_error}",
        )

    doc_provider_rows: dict[str, dict[str, Any]] = {}
    if doc_text is not None:
        doc_provider_rows = _provider_rows_from_doc(doc_text)
        for provider in selected_providers:
            if provider not in doc_provider_rows:
                _append_unique(
                    fail_closed_blockers,
                    "readiness_doc",
                    f"{readiness_doc}: missing provider table row for {provider}",
                )

    compact_policy_results, bootstrap_query = _validate_compact_policy(
        repo_root, report, doc_text, fail_closed_blockers
    )

    provider_packets: dict[str, Any] = {}
    categories = report.get("categories") if isinstance(report, dict) else {}
    artifacts = report.get("artifacts") if isinstance(report, dict) else []
    provider_gates = report.get("provider_gates") if isinstance(report, dict) else {}
    report_categories = categories if isinstance(categories, dict) else {}
    report_artifacts = artifacts if isinstance(artifacts, list) else []
    report_provider_gates = provider_gates if isinstance(provider_gates, dict) else {}

    for provider in selected_providers:
        gate = report_provider_gates.get(provider)
        if not isinstance(gate, dict):
            _append_unique(
                fail_closed_blockers,
                "readiness_report",
                f"{readiness_report}: missing provider gate for {provider}",
            )
            gate = {
                "display_name": provider.title(),
                "status": BLOCKED,
                "readiness_estimate_percent": 0,
                "target_packet_tokens": 0,
            }

        doc_row = doc_provider_rows.get(provider)
        if isinstance(doc_row, dict):
            for field in ("status", "readiness_estimate_percent", "target_packet_tokens"):
                if gate.get(field) != doc_row.get(field):
                    _append_unique(
                        fail_closed_blockers,
                        provider,
                        (
                            f"provider gate mismatch for {provider}: report {field}={gate.get(field)!r} "
                            f"!= doc {field}={doc_row.get(field)!r}"
                        ),
                    )

        category_focus = _select_category_focus(report_categories, bounds.max_artifacts)
        artifact_focus = _select_artifact_focus(report_artifacts, report_categories, bounds)
        posture, allowed = _provider_posture(str(gate.get("status") or ""), fail_closed_blockers)
        provider_packets[provider] = {
            "display_name": gate.get("display_name") or provider.title(),
            "status": gate.get("status") or BLOCKED,
            "readiness_estimate_percent": int(gate.get("readiness_estimate_percent") or 0),
            "target_packet_tokens": int(gate.get("target_packet_tokens") or 0),
            "takeover_posture": posture,
            "handoff_allowed": allowed,
            "category_focus": category_focus,
            "artifact_focus": artifact_focus,
            "focus_notes": _provider_focus_notes(provider, gate, category_focus),
            "operator_commands": _provider_commands(repo_root),
            "proof_boundary": PROOF_BOUNDARY,
            "bootstrap_query": bootstrap_query,
        }

    return {
        "schema": SCHEMA,
        "generated_at": utc_now(),
        "repo_root": str(repo_root),
        "inputs": {
            "readiness_report": readiness_report,
            "readiness_doc": readiness_doc,
        },
        "mode": mode,
        "bounds": {
            "providers": selected_providers,
            "max_artifacts_per_provider": bounds.max_artifacts,
            "max_items_per_artifact": bounds.max_items_per_artifact,
            "max_text_chars": bounds.max_text_chars,
        },
        "fail_closed": not not fail_closed_blockers,
        "fail_closed_blockers": fail_closed_blockers,
        "compact_check": {
            "bootstrap_query": bootstrap_query,
            "policy_results": compact_policy_results,
            "sample_command": (
                "python3 tools/model-takeover-handoff.py --root . "
                "--mode compact-check --stdout-format summary"
            ),
            "token_saving_behavior": (
                "Compact mode keeps context bounded to the highest-signal categories and "
                "artifact rows already summarized by the readiness packet."
            ),
        },
        "providers": provider_packets,
    }


def render_markdown(packet: dict[str, Any]) -> str:
    lines = [
        "# Model Takeover Provider Handoff Packet",
        "",
        f"Generated: {packet.get('generated_at')}",
        f"Root: `{packet.get('repo_root')}`",
        "",
        "## Inputs",
        "",
        f"- Readiness report: `{packet['inputs']['readiness_report']}`",
        f"- Readiness doc: `{packet['inputs']['readiness_doc']}`",
        f"- Mode: `{packet.get('mode', FULL_MODE)}`",
        f"- Fail closed: `{str(packet.get('fail_closed')).lower()}`",
    ]
    compact_check = packet.get("compact_check") or {}
    policy_rows = compact_check.get("policy_results") or []
    if policy_rows:
        lines.extend(["", "## Compact Check", ""])
        bootstrap = compact_check.get("bootstrap_query") or {}
        bootstrap_path = bootstrap.get("path") if isinstance(bootstrap, dict) else None
        lines.append(f"- Bootstrap query: `{bootstrap_path or 'not-found'}`")
        lines.append(f"- Sample command: `{compact_check.get('sample_command')}`")
        lines.append(f"- Token behavior: {compact_check.get('token_saving_behavior')}")
        lines.append("")
        lines.append("| Check | Status | Detail |")
        lines.append("|---|---:|---|")
        for row in policy_rows:
            detail = row["message"]
            if row.get("evidence"):
                detail += f" ({row['evidence']})"
            lines.append(f"| {row['key']} | {row['status']} | {detail} |")
    blockers = packet.get("fail_closed_blockers") or []
    if blockers:
        lines.extend(["", "## Fail-Closed Blockers", ""])
        for blocker in blockers:
            lines.append(f"- `{blocker['scope']}`: {blocker['message']}")

    for provider in PROVIDER_ORDER:
        row = packet.get("providers", {}).get(provider)
        if not isinstance(row, dict):
            continue
        lines.extend(
            [
                "",
                f"## {row['display_name']}",
                "",
                f"- Status: `{row['status']}`",
                f"- Readiness estimate: `{row['readiness_estimate_percent']}%`",
                f"- Target packet tokens: `{row['target_packet_tokens']}`",
                f"- Takeover posture: `{row['takeover_posture']}`",
                f"- Handoff allowed: `{str(row['handoff_allowed']).lower()}`",
                "",
                "### Category Focus",
                "",
            ]
        )
        for category in row.get("category_focus", []):
            detail = []
            if category.get("blockers"):
                detail.append("blockers=" + "; ".join(category["blockers"]))
            if category.get("warnings"):
                detail.append("warnings=" + "; ".join(category["warnings"]))
            suffix = f" ({'; '.join(detail)})" if detail else ""
            lines.append(f"- `{category['label']}`: `{category['status']}`{suffix}")

        lines.extend(["", "### Artifact Focus", ""])
        for artifact in row.get("artifact_focus", []):
            path = artifact.get("path") or "-"
            lines.append(
                f"- `{artifact['label']}` [{artifact['category']}]: `{path}` "
                f"(required={str(artifact['required']).lower()}, present={str(artifact['present']).lower()})"
            )
            if artifact.get("parse_error"):
                lines.append(f"  - parse_error: {artifact['parse_error']}")
            snapshot_summary = artifact.get("snapshot_summary")
            if isinstance(snapshot_summary, dict):
                guidance = snapshot_summary.get("scanner_coordination_guidance")
                if isinstance(guidance, dict):
                    lines.append(
                        "  - scanner_coordination: "
                        f"refresh_before_more_detector_assignments=`"
                        f"{str(bool(guidance.get('refresh_inventory_before_more_detector_assignments'))).lower()}` "
                        f"do_not_redispatch={guidance.get('do_not_redispatch_statuses', [])}"
                    )
                    if guidance.get("reason"):
                        lines.append(f"    reason: {guidance.get('reason')}")
                selector_counts = snapshot_summary.get("selector_skipped_or_already_counts")
                if isinstance(selector_counts, dict) and selector_counts:
                    bounded_counts = [
                        f"{_bounded_text(key, 120)}={int(value)}"
                        for key, value in list(selector_counts.items())[:6]
                        if isinstance(value, (int, float)) and not isinstance(value, bool)
                    ]
                    if bounded_counts:
                        lines.append(
                            "  - selector_skipped_or_already_counts: "
                            + ", ".join(f"`{count}`" for count in bounded_counts)
                        )
                skipped_samples = snapshot_summary.get("skipped_worker_slot_samples")
                if isinstance(skipped_samples, list) and skipped_samples:
                    sample = skipped_samples[0]
                    if isinstance(sample, dict):
                        evidence = (
                            (sample.get("matching_dirty_paths") if isinstance(sample.get("matching_dirty_paths"), list) else [])
                            + (sample.get("local_evidence_paths") if isinstance(sample.get("local_evidence_paths"), list) else [])
                            + (
                                sample.get("committed_after_queue_paths")
                                if isinstance(sample.get("committed_after_queue_paths"), list)
                                else []
                            )
                        )
                        lines.append(
                            "  - skipped_worker_sample: "
                            f"row=`{sample.get('row_id', '')}` reason=`{sample.get('skip_reason', '')}` "
                            f"evidence={', '.join(str(path) for path in evidence[:3]) or '-'}"
                        )
            for item in artifact.get("bounded_items", []):
                status = item.get("status") or "unknown"
                lines.append(f"  - [{status}] {item.get('summary')}")
                worker_slot = item.get("worker_slot")
                if isinstance(worker_slot, dict) and worker_slot.get("row_id"):
                    owned = ", ".join(str(path) for path in worker_slot.get("owned_paths", [])[:3]) or "-"
                    coordination = worker_slot.get("local_coordination_status") or "unknown"
                    lines.append(
                        "    worker_slot: "
                        f"`{worker_slot.get('slot_id', '')}` row=`{worker_slot.get('row_id', '')}` "
                        f"model=`{worker_slot.get('model_hint', '')}` "
                        f"coordination=`{coordination}` owned={owned}"
                    )

        lines.extend(["", "### Focus Notes", ""])
        for note in row.get("focus_notes", []):
            lines.append(f"- {note}")

        lines.extend(["", "### Operator Commands", ""])
        for command in row.get("operator_commands", []):
            lines.append(f"- {command['reason']}: `{command['command']}`")

        lines.extend(["", "### Proof Boundary", "", row.get("proof_boundary") or PROOF_BOUNDARY])

    return "\n".join(lines).rstrip() + "\n"


def _output_path(repo_root: Path, value: str) -> Path:
    path = Path(value)
    if path.is_absolute():
        return path
    return repo_root / path


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".", help="repo root")
    parser.add_argument("--readiness-report", default=DEFAULT_REPORT)
    parser.add_argument("--readiness-doc", default=DEFAULT_DOC)
    parser.add_argument("--json-out", default=DEFAULT_JSON_OUT)
    parser.add_argument("--doc-out", default=DEFAULT_DOC_OUT)
    parser.add_argument("--provider", action="append", choices=PROVIDER_ORDER)
    parser.add_argument("--mode", choices=(FULL_MODE, COMPACT_CHECK_MODE), default=FULL_MODE)
    parser.add_argument("--max-artifacts", type=int, default=DEFAULT_MAX_ARTIFACTS)
    parser.add_argument("--max-items-per-artifact", type=int, default=DEFAULT_MAX_ITEMS)
    parser.add_argument("--max-text", type=int, default=DEFAULT_MAX_TEXT)
    parser.add_argument(
        "--stdout-format",
        choices=("none", "json", "markdown", "summary"),
        default="summary",
    )
    parser.add_argument("--fail-on-blockers", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    repo_root = Path(args.root).resolve()
    bounds = Bounds.from_values(
        max_artifacts=args.max_artifacts,
        max_items_per_artifact=args.max_items_per_artifact,
        max_text_chars=args.max_text,
    )
    if (
        args.mode == COMPACT_CHECK_MODE
        and args.max_artifacts == DEFAULT_MAX_ARTIFACTS
        and args.max_items_per_artifact == DEFAULT_MAX_ITEMS
        and args.max_text == DEFAULT_MAX_TEXT
    ):
        bounds = COMPACT_BOUNDS
    packet = build_packet(
        repo_root,
        readiness_report=args.readiness_report,
        readiness_doc=args.readiness_doc,
        providers=args.provider,
        bounds=bounds,
        mode=args.mode,
    )
    json_out = _output_path(repo_root, args.json_out)
    doc_out = _output_path(repo_root, args.doc_out)
    write_json(json_out, packet)
    write_text(doc_out, render_markdown(packet))

    if args.stdout_format == "json":
        print(json.dumps(packet, indent=2, sort_keys=True))
    elif args.stdout_format == "markdown":
        print(render_markdown(packet), end="")
    elif args.stdout_format == "summary":
        print(
            "model-takeover handoff: "
            f"mode={packet.get('mode', FULL_MODE)} "
            f"providers={len(packet.get('providers', {}))} "
            f"fail_closed={str(packet.get('fail_closed')).lower()} "
            f"json={json_out} doc={doc_out}"
        )

    if args.fail_on_blockers and packet.get("fail_closed_blockers"):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
