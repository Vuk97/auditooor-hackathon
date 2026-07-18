#!/usr/bin/env python3
"""Known capability-gap scoring for the auditooor control plane.

The scorer is intentionally conservative: it only emits a gap when a supplied
state packet, discovered artifact, or explicit next-action row provides
evidence. Missing optional state is treated as unknown, not as a gap.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
from typing import Any, Iterable

from .candidates import discover_candidates, paste_ready_blockers
from .next_actions import rank_next_actions
from .runs import discover_run_rows
from .status import collect_status


SCHEMA = "auditooor.control.gaps.v1"

P0 = "P0"
P1 = "P1"
P2 = "P2"

GAP_SCANNER_RECALL = "scanner_recall"
GAP_INVARIANT_AUTOSEEDING = "invariant_autoseeding"
GAP_HARNESS_EXECUTION_REPLAY = "harness_execution_replay"
GAP_IMPACT_CONTRACT_GATING = "impact_contract_gating"
GAP_PROVIDER_ROUTING = "provider_routing"
GAP_DIRTY_WORKSPACE_HYGIENE = "dirty_workspace_hygiene"
GAP_SUBMISSION_PASTE_READINESS = "submission_paste_readiness"

_ACTIVE_CANDIDATE_STATUSES = {
    "",
    "candidate",
    "impact_mapped",
    "lead",
    "oos_checked",
    "paste_ready",
    "poc_executed",
    "poc_planned",
}
_TERMINAL_CANDIDATE_STATUSES = {"accepted", "duplicate", "killed", "paid", "rejected", "submitted"}
_HIGH_SEVERITIES = {"critical", "high"}
_BAD_RUN_STATES = {"blocked", "failed", "missing_workspace", "partial", "planned"}
_PROVIDER_MARKERS = ("kimi", "minimax", "provider", "llm-dispatch", "dispatch-preflight")


@dataclass(frozen=True)
class GapRow:
    id: str
    category: str
    priority: str
    title: str
    reason: str
    evidence: list[str] = field(default_factory=list)
    stop_condition: str = ""
    next_command: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category,
            "priority": self.priority,
            "title": self.title,
            "reason": self.reason,
            "evidence": self.evidence,
            "stop_condition": self.stop_condition,
            "next_command": self.next_command,
        }


def score_known_capability_gaps(
    workspace: str | Path,
    *,
    status: dict[str, Any] | None = None,
    candidates: Iterable[dict[str, Any]] | None = None,
    runs: Iterable[dict[str, Any]] | None = None,
    next_actions: Iterable[dict[str, Any]] | None = None,
    dirty_files: Iterable[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Return evidence-backed P0/P1/P2 capability-gap rows.

    Callers may pass already-collected state packets. When omitted, the scorer
    discovers status, candidates, runs, and next actions from the workspace.
    Dirty-file rows are only consumed when explicitly supplied or embedded in
    the status packet because collecting git state is a repo-level concern.
    """

    ws = Path(workspace).expanduser()
    status_packet = status if status is not None else collect_status(ws)
    candidate_rows = list(candidates) if candidates is not None else [
        candidate.to_dict() for candidate in discover_candidates(ws)
    ]
    run_rows = list(runs) if runs is not None else discover_run_rows(ws)
    action_rows = list(next_actions) if next_actions is not None else rank_next_actions(
        ws,
        status_packet,
        candidate_rows,
        run_rows,
    )
    dirty_rows = list(dirty_files) if dirty_files is not None else list(
        _iter_dicts(status_packet.get("dirty_files") or status_packet.get("dirty") or [])
    )

    rows: list[GapRow] = []
    rows.extend(_scanner_recall_gaps(ws, status_packet, run_rows, action_rows))
    rows.extend(_invariant_autoseeding_gaps(ws, status_packet, candidate_rows, action_rows))
    rows.extend(_harness_execution_gaps(candidate_rows, run_rows, action_rows))
    rows.extend(_impact_contract_gaps(ws, status_packet, candidate_rows, action_rows))
    rows.extend(_provider_routing_gaps(status_packet, candidate_rows, run_rows, action_rows))
    rows.extend(_dirty_workspace_gaps(dirty_rows, action_rows))
    rows.extend(_paste_readiness_gaps(candidate_rows, action_rows))

    ordered = sorted(_dedupe_rows(rows), key=lambda row: (_priority_sort(row.priority), row.category, row.id))
    counts: dict[str, int] = {P0: 0, P1: 0, P2: 0}
    for row in ordered:
        counts[row.priority] = counts.get(row.priority, 0) + 1
    return {
        "schema": SCHEMA,
        "workspace": str(ws),
        "gap_count": len(ordered),
        "counts_by_priority": counts,
        "rows": [row.to_dict() for row in ordered],
    }


def render_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, sort_keys=True) + "\n"


def render_human(report: dict[str, Any]) -> str:
    rows = list(_iter_dicts(report.get("rows") or []))
    if not rows:
        return "known capability gaps: none"
    lines = [f"known capability gaps: {len(rows)}"]
    for row in rows:
        lines.append(
            "{priority} {category}: {title} ({evidence})".format(
                priority=row.get("priority") or "?",
                category=row.get("category") or "unknown",
                title=row.get("title") or row.get("reason") or "gap",
                evidence="; ".join(list(row.get("evidence") or [])[:2]) or "evidence recorded",
            )
        )
    return "\n".join(lines)


def _scanner_recall_gaps(
    ws: Path,
    status: dict[str, Any],
    runs: list[dict[str, Any]],
    actions: list[dict[str, Any]],
) -> list[GapRow]:
    evidence: list[str] = []
    command = _matching_action_command(actions, "scan")
    if _status_missing(status, ("scan_report", "static_analysis_summary")) and not _run_tool_present(runs, {"scan", "engage"}):
        evidence.append("status artifacts show no scan_report.md or static-analysis-summary.md")
    if _needs_rust_scan(status) and _status_missing(status, ("rust_scan_summary",)) and not _run_tool_present(runs, {"rust-scan"}):
        evidence.append("workspace is marked Rust/DLT but scanners/rust/SCAN_RUST_SUMMARY.json is absent")
    bad_runs = _bad_runs(runs, {"scan", "rust-scan"})
    evidence.extend(_run_evidence(bad_runs))
    if not evidence:
        return []
    priority = P0 if _needs_rust_scan(status) and (
        "rust/dlt" in " ".join(evidence).lower() or bool(_bad_runs(runs, {"rust-scan"}))
    ) else P1
    return [
        GapRow(
            id=GAP_SCANNER_RECALL,
            category=GAP_SCANNER_RECALL,
            priority=priority,
            title="Scanner recall evidence is incomplete",
            reason="Canonical scanner artifacts or successful scanner runs are missing/blocked.",
            evidence=_stable_unique(evidence),
            stop_condition="canonical scan summaries exist and scanner run rows are executed or explicitly waived",
            next_command=command or f"python3 tools/engage.py --workspace {_shell_ws(ws)} --stage scan",
        )
    ]


def _invariant_autoseeding_gaps(
    ws: Path,
    status: dict[str, Any],
    candidates: list[dict[str, Any]],
    actions: list[dict[str, Any]],
) -> list[GapRow]:
    high_candidate_ids = [
        _candidate_id(candidate)
        for candidate in candidates
        if _candidate_active(candidate) and _severity(candidate).lower() in _HIGH_SEVERITIES
    ]
    high_workspace = _bool(status.get("high_impact_workspace")) or _severity(status).lower() in _HIGH_SEVERITIES
    if not high_workspace and not high_candidate_ids:
        return []
    if _artifact_ready(status, "invariant_ledger") or (ws / ".auditooor" / "invariant_ledger.json").exists():
        return []
    evidence = ["high-impact workspace/candidate requires invariant seed evidence"]
    if high_candidate_ids:
        evidence.append("high severity candidates: " + ", ".join(sorted(high_candidate_ids)))
    return [
        GapRow(
            id=GAP_INVARIANT_AUTOSEEDING,
            category=GAP_INVARIANT_AUTOSEEDING,
            priority=P1,
            title="Invariant autoseeding is not evidenced",
            reason="High-impact lanes need invariant coverage or a waiver before promotion.",
            evidence=evidence,
            stop_condition="invariant ledger exists or a reviewed waiver explains why no invariant lane applies",
            next_command=_matching_action_command(actions, "invariant") or f"make audit-deep WS={_shell_ws(ws)}",
        )
    ]


def _harness_execution_gaps(
    candidates: list[dict[str, Any]],
    runs: list[dict[str, Any]],
    actions: list[dict[str, Any]],
) -> list[GapRow]:
    rows: list[GapRow] = []
    proof_counted = any(run.get("tool") == "poc-execution" and run.get("proof_counted") is True for run in runs)
    bad_poc_runs = _bad_runs(runs, {"poc-execution"})
    for candidate in candidates:
        if not _candidate_active(candidate):
            continue
        cid = _candidate_id(candidate)
        proof = str(candidate.get("proof_state") or "").lower()
        blockers = list(candidate.get("paste_ready_blockers") or paste_ready_blockers(candidate))
        missing_harness = proof in {"", "planned", "scaffolded"} or any(
            blocker in blockers for blocker in ("missing_poc_command", "missing_poc_result", "missing_inline_poc")
        )
        if not missing_harness:
            continue
        rows.append(
            GapRow(
                id=f"{GAP_HARNESS_EXECUTION_REPLAY}:{cid}",
                category=GAP_HARNESS_EXECUTION_REPLAY,
                priority=P0,
                title=f"Candidate {cid} lacks executed harness/replay proof",
                reason="Candidate has no executed PoC/replay result suitable for report evidence.",
                evidence=_stable_unique(
                    [f"proof_state={proof or 'missing'}"] + [f"paste_blocker={blocker}" for blocker in blockers]
                ),
                stop_condition="poc_execution manifest records command output, final_result=proved, and impact_assertion=exploit_impact",
                next_command=_matching_action_command(actions, cid) or "make poc-execution-record WS=<workspace> BRIEF=<draft> CMD='<test command>'",
            )
        )
    if bad_poc_runs and not proof_counted:
        rows.append(
            GapRow(
                id=f"{GAP_HARNESS_EXECUTION_REPLAY}:blocked-runs",
                category=GAP_HARNESS_EXECUTION_REPLAY,
                priority=P0,
                title="PoC execution manifests are blocked or partial",
                reason="Existing harness/replay artifacts do not count as exploit proof.",
                evidence=_run_evidence(bad_poc_runs),
                stop_condition="at least one PoC execution row is proof_counted=true or blocked manifests are closed",
                next_command="make poc-execution-record WS=<workspace> BRIEF=<draft> CMD='<test command>'",
            )
        )
    return rows


def _impact_contract_gaps(
    ws: Path,
    status: dict[str, Any],
    candidates: list[dict[str, Any]],
    actions: list[dict[str, Any]],
) -> list[GapRow]:
    rows: list[GapRow] = []
    severity_state = _readiness_status(status, "severity")
    if severity_state in {"missing", "blocked_unknown"}:
        rows.append(
            GapRow(
                id=f"{GAP_IMPACT_CONTRACT_GATING}:rubric",
                category=GAP_IMPACT_CONTRACT_GATING,
                priority=P0,
                title="Impact contract rubric is not ready",
                reason="Severity and rubric coverage are required before filing or High/Critical framing.",
                evidence=[f"status.readiness.severity={severity_state}"],
                stop_condition="severity rubric and RUBRIC_COVERAGE.md are present and non-placeholder",
                next_command=_matching_action_command(actions, "severity") or f"python3 tools/engage.py --workspace {_shell_ws(ws)} --stage intake-baseline",
            )
        )
    for candidate in candidates:
        if not _candidate_active(candidate):
            continue
        cid = _candidate_id(candidate)
        missing = [field for field in ("severity", "impact") if not str(candidate.get(field) or "").strip()]
        impact_contract = candidate.get("impact_contract")
        if isinstance(impact_contract, dict) and not str(impact_contract.get("listed_impact") or candidate.get("impact") or "").strip():
            missing.append("impact_contract.listed_impact")
        if missing:
            rows.append(
                GapRow(
                    id=f"{GAP_IMPACT_CONTRACT_GATING}:{cid}",
                    category=GAP_IMPACT_CONTRACT_GATING,
                    priority=P0,
                    title=f"Candidate {cid} lacks impact-contract fields",
                    reason="Candidate cannot be promoted without exact severity and listed-impact mapping.",
                    evidence=[f"missing={','.join(_stable_unique(missing))}"],
                    stop_condition="candidate records severity plus exact listed program impact/OOS mapping",
                    next_command=_matching_action_command(actions, cid) or "python3 tools/program-impact-mapping-check.py <draft>",
                )
            )
    return rows


def _provider_routing_gaps(
    status: dict[str, Any],
    candidates: list[dict[str, Any]],
    runs: list[dict[str, Any]],
    actions: list[dict[str, Any]],
) -> list[GapRow]:
    evidence: list[str] = []
    provider_state = status.get("provider_routing") or status.get("providers") or status.get("provider")
    if isinstance(provider_state, dict):
        state_text = json.dumps(provider_state, sort_keys=True).lower()
        if any(marker in state_text for marker in ("missing", "blocked", "unverified", "direct_provider_call")):
            evidence.append("status provider routing records missing/blocked/unverified provider state")
    for candidate in candidates:
        text = json.dumps(candidate, sort_keys=True, default=str).lower()
        if any(marker in text for marker in _PROVIDER_MARKERS) and str(candidate.get("proof_state") or "").lower() not in {"executed", "proved"}:
            evidence.append(f"candidate {_candidate_id(candidate)} has provider-derived state without executed local proof")
    for run in runs:
        text = json.dumps(run, sort_keys=True, default=str).lower()
        if any(marker in text for marker in _PROVIDER_MARKERS) and str(run.get("execution_state") or "").lower() in _BAD_RUN_STATES:
            evidence.append(f"provider run {run.get('artifact_path') or run.get('tool')} is {run.get('execution_state')}")
    if not evidence:
        return []
    return [
        GapRow(
            id=GAP_PROVIDER_ROUTING,
            category=GAP_PROVIDER_ROUTING,
            priority=P2,
            title="Provider routing lacks local verification evidence",
            reason="Provider-derived work is advisory until preflighted and locally verified.",
            evidence=_stable_unique(evidence),
            stop_condition="provider packet has dispatch-preflight evidence and survivors have local verification/proof rows",
            next_command=_matching_action_command(actions, "provider") or "python3 tools/dispatch-preflight.py <template> <packet>",
        )
    ]


def _dirty_workspace_gaps(dirty_files: list[dict[str, Any]], actions: list[dict[str, Any]]) -> list[GapRow]:
    if not dirty_files:
        return []
    source_dirty = [
        row for row in dirty_files
        if str(row.get("role") or "").lower() in {"source_code", "canonical_doc", "unknown"}
    ]
    evidence = [
        f"{row.get('status') or 'dirty'}:{row.get('path') or '<unknown>'}"
        for row in (source_dirty or dirty_files)[:8]
    ]
    return [
        GapRow(
            id=GAP_DIRTY_WORKSPACE_HYGIENE,
            category=GAP_DIRTY_WORKSPACE_HYGIENE,
            priority=P1 if source_dirty else P2,
            title="Dirty workspace needs explicit hygiene handling",
            reason="Unreviewed dirty rows can mix operator, worker, and generated state.",
            evidence=evidence,
            stop_condition="dirty rows are committed, ignored, moved to evidence, or explicitly preserved with ownership",
            next_command=_matching_action_command(actions, "dirty") or "git status --short",
        )
    ]


def _paste_readiness_gaps(candidates: list[dict[str, Any]], actions: list[dict[str, Any]]) -> list[GapRow]:
    rows: list[GapRow] = []
    for candidate in candidates:
        if not _candidate_active(candidate):
            continue
        blockers = list(candidate.get("paste_ready_blockers") or paste_ready_blockers(candidate))
        if not blockers:
            continue
        cid = _candidate_id(candidate)
        rows.append(
            GapRow(
                id=f"{GAP_SUBMISSION_PASTE_READINESS}:{cid}",
                category=GAP_SUBMISSION_PASTE_READINESS,
                priority=P0 if str(candidate.get("status") or "").lower() == "paste_ready" else P1,
                title=f"Candidate {cid} is not paste-ready",
                reason="Paste readiness requires all required submission fields and proof artifacts.",
                evidence=[f"paste_blockers={','.join(blockers)}"],
                stop_condition="paste_ready_blockers is empty for the normalized candidate",
                next_command=_matching_action_command(actions, cid) or "python3 tools/pre-submit-check.sh <draft> --fix",
            )
        )
    return rows


def _status_missing(status: dict[str, Any], artifact_keys: tuple[str, ...]) -> bool:
    artifacts = status.get("artifacts")
    if not isinstance(artifacts, dict):
        return False
    observed = [artifacts.get(key) for key in artifact_keys if key in artifacts]
    if not observed:
        return False
    return all(not _artifact_row_present(row) for row in observed)


def _artifact_ready(status: dict[str, Any], artifact_key: str) -> bool:
    artifacts = status.get("artifacts")
    if not isinstance(artifacts, dict) or artifact_key not in artifacts:
        return False
    row = artifacts[artifact_key]
    if isinstance(row, dict):
        return bool(row.get("exists")) and str(row.get("status") or "").lower() not in {"missing", "blocked_unknown"}
    return bool(row)


def _artifact_row_present(row: Any) -> bool:
    if isinstance(row, dict):
        if "exists" in row:
            return bool(row["exists"])
        status = str(row.get("status") or "").lower()
        return status not in {"", "missing", "blocked_unknown"}
    return bool(row)


def _readiness_status(status: dict[str, Any], key: str) -> str:
    readiness = status.get("readiness")
    if isinstance(readiness, dict):
        row = readiness.get(key)
        if isinstance(row, dict):
            return str(row.get("status") or "").lower()
    return str(status.get(f"{key}_status") or "").lower()


def _needs_rust_scan(status: dict[str, Any]) -> bool:
    return any(
        _bool(status.get(key))
        for key in ("rust_workspace", "has_rust_roots", "dlt_workspace", "blockchain_dlt", "needs_rust_scan")
    )


def _run_tool_present(runs: list[dict[str, Any]], tools: set[str]) -> bool:
    return any(str(run.get("tool") or "").lower() in tools for run in runs)


def _bad_runs(runs: list[dict[str, Any]], tools: set[str]) -> list[dict[str, Any]]:
    return [
        run for run in runs
        if str(run.get("tool") or "").lower() in tools
        and str(run.get("execution_state") or "").lower() in _BAD_RUN_STATES
    ]


def _run_evidence(runs: list[dict[str, Any]]) -> list[str]:
    evidence: list[str] = []
    for run in runs:
        label = run.get("artifact_path") or run.get("tool") or "run"
        evidence.append(f"{label}:execution_state={run.get('execution_state')}")
        for blocker in run.get("blockers") or []:
            evidence.append(f"{label}:blocker={blocker}")
        for warning in run.get("warnings") or []:
            evidence.append(f"{label}:warning={warning}")
    return _stable_unique(evidence)


def _candidate_active(row: dict[str, Any]) -> bool:
    status = str(row.get("status") or "").lower()
    if status in _TERMINAL_CANDIDATE_STATUSES:
        return False
    return status in _ACTIVE_CANDIDATE_STATUSES or status not in _TERMINAL_CANDIDATE_STATUSES


def _candidate_id(row: dict[str, Any]) -> str:
    return str(row.get("id") or row.get("candidate_id") or row.get("slug") or "candidate")


def _severity(row: dict[str, Any]) -> str:
    return str(row.get("severity") or row.get("max_severity") or "")


def _matching_action_command(actions: list[dict[str, Any]], needle: str) -> str:
    needle_lower = needle.lower()
    for action in actions:
        haystack = " ".join(
            str(action.get(key) or "")
            for key in ("reason", "command", "artifact", "stop_condition")
        ).lower()
        if needle_lower in haystack:
            return str(action.get("command") or "")
    return ""


def _dedupe_rows(rows: Iterable[GapRow]) -> list[GapRow]:
    by_id: dict[str, GapRow] = {}
    for row in rows:
        current = by_id.get(row.id)
        if current is None or _priority_sort(row.priority) < _priority_sort(current.priority):
            by_id[row.id] = row
    return list(by_id.values())


def _priority_sort(priority: str) -> int:
    return {P0: 0, P1: 1, P2: 2}.get(priority, 9)


def _iter_dicts(rows: Iterable[Any]) -> Iterable[dict[str, Any]]:
    for row in rows:
        if isinstance(row, dict):
            yield row


def _bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "ready", "present"}
    return bool(value)


def _stable_unique(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def _shell_ws(ws: Path) -> str:
    text = str(ws)
    if all(ch.isalnum() or ch in "/._~=-" for ch in text):
        return text
    return "'" + text.replace("'", "'\"'\"'") + "'"


__all__ = [
    "SCHEMA",
    "GapRow",
    "score_known_capability_gaps",
    "render_human",
    "render_json",
]
