#!/usr/bin/env python3
"""Provider routing primitives for control-plane task packets.

The functions in this module are deliberately read-only and stdlib-only. They
turn normalized candidates, run rows, and next actions into provider task
packets with explicit proof boundaries. Provider output can suggest local work;
it cannot itself promote a finding unless the packet's fail-closed criteria are
met by durable local artifacts.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable


PROVIDER_TASK_SCHEMA = "auditooor.provider_task.v1"

PROVIDER_ORDER = ("kimi", "minimax", "claude", "codex")

ADVISORY_PROVIDERS = {"kimi", "minimax"}
IMPLEMENTATION_PROVIDERS = {"claude"}
GATE_PROVIDER = "codex"

PROVIDER_PROFILES: dict[str, dict[str, Any]] = {
    "kimi": {
        "role": "source_extraction",
        "evidence_rule": "advisory_only",
        "max_context_tokens_hint": 250_000,
        "budget_hint": "medium",
        "can_draft": False,
        "can_wire_harness": False,
        "can_gate_submission": False,
        "default_task_kinds": ["source-extract", "fixture-map"],
    },
    "minimax": {
        "role": "adversarial_kill",
        "evidence_rule": "advisory_only",
        "max_context_tokens_hint": 1_000_000,
        "budget_hint": "medium",
        "can_draft": False,
        "can_wire_harness": False,
        "can_gate_submission": False,
        "default_task_kinds": ["adversarial-kill", "duplicate-oos-review"],
    },
    "claude": {
        "role": "implementation",
        "evidence_rule": "may_draft_or_wire_local_artifacts",
        "max_context_tokens_hint": 180_000,
        "budget_hint": "medium",
        "can_draft": True,
        "can_wire_harness": True,
        "can_gate_submission": False,
        "default_task_kinds": ["harness-plan", "draft-wire", "closure-work"],
    },
    "codex": {
        "role": "proof_and_submission_gate",
        "evidence_rule": "local_proof_required",
        "max_context_tokens_hint": 200_000,
        "budget_hint": "low",
        "can_draft": True,
        "can_wire_harness": True,
        "can_gate_submission": True,
        "default_task_kinds": ["proof-gate", "submission-language-review"],
    },
}


@dataclass(frozen=True)
class ProviderTask:
    schema: str
    id: str
    provider: str
    task_kind: str
    subject_type: str
    subject_id: str
    title: str
    priority: int
    evidence_rule: str
    proof_boundary: str
    required_artifacts: list[str] = field(default_factory=list)
    fail_closed_promotion_criteria: list[str] = field(default_factory=list)
    budget_hint: str = "medium"
    context_hints: dict[str, Any] = field(default_factory=dict)
    input_refs: dict[str, Any] = field(default_factory=dict)
    blockers: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def provider_profiles() -> dict[str, dict[str, Any]]:
    """Return a copy of static provider calibration profiles."""

    return {
        name: {
            **profile,
            "default_task_kinds": list(profile["default_task_kinds"]),
        }
        for name, profile in PROVIDER_PROFILES.items()
    }


def build_provider_tasks(
    workspace: str | Path,
    *,
    candidates: Iterable[Any] | None = None,
    runs: Iterable[dict[str, Any]] | None = None,
    next_actions: Iterable[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Build normalized provider task rows from control-plane state inputs."""

    ws = Path(workspace).expanduser()
    tasks: list[ProviderTask] = []
    run_rows = [dict(row) for row in runs or []]
    candidate_rows = [_object_to_dict(candidate) for candidate in candidates or []]
    action_rows = [dict(action) for action in next_actions or []]
    proof_artifacts = _proof_counted_artifacts(run_rows)

    for candidate in candidate_rows:
        tasks.extend(_candidate_tasks(ws, candidate, proof_artifacts))

    for run in run_rows:
        tasks.extend(_run_row_tasks(ws, run))

    for action in action_rows:
        tasks.extend(_next_action_tasks(ws, action))

    return [task.to_dict() for task in _dedupe_tasks(tasks)]


def calibrate_provider_task(task: dict[str, Any]) -> dict[str, Any]:
    """Attach provider profile details and fail-closed promotion status."""

    provider = str(task.get("provider") or "").lower()
    profile = PROVIDER_PROFILES.get(provider)
    if profile is None:
        calibrated = dict(task)
        calibrated["calibration_status"] = "blocked"
        calibrated["calibration_blockers"] = ["unknown_provider"]
        return calibrated

    calibrated = dict(task)
    blockers = list(calibrated.get("blockers") or [])
    criteria = list(calibrated.get("fail_closed_promotion_criteria") or [])
    artifacts = list(calibrated.get("required_artifacts") or [])
    if provider in ADVISORY_PROVIDERS:
        blockers.append("provider_output_advisory_only")
    if provider == GATE_PROVIDER and not artifacts:
        blockers.append("codex_gate_missing_required_artifacts")
    if provider == GATE_PROVIDER and not criteria:
        blockers.append("codex_gate_missing_promotion_criteria")

    calibrated["provider_profile"] = {
        key: value
        for key, value in profile.items()
        if key not in {"default_task_kinds"}
    }
    calibrated["calibration_status"] = "blocked" if blockers else "ready"
    calibrated["calibration_blockers"] = _stable_unique(blockers)
    return calibrated


def calibrate_provider_tasks(tasks: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return [calibrate_provider_task(task) for task in tasks]


def promotion_blockers(task: dict[str, Any], artifacts_present: Iterable[str] | None = None) -> list[str]:
    """Return fail-closed blockers for treating a task as promotion-ready."""

    provider = str(task.get("provider") or "").lower()
    blockers = list(task.get("blockers") or [])
    if provider in ADVISORY_PROVIDERS:
        blockers.append("advisory_provider_cannot_promote")
    if provider == "claude":
        blockers.append("claude_output_requires_codex_gate")
    required = [str(item) for item in task.get("required_artifacts") or []]
    present = set(artifacts_present or [])
    for artifact in required:
        if artifact not in present:
            blockers.append(f"missing_artifact:{artifact}")
    criteria = [str(item) for item in task.get("fail_closed_promotion_criteria") or []]
    if not criteria:
        blockers.append("missing_fail_closed_criteria")
    return _stable_unique(blockers)


def _candidate_tasks(
    ws: Path,
    candidate: dict[str, Any],
    proof_artifacts: dict[str, list[str]],
) -> list[ProviderTask]:
    cid = _string(candidate.get("id") or candidate.get("candidate_id") or "candidate")
    title = _string(candidate.get("title") or candidate.get("claim") or cid)
    proof_state = _string(candidate.get("proof_state") or candidate.get("status")).lower()
    source_paths = _string_list(candidate.get("source_paths") or candidate.get("files"))
    candidate_refs = {"candidate": cid, "source_paths": source_paths}
    tasks: list[ProviderTask] = []

    if proof_state in {"", "lead", "candidate", "planned", "scaffolded", "blocked"}:
        tasks.append(
            _task(
                ws,
                provider="kimi",
                kind="source-extract",
                subject_type="candidate",
                subject_id=cid,
                title=f"Extract line-cited production evidence for {title}",
                priority=30,
                required_artifacts=[
                    ".auditooor/semantic_graph.json",
                    "provider-packets/source-extract",
                ],
                criteria=[
                    "line-cited source facts are locally checked",
                    "production path is mapped before PoC promotion",
                ],
                input_refs=candidate_refs,
            )
        )
        tasks.append(
            _task(
                ws,
                provider="minimax",
                kind="adversarial-kill",
                subject_type="candidate",
                subject_id=cid,
                title=f"Kill or narrow duplicate/OOS/theory risk for {title}",
                priority=35,
                required_artifacts=[
                    "submission-corpus-map result",
                    "per-finding OOS notes",
                ],
                criteria=[
                    "duplicate and OOS concerns are locally resolved",
                    "provider rejection is converted into a terminal blocker or local check",
                ],
                input_refs=candidate_refs,
            )
        )

    if not _candidate_has_executed_poc(candidate):
        tasks.append(
            _task(
                ws,
                provider="claude",
                kind="harness-plan",
                subject_type="candidate",
                subject_id=cid,
                title=f"Wire executable PoC or closure harness for {title}",
                priority=45,
                required_artifacts=[
                    "poc test or explicit replay artifact",
                    "poc_execution/**/execution_manifest.json",
                ],
                criteria=[
                    "harness compiles and runs locally",
                    "execution manifest records proved, disproved, or blocked",
                    "impact assertion is explicit",
                ],
                input_refs=candidate_refs,
            )
        )

    if _candidate_gate_ready(candidate, proof_artifacts):
        artifacts = proof_artifacts.get(cid) or _candidate_artifacts(candidate)
        tasks.append(
            _task(
                ws,
                provider="codex",
                kind="proof-gate",
                subject_type="candidate",
                subject_id=cid,
                title=f"Gate proof chain and submission language for {title}",
                priority=20,
                required_artifacts=artifacts,
                criteria=[
                    "local proof artifact is executed and impact-counted",
                    "per-finding OOS check is present and clear",
                    "pre-submit-check passes for the exact draft",
                    "submission language does not rely on advisory provider output",
                ],
                input_refs=candidate_refs,
            )
        )

    return tasks


def _run_row_tasks(ws: Path, run: dict[str, Any]) -> list[ProviderTask]:
    state = _string(run.get("execution_state")).lower()
    tool = _string(run.get("tool") or "run")
    artifact = _string(run.get("artifact_path") or tool)
    if state not in {"blocked", "partial", "planned", "missing_workspace"}:
        return []
    return [
        _task(
            ws,
            provider="claude",
            kind="closure-work",
            subject_type="run",
            subject_id=artifact,
            title=f"Close blocked or partial {tool} run",
            priority=65,
            required_artifacts=[artifact],
            criteria=[
                "rerun or waiver is recorded in a durable artifact",
                "blocked lanes are terminally explained before promotion",
            ],
            input_refs={"run": run},
        )
    ]


def _next_action_tasks(ws: Path, action: dict[str, Any]) -> list[ProviderTask]:
    reason = _string(action.get("reason") or "next action")
    artifact = _string(action.get("artifact") or "workspace artifact")
    priority = _int(action.get("priority"), 70)
    provider = "claude"
    kind = "closure-work"
    if "submission" in reason.lower() or "proof" in reason.lower():
        provider = "codex"
        kind = "proof-gate"
    return [
        _task(
            ws,
            provider=provider,
            kind=kind,
            subject_type="next_action",
            subject_id=_slug(reason),
            title=f"Resolve next action: {reason}",
            priority=priority,
            required_artifacts=[artifact],
            criteria=[
                _string(action.get("stop_condition") or "stop condition is satisfied"),
                "result is recorded locally before promotion",
            ],
            input_refs={"next_action": action},
        )
    ]


def _task(
    ws: Path,
    *,
    provider: str,
    kind: str,
    subject_type: str,
    subject_id: str,
    title: str,
    priority: int,
    required_artifacts: list[str],
    criteria: list[str],
    input_refs: dict[str, Any],
) -> ProviderTask:
    profile = PROVIDER_PROFILES[provider]
    blockers: list[str] = []
    if provider in ADVISORY_PROVIDERS:
        proof_boundary = (
            f"{provider} output is advisory and must be converted into local "
            "source, run, live-proof, or PoC evidence before promotion."
        )
    elif provider == "claude":
        proof_boundary = (
            "Claude may draft or wire artifacts, but Codex must gate proof and "
            "submission language before filing."
        )
    else:
        proof_boundary = (
            "Codex gates only durable local evidence; provider text is never a "
            "substitute for executed proof."
        )
    return ProviderTask(
        schema=PROVIDER_TASK_SCHEMA,
        id=f"{provider}:{kind}:{_slug(subject_id)}",
        provider=provider,
        task_kind=kind,
        subject_type=subject_type,
        subject_id=subject_id,
        title=title,
        priority=priority,
        evidence_rule=_string(profile["evidence_rule"]),
        proof_boundary=proof_boundary,
        required_artifacts=_stable_unique(required_artifacts),
        fail_closed_promotion_criteria=_stable_unique(criteria),
        budget_hint=_string(profile["budget_hint"]),
        context_hints={
            "workspace": ws.as_posix(),
            "max_context_tokens_hint": profile["max_context_tokens_hint"],
            "provider_role": profile["role"],
            "task_focus": kind,
        },
        input_refs=input_refs,
        blockers=blockers,
    )


def _candidate_has_executed_poc(candidate: dict[str, Any]) -> bool:
    proof_state = _string(candidate.get("proof_state")).lower()
    if proof_state in {"executed", "proved"}:
        return True
    if _truthy(candidate.get("proof_counted")):
        return True
    poc = candidate.get("poc")
    if isinstance(poc, dict):
        result = _string(poc.get("result") or poc.get("expected_output")).lower()
        if "passed" in result or "proved" in result:
            return True
    result = _string(candidate.get("poc_result")).lower()
    return "passed" in result or result == "proved"


def _candidate_gate_ready(candidate: dict[str, Any], proof_artifacts: dict[str, list[str]]) -> bool:
    cid = _string(candidate.get("id") or candidate.get("candidate_id"))
    if proof_artifacts.get(cid):
        return True
    return _candidate_has_executed_poc(candidate) and (
        _truthy(candidate.get("oos_checked"))
        or _truthy(candidate.get("oos_clear"))
        or _nested_truthy(candidate, "oos", "checked")
    )


def _candidate_artifacts(candidate: dict[str, Any]) -> list[str]:
    artifacts = _string_list(candidate.get("source_paths"))
    draft = _string(candidate.get("draft") or candidate.get("draft_path"))
    if draft:
        artifacts.append(draft)
    poc = candidate.get("poc")
    if isinstance(poc, dict):
        command = _string(poc.get("command"))
        if command:
            artifacts.append(f"poc_command:{command}")
    return _stable_unique(artifacts or ["poc_execution/**/execution_manifest.json"])


def _proof_counted_artifacts(run_rows: list[dict[str, Any]]) -> dict[str, list[str]]:
    by_candidate: dict[str, list[str]] = {}
    for row in run_rows:
        if row.get("proof_counted") is not True:
            continue
        artifact = _string(row.get("artifact_path"))
        cid = _candidate_id_from_artifact(artifact)
        if cid:
            by_candidate.setdefault(cid, []).append(artifact)
    return {cid: _stable_unique(paths) for cid, paths in by_candidate.items()}


def _candidate_id_from_artifact(artifact: str) -> str:
    parts = [part for part in artifact.split("/") if part]
    if "poc_execution" in parts:
        idx = parts.index("poc_execution")
        if idx + 1 < len(parts):
            return parts[idx + 1]
    return ""


def _object_to_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return dict(value)
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        row = to_dict()
        return dict(row) if isinstance(row, dict) else {}
    if hasattr(value, "__dict__"):
        return dict(value.__dict__)
    return {}


def _dedupe_tasks(tasks: list[ProviderTask]) -> list[ProviderTask]:
    seen: set[str] = set()
    deduped: list[ProviderTask] = []
    for task in sorted(tasks, key=lambda row: (row.priority, row.provider, row.id)):
        if task.id in seen:
            continue
        seen.add(task.id)
        deduped.append(task)
    return deduped


def _stable_unique(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        item = _string(value)
        if not item or item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def _string(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [_string(value)] if _string(value) else []
    if isinstance(value, list):
        return [_string(item) for item in value if _string(item)]
    if isinstance(value, tuple):
        return [_string(item) for item in value if _string(item)]
    return []


def _truthy(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "pass", "passed", "clear"}
    return bool(value)


def _nested_truthy(row: dict[str, Any], key: str, nested_key: str) -> bool:
    value = row.get(key)
    return isinstance(value, dict) and _truthy(value.get(nested_key))


def _int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _slug(value: str) -> str:
    text = _string(value).lower()
    chars = [char if char.isalnum() or char in "._-" else "-" for char in text]
    slug = "-".join(part for part in "".join(chars).split("-") if part)
    return slug or "task"


__all__ = [
    "PROVIDER_TASK_SCHEMA",
    "PROVIDER_PROFILES",
    "ProviderTask",
    "build_provider_tasks",
    "calibrate_provider_task",
    "calibrate_provider_tasks",
    "promotion_blockers",
    "provider_profiles",
]
