#!/usr/bin/env python3
"""Safe prompt workpack generation for control-plane provider tasks.

Workpacks are bounded prompts, not dispatch commands.  They preserve the
provider task proof boundary, pin writable ownership to explicit artifact
paths, and carry enough gap context for a model/operator to close the lane
without treating provider text as proof.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable
import json

from .providers import PROVIDER_PROFILES, promotion_blockers


SCHEMA = "auditooor.control.workpacks.v1"
PROMPT_MAX_CHARS = 6000
DEFAULT_OUTPUT_ROOT = "provider_workpacks"

_PROVIDER_OUTPUTS = {
    "kimi": "provider_outputs/kimi/{subject}.md",
    "minimax": "provider_outputs/minimax/{subject}.md",
    "claude": "agent_outputs/claude_{subject}.md",
    "codex": "codex_reviews/{subject}_gate.md",
}
_PATH_MARKERS = ("/", ".json", ".md", ".sol", ".rs", ".py", ".sh", ".toml", ".yaml", ".yml", ".txt")
_TASK_GAP_HINTS = {
    "source-extract": {"scanner_recall", "provider_routing", "impact_contract_gating"},
    "fixture-map": {"scanner_recall", "provider_routing"},
    "adversarial-kill": {"provider_routing", "submission_paste_readiness", "impact_contract_gating"},
    "duplicate-oos-review": {"submission_paste_readiness", "impact_contract_gating"},
    "harness-plan": {"harness_execution_replay", "invariant_autoseeding"},
    "draft-wire": {"submission_paste_readiness", "impact_contract_gating"},
    "closure-work": {"scanner_recall", "harness_execution_replay", "dirty_workspace_hygiene"},
    "proof-gate": {"harness_execution_replay", "submission_paste_readiness", "impact_contract_gating"},
    "submission-language-review": {"submission_paste_readiness", "impact_contract_gating"},
}


@dataclass(frozen=True)
class Workpack:
    schema: str
    id: str
    provider: str
    task_id: str
    task_kind: str
    subject_type: str
    subject_id: str
    title: str
    prompt: str
    time_budget_minutes: int | None = None
    kill_conditions: list[str] = field(default_factory=list)
    owned_files: list[str] = field(default_factory=list)
    read_only_refs: list[str] = field(default_factory=list)
    required_artifacts: list[str] = field(default_factory=list)
    promotion_blockers: list[str] = field(default_factory=list)
    proof_boundary: str = ""
    gap_rows: list[dict[str, Any]] = field(default_factory=list)
    output_path: str = ""
    launch_command: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "id": self.id,
            "provider": self.provider,
            "task_id": self.task_id,
            "task_kind": self.task_kind,
            "subject_type": self.subject_type,
            "subject_id": self.subject_id,
            "title": self.title,
            "time_budget_minutes": self.time_budget_minutes,
            "kill_conditions": list(self.kill_conditions),
            "prompt": self.prompt,
            "owned_files": list(self.owned_files),
            "read_only_refs": list(self.read_only_refs),
            "required_artifacts": list(self.required_artifacts),
            "promotion_blockers": list(self.promotion_blockers),
            "proof_boundary": self.proof_boundary,
            "gap_rows": [dict(row) for row in self.gap_rows],
            "output_path": self.output_path,
            "launch_command": self.launch_command,
        }


def build_workpacks(
    workspace: str | Path,
    *,
    provider_tasks: Iterable[dict[str, Any]],
    gap_rows: Iterable[dict[str, Any]] | dict[str, Any] | None = None,
    output_root: str = DEFAULT_OUTPUT_ROOT,
    max_gap_rows: int = 3,
) -> list[dict[str, Any]]:
    """Build bounded prompt workpacks from provider tasks and gap rows."""

    ws = Path(workspace).expanduser()
    gaps = _normalize_gap_rows(gap_rows)
    packs = [
        _build_workpack(ws, task, gaps, output_root=output_root, max_gap_rows=max_gap_rows)
        for task in provider_tasks
    ]
    return [pack.to_dict() for pack in _dedupe_workpacks(packs)]


def build_workpack_report(
    workspace: str | Path,
    *,
    provider_tasks: Iterable[dict[str, Any]],
    gap_rows: Iterable[dict[str, Any]] | dict[str, Any] | None = None,
    output_root: str = DEFAULT_OUTPUT_ROOT,
    max_gap_rows: int = 3,
) -> dict[str, Any]:
    """Return a serializable workpack report."""

    packs = build_workpacks(
        workspace,
        provider_tasks=provider_tasks,
        gap_rows=gap_rows,
        output_root=output_root,
        max_gap_rows=max_gap_rows,
    )
    counts: dict[str, int] = {}
    for pack in packs:
        provider = str(pack.get("provider") or "unknown")
        counts[provider] = counts.get(provider, 0) + 1
    return {
        "schema": SCHEMA,
        "workspace": str(Path(workspace).expanduser()),
        "workpack_count": len(packs),
        "counts_by_provider": counts,
        "workpacks": packs,
    }


def render_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, sort_keys=True) + "\n"


def render_markdown(report: dict[str, Any]) -> str:
    """Render workpacks as reviewable Markdown prompts."""

    packs = list(_iter_dicts(report.get("workpacks") or []))
    if not packs:
        return "# Control Workpacks\n\nNo workpacks generated.\n"
    lines = ["# Control Workpacks", ""]
    for pack in packs:
        lines.extend(
            [
                f"## {pack.get('id')}",
                "",
                f"- Provider: {pack.get('provider')}",
                f"- Task id: {pack.get('task_id')}",
                f"- Task: {pack.get('task_kind')}",
                f"- Subject: {pack.get('subject_type')} {pack.get('subject_id')}",
                f"- Time budget minutes: {_format_time_budget(pack.get('time_budget_minutes'))}",
                "- Kill conditions:",
                *_bullet_lines(
                    _string_list(pack.get("kill_conditions")),
                    fallback="No explicit kill conditions supplied; apply proof-boundary and hard-constraint stops.",
                ),
                f"- Output path: {pack.get('output_path')}",
                "",
                "```text",
                str(pack.get("prompt") or ""),
                "```",
                "",
            ]
        )
    return "\n".join(lines)


def _build_workpack(
    ws: Path,
    task: dict[str, Any],
    gaps: list[dict[str, Any]],
    *,
    output_root: str,
    max_gap_rows: int,
) -> Workpack:
    provider = _string(task.get("provider")).lower()
    task_id = _string(task.get("id") or f"{provider}:{task.get('task_kind')}")
    task_kind = _string(task.get("task_kind") or "task")
    subject_type = _string(task.get("subject_type") or "task")
    subject_id = _string(task.get("subject_id") or task_id)
    subject_slug = _slug(subject_id)
    title = _string(task.get("title") or task_id)
    time_budget_minutes = _time_budget_minutes(task.get("time_budget_minutes"))
    kill_conditions = _stable_unique(_string_list(task.get("kill_conditions")))
    required = _stable_unique(_string_list(task.get("required_artifacts")))
    proof_boundary = _string(task.get("proof_boundary")) or _default_boundary(provider)
    read_only = _read_only_refs(task)
    owned = _owned_files(provider, subject_slug, task, required)
    blockers = promotion_blockers(task)
    relevant_gaps = _select_gap_rows(task, gaps, max_gap_rows=max_gap_rows)
    output_path = f"{output_root.rstrip('/')}/{provider or 'unknown'}_{_slug(task_id)}.md"
    prompt = _render_prompt(
        workspace=ws,
        provider=provider,
        task_kind=task_kind,
        subject_type=subject_type,
        subject_id=subject_id,
        title=title,
        time_budget_minutes=time_budget_minutes,
        kill_conditions=kill_conditions,
        owned_files=owned,
        read_only_refs=read_only,
        required_artifacts=required,
        promotion_criteria=_stable_unique(_string_list(task.get("fail_closed_promotion_criteria"))),
        promotion_blockers=blockers,
        proof_boundary=proof_boundary,
        gap_rows=relevant_gaps,
    )
    return Workpack(
        schema=SCHEMA,
        id=f"workpack:{_slug(task_id)}",
        provider=provider,
        task_id=task_id,
        task_kind=task_kind,
        subject_type=subject_type,
        subject_id=subject_id,
        title=title,
        prompt=_bounded(prompt),
        time_budget_minutes=time_budget_minutes,
        kill_conditions=kill_conditions,
        owned_files=owned,
        read_only_refs=read_only,
        required_artifacts=required,
        promotion_blockers=blockers,
        proof_boundary=proof_boundary,
        gap_rows=relevant_gaps,
        output_path=output_path,
        launch_command="",
    )


def _render_prompt(
    *,
    workspace: Path,
    provider: str,
    task_kind: str,
    subject_type: str,
    subject_id: str,
    title: str,
    time_budget_minutes: int | None,
    kill_conditions: list[str],
    owned_files: list[str],
    read_only_refs: list[str],
    required_artifacts: list[str],
    promotion_criteria: list[str],
    promotion_blockers: list[str],
    proof_boundary: str,
    gap_rows: list[dict[str, Any]],
) -> str:
    profile = PROVIDER_PROFILES.get(provider, {})
    lines = [
        f"Provider: {provider or 'unknown'}",
        f"Role: {_string(profile.get('role') or 'unclassified')}",
        f"Task kind: {task_kind}",
        f"Subject: {subject_type} {subject_id}",
        f"Workspace: {workspace}",
        "",
        "Objective:",
        f"- {title}",
        "",
        "Time budget minutes:",
        f"- {_format_time_budget(time_budget_minutes)}",
        "",
        "Kill conditions:",
    ]
    lines.extend(
        _bullet_lines(
            kill_conditions,
            fallback="No explicit kill conditions supplied; apply proof-boundary and hard-constraint stops.",
        )
    )
    lines.extend([
        "",
        "Owned files:",
    ])
    lines.extend(_bullet_lines(owned_files, fallback="No source ownership. Write only the provider output artifact named below."))
    lines.extend(["", "Read-only references:"])
    lines.extend(_bullet_lines(read_only_refs, fallback="Use only the supplied task packet and workspace metadata."))
    lines.extend(["", "Required artifacts:"])
    lines.extend(_bullet_lines(required_artifacts, fallback="Record a terminal blocker if no durable artifact applies."))
    lines.extend(["", "Fail-closed promotion criteria:"])
    lines.extend(_bullet_lines(promotion_criteria, fallback="No promotion criteria supplied; treat as blocked."))
    lines.extend(["", "Promotion blockers:"])
    lines.extend(_bullet_lines(promotion_blockers, fallback="No computed blockers, but proof-boundary rules still apply."))
    lines.extend(["", "Proof boundary:", f"- {proof_boundary}", ""])
    lines.extend(
        [
            "Hard constraints:",
            "- Do not launch workers, agents, provider calls, GitHub Actions, PRs, or submissions.",
            "- Do not promote advisory model text as proof.",
            "- Keep output bounded to the owned files and required artifacts listed above.",
            "- If an owned artifact cannot be produced, write a blocker with exact missing prerequisite and stop condition.",
            "- Every promoted claim needs local source, run, live-proof, replay, or PoC evidence.",
            "",
            "Gap context:",
        ]
    )
    if gap_rows:
        for row in gap_rows:
            evidence = "; ".join(_string_list(row.get("evidence"))[:2])
            stop = _string(row.get("stop_condition"))
            lines.append(
                f"- {row.get('priority', '?')} {row.get('category', 'gap')}: "
                f"{row.get('title') or row.get('id')}"
            )
            if evidence:
                lines.append(f"  evidence: {evidence}")
            if stop:
                lines.append(f"  stop: {stop}")
    else:
        lines.append("- No directly matching gap row supplied.")
    lines.extend(["", "Deliverable:", "- A concise Markdown work result with files touched, artifacts produced, proof status, and blockers."])
    return "\n".join(lines) + "\n"


def _select_gap_rows(task: dict[str, Any], gaps: list[dict[str, Any]], *, max_gap_rows: int) -> list[dict[str, Any]]:
    if max_gap_rows <= 0:
        return []
    task_kind = _string(task.get("task_kind"))
    subject = _string(task.get("subject_id") or task.get("id")).lower()
    hint_categories = _TASK_GAP_HINTS.get(task_kind, set())
    scored: list[tuple[int, str, dict[str, Any]]] = []
    for row in gaps:
        haystack = " ".join(
            [
                _string(row.get("id")),
                _string(row.get("category")),
                _string(row.get("title")),
                _string(row.get("reason")),
                " ".join(_string_list(row.get("evidence"))),
            ]
        ).lower()
        score = 0
        if subject and subject in haystack:
            score += 40
        if _string(row.get("category")) in hint_categories:
            score += 20
        score += {"P0": 9, "P1": 6, "P2": 3}.get(_string(row.get("priority")), 0)
        if score:
            scored.append((-score, _string(row.get("id")), row))
    return [dict(row) for _, _, row in sorted(scored)[:max_gap_rows]]


def _owned_files(
    provider: str,
    subject_slug: str,
    task: dict[str, Any],
    required: list[str],
) -> list[str]:
    explicit = _string_list(task.get("owned_files"))
    if explicit:
        return _stable_unique(explicit)
    output_template = _PROVIDER_OUTPUTS.get(provider, "provider_outputs/{provider}/{subject}.md")
    owned = [output_template.format(provider=provider or "unknown", subject=subject_slug)]
    if provider in {"claude", "codex"}:
        owned.extend(path for path in required if _looks_like_path(path))
    return _stable_unique(owned)


def _read_only_refs(task: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    refs.extend(_string_list(task.get("read_only_refs")))
    refs.extend(_string_list(task.get("source_paths")))
    input_refs = task.get("input_refs")
    if isinstance(input_refs, dict):
        refs.extend(_string_list(input_refs.get("source_paths")))
        candidate = input_refs.get("candidate")
        if isinstance(candidate, dict):
            refs.extend(_string_list(candidate.get("source_paths") or candidate.get("files")))
        run = input_refs.get("run")
        if isinstance(run, dict):
            refs.append(_string(run.get("artifact_path")))
        action = input_refs.get("next_action")
        if isinstance(action, dict):
            refs.append(_string(action.get("artifact")))
    return _stable_unique(refs)


def _normalize_gap_rows(rows: Iterable[dict[str, Any]] | dict[str, Any] | None) -> list[dict[str, Any]]:
    if rows is None:
        return []
    if isinstance(rows, dict):
        return [dict(row) for row in _iter_dicts(rows.get("rows") or [])]
    return [dict(row) for row in _iter_dicts(rows)]


def _dedupe_workpacks(packs: list[Workpack]) -> list[Workpack]:
    seen: set[str] = set()
    out: list[Workpack] = []
    for pack in sorted(packs, key=lambda row: (row.provider, row.task_id)):
        if pack.id in seen:
            continue
        seen.add(pack.id)
        out.append(pack)
    return out


def _bullet_lines(values: list[str], *, fallback: str) -> list[str]:
    if not values:
        return [f"- {fallback}"]
    return [f"- {value}" for value in values]


def _default_boundary(provider: str) -> str:
    if provider in {"kimi", "minimax"}:
        return f"{provider} output is advisory and cannot promote a candidate without local proof."
    if provider == "claude":
        return "Claude may implement or draft artifacts, but Codex must gate proof before filing."
    if provider == "codex":
        return "Codex gates durable local evidence; provider text is not proof."
    return "Unknown provider output cannot promote a candidate."


def _looks_like_path(value: str) -> bool:
    text = _string(value)
    if not text or text.startswith("poc_command:"):
        return False
    return any(marker in text for marker in _PATH_MARKERS)


def _bounded(prompt: str) -> str:
    if len(prompt) <= PROMPT_MAX_CHARS:
        return prompt
    suffix = "\n[truncated: prompt exceeded bounded workpack limit]\n"
    return prompt[: PROMPT_MAX_CHARS - len(suffix)].rstrip() + suffix


def _iter_dicts(values: Iterable[Any]) -> Iterable[dict[str, Any]]:
    for value in values:
        if isinstance(value, dict):
            yield value


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


def _format_time_budget(value: Any) -> str:
    minutes = _time_budget_minutes(value)
    return "null" if minutes is None else str(minutes)


def _time_budget_minutes(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value > 0 else None
    text = _string(value)
    if not text:
        return None
    try:
        minutes = int(text, 10)
    except ValueError:
        return None
    return minutes if minutes > 0 else None


def _string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        item = _string(value)
        return [item] if item else []
    if isinstance(value, (list, tuple)):
        return [_string(item) for item in value if _string(item)]
    return []


def _string(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _slug(value: str) -> str:
    text = _string(value).lower()
    chars = [char if char.isalnum() or char in "._-" else "-" for char in text]
    slug = "-".join(part for part in "".join(chars).split("-") if part)
    return slug or "workpack"


__all__ = [
    "SCHEMA",
    "Workpack",
    "build_workpack_report",
    "build_workpacks",
    "render_json",
    "render_markdown",
]
