from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable


def render_handoff(
    workspace: str | Path,
    status: dict[str, Any] | None,
    candidates: Iterable[dict[str, Any]] | None,
    runs: Iterable[dict[str, Any]] | None,
    next_actions: Iterable[dict[str, Any]] | None,
    audience: str = "claude",
) -> str:
    """Render a concise internal handoff packet from control-plane state."""

    ws = Path(workspace)
    state = status or {}
    candidate_rows = list(candidates or [])
    run_rows = list(runs or [])
    action_rows = list(next_actions or [])
    title = _workspace_label(ws)

    lines = [
        f"# Auditooor Handoff: {title}",
        "",
        f"Audience: {audience}",
        f"Workspace: {_workspace_context(ws)}",
        f"Stage: {state.get('stage') or state.get('phase') or 'unknown'}",
    ]

    blockers = _as_list(state.get("blockers"))
    if blockers:
        lines.extend(["", "## Blockers"])
        lines.extend(f"- {_clean_text(str(blocker), ws)}" for blocker in blockers[:8])

    lines.extend(["", "## Candidates"])
    if candidate_rows:
        for candidate in candidate_rows[:8]:
            cid = candidate.get("id") or candidate.get("candidate_id") or "candidate"
            severity = candidate.get("severity") or "unrated"
            lifecycle = candidate.get("status") or candidate.get("state") or "unknown"
            missing = _missing_candidate_bits(candidate)
            suffix = f"; missing {', '.join(missing)}" if missing else "; gates present"
            lines.append(f"- {cid}: {severity}, {lifecycle}{suffix}")
    else:
        lines.append("- none recorded")

    lines.extend(["", "## Recent Runs"])
    if run_rows:
        for run in run_rows[:8]:
            name = run.get("name") or run.get("stage") or run.get("tool") or "run"
            state_text = run.get("state") or run.get("status") or "unknown"
            artifact = run.get("artifact") or run.get("summary") or ""
            artifact_text = f" ({_artifact_label(str(artifact), ws)})" if artifact else ""
            lines.append(f"- {name}: {state_text}{artifact_text}")
    else:
        lines.append("- none recorded")

    lines.extend(["", "## Next Actions"])
    if action_rows:
        for action in sorted(action_rows, key=lambda row: int(row.get("priority", 999)))[:10]:
            lines.append(
                "- P{priority}: {reason}\n"
                "  Command: `{command}`\n"
                "  Artifact: `{artifact}`\n"
                "  Stop: {stop}\n"
                "  Boundary: {boundary}".format(
                    priority=action.get("priority"),
                    reason=_clean_text(str(action.get("reason", "")), ws),
                    command=_clean_text(str(action.get("command", "")), ws),
                    artifact=_artifact_label(str(action.get("artifact", "")), ws),
                    stop=_clean_text(str(action.get("stop_condition", "")), ws),
                    boundary=_clean_text(str(action.get("proof_boundary", "")), ws),
                )
            )
    else:
        lines.append("- none ranked")

    lines.extend(
        [
            "",
            "## Proof Rule",
            "Only executed local PoC, fork/live/source proof, or recorded command output can support submission language. LLM output, scanners, and plans are advisory until locally proved.",
        ]
    )

    return "\n".join(lines).rstrip() + "\n"


def _missing_candidate_bits(candidate: dict[str, Any]) -> list[str]:
    missing = []
    if not any(candidate.get(key) for key in ("oos_checked", "oos_clear", "has_oos_check")):
        missing.append("OOS")
    if not any(candidate.get(key) for key in ("inline_poc", "inline_poc_ready", "has_inline_poc", "poc_inline")):
        missing.append("inline PoC")
    if not any(candidate.get(key) for key in ("test_output", "has_test_output", "forge_pass", "poc_result")):
        missing.append("test output")
    return missing


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _workspace_label(ws: Path) -> str:
    return ws.name or str(ws)


def _workspace_context(ws: Path) -> str:
    return str(ws)


def _artifact_label(value: str, ws: Path) -> str:
    if not value:
        return value
    cleaned = _clean_text(value, ws)
    if cleaned.startswith("/"):
        return Path(cleaned).name
    return cleaned


def _clean_text(value: str, ws: Path) -> str:
    """Avoid leaking local absolute paths unrelated to the workspace context."""

    ws_text = str(ws)
    if ws_text and ws_text in value:
        value = value.replace(ws_text, "<workspace>")
    parts = []
    for token in value.split():
        if token.startswith("/") and not token.startswith("<workspace>"):
            parts.append(Path(token).name)
        else:
            parts.append(token)
    return " ".join(parts)
