from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable


ActionRow = dict[str, Any]


REQUIRED_INTAKE_ARTIFACTS = (
    ("SCOPE.md", "scope text is missing", "import or write the program scope"),
    ("OOS.md", "OOS text is missing", "persist explicit out-of-scope clauses"),
    ("SEVERITY.md", "severity rubric is missing", "persist the program severity rubric"),
    (
        "RUBRIC_COVERAGE.md",
        "rubric coverage is missing",
        "map listed impacts before mining or filing",
    ),
)


def rank_next_actions(
    workspace: str | Path,
    status: dict[str, Any] | None = None,
    candidates: Iterable[dict[str, Any]] | None = None,
    runs: Iterable[dict[str, Any]] | None = None,
) -> list[ActionRow]:
    """Return ranked read-only next-action rows for a workspace state packet.

    The function accepts incomplete status dictionaries because the initial
    control plane will be assembled from mixed existing artifacts. Explicit
    dictionary fields win, and missing keys fall back to filesystem presence.
    """

    ws = Path(workspace)
    state = status or {}
    candidate_rows = list(candidates or [])
    run_rows = list(runs or state.get("runs", []) or [])
    actions: list[ActionRow] = []

    for artifact, reason, stop in REQUIRED_INTAKE_ARTIFACTS:
        if artifact == "OOS.md":
            present = _artifact_present(ws, state, artifact) or _artifact_present(
                ws, state, "OOS_PASTED.md"
            )
        else:
            present = _artifact_present(ws, state, artifact)
        if not present:
            command = _intake_command(ws, artifact)
            actions.append(
                _row(
                    10,
                    reason,
                    command,
                    artifact,
                    stop,
                    "Operator-supplied scope/OOS/severity text is policy context, not exploit proof.",
                )
            )

    if not _artifact_present(ws, state, ".auditooor/semantic_graph.json"):
        actions.append(
            _row(
                30,
                "semantic graph is missing",
                f"make semantic-graph WS={_shell_ws(ws)}",
                ".auditooor/semantic_graph.json",
                "semantic graph JSON exists and names entrypoints, roles, writes, and external calls",
                "Semantic graph output is production-path context; candidates still need local proof.",
            )
        )

    if _is_high_impact_workspace(state) and not _invariant_ledger_present(ws, state):
        actions.append(
            _row(
                35,
                "high-impact workspace is missing an invariant ledger",
                f"make audit-deep WS={_shell_ws(ws)}",
                "INVARIANT_LEDGER.md",
                "invariant ledger exists or a waiver explains why no invariant lane applies",
                "Invariant coverage is a promotion gate input, not submission evidence by itself.",
            )
        )

    if _needs_rust_scan(state) and not _rust_scan_present(ws, state):
        actions.append(
            _row(
                40,
                "Rust/DLT workspace is missing the canonical Rust scan summary",
                f"python3 tools/engage.py --workspace {_shell_ws(ws)} --stage scan-rust",
                "scanners/rust/SCAN_RUST_SUMMARY.json",
                "canonical Rust scan summary JSON or Markdown exists",
                "Scanner output is triage evidence; reportable claims require source or runtime proof.",
            )
        )

    for candidate in candidate_rows:
        actions.extend(_candidate_actions(ws, candidate))

    if _audit_deep_partial(state, run_rows):
        actions.append(
            _row(
                70,
                "audit-deep has partial, blocked, or skipped execution lanes",
                f"make audit-deep WS={_shell_ws(ws)}",
                "audit-deep summary",
                "all required audit-deep lanes are executed, waived, or terminally blocked with reasons",
                "Deep-engine output remains advisory until replayed and recorded as executed proof.",
            )
        )

    if not actions:
        actions.append(
            _row(
                90,
                "no structural blockers detected in the supplied status packet",
                f"python3 tools/engage.py --workspace {_shell_ws(ws)} --stage mine-prioritize",
                "swarm/mining_priorities.json",
                "fresh mining priorities exist or all candidates are terminal",
                "Prioritization is planning context, not exploit proof.",
            )
        )

    return sorted(actions, key=lambda row: (int(row["priority"]), row["reason"]))


def _candidate_actions(ws: Path, candidate: dict[str, Any]) -> list[ActionRow]:
    cid = str(candidate.get("id") or candidate.get("candidate_id") or "candidate")
    draft = str(candidate.get("draft") or candidate.get("draft_path") or "<draft>")
    safe_draft = _display_artifact(draft)
    actions: list[ActionRow] = []

    if not _truthy_any(candidate, ("oos_checked", "oos_clear", "has_oos_check")):
        actions.append(
            _row(
                50,
                f"candidate {cid} is missing per-finding OOS clearance",
                f"python3 tools/per-finding-oos-check.py {_shell_ws(ws)} {safe_draft}",
                f"{cid}:OOS_CHECK.md",
                "candidate records an OOS check result for the exact draft",
                "OOS clearance only proves eligibility against scope, not exploitability.",
            )
        )

    if not _truthy_any(candidate, ("inline_poc", "inline_poc_ready", "has_inline_poc", "poc_inline")):
        actions.append(
            _row(
                55,
                f"candidate {cid} is missing an inline PoC",
                f"python3 tools/poc-scaffold.py --bootstrap-workspace {_shell_ws(ws)} --out poc-tests/{cid}.t.sol",
                f"{cid}:inline_poc",
                "draft includes a triager-inspectable inline PoC or explicit replay artifact",
                "A scaffold is not proof until wired, executed, and impact-asserted.",
            )
        )

    if not _truthy_any(candidate, ("test_output", "has_test_output", "forge_pass", "poc_result")):
        actions.append(
            _row(
                60,
                f"candidate {cid} is missing executed test output",
                f"make poc-execution-record WS={_shell_ws(ws)} BRIEF={safe_draft} CMD='<test command>'",
                f"{cid}:poc_execution",
                "poc_execution manifest records command output and a proved/disproved/blocked result",
                "Only executed local output with impact assertions can support submission language.",
            )
        )

    return actions


def _row(
    priority: int,
    reason: str,
    command: str,
    artifact: str,
    stop_condition: str,
    proof_boundary: str,
) -> ActionRow:
    return {
        "priority": priority,
        "reason": reason,
        "command": command,
        "artifact": artifact,
        "stop_condition": stop_condition,
        "proof_boundary": proof_boundary,
    }


def _artifact_present(ws: Path, status: dict[str, Any], artifact: str) -> bool:
    artifacts = status.get("artifacts", {})
    if isinstance(artifacts, dict):
        if artifact in artifacts:
            return bool(artifacts[artifact])
        base = Path(artifact).name
        if base in artifacts:
            return bool(artifacts[base])

    key = _artifact_key(artifact)
    for prefix in ("has_", ""):
        if prefix + key in status:
            return bool(status[prefix + key])

    if artifact == "SEVERITY.md" and (
        _artifact_present(ws, status, "SEVERITY_SMART_CONTRACTS.md")
        or _artifact_present(ws, status, "SEVERITY_BLOCKCHAIN_DLT.md")
    ):
        return True

    return (ws / artifact).exists()


def _artifact_key(artifact: str) -> str:
    return (
        artifact.lower()
        .replace(".", "_")
        .replace("/", "_")
        .replace("-", "_")
    )


def _invariant_ledger_present(ws: Path, status: dict[str, Any]) -> bool:
    return any(
        _artifact_present(ws, status, artifact)
        for artifact in (
            "INVARIANT_LEDGER.md",
            "docs/INVARIANT_LEDGER.md",
            ".auditooor/invariant_ledger.json",
        )
    )


def _rust_scan_present(ws: Path, status: dict[str, Any]) -> bool:
    return any(
        _artifact_present(ws, status, artifact)
        for artifact in (
            "scanners/rust/SCAN_RUST_SUMMARY.json",
            "scanners/rust/SCAN_RUST_SUMMARY.md",
        )
    )


def _is_high_impact_workspace(status: dict[str, Any]) -> bool:
    if "high_impact_workspace" in status:
        return bool(status["high_impact_workspace"])
    severity = str(status.get("max_severity") or status.get("severity") or "").lower()
    return severity in {"high", "critical"}


def _needs_rust_scan(status: dict[str, Any]) -> bool:
    return any(
        bool(status.get(key))
        for key in (
            "rust_workspace",
            "has_rust_roots",
            "dlt_workspace",
            "blockchain_dlt",
            "needs_rust_scan",
        )
    )


def _audit_deep_partial(status: dict[str, Any], runs: Iterable[dict[str, Any]]) -> bool:
    audit_deep = status.get("audit_deep")
    if isinstance(audit_deep, dict):
        state = str(audit_deep.get("state") or audit_deep.get("status") or "").lower()
        if state in {"partial", "blocked", "skipped", "incomplete"}:
            return True
        lanes = audit_deep.get("lanes")
        if isinstance(lanes, list):
            return any(
                str(lane.get("state") or lane.get("status") or "").lower()
                in {"partial", "blocked", "skipped", "incomplete", "planned"}
                for lane in lanes
                if isinstance(lane, dict)
            )
    elif str(audit_deep).lower() in {"partial", "blocked", "skipped", "incomplete"}:
        return True

    for run in runs:
        if not isinstance(run, dict):
            continue
        name = str(run.get("name") or run.get("stage") or run.get("tool") or "").lower()
        state = str(run.get("state") or run.get("status") or "").lower()
        if name in {"audit-deep", "audit_deep"} and state in {
            "partial",
            "blocked",
            "skipped",
            "incomplete",
        }:
            return True
    return False


def _truthy_any(row: dict[str, Any], keys: Iterable[str]) -> bool:
    return any(bool(row.get(key)) for key in keys)


def _intake_command(ws: Path, artifact: str) -> str:
    if artifact == "OOS.md":
        return f"python3 tools/operator-oos-import.py {_shell_ws(ws)}"
    return f"python3 tools/engage.py --workspace {_shell_ws(ws)} --stage intake-baseline"


def _shell_ws(ws: Path) -> str:
    text = str(ws)
    if not text:
        return "."
    if all(ch.isalnum() or ch in "/._~=-" for ch in text):
        return text
    return "'" + text.replace("'", "'\"'\"'") + "'"


def _display_artifact(value: str) -> str:
    if value.startswith("/"):
        return Path(value).name
    return value
