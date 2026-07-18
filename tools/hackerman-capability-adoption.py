#!/usr/bin/env python3
"""Report MCP callable adoption over the last N hunt iterations.

Reads ``.auditooor/mcp_call_log.jsonl`` from one or more workspaces (or any
``--extra-log`` files / glob) and prints per-callable invocation counts. Flags
callables with <3 calls as LOW_ADOPTION and ==0 calls as DEAD_ADOPTION over
the chosen N-iteration window (default N=7).

Schema of the log rows is whatever ``vault-mcp-server.py::_record_call_telemetry``
emits today:

    {"ts": "...Z",
     "workspace": "/abs/path",
     "callable": "vault_resume_context",
     "args_hash": "deadbee0",
     "verdict": "ok|degraded|error|unknown",
     "duration_ms": 12,
     "degraded": false}

This tool is read-only; it never writes or rotates the log.
"""
from __future__ import annotations

import argparse
import glob
import json
from collections import OrderedDict
from pathlib import Path
from typing import Any, Iterable


REPO_ROOT = Path(__file__).resolve().parents[1]

# Mirror tools/hackerman-capability-status.py::TRACKED_CALLABLES_FOR_ADOPTION
# so the two surfaces stay in lockstep without an import cycle.
TRACKED_CALLABLES = (
    "vault_resume_context",
    "vault_exploit_context",
    "vault_harness_context",
    "vault_knowledge_gap_context",
    "vault_function_mindset",
    "vault_function_signature_shape",
    "vault_function_shape_attack_evidence",
    "vault_cross_language_pattern_lift",
    "vault_hackerman_chain_candidates",
    "vault_hackerman_exploit_predicates",
    "vault_hackerman_go_cosmos_inventory",
    "vault_chained_attack_plan_context",
    "vault_toolsite_context",
    "vault_hacker_brief_for_lane",
    "vault_hacker_brief_for_lane_v2",
    "vault_hacker_brief_for_lane_v3",
    "vault_attack_class_evidence",
    "vault_attack_class_evidence_v2",
    "vault_attack_class_evidence_v3",
    "vault_hackerman_detector_relationships",
    "vault_severity_calibration",
    "vault_detector_action_graph_context",
    "vault_high_impact_execution_bridge_context",
    "vault_poc_execution_record_context",
    "vault_cosmos_evidence_pack_context",
    "vault_solidity_detector_proof_context",
    "vault_loop_finalization_check",
    # V3 conversion / judgment / corpus-delivery surfaces. These are the
    # callables that should become visible once the V3 pipes are used during
    # real hunts, not merely documented in the tooling index.
    "vault_hackerman_novel_vector_context",
    "vault_current_to_exploit_conversion_gate_context",
    "vault_exploit_queue_context",
    "vault_exploit_severity_scope_oracle",
    "vault_poc_falsification_context",
    "vault_agent_artifact_mining_context",
    "vault_audit_deep_manifest_summary",
    "vault_mcp_explorer_context",
    "vault_originality_before_proof_gate",
    "vault_high_plus_submission_gate",
    "vault_proof_artifact_index_context",
)
LOW_ADOPTION_THRESHOLD = 3


def _resolve_workspace_log(workspace: str) -> Path:
    return Path(workspace).expanduser() / ".auditooor" / "mcp_call_log.jsonl"


def _collect_logs(
    *,
    workspaces: list[str],
    workspace_globs: list[str],
    extra_logs: list[str],
) -> list[Path]:
    paths: list[Path] = []
    for ws in workspaces:
        p = _resolve_workspace_log(ws)
        if p.is_file():
            paths.append(p)
    for pattern in workspace_globs:
        for match in glob.glob(str(Path(pattern).expanduser())):
            p = _resolve_workspace_log(match)
            if p.is_file():
                paths.append(p)
    for raw in extra_logs:
        p = Path(raw).expanduser()
        if p.is_file():
            paths.append(p)
    # Dedup while preserving order.
    seen: set[str] = set()
    out: list[Path] = []
    for p in paths:
        key = str(p.resolve())
        if key in seen:
            continue
        seen.add(key)
        out.append(p)
    return out


def _read_rows(paths: Iterable[Path]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in paths:
        log_key = str(path.expanduser().resolve())
        try:
            with path.open("r", encoding="utf-8", errors="ignore") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        row = json.loads(line)
                    except Exception:
                        continue
                    if isinstance(row, dict):
                        row = dict(row)
                        row["_log_path"] = log_key
                        rows.append(row)
        except Exception:
            continue
    # Sort by ts (string lex ISO is fine for Zulu-suffix timestamps).
    rows.sort(key=lambda r: r.get("ts") or "")
    return rows


def _window_rows(rows: list[dict[str, Any]], iterations: int) -> list[dict[str, Any]]:
    """Return only rows within the last `iterations` hunt iterations.

    Heuristic for "iteration boundary": the call log records one or more
    ``vault_resume_context`` calls at the start of each iteration. The last N
    iterations therefore start at the N-th-from-last distinct
    ``vault_resume_context`` ts. If fewer resume rows exist, return all rows.
    """
    if iterations <= 0:
        return rows
    resume_ts = [r.get("ts") for r in rows if r.get("callable") == "vault_resume_context"]
    if len(resume_ts) <= iterations:
        return rows
    cutoff = resume_ts[-iterations]
    return [r for r in rows if (r.get("ts") or "") >= (cutoff or "")]


def _workspace_key(row: dict[str, Any]) -> str:
    workspace = row.get("workspace")
    if isinstance(workspace, str) and workspace.strip():
        return workspace.strip()
    log_path = row.get("_log_path")
    if isinstance(log_path, str) and log_path.strip():
        return f"log:{log_path.strip()}"
    return "unknown"


def _window_rows_by_workspace(
    rows: list[dict[str, Any]],
    iterations: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(_workspace_key(row), []).append(row)

    windowed_all: list[dict[str, Any]] = []
    breakdown: list[dict[str, Any]] = []
    for workspace in sorted(grouped):
        group = sorted(grouped[workspace], key=lambda r: r.get("ts") or "")
        windowed = _window_rows(group, iterations)
        windowed_all.extend(windowed)
        resume_total = sum(1 for row in group if row.get("callable") == "vault_resume_context")
        resume_window = sum(1 for row in windowed if row.get("callable") == "vault_resume_context")
        breakdown.append(
            {
                "workspace": workspace,
                "total_rows": len(group),
                "rows_in_window": len(windowed),
                "resume_rows_total": resume_total,
                "resume_rows_in_window": resume_window,
                "window_start_ts": windowed[0].get("ts") if windowed else None,
                "window_end_ts": windowed[-1].get("ts") if windowed else None,
                "log_paths": sorted(
                    {
                        str(row.get("_log_path"))
                        for row in group
                        if isinstance(row.get("_log_path"), str)
                    }
                ),
            }
        )
    windowed_all.sort(key=lambda r: r.get("ts") or "")
    return windowed_all, breakdown


def build_report(
    *,
    workspaces: list[str],
    workspace_globs: list[str] | None = None,
    extra_logs: list[str] | None = None,
    iterations: int = 7,
) -> dict[str, Any]:
    workspace_globs = workspace_globs or []
    extra_logs = extra_logs or []
    log_paths = _collect_logs(
        workspaces=workspaces,
        workspace_globs=workspace_globs,
        extra_logs=extra_logs,
    )
    rows = _read_rows(log_paths)
    windowed, workspace_breakdown = _window_rows_by_workspace(rows, iterations)
    counts: dict[str, int] = {name: 0 for name in TRACKED_CALLABLES}
    other_counts: dict[str, int] = {}
    for row in windowed:
        name = row.get("callable")
        if not isinstance(name, str):
            continue
        if name in counts:
            counts[name] += 1
        else:
            other_counts[name] = other_counts.get(name, 0) + 1
    low = sorted(
        n for n, c in counts.items() if 0 < c < LOW_ADOPTION_THRESHOLD
    )
    dead = sorted(n for n, c in counts.items() if c == 0)
    return OrderedDict(
        [
            ("schema", "auditooor.hackerman_capability_adoption.v1"),
            ("iterations_window", iterations),
            ("log_paths", [str(p) for p in log_paths]),
            ("total_rows", len(rows)),
            ("rows_in_window", len(windowed)),
            ("workspace_breakdown", workspace_breakdown),
            ("tracked_callable_count", len(TRACKED_CALLABLES)),
            ("counts", counts),
            ("other_counts", other_counts),
            ("observed_tracked_callables", sorted(n for n, c in counts.items() if c > 0)),
            ("untracked_vault_callables", sorted(n for n in other_counts if n.startswith("vault_"))),
            ("low_adoption", low),
            ("dead_adoption", dead),
        ]
    )


def render_text(report: dict[str, Any]) -> str:
    lines = [
        "=== hackerman-capability-adoption ===",
        f"iterations_window={report['iterations_window']}",
        f"log_paths={len(report['log_paths'])}",
    ]
    for path in report["log_paths"]:
        lines.append(f"  - {path}")
    lines.extend(
        [
            f"total_rows={report['total_rows']}",
            f"rows_in_window={report['rows_in_window']}",
            f"tracked_callable_count={report['tracked_callable_count']}",
            "",
            "Workspace windows:",
        ]
    )
    for item in report.get("workspace_breakdown", []):
        lines.append(
            "  {workspace}: rows={rows} window_rows={window_rows} "
            "resume={resume_window}/{resume_total} window={start}..{end}".format(
                workspace=item.get("workspace", ""),
                rows=item.get("total_rows", 0),
                window_rows=item.get("rows_in_window", 0),
                resume_window=item.get("resume_rows_in_window", 0),
                resume_total=item.get("resume_rows_total", 0),
                start=item.get("window_start_ts") or "(none)",
                end=item.get("window_end_ts") or "(none)",
            )
        )
    lines.extend(
        [
            "",
            "Tracked callable counts:",
        ]
    )
    for name in TRACKED_CALLABLES:
        count = report["counts"].get(name, 0)
        suffix = ""
        if count == 0:
            suffix = "  [DEAD_ADOPTION]"
        elif count < LOW_ADOPTION_THRESHOLD:
            suffix = "  [LOW_ADOPTION]"
        lines.append(f"  {name}: {count}{suffix}")
    if report["other_counts"]:
        lines.extend(["", "Other observed callables:"])
        for name in sorted(report["other_counts"]):
            lines.append(f"  {name}: {report['other_counts'][name]}")
    if report.get("untracked_vault_callables"):
        lines.extend(["", "Untracked vault callables observed:"])
        for name in report["untracked_vault_callables"]:
            lines.append(f"  {name}: {report['other_counts'][name]}")
    lines.extend(
        [
            "",
            f"LOW_ADOPTION ({len(report['low_adoption'])}): {', '.join(report['low_adoption']) or '(none)'}",
            f"DEAD_ADOPTION ({len(report['dead_adoption'])}): {', '.join(report['dead_adoption']) or '(none)'}",
        ]
    )
    return "\n".join(lines) + "\n"


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--workspace",
        action="append",
        default=[],
        help="Absolute or ~-prefixed workspace path (repeatable).",
    )
    parser.add_argument(
        "--workspace-glob",
        action="append",
        default=[],
        help="Glob expanded to workspace paths (repeatable).",
    )
    parser.add_argument(
        "--extra-log",
        action="append",
        default=[],
        help="Direct path to an mcp_call_log.jsonl file (repeatable).",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=7,
        help="N hunt iterations of history to consider (default: 7).",
    )
    parser.add_argument("--format", choices=("text", "json"), default="text")
    return parser.parse_args(list(argv) if argv is not None else None)


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv)
    report = build_report(
        workspaces=args.workspace,
        workspace_globs=args.workspace_glob,
        extra_logs=args.extra_log,
        iterations=args.iterations,
    )
    if args.format == "json":
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print(render_text(report), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
