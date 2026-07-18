#!/usr/bin/env python3
"""Terminalize execution-manifest proof blockers without promoting proof.

This is the FI lane reducer: it consumes the current execution-proof command
manifest plus recent impact/live closeout ledgers and emits exact next-command
families for rows that are still blocked. A row is a closure candidate only
when a local ``poc_execution/**/execution_manifest.json`` records
``final_result=proved``, ``impact_assertion=exploit_impact``,
``evidence_class=executed_with_manifest``, and at least one structured passing
command.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))
from execution_manifest_proof import (  # noqa: E402
    command_evidence_counts,
    command_status_counts,
    is_strict_proved_execution_manifest,
    strict_terminal_blockers,
)


SCHEMA = "auditooor.execution_manifest_proof_blocker_lane.v1"
PROOF_BOUNDARY = (
    "This ledger terminalizes execution-manifest blockers. It does not promote "
    "severity, submission posture, or proof. Closure candidates require a "
    "poc_execution/**/execution_manifest.json with final_result=proved, "
    "impact_assertion=exploit_impact, evidence_class=executed_with_manifest, "
    "and at least one structured commands_attempted row with a non-empty "
    "command, status=pass, and exit_code=0."
)


def load_json(path: Path, *, required: bool = True) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        if required:
            raise SystemExit(f"[fi-execution] ERR missing input: {path}") from None
        return {}
    except json.JSONDecodeError as exc:
        raise SystemExit(f"[fi-execution] ERR invalid JSON in {path}: {exc}") from None


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def slug(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9_.-]+", "-", value)
    return value.strip("-") or "row"


def list_rows(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [row for row in value if isinstance(row, dict)]
    if not isinstance(value, dict):
        return []
    for key in ("rows", "terminal_blockers", "blocked_path_execution_rows", "reduced_rows"):
        rows = value.get(key)
        if isinstance(rows, list):
            return [row for row in rows if isinstance(row, dict)]
    return []


def route_family(candidate_id: str) -> str:
    parts = candidate_id.split("-")
    if len(parts) >= 3 and parts[0] == "imo":
        # imo-critical-access-control-01 -> access_control
        return "_".join(parts[2:-1]) or "impact_miss"
    return "execution_manifest"


def classify_manifest(path: Path, manifest: dict[str, Any], workspace: Path) -> dict[str, Any]:
    candidate_id = str(manifest.get("candidate_id") or path.parent.name)
    counts = command_evidence_counts(manifest)
    pass_count = counts["passing_command_count"]
    blockers = strict_terminal_blockers(manifest)
    final_result = str(manifest.get("final_result") or "missing")
    impact_assertion = str(manifest.get("impact_assertion") or "missing")
    evidence_class = str(manifest.get("evidence_class") or "missing")
    family = route_family(candidate_id)
    next_command = (
        f"make poc-execution-record WS={workspace} "
        f"BRIEF=.auditooor/impact_miss_harness_briefs/{candidate_id}.md "
        f"CANDIDATE_ID={candidate_id} CMD='<project-specific command proving {family} listed impact>' "
        "RESULT=proved IMPACT=exploit_impact"
    )
    return {
        "candidate_id": candidate_id,
        "path": str(path),
        "route_family": family,
        "final_result": final_result,
        "impact_assertion": impact_assertion,
        "evidence_class": evidence_class,
        "commands_attempted_count": counts["commands_attempted_count"],
        "structured_command_count": counts["structured_command_count"],
        "unstructured_command_count": counts["unstructured_command_count"],
        "command_with_text_count": counts["command_with_text_count"],
        "passing_command_count": pass_count,
        "missing_exit_code_count": counts["missing_exit_code_count"],
        "bool_exit_code_count": counts["bool_exit_code_count"],
        "command_status_counts": command_status_counts(manifest),
        "terminal_blockers": blockers,
        "next_command_family": "proved_poc_execution_manifest",
        "next_command": next_command,
        "closure_candidate": is_strict_proved_execution_manifest(manifest),
        "submit_ready": False,
        "promotion_allowed": False,
        "proof_boundary": PROOF_BOUNDARY,
    }


def classify_command_task(row: dict[str, Any], workspace: Path) -> dict[str, Any]:
    task_id = str(row.get("task_id") or "task")
    proof_kind = str(row.get("proof_kind") or "unknown")
    readiness = str(row.get("readiness") or "")
    blockers = list(row.get("safety_blocks") or [])
    placeholders = list(row.get("unresolved_placeholders") or [])
    if placeholders and "unresolved_placeholders" not in blockers:
        blockers.append("unresolved_placeholders")
    if readiness == "safe_to_execute":
        status = "safe_validator_already_executed_or_available"
    elif readiness == "needs_binding":
        status = "terminal_needs_concrete_binding"
    else:
        status = "terminal_manual_validation_required"
    return {
        "task_id": task_id,
        "proof_kind": proof_kind,
        "readiness": readiness,
        "status": status,
        "terminal_blockers": blockers,
        "unresolved_placeholders": placeholders,
        "binding_manifest_path": row.get("binding_manifest_path") or "",
        "outcome_manifest_path": row.get("outcome_manifest_path") or "",
        "next_command_family": proof_kind,
        "next_command": row.get("proof_recording_command_template")
        or (
            f"make poc-execution-record WS={workspace} BRIEF=<brief> "
            f"CANDIDATE_ID={task_id} CMD='<executed local command>' RESULT=needs_human IMPACT=unknown"
        ),
        "closure_candidate": False,
        "evidence_class": "scaffolded_unverified",
        "submit_ready": False,
        "promotion_allowed": False,
        "proof_boundary": PROOF_BOUNDARY,
    }


def summarize_input_counts(
    fm: dict[str, Any],
    ev: dict[str, Any],
    fg: dict[str, Any],
    poc_rows: list[dict[str, Any]],
    command_task_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    fm_counts = (fm.get("before_after_counts") or {}).get("execution_manifest_gate") or {}
    ev_counts = ev.get("before_after_counts") or {}
    fg_counts = fg.get("before_after_counts") or {}
    return {
        "fm_execution_manifest_gate": fm_counts,
        "ev_bridge_finalization": ev_counts,
        "fg_summary": fg_counts,
        "local_poc_execution_manifest_count": len(poc_rows),
        "local_command_task_count": len(command_task_rows),
    }


def build_payload(workspace: Path) -> dict[str, Any]:
    aud = workspace / ".auditooor"
    fm = load_json(aud / "pr560_worker_fm_execution_manifest_gate.json")
    command_manifest = load_json(aud / "execution_proof_command_manifest.json")
    ev = load_json(aud / "pr560_worker_ev_bridge_finalization_closure.json")
    fg = load_json(aud / "pr560_worker_fg_proof_live_closure.json")

    poc_rows = []
    for path in sorted((workspace / "poc_execution").glob("**/execution_manifest.json")):
        data = load_json(path)
        if isinstance(data, dict):
            poc_rows.append(classify_manifest(path, data, workspace))

    task_rows = [
        classify_command_task(row, workspace)
        for row in list_rows(command_manifest)
        if str(row.get("readiness") or "") != "safe_to_execute"
    ]

    closure_candidates = [row for row in poc_rows if row["closure_candidate"]]
    terminal_manifest_rows = [row for row in poc_rows if not row["closure_candidate"]]
    terminal_task_rows = [row for row in task_rows if not row["closure_candidate"]]

    family_counts = Counter(row["route_family"] for row in terminal_manifest_rows)
    blocker_counts = Counter(
        blocker
        for row in terminal_manifest_rows + terminal_task_rows
        for blocker in row.get("terminal_blockers", [])
    )
    task_family_counts = Counter(row["proof_kind"] for row in terminal_task_rows)
    next_command_families: dict[str, dict[str, Any]] = {}
    for row in terminal_manifest_rows:
        family = row["route_family"]
        next_command_families.setdefault(
            family,
            {
                "family": family,
                "row_count": 0,
                "next_command_template": row["next_command"],
                "status": "terminal_until_project_specific_command_proves_listed_impact",
            },
        )["row_count"] += 1
    for row in terminal_task_rows:
        family = f"task_{row['proof_kind']}"
        next_command_families.setdefault(
            family,
            {
                "family": family,
                "row_count": 0,
                "next_command_template": row["next_command"],
                "status": row["status"],
            },
        )["row_count"] += 1

    return {
        "schema": SCHEMA,
        "generated_at_unix": int(time.time()),
        "workspace": str(workspace),
        "inputs_consumed": {
            "fm": str(aud / "pr560_worker_fm_execution_manifest_gate.json"),
            "execution_proof_command_manifest": str(aud / "execution_proof_command_manifest.json"),
            "ev": str(aud / "pr560_worker_ev_bridge_finalization_closure.json"),
            "fg": str(aud / "pr560_worker_fg_proof_live_closure.json"),
        },
        "before_counts": summarize_input_counts(fm, ev, fg, poc_rows, list_rows(command_manifest)),
        "after_counts": {
            "poc_execution_manifest_count": len(poc_rows),
            "proved_exploit_impact_closure_candidates": len(closure_candidates),
            "terminal_poc_execution_manifest_blockers": len(terminal_manifest_rows),
            "terminal_command_task_blockers": len(terminal_task_rows),
            "route_family_counts": dict(sorted(family_counts.items())),
            "task_family_counts": dict(sorted(task_family_counts.items())),
            "terminal_blocker_counts": dict(sorted(blocker_counts.items())),
            "next_command_family_count": len(next_command_families),
        },
        "closure_candidates": closure_candidates,
        "terminal_poc_execution_manifest_blockers": terminal_manifest_rows,
        "terminal_command_task_blockers": terminal_task_rows,
        "terminal_next_command_families": sorted(next_command_families.values(), key=lambda r: r["family"]),
        "promotion_allowed": False,
        "submission_posture": "NOT_SUBMIT_READY",
        "proof_boundary": PROOF_BOUNDARY,
        "residual_blockers": (
            "No proved exploit-impact manifests were found unless closure_candidates is non-empty. "
            "Blocked-path rows require project-specific commands, source citations, and exact listed-impact assertions."
        ),
    }


def write_family_artifacts(payload: dict[str, Any], out_dir: Path) -> None:
    blocker_dir = out_dir / "execution_manifest_terminal_blockers_fi"
    candidate_dir = out_dir / "execution_manifest_closure_candidates_fi"
    by_family: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in payload["terminal_poc_execution_manifest_blockers"]:
        by_family[row["route_family"]].append(row)
    for row in payload["terminal_command_task_blockers"]:
        by_family[f"task_{row['proof_kind']}"].append(row)
    for family, rows in by_family.items():
        write_json(
            blocker_dir / f"{slug(family)}.json",
            {
                "schema": f"{SCHEMA}.terminal_family.v1",
                "family": family,
                "row_count": len(rows),
                "rows": rows,
                "promotion_allowed": False,
                "proof_boundary": PROOF_BOUNDARY,
            },
        )
    for row in payload["closure_candidates"]:
        write_json(candidate_dir / f"{slug(row['candidate_id'])}.json", row)


def render_markdown(payload: dict[str, Any]) -> str:
    after = payload["after_counts"]
    lines = [
        "# FI Execution Manifest Proof Blocker Lane",
        "",
        PROOF_BOUNDARY,
        "",
        "## Summary",
        "",
        f"- PoC execution manifests: `{after['poc_execution_manifest_count']}`",
        f"- Closure candidates: `{after['proved_exploit_impact_closure_candidates']}`",
        f"- Terminal PoC execution blockers: `{after['terminal_poc_execution_manifest_blockers']}`",
        f"- Terminal command-task blockers: `{after['terminal_command_task_blockers']}`",
        f"- Next-command families: `{after['next_command_family_count']}`",
        "",
        "## Blocker Counts",
        "",
    ]
    for key, value in after["terminal_blocker_counts"].items():
        lines.append(f"- `{key}`: `{value}`")
    lines.extend(["", "## Next Command Families", "", "| Family | Rows | Status |", "|---|---:|---|"])
    for row in payload["terminal_next_command_families"]:
        lines.append(f"| `{row['family']}` | `{row['row_count']}` | `{row['status']}` |")
    lines.extend(
        [
            "",
            "## Residual",
            "",
            payload["residual_blockers"],
        ]
    )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-md", type=Path)
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args(argv)

    workspace = args.workspace.expanduser().resolve()
    out_json = (args.out_json or workspace / ".auditooor" / "pr560_worker_fi_execution_manifest_blockers.json").resolve()
    out_md = (args.out_md or workspace / ".auditooor" / "pr560_worker_fi_execution_manifest_blockers.md").resolve()
    payload = build_payload(workspace)
    write_family_artifacts(payload, out_json.parent)
    write_json(out_json, payload)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text(render_markdown(payload), encoding="utf-8")
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    print(
        "[fi-execution] OK "
        f"manifests={payload['after_counts']['poc_execution_manifest_count']} "
        f"closures={payload['after_counts']['proved_exploit_impact_closure_candidates']} "
        f"terminal={payload['after_counts']['terminal_poc_execution_manifest_blockers']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
