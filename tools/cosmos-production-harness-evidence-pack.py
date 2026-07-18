#!/usr/bin/env python3
"""Build a triager-facing evidence pack from a Cosmos harness execution record.

This is a bridge from ``cosmos-production-harness-exec.py`` output to the exact
questions triagers ask for Cosmos / dYdX HIGH+ claims. It does not execute a
PoC and it does not upgrade self-reported runtime markers into independent
proof. It makes missing proof obligations explicit and produces a compact JSON
and optional Markdown checklist.

Exit codes:
  0 - evidence pack built and all required checklist rows are satisfied
  1 - evidence pack built but required rows are missing/failed
  2 - input error
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.cosmos_production_harness_evidence_pack.v1"
TOOL = "cosmos-production-harness-evidence-pack"
RUNTIME_EVENT_SCHEMA = "auditooor.cosmos_production_harness_runtime_event.v1"
BOUNDARY = (
    "Evidence-pack bridge only. Passing rows mean the execution record and "
    "runtime-marker transcript contain the required observations; this is not "
    "independent exploit proof or submission-ready evidence by itself."
)


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _read_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"JSON object expected: {path}")
    return payload


def _load_runtime_events(exec_record: dict[str, Any]) -> tuple[list[dict[str, Any]], str, str]:
    guard = exec_record.get("runtime_observation_guard") or {}
    events_path_value = str(guard.get("events_path") or "")
    if not events_path_value:
        return [], "", ""
    events_path = Path(events_path_value).expanduser().resolve()
    if not events_path.is_file():
        return [], str(events_path), ""
    events_payload = _read_json(events_path)
    events = events_payload.get("events") or []
    if not isinstance(events, list):
        events = []
    return [event for event in events if isinstance(event, dict)], str(events_path), _sha256_file(events_path)


def _event_by_name(events: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for event in events:
        name = str(event.get("event") or "")
        if name and event.get("schema") == RUNTIME_EVENT_SCHEMA and name not in out:
            out[name] = event
    return out


def _path_status(path_value: Any) -> dict[str, Any]:
    path = Path(str(path_value or "")).expanduser()
    if not str(path_value or "").strip():
        return {"path": "", "exists": False, "sha256": ""}
    resolved = path.resolve()
    return {
        "path": str(resolved),
        "exists": resolved.is_file(),
        "sha256": _sha256_file(resolved) if resolved.is_file() else "",
    }


def _row(row_id: str, status: str, summary: str, evidence: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "id": row_id,
        "status": status,
        "summary": summary,
        "evidence": evidence or {},
    }


def build_evidence_pack(exec_record_path: Path) -> tuple[dict[str, Any], int]:
    exec_record_path = exec_record_path.expanduser().resolve()
    if not exec_record_path.is_file():
        raise ValueError(f"exec-record not found: {exec_record_path}")
    exec_record = _read_json(exec_record_path)
    events, events_path, events_sha = _load_runtime_events(exec_record)
    events_by_name = _event_by_name(events)

    preflight = exec_record.get("preflight") or {}
    execution = exec_record.get("execution") or {}
    guard = exec_record.get("runtime_observation_guard") or {}
    network_required = "network_profile" in (guard.get("required_events") or [])

    stdout = _path_status(execution.get("stdout_path"))
    stderr = _path_status(execution.get("stderr_path"))
    exact_meta_ok = bool(
        exec_record.get("workspace_commit")
        and execution.get("command")
        and execution.get("cwd")
        and stdout["exists"]
        and stderr["exists"]
    )

    app_profile = events_by_name.get("app_profile") or {}
    block_execution = events_by_name.get("block_execution") or {}
    restart_check = events_by_name.get("restart_check") or {}
    impact_assertion = events_by_name.get("impact_assertion") or {}
    network_profile = events_by_name.get("network_profile") or {}

    rows = [
        _row(
            "real_backend",
            "pass" if app_profile.get("db_backend") and str(app_profile.get("db_backend")).lower() in {"goleveldb", "pebbledb", "leveldb"} else "missing",
            "Runtime marker identifies a persistent DB backend (GoLevelDB/PebbleDB).",
            {"db_backend": app_profile.get("db_backend"), "data_dir": app_profile.get("data_dir")},
        ),
        _row(
            "no_private_state_injection",
            "pass" if app_profile.get("private_state_injection") is False and preflight.get("phase_a_ready") else "missing",
            "Preflight passed and runtime marker states private_state_injection=false.",
            {
                "phase_a_ready": preflight.get("phase_a_ready"),
                "private_state_injection": app_profile.get("private_state_injection"),
            },
        ),
        _row(
            "real_block_execution_path",
            "pass" if block_execution.get("finalize_block") and block_execution.get("commit") else "missing",
            "Runtime marker records FinalizeBlock followed by Commit.",
            {
                "height": block_execution.get("height"),
                "finalize_block": block_execution.get("finalize_block"),
                "commit": block_execution.get("commit"),
                "app_hash": block_execution.get("app_hash") or block_execution.get("app_hash_after"),
            },
        ),
        _row(
            "restart_behavior",
            "pass" if restart_check.get("restarted") and restart_check.get("same_data_dir") else "missing",
            "Runtime marker records close/reopen from the same data dir.",
            {
                "restarted": restart_check.get("restarted"),
                "same_data_dir": restart_check.get("same_data_dir"),
                "assertion": restart_check.get("post_restart_assertion") or restart_check.get("assertion"),
            },
        ),
        _row(
            "impact_assertion",
            "pass" if impact_assertion.get("assertion") and impact_assertion.get("observed") else "missing",
            "Runtime marker includes the candidate-specific impact assertion and observed result.",
            {"assertion": impact_assertion.get("assertion"), "observed": impact_assertion.get("observed")},
        ),
        _row(
            "multi_validator_liveness",
            "pass"
            if network_required and int(network_profile.get("validator_count") or network_profile.get("validators") or 0) >= 2
            else ("not_applicable" if not network_required else "missing"),
            "Network-level claims require a >=2-validator network_profile marker.",
            {
                "network_required": network_required,
                "validator_count": network_profile.get("validator_count") or network_profile.get("validators"),
            },
        ),
        _row(
            "exact_repro_metadata",
            "pass" if exact_meta_ok else "missing",
            "Execution record includes commit, command, cwd, stdout, stderr, and log hashes.",
            {
                "workspace_commit": exec_record.get("workspace_commit"),
                "command": execution.get("command"),
                "cwd": execution.get("cwd"),
                "stdout": stdout,
                "stderr": stderr,
            },
        ),
        _row(
            "runtime_guard",
            "pass" if guard.get("status") == "pass" and execution.get("status") == "pass" else "missing",
            "Execution passed and runtime-marker guard passed.",
            {"execution_status": execution.get("status"), "runtime_guard_status": guard.get("status")},
        ),
    ]
    required_failed = [row for row in rows if row["status"] not in {"pass", "not_applicable"}]
    verdict = "complete_runtime_marker_pack" if not required_failed else "incomplete"
    exit_code = 0 if verdict == "complete_runtime_marker_pack" else 1

    pack = {
        "schema": SCHEMA,
        "tool": TOOL,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "exec_record": {"path": str(exec_record_path), "sha256": _sha256_file(exec_record_path)},
        "candidate_id": exec_record.get("candidate_id", ""),
        "workspace": exec_record.get("workspace", ""),
        "workspace_commit": exec_record.get("workspace_commit", ""),
        "runtime_events": {"path": events_path, "sha256": events_sha, "events_seen": sorted(events_by_name)},
        "verdict": verdict,
        "failed_required_rows": [row["id"] for row in required_failed],
        "triager_rows": rows,
        "runtime_proof_claimed": False,
        "advisory_boundary": BOUNDARY,
    }
    return pack, exit_code


def render_markdown(pack: dict[str, Any]) -> str:
    lines = [
        f"# Cosmos Production Harness Evidence Pack - {pack.get('candidate_id') or 'candidate'}",
        "",
        f"- Verdict: `{pack['verdict']}`",
        f"- Runtime proof claimed: `{str(pack['runtime_proof_claimed']).lower()}`",
        f"- Workspace commit: `{pack.get('workspace_commit') or 'missing'}`",
        f"- Exec record: `{pack['exec_record']['path']}`",
        "",
        "## Triager Ask Matrix",
        "",
        "| Ask | Status | Evidence |",
        "| --- | --- | --- |",
    ]
    for row in pack["triager_rows"]:
        evidence = json.dumps(row.get("evidence") or {}, sort_keys=True)
        if len(evidence) > 180:
            evidence = evidence[:177] + "..."
        lines.append(f"| `{row['id']}` | `{row['status']}` | {evidence} |")
    lines.extend(["", f"Boundary: {pack['advisory_boundary']}", ""])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exec-record", required=True, type=Path)
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-md", type=Path)
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args(argv)

    try:
        pack, code = build_evidence_pack(args.exec_record)
    except Exception as exc:
        print(json.dumps({"schema": SCHEMA, "tool": TOOL, "error": str(exc)}, indent=2), file=sys.stderr)
        return 2

    if args.out_json:
        args.out_json.expanduser().resolve().write_text(json.dumps(pack, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.out_md:
        args.out_md.expanduser().resolve().write_text(render_markdown(pack), encoding="utf-8")
    if args.print_json:
        print(json.dumps(pack, indent=2, sort_keys=True))
    else:
        print(f"[{TOOL}] verdict={pack['verdict']} failed={','.join(pack['failed_required_rows']) or 'none'}")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
