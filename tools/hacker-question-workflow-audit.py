#!/usr/bin/env python3
"""Audit hacker-question obligation lifecycle evidence for one workspace."""
from __future__ import annotations

import argparse
import json
import re
import shlex
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.hacker_question_workflow_audit.v1"
OPEN_STATES = {"open"}
CLOSED_STATES = {"answered", "killed", "promoted_to_chain", "promoted_to_poc"}
KNOWN_STATES = OPEN_STATES | CLOSED_STATES
DRAFT_DIRS = ("staging", "paste_ready", "packaged", "held")
SEVERITY_ORDER = {"pass": 0, "warn": 1, "fail": 2}


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _status_max(statuses: list[str]) -> str:
    if not statuses:
        return "pass"
    return max(statuses, key=lambda item: SEVERITY_ORDER.get(item, 0))


def _rel(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return str(path)


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _read_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def obligations_path(workspace: Path) -> Path:
    return workspace / ".auditooor" / "hacker_question_obligations.jsonl"


def source_read_receipts_path(workspace: Path) -> Path:
    return workspace / ".auditooor" / "source_read_receipts.jsonl"


def load_obligations(workspace: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    path = obligations_path(workspace)
    rows: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    if not path.exists():
        return rows, errors
    for lineno, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as exc:
            errors.append({"line": lineno, "error": str(exc)})
            continue
        if isinstance(payload, dict):
            rows.append(payload)
        else:
            errors.append({"line": lineno, "error": "row is not a JSON object"})
    return rows, errors


def load_source_read_receipts(workspace: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    path = source_read_receipts_path(workspace)
    rows: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    if not path.exists():
        return rows, errors
    for lineno, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as exc:
            errors.append({"line": lineno, "error": str(exc)})
            continue
        if isinstance(payload, dict):
            rows.append(payload)
        else:
            errors.append({"line": lineno, "error": "row is not a JSON object"})
    return rows, errors


def _token_present(text: str, token: str) -> bool:
    token = str(token or "").strip()
    if not token:
        return False
    pattern = r"(?<![A-Za-z0-9_])" + re.escape(token) + r"(?![A-Za-z0-9_])"
    return re.search(pattern, text) is not None


def obligation_match_reasons(obligation: dict[str, Any], text: str) -> list[str]:
    reasons: list[str] = []
    obligation_id = str(obligation.get("obligation_id", "")).strip()
    if obligation_id and (f"obligation:{obligation_id}" in text or _token_present(text, obligation_id)):
        reasons.append("obligation_id")

    function_signature = str(obligation.get("function_signature", "")).strip()
    if function_signature and function_signature in text:
        reasons.append("function_signature")

    file_path = str(obligation.get("file", "")).strip()
    function_name = str(obligation.get("function_name", "")).strip()
    if file_path and function_name and file_path in text and _token_present(text, function_name):
        reasons.append("file_and_function_name")
    return reasons


def discover_drafts(workspace: Path) -> list[Path]:
    submissions = workspace / "submissions"
    drafts: list[Path] = []
    for dirname in DRAFT_DIRS:
        root = submissions / dirname
        if root.is_dir():
            drafts.extend(path for path in root.rglob("*.md") if path.is_file())
    return sorted({path.resolve() for path in drafts})


def match_open_obligations_to_drafts(workspace: Path, obligations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    open_rows = [row for row in obligations if row.get("state") in OPEN_STATES]
    matches: list[dict[str, Any]] = []
    for draft in discover_drafts(workspace):
        try:
            text = _read_text(draft)
        except OSError as exc:
            matches.append(
                {
                    "draft_ref": _rel(draft, workspace),
                    "status": "error",
                    "error": str(exc),
                    "obligations": [],
                }
            )
            continue
        draft_matches: list[dict[str, Any]] = []
        for row in open_rows:
            reasons = obligation_match_reasons(row, text)
            if not reasons:
                continue
            draft_matches.append(
                {
                    "obligation_id": str(row.get("obligation_id", "")),
                    "state": str(row.get("state", "")),
                    "file": str(row.get("file", "")),
                    "function_name": str(row.get("function_name", "")),
                    "function_signature": str(row.get("function_signature", "")),
                    "attack_class": str(row.get("attack_class", "")),
                    "question": str(row.get("question", ""))[:240],
                    "match_reasons": reasons,
                }
            )
        if draft_matches:
            matches.append(
                {
                    "draft_ref": _rel(draft, workspace),
                    "status": "matched_open_obligation",
                    "obligations": draft_matches,
                }
            )
    return matches


def _extract_tasks(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    for key in ("tasks", "rows", "ranked_queue"):
        rows = payload.get(key)
        if isinstance(rows, list):
            return [row for row in rows if isinstance(row, dict)]
    sections = payload.get("sections")
    if isinstance(sections, dict):
        out: list[dict[str, Any]] = []
        for section in sections.values():
            if isinstance(section, dict) and isinstance(section.get("rows"), list):
                out.extend(row for row in section["rows"] if isinstance(row, dict))
        return out
    return []


def audit_proof_queues(workspace: Path, obligations: list[dict[str, Any]]) -> dict[str, Any]:
    queue_paths = [
        workspace / ".auditooor" / "proof_obligation_queue.json",
        workspace / ".auditooor" / "detector_proof_gap_queue.json",
    ]
    open_rows = [row for row in obligations if row.get("state") in OPEN_STATES]
    queues: list[dict[str, Any]] = []
    matched_ids: set[str] = set()
    errors: list[dict[str, str]] = []

    for path in queue_paths:
        if not path.exists():
            queues.append({"path": _rel(path, workspace), "exists": False, "task_count": 0})
            continue
        try:
            payload = _read_json(path)
        except (OSError, json.JSONDecodeError) as exc:
            errors.append({"path": _rel(path, workspace), "error": str(exc)})
            queues.append({"path": _rel(path, workspace), "exists": True, "task_count": 0, "parse_error": str(exc)})
            continue
        tasks = _extract_tasks(payload)
        queue_blob_by_task = [json.dumps(task, sort_keys=True, ensure_ascii=True) for task in tasks]
        for row in open_rows:
            oid = str(row.get("obligation_id", "")).strip()
            question = str(row.get("question", "")).strip()
            file_path = str(row.get("file", "")).strip()
            function_name = str(row.get("function_name", "")).strip()
            for blob in queue_blob_by_task:
                if oid and oid in blob:
                    matched_ids.add(oid)
                elif question and question in blob:
                    matched_ids.add(oid)
                elif file_path and function_name and file_path in blob and function_name in blob:
                    matched_ids.add(oid)
        queues.append(
            {
                "path": _rel(path, workspace),
                "exists": True,
                "schema": str(payload.get("schema", "")) if isinstance(payload, dict) else "",
                "task_count": len(tasks),
            }
        )

    existing_task_count = sum(int(row.get("task_count", 0)) for row in queues if row.get("exists"))
    missing_open = [
        str(row.get("obligation_id", ""))
        for row in open_rows
        if str(row.get("obligation_id", "")) not in matched_ids
    ]
    if errors:
        status = "fail"
        summary = "one or more proof queues could not be parsed"
    elif open_rows and existing_task_count == 0:
        status = "warn"
        summary = "open obligations exist but no proof queue tasks were found"
    elif open_rows and missing_open:
        status = "warn"
        summary = "some open obligations were not found in proof queue task text"
    else:
        status = "pass"
        summary = "proof queue evidence is present or no open obligations require queueing"

    return {
        "status": status,
        "summary": summary,
        "queues": queues,
        "matched_open_obligation_ids": sorted(matched_ids),
        "open_obligation_ids_missing_from_queues": missing_open,
        "errors": errors,
    }


def _find_line(text: str, needle: str) -> int | None:
    for index, line in enumerate(text.splitlines(), 1):
        if needle in line:
            return index
    return None


def audit_gate_references(repo_root: Path) -> dict[str, Any]:
    makefile = repo_root / "Makefile"
    pre_submit = repo_root / "tools" / "pre-submit-check.sh"
    evidence: dict[str, Any] = {
        "makefile": {"path": str(makefile), "exists": makefile.exists(), "checks": {}},
        "pre_submit": {"path": str(pre_submit), "exists": pre_submit.exists(), "checks": {}},
    }

    if makefile.exists():
        text = _read_text(makefile)
        checks = {
            "proof_obligation_queue_target": _find_line(text, "proof-obligation-queue:"),
            "proof_obligation_queue_tool": _find_line(text, "tools/proof-obligation-queue.py"),
            "pre_submit_reference": _find_line(text, "tools/pre-submit-check.sh"),
        }
        evidence["makefile"]["checks"] = {
            key: {"present": value is not None, "line": value} for key, value in checks.items()
        }

    if pre_submit.exists():
        text = _read_text(pre_submit)
        checks = {
            "hacker_question_gate_label": _find_line(text, "HACKER-QUESTION-ANSWERS"),
            "obligation_tool_reference": _find_line(text, "hacker-question-obligations.py"),
            "gate_draft_call": _find_line(text, "gate-draft"),
        }
        evidence["pre_submit"]["checks"] = {
            key: {"present": value is not None, "line": value} for key, value in checks.items()
        }

    missing: list[str] = []
    for group, payload in evidence.items():
        if not payload.get("exists"):
            missing.append(group)
            continue
        for key, check in payload.get("checks", {}).items():
            if not check.get("present"):
                missing.append(f"{group}.{key}")
    status = "pass" if not missing else "fail"
    return {
        "status": status,
        "summary": "Makefile and pre-submit gate references are present" if status == "pass" else "missing workflow gate references",
        "missing": missing,
        "evidence": evidence,
    }


def source_read_receipt_summary(
    workspace: Path,
    rows: list[dict[str, Any]],
    errors: list[dict[str, Any]],
) -> dict[str, Any]:
    question_total = sum(int(row.get("hacker_question_count", 0) or 0) for row in rows)
    hypothesis_total = sum(int(row.get("corpus_backed_hypothesis_count", 0) or 0) for row in rows)
    zero_question_rows = [row for row in rows if int(row.get("hacker_question_count", 0) or 0) == 0]
    skipped_hist: dict[str, int] = {}
    for row in rows:
        for reason in row.get("skipped_reasons") or []:
            key = str(reason)
            skipped_hist[key] = skipped_hist.get(key, 0) + 1
        no_reason = str(row.get("no_questions_reason", "")).strip()
        if no_reason:
            skipped_hist[no_reason] = skipped_hist.get(no_reason, 0) + 1
    if errors:
        status = "fail"
        summary = "source_read_receipts.jsonl has parse errors"
    else:
        status = "pass"
        summary = "source-read receipts are present" if rows else "source_read_receipts.jsonl is missing or empty"
    return {
        "status": status,
        "summary": summary,
        "path": _rel(source_read_receipts_path(workspace), workspace),
        "exists": source_read_receipts_path(workspace).exists(),
        "total": len(rows),
        "hacker_question_count": question_total,
        "corpus_backed_hypothesis_count": hypothesis_total,
        "zero_question_receipts": len(zero_question_rows),
        "skipped_reason_histogram": skipped_hist,
        "parse_errors": errors,
        "recent": [
            {
                "receipt_id": str(row.get("receipt_id", "")),
                "file": str(row.get("file", "")),
                "language": str(row.get("language", "")),
                "functions_analyzed": int(row.get("functions_analyzed", 0) or 0),
                "hacker_question_count": int(row.get("hacker_question_count", 0) or 0),
                "corpus_backed_hypothesis_count": int(
                    row.get("corpus_backed_hypothesis_count", 0) or 0
                ),
                "no_questions_reason": str(row.get("no_questions_reason", "")),
            }
            for row in rows[-8:]
        ],
    }


def obligation_summary(
    workspace: Path,
    rows: list[dict[str, Any]],
    errors: list[dict[str, Any]],
    receipt_check: dict[str, Any] | None = None,
) -> dict[str, Any]:
    by_state: dict[str, int] = {}
    for row in rows:
        state = str(row.get("state", "missing"))
        by_state[state] = by_state.get(state, 0) + 1
    open_rows = [row for row in rows if row.get("state") in OPEN_STATES]
    closed_rows = [row for row in rows if row.get("state") in CLOSED_STATES]
    unknown_rows = [row for row in rows if row.get("state") not in KNOWN_STATES]

    if errors:
        status = "fail"
        summary = "obligation JSONL has parse errors"
    elif (not obligations_path(workspace).exists() or not rows) and receipt_check and receipt_check.get("total", 0) > 0:
        status = "pass"
        summary = "no open obligations, but source-read receipts prove the injector ran"
    elif not obligations_path(workspace).exists():
        status = "fail"
        summary = "hacker_question_obligations.jsonl is missing"
    elif not rows:
        status = "fail"
        summary = "hacker_question_obligations.jsonl has no obligation rows"
    elif unknown_rows:
        status = "fail"
        summary = "one or more obligations use an unknown state"
    elif open_rows:
        status = "warn"
        summary = "open hacker-question obligations remain"
    else:
        status = "pass"
        summary = "all hacker-question obligations are closed"

    return {
        "status": status,
        "summary": summary,
        "path": _rel(obligations_path(workspace), workspace),
        "exists": obligations_path(workspace).exists(),
        "total": len(rows),
        "by_state": by_state,
        "open": [
            {
                "obligation_id": str(row.get("obligation_id", "")),
                "file": str(row.get("file", "")),
                "function_name": str(row.get("function_name", "")),
                "attack_class": str(row.get("attack_class", "")),
                "question": str(row.get("question", ""))[:240],
                "local_verification_cmd": str(row.get("local_verification_cmd", "")),
            }
            for row in open_rows
        ],
        "closed_ids": [str(row.get("obligation_id", "")) for row in closed_rows],
        "unknown_state_ids": [str(row.get("obligation_id", "")) for row in unknown_rows],
        "parse_errors": errors,
    }


def build_next_commands(
    workspace: Path,
    obligation_check: dict[str, Any],
    proof_queue_check: dict[str, Any],
    draft_matches: list[dict[str, Any]],
    receipt_check: dict[str, Any] | None = None,
) -> list[str]:
    commands: list[str] = []
    ws = shlex.quote(str(workspace))
    receipt_total = int((receipt_check or {}).get("total", 0) or 0)
    if receipt_total == 0 and (not obligation_check.get("exists") or obligation_check.get("total") == 0):
        commands.append(
            f"python3 tools/hacker-question-obligations.py --json ingest-injection {ws} '<pre_source_read_injection_json>'"
        )
    for row in obligation_check.get("open", [])[:8]:
        oid = row.get("obligation_id")
        if oid:
            commands.append(
                f"python3 tools/hacker-question-obligations.py update {ws} {oid} --state answered --notes '<answer/kill/promote evidence>'"
            )
    for match in draft_matches[:8]:
        draft_path = workspace / str(match.get("draft_ref", ""))
        draft_arg = shlex.quote(str(draft_path))
        commands.append(f"python3 tools/hacker-question-obligations.py --json gate-draft {ws} {draft_arg}")
        commands.append(f"bash tools/pre-submit-check.sh {draft_arg}")
    if proof_queue_check.get("status") != "pass":
        commands.append(f"make proof-obligation-queue WS={ws} PRINT_JSON=1")

    deduped: list[str] = []
    seen: set[str] = set()
    for command in commands:
        if command in seen:
            continue
        seen.add(command)
        deduped.append(command)
    return deduped


def audit_workspace(workspace: Path, *, repo_root: Path | None = None) -> dict[str, Any]:
    workspace = workspace.expanduser().resolve()
    repo_root = (repo_root or Path(__file__).resolve().parents[1]).expanduser().resolve()
    rows, errors = load_obligations(workspace)
    receipt_rows, receipt_errors = load_source_read_receipts(workspace)
    receipt_check = source_read_receipt_summary(workspace, receipt_rows, receipt_errors)
    obligation_check = obligation_summary(workspace, rows, errors, receipt_check)
    draft_matches = match_open_obligations_to_drafts(workspace, rows)
    draft_status = "fail" if draft_matches else "pass"
    proof_queue_check = audit_proof_queues(workspace, rows)
    gate_check = audit_gate_references(repo_root)
    next_commands = build_next_commands(
        workspace,
        obligation_check,
        proof_queue_check,
        draft_matches,
        receipt_check,
    )

    checks = {
        "obligations": obligation_check,
        "staged_drafts": {
            "status": draft_status,
            "summary": (
                "staged drafts match open obligations"
                if draft_matches
                else "no staged draft matched an open obligation"
            ),
            "draft_count": len(discover_drafts(workspace)),
            "matching_drafts": draft_matches,
        },
        "proof_queues": proof_queue_check,
        "gate_references": gate_check,
        "source_read_receipts": receipt_check,
    }
    status = _status_max([str(check.get("status", "pass")) for check in checks.values()])
    return {
        "schema": SCHEMA,
        "generated_at_utc": _utc_now(),
        "workspace": str(workspace),
        "repo_root": str(repo_root),
        "status": status,
        "summary": {
            "total_obligations": obligation_check["total"],
            "open_obligations": len(obligation_check["open"]),
            "closed_obligations": len(obligation_check["closed_ids"]),
            "source_read_receipts": receipt_check["total"],
            "hacker_question_count": receipt_check["hacker_question_count"],
            "corpus_backed_hypothesis_count": receipt_check["corpus_backed_hypothesis_count"],
            "matching_drafts": len(draft_matches),
            "proof_queue_status": proof_queue_check["status"],
            "gate_reference_status": gate_check["status"],
        },
        "checks": checks,
        "next_commands": next_commands,
        "advisory_boundary": (
            "This audits local lifecycle and gate evidence only; it does not prove exploitability, "
            "submission readiness, originality, or external platform state."
        ),
    }


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Hacker Question Workflow Audit",
        "",
        f"- Status: **{payload['status']}**",
        f"- Workspace: `{payload['workspace']}`",
        f"- Obligations: {payload['summary']['total_obligations']} total / {payload['summary']['open_obligations']} open / {payload['summary']['closed_obligations']} closed",
        f"- Source-read receipts: {payload['summary'].get('source_read_receipts', 0)} receipts / {payload['summary'].get('hacker_question_count', 0)} hacker questions / {payload['summary'].get('corpus_backed_hypothesis_count', 0)} corpus-backed hypotheses",
        f"- Matching staged drafts: {payload['summary']['matching_drafts']}",
        f"- Proof queues: {payload['summary']['proof_queue_status']}",
        f"- Gate references: {payload['summary']['gate_reference_status']}",
        "",
        "## Checks",
    ]
    for name, check in payload["checks"].items():
        lines.append(f"- `{name}`: **{check.get('status', 'pass')}** - {check.get('summary', '')}")
    if payload.get("next_commands"):
        lines.extend(["", "## Next Commands"])
        lines.extend(f"- `{command}`" for command in payload["next_commands"])
    return "\n".join(lines) + "\n"


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, help="Workspace root to audit")
    parser.add_argument(
        "--repo-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Repo root containing Makefile and tools/pre-submit-check.sh",
    )
    parser.add_argument(
        "--format",
        choices=("json", "markdown"),
        default="json",
        help="Output format",
    )
    parser.add_argument("--markdown", action="store_true", help="Alias for --format markdown")
    parser.add_argument("--strict", action="store_true", help="Exit nonzero on warn status as well as fail.")
    return parser.parse_args(argv)


def run(argv: list[str] | None = None) -> dict[str, Any]:
    args = _parse_args(argv)
    return audit_workspace(Path(args.workspace), repo_root=Path(args.repo_root))


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    payload = audit_workspace(Path(args.workspace), repo_root=Path(args.repo_root))
    output_format = "markdown" if args.markdown else args.format
    if output_format == "markdown":
        sys.stdout.write(render_markdown(payload))
    else:
        print(json.dumps(payload, indent=2, sort_keys=True))
    status = str(payload.get("status", "fail"))
    if status == "fail" or (args.strict and status == "warn"):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
