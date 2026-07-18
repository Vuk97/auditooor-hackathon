#!/usr/bin/env python3
"""Validate the PR hygiene memory-gate block in a PR body markdown file.

The gate is advisory by default: missing or weak fields are reported in JSON
but exit 0. Pass ``--strict`` to exit 1 when the PR hygiene block is missing or
incomplete.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.pr_hygiene_check.v1"

FIELD_LABELS = {
    "changed_file_scope.exact_file_list": "exact file list",
    "changed_file_scope.review_slice_reason": "why these files belong in one slice",
    "checks.exact_commands": "exact commands",
    "checks.result": "result",
    "mcp_context.context_pack_id": "context_pack_id",
    "mcp_context.context_pack_hash": "context_pack_hash",
    "mcp_context.source_refs": "source_refs",
    "mcp_context.receipt_proof": "receipt_proof",
    "generated_file_exclusion.excluded_paths_patterns": "excluded paths/patterns",
    "generated_file_exclusion.confirmation": "confirmation",
}

PLACEHOLDERS = {
    "",
    "-",
    "n/a",
    "na",
    "none",
    "null",
    "tbd",
    "todo",
    "unknown",
    "fill me",
    "fill in",
}
SHORTHAND_CHECKS = {
    "tests pass",
    "tests passed",
    "usual checks",
    "standard checks",
    "ci",
    "pass",
    "passed",
}
PATH_TOKEN_RE = re.compile(r"`([^`]+)`|(?:^|[\s,])([A-Za-z0-9_.@+-]+(?:/[A-Za-z0-9_.@+*{}-]+)+)")
WORKFLOW_PATH_EXACT = {
    "docs/PR_HYGIENE_MEMORY_GATE_2026-05-06.md",
    "docs/WORKFLOW_ENFORCEMENT_ALWAYS_ON.md",
    "tools/batch-boundary-preflight.py",
    "tools/model-takeover-handoff.py",
    "tools/pr-hygiene-check.py",
    "tools/vault-mcp-server.py",
    "tools/workpack-validator.py",
    "tools/control/handoff.py",
    "tools/control/workpacks.py",
}
WORKFLOW_PATH_RE = re.compile(
    r"(^|/)(?:\.github/workflows/|[^/]*(?:workflow|workpack|handoff|pr[-_]hygiene|memory[-_]context|mcp)[^/]*)",
    re.IGNORECASE,
)
MCP_WORKFLOW_CLAIM_RE = re.compile(
    r"\b(?:"
    r"mcp[-_\s]+backed|"
    r"mcp[-_\s]+workflow|"
    r"mcp[-_\s]+resume[-_\s]+context|"
    r"vault[-_\s]+mcp[-_\s]+context|"
    r"vault_(?:resume|exploit|harness|knowledge_gap)_context"
    r")\b|--call\s+vault_(?:resume|exploit|harness|knowledge_gap)_context\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class CheckResult:
    id: str
    status: str
    message: str
    evidence: dict[str, Any]


def _normalize_label(label: str) -> str:
    return re.sub(r"\s+", " ", label.strip().lower())


def _strip_markup(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == "`" and value[-1] == "`":
        return value[1:-1].strip()
    return value


def _is_placeholder(value: str | None) -> bool:
    if value is None:
        return True
    normalized = _strip_markup(value).strip().lower()
    return normalized in PLACEHOLDERS


def _extract_pr_hygiene_block(text: str) -> tuple[list[str], int | None]:
    lines = text.splitlines()
    start = None
    for idx, line in enumerate(lines):
        if re.match(r"^##\s+PR Hygiene\s*$", line):
            start = idx
            break
    if start is None:
        return [], None

    end = len(lines)
    for idx in range(start + 1, len(lines)):
        if re.match(r"^##\s+\S", lines[idx]):
            end = idx
            break
    return lines[start:end], start + 1


def _extract_fields(block_lines: list[str]) -> dict[str, str]:
    by_label: dict[str, str] = {}
    bullet_re = re.compile(r"^\s*-\s+([^:]+):\s*(.*)$")
    for line in block_lines:
        match = bullet_re.match(line)
        if not match:
            continue
        by_label[_normalize_label(match.group(1))] = match.group(2).strip()

    fields: dict[str, str] = {}
    for field_id, label in FIELD_LABELS.items():
        normalized = _normalize_label(label)
        if normalized in by_label:
            fields[field_id] = by_label[normalized]
    return fields


def _path_tokens(value: str) -> list[str]:
    tokens: list[str] = []
    for match in PATH_TOKEN_RE.finditer(value):
        token = match.group(1) or match.group(2) or ""
        token = token.strip().strip(".,;")
        if token:
            tokens.append(token)
    return tokens


def _has_exact_file_list(value: str | None) -> tuple[bool, list[str]]:
    if _is_placeholder(value):
        return False, []
    assert value is not None
    tokens = _path_tokens(value)
    exact_tokens = [
        token
        for token in tokens
        if not token.endswith("/")
        and "*" not in token
        and "{" not in token
        and "}" not in token
        and Path(token).suffix
    ]
    return bool(exact_tokens), exact_tokens


def _workflow_affecting_paths(paths: list[str]) -> list[str]:
    return [
        path
        for path in paths
        if path in WORKFLOW_PATH_EXACT or WORKFLOW_PATH_RE.search(path)
    ]


def _has_exact_commands(value: str | None) -> bool:
    if _is_placeholder(value):
        return False
    assert value is not None
    normalized = _strip_markup(value).strip().lower()
    if normalized in SHORTHAND_CHECKS:
        return False
    if "usual" in normalized or "standard checks" in normalized:
        return False
    return True


def _has_command_with(value: str, required: tuple[str, ...]) -> bool:
    normalized = _strip_markup(value).replace("`", "").lower()
    segments = [segment.strip() for segment in re.split(r"[;\n]", normalized)]
    return any(
        all(token.lower() in segment for token in required)
        for segment in segments
        if segment
    )


def _workflow_gate_command_gaps(commands: str | None, workflow_paths: list[str]) -> list[str]:
    if _is_placeholder(commands):
        gaps = ["strict PR hygiene gate", "MCP/context gate"]
        if any("workpack" in path.lower() for path in workflow_paths):
            gaps.append("workpack validation gate")
        return gaps
    assert commands is not None
    gaps: list[str] = []
    has_pr_gate = (
        _has_command_with(commands, ("python3 tools/pr-hygiene-check.py", "--strict"))
        or _has_command_with(commands, ("python3 tools/batch-boundary-preflight.py", "--pr-strict"))
    )
    if not has_pr_gate:
        gaps.append("strict PR hygiene gate")

    has_context_gate = (
        _has_command_with(
            commands,
            (
                "python3 tools/memory-context-load.py",
                "--check",
                "--strict",
                "--require-proof",
            ),
        )
        or _has_command_with(commands, ("python3 tools/vault-mcp-server.py", "--self-test"))
        or _has_command_with(
            commands,
            ("python3 tools/memory-context-parity-check.py", "--strict"),
        )
    )
    if not has_context_gate:
        gaps.append("MCP/context gate")

    if any("workpack" in path.lower() for path in workflow_paths) and not _has_command_with(
        commands,
        ("python3 tools/workpack-validator.py",),
    ):
        gaps.append("workpack validation gate")
    return gaps


def _workflow_context_evidence_gaps(fields: dict[str, str]) -> list[str]:
    gaps: list[str] = []
    source_refs = fields.get("mcp_context.source_refs")
    pack_id = fields.get("mcp_context.context_pack_id")
    pack_hash = fields.get("mcp_context.context_pack_hash")
    receipt_proof = fields.get("mcp_context.receipt_proof")

    if _is_placeholder(source_refs):
        gaps.append("source_refs")
    if (_is_placeholder(pack_id) or _is_placeholder(pack_hash)) and _is_placeholder(receipt_proof):
        gaps.append("context_pack_id/context_pack_hash or receipt_proof")
    return gaps


def _has_context_pack_source_evidence(fields: dict[str, str]) -> bool:
    return (
        not _is_placeholder(fields.get("mcp_context.context_pack_id"))
        and not _is_placeholder(fields.get("mcp_context.context_pack_hash"))
        and not _is_placeholder(fields.get("mcp_context.source_refs"))
    )


def _mcp_workflow_claims(text: str) -> list[str]:
    claims: list[str] = []
    for match in MCP_WORKFLOW_CLAIM_RE.finditer(text):
        claim = " ".join(match.group(0).split())
        if claim not in claims:
            claims.append(claim)
    return claims


def _mcp_context_ok(fields: dict[str, str]) -> tuple[bool, str]:
    pack_id = fields.get("mcp_context.context_pack_id")
    pack_hash = fields.get("mcp_context.context_pack_hash")
    source_refs = fields.get("mcp_context.source_refs")
    receipt_proof = fields.get("mcp_context.receipt_proof")
    has_pack = (
        not _is_placeholder(pack_id)
        and not _is_placeholder(pack_hash)
        and not _is_placeholder(source_refs)
    )
    has_receipt_fallback = not _is_placeholder(receipt_proof)
    if has_pack:
        return True, "context pack id/hash/source_refs present"
    if has_receipt_fallback:
        return True, "receipt_proof fallback present"
    return False, "missing MCP context pack id/hash/source_refs and receipt_proof fallback"


def validate_pr_body(text: str, *, pr_body_path: str = "") -> dict[str, Any]:
    block_lines, block_start_line = _extract_pr_hygiene_block(text)
    fields = _extract_fields(block_lines)
    checks: list[CheckResult] = []

    if not block_lines:
        checks.append(
            CheckResult(
                id="pr_hygiene_block",
                status="fail",
                message="missing ## PR Hygiene block",
                evidence={"line": None},
            )
        )
    else:
        checks.append(
            CheckResult(
                id="pr_hygiene_block",
                status="pass",
                message="found ## PR Hygiene block",
                evidence={"line": block_start_line},
            )
        )

    missing_labels = [
        field_id for field_id in FIELD_LABELS if field_id not in fields
    ]
    checks.append(
        CheckResult(
            id="required_field_labels",
            status="pass" if not missing_labels else "fail",
            message="all documented PR hygiene labels present"
            if not missing_labels
            else "missing documented PR hygiene labels",
            evidence={"missing_field_labels": missing_labels},
        )
    )

    ok, exact_files = _has_exact_file_list(fields.get("changed_file_scope.exact_file_list"))
    checks.append(
        CheckResult(
            id="changed_file_scope.exact_file_list",
            status="pass" if ok else "fail",
            message="exact changed files listed" if ok else "missing exact changed-file list",
            evidence={
                "value": fields.get("changed_file_scope.exact_file_list"),
                "path_tokens": exact_files,
            },
        )
    )
    workflow_paths = _workflow_affecting_paths(exact_files)

    reason = fields.get("changed_file_scope.review_slice_reason")
    checks.append(
        CheckResult(
            id="changed_file_scope.review_slice_reason",
            status="pass" if not _is_placeholder(reason) else "fail",
            message="review slice reason present" if not _is_placeholder(reason) else "missing review slice reason",
            evidence={"value": reason},
        )
    )

    commands = fields.get("checks.exact_commands")
    checks.append(
        CheckResult(
            id="checks.exact_commands",
            status="pass" if _has_exact_commands(commands) else "fail",
            message="exact check commands present" if _has_exact_commands(commands) else "missing exact check commands",
            evidence={"value": commands},
        )
    )

    result = fields.get("checks.result")
    checks.append(
        CheckResult(
            id="checks.result",
            status="pass" if not _is_placeholder(result) else "fail",
            message="check result present" if not _is_placeholder(result) else "missing check result",
            evidence={"value": result},
        )
    )

    mcp_ok, mcp_message = _mcp_context_ok(fields)
    checks.append(
        CheckResult(
            id="mcp_context.provenance",
            status="pass" if mcp_ok else "fail",
            message=mcp_message,
            evidence={
                "context_pack_id": fields.get("mcp_context.context_pack_id"),
                "context_pack_hash": fields.get("mcp_context.context_pack_hash"),
                "source_refs": fields.get("mcp_context.source_refs"),
                "receipt_proof": fields.get("mcp_context.receipt_proof"),
            },
        )
    )

    mcp_claims = _mcp_workflow_claims(text)
    has_claim_evidence = _has_context_pack_source_evidence(fields)
    checks.append(
        CheckResult(
            id="mcp_context.claim_evidence",
            status="pass" if not mcp_claims or has_claim_evidence else "fail",
            message=(
                "MCP-backed workflow claim includes context pack id/hash and source_refs"
                if mcp_claims and has_claim_evidence
                else "no MCP-backed workflow claim detected"
                if not mcp_claims
                else "MCP-backed workflow claim missing context pack id/hash or source_refs"
            ),
            evidence={
                "claims": mcp_claims,
                "requires": [
                    "mcp_context.context_pack_id",
                    "mcp_context.context_pack_hash",
                    "mcp_context.source_refs",
                ],
                "context_pack_id": fields.get("mcp_context.context_pack_id"),
                "context_pack_hash": fields.get("mcp_context.context_pack_hash"),
                "source_refs": fields.get("mcp_context.source_refs"),
            },
        )
    )

    command_gaps = _workflow_gate_command_gaps(commands, workflow_paths) if workflow_paths else []
    context_gaps = _workflow_context_evidence_gaps(fields) if workflow_paths else []
    workflow_ok = not command_gaps and not context_gaps
    checks.append(
        CheckResult(
            id="workflow_handoff.enforcement",
            status="pass" if workflow_ok else "fail",
            message=(
                "workflow-affecting PR includes MCP/context evidence and exact gate commands"
                if workflow_paths and workflow_ok
                else "non-workflow PR; workflow handoff gate not required"
                if not workflow_paths
                else "workflow-affecting PR missing MCP/context evidence or exact gate commands"
            ),
            evidence={
                "workflow_affecting_paths": workflow_paths,
                "missing_gate_commands": command_gaps,
                "missing_context_evidence": context_gaps,
                "required_gate_command_examples": [
                    "python3 tools/pr-hygiene-check.py <pr-body.md> --strict",
                    "python3 tools/memory-context-load.py --workspace <workspace> --check --strict --require-proof --json",
                    "python3 tools/workpack-validator.py <workpack.md>",
                ],
            },
        )
    )

    excluded = fields.get("generated_file_exclusion.excluded_paths_patterns")
    checks.append(
        CheckResult(
            id="generated_file_exclusion.excluded_paths_patterns",
            status="pass" if not _is_placeholder(excluded) else "fail",
            message="generated/local exclusion paths present"
            if not _is_placeholder(excluded)
            else "missing generated/local exclusion paths",
            evidence={"value": excluded},
        )
    )

    confirmation = fields.get("generated_file_exclusion.confirmation")
    checks.append(
        CheckResult(
            id="generated_file_exclusion.confirmation",
            status="pass" if not _is_placeholder(confirmation) else "fail",
            message="generated/local exclusion confirmation present"
            if not _is_placeholder(confirmation)
            else "missing generated/local exclusion confirmation",
            evidence={"value": confirmation},
        )
    )

    missing = [check.id for check in checks if check.status != "pass"]
    present_fields = sorted(fields)
    report = {
        "schema": SCHEMA,
        "pr_body_path": pr_body_path,
        "ok": not missing,
        "checks": [check.__dict__ for check in checks],
        "missing": missing,
        "field_labels": {
            "present": present_fields,
            "missing": missing_labels,
        },
        "summary": {
            "missing_count": len(missing),
            "check_count": len(checks),
            "present_field_count": len(present_fields),
            "missing_field_label_count": len(missing_labels),
        },
        "advisory": {
            "default_exit_code": 0,
            "strict_exit_code": 1 if missing else 0,
        },
    }
    return report


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pr_body", type=Path, help="Path to a PR body markdown file")
    parser.add_argument("--strict", action="store_true", help="exit 1 when required hygiene fields are missing")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None, *, stdout: Any = None) -> int:
    args = parse_args(argv)
    out = stdout or sys.stdout
    try:
        text = args.pr_body.read_text(encoding="utf-8")
    except OSError as exc:
        print(
            json.dumps(
                {
                    "schema": SCHEMA,
                    "pr_body_path": str(args.pr_body),
                    "ok": False,
                    "error": "read_failed",
                    "message": str(exc),
                },
                sort_keys=True,
            ),
            file=out,
        )
        return 2

    report = validate_pr_body(text, pr_body_path=str(args.pr_body))
    print(json.dumps(report, sort_keys=True), file=out)
    if args.strict and not report["ok"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
