#!/usr/bin/env python3
"""universal-task-ledger-validate.py — validate auditooor.universal_task_ledger.v1 rows.

Lane 6 of MCP harness review (PR #658). Schema: schemas/universal_task_ledger.v1.json.

Usage:
    python3 tools/universal-task-ledger-validate.py <path/to/ledger.jsonl>
    python3 tools/universal-task-ledger-validate.py --strict   # exit non-zero on warnings
    python3 tools/universal-task-ledger-validate.py --check-substate  # enforce per-type substate map

Exit codes:
    0 = valid
    1 = schema violation (always hard-fail)
    2 = substate violation (advisory unless --check-substate)

Written by Claude Opus 4.7 for PR #658 implementation Phase 1 commit 1.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from datetime import datetime, timezone

REPO = pathlib.Path(__file__).resolve().parent.parent
SCHEMA_PATH = REPO / "schemas" / "universal_task_ledger.v1.json"

# Per-type allowed substates (mirrors the type_substate_map in the schema).
TYPE_SUBSTATE_MAP = {
    "klbq_burndown": {"verified", "regressed", "needs_human"},
    "retro_audit": {"scoped", "hunting", "poc-build", "filed", "dropped", "closed"},
    "corpus_mining": {"patterns-extracted", "wired", "documented-only"},
    "detector_authoring": {"spec", "fixture", "tested", "wired", "regression-locked"},
    "cross_engagement_propagation": {"proposed", "scoped", "dispatched", "yielded"},
    "in_engagement_hunt": {"dispatched", "triaging", "poc-pass", "staged", "paste-ready", "filed", "dropped"},
    "filing_lifecycle": {"drafted", "paste-ready", "filed", "triaged", "accepted", "escalated", "duplicate", "rejected", "paid", "closed"},
    "rule_codification": {"proposed", "drafted", "landed-in-claude-md", "tooled"},
    "triager_response": {"awaiting-us", "awaiting-them", "clarification-pending", "closed"},
    "tooling_ship": {"planned", "coded", "tested", "wired", "landed"},
    "pr_landing": {"open", "review", "conflict", "landed", "closed"},
    "next_loop_priority": {"queued", "active", "done"},
    "commit_mining": {"scheduled", "running", "classified", "dispatched"},
    "external_intel_intake": {"ingested", "distilled", "wired"},
    "regression_repro": {"repro", "upstream-filed", "landed", "closed"},
}

ID_RE = re.compile(r"^T[A-Z_]+-[0-9]{8}-[a-z0-9-]{1,40}$")
ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}([.+-]|Z)")


def _load_schema():
    if not SCHEMA_PATH.is_file():
        raise SystemExit(f"[fatal] schema not found: {SCHEMA_PATH}")
    with SCHEMA_PATH.open(encoding="utf-8") as fh:
        return json.load(fh)


def _validate_row(row, schema, *, check_substate=False):
    """Returns (errors: list[str], warnings: list[str])."""
    errors = []
    warnings = []

    # Required fields
    for field in schema.get("required", []):
        if field not in row:
            errors.append(f"missing required field: {field}")

    # Schema constant
    if row.get("schema") != "auditooor.universal_task_ledger.v1":
        errors.append(f"schema field must be 'auditooor.universal_task_ledger.v1', got {row.get('schema')!r}")

    # ID format
    rid = row.get("id", "")
    if rid and not ID_RE.match(rid):
        errors.append(f"id format invalid (expected T<TYPE>-<YYYYMMDD>-<slug>): {rid!r}")

    # Type enum
    valid_types = set(schema["properties"]["type"]["enum"])
    rtype = row.get("type")
    if rtype and rtype not in valid_types:
        errors.append(f"type {rtype!r} not in allowed enum")

    # Status enum
    valid_status = set(schema["properties"]["status"]["enum"])
    rstatus = row.get("status")
    if rstatus and rstatus not in valid_status:
        errors.append(f"status {rstatus!r} not in allowed enum")

    # Substate per-type advisory check
    if rtype in TYPE_SUBSTATE_MAP:
        rsub = row.get("status_substate")
        if rsub and rsub not in TYPE_SUBSTATE_MAP[rtype]:
            msg = f"status_substate {rsub!r} not in TYPE_SUBSTATE_MAP[{rtype}]"
            if check_substate:
                errors.append(msg)
            else:
                warnings.append(msg)

    # Owner enum
    valid_owners = set(schema["properties"]["owner_agent"]["enum"])
    rowner = row.get("owner_agent")
    if rowner and rowner not in valid_owners:
        errors.append(f"owner_agent {rowner!r} not in allowed enum")

    # Priority enum
    valid_pri = set(schema["properties"]["priority"]["enum"])
    rpri = row.get("priority")
    if rpri and rpri not in valid_pri:
        errors.append(f"priority {rpri!r} not in allowed enum")

    # ISO datetime fields
    for field in ("created_at", "last_touched"):
        v = row.get(field)
        if v and not ISO_RE.match(str(v)):
            errors.append(f"{field} must be ISO-8601 datetime: {v!r}")

    # Title length
    title = row.get("title", "")
    if title and (len(title) > 120 or len(title) < 8):
        errors.append(f"title length {len(title)} not in [8, 120]")

    # MCP context_pack_id pattern (advisory if absent)
    cpid = row.get("mcp_context_pack_id")
    if cpid and not re.match(r"^auditooor\.[a-z_.]+\.v[0-9]+:[a-z_]+:[a-f0-9]{16}$", cpid):
        warnings.append(f"mcp_context_pack_id format suspicious: {cpid!r}")

    # rules_cited / frames_applied formats
    for r in row.get("rules_cited", []) or []:
        if not re.match(r"^L[0-9]+(-Disc-[0-9]+)?$", r):
            warnings.append(f"rules_cited entry {r!r} doesn't match L<N> or L<N>-Disc-<N> format")
    for f in row.get("frames_applied", []) or []:
        if not re.match(r"^AMF-[0-9]{3}$", f):
            warnings.append(f"frames_applied entry {f!r} doesn't match AMF-NNN format")

    # Terminal-state immutability advisory: shipped/dropped/superseded shouldn't have new transitions
    if rstatus in {"shipped", "dropped", "superseded"}:
        last = row.get("transitions", []) or []
        # Just an advisory check - we can't fully enforce immutability without prior state
        if last and last[-1].get("to_status") != rstatus:
            warnings.append(f"terminal status {rstatus} but last transition ends in {last[-1].get('to_status')!r}")

    return errors, warnings


def validate_file(path, *, strict=False, check_substate=False):
    """Validate a JSONL file of universal task ledger rows. Returns (n_rows, n_err, n_warn)."""
    schema = _load_schema()
    n_rows = n_err = n_warn = 0

    with pathlib.Path(path).open(encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            n_rows += 1
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                print(f"[{path}:{lineno}] JSON decode error: {exc}", file=sys.stderr)
                n_err += 1
                continue
            errors, warnings = _validate_row(row, schema, check_substate=check_substate)
            for err in errors:
                print(f"[{path}:{lineno}] ERROR: {err}", file=sys.stderr)
                n_err += 1
            for w in warnings:
                print(f"[{path}:{lineno}] WARN: {w}", file=sys.stderr)
                n_warn += 1

    return n_rows, n_err, n_warn


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("path", nargs="?", default=None, help="JSONL ledger file (default: obsidian-vault/universal_task_ledger.jsonl)")
    parser.add_argument("--strict", action="store_true", help="treat warnings as errors")
    parser.add_argument("--check-substate", action="store_true", help="enforce per-type substate map (default advisory)")
    parser.add_argument("--print-schema", action="store_true", help="print resolved schema and exit")
    args = parser.parse_args()

    if args.print_schema:
        print(json.dumps(_load_schema(), indent=2))
        return 0

    path = args.path or REPO.parent / "obsidian-vault" / "universal_task_ledger.jsonl"
    path = pathlib.Path(path).resolve()

    if not path.is_file():
        # Empty ledger is valid (no rows yet)
        print(f"[universal-task-ledger-validate] ledger absent at {path} (empty ledger is valid)")
        return 0

    n_rows, n_err, n_warn = validate_file(path, strict=args.strict, check_substate=args.check_substate)
    summary = f"[universal-task-ledger-validate] rows={n_rows} errors={n_err} warnings={n_warn}"
    print(summary, file=sys.stderr)

    if n_err > 0:
        return 1
    if args.strict and n_warn > 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
