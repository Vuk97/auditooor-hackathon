#!/usr/bin/env python3
"""hot-function-hacker-question-receipt.py - Build and check hot-function / hacker-question receipts.

Schema: auditooor.hot_function_hacker_question_receipt.v1
Receipt path: <workspace>/.auditooor/hot_function_hacker_question_receipt.json

Two modes:

  BUILD (--workspace <ws>)
    Read <ws>/.auditooor/exploit_queue.source_mined.json (or exploit_queue.json
    as fallback).  For every queue row produce a receipt row that binds:
      - queue_row_ref: stable identity fields from the queue row
      - source_artifact_refs: local artifact paths / source refs on the row
      - source_anchors: file-path + line range (resolved from row fields)
      - hot_functions: resolved function signatures with language + rank
      - function_mindset: ranked attack classes via vault_function_mindset when
        available; gracefully degrades to row-carried attack_class when not
      - hacker_questions: rendered from row fields or left as placeholders with
        an unresolved_reason
      - gate_blockers: blocker codes from initial inspection

    Writes the receipt JSON and a Markdown summary.  Exits 0.

  CHECK (default, no --build)
    Validate that a receipt exists, is schema-valid, and every non-terminal
    source-mined queue row has a receipt row.

    --strict: exit non-zero when any non-terminal row lacks a receipt.

Exit codes:
  0 - success / all rows receipted (or no source-mined queue)
  1 - argument error
  2 - strict check failed (missing or blocked receipt rows)
  3 - receipt file missing (strict mode)
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

SCHEMA = "auditooor.hot_function_hacker_question_receipt.v1"
FUNCTION_MINDSET_TOOL = "vault_function_mindset / hot-function-hacker-question-receipt.py v1"

RECEIPT_FILENAME = "hot_function_hacker_question_receipt.json"
RECEIPT_MD_FILENAME = "hot_function_hacker_question_receipt.md"
SOURCE_MINED_QUEUE_FILENAME = "exploit_queue.source_mined.json"
FALLBACK_QUEUE_FILENAME = "exploit_queue.json"

# Blocker codes (from design note)
BLOCKER_MISSING_SOURCE_ANCHOR = "missing_source_anchor"
BLOCKER_UNRESOLVED_HOT_FUNCTION = "unresolved_hot_function"
BLOCKER_MISSING_FUNCTION_MINDSET = "missing_function_mindset"
BLOCKER_MISSING_HACKER_QUESTIONS = "missing_hacker_questions"
BLOCKER_ANCHOR_FILE_MISSING = "anchor_file_missing"
BLOCKER_ANCHOR_LINE_RANGE_INVALID = "anchor_line_range_invalid"
BLOCKER_RECEIPT_PROOF_MISSING = "receipt_proof_missing"
BLOCKER_RECEIPT_PROOF_INVALID = "receipt_proof_invalid"

# Terminal row states - exempt from receipt blockers (matching v3-source-first-row-gate.py)
TERMINAL_STATES = frozenset({
    "disproved", "drop", "dropped", "killed", "closed", "oos", "out_of_scope",
    "out-of-scope", "oosclosed", "duplicate", "dupe", "won't fix", "wontfix",
    "false_positive", "false-positive", "fp", "terminal", "terminal_no_submission",
})


# ---------------------------------------------------------------------------
# Utilities (self-contained; do not import from sibling tools)
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _norm(value: Any, *, limit: int = 500) -> str:
    if isinstance(value, (list, tuple, set)):
        value = "; ".join(_norm(v, limit=limit) for v in value if _norm(v, limit=limit))
    elif isinstance(value, dict):
        value = json.dumps(value, sort_keys=True)
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    return text[:limit]


MISSING_VALUES = frozenset({"", "none", "null", "n/a", "tbd", "todo", "unknown", "unset"})
PLACEHOLDER_MARKERS = ("placeholder", "fill in", "fill_in", "to be determined", "not set")


def _is_present(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return True
    if isinstance(value, (list, tuple, set)):
        return any(_is_present(item) for item in value)
    if isinstance(value, dict):
        return bool(value)
    text = _norm(value).lower()
    if not text or text in MISSING_VALUES:
        return False
    return not any(marker in text for marker in PLACEHOLDER_MARKERS)


def _first(row: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = row.get(key)
        if _is_present(value):
            return _norm(value)
    return ""


def _candidate_id(row: dict[str, Any]) -> str:
    return _first(row, "lead_id", "candidate_id", "row_id", "id", "title") or "candidate"


def _stable_key(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "", _norm(value).lower())


def _read_json(path: Path) -> Any | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _sha256_of(payload: dict[str, Any]) -> str:
    """SHA-256 of canonical JSON (sorted keys, no trailing whitespace)."""
    canonical = json.dumps(payload, indent=None, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Queue loading
# ---------------------------------------------------------------------------

def _rows_from_payload(payload: Any) -> list[dict[str, Any]]:
    if payload is None:
        return []
    if isinstance(payload, list):
        return [r for r in payload if isinstance(r, dict)]
    if isinstance(payload, dict):
        for key in ("rows", "candidates", "leads", "queue", "items"):
            rows = payload.get(key)
            if isinstance(rows, list):
                return [r for r in rows if isinstance(r, dict)]
        return [payload] if payload else []
    return []


def _load_queue(workspace: Path, queue_path: Path | None) -> tuple[Path | None, list[dict[str, Any]]]:
    if queue_path is not None:
        path = queue_path
        rows = _rows_from_payload(_read_json(path)) if path.is_file() else []
        return path, rows
    primary = workspace / ".auditooor" / SOURCE_MINED_QUEUE_FILENAME
    fallback = workspace / ".auditooor" / FALLBACK_QUEUE_FILENAME
    if primary.is_file():
        return primary, _rows_from_payload(_read_json(primary))
    if fallback.is_file():
        return fallback, _rows_from_payload(_read_json(fallback))
    return None, []


# ---------------------------------------------------------------------------
# Terminal row detection
# ---------------------------------------------------------------------------

def _is_terminal(row: dict[str, Any]) -> bool:
    if row.get("row_is_advisory") is True or row.get("advisory_only") is True:
        return True
    status_fields = " ".join(
        _first(row, key)
        for key in ("proof_status", "quality_gate_status", "status",
                    "packet_state", "scope_status", "verdict",
                    "execution_contract_claim")
    ).lower()
    return any(state in status_fields for state in TERMINAL_STATES)


# ---------------------------------------------------------------------------
# Receipt row building
# ---------------------------------------------------------------------------

def _detect_language(file_path: str) -> str:
    ext_map = {
        ".sol": "Solidity", ".go": "Go", ".rs": "Rust",
        ".py": "Python", ".ts": "TypeScript", ".tsx": "TypeScript",
        ".cairo": "Cairo", ".move": "Move",
    }
    suffix = Path(file_path).suffix.lower() if file_path else ""
    return ext_map.get(suffix, "unknown")


def _resolve_source_anchors(row: dict[str, Any], workspace: Path) -> tuple[list[dict[str, Any]], list[str]]:
    """Extract source anchors from row fields; validate file existence."""
    anchors: list[dict[str, Any]] = []
    blockers: list[str] = []

    # Pull anchor-like fields from the row
    raw_anchors: list[dict[str, Any]] = []
    for key in ("source_anchors", "source_anchor", "anchors"):
        val = row.get(key)
        if isinstance(val, list):
            raw_anchors.extend(v for v in val if isinstance(v, dict))
        elif isinstance(val, dict):
            raw_anchors.append(val)

    # Also try to synthesize one from proof_path / source_file / file_path
    if not raw_anchors:
        for key in ("proof_path", "source_file", "file_path", "affected_file"):
            path_str = _first(row, key)
            if path_str:
                raw_anchors.append({"file_path": path_str})
                break

    if not raw_anchors:
        blockers.append(BLOCKER_MISSING_SOURCE_ANCHOR)
        return anchors, blockers

    for anchor_raw in raw_anchors:
        file_path = str(anchor_raw.get("file_path") or anchor_raw.get("path") or "")
        start_line = anchor_raw.get("start_line")
        end_line = anchor_raw.get("end_line")
        anchor_text = str(anchor_raw.get("anchor_text") or anchor_raw.get("text") or "")

        # Validate file existence (relative to workspace)
        resolved_file = None
        if file_path:
            candidate = Path(file_path)
            if not candidate.is_absolute():
                candidate = workspace / candidate
            if candidate.is_file():
                resolved_file = str(candidate)
            else:
                # Only warn - the file may be in the target repo, not the workspace
                pass

        # Validate line range
        line_range_ok = True
        if start_line is not None and end_line is not None:
            try:
                sl, el = int(start_line), int(end_line)
                if sl < 1 or el < sl:
                    line_range_ok = False
                    blockers.append(BLOCKER_ANCHOR_LINE_RANGE_INVALID)
            except (TypeError, ValueError):
                line_range_ok = False
                blockers.append(BLOCKER_ANCHOR_LINE_RANGE_INVALID)

        anchor_text_hash = hashlib.sha256(anchor_text.encode()).hexdigest()[:16] if anchor_text else None

        anchors.append({
            "file_path": file_path,
            "resolved_file": resolved_file,
            "start_line": start_line,
            "end_line": end_line,
            "function_signature": anchor_raw.get("function_signature"),
            "anchor_text_hash": anchor_text_hash,
            "anchor_file_present": resolved_file is not None,
        })

    return anchors, blockers


def _resolve_hot_functions(row: dict[str, Any], anchors: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[str]]:
    """Extract or synthesize hot function list from row fields."""
    functions: list[dict[str, Any]] = []
    blockers: list[str] = []

    # Try explicit fields first
    raw_fns: list[dict[str, Any]] = []
    for key in ("hot_functions", "hot_function", "functions"):
        val = row.get(key)
        if isinstance(val, list):
            raw_fns.extend(v for v in val if isinstance(v, dict))
        elif isinstance(val, dict):
            raw_fns.append(val)

    if raw_fns:
        for i, fn in enumerate(raw_fns):
            file_path = str(fn.get("file_path") or fn.get("path") or "")
            sig = str(fn.get("function_signature") or fn.get("function") or fn.get("name") or "")
            lang = fn.get("language") or _detect_language(file_path)
            functions.append({
                "file_path": file_path,
                "function_signature": sig,
                "language": lang,
                "shape_hash": fn.get("shape_hash"),
                "rank": fn.get("rank", i + 1),
                "reason": fn.get("reason") or "from row hot_functions field",
            })
        return functions, blockers

    # Try to synthesize from anchors
    for i, anchor in enumerate(anchors):
        if anchor.get("function_signature"):
            functions.append({
                "file_path": anchor.get("file_path", ""),
                "function_signature": anchor["function_signature"],
                "language": _detect_language(anchor.get("file_path", "")),
                "shape_hash": None,
                "rank": i + 1,
                "reason": "synthesized from source anchor",
            })

    # Try from named function fields on the row
    if not functions:
        for key in ("function_signature", "affected_function", "vulnerable_function", "entry_point"):
            sig = _first(row, key)
            if sig:
                file_path = _first(row, "proof_path", "source_file", "file_path", "affected_file")
                functions.append({
                    "file_path": file_path,
                    "function_signature": sig,
                    "language": _detect_language(file_path),
                    "shape_hash": None,
                    "rank": 1,
                    "reason": f"synthesized from row field '{key}'",
                })
                break

    if not functions:
        blockers.append(BLOCKER_UNRESOLVED_HOT_FUNCTION)

    return functions, blockers


def _resolve_function_mindset(row: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Extract function-mindset ranked attack classes from row or inline fields."""
    blockers: list[str] = []

    # Try explicit mindset block first
    mindset_raw = row.get("function_mindset") or row.get("mindset")
    if isinstance(mindset_raw, dict) and mindset_raw.get("ranked_attack_classes"):
        return {
            "target_repo": mindset_raw.get("target_repo"),
            "ranked_attack_classes": list(mindset_raw["ranked_attack_classes"]),
            "context_pack_id": mindset_raw.get("context_pack_id"),
            "context_pack_hash": mindset_raw.get("context_pack_hash"),
            "source": "row_mindset_field",
        }, blockers

    # Try ranked_attack_classes directly on the row
    rac = row.get("ranked_attack_classes")
    if isinstance(rac, list) and rac:
        return {
            "target_repo": row.get("target_repo"),
            "ranked_attack_classes": rac,
            "context_pack_id": None,
            "context_pack_hash": None,
            "source": "row_ranked_attack_classes_field",
        }, blockers

    # Fall back to attack_class / attack_classes single value
    attack_class = _first(row, "attack_class", "attack_classes", "bug_class")
    if attack_class:
        return {
            "target_repo": row.get("target_repo"),
            "ranked_attack_classes": [{"attack_class": attack_class, "rank": 1, "source": "row_attack_class_field"}],
            "context_pack_id": None,
            "context_pack_hash": None,
            "source": "row_attack_class_field",
        }, blockers

    # No mindset data at all
    blockers.append(BLOCKER_MISSING_FUNCTION_MINDSET)
    return {
        "target_repo": row.get("target_repo"),
        "ranked_attack_classes": [],
        "context_pack_id": None,
        "context_pack_hash": None,
        "source": "unresolved",
    }, blockers


def _render_hacker_questions(row: dict[str, Any], mindset: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
    """Render hacker questions from row fields or synthesize from mindset."""
    blockers: list[str] = []
    questions: list[dict[str, Any]] = []

    # Try explicit hacker_questions field
    raw_qs = row.get("hacker_questions") or row.get("questions") or row.get("hacker_question")
    if isinstance(raw_qs, list) and raw_qs:
        for i, q in enumerate(raw_qs):
            if isinstance(q, dict):
                questions.append({
                    "question_id": q.get("question_id") or f"hq-{i+1:03d}",
                    "schema": "auditooor.hacker_question.v1",
                    "prompt_text": q.get("prompt_text") or q.get("question") or q.get("text") or "",
                    "proof_obligation": q.get("proof_obligation") or q.get("obligation") or "",
                    "kill_condition": q.get("kill_condition") or q.get("kill") or "",
                })
            elif isinstance(q, str) and q.strip():
                questions.append({
                    "question_id": f"hq-{i+1:03d}",
                    "schema": "auditooor.hacker_question.v1",
                    "prompt_text": q.strip(),
                    "proof_obligation": "",
                    "kill_condition": "",
                })
        if questions:
            return questions, blockers

    # Synthesize from mindset ranked attack classes
    ranked = mindset.get("ranked_attack_classes") or []
    cid = _candidate_id(row)
    severity = _first(row, "likely_severity", "claimed_severity", "severity")
    title = _first(row, "title", "root_cause_hypothesis") or cid

    for i, rac in enumerate(ranked[:3]):
        ac = rac.get("attack_class") or rac if isinstance(rac, str) else "unknown"
        questions.append({
            "question_id": f"hq-{i+1:03d}",
            "schema": "auditooor.hacker_question.v1",
            "prompt_text": (
                f"For candidate '{title}' ({severity}): does the {ac} pattern "
                f"allow an attacker to reach the vulnerable path? "
                f"What preconditions must hold?"
            ),
            "proof_obligation": f"Show a call path reaching the {ac} trigger with attacker-controlled input.",
            "kill_condition": f"If no {ac} trigger is reachable without privileged access, this question is killed.",
        })

    if not questions:
        # Absolute fallback - generic question from row fields
        questions.append({
            "question_id": "hq-001",
            "schema": "auditooor.hacker_question.v1",
            "prompt_text": (
                f"For candidate '{title}': what is the exact vulnerable call path "
                f"and what attacker-controlled inputs trigger the bug?"
            ),
            "proof_obligation": "Show a PoC that reaches the vulnerable state with attacker input.",
            "kill_condition": "If no attacker-controlled trigger path exists, drop the candidate.",
            "unresolved_reason": "synthesized from title - no mindset or explicit questions available",
        })

    return questions, blockers


def _build_receipt_row(
    row: dict[str, Any],
    row_index: int,
    workspace: Path,
) -> dict[str, Any]:
    """Build one receipt row for one queue row."""
    cid = _candidate_id(row)
    blockers: list[str] = []

    # Queue row reference
    queue_row_ref = {
        "row_index": row_index,
        "candidate_id": cid,
        "title": _first(row, "title", "root_cause_hypothesis") or cid,
        "likely_severity": _first(row, "likely_severity", "claimed_severity", "severity"),
        "attack_class": _first(row, "attack_class", "attack_classes", "bug_class"),
    }

    # Source artifact refs
    source_artifact_refs: list[str] = []
    for key in ("source_artifacts", "source_artifact", "source_refs", "proof_path",
                 "source_files", "source_file"):
        val = row.get(key)
        if isinstance(val, list):
            source_artifact_refs.extend(str(v) for v in val if v)
        elif _is_present(val):
            source_artifact_refs.append(str(val))

    # Source anchors
    source_anchors, anchor_blockers = _resolve_source_anchors(row, workspace)
    blockers.extend(anchor_blockers)

    # Hot functions
    hot_functions, fn_blockers = _resolve_hot_functions(row, source_anchors)
    blockers.extend(fn_blockers)

    # Function mindset
    function_mindset, mindset_blockers = _resolve_function_mindset(row)
    blockers.extend(mindset_blockers)

    # Hacker questions
    hacker_questions, q_blockers = _render_hacker_questions(row, function_mindset)
    blockers.extend(q_blockers)

    if not hacker_questions:
        blockers.append(BLOCKER_MISSING_HACKER_QUESTIONS)

    # Deduplicate blockers
    blockers = sorted(set(blockers))

    return {
        "candidate_id": cid,
        "is_terminal": _is_terminal(row),
        "queue_row_ref": queue_row_ref,
        "source_artifact_refs": source_artifact_refs,
        "source_anchors": source_anchors,
        "hot_functions": hot_functions,
        "function_mindset": function_mindset,
        "hacker_questions": hacker_questions,
        "gate_blockers": blockers,
    }


# ---------------------------------------------------------------------------
# Receipt proof
# ---------------------------------------------------------------------------

def _compute_receipt_proof(receipt: dict[str, Any]) -> str:
    """SHA-256 of the receipt dict with receipt_proof field excluded."""
    copy = {k: v for k, v in receipt.items() if k != "receipt_proof"}
    return _sha256_of(copy)


# ---------------------------------------------------------------------------
# Summary + Markdown
# ---------------------------------------------------------------------------

def _build_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(rows)
    terminal = sum(1 for r in rows if r.get("is_terminal"))
    receipted = total
    blocked = sum(1 for r in rows if r.get("gate_blockers"))
    blocker_counts: Counter[str] = Counter()
    for r in rows:
        for b in r.get("gate_blockers") or []:
            blocker_counts[b] += 1
    return {
        "rows_seen": total,
        "rows_terminal": terminal,
        "rows_receipted": receipted,
        "rows_blocked": blocked,
        "rows_clean": receipted - blocked,
        "blocker_histogram": dict(blocker_counts.most_common()),
    }


def _render_markdown(receipt: dict[str, Any]) -> str:
    summary = receipt.get("summary", {})
    rows = receipt.get("rows", [])
    lines = [
        "# Hot-Function Hacker-Question Receipt",
        "",
        f"Schema: `{receipt.get('schema')}`",
        f"Workspace: `{receipt.get('workspace')}`",
        f"Generated: {receipt.get('generated_at')}",
        f"Source queue: `{receipt.get('source_queue_path')}`",
        "",
        "## Summary",
        "",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Rows seen | {summary.get('rows_seen', 0)} |",
        f"| Terminal (exempt) | {summary.get('rows_terminal', 0)} |",
        f"| Receipted | {summary.get('rows_receipted', 0)} |",
        f"| With blockers | {summary.get('rows_blocked', 0)} |",
        f"| Clean | {summary.get('rows_clean', 0)} |",
        "",
    ]
    hist = summary.get("blocker_histogram", {})
    if hist:
        lines += [
            "## Blocker Histogram",
            "",
            "| Blocker | Count |",
            "|---------|-------|",
        ]
        for code, count in hist.items():
            lines.append(f"| `{code}` | {count} |")
        lines.append("")

    lines += ["## Row Receipts", ""]
    for row in rows:
        cid = row.get("candidate_id", "?")
        terminal = row.get("is_terminal", False)
        blockers = row.get("gate_blockers") or []
        status = "TERMINAL" if terminal else ("BLOCKED" if blockers else "CLEAN")
        lines.append(f"### {cid} [{status}]")
        lines.append("")
        qr = row.get("queue_row_ref", {})
        lines.append(f"- Title: {qr.get('title', '?')}")
        lines.append(f"- Severity: {qr.get('likely_severity', 'unknown')}")
        lines.append(f"- Attack class: {qr.get('attack_class', 'unknown')}")
        hf = row.get("hot_functions") or []
        if hf:
            lines.append(f"- Hot functions: {', '.join(f.get('function_signature') or f.get('file_path', '?') for f in hf[:3])}")
        if blockers:
            lines.append(f"- Blockers: {', '.join(f'`{b}`' for b in blockers)}")
        qs = row.get("hacker_questions") or []
        for q in qs[:2]:
            lines.append(f"- Q: {q.get('prompt_text', '')[:120]}")
        lines.append("")

    lines += [
        "## Receipt Proof",
        "",
        f"`{receipt.get('receipt_proof', 'missing')}`",
        "",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# BUILD mode
# ---------------------------------------------------------------------------

def cmd_build(
    workspace: Path,
    queue_path: Path | None,
    out_json: Path,
    out_md: Path | None,
    print_json: bool,
) -> int:
    queue_file, rows = _load_queue(workspace, queue_path)

    if queue_file is None or not rows:
        msg = "no_source_mined_queue"
        receipt: dict[str, Any] = {
            "schema": SCHEMA,
            "workspace": str(workspace.resolve()),
            "generated_at": _utc_now(),
            "source_queue_path": str(queue_file) if queue_file else "not_found",
            "function_mindset_tool": FUNCTION_MINDSET_TOOL,
            "rows": [],
            "summary": {
                "rows_seen": 0,
                "rows_terminal": 0,
                "rows_receipted": 0,
                "rows_blocked": 0,
                "rows_clean": 0,
                "blocker_histogram": {},
                "no_source_mined_queue": True,
            },
        }
        receipt["receipt_proof"] = _compute_receipt_proof(receipt)
        _write_json(out_json, receipt)
        if out_md:
            out_md.parent.mkdir(parents=True, exist_ok=True)
            out_md.write_text(_render_markdown(receipt), encoding="utf-8")
        if print_json:
            print(json.dumps(receipt, indent=2, sort_keys=True))
        print(f"[hot-function-receipt] {msg} - wrote empty receipt to {out_json}", file=sys.stderr)
        return 0

    receipt_rows = []
    for i, row in enumerate(rows):
        receipt_rows.append(_build_receipt_row(row, i, workspace))

    summary = _build_summary(receipt_rows)
    receipt = {
        "schema": SCHEMA,
        "workspace": str(workspace.resolve()),
        "generated_at": _utc_now(),
        "source_queue_path": str(queue_file),
        "function_mindset_tool": FUNCTION_MINDSET_TOOL,
        "rows": receipt_rows,
        "summary": summary,
    }
    receipt["receipt_proof"] = _compute_receipt_proof(receipt)

    _write_json(out_json, receipt)
    if out_md:
        out_md.parent.mkdir(parents=True, exist_ok=True)
        out_md.write_text(_render_markdown(receipt), encoding="utf-8")
    if print_json:
        print(json.dumps(receipt, indent=2, sort_keys=True))

    print(
        f"[hot-function-receipt] built receipt: {summary['rows_seen']} rows, "
        f"{summary['rows_blocked']} blocked, {summary['rows_clean']} clean "
        f"-> {out_json}",
        file=sys.stderr,
    )
    return 0


# ---------------------------------------------------------------------------
# CHECK mode
# ---------------------------------------------------------------------------

def _validate_receipt_schema(receipt: Any) -> list[str]:
    """Return list of schema violation descriptions."""
    issues: list[str] = []
    if not isinstance(receipt, dict):
        return ["receipt is not a JSON object"]
    if receipt.get("schema") != SCHEMA:
        issues.append(f"schema mismatch: got {receipt.get('schema')!r}, want {SCHEMA!r}")
    for field in ("workspace", "generated_at", "source_queue_path", "function_mindset_tool", "rows", "summary"):
        if field not in receipt:
            issues.append(f"missing top-level field: {field!r}")
    if "receipt_proof" not in receipt:
        issues.append("missing receipt_proof")
    else:
        expected = _compute_receipt_proof(receipt)
        if receipt["receipt_proof"] != expected:
            issues.append(f"receipt_proof mismatch: stored={receipt['receipt_proof']!r} expected={expected!r}")
    return issues


def cmd_check(
    workspace: Path,
    queue_path: Path | None,
    receipt_path: Path,
    strict: bool,
    print_json: bool,
) -> int:
    # Load queue to know which rows need receipts
    queue_file, queue_rows = _load_queue(workspace, queue_path)

    result: dict[str, Any] = {
        "schema": "auditooor.hot_function_receipt_check.v1",
        "workspace": str(workspace.resolve()),
        "checked_at": _utc_now(),
        "receipt_path": str(receipt_path),
        "queue_path": str(queue_file) if queue_file else "not_found",
        "verdict": "pass",
        "issues": [],
        "rows": [],
    }

    # No queue - trivially pass
    if queue_file is None or not queue_rows:
        result["verdict"] = "pass"
        result["issues"].append("no_source_mined_queue - check trivially passes")
        if print_json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print("[hot-function-receipt-check] PASS - no source-mined queue found")
        return 0

    # Check receipt file exists
    if not receipt_path.is_file():
        result["verdict"] = "fail" if strict else "warn"
        result["issues"].append(f"receipt file not found: {receipt_path}")
        if print_json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            level = "FAIL" if strict else "WARN"
            print(f"[hot-function-receipt-check] {level} - receipt file not found: {receipt_path}")
        return (3 if strict else 0)

    receipt = _read_json(receipt_path)
    schema_issues = _validate_receipt_schema(receipt)
    if schema_issues:
        result["verdict"] = "fail" if strict else "warn"
        result["issues"].extend(schema_issues)
        if print_json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            level = "FAIL" if strict else "WARN"
            print(f"[hot-function-receipt-check] {level} - schema issues: {schema_issues}")
        return (2 if strict else 0)

    # Build index of receipt rows by candidate_id
    receipt_rows = receipt.get("rows") or []
    receipt_index: dict[str, dict[str, Any]] = {}
    for r in receipt_rows:
        cid = r.get("candidate_id") or ""
        if cid:
            receipt_index[_stable_key(cid)] = r

    # Check each non-terminal queue row has a receipt row
    row_results = []
    any_fail = False
    for i, qrow in enumerate(queue_rows):
        cid = _candidate_id(qrow)
        terminal = _is_terminal(qrow)
        receipt_row = receipt_index.get(_stable_key(cid))
        row_verdict: dict[str, Any] = {
            "row_index": i,
            "candidate_id": cid,
            "is_terminal": terminal,
        }
        if terminal:
            row_verdict["verdict"] = "exempt"
        elif receipt_row is None:
            row_verdict["verdict"] = "fail"
            row_verdict["blocker"] = "hot_function_receipt_row_missing"
            any_fail = True
        else:
            gate_blockers = receipt_row.get("gate_blockers") or []
            if gate_blockers:
                row_verdict["verdict"] = "warn"
                row_verdict["gate_blockers"] = gate_blockers
            else:
                row_verdict["verdict"] = "pass"
        row_results.append(row_verdict)

    result["rows"] = row_results

    if any_fail:
        result["verdict"] = "fail" if strict else "warn"
    elif any(r.get("verdict") == "warn" for r in row_results):
        result["verdict"] = "warn"
    else:
        result["verdict"] = "pass"

    if print_json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        total = len(queue_rows)
        missing = sum(1 for r in row_results if r.get("blocker") == "hot_function_receipt_row_missing")
        blocked = sum(1 for r in row_results if r.get("verdict") == "warn")
        clean = sum(1 for r in row_results if r.get("verdict") == "pass")
        exempt = sum(1 for r in row_results if r.get("verdict") == "exempt")
        print(
            f"[hot-function-receipt-check] {result['verdict'].upper()} - "
            f"{total} rows: {clean} clean, {blocked} blocked, {missing} missing-receipt, {exempt} exempt"
        )

    if strict and result["verdict"] == "fail":
        return 2
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="Build or check hot-function hacker-question receipts.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--workspace", "-w", type=Path, default=Path("."),
                    help="Workspace root (default: current directory)")
    ap.add_argument("--build", action="store_true",
                    help="BUILD mode: generate receipt from source-mined queue")
    ap.add_argument("--queue", type=Path, default=None,
                    help="Override source-mined queue path")
    ap.add_argument("--out-json", type=Path, default=None,
                    help="Override output JSON path (default: <ws>/.auditooor/" + RECEIPT_FILENAME + ")")
    ap.add_argument("--out-md", type=Path, default=None,
                    help="Override output Markdown path (default: <ws>/.auditooor/" + RECEIPT_MD_FILENAME + ")")
    ap.add_argument("--no-md", action="store_true",
                    help="Skip Markdown output")
    ap.add_argument("--strict", action="store_true",
                    help="CHECK mode: exit non-zero when any non-terminal row lacks a receipt")
    ap.add_argument("--print-json", action="store_true",
                    help="Print JSON result to stdout")
    return ap.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    workspace = args.workspace.expanduser().resolve()

    auditooor_dir = workspace / ".auditooor"
    default_out_json = auditooor_dir / RECEIPT_FILENAME
    default_out_md = auditooor_dir / RECEIPT_MD_FILENAME

    out_json = (args.out_json.expanduser().resolve() if args.out_json else default_out_json)
    out_md = None if args.no_md else (args.out_md.expanduser().resolve() if args.out_md else default_out_md)
    queue_path = args.queue.expanduser().resolve() if args.queue else None

    if args.build:
        return cmd_build(workspace, queue_path, out_json, out_md, args.print_json)
    else:
        return cmd_check(workspace, queue_path, out_json, args.strict, args.print_json)


if __name__ == "__main__":
    sys.exit(main())
