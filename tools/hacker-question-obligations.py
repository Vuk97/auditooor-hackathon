#!/usr/bin/env python3
"""hacker-question-obligations -- Lane 5: Function-Level Hacker Question Lifecycle.

Manages the per-workspace ``hacker_question_obligations.jsonl`` artifact under
``<ws>/.auditooor/``.  Each obligation row records a pre-source-read hacker
question as a persistent audit work unit with a lifecycle state.

Schema: ``auditooor.hacker_question_obligation.v1``

Fields per row:
    schema                  "auditooor.hacker_question_obligation.v1"
    obligation_id           stable sha256[:12] dedup key (ws+file+fn+question)
    workspace               absolute workspace path string
    file                    relative file path inside workspace / target repo
    function_signature      full function signature string (may be empty for regex fallback)
    function_name           function name (short)
    attack_class            attack class id from ranker / renderer
    question                hacker question text
    question_source         "corpus-derived" | "curated-library" | "economic-primitive"
    corpus_provenance       source_record_id or shape_class or primitive id
    state                   "open" | "answered" | "killed" | "promoted_to_chain"
                            | "promoted_to_poc"
    source_refs             list[str] -- corpus record ids or file:line refs
    local_verification_cmd  suggested verification command string
    operator_notes          free-form string (default "")
    created_at_utc          ISO-8601 creation timestamp
    updated_at_utc          ISO-8601 last-update timestamp
    context_pack_id         MCP context pack id at injection time

CLI:
    python3 tools/hacker-question-obligations.py append  <ws> <payload_json>
    python3 tools/hacker-question-obligations.py query   <ws> [--state open] [--json]
    python3 tools/hacker-question-obligations.py update  <ws> <obligation_id> --state killed
                                                         [--notes "reason"]
    python3 tools/hacker-question-obligations.py ingest-injection <ws> <injection_json>
        Convenience: parse a pre-source-read injection JSON payload and bulk-append
        every function's hacker questions as open obligations.
    python3 tools/hacker-question-obligations.py gate-draft <ws> <draft.md>
        Fail if the draft references a still-open obligation.
    python3 tools/hacker-question-obligations.py gate-source-read-receipts <ws> <draft.md>
        Strict helper: fail if cited production source files lack a
        source-read receipt or hacker-question obligation.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA = "auditooor.hacker_question_obligation.v1"
DRAFT_GATE_SCHEMA = "auditooor.hacker_question_obligation_draft_gate.v1"
SOURCE_READ_RECEIPT_SCHEMA = "auditooor.source_read_receipt.v1"
SOURCE_READ_RECEIPT_GATE_SCHEMA = "auditooor.source_read_receipt_draft_gate.v1"
VALID_STATES = frozenset(
    ["open", "answered", "killed", "promoted_to_chain", "promoted_to_poc"]
)
HIGH_SIGNAL_STATES = frozenset(["open"])
# States that are eligible for exploit-queue ingest
INGEST_STATES = frozenset(["open"])
REPO_ROOT = Path(__file__).resolve().parent.parent
CORPUS_INDEX_MANIFEST_PATH = REPO_ROOT / "audit" / "corpus_tags" / "index" / "manifest.json"
DEDUP_PRESERVE_FIELDS = frozenset(
    {
        "schema",
        "obligation_id",
        "workspace",
        "file",
        "function_signature",
        "question",
        "state",
        "created_at_utc",
    }
)


# ---------------------------------------------------------------------------
# Obligation ID
# ---------------------------------------------------------------------------


def _obligation_id(workspace: str, file: str, function_signature: str, question: str) -> str:
    """Stable 12-char hex id for deduplication.

    Keyed on (workspace, file, function_signature, question) so different
    questions on the same function produce distinct obligations.
    """
    key = json.dumps(
        [workspace, file, function_signature, question],
        sort_keys=True,
        ensure_ascii=True,
    )
    return hashlib.sha256(key.encode()).hexdigest()[:12]


# ---------------------------------------------------------------------------
# Obligation path
# ---------------------------------------------------------------------------


def _obligations_path(ws: Path) -> Path:
    return ws / ".auditooor" / "hacker_question_obligations.jsonl"


def _source_read_receipts_path(ws: Path) -> Path:
    return ws / ".auditooor" / "source_read_receipts.jsonl"


# ---------------------------------------------------------------------------
# Load / save
# ---------------------------------------------------------------------------


def load_obligations(ws: Path) -> list[dict[str, Any]]:
    """Load all obligations from the jsonl file.  Returns [] if absent."""
    p = _obligations_path(ws)
    if not p.exists():
        return []
    rows: list[dict[str, Any]] = []
    try:
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    except Exception:
        pass
    return rows


def load_source_read_receipts(ws: Path) -> list[dict[str, Any]]:
    """Load source-read receipt rows. Returns [] if absent or unreadable."""
    p = _source_read_receipts_path(ws)
    if not p.exists():
        return []
    rows: list[dict[str, Any]] = []
    try:
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    except Exception:
        pass
    return rows


def save_obligations(ws: Path, rows: list[dict[str, Any]]) -> None:
    """Write obligations to jsonl, one row per line."""
    p = _obligations_path(ws)
    p.parent.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps(r, ensure_ascii=False, sort_keys=True) for r in rows]
    p.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def append_source_read_receipt(ws: Path, row: dict[str, Any]) -> None:
    """Append one source-read receipt row to the workspace JSONL ledger."""
    p = _source_read_receipts_path(ws)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def _source_file_snapshot(path: Path) -> dict[str, Any] | None:
    """Return stable source metadata for an existing regular file."""
    try:
        if not path.is_file():
            return None
        stat = path.stat()
        return {
            "source_path": str(path),
            "source_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "source_mtime_ns": stat.st_mtime_ns,
            "source_size_bytes": stat.st_size,
        }
    except Exception:
        return None


def _source_snapshot_for_paths(
    ws: Path, file_path: str, absolute_file_path: str
) -> dict[str, Any] | None:
    candidates: list[Path] = []
    if file_path:
        candidates.append(ws / file_path)
    if absolute_file_path:
        candidates.append(Path(absolute_file_path))
    for candidate in candidates:
        snapshot = _source_file_snapshot(candidate)
        if snapshot is not None:
            return snapshot
    return None


def _display_repo_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(REPO_ROOT.resolve()).as_posix()
    except (OSError, ValueError):
        return str(path)


def _corpus_index_manifest_snapshot() -> dict[str, Any]:
    path = CORPUS_INDEX_MANIFEST_PATH
    base = {
        "corpus_index_hash": "",
        "corpus_index_manifest": _display_repo_path(path),
        "corpus_index_hash_status": "missing_manifest",
    }
    if not path.is_file():
        return base
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {**base, "corpus_index_hash_status": "invalid_manifest"}
    if not isinstance(payload, dict):
        return {**base, "corpus_index_hash_status": "invalid_manifest"}
    index_hash = str(payload.get("corpus_index_hash") or "").strip()
    if not re.fullmatch(r"[0-9a-fA-F]{64}", index_hash):
        return {**base, "corpus_index_hash_status": "invalid_manifest"}
    return {
        "corpus_index_hash": index_hash.lower(),
        "corpus_index_manifest": _display_repo_path(path),
        "corpus_index_hash_status": "present",
        "corpus_index_manifest_schema": str(payload.get("schema", "")),
    }


# ---------------------------------------------------------------------------
# Core operations
# ---------------------------------------------------------------------------


def _now_utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_obligation(
    workspace: str,
    file: str,
    function_signature: str,
    function_name: str,
    attack_class: str,
    question: str,
    question_source: str = "corpus-derived",
    language: str = "",
    corpus_provenance: str = "",
    source_refs: list[str] | None = None,
    local_verification_cmd: str = "",
    operator_notes: str = "",
    context_pack_id: str = "",
    proof_gate: str = "",
    claim_boundary: str = "",
    proof_obligation: str = "",
    kill_condition: str = "",
    function_shape: str = "",
    function_shape_fine: str = "",
    reasoning_axis: str = "",
    rationale: str = "",
    economic_primitive: str = "",
    economic_category: str = "",
    profit_source: str = "",
    incident_anchor: str = "",
    state: str = "open",
) -> dict[str, Any]:
    """Build a single obligation dict (not yet persisted)."""
    oid = _obligation_id(workspace, file, function_signature, question)
    now = _now_utc()
    return {
        "schema": SCHEMA,
        "obligation_id": oid,
        "workspace": workspace,
        "file": file,
        "function_signature": function_signature,
        "function_name": function_name,
        "language": language,
        "attack_class": attack_class,
        "question": question,
        "question_source": question_source,
        "corpus_provenance": corpus_provenance,
        "state": state if state in VALID_STATES else "open",
        "source_refs": source_refs or [],
        "local_verification_cmd": local_verification_cmd,
        "operator_notes": operator_notes,
        "proof_gate": proof_gate,
        "claim_boundary": claim_boundary,
        "proof_obligation": proof_obligation,
        "kill_condition": kill_condition,
        "function_shape": function_shape,
        "function_shape_fine": function_shape_fine,
        "reasoning_axis": reasoning_axis,
        "rationale": rationale,
        "economic_primitive": economic_primitive,
        "economic_category": economic_category,
        "profit_source": profit_source,
        "incident_anchor": incident_anchor,
        "created_at_utc": now,
        "updated_at_utc": now,
        "context_pack_id": context_pack_id,
    }


def append_obligations(
    ws: Path, new_rows: list[dict[str, Any]], *, dry_run: bool = False
) -> dict[str, int]:
    """Idempotently append obligations to the jsonl.

    Deduplicates by ``obligation_id``. Existing rows with matching ids keep
    their identity and lifecycle state, but may be enriched with missing
    proof/context metadata from newer appends.

    Returns a summary dict: {"appended": N, "skipped_duplicate": M}.
    """
    existing = load_obligations(ws)
    existing_by_id = {r["obligation_id"]: r for r in existing if "obligation_id" in r}
    existing_ids = set(existing_by_id)

    appended = 0
    skipped = 0
    merged = 0
    to_add: list[dict[str, Any]] = []
    for row in new_rows:
        oid = row.get("obligation_id", "")
        if not oid:
            oid = _obligation_id(
                row.get("workspace", ""),
                row.get("file", ""),
                row.get("function_signature", ""),
                row.get("question", ""),
            )
            row = dict(row)
            row["obligation_id"] = oid
        if oid in existing_ids:
            skipped += 1
            if _merge_obligation_context(existing_by_id.get(oid, {}), row):
                merged += 1
        else:
            existing_ids.add(oid)
            existing_by_id[oid] = row
            to_add.append(row)
            appended += 1

    if not dry_run and (to_add or merged):
        save_obligations(ws, existing + to_add)

    return {"appended": appended, "skipped_duplicate": skipped, "merged_duplicate": merged}


def _is_empty_obligation_value(value: Any) -> bool:
    return value is None or value == "" or value == [] or value == {}


def _merge_obligation_context(existing: dict[str, Any], incoming: dict[str, Any]) -> bool:
    """Enrich duplicate obligations without changing identity or lifecycle state."""
    if not existing:
        return False
    changed = False
    for key, value in incoming.items():
        if key in DEDUP_PRESERVE_FIELDS or key == "updated_at_utc":
            continue
        if _is_empty_obligation_value(value):
            continue
        current = existing.get(key)
        if isinstance(current, list) and isinstance(value, list):
            merged_list = list(dict.fromkeys([*current, *value]))
            if merged_list != current:
                existing[key] = merged_list
                changed = True
        elif isinstance(current, dict) and isinstance(value, dict):
            merged_dict = dict(current)
            for subkey, subvalue in value.items():
                if _is_empty_obligation_value(merged_dict.get(subkey)) and not _is_empty_obligation_value(subvalue):
                    merged_dict[subkey] = subvalue
            if merged_dict != current:
                existing[key] = merged_dict
                changed = True
        elif _is_empty_obligation_value(current):
            existing[key] = value
            changed = True
    if changed:
        existing["updated_at_utc"] = _now_utc()
    return changed


def query_obligations(
    ws: Path,
    state: str | None = None,
    attack_class: str | None = None,
    file: str | None = None,
) -> list[dict[str, Any]]:
    """Return obligations filtered by optional criteria."""
    rows = load_obligations(ws)
    if state:
        rows = [r for r in rows if r.get("state") == state]
    if attack_class:
        rows = [r for r in rows if r.get("attack_class", "").lower() == attack_class.lower()]
    if file:
        rows = [r for r in rows if r.get("file", "") == file]
    return rows


def update_obligation(
    ws: Path,
    obligation_id: str,
    *,
    state: str | None = None,
    operator_notes: str | None = None,
    local_verification_cmd: str | None = None,
) -> bool:
    """Update a single obligation's mutable fields.

    Returns True if the obligation was found and updated, False if not found.
    State must be one of VALID_STATES; invalid states are rejected.
    """
    if state is not None and state not in VALID_STATES:
        raise ValueError(
            f"invalid state {state!r}; must be one of {sorted(VALID_STATES)}"
        )
    rows = load_obligations(ws)
    found = False
    for row in rows:
        if row.get("obligation_id") == obligation_id:
            if state is not None:
                row["state"] = state
            if operator_notes is not None:
                row["operator_notes"] = operator_notes
            if local_verification_cmd is not None:
                row["local_verification_cmd"] = local_verification_cmd
            row["updated_at_utc"] = _now_utc()
            found = True
            break
    if found:
        save_obligations(ws, rows)
    return found


# ---------------------------------------------------------------------------
# Injection payload ingest
# ---------------------------------------------------------------------------


def _local_verification_cmd_for(attack_class: str, file: str, fn_name: str) -> str:
    """Suggest a grep-based verification command for an open obligation."""
    ext = Path(file).suffix.lower()
    if ext == ".sol":
        return f"grep -n '{fn_name}' {file}"
    if ext in (".go", ".rs", ".ts"):
        return f"grep -n '{fn_name}' {file}"
    return f"grep -rn '{fn_name}' {file}"


def ingest_injection_payload(
    ws: Path,
    payload: dict[str, Any],
    workspace_str: str | None = None,
) -> dict[str, int]:
    """Parse a pre-source-read injection payload and bulk-append obligations.

    Each function entry in ``payload["functions"]`` contributes one obligation
    per hacker question.  Questions are tagged ``open`` at ingest.

    Returns the same summary as ``append_obligations``.
    """
    ws_str = workspace_str or str(ws)
    file_path = str(payload.get("file_path", ""))
    context_pack_id = str(payload.get("context_pack_id", ""))

    new_rows: list[dict[str, Any]] = []
    for fn in payload.get("functions", []):
        if not isinstance(fn, dict):
            continue
        fn_name = str(fn.get("name", ""))
        fn_sig = str(fn.get("function_signature", "")) or fn_name
        # Build attack-class lookup from top_attack_classes
        ac_by_class_id: dict[str, dict] = {}
        for ac in fn.get("top_attack_classes", []):
            cid = str(ac.get("class_id", ""))
            if cid:
                ac_by_class_id[cid] = ac

        for q in fn.get("hacker_questions", []):
            if not isinstance(q, dict):
                continue
            question_text = str(q.get("question", "")).strip()
            if not question_text:
                continue

            attack_class = (
                str(q.get("attack_class", "")).strip()
                or str(q.get("shape_class", "")).strip()
                or str(q.get("economic_primitive", "")).strip()
            )
            question_source = str(q.get("question_source", "corpus-derived"))
            # corpus_provenance: prefer source_record_id, then shape_class, then economic_primitive
            corpus_provenance = (
                str(q.get("source_record_id", "")).strip()
                or str(q.get("shape_class", "")).strip()
                or str(q.get("economic_primitive", "")).strip()
            )
            source_refs = []
            if corpus_provenance:
                source_refs = [corpus_provenance]

            local_cmd = _local_verification_cmd_for(attack_class, file_path, fn_name)

            row = make_obligation(
                workspace=ws_str,
                file=file_path,
                function_signature=fn_sig,
                function_name=fn_name,
                attack_class=attack_class,
                question=question_text,
                question_source=question_source,
                corpus_provenance=corpus_provenance,
                source_refs=source_refs,
                local_verification_cmd=local_cmd,
                operator_notes="",
                context_pack_id=context_pack_id,
                proof_gate=str(q.get("proof_gate", "")),
                claim_boundary=str(q.get("claim_boundary", "")),
                proof_obligation=str(q.get("proof_obligation", "")),
                kill_condition=str(q.get("kill_condition", "")),
                function_shape=str(q.get("function_shape", "") or fn.get("shape_hash", "")),
                function_shape_fine=str(q.get("function_shape_fine", "") or fn.get("shape_hash_fine", "")),
                reasoning_axis=str(q.get("reasoning_axis", "")),
                rationale=str(q.get("rationale", "")),
                economic_primitive=str(q.get("economic_primitive", "")),
                economic_category=str(q.get("economic_category", "")),
                profit_source=str(q.get("profit_source", "")),
                incident_anchor=str(q.get("incident_anchor", "")),
                state="open",
            )
            new_rows.append(row)

    return append_obligations(ws, new_rows)


def _normalized_path_variants(path: str) -> set[str]:
    """Return conservative comparable variants for source paths."""
    raw = str(path or "").strip().strip("`'\"")
    if not raw:
        return set()
    raw = raw.replace("\\", "/")
    variants = {raw.lstrip("./")}
    try:
        p = Path(raw)
        variants.add(str(p).replace("\\", "/").lstrip("./"))
        variants.add(p.name)
    except Exception:
        pass
    return {v for v in variants if v}


def _paths_match(a: str, b: str) -> bool:
    left = str(a or "").strip().strip("`'\"").replace("\\", "/").lstrip("./")
    right = str(b or "").strip().strip("`'\"").replace("\\", "/").lstrip("./")
    if not left or not right:
        return False
    if left == right or left.endswith("/" + right) or right.endswith("/" + left):
        return True
    # Basename-only citations are common in drafts. Allow them, but do not let
    # two different explicit directories match only because the filename agrees.
    if "/" not in left or "/" not in right:
        av = _normalized_path_variants(left)
        bv = _normalized_path_variants(right)
        if av & bv:
            return True
    return False


def record_source_read_receipt(
    ws: Path,
    payload: dict[str, Any],
    workspace_str: str | None = None,
) -> dict[str, Any]:
    """Persist a durable source-read receipt for one injection payload.

    This is intentionally separate from obligations: files with no rendered
    hacker questions still prove that the pre-source-read hook ran.
    """
    ws_str = workspace_str or str(ws)
    file_path = str(payload.get("file_path", "")).strip()
    absolute_file_path = str(payload.get("absolute_file_path", "")).strip()
    function_names = [
        str(fn.get("name", "")).strip()
        for fn in payload.get("functions", [])
        if isinstance(fn, dict) and str(fn.get("name", "")).strip()
    ]
    functions = [fn for fn in payload.get("functions", []) if isinstance(fn, dict)]
    hacker_question_count = 0
    question_counts_by_source: dict[str, int] = {}
    corpus_backed_hypothesis_count = 0
    for fn in functions:
        questions = fn.get("hacker_questions") if isinstance(fn.get("hacker_questions"), list) else []
        hacker_question_count += len(questions)
        for question in questions:
            if not isinstance(question, dict):
                continue
            source = str(question.get("question_source") or "unknown").strip() or "unknown"
            question_counts_by_source[source] = question_counts_by_source.get(source, 0) + 1
        hypotheses = fn.get("corpus_backed_hypotheses")
        if isinstance(hypotheses, list):
            corpus_backed_hypothesis_count += len(hypotheses)
    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    no_questions_reason = str(summary.get("no_questions_reason", "")).strip()
    if not no_questions_reason and hacker_question_count == 0:
        skipped = [str(item) for item in (payload.get("skipped_reasons") or []) if str(item)]
        no_questions_reason = "; ".join(skipped) if skipped else "renderer-produced-zero-questions"
    receipt_key = json.dumps(
        [ws_str, file_path, absolute_file_path, payload.get("context_pack_id", "")],
        sort_keys=True,
        ensure_ascii=True,
    )
    row = {
        "schema": SOURCE_READ_RECEIPT_SCHEMA,
        "receipt_id": hashlib.sha256(receipt_key.encode()).hexdigest()[:12],
        "workspace": ws_str,
        "file": file_path,
        "absolute_file_path": absolute_file_path,
        "target_repo": str(payload.get("target_repo", "")),
        "language": str(payload.get("language", "")),
        "functions_analyzed": int(payload.get("functions_analyzed", 0) or 0),
        "function_names": function_names[:50],
        "context_pack_id": str(payload.get("context_pack_id", "")),
        "context_pack_hash": str(payload.get("context_pack_hash", "")),
        "hacker_question_count": int(summary.get("hacker_question_count", hacker_question_count) or 0),
        "hacker_question_counts_by_source": (
            summary.get("hacker_question_counts_by_source")
            if isinstance(summary.get("hacker_question_counts_by_source"), dict)
            else question_counts_by_source
        ),
        "corpus_backed_hypothesis_count": int(
            summary.get("corpus_backed_hypothesis_count", corpus_backed_hypothesis_count) or 0
        ),
        "no_questions_reason": no_questions_reason,
        "source_injection_schema": str(payload.get("schema", "")),
        "skipped_reasons": [
            str(item) for item in (payload.get("skipped_reasons") or [])[:20]
        ],
        "created_at_utc": _now_utc(),
    }
    row.update(_corpus_index_manifest_snapshot())
    snapshot = _source_snapshot_for_paths(ws, file_path, absolute_file_path)
    if snapshot is not None:
        row.update(snapshot)
    append_source_read_receipt(ws, row)
    return row


# ---------------------------------------------------------------------------
# Exploit-queue ingest helper (called by exploit-queue.py)
# ---------------------------------------------------------------------------


def gather_open_obligations_as_queue_rows(ws: Path) -> list[dict[str, Any]]:
    """Return exploit-queue base-row dicts for high-signal open obligations.

    Gracefully returns [] if the obligations file is absent.
    Mirrors the shape expected by exploit-queue._make_base_row().
    """
    obligations_path = _obligations_path(ws)
    if not obligations_path.exists():
        return []

    open_rows = query_obligations(ws, state="open")
    if not open_rows:
        return []

    queue_rows: list[dict[str, Any]] = []
    for ob in open_rows:
        attack_class = str(ob.get("attack_class", "unknown")).strip() or "unknown"
        fn_name = str(ob.get("function_name", "")).strip()
        file_path = str(ob.get("file", "")).strip()
        question = str(ob.get("question", "")).strip()
        fn_sig = str(ob.get("function_signature", "")).strip()
        obligation_id = str(ob.get("obligation_id", "")).strip()

        # Title: bounded at 120 chars
        title_base = f"[obligation:{obligation_id}] {attack_class}: {fn_name or file_path}"
        title = title_base[:120]

        # Source refs: corpus_provenance + obligation_id
        source_refs: list[str] = [r for r in ob.get("source_refs", []) if r]
        if obligation_id and obligation_id not in source_refs:
            source_refs.append(f"obligation:{obligation_id}")
        source_refs = source_refs[:4]

        local_cmd = str(ob.get("local_verification_cmd", "")).strip()
        next_cmd = local_cmd or f"grep -n '{fn_name}' {file_path}"

        # Build an exploit-queue compatible row dict
        row: dict[str, Any] = {
            "lead_id": "",  # assigned later by exploit-queue
            "title": title,
            "source_refs": source_refs,
            "source_artifacts_complete": False,
            "source_artifact_gaps": ["attacker_control", "impact_path", "proof_shell"],
            "quality_gate_status": "needs_source",
            "attack_class": attack_class,
            "likely_severity": "unknown",
            "severity_confidence": "low",
            "attacker_control": "missing",
            "impact_path": "unknown",
            "proof_path": "missing",
            "proof_artifact_precedent_refs": [],
            "metric_integrity_refs": [],
            "learning_route": "mine-source",
            "next_command": next_cmd[:200],
            "blockers": [
                f"Answer obligation {obligation_id}: {question[:80]}",
            ],
            "dupe_risk": "unknown",
            "priority_score": 0.0,
            "_truth_table": {},
            "_impact_contract_status": "unknown",
            "_impact_contract_gaps": [],
            # Lane-5-specific tag (stripped by _strip_internals in exploit-queue)
            "_obligation_id": obligation_id,
            "_obligation_source": "hacker_question_obligations",
        }
        # Functional signature note for context
        if fn_sig:
            row["blockers"].append(f"Function: {fn_sig[:100]}")
        queue_rows.append(row)

    return queue_rows


# ---------------------------------------------------------------------------
# Draft gate
# ---------------------------------------------------------------------------


def _token_present(text: str, token: str) -> bool:
    token = str(token or "").strip()
    if not token:
        return False
    pattern = r"(?<![A-Za-z0-9_])" + re.escape(token) + r"(?![A-Za-z0-9_])"
    return re.search(pattern, text) is not None


def _obligation_draft_match_reasons(ob: dict[str, Any], draft_text: str) -> list[str]:
    """Return deterministic reasons that tie an obligation to a draft."""
    reasons: list[str] = []

    obligation_id = str(ob.get("obligation_id", "")).strip()
    if obligation_id and (
        f"obligation:{obligation_id}" in draft_text
        or _token_present(draft_text, obligation_id)
    ):
        reasons.append("obligation_id")

    fn_sig = str(ob.get("function_signature", "")).strip()
    if fn_sig and fn_sig in draft_text:
        reasons.append("function_signature")

    file_path = str(ob.get("file", "")).strip()
    fn_name = str(ob.get("function_name", "")).strip()
    if file_path and fn_name and file_path in draft_text and _token_present(draft_text, fn_name):
        reasons.append("file_and_function_name")

    return reasons


def matching_open_obligations_for_text(
    ws: Path,
    text: str,
    *,
    changed_artifacts: list[str] | None = None,
    limit: int = 20,
) -> list[dict[str, Any]]:
    """Return open obligations deterministically matched by text/artifacts."""
    combined_text = text
    if changed_artifacts:
        combined_text += "\n" + "\n".join(str(item) for item in changed_artifacts)

    matches: list[dict[str, Any]] = []
    for ob in query_obligations(ws, state="open"):
        reasons = _obligation_draft_match_reasons(ob, combined_text)
        if not reasons:
            continue
        matches.append(
            {
                "obligation_id": str(ob.get("obligation_id", "")),
                "state": str(ob.get("state", "")),
                "file": str(ob.get("file", "")),
                "function_name": str(ob.get("function_name", "")),
                "function_signature": str(ob.get("function_signature", "")),
                "attack_class": str(ob.get("attack_class", "")),
                "question": str(ob.get("question", ""))[:240],
                "match_reasons": reasons,
            }
        )
    return matches[: max(limit, 0)]


def gate_draft_obligations(ws: Path, draft_path: Path) -> dict[str, Any]:
    """Fail when a draft still matches open hacker-question obligations.

    This is intentionally narrow: a draft is blocked only when it explicitly
    references an obligation id, an exact function signature, or an exact
    file/function pair.  Broad attack-class matching stays advisory to avoid
    false blocks on unrelated findings.
    """
    try:
        draft_text = draft_path.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        return {
            "schema": DRAFT_GATE_SCHEMA,
            "status": "error",
            "workspace": str(ws),
            "draft_path": str(draft_path),
            "errors": [{"code": "draft_read_failed", "message": str(exc)}],
            "counts": {"total_obligations": len(load_obligations(ws)), "blocking": 0},
            "blocking_obligations": [],
        }

    rows = load_obligations(ws)
    considered = [row for row in rows if row.get("state") in HIGH_SIGNAL_STATES]
    blocking = matching_open_obligations_for_text(ws, draft_text)

    return {
        "schema": DRAFT_GATE_SCHEMA,
        "status": "fail" if blocking else "pass",
        "workspace": str(ws),
        "draft_path": str(draft_path),
        "errors": [],
        "counts": {
            "total_obligations": len(rows),
            "high_signal_considered": len(considered),
            "blocking": len(blocking),
        },
        "blocking_obligations": blocking,
    }


SOURCE_EXTENSIONS = (".sol", ".go", ".rs", ".ts", ".py")
SOURCE_PATH_RE = re.compile(
    r"(?P<path>(?:[A-Za-z0-9_.@+-]+/)*[A-Za-z0-9_.@+-]+"
    r"(?:\.sol|\.go|\.rs|\.ts|\.py))"
)
NON_PRODUCTION_PATH_PARTS = {
    ".auditooor",
    "audit",
    "docs",
    "fork_replay",
    "node_modules",
    "poc",
    "poc-tests",
    "poc_execution",
    "prior_audits",
    "reports",
    "scope_review",
    "submissions",
    "test",
    "tests",
}


def _is_probable_production_source_path(path: str) -> bool:
    p = path.strip().strip("`'\"").replace("\\", "/").lstrip("./")
    if not p.endswith(SOURCE_EXTENSIONS):
        return False
    parts = [part.lower() for part in p.split("/") if part]
    if any(part in NON_PRODUCTION_PATH_PARTS for part in parts):
        return False
    name = Path(p).name.lower()
    if (
        name.endswith("_test.go")
        or name.endswith(".t.sol")
        or name.endswith("_test.rs")
        or name.endswith("_test.ts")
        or name.startswith("test_")
    ):
        return False
    return True


def extract_cited_source_files(text: str) -> list[str]:
    """Extract cited production source files from markdown-ish draft text."""
    seen: set[str] = set()
    out: list[str] = []
    for match in SOURCE_PATH_RE.finditer(text):
        path = match.group("path").strip().strip("`'\"")
        if not _is_probable_production_source_path(path):
            continue
        key = path.replace("\\", "/").lstrip("./")
        if key in seen:
            continue
        seen.add(key)
        out.append(key)
    return out


def _source_read_receipt_for_file(
    ws: Path,
    receipts: list[dict[str, Any]],
    obligations: list[dict[str, Any]],
    cited_file: str,
) -> dict[str, Any] | None:
    # Receipts are an append-only JSONL ledger loaded oldest-first. A single
    # cited file may have several read receipts (e.g. an early read that went
    # stale after the source was re-pinned, plus a later re-read against the
    # current bytes). Selecting the FIRST (oldest) path-match spuriously FAILs
    # the gate as `stale_receipt` even when a newer current-hash match proves
    # the current source bytes were read (#81). Prefer the NEWEST current-hash
    # match; if none exists, fall back to the newest matching receipt so an
    # all-stale history still surfaces the stale/mismatch state and FAILs.
    # This reads the ledger only - it does not mutate the append-only file.
    newest_match: dict[str, Any] | None = None
    newest_any: dict[str, Any] | None = None
    for row in receipts:
        if _paths_match(str(row.get("file", "")), cited_file) or _paths_match(
            str(row.get("absolute_file_path", "")), cited_file
        ):
            source_sha256 = str(row.get("source_sha256", "")).strip()
            hash_status = "missing_legacy_hash"
            snapshot = None
            if source_sha256:
                snapshot = _source_snapshot_for_paths(
                    ws,
                    str(row.get("file", "")),
                    str(row.get("absolute_file_path", "")),
                )
                if snapshot is None:
                    hash_status = "current_source_missing"
                elif snapshot.get("source_sha256") == source_sha256:
                    hash_status = "match"
                else:
                    hash_status = "mismatch"
            resolved = {
                "kind": "source_read_receipt",
                "receipt_id": str(row.get("receipt_id", "")),
                "file": str(row.get("file", "")),
                "functions_analyzed": row.get("functions_analyzed", 0),
                "created_at_utc": str(row.get("created_at_utc", "")),
                "hash_status": hash_status,
                "source_path": str(snapshot.get("source_path", "")) if source_sha256 and snapshot else "",
            }
            # Ledger is oldest-first, so later iterations are newer: overwrite to
            # keep the newest candidate in each bucket.
            newest_any = resolved
            if hash_status == "match":
                newest_match = resolved
    if newest_match is not None:
        return newest_match
    if newest_any is not None:
        return newest_any
    for row in obligations:
        if _paths_match(str(row.get("file", "")), cited_file):
            return {
                "kind": "hacker_question_obligation",
                "obligation_id": str(row.get("obligation_id", "")),
                "file": str(row.get("file", "")),
                "state": str(row.get("state", "")),
                "created_at_utc": str(row.get("created_at_utc", "")),
            }
    return None


def gate_draft_source_read_receipts(
    ws: Path,
    draft_path: Path,
    *,
    extra_source_files: list[str] | None = None,
) -> dict[str, Any]:
    """Strict helper: every cited production source file needs a receipt.

    The pre-submit check calls this only when explicitly requested, so existing
    drafts remain compatible by default.
    """
    try:
        draft_text = draft_path.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        return {
            "schema": SOURCE_READ_RECEIPT_GATE_SCHEMA,
            "status": "error",
            "workspace": str(ws),
            "draft_path": str(draft_path),
            "errors": [{"code": "draft_read_failed", "message": str(exc)}],
            "counts": {"cited_source_files": 0, "with_receipts": 0, "missing_receipts": 0},
            "cited_source_files": [],
            "missing_receipts": [],
        }

    cited = extract_cited_source_files(draft_text)
    for extra in extra_source_files or []:
        path = str(extra).strip().strip("`'\"").replace("\\", "/").lstrip("./")
        if path and path not in cited:
            cited.append(path)
    receipts = load_source_read_receipts(ws)
    obligations = load_obligations(ws)
    rows: list[dict[str, Any]] = []
    missing: list[str] = []
    stale: list[str] = []
    for cited_file in cited:
        receipt = _source_read_receipt_for_file(ws, receipts, obligations, cited_file)
        if receipt is None:
            missing.append(cited_file)
            rows.append({"file": cited_file, "status": "missing_receipt"})
        elif (
            receipt.get("kind") == "source_read_receipt"
            and receipt.get("hash_status") in {"mismatch", "current_source_missing"}
        ):
            stale.append(cited_file)
            rows.append({"file": cited_file, "status": "stale_receipt", "receipt": receipt})
        else:
            rows.append({"file": cited_file, "status": "receipt_found", "receipt": receipt})

    return {
        "schema": SOURCE_READ_RECEIPT_GATE_SCHEMA,
        "status": "fail" if missing or stale else "pass",
        "workspace": str(ws),
        "draft_path": str(draft_path),
        "errors": [],
        "counts": {
            "cited_source_files": len(cited),
            "with_receipts": len(cited) - len(missing) - len(stale),
            "missing_receipts": len(missing),
            "stale_receipts": len(stale),
            "source_read_receipts": len(receipts),
            "hacker_question_obligations": len(obligations),
        },
        "cited_source_files": rows,
        "missing_receipts": missing,
        "stale_receipts": stale,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _cmd_append(args: argparse.Namespace) -> int:
    ws = Path(args.workspace).expanduser().resolve()
    try:
        row_dict = json.loads(args.payload_json)
    except Exception as exc:
        print(f"ERROR: invalid JSON payload: {exc}", file=sys.stderr)
        return 1
    if not isinstance(row_dict, dict):
        print("ERROR: payload must be a JSON object", file=sys.stderr)
        return 1
    # Build a proper obligation
    obligation = make_obligation(
        workspace=str(ws),
        file=str(row_dict.get("file", "")),
        function_signature=str(row_dict.get("function_signature", "")),
        function_name=str(row_dict.get("function_name", "")),
        attack_class=str(row_dict.get("attack_class", "")),
        question=str(row_dict.get("question", "")),
        question_source=str(row_dict.get("question_source", "corpus-derived")),
        corpus_provenance=str(row_dict.get("corpus_provenance", "")),
        source_refs=row_dict.get("source_refs") or [],
        local_verification_cmd=str(row_dict.get("local_verification_cmd", "")),
        operator_notes=str(row_dict.get("operator_notes", "")),
        context_pack_id=str(row_dict.get("context_pack_id", "")),
        proof_gate=str(row_dict.get("proof_gate", "")),
        claim_boundary=str(row_dict.get("claim_boundary", "")),
        proof_obligation=str(row_dict.get("proof_obligation", "")),
        kill_condition=str(row_dict.get("kill_condition", "")),
        function_shape=str(row_dict.get("function_shape", "")),
        function_shape_fine=str(row_dict.get("function_shape_fine", "")),
        reasoning_axis=str(row_dict.get("reasoning_axis", "")),
        rationale=str(row_dict.get("rationale", "")),
        economic_primitive=str(row_dict.get("economic_primitive", "")),
        economic_category=str(row_dict.get("economic_category", "")),
        profit_source=str(row_dict.get("profit_source", "")),
        incident_anchor=str(row_dict.get("incident_anchor", "")),
        state=str(row_dict.get("state", "open")),
    )
    obligation = {**row_dict, **obligation}
    result = append_obligations(ws, [obligation])
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(
            f"[obligations] appended={result['appended']} "
            f"skipped_duplicate={result['skipped_duplicate']}"
        )
    return 0


def _cmd_query(args: argparse.Namespace) -> int:
    ws = Path(args.workspace).expanduser().resolve()
    rows = query_obligations(
        ws,
        state=args.state or None,
        attack_class=args.attack_class or None,
        file=args.file or None,
    )
    if args.json:
        print(json.dumps(rows, indent=2, ensure_ascii=False, sort_keys=True))
    else:
        print(f"[obligations] found {len(rows)} row(s)")
        for r in rows:
            print(
                f"  {r['obligation_id']} [{r['state']}] {r['attack_class']}: "
                f"{r['function_name']} @ {r['file']}"
            )
    return 0


def _cmd_update(args: argparse.Namespace) -> int:
    ws = Path(args.workspace).expanduser().resolve()
    found = update_obligation(
        ws,
        obligation_id=args.obligation_id,
        state=args.state or None,
        operator_notes=args.notes or None,
    )
    if args.json:
        print(json.dumps({"updated": found, "obligation_id": args.obligation_id}, indent=2))
    else:
        status = "updated" if found else "not found"
        print(f"[obligations] {status}: {args.obligation_id}")
    return 0 if found else 1


def _cmd_ingest_injection(args: argparse.Namespace) -> int:
    ws = Path(args.workspace).expanduser().resolve()
    try:
        payload = json.loads(args.injection_json)
    except Exception as exc:
        print(f"ERROR: invalid JSON: {exc}", file=sys.stderr)
        return 1
    result = ingest_injection_payload(ws, payload)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(
            f"[obligations] ingested injection: "
            f"appended={result['appended']} "
            f"skipped_duplicate={result['skipped_duplicate']}"
        )
    return 0


def _cmd_gate_source_read_receipts(args: argparse.Namespace) -> int:
    ws = Path(args.workspace).expanduser().resolve()
    draft_path = Path(args.draft_path).expanduser().resolve()
    result = gate_draft_source_read_receipts(ws, draft_path)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True))
    else:
        counts = result.get("counts", {})
        print(
            f"[source-read-receipts] draft gate {result['status']}: "
            f"missing={counts.get('missing_receipts', 0)} "
            f"stale={counts.get('stale_receipts', 0)} "
            f"cited={counts.get('cited_source_files', 0)}"
        )
        for item in result.get("missing_receipts", [])[:8]:
            print(f"  missing receipt: {item}")
        for item in result.get("stale_receipts", [])[:8]:
            print(f"  stale receipt: {item}")
    if result["status"] == "error":
        return 2
    return 1 if result["status"] == "fail" else 0


def _cmd_gate_draft(args: argparse.Namespace) -> int:
    ws = Path(args.workspace).expanduser().resolve()
    draft_path = Path(args.draft_path).expanduser().resolve()
    result = gate_draft_obligations(ws, draft_path)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True))
    else:
        print(
            f"[obligations] draft gate {result['status']}: "
            f"blocking={result.get('counts', {}).get('blocking', 0)}"
        )
        for ob in result.get("blocking_obligations", [])[:8]:
            print(
                f"  {ob['obligation_id']} {ob['attack_class']}: "
                f"{ob['function_name']} @ {ob['file']}"
            )
    if result["status"] == "error":
        return 2
    return 1 if result["status"] == "fail" else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Emit JSON output")
    sub = parser.add_subparsers(dest="command")

    # append
    p_append = sub.add_parser("append", help="Append a single obligation")
    p_append.add_argument("workspace", help="Workspace root path")
    p_append.add_argument("payload_json", help="JSON object with obligation fields")

    # query
    p_query = sub.add_parser("query", help="Query obligations")
    p_query.add_argument("workspace", help="Workspace root path")
    p_query.add_argument("--state", default="", help="Filter by state")
    p_query.add_argument("--attack-class", default="", help="Filter by attack class")
    p_query.add_argument("--file", default="", help="Filter by file path")

    # update
    p_update = sub.add_parser("update", help="Update an obligation's state")
    p_update.add_argument("workspace", help="Workspace root path")
    p_update.add_argument("obligation_id", help="12-char obligation id")
    p_update.add_argument("--state", default="", help="New state")
    p_update.add_argument("--notes", default="", help="Operator notes")

    # ingest-injection
    p_ingest = sub.add_parser(
        "ingest-injection",
        help="Parse a pre-source-read injection JSON and bulk-append obligations",
    )
    p_ingest.add_argument("workspace", help="Workspace root path")
    p_ingest.add_argument("injection_json", help="JSON string of injection payload")

    # gate-draft
    p_gate = sub.add_parser(
        "gate-draft",
        help="Fail if a draft references an unresolved hacker-question obligation",
    )
    p_gate.add_argument("workspace", help="Workspace root path")
    p_gate.add_argument("draft_path", help="Draft markdown path")

    # gate-source-read-receipts
    p_source_gate = sub.add_parser(
        "gate-source-read-receipts",
        help="Strictly fail if cited production source files lack a source-read receipt",
    )
    p_source_gate.add_argument("workspace", help="Workspace root path")
    p_source_gate.add_argument("draft_path", help="Draft markdown path")

    args = parser.parse_args(argv)

    if args.command == "append":
        return _cmd_append(args)
    if args.command == "query":
        return _cmd_query(args)
    if args.command == "update":
        return _cmd_update(args)
    if args.command == "ingest-injection":
        return _cmd_ingest_injection(args)
    if args.command == "gate-draft":
        return _cmd_gate_draft(args)
    if args.command == "gate-source-read-receipts":
        return _cmd_gate_source_read_receipts(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
