#!/usr/bin/env python3
"""Build bounded offline V3 worker packets with local evidence receipts."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable, Sequence

TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

from lib.mcp_evidence_receipt import (  # noqa: E402
    LEGACY_SCHEMA as MCP_EVIDENCE_LEGACY_SCHEMA,
    SCHEMA as MCP_EVIDENCE_SCHEMA,
    build_receipt as build_mcp_evidence_receipt,
)


SCHEMA = "auditooor.v3_worker_packet.v1"
LESSON_PACK_REASON_PREFIX = "NO_LESSON_PACK_REASON:"
MAX_CONTEXT_REFS = 24
MAX_SOURCE_FILES = 80
MAX_OBLIGATIONS = 80
MAX_COMMANDS = 32
MAX_TEXT = 700
AUTO_WORKSPACE_RECEIPTS = (
    ".auditooor/memory_context_receipt.json",
    ".auditooor/brain_prime_receipt.json",
    ".auditooor/hacker_brief.md.json",
    ".auditooor/hacker_brief.hackerman.json",
    ".auditooor/last_mcp_recall.json",
    ".auditooor/prefiling_stress_test.json",
    ".auditooor/prior_disclosure_index.json",
    ".auditooor/agent_artifact_lesson_candidates.json",
    ".auditooor/source_read_receipts.jsonl",
    ".auditooor/hacker_question_obligations.jsonl",
)
LOCAL_PATH_KEYS = {
    "artifact_path",
    "candidate_artifact_path",
    "draft_path",
    "exec_record_path",
    "file",
    "file_path",
    "manifest_path",
    "path",
    "record_path",
    "report_path",
    "source_path",
    "source_ref",
    "workspace_path",
}
REMOTE_REF_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)
LINE_SUFFIX_RE = re.compile(r"(?P<path>.+?)(?::(?P<line>[1-9][0-9]*))?$")
NETWORK_COMMAND_RE = re.compile(
    r"(^|\s)(curl|wget|gh|ssh|scp|rsync)\b|"
    r"\bgit\s+(fetch|pull|push|ls-remote|clone|submodule\s+update)\b|"
    r"https?://",
    re.IGNORECASE,
)
HIGH_CRITICAL_RE = re.compile(r"^(?:high|critical)$", re.IGNORECASE)
CONTEXT_PACK_HASH_RE = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)
CALLABLE_RE = re.compile(r"^[a-z][a-z0-9_]*$")
MCP_EVIDENCE_RECEIPT_SCHEMAS = {MCP_EVIDENCE_SCHEMA, MCP_EVIDENCE_LEGACY_SCHEMA}
LESSON_RECEIPT_HINTS = (
    "attack_class",
    "bug_family",
    "candidate_judgment",
    "chain",
    "corpus_mining",
    "detector_action_graph",
    "dupe",
    "external_corpus",
    "function_mindset",
    "function_shape_attack_evidence",
    "hacker",
    "hacker_question",
    "kill_rubric",
    "language_patterns",
    "lesson",
    "originality",
    "prefiling",
    "proof_hardening",
    "severity_calibration",
    "source_read_receipt",
    "source-read",
    "triager",
    # r36-rebuttal: lane fix-2-deeper-gaps-2026-05-28
    # CAP-GAP-NI-7b expansion: AUTO_WORKSPACE_RECEIPTS canonical lesson-pack
    # receipt families that the v1 hint list missed. Schemas (or substrings)
    # that the post-flatten receipt dict carries as its `schema` field.
    "brain_prime",          # auditooor.brain_prime_receipt.v1
    "memory_context",       # auditooor.memory_context_receipt.v1
    "hacker_brief",         # auditooor.hacker_brief_*
    "prior_disclosure",     # auditooor.prior_disclosure_index.v1
    "stress_test",          # auditooor.prefiling_stress_test.v1
    "lesson_candidates",    # auditooor.agent_artifact_lesson_candidates.v1
    "vault_context_pack",   # auditooor.vault_context_pack.v1 (resume packs)
)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def _stable_hash(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _bounded_text(value: Any, *, max_len: int = MAX_TEXT) -> str:
    text = str(value or "").strip()
    text = re.sub(r"\s+", " ", text)
    if len(text) > max_len:
        return text[: max_len - 3].rstrip() + "..."
    return text


def _dedupe_bounded(values: Iterable[Any], *, limit: int, max_len: int = MAX_TEXT) -> tuple[list[str], int]:
    out: list[str] = []
    seen: set[str] = set()
    total = 0
    for value in values:
        text = _bounded_text(value, max_len=max_len)
        if not text:
            continue
        total += 1
        if text in seen:
            continue
        seen.add(text)
        if len(out) < limit:
            out.append(text)
    return out, max(0, total - len(out))


def _bounded_json(value: Any, *, max_len: int = MAX_TEXT) -> Any:
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key in sorted(value):
            if len(out) >= 24:
                break
            out[_bounded_text(key, max_len=80)] = _bounded_json(value[key], max_len=max_len)
        return out
    if isinstance(value, list):
        return [_bounded_json(item, max_len=max_len) for item in value[:24]]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return _bounded_text(value, max_len=max_len) if isinstance(value, str) else value
    return _bounded_text(value, max_len=max_len)


def _read_text_file(path: Path) -> list[str]:
    rows: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            rows.append(stripped)
    return rows


def _read_json_or_text_list(path: Path) -> list[Any]:
    raw = path.read_text(encoding="utf-8")
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return _read_text_file(path)
    if isinstance(parsed, list):
        return parsed
    if isinstance(parsed, dict):
        for key in ("items", "rows", "refs", "source_refs", "obligations", "commands", "files"):
            value = parsed.get(key)
            if isinstance(value, list):
                return value
        return [parsed]
    return [parsed]


def _parse_context_ref(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return _bounded_json(value)
    if isinstance(value, str):
        text = value.strip()
        if text.startswith("{"):
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                parsed = None
            if isinstance(parsed, dict):
                return _bounded_json(parsed)
        return {"ref": _bounded_text(text)}
    return {"ref": _bounded_text(value)}


def _read_json_or_jsonl(path: Path) -> Any:
    raw = path.read_text(encoding="utf-8")
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        rows: list[Any] = []
        for line in raw.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            try:
                rows.append(json.loads(stripped))
            except json.JSONDecodeError:
                rows.append(stripped)
        return rows


def _artifact_ref(path: Path, workspace_path: Path) -> str:
    try:
        return str(path.relative_to(workspace_path))
    except ValueError:
        return str(path)


def _collect_receipt_refs_from_value(
    value: Any,
    *,
    artifact_path: Path,
    workspace_path: Path,
) -> list[dict[str, Any]]:
    refs: list[dict[str, Any]] = []

    def visit(node: Any) -> None:
        if isinstance(node, dict):
            context_pack_id = _bounded_text(node.get("context_pack_id") or node.get("id"), max_len=180)
            context_pack_hash = _bounded_text(node.get("context_pack_hash"), max_len=180)
            if context_pack_id and context_pack_hash:
                ref: dict[str, Any] = {
                    "context_pack_id": context_pack_id,
                    "context_pack_hash": context_pack_hash,
                    "artifact_path": _artifact_ref(artifact_path, workspace_path),
                }
                for key in (
                    "args_hash",
                    "callable",
                    "consumer_packet_hash",
                    "corpus_index_hash",
                    "tool",
                    "requirement_id",
                    "context_kind",
                    "pack_schema",
                    "pack_path",
                    "schema",
                    "target_repo",
                    "output_artifact_hash",
                    "language",
                    "file_path",
                    "repo_sha",
                    "timestamp",
                    "source_file",
                ):
                    item = node.get(key)
                    if isinstance(item, (str, int, float, bool)):
                        ref[key] = _bounded_text(item, max_len=180) if isinstance(item, str) else item
                required_call_set = node.get("required_call_set")
                if isinstance(required_call_set, list):
                    ref["required_call_set"] = [
                        _bounded_text(item, max_len=180)
                        for item in required_call_set[:8]
                        if isinstance(item, str)
                    ]
                source_refs = node.get("source_refs")
                if isinstance(source_refs, list):
                    ref["source_refs"] = [_bounded_text(item, max_len=180) for item in source_refs[:8]]
                refs.append(ref)
            for child in node.values():
                visit(child)
        elif isinstance(node, list):
            for child in node:
                visit(child)

    visit(value)
    return refs


def _workspace_receipt_context_refs(workspace_path: Path) -> tuple[list[dict[str, Any]], int]:
    refs: list[dict[str, Any]] = []
    for rel in AUTO_WORKSPACE_RECEIPTS:
        path = workspace_path / rel
        if not path.is_file():
            continue
        try:
            payload = _read_json_or_jsonl(path)
        except OSError:
            continue
        refs.extend(
            _collect_receipt_refs_from_value(
                payload,
                artifact_path=path,
                workspace_path=workspace_path,
            )
        )
    deduped_all: list[dict[str, Any]] = []
    seen: set[str] = set()
    for ref in refs:
        marker = _stable_hash(ref)
        if marker in seen:
            continue
        seen.add(marker)
        deduped_all.append(ref)
    deduped = _prioritize_context_refs(deduped_all)[:MAX_CONTEXT_REFS]
    return deduped, max(0, len(refs) - len(deduped))


def _collect_context_refs(refs: Sequence[Any], files: Sequence[Path]) -> tuple[list[dict[str, Any]], int]:
    raw: list[Any] = list(refs)
    for path in files:
        raw.extend(_read_json_or_text_list(path))
    parsed = [_parse_context_ref(item) for item in raw]
    deduped_all: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in parsed:
        marker = _stable_hash(item)
        if marker in seen:
            continue
        seen.add(marker)
        deduped_all.append(item)
    deduped = _prioritize_context_refs(deduped_all)[:MAX_CONTEXT_REFS]
    return deduped, max(0, len(parsed) - len(deduped))


def _collect_list(values: Sequence[str], files: Sequence[Path], *, limit: int) -> tuple[list[str], int]:
    raw: list[Any] = list(values)
    for path in files:
        raw.extend(_read_json_or_text_list(path))
    return _dedupe_bounded(raw, limit=limit)


def _strip_local_ref(value: str) -> str | None:
    text = value.strip().strip("`'\"")
    if not text or REMOTE_REF_RE.match(text):
        return None
    if text.startswith("mailto:"):
        return None
    if text.startswith("file://"):
        text = text[7:]
    match = LINE_SUFFIX_RE.match(text)
    if match is None:
        return None
    return match.group("path").strip()


def _resolve_local_path(value: str, workspace_path: Path) -> Path | None:
    stripped = _strip_local_ref(value)
    if stripped is None:
        return None
    candidate = Path(stripped).expanduser()
    if not candidate.is_absolute():
        candidate = workspace_path / candidate
    try:
        return candidate.resolve(strict=False)
    except OSError:
        return candidate.absolute()


def _walk_key_values(value: Any) -> Iterable[tuple[str, Any]]:
    if isinstance(value, dict):
        for key, child in value.items():
            yield str(key), child
            yield from _walk_key_values(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_key_values(child)


def _local_paths_from_context_refs(context_refs: Sequence[dict[str, Any]], workspace_path: Path) -> list[Path]:
    paths: list[Path] = []
    for ref in context_refs:
        for key, value in _walk_key_values(ref):
            if key not in LOCAL_PATH_KEYS or not isinstance(value, str):
                continue
            resolved = _resolve_local_path(value, workspace_path)
            if resolved is not None:
                paths.append(resolved)
    return paths


def _hash_file(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            sha.update(chunk)
    return sha.hexdigest()


def _file_receipt(input_ref: str, path: Path) -> dict[str, Any]:
    receipt: dict[str, Any] = {
        "input_ref": input_ref,
        "resolved_path": str(path),
        "exists": path.exists(),
        "is_file": path.is_file(),
    }
    if path.is_file():
        stat = path.stat()
        receipt.update(
            {
                "size_bytes": stat.st_size,
                "mtime_unix": int(stat.st_mtime),
                "sha256": _hash_file(path),
            }
        )
    return receipt


def _build_file_receipts(
    *,
    workspace_path: Path,
    source_files: Sequence[str],
    context_refs: Sequence[dict[str, Any]],
) -> list[dict[str, Any]]:
    candidates: list[tuple[str, Path]] = []
    for value in source_files:
        resolved = _resolve_local_path(value, workspace_path)
        if resolved is not None:
            candidates.append((value, resolved))
    for path in _local_paths_from_context_refs(context_refs, workspace_path):
        candidates.append((str(path), path))

    receipts: list[dict[str, Any]] = []
    seen: set[str] = set()
    for input_ref, path in candidates:
        marker = str(path)
        if marker in seen:
            continue
        seen.add(marker)
        receipts.append(_file_receipt(input_ref, path))
    return receipts


def _offline_command_blockers(commands: Sequence[str]) -> list[dict[str, str]]:
    blockers: list[dict[str, str]] = []
    for command in commands:
        if NETWORK_COMMAND_RE.search(command):
            blockers.append(
                {
                    "command": command,
                    "reason": "command appears to require network or remote state",
                }
            )
    return blockers


def _has_context_pack_receipt(ref: dict[str, Any]) -> bool:
    context_pack_id = _bounded_text(ref.get("context_pack_id") or ref.get("id"), max_len=180)
    context_pack_hash = _bounded_text(ref.get("context_pack_hash"), max_len=180)
    return bool(context_pack_id and CONTEXT_PACK_HASH_RE.fullmatch(context_pack_hash))


def _is_mcp_evidence_receipt(ref: dict[str, Any]) -> bool:
    schema = _bounded_text(ref.get("schema"), max_len=180)
    callable_name = _bounded_text(ref.get("callable") or ref.get("tool"), max_len=180)
    return bool(
        schema in MCP_EVIDENCE_RECEIPT_SCHEMAS
        and _has_context_pack_receipt(ref)
        and CALLABLE_RE.fullmatch(callable_name)
    )


def _is_lesson_pack_receipt(ref: dict[str, Any]) -> bool:
    if not _has_context_pack_receipt(ref):
        return False
    if _is_mcp_evidence_receipt(ref):
        return True
    haystack = json.dumps(ref, sort_keys=True, ensure_ascii=True).lower()
    return any(hint in haystack for hint in LESSON_RECEIPT_HINTS)


def _prioritize_context_refs(refs: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        refs,
        key=lambda ref: (
            0 if _is_mcp_evidence_receipt(ref) else 1 if _is_lesson_pack_receipt(ref) else 2,
            _stable_hash(ref),
        ),
    )


def _lesson_pack_receipt_refs(context_refs: Sequence[dict[str, Any]]) -> list[dict[str, str]]:
    refs: list[dict[str, str]] = []
    for ref in context_refs:
        if not _is_lesson_pack_receipt(ref):
            continue
        refs.append(
            {
                "context_pack_id": _bounded_text(ref.get("context_pack_id") or ref.get("id"), max_len=180),
                "context_pack_hash": _bounded_text(ref.get("context_pack_hash"), max_len=180),
                "tool": _bounded_text(ref.get("tool"), max_len=180),
                "schema": _bounded_text(ref.get("schema"), max_len=180),
                "artifact_path": _bounded_text(ref.get("artifact_path"), max_len=180),
            }
        )
    return refs


def _lesson_pack_blockers(
    *,
    severity: str,
    context_refs: Sequence[dict[str, Any]],
    no_lesson_pack_reason: str,
) -> list[dict[str, str]]:
    if not HIGH_CRITICAL_RE.match(severity.strip()):
        return []
    if _lesson_pack_receipt_refs(context_refs):
        return []
    reason = _bounded_text(no_lesson_pack_reason, max_len=400)
    if reason.startswith(LESSON_PACK_REASON_PREFIX) and len(reason) > len(LESSON_PACK_REASON_PREFIX):
        return []
    return [
        {
            "code": "missing_lesson_pack_receipt",
            "reason": (
                "High/Critical worker packets must include a real MCP lesson-pack receipt "
                "(context_pack_id + context_pack_hash) or a typed "
                f"{LESSON_PACK_REASON_PREFIX}<reason>."
            ),
        }
    ]


def build_packet(
    *,
    workspace_path: Path,
    packet_id: str = "",
    title: str = "",
    severity: str = "",
    mcp_context_refs: Sequence[Any] = (),
    mcp_context_files: Sequence[Path] = (),
    auto_workspace_receipts: bool = False,
    no_lesson_pack_reason: str = "",
    source_files: Sequence[str] = (),
    source_files_files: Sequence[Path] = (),
    hacker_questions: Sequence[str] = (),
    hacker_questions_files: Sequence[Path] = (),
    proof_obligations: Sequence[str] = (),
    proof_obligations_files: Sequence[Path] = (),
    verification_commands: Sequence[str] = (),
    verification_command_files: Sequence[Path] = (),
    generated_at: str | None = None,
) -> dict[str, Any]:
    workspace_path = workspace_path.expanduser().resolve(strict=False)
    auto_context_refs: list[dict[str, Any]] = []
    auto_context_truncated = 0
    if auto_workspace_receipts:
        auto_context_refs, auto_context_truncated = _workspace_receipt_context_refs(workspace_path)
    context_refs, context_truncated = _collect_context_refs(
        [*auto_context_refs, *mcp_context_refs],
        mcp_context_files,
    )
    source_rows, source_truncated = _collect_list(source_files, source_files_files, limit=MAX_SOURCE_FILES)
    hacker_rows, hacker_truncated = _collect_list(
        hacker_questions,
        hacker_questions_files,
        limit=MAX_OBLIGATIONS,
    )
    proof_rows, proof_truncated = _collect_list(
        proof_obligations,
        proof_obligations_files,
        limit=MAX_OBLIGATIONS,
    )
    command_rows, command_truncated = _collect_list(
        verification_commands,
        verification_command_files,
        limit=MAX_COMMANDS,
    )
    file_receipts = _build_file_receipts(
        workspace_path=workspace_path,
        source_files=source_rows,
        context_refs=context_refs,
    )
    lesson_pack_refs = _lesson_pack_receipt_refs(context_refs)
    offline_blockers = _offline_command_blockers(command_rows)
    lesson_pack_blockers = _lesson_pack_blockers(
        severity=severity,
        context_refs=context_refs,
        no_lesson_pack_reason=no_lesson_pack_reason,
    )
    validation_blocked = bool(offline_blockers or lesson_pack_blockers)
    packet: dict[str, Any] = {
        "schema": SCHEMA,
        "generated_at": generated_at or utc_now(),
        "packet_id": _bounded_text(packet_id or "v3-worker-packet", max_len=120),
        "title": _bounded_text(title or "V3 Worker Packet", max_len=160),
        "severity": _bounded_text(severity, max_len=40),
        "workspace_path": str(workspace_path),
        "offline_only": True,
        "mcp_context_refs": context_refs,
        "no_lesson_pack_reason": _bounded_text(no_lesson_pack_reason, max_len=400),
        "source_files": source_rows,
        "hacker_question_obligations": hacker_rows,
        "proof_obligations": proof_rows,
        "required_local_verification_commands": command_rows,
        "evidence_receipts": {
            "local_file_hashes": file_receipts,
            "receipt_count": len(file_receipts),
            "lesson_pack_receipt_count": len(lesson_pack_refs),
            "lesson_pack_receipts": lesson_pack_refs,
            "missing_files": [
                receipt["resolved_path"]
                for receipt in file_receipts
                if not receipt.get("exists") or not receipt.get("is_file")
            ],
        },
        "bounds": {
            "max_context_refs": MAX_CONTEXT_REFS,
            "max_source_files": MAX_SOURCE_FILES,
            "max_obligations": MAX_OBLIGATIONS,
            "max_commands": MAX_COMMANDS,
            "truncated": {
                "mcp_context_refs": context_truncated + auto_context_truncated,
                "source_files": source_truncated,
                "hacker_question_obligations": hacker_truncated,
                "proof_obligations": proof_truncated,
                "verification_commands": command_truncated,
            },
        },
        "offline_validation": {
            "status": "blocked" if validation_blocked else "ok",
            "blocked_commands": offline_blockers,
            "lesson_pack_blockers": lesson_pack_blockers,
            "note": "Commands are recorded for local verification only; this tool does not execute them.",
        },
    }
    packet["packet_hash"] = _stable_hash({key: value for key, value in packet.items() if key != "packet_hash"})
    return packet


def build_packet_mcp_evidence_receipt(
    packet: dict[str, Any],
    *,
    workspace_path: Path,
    required_call_set: Sequence[str] = (),
) -> dict[str, Any] | None:
    context_refs = [ref for ref in packet.get("mcp_context_refs") or [] if isinstance(ref, dict)]
    lesson_refs = [ref for ref in context_refs if _is_lesson_pack_receipt(ref)]
    if not lesson_refs:
        return None
    primary = lesson_refs[0]
    calls: list[str] = [
        _bounded_text(call, max_len=180)
        for call in required_call_set
        if CALLABLE_RE.fullmatch(_bounded_text(call, max_len=180))
    ]
    for ref in lesson_refs:
        for key in ("callable", "tool"):
            call = _bounded_text(ref.get(key), max_len=180)
            if CALLABLE_RE.fullmatch(call) and call not in calls:
                calls.append(call)
    if not calls:
        return None
    packet_hash = _bounded_text(packet.get("packet_hash"), max_len=180)
    if not CONTEXT_PACK_HASH_RE.fullmatch(packet_hash):
        return None
    source_hashes = [
        row
        for row in packet.get("evidence_receipts", {}).get("local_file_hashes") or []
        if isinstance(row, dict) and row.get("sha256")
    ]
    args = {
        "packet_id": packet.get("packet_id"),
        "severity": packet.get("severity"),
        "source_files": packet.get("source_files"),
        "proof_obligations": packet.get("proof_obligations"),
        "required_local_verification_commands": packet.get("required_local_verification_commands"),
    }
    return build_mcp_evidence_receipt(
        callable_name=calls[0],
        workspace=workspace_path,
        context_pack_id=_bounded_text(primary.get("context_pack_id") or primary.get("id"), max_len=180),
        context_pack_hash=_bounded_text(primary.get("context_pack_hash"), max_len=180),
        consumer_packet_hash=packet_hash,
        output_artifact_hash=_stable_hash(packet),
        source_file_hashes=source_hashes,
        required_call_set=calls,
        args=args,
    )


def render_markdown(packet: dict[str, Any]) -> str:
    lines = [
        "# V3 Worker Packet",
        "",
        f"- Packet ID: `{packet.get('packet_id', '')}`",
        f"- Packet hash: `{packet.get('packet_hash', '')}`",
        f"- Generated at: `{packet.get('generated_at', '')}`",
        f"- Severity: `{packet.get('severity', '') or 'unspecified'}`",
        f"- Workspace: `{packet.get('workspace_path', '')}`",
        f"- Offline only: {'yes' if packet.get('offline_only') else 'no'}",
        f"- Offline validation: `{packet.get('offline_validation', {}).get('status', 'unknown')}`",
        "",
        "## MCP Context Refs",
    ]
    context_refs = packet.get("mcp_context_refs") or []
    if context_refs:
        for ref in context_refs:
            label = ref.get("context_pack_id") or ref.get("id") or ref.get("ref") or json.dumps(ref, sort_keys=True)
            suffix = ""
            if ref.get("context_pack_hash"):
                suffix = f" (hash `{ref['context_pack_hash']}`)"
            source = ""
            if ref.get("artifact_path"):
                source = f" from `{_bounded_text(ref['artifact_path'], max_len=180)}`"
            lines.append(f"- {_bounded_text(label, max_len=180)}{suffix}{source}")
    else:
        lines.append("- none")
    no_lesson_reason = packet.get("no_lesson_pack_reason") or ""
    if no_lesson_reason:
        lines.append(f"- {_bounded_text(no_lesson_reason, max_len=220)}")

    sections = [
        ("Source Files", "source_files"),
        ("Hacker Question Obligations", "hacker_question_obligations"),
        ("Proof Obligations", "proof_obligations"),
        ("Required Local Verification Commands", "required_local_verification_commands"),
    ]
    for title, key in sections:
        lines.extend(("", f"## {title}"))
        rows = packet.get(key) or []
        if not rows:
            lines.append("- none")
            continue
        for row in rows:
            text = _bounded_text(row, max_len=220)
            if key == "required_local_verification_commands":
                lines.append(f"- `{text}`")
            else:
                lines.append(f"- {text}")

    lines.extend(("", "## Local File Hash Receipts"))
    receipts = packet.get("evidence_receipts", {}).get("local_file_hashes") or []
    if not receipts:
        lines.append("- none")
    for receipt in receipts:
        path = receipt.get("resolved_path") or receipt.get("input_ref") or ""
        if receipt.get("sha256"):
            lines.append(
                f"- `{path}` sha256 `{receipt['sha256']}` size `{receipt.get('size_bytes', 0)}`"
            )
        else:
            status = "missing" if not receipt.get("exists") else "not_file"
            lines.append(f"- `{path}` {status}")

    blockers = packet.get("offline_validation", {}).get("blocked_commands") or []
    lesson_blockers = packet.get("offline_validation", {}).get("lesson_pack_blockers") or []
    if blockers or lesson_blockers:
        lines.extend(("", "## Offline Blockers"))
        for blocker in blockers:
            lines.append(f"- `{blocker.get('command', '')}`: {blocker.get('reason', '')}")
        for blocker in lesson_blockers:
            lines.append(f"- `{blocker.get('code', '')}`: {blocker.get('reason', '')}")

    truncated = packet.get("bounds", {}).get("truncated") or {}
    if any(truncated.values()):
        lines.extend(("", "## Bounds"))
        for key, count in truncated.items():
            if count:
                lines.append(f"- {key}: {count} item(s) omitted")
    return "\n".join(lines) + "\n"


def _path_list(values: Sequence[str] | None) -> list[Path]:
    return [Path(value) for value in values or []]


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=Path.cwd(), help="Workspace used to resolve relative files")
    parser.add_argument("--packet-id", default="")
    parser.add_argument("--title", default="")
    parser.add_argument("--severity", default="", help="Finding/hunt severity; High/Critical require lesson-pack receipt or typed no-lesson reason")
    parser.add_argument("--mcp-context-ref", action="append", default=[])
    parser.add_argument("--mcp-context-file", action="append", default=[])
    parser.add_argument(
        "--auto-workspace-receipts",
        action="store_true",
        help="Auto-harvest context_pack_id/hash refs from known <workspace>/.auditooor sidecar receipts",
    )
    parser.add_argument("--no-lesson-pack-reason", default="", help=f"Typed fallback, must start with {LESSON_PACK_REASON_PREFIX}")
    parser.add_argument("--source-file", action="append", default=[])
    parser.add_argument("--source-files-file", action="append", default=[])
    parser.add_argument("--hacker-question", action="append", default=[])
    parser.add_argument("--hacker-questions-file", action="append", default=[])
    parser.add_argument("--proof-obligation", action="append", default=[])
    parser.add_argument("--proof-obligations-file", action="append", default=[])
    parser.add_argument("--verification-command", action="append", default=[])
    parser.add_argument("--verification-commands-file", action="append", default=[])
    parser.add_argument("--out-json", type=Path, default=None)
    parser.add_argument("--out-md", type=Path, default=None)
    parser.add_argument(
        "--out-mcp-evidence-receipt",
        type=Path,
        default=None,
        help="Write an auditooor.mcp_evidence_receipt.v1 sidecar bound to the packet hash when a lesson-pack receipt exists",
    )
    parser.add_argument(
        "--required-mcp-call",
        action="append",
        default=[],
        help="MCP callable that must be represented in the emitted evidence receipt required_call_set",
    )
    parser.add_argument("--markdown", action="store_true", help="Print markdown instead of JSON")
    parser.add_argument("--strict", action="store_true", help="Exit nonzero when offline validation is blocked")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    packet = build_packet(
        workspace_path=args.workspace,
        packet_id=args.packet_id,
        title=args.title,
        severity=args.severity,
        mcp_context_refs=args.mcp_context_ref,
        mcp_context_files=_path_list(args.mcp_context_file),
        auto_workspace_receipts=args.auto_workspace_receipts,
        no_lesson_pack_reason=args.no_lesson_pack_reason,
        source_files=args.source_file,
        source_files_files=_path_list(args.source_files_file),
        hacker_questions=args.hacker_question,
        hacker_questions_files=_path_list(args.hacker_questions_file),
        proof_obligations=args.proof_obligation,
        proof_obligations_files=_path_list(args.proof_obligations_file),
        verification_commands=args.verification_command,
        verification_command_files=_path_list(args.verification_commands_file),
    )
    if args.out_json:
        args.out_json.parent.mkdir(parents=True, exist_ok=True)
        args.out_json.write_text(json.dumps(packet, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown = render_markdown(packet)
    if args.out_md:
        args.out_md.parent.mkdir(parents=True, exist_ok=True)
        args.out_md.write_text(markdown, encoding="utf-8")
    if args.out_mcp_evidence_receipt:
        receipt = build_packet_mcp_evidence_receipt(
            packet,
            workspace_path=args.workspace.expanduser().resolve(strict=False),
            required_call_set=args.required_mcp_call,
        )
        if receipt is None:
            print(
                "v3-worker-packet-builder: WARN: no MCP evidence receipt written; "
                "packet has no validated lesson-pack callable receipt",
                file=sys.stderr,
            )
            if args.strict and packet.get("offline_validation", {}).get("status") == "blocked":
                return 1
        else:
            args.out_mcp_evidence_receipt.parent.mkdir(parents=True, exist_ok=True)
            args.out_mcp_evidence_receipt.write_text(
                json.dumps(receipt, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
    if args.markdown:
        print(markdown, end="")
    elif not args.out_json:
        print(json.dumps(packet, indent=2, sort_keys=True))
    if args.strict and packet.get("offline_validation", {}).get("status") == "blocked":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
