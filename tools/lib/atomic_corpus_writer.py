# r36-rebuttal: work3-r67-unique-id-2026-05-26 registered in .auditooor/agent_pathspec.json via tools/agent-pathspec-register.py register
"""Atomic-write + auto-rotation wrapper library for corpus files (LIFT-26 / R67).

Rule R67: Corpus File Atomic-Write + Rotation Required

Codified 2026-05-26 after the LIFT-9 940-record loss incident (2.0M -> 216K
shrinkage of invariants_pilot_audited.jsonl during a refresh pipeline run).
The only saving grace was a single manual ad-hoc backup (.bak.pre-quarantine
-2026-05-26) created opportunistically by a lane that happened to remember.
No automatic rotation policy existed; no atomic-write enforcement existed.
R67 codifies both.

Pattern:

1. If file exists + backup_first=True: copy to .bak.<utc>.<sha256[:8]>
2. Write content to <path>.tmp.<uuid>
3. sha256_check=True: verify .tmp matches expected sha256
4. Atomic os.replace(.tmp, <path>)
5. Append a rotation_log entry at <path>.rotation_log.jsonl with
   {ts, sha256, backup_path, byte_count, prior_byte_count}.
6. Auto-prune backups per rotation policy (last-N + TTL-days), preserving
   any backup whose name starts with `.bak.pre-` (manual safety backups).

Env overrides:
- AUDITOOOR_R67_BACKUP_TTL_DAYS (default 14): TTL for non-pre backups.
- AUDITOOOR_R67_BACKUP_KEEP_LAST (default 10): minimum number of recent
  backups to retain per file regardless of TTL.

The library is dependency-free (stdlib only). Public API:

- atomic_write_corpus_file(path, content, *, sha256_check=True,
      backup_first=True, expected_sha256=None, record_id_field=None) -> dict
- list_backups(path) -> list[Path]
- prune_backups(path, *, keep_last=None, ttl_days=None) -> dict
- read_rotation_log(path) -> list[dict]
- rotation_log_path(path) -> Path
- find_corpus_writer_candidates(repo_root) -> list[Path]
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = "auditooor.r67_atomic_corpus_writer.v1"

# Common ID field names tried in order when no record_id_field is specified.
DEFAULT_ID_FIELDS = ("record_id", "invariant_id", "gct_id", "question_id", "narrative_id")

# Backup naming conventions.
_BACKUP_TIMESTAMP_RE = re.compile(
    r"\.bak\.(?P<ts>\d{8}T\d{6}Z)\.(?P<sha>[0-9a-f]{8})(?:\.[0-9a-f]{6})?$"
)
_BACKUP_MANUAL_PREFIX = ".bak.pre-"


def _utc_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_path(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _as_bytes(content) -> bytes:
    if isinstance(content, bytes):
        return content
    if isinstance(content, str):
        return content.encode("utf-8")
    raise TypeError(f"content must be str or bytes, got {type(content).__name__}")


def rotation_log_path(path) -> Path:
    """Return the canonical rotation-log path for ``path``."""
    p = Path(path)
    return Path(str(p) + ".rotation_log.jsonl")


def _append_rotation_log(path: Path, record: dict) -> Path:
    log_path = rotation_log_path(path)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(record, sort_keys=True) + "\n"
    with open(log_path, "a", encoding="utf-8") as fh:
        fh.write(line)
    return log_path


def read_rotation_log(path) -> list[dict]:
    """Return the rotation-log entries for ``path`` (oldest first)."""
    log_path = rotation_log_path(path)
    if not log_path.exists():
        return []
    out: list[dict] = []
    with open(log_path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                # Skip malformed lines rather than failing reads.
                continue
    return out


def list_backups(path) -> list[Path]:
    """Return every backup file alongside ``path`` (both auto-rotated and manual).

    Auto-rotated names: ``<name>.bak.<utc-ts>.<sha8>``
    Manual safety names: ``<name>.bak.pre-<tag>`` (preserved by prune policy)
    """
    p = Path(path)
    if not p.parent.exists():
        return []
    name = p.name
    prefix = name + ".bak."
    out: list[Path] = []
    for entry in p.parent.iterdir():
        if entry.name.startswith(prefix):
            out.append(entry)
    return sorted(out)


def _parse_backup_ts(backup_path: Path) -> tuple[float, bool]:
    """Return (epoch_seconds, is_manual) for a backup file.

    For manual `.bak.pre-*` files, falls back to mtime; ``is_manual=True``.
    For auto `.bak.<utc>.<sha8>` files, parses the embedded timestamp.
    """
    suffix = backup_path.name.rsplit(".bak.", 1)[-1]
    if suffix.startswith("pre-"):
        return (backup_path.stat().st_mtime, True)
    m = _BACKUP_TIMESTAMP_RE.search(backup_path.name)
    if m:
        try:
            ts = datetime.strptime(m.group("ts"), "%Y%m%dT%H%M%SZ")
            ts = ts.replace(tzinfo=timezone.utc)
            return (ts.timestamp(), False)
        except ValueError:
            return (backup_path.stat().st_mtime, False)
    return (backup_path.stat().st_mtime, False)


def _count_unique_record_ids(
    data: bytes,
    record_id_field: str | None = None,
) -> tuple[int | None, str | None]:
    """Count unique record IDs in a JSONL byte blob.

    Tries ``record_id_field`` first; if None, tries ``DEFAULT_ID_FIELDS`` in
    order.  Returns ``(unique_count, field_name_used)`` or ``(None, None)``
    when no ID field is found in any parsed record.

    Only the first 200 lines are sampled to detect the field name; full scan
    follows once the field is identified.
    """
    lines = data.split(b"\n")

    # Step 1: determine which field to use.
    candidate_fields: tuple[str, ...] = (
        (record_id_field,) if record_id_field else DEFAULT_ID_FIELDS
    )
    detected_field: str | None = None

    for line in lines[:200]:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(obj, dict):
            continue
        for f in candidate_fields:
            if f in obj:
                detected_field = f
                break
        if detected_field:
            break

    if detected_field is None:
        return (None, None)

    # Step 2: full scan.
    seen: set = set()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(obj, dict) and detected_field in obj:
            val = obj[detected_field]
            # Normalise to hashable.
            seen.add(val if not isinstance(val, (dict, list)) else json.dumps(val, sort_keys=True))

    return (len(seen), detected_field)


def prune_backups(
    path,
    *,
    keep_last: int | None = None,
    ttl_days: int | None = None,
) -> dict:
    """Prune old backups for ``path`` per the rotation policy.

    Policy:
    - Always preserve any backup whose name starts with ``<name>.bak.pre-``.
    - Keep the most recent ``keep_last`` auto backups (default
      AUDITOOOR_R67_BACKUP_KEEP_LAST=10).
    - Remove any auto backup older than ``ttl_days`` days (default
      AUDITOOOR_R67_BACKUP_TTL_DAYS=14), provided that doing so does not
      violate the keep_last floor.

    Returns ``{kept, pruned, manual_preserved}`` lists of Path objects.
    """
    if keep_last is None:
        keep_last = int(os.environ.get("AUDITOOOR_R67_BACKUP_KEEP_LAST", "10"))
    if ttl_days is None:
        ttl_days = int(os.environ.get("AUDITOOOR_R67_BACKUP_TTL_DAYS", "14"))

    backups = list_backups(path)
    auto: list[tuple[float, Path]] = []
    manual: list[Path] = []
    for b in backups:
        ts, is_manual = _parse_backup_ts(b)
        if is_manual:
            manual.append(b)
        else:
            auto.append((ts, b))

    # Sort auto backups newest-first.
    auto.sort(key=lambda pair: pair[0], reverse=True)

    # r36-rebuttal: lane-LIFT-26-R67 registered in agent_pathspec.json
    cutoff = time.time() - (ttl_days * 86400) if ttl_days > 0 else 0.0
    kept: list[Path] = []
    pruned: list[Path] = []

    for idx, (ts, b) in enumerate(auto):
        # Policy:
        #   1. Anything beyond the keep_last most-recent slot is a candidate
        #      for pruning regardless of TTL (cap).
        #   2. Anything within keep_last AND older than ttl_days is ALSO
        #      pruned (TTL applies to older daily snapshots).
        # Combined: prune when (idx >= keep_last) OR (ttl_days>0 AND ts<cutoff).
        prune_this = False
        if idx >= keep_last:
            prune_this = True
        elif ttl_days > 0 and ts < cutoff:
            prune_this = True

        if prune_this:
            try:
                b.unlink()
                pruned.append(b)
            except OSError:
                kept.append(b)
        else:
            kept.append(b)

    return {
        "kept": kept,
        "pruned": pruned,
        "manual_preserved": manual,
    }


class AtomicWriteError(RuntimeError):
    """Raised when atomic-write verification fails."""


def atomic_write_corpus_file(
    path,
    content,
    *,
    sha256_check: bool = True,
    backup_first: bool = True,
    expected_sha256: str | None = None,
    prune: bool = True,
    record_id_field: str | None = None,
) -> dict:
    """Atomically write ``content`` to ``path`` with backup + sha256 verification.

    Parameters
    ----------
    path : Path-like
        Target corpus file path.
    content : str | bytes
        File contents.
    sha256_check : bool, default True
        Verify the temp file's sha256 matches the expected hash before rename.
    backup_first : bool, default True
        If ``path`` exists, copy it to ``<path>.bak.<utc>.<sha8>`` before write.
    expected_sha256 : str | None
        If provided, the temp file's sha must match this value. Otherwise the
        computed sha of ``content`` itself is used.
    prune : bool, default True
        After the write, run :func:`prune_backups` for housekeeping.
    record_id_field : str | None, default None
        JSONL field used to count unique record IDs (e.g. "invariant_id").
        If None, ``DEFAULT_ID_FIELDS`` are tried in order. If no ID field is
        found, ``unique_record_id_count_*`` fields are emitted as ``null``.

    Returns
    -------
    dict
        ``{schema, success, path, backup_path, sha256, byte_count,
        prior_byte_count, rotation_log_path, unique_record_id_count_before,
        unique_record_id_count_after, record_id_field, dedup_dropped_count}``.

    Raises
    ------
    AtomicWriteError
        If sha256 verification fails. The temp file is unlinked and the
        original file is left untouched.
    """
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    data = _as_bytes(content)
    content_sha = _sha256_bytes(data)
    target_sha = expected_sha256 or content_sha

    prior_byte_count = p.stat().st_size if p.exists() else 0
    prior_data = p.read_bytes() if p.exists() else b""
    backup_path: Path | None = None

    # Step 1: backup.
    if backup_first and p.exists():
        prior_sha = _sha256_path(p)
        backup_name = f"{p.name}.bak.{_utc_ts()}.{prior_sha[:8]}"
        backup_path = p.parent / backup_name
        # If a collision occurs in the same second, append a uuid suffix.
        if backup_path.exists():
            backup_path = p.parent / f"{backup_name}.{uuid.uuid4().hex[:6]}"
        shutil.copy2(p, backup_path)

    # Step 2: tempfile write in same directory (required for atomic rename
    # across the OS-level filesystem boundary).
    tmp_path = p.parent / f"{p.name}.tmp.{uuid.uuid4().hex}"
    try:
        with open(tmp_path, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())

        # Step 3: sha256 verification.
        if sha256_check:
            written_sha = _sha256_path(tmp_path)
            if written_sha != target_sha:
                tmp_path.unlink(missing_ok=True)
                raise AtomicWriteError(
                    f"sha256 mismatch on tempfile write: "
                    f"got {written_sha}, expected {target_sha}"
                )

        # Step 4: atomic rename (POSIX guarantee).
        os.replace(tmp_path, p)
    finally:
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)

    # Step 5: rotation log entry with unique-ID counts (Task #229 forensic anchor).
    # Count unique IDs in the before/after data so line-count shrinkage can be
    # distinguished from real record-ID loss (dedup = warn, real loss = fail).
    uid_before, uid_field_before = _count_unique_record_ids(prior_data, record_id_field)
    uid_after, uid_field_after = _count_unique_record_ids(data, record_id_field)
    uid_field_used = uid_field_after or uid_field_before
    dedup_dropped: int | None = None
    if uid_before is not None:
        line_count_before = prior_data.count(b"\n") + (1 if prior_data and not prior_data.endswith(b"\n") else 0) if prior_data else 0
        dedup_dropped = line_count_before - uid_before if line_count_before >= uid_before else None
    record = {
        "schema": SCHEMA,
        "ts": _utc_ts(),
        "path": str(p),
        "sha256": content_sha,
        "byte_count": len(data),
        "prior_byte_count": prior_byte_count,
        "backup_path": str(backup_path) if backup_path else None,
        "unique_record_id_count_before": uid_before,
        "unique_record_id_count_after": uid_after,
        "record_id_field": uid_field_used,
        "dedup_dropped_count": dedup_dropped,
    }
    log_path = _append_rotation_log(p, record)

    # Step 6: optional prune.
    if prune:
        prune_backups(p)

    return {
        "schema": SCHEMA,
        "success": True,
        "path": str(p),
        "backup_path": str(backup_path) if backup_path else None,
        "sha256": content_sha,
        "byte_count": len(data),
        "prior_byte_count": prior_byte_count,
        "rotation_log_path": str(log_path),
        "unique_record_id_count_before": uid_before,
        "unique_record_id_count_after": uid_after,
        "record_id_field": uid_field_used,
        "dedup_dropped_count": dedup_dropped,
    }


def find_corpus_writer_candidates(repo_root) -> list[Path]:
    """Return tools that write to derived/ corpus surfaces (migration scan).

    Returns a list of tool paths that mention any of the canonical derived
    corpus stems and also use a write idiom (open(..., "w"), shutil.copy,
    os.replace, Path.write_text/write_bytes, etc.).
    """
    repo_root = Path(repo_root)
    stems = (
        "invariants_pilot_audited",
        "exploit_predicates",
        "global_chain_templates",
        "hacker_questions_library",
        "tok_a_enrichment",
        "tok_b_enrichment",
        "invariants_extracted",
        "invariants_quarantine_tier5",
    )
    write_idioms = (
        'open(',
        '"w"',
        "'w'",
        ".write_text(",
        ".write_bytes(",
        "os.replace(",
        "shutil.copy(",
        "shutil.move(",
        ">>",
        ">",
    )
    candidates: list[Path] = []
    tools_dir = repo_root / "tools"
    if not tools_dir.exists():
        return candidates
    for tool in tools_dir.glob("*.py"):
        try:
            text = tool.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if not any(stem in text for stem in stems):
            continue
        if any(idiom in text for idiom in write_idioms):
            candidates.append(tool)
    return sorted(candidates)
