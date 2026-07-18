#!/usr/bin/env python3
"""Build a pre-computed detector-relationships sidecar for the Hackerman corpus.

Lane W6-10: `hackerman-detector-relationships.py` reparses the full corpus on
every query. This builder normalizes the corpus rows once, writes them to a
derived JSONL sidecar, and exposes a cached query helper that joins engage
report detector clusters against the sidecar instead of reparsing YAML.

The sidecar stores only the corpus-derived record rows. Detector clusters stay
request-scoped, so the query helper still reads the current engage report and
reuses the existing relationship scoring logic without mutating corpus YAML.

B8 (V3 plan): The monolith JSONL sidecar grows with the corpus. The sharded
layout (--shard mode, now the default) writes a manifest.json plus bounded
shard files so that no single artifact approaches GitHub's 100 MB hard limit.
Consumers use `load_sidecar` (auto-detects manifest vs monolith) or
`sidecar_is_fresh` which checks both forms.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = REPO_ROOT / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

from hackerman_query_common import (  # noqa: E402
    DEFAULT_DERIVED_DIR,
    DEFAULT_TAGS_DIR,
    corpus_content_fingerprint,
    load_query_module,
    utc_now,
)


SIDECAR_SCHEMA = "auditooor.hackerman_detector_relationship_records_sidecar.v1"
META_SCHEMA = "auditooor.hackerman_detector_relationship_records_sidecar.meta.v1"
MANIFEST_SCHEMA = "auditooor.hackerman_detector_relationship_records_sidecar.manifest.v1"
DEFAULT_SIDECAR_NAME = "detector_relationship_records.jsonl"
DEFAULT_SIDECAR_PATH = DEFAULT_DERIVED_DIR / DEFAULT_SIDECAR_NAME
DEFAULT_SHARD_TARGET_BYTES = 8 * 1024 * 1024  # 8 MiB per shard
SIZE_HARD_BYTES_DEFAULT = 95 * 1024 * 1024    # 95 MiB hard limit per file


def _load_query_tool() -> Any:
    return load_query_module(
        "hackerman-detector-relationships.py",
        "_w610_hdr_sidecar",
    )


def _default_sidecar_path(tag_dir: Path) -> Path:
    return tag_dir.parent / "derived" / DEFAULT_SIDECAR_NAME


def _manifest_path(out_path: Path) -> Path:
    return out_path.with_name(f"{out_path.stem}.manifest.json")


def _shard_dir(out_path: Path) -> Path:
    return out_path.with_name(f"{out_path.stem}.d")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _base_meta(
    mod: Any,
    tag_dir: Path,
    records: list[Any],
    summary: dict[str, Any],
    fingerprint: str,
    file_count: int,
) -> dict[str, Any]:
    return {
        "schema_version": META_SCHEMA,
        "sidecar_schema": SIDECAR_SCHEMA,
        "tag_dir": str(tag_dir),
        "corpus_fingerprint": fingerprint,
        "corpus_file_count": file_count,
        "tag_files_scanned": summary.get("tag_files_scanned", 0),
        "records_loaded": summary.get("records_loaded", len(records)),
        "records_skipped_invalid": summary.get("records_skipped_invalid", 0),
        "records_skipped_non_record": summary.get("records_skipped_non_record", 0),
        "invalid_records": summary.get("invalid_records", []),
        "tool_schema_version": getattr(mod, "SCHEMA", ""),
        "generated_at_utc": utc_now(),
    }


def build_sidecar(tag_dir: Path, out_path: Path) -> dict[str, Any]:
    """Run the full corpus parse once and write normalized record rows.

    Prefer `build_sharded_sidecar` for new builds. This path is retained for
    callers that explicitly request the monolith layout (--monolith flag).
    Raises `RuntimeError` if the resulting file would exceed SIZE_HARD_BYTES_DEFAULT.
    """
    mod = _load_query_tool()
    fingerprint, file_count = corpus_content_fingerprint(tag_dir, recursive=True)
    bug_map = mod._load_bug_class_map(mod.BUG_CLASS_MAP)
    records, summary = mod._load_records(tag_dir, bug_map)
    meta = _base_meta(mod, tag_dir, records, summary, fingerprint, file_count)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = out_path.with_name(f".{out_path.name}.{os.getpid()}.tmp")
    lines = [json.dumps(meta, sort_keys=True)]
    lines.extend(json.dumps(row, sort_keys=True) for row in records)
    tmp_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    size_bytes = tmp_path.stat().st_size
    if size_bytes >= SIZE_HARD_BYTES_DEFAULT:
        try:
            tmp_path.unlink()
        except OSError:
            pass
        raise RuntimeError(
            f"detector_relationship_records monolith sidecar would exceed hard size limit "
            f"({size_bytes} >= {SIZE_HARD_BYTES_DEFAULT}); use build_sharded_sidecar instead"
        )
    tmp_path.replace(out_path)
    return meta


def build_sharded_sidecar(
    tag_dir: Path,
    out_path: Path,
    *,
    shard_target_bytes: int = DEFAULT_SHARD_TARGET_BYTES,
) -> dict[str, Any]:
    """Run extraction once and write a bounded manifest plus JSONL shards.

    The manifest is written to ``<stem>.manifest.json`` alongside ``out_path``.
    Individual shards live under ``<stem>.d/shard-NNNNN.jsonl``. No single shard
    file exceeds ``shard_target_bytes`` (configurable). Consumers call
    ``load_sidecar`` which auto-detects the manifest and streams shards.
    """
    mod = _load_query_tool()
    fingerprint, file_count = corpus_content_fingerprint(tag_dir, recursive=True)
    bug_map = mod._load_bug_class_map(mod.BUG_CLASS_MAP)
    records, summary = mod._load_records(tag_dir, bug_map)
    meta = _base_meta(mod, tag_dir, records, summary, fingerprint, file_count)

    manifest_path = _manifest_path(out_path)
    shard_dir = _shard_dir(out_path)
    tmp_dir = shard_dir.with_name(f".{shard_dir.name}.{os.getpid()}.tmp")
    if tmp_dir.exists():
        for old in tmp_dir.glob("*"):
            old.unlink()
        tmp_dir.rmdir()
    tmp_dir.mkdir(parents=True, exist_ok=True)

    shard_target_bytes = max(1024, int(shard_target_bytes))
    shards: list[dict[str, Any]] = []
    current_fh = None
    current_path: Path | None = None
    current_records = 0
    current_bytes = 0
    first_record_id = ""
    last_record_id = ""

    def close_current() -> None:
        nonlocal current_fh, current_path, current_records, current_bytes
        nonlocal first_record_id, last_record_id
        if current_fh is None or current_path is None:
            return
        current_fh.close()
        shards.append(
            {
                "path": current_path.name,
                "records_emitted": current_records,
                "size_bytes": current_path.stat().st_size,
                "sha256": _sha256_file(current_path),
                "first_record_id": first_record_id,
                "last_record_id": last_record_id,
            }
        )
        current_fh = None
        current_path = None
        current_records = 0
        current_bytes = 0
        first_record_id = ""
        last_record_id = ""

    try:
        for row in records:
            line = json.dumps(row, sort_keys=True) + "\n"
            encoded_len = len(line.encode("utf-8"))
            if current_fh is None or (
                current_records > 0 and current_bytes + encoded_len > shard_target_bytes
            ):
                close_current()
                current_path = tmp_dir / f"shard-{len(shards):05d}.jsonl"
                current_fh = current_path.open("w", encoding="utf-8")
            rid = str(row.get("record_id") or "")
            if not first_record_id:
                first_record_id = rid
            last_record_id = rid
            current_fh.write(line)
            current_records += 1
            current_bytes += encoded_len
        close_current()

        total_shard_bytes = sum(int(s["size_bytes"]) for s in shards)
        manifest = {
            **meta,
            "schema_version": MANIFEST_SCHEMA,
            "meta_schema": META_SCHEMA,
            "sidecar_layout": "sharded-jsonl",
            "sidecar_path": str(out_path),
            "manifest_path": str(manifest_path),
            "shard_dir": shard_dir.name,
            "shard_count": len(shards),
            "shard_target_bytes": shard_target_bytes,
            "shard_total_size_bytes": total_shard_bytes,
            "shards": shards,
        }
        out_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_manifest = manifest_path.with_name(f".{manifest_path.name}.{os.getpid()}.tmp")
        tmp_manifest.write_text(json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8")

        if shard_dir.exists():
            for old in shard_dir.glob("*.jsonl"):
                old.unlink()
        else:
            shard_dir.mkdir(parents=True, exist_ok=True)
        for shard in shards:
            (tmp_dir / shard["path"]).replace(shard_dir / shard["path"])
        tmp_dir.rmdir()
        tmp_manifest.replace(manifest_path)
        return manifest
    except Exception:
        if current_fh is not None:
            current_fh.close()
        for old in tmp_dir.glob("*"):
            old.unlink()
        if tmp_dir.exists():
            tmp_dir.rmdir()
        raise


def load_monolith_sidecar(sidecar_path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Parse the legacy monolith JSONL sidecar into ``(meta, records)``."""
    if not sidecar_path.is_file():
        raise ValueError(f"sidecar not found: {sidecar_path}")
    meta: dict[str, Any] = {}
    records: list[dict[str, Any]] = []
    with sidecar_path.open("r", encoding="utf-8") as fh:
        for index, line in enumerate(fh):
            line = line.strip()
            if not line:
                continue
            doc = json.loads(line)
            if index == 0:
                if not isinstance(doc, dict) or doc.get("schema_version") != META_SCHEMA:
                    raise ValueError("sidecar meta header missing or wrong schema")
                meta = doc
            elif isinstance(doc, dict):
                records.append(doc)
    if not meta:
        raise ValueError("empty sidecar (no meta header)")
    return meta, records


def load_sharded_sidecar(manifest_path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Parse a sharded sidecar manifest and return ``(manifest, records)``."""
    if not manifest_path.is_file():
        raise ValueError(f"manifest not found: {manifest_path}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or manifest.get("schema_version") != MANIFEST_SCHEMA:
        raise ValueError("sidecar manifest missing or wrong schema")
    shard_dir = manifest_path.parent / str(manifest.get("shard_dir") or "")
    records: list[dict[str, Any]] = []
    for shard in manifest.get("shards") or []:
        if not isinstance(shard, dict):
            continue
        shard_path = shard_dir / str(shard.get("path") or "")
        if not shard_path.is_file():
            raise ValueError(f"sidecar shard missing: {shard_path}")
        expected_sha = str(shard.get("sha256") or "")
        if expected_sha and _sha256_file(shard_path) != expected_sha:
            raise ValueError(f"sidecar shard checksum mismatch: {shard_path}")
        with shard_path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                doc = json.loads(line)
                if isinstance(doc, dict):
                    records.append(doc)
    return manifest, records


def load_sidecar(sidecar_path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Parse the sidecar into ``(meta, records)``.

    Auto-detects sharded vs monolith layout. Prefers the manifest when both
    ``<stem>.manifest.json`` and the monolith JSONL exist (sharded is canonical).
    Raises ``ValueError`` if the file/manifest is missing or malformed.
    """
    manifest_path = _manifest_path(sidecar_path)
    if manifest_path.is_file():
        return load_sharded_sidecar(manifest_path)
    return load_monolith_sidecar(sidecar_path)


def _stale_tolerance_pct() -> float:
    """Env-controlled tolerance for accepting a sidecar as approximately-fresh.

    Reads ``AUDITOOOR_SIDECAR_STALE_TOLERANCE_PCT`` (default 5.0). See the
    matching helper in ``hackerman-exploit-predicates-sidecar.py`` for the full
    rationale. Prevents the slow fallback path from firing on every minor
    corpus mutation.
    """
    raw = os.environ.get("AUDITOOOR_SIDECAR_STALE_TOLERANCE_PCT", "5.0").strip()
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return 5.0
    return max(0.0, min(100.0, value))


def _freshness_from_meta(tag_dir: Path, meta: dict[str, Any]) -> tuple[bool, str]:
    fingerprint, file_count = corpus_content_fingerprint(tag_dir, recursive=True)
    if meta.get("corpus_fingerprint") == fingerprint and meta.get("corpus_file_count") == file_count:
        return True, "fresh"
    tolerance_pct = _stale_tolerance_pct()
    cached_fp = meta.get("corpus_fingerprint")
    cached_count = int(meta.get("corpus_file_count") or 0)
    same_count_diff_fp = (
        cached_fp != fingerprint
        and cached_count == file_count
    )
    if tolerance_pct <= 0 or cached_count <= 0 or same_count_diff_fp:
        if cached_fp != fingerprint:
            return False, "corpus fingerprint changed"
        return False, "corpus file count changed"
    drift = abs(file_count - cached_count)
    drift_pct = (drift / cached_count) * 100.0 if cached_count else 100.0
    if drift_pct <= tolerance_pct:
        return True, (
            f"stale-tolerant: file-count drift {drift} ({drift_pct:.2f}%) "
            f"<= tolerance {tolerance_pct:.2f}% (cached={cached_count}, current={file_count})"
        )
    return False, (
        f"corpus fingerprint changed: file-count drift {drift} "
        f"({drift_pct:.2f}%) exceeds tolerance {tolerance_pct:.2f}% "
        f"(cached={cached_count}, current={file_count})"
    )


def sidecar_manifest_is_fresh(tag_dir: Path, manifest_path: Path) -> tuple[bool, str]:
    """Freshness check for the sharded manifest layout."""
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if not isinstance(manifest, dict) or manifest.get("schema_version") != MANIFEST_SCHEMA:
            return False, "sidecar manifest missing or wrong schema"
        shard_dir = manifest_path.parent / str(manifest.get("shard_dir") or "")
        for shard in manifest.get("shards") or []:
            if not isinstance(shard, dict):
                return False, "sidecar manifest contains malformed shard row"
            shard_path = shard_dir / str(shard.get("path") or "")
            if not shard_path.is_file():
                return False, f"sidecar shard missing: {shard_path}"
        return _freshness_from_meta(tag_dir, manifest)
    except (OSError, json.JSONDecodeError) as exc:
        return False, f"sidecar manifest unreadable: {exc}"


def sidecar_is_fresh(tag_dir: Path, sidecar_path: Path) -> tuple[bool, str]:
    """Cheap freshness check - stats corpus files, never re-parses YAML.

    Checks the sharded manifest when present; falls back to monolith JSONL.
    """
    manifest_path = _manifest_path(sidecar_path)
    if manifest_path.is_file():
        return sidecar_manifest_is_fresh(tag_dir, manifest_path)
    try:
        meta, _ = load_monolith_sidecar(sidecar_path)
    except (ValueError, json.JSONDecodeError) as exc:
        return False, f"sidecar unreadable: {exc}"
    return _freshness_from_meta(tag_dir, meta)


def _query_with_records(
    tag_dir: Path,
    engage_report: str | None,
    records: list[dict[str, Any]],
    limit: int,
    *,
    sidecar_used: bool,
    sidecar_path: Path | None,
    sidecar_status: str,
    meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    mod = _load_query_tool()
    detectors, warnings = mod._load_engage_report(engage_report)
    detectors.sort(key=mod._detector_sort_key)
    selected_detectors = detectors[:limit]
    detector_rows: list[dict[str, Any]] = []
    relationship_total = 0
    for detector in selected_detectors:
        relationships = mod._relationship_rows(detector, records, per_detector_limit=limit)
        relationship_total += len(relationships)
        detector_rows.append(
            {
                "detector_slug": detector["detector_slug"],
                "hit_count": detector["hit_count"],
                "severities": detector["severities"],
                "hits": detector["hits"],
                "relationships": relationships,
            }
        )
    digest = mod.stable_hash(
        {
            "schema": mod.SCHEMA,
            "tag_dir": str(tag_dir),
            "engage_report": engage_report or "",
            "limit": limit,
            "detectors": [row["detector_slug"] for row in detector_rows],
            "relationship_ids": [
                rel["relationship_id"]
                for row in detector_rows
                for rel in row["relationships"]
            ],
        }
    )
    summary = {
        "tag_files_scanned": int((meta or {}).get("tag_files_scanned") or 0),
        "records_loaded": int((meta or {}).get("records_loaded") or len(records)),
        "records_skipped_invalid": int((meta or {}).get("records_skipped_invalid") or 0),
        "records_skipped_non_record": int((meta or {}).get("records_skipped_non_record") or 0),
        "invalid_records": list((meta or {}).get("invalid_records") or [])[:10],
        "detectors_scanned": len(detectors),
        "detectors_returned": len(detector_rows),
        "relationship_rows_returned": relationship_total,
    }
    return {
        "schema": mod.SCHEMA,
        "context_pack_id": f"{mod.SCHEMA}:{digest[:16]}",
        "context_pack_hash": digest,
        "generated_at_utc": mod.utc_now(),
        "advisory_only": True,
        "submission_posture": "NOT_SUBMIT_READY",
        "inputs": {
            "tag_dir": str(tag_dir),
            "engage_report": str(engage_report or ""),
            "limit": limit,
        },
        "summary": summary,
        "warnings": warnings,
        "detectors": detector_rows,
        "sidecar_used": sidecar_used,
        "sidecar_path": str(sidecar_path or ""),
        "sidecar_status": sidecar_status,
    }


def load_relationship_summary(
    tag_dir: Path,
    engage_report: str | None,
    sidecar_path: Path | None = None,
    allow_slow_fallback: bool = True,
    *,
    limit: int = 5,
) -> dict[str, Any]:
    """Return detector relationships by joining engage-report rows to the sidecar."""
    mod = _load_query_tool()
    limit = mod.clamp_limit(limit, default=5, maximum=50)
    sidecar_path = sidecar_path or _default_sidecar_path(tag_dir)
    fresh, reason = sidecar_is_fresh(tag_dir, sidecar_path)
    if fresh:
        meta, records = load_sidecar(sidecar_path)
        return _query_with_records(
            tag_dir,
            engage_report,
            records,
            limit,
            sidecar_used=True,
            sidecar_path=sidecar_path,
            sidecar_status=reason,
            meta=meta,
        )
    if not allow_slow_fallback:
        raise ValueError(f"sidecar not usable ({reason}) and slow fallback disabled")
    args = argparse.Namespace(
        tag_dir=str(tag_dir),
        engage_report=engage_report or None,
        limit=limit,
        json=True,
        out="-",
    )
    payload = mod.build_payload(args)
    payload["sidecar_used"] = False
    payload["sidecar_path"] = str(sidecar_path)
    payload["sidecar_status"] = reason
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag-dir", default=str(DEFAULT_TAGS_DIR))
    parser.add_argument("--out", default=None)
    parser.add_argument(
        "--monolith",
        action="store_true",
        help="Write the legacy single JSONL sidecar instead of the sharded manifest layout.",
    )
    parser.add_argument(
        "--shard-target-mb",
        default=str(DEFAULT_SHARD_TARGET_BYTES / 1024 / 1024),
        help="Approximate maximum shard size in MiB for the sharded layout.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Only report freshness (exit 0 fresh, 1 stale). Does not rebuild.",
    )
    parser.add_argument(
        "--engage-report",
        default=None,
        help="Optional engage_report.json or engage_report.md path. When set, query from the sidecar instead of rebuilding.",
    )
    parser.add_argument("--limit", type=int, default=5)
    parser.add_argument(
        "--no-slow-fallback",
        action="store_true",
        help="Fail instead of reparsing the corpus when querying with a stale or missing sidecar.",
    )
    parser.add_argument("--json", action="store_true", help="Emit a JSON summary or query payload.")
    args = parser.parse_args(argv)

    tag_dir = Path(args.tag_dir).expanduser().resolve()
    out_path = (
        Path(args.out).expanduser().resolve()
        if args.out
        else _default_sidecar_path(tag_dir).expanduser().resolve()
    )
    if not tag_dir.is_dir():
        print(f"tag dir not found: {tag_dir}", file=sys.stderr)
        return 2

    if args.check:
        fresh, reason = sidecar_is_fresh(tag_dir, out_path)
        result = {"fresh": fresh, "reason": reason, "sidecar_path": str(out_path)}
        if args.json:
            print(json.dumps(result, sort_keys=True))
        else:
            print(f"{'FRESH' if fresh else 'STALE'}: {reason} ({out_path})")
        return 0 if fresh else 1

    if args.engage_report:
        payload = load_relationship_summary(
            tag_dir,
            args.engage_report,
            out_path,
            allow_slow_fallback=not args.no_slow_fallback,
            limit=args.limit,
        )
        if args.json:
            print(json.dumps(payload, sort_keys=True))
        else:
            mod = _load_query_tool()
            print(mod.render_markdown(payload), end="")
        return 0

    if args.monolith:
        meta = build_sidecar(tag_dir, out_path)
        layout = "jsonl"
    else:
        meta = build_sharded_sidecar(
            tag_dir,
            out_path,
            shard_target_bytes=int(float(args.shard_target_mb) * 1024 * 1024),
        )
        layout = meta.get("sidecar_layout", "sharded-jsonl")

    result = {
        "built": True,
        "sidecar_path": str(out_path),
        "manifest_path": str(_manifest_path(out_path)) if not args.monolith else "",
        "sidecar_layout": layout,
        "records_loaded": meta["records_loaded"],
        "corpus_file_count": meta["corpus_file_count"],
        "corpus_fingerprint": meta["corpus_fingerprint"],
    }
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        dest = _manifest_path(out_path) if not args.monolith else out_path
        print(
            f"built sidecar: {meta['records_loaded']} records from "
            f"{meta['corpus_file_count']} files -> {dest}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
