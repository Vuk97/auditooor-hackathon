#!/usr/bin/env python3
"""Report whether hunter-facing Hackerman sidecars cover the active corpus.

This is a visibility/enforcement helper for HACKERMAN_V3 Lane B/J. It does not
rebuild sidecars. It compares the canonical recursive corpus walker against the
derived sidecar metadata so operators can see when mined records are present on
disk but absent from hunter-facing MCP surfaces.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = REPO_ROOT / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

from hackerman_query_common import (  # noqa: E402
    DEFAULT_DERIVED_DIR,
    DEFAULT_TAGS_DIR,
    iter_corpus_record_paths,
    yaml_load,
)


SCHEMA_VERSION = "auditooor.hackerman_sidecar_coverage_report.v1"
ACTIVE_RECORD_SCHEMAS = {
    "auditooor.hackerman_record.v1",
    "auditooor.hackerman_record.v1.1",
    "auditooor.darknavy_web3_record.v1",
}
SIZE_WARN_BYTES_DEFAULT = 50 * 1024 * 1024
SIZE_HARD_BYTES_DEFAULT = 95 * 1024 * 1024
BLOCKED_MANIFEST_SUFFIX = ".blocked.json"


SIDECAR_SPECS = (
    {
        "name": "exploit_predicates",
        "file": "exploit_predicates.jsonl",
        "manifest_file": "exploit_predicates.manifest.json",
        "sharded": True,
        "kind": "jsonl",
        "record_count_keys": ("records_emitted",),
    },
    {
        "name": "detector_relationship_records",
        "file": "detector_relationship_records.jsonl",
        "manifest_file": "detector_relationship_records.manifest.json",
        "sharded": True,
        "kind": "jsonl",
        "record_count_keys": ("records_loaded", "records_emitted"),
    },
    {
        "name": "chain_candidates",
        "file": "chain_candidates.jsonl",
        "manifest_file": "chain_candidates.manifest.json",
        "sharded": True,
        "kind": "jsonl",
        "record_count_keys": ("records_emitted",),
    },
    {
        "name": "chain_unify_payload",
        "file": "chain_unify_payload.json",
        "kind": "json",
        "record_count_keys": ("chain_candidates_records_emitted",),
    },
)


def _load_record(path: Path) -> dict[str, Any] | None:
    try:
        if path.suffix == ".json":
            doc = json.loads(path.read_text(encoding="utf-8"))
        else:
            doc = yaml_load(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return doc if isinstance(doc, dict) else None


def corpus_inventory(tag_dir: Path) -> dict[str, Any]:
    record_paths = list(iter_corpus_record_paths(tag_dir))
    by_schema: Counter[str] = Counter()
    by_top_level: Counter[str] = Counter()
    active_paths: list[str] = []
    for item in record_paths:
        doc = _load_record(item.path)
        schema = str((doc or {}).get("schema_version") or "")
        if schema:
            by_schema[schema] += 1
        if schema in ACTIVE_RECORD_SCHEMAS:
            active_paths.append(item.relative_path)
            top = item.relative_path.split("/", 1)[0] if "/" in item.relative_path else "."
            by_top_level[top] += 1
    return {
        "record_files_seen": len(record_paths),
        "active_records": len(active_paths),
        "active_record_schemas": sorted(ACTIVE_RECORD_SCHEMAS),
        "schemas_seen": dict(sorted(by_schema.items())),
        "active_records_by_top_level": dict(sorted(by_top_level.items())),
    }


def _jsonl_meta_and_count(path: Path) -> tuple[dict[str, Any], int]:
    meta: dict[str, Any] = {}
    row_count = 0
    with path.open("r", encoding="utf-8") as fh:
        for index, line in enumerate(fh):
            line = line.strip()
            if not line:
                continue
            if index == 0:
                try:
                    doc = json.loads(line)
                except json.JSONDecodeError:
                    doc = {}
                if isinstance(doc, dict):
                    meta = doc
            else:
                row_count += 1
    return meta, row_count


def _json_meta(path: Path) -> dict[str, Any]:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    if not isinstance(doc, dict):
        return {}
    meta = doc.get("meta")
    if isinstance(meta, dict):
        return meta
    return doc


def _sharded_manifest_reader(path: Path, manifest_file: str) -> dict[str, Any]:
    """Read a sharded-sidecar manifest and verify shard presence.

    Works for any sidecar whose root `.jsonl` is a 0-byte marker and whose
    records live in a shard directory enumerated by a companion manifest JSON.
    The manifest must have a ``shard_dir`` field and a ``shards`` list whose
    entries carry a ``path`` key relative to ``shard_dir``.

    Returns an empty dict when no manifest file is present (caller falls back
    to the regular file-based path).  Returns a dict with ``unreadable=True``
    on parse errors so the caller can surface a diagnostic blocker.
    """
    manifest_path = path.with_name(manifest_file)
    if not manifest_path.is_file():
        return {}
    try:
        doc = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception:
        return {"path": str(manifest_path), "unreadable": True}
    if not isinstance(doc, dict):
        return {"path": str(manifest_path), "unreadable": True}
    # Accept any manifest that has a shard_dir - no hard schema-version pin so
    # future sidecars with new manifest schemas are handled transparently.
    if not doc.get("shard_dir"):
        doc = dict(doc)
        doc["path"] = str(manifest_path)
        doc["unreadable"] = True
        return doc
    shard_dir = manifest_path.parent / str(doc.get("shard_dir") or "")
    missing_shards: list[str] = []
    shard_rows = doc.get("shards") if isinstance(doc.get("shards"), list) else []
    for shard in shard_rows:
        if not isinstance(shard, dict):
            continue
        shard_path = shard_dir / str(shard.get("path") or "")
        if not shard_path.is_file():
            missing_shards.append(str(shard_path))
    out = dict(doc)
    out["path"] = str(manifest_path)
    out["shards_missing"] = missing_shards[:20]
    out["all_shards_present"] = not missing_shards
    return out


def _exploit_predicates_manifest(path: Path) -> dict[str, Any]:
    """Backward-compat wrapper - delegates to the generic sharded reader."""
    return _sharded_manifest_reader(path, "exploit_predicates.manifest.json")


def _blocked_manifest(path: Path) -> dict[str, Any]:
    manifest_path = path.with_name(f"{path.name}{BLOCKED_MANIFEST_SUFFIX}")
    if not manifest_path.is_file():
        return {}
    try:
        doc = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception:
        return {"path": str(manifest_path), "unreadable": True}
    if not isinstance(doc, dict):
        return {"path": str(manifest_path), "unreadable": True}
    doc = dict(doc)
    doc.setdefault("path", str(manifest_path))
    return doc


def _first_int(meta: dict[str, Any], keys: tuple[str, ...]) -> int:
    for key in keys:
        value = meta.get(key)
        if isinstance(value, bool):
            continue
        if isinstance(value, (int, float)):
            return int(value)
        try:
            return int(str(value))
        except (TypeError, ValueError):
            continue
    return 0


def _ratio(numerator: int, denominator: int) -> float:
    return round(float(numerator) / float(denominator), 6) if denominator else 0.0


def sidecar_row(
    derived_dir: Path,
    spec: dict[str, Any],
    *,
    active_records: int,
    canonical_files: int,
    size_warn_bytes: int,
    size_hard_bytes: int,
    min_file_coverage: float,
) -> dict[str, Any]:
    path = derived_dir / str(spec["file"])
    manifest_file = spec.get("manifest_file", "")
    if manifest_file and (spec.get("sharded") or (path.is_file() and path.stat().st_size == 0)):
        manifest = _sharded_manifest_reader(path, manifest_file)
    else:
        manifest = {}
    row: dict[str, Any] = {
        "name": spec["name"],
        "path": str(manifest.get("path") or path),
        "exists": path.is_file() or bool(manifest),
    }
    if manifest and not manifest.get("unreadable"):
        meta = manifest
        row_count = int(meta.get("records_emitted") or 0)
        size_bytes = int(meta.get("shard_total_size_bytes") or 0)
        max_shard_size_bytes = 0
        if not size_bytes:
            shard_dir = Path(str(meta.get("path") or path)).parent / str(meta.get("shard_dir") or "")
            for shard in meta.get("shards") or []:
                if isinstance(shard, dict):
                    shard_path = shard_dir / str(shard.get("path") or "")
                    if shard_path.is_file():
                        shard_size = shard_path.stat().st_size
                        size_bytes += shard_size
                        max_shard_size_bytes = max(max_shard_size_bytes, shard_size)
        if not max_shard_size_bytes:
            for shard in meta.get("shards") or []:
                if isinstance(shard, dict):
                    max_shard_size_bytes = max(
                        max_shard_size_bytes,
                        _first_int(shard, ("size_bytes",)),
                    )
        size_limit_check_bytes = max_shard_size_bytes
    elif not path.is_file():
        row["status"] = "missing"
        row["blockers"] = ["sidecar_missing"]
        blocked_manifest = _blocked_manifest(path)
        if blocked_manifest:
            row["blocked_manifest"] = blocked_manifest
            for blocker in blocked_manifest.get("blockers") or []:
                if blocker not in row["blockers"]:
                    row["blockers"].append(str(blocker))
        return row
    else:
        size_bytes = path.stat().st_size
        if spec.get("kind") == "jsonl":
            meta, row_count = _jsonl_meta_and_count(path)
        else:
            meta = _json_meta(path)
            row_count = _first_int(meta, tuple(spec.get("record_count_keys") or ()))
        size_limit_check_bytes = size_bytes

    corpus_file_count = _first_int(meta, ("corpus_file_count",))
    emitted_records = _first_int(meta, tuple(spec.get("record_count_keys") or ()))
    if not emitted_records:
        emitted_records = row_count

    blockers: list[str] = []
    warnings: list[str] = []
    blocked_manifest = _blocked_manifest(path)
    if blocked_manifest:
        blockers.extend(str(blocker) for blocker in (blocked_manifest.get("blockers") or []))
    if manifest.get("unreadable"):
        blockers.append("sidecar_manifest_unreadable")
    if manifest and not manifest.get("all_shards_present", True):
        blockers.append("sidecar_shard_missing")
    file_coverage = _ratio(corpus_file_count, canonical_files)
    row_coverage = _ratio(emitted_records, active_records)
    if file_coverage < min_file_coverage:
        blockers.append("sidecar_not_recursive_corpus_parity")
    if size_limit_check_bytes >= size_hard_bytes:
        blockers.append("sidecar_size_hard_limit")
    elif size_limit_check_bytes >= size_warn_bytes:
        warnings.append("sidecar_size_warning")
    blockers = list(dict.fromkeys(blockers))

    row.update(
        {
            "status": "blocked" if blockers else "ok",
            "size_bytes": size_bytes,
            "size_limit_check_bytes": size_limit_check_bytes,
            "shard_total_size_bytes": int(meta.get("shard_total_size_bytes") or 0),
            "max_shard_size_bytes": int(size_limit_check_bytes),
            "size_warn_bytes": size_warn_bytes,
            "size_hard_bytes": size_hard_bytes,
            "meta_schema": meta.get("schema_version", ""),
            "sidecar_schema": meta.get("sidecar_schema", ""),
            "sidecar_layout": meta.get("sidecar_layout", "jsonl"),
            "manifest_path": str(manifest.get("path") or ""),
            "shard_count": int(meta.get("shard_count") or 0),
            "meta_corpus_file_count": corpus_file_count,
            "emitted_record_count": emitted_records,
            "physical_row_count": row_count,
            "canonical_file_coverage_ratio": file_coverage,
            "active_record_coverage_ratio": row_coverage,
            "min_file_coverage": min_file_coverage,
            "blockers": blockers,
            "warnings": warnings,
        }
    )
    if manifest:
        row["manifest"] = {
            "schema_version": manifest.get("schema_version", ""),
            "path": manifest.get("path", ""),
            "shard_dir": manifest.get("shard_dir", ""),
            "shard_count": manifest.get("shard_count", 0),
            "all_shards_present": manifest.get("all_shards_present", False),
            "shards_missing": manifest.get("shards_missing", []),
        }
    if blocked_manifest:
        row["blocked_manifest"] = blocked_manifest
    return row


def build_report(
    tag_dir: Path,
    derived_dir: Path,
    *,
    min_file_coverage: float,
    size_warn_bytes: int,
    size_hard_bytes: int,
) -> dict[str, Any]:
    corpus = corpus_inventory(tag_dir)
    sidecars = [
        sidecar_row(
            derived_dir,
            spec,
            active_records=int(corpus["active_records"]),
            canonical_files=int(corpus["record_files_seen"]),
            size_warn_bytes=size_warn_bytes,
            size_hard_bytes=size_hard_bytes,
            min_file_coverage=min_file_coverage,
        )
        for spec in SIDECAR_SPECS
    ]
    blockers = [
        f"{row['name']}:{blocker}"
        for row in sidecars
        for blocker in row.get("blockers", [])
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "tag_dir": str(tag_dir),
        "derived_dir": str(derived_dir),
        "corpus": corpus,
        "sidecars": sidecars,
        "blockers": blockers,
        "status": "blocked" if blockers else "ok",
    }


def _bytes_from_mb(value: str | int | float) -> int:
    return int(float(value) * 1024 * 1024)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag-dir", default=str(DEFAULT_TAGS_DIR))
    parser.add_argument("--derived-dir", default=str(DEFAULT_DERIVED_DIR))
    parser.add_argument("--out-json")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--min-file-coverage", type=float, default=0.98)
    parser.add_argument("--size-warn-mb", default=str(SIZE_WARN_BYTES_DEFAULT / 1024 / 1024))
    parser.add_argument("--size-hard-mb", default=str(SIZE_HARD_BYTES_DEFAULT / 1024 / 1024))
    args = parser.parse_args(argv)

    tag_dir = Path(args.tag_dir).expanduser().resolve()
    derived_dir = Path(args.derived_dir).expanduser().resolve()
    if not tag_dir.is_dir():
        print(f"tag dir not found: {tag_dir}", file=sys.stderr)
        return 2
    report = build_report(
        tag_dir,
        derived_dir,
        min_file_coverage=max(0.0, min(float(args.min_file_coverage), 1.0)),
        size_warn_bytes=_bytes_from_mb(args.size_warn_mb),
        size_hard_bytes=_bytes_from_mb(args.size_hard_mb),
    )
    if args.out_json:
        out_path = Path(args.out_json).expanduser().resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.json or not args.out_json:
        print(json.dumps(report, indent=2, sort_keys=True))
    return 1 if args.strict and report.get("status") != "ok" else 0


if __name__ == "__main__":
    raise SystemExit(main())
