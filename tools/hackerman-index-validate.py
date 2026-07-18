#!/usr/bin/env python3
"""Validate hackerman corpus indexes for integrity.

Wave-2 PR-A acceptance tool: walks ``audit/corpus_tags/index/*.jsonl``
plus any sharded ``audit/corpus_tags/index/<name>.d/`` subdirectories,
counts rows per index, verifies sharded-index manifest consistency, and
emits a deterministic verdict suitable for CI gating.

Verdict keys (JSON output, stdout):

    schema:      'auditooor.hackerman_index_validate.v1'
    index_dir:   absolute path of the index dir scanned
    indexes:     { <index_name>: { rows: int, kind: 'monolith'|'sharded',
                                  path: str, shards: [str], manifest_rows: int|None,
                                  manifest_shards: [str]|None } }
    expected_indexes: list of expected canonical index names
    missing_indexes:  list of expected indexes not present on disk
    unknown_indexes:  list of indexes present on disk but not in INDEX_NAMES
    errors:           list of {index, code, detail} structural errors
    verdict:          'pass' | 'fail'
    summary:          one-line human-readable summary

Exit codes: 0 = pass, 1 = fail (structural errors or missing indexes).

Designed to be run after ``make hackerman-index`` to confirm the five
Wave-2 PR-A additive indexes (``by_cve_id``, ``by_ghsa_id``, ``by_firm``,
``by_verification_tier``, ``by_incident_date``) plus the legacy 11
indexes are all present and consistent.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INDEX_DIR = REPO_ROOT / "audit" / "corpus_tags" / "index"
SCHEMA_VERSION = "auditooor.hackerman_index_validate.v1"


def _load_index_build_module() -> Any:
    """Load the sibling index-build module to share INDEX_NAMES / SHARDED set."""
    spec = importlib.util.spec_from_file_location(
        "_hackerman_index_build", str(REPO_ROOT / "tools" / "hackerman-index-build.py")
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


def _count_jsonl_rows(path: Path) -> Tuple[int, List[Dict[str, Any]]]:
    """Return (row_count, structural_errors) for ``path``.

    A row is counted if the line parses as a JSON object with a non-empty
    ``key`` field; otherwise the line is reported as a structural error.
    Empty lines are skipped silently (matches build-side semantics).
    """
    rows = 0
    errors: List[Dict[str, Any]] = []
    if not path.exists():
        return 0, errors
    with path.open("r", encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, start=1):
            line = raw.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError as exc:
                errors.append({
                    "code": "json-decode-error",
                    "detail": f"{path.name}:{lineno}: {exc}",
                })
                continue
            if not isinstance(payload, dict):
                errors.append({
                    "code": "row-not-object",
                    "detail": f"{path.name}:{lineno}: row is {type(payload).__name__}",
                })
                continue
            key = payload.get("key")
            if key in (None, ""):
                errors.append({
                    "code": "row-missing-key",
                    "detail": f"{path.name}:{lineno}: row has empty/missing 'key'",
                })
                continue
            rows += 1
    return rows, errors


def _validate_sharded_index(
    index_name: str,
    shard_dir: Path,
    expected_schema: str,
) -> Dict[str, Any]:
    """Validate a sharded index directory and return its summary entry."""
    summary: Dict[str, Any] = {
        "kind": "sharded",
        "path": str(shard_dir),
        "rows": 0,
        "shards": [],
        "manifest_rows": None,
        "manifest_shards": None,
    }
    structural_errors: List[Dict[str, Any]] = []

    manifest_path = shard_dir / "manifest.json"
    manifest: Optional[Dict[str, Any]] = None
    if not manifest_path.exists():
        structural_errors.append({
            "index": index_name,
            "code": "manifest-missing",
            "detail": f"{manifest_path} not found",
        })
    else:
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            structural_errors.append({
                "index": index_name,
                "code": "manifest-invalid-json",
                "detail": f"{manifest_path}: {exc}",
            })
        else:
            if not isinstance(manifest, dict):
                structural_errors.append({
                    "index": index_name,
                    "code": "manifest-not-object",
                    "detail": f"{manifest_path}: top-level is {type(manifest).__name__}",
                })
                manifest = None

    shard_paths = sorted(shard_dir.glob("*.jsonl"))
    summary["shards"] = [p.name for p in shard_paths]

    total_rows = 0
    for shard_path in shard_paths:
        rows, row_errors = _count_jsonl_rows(shard_path)
        total_rows += rows
        for err in row_errors:
            structural_errors.append({"index": index_name, **err})
    summary["rows"] = total_rows

    if manifest is not None:
        schema = manifest.get("schema")
        if schema != expected_schema:
            structural_errors.append({
                "index": index_name,
                "code": "manifest-schema-mismatch",
                "detail": f"manifest.schema={schema!r} expected {expected_schema!r}",
            })
        manifest_rows = manifest.get("rows")
        manifest_shards = manifest.get("shards")
        summary["manifest_rows"] = manifest_rows if isinstance(manifest_rows, int) else None
        summary["manifest_shards"] = manifest_shards if isinstance(manifest_shards, list) else None
        if isinstance(manifest_rows, int) and manifest_rows != total_rows:
            structural_errors.append({
                "index": index_name,
                "code": "manifest-rows-mismatch",
                "detail": f"manifest.rows={manifest_rows} but counted {total_rows} rows on disk",
            })
        if isinstance(manifest_shards, list) and sorted(manifest_shards) != summary["shards"]:
            structural_errors.append({
                "index": index_name,
                "code": "manifest-shards-mismatch",
                "detail": (
                    f"manifest.shards={sorted(manifest_shards)!r} but on-disk={summary['shards']!r}"
                ),
            })
        if manifest.get("index_name") not in (index_name, None):
            structural_errors.append({
                "index": index_name,
                "code": "manifest-index-name-mismatch",
                "detail": f"manifest.index_name={manifest.get('index_name')!r} expected {index_name!r}",
            })

    summary["errors"] = structural_errors
    return summary


def _manifest_error(code: str, detail: str) -> Dict[str, Any]:
    return {"index": "manifest", "code": code, "detail": detail}


def _validate_root_manifest(
    index_dir: Path,
    build_mod: Any,
    counted_rows_by_index: Dict[str, int],
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Validate ``index/manifest.json`` against canonical index artifacts."""
    manifest_path = index_dir / "manifest.json"
    summary: Dict[str, Any] = {
        "path": str(manifest_path),
        "present": manifest_path.is_file(),
        "schema": None,
        "corpus_index_hash": "",
        "file_count": None,
    }
    errors: List[Dict[str, Any]] = []

    if not manifest_path.is_file():
        errors.append(_manifest_error("root-manifest-missing", f"{manifest_path} not found"))
        return summary, errors

    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        errors.append(_manifest_error("root-manifest-invalid-json", f"{manifest_path}: {exc}"))
        return summary, errors

    if not isinstance(payload, dict):
        errors.append(_manifest_error("root-manifest-not-object", f"{manifest_path}: top-level is {type(payload).__name__}"))
        return summary, errors

    summary["schema"] = payload.get("schema")
    summary["corpus_index_hash"] = str(payload.get("corpus_index_hash") or "")
    summary["file_count"] = payload.get("file_count")

    expected_schema = getattr(build_mod, "ROOT_INDEX_MANIFEST_SCHEMA", "")
    if payload.get("schema") != expected_schema:
        errors.append(_manifest_error(
            "root-manifest-schema-mismatch",
            f"manifest.schema={payload.get('schema')!r} expected {expected_schema!r}",
        ))

    preserve_existing = payload.get("preserve_existing")
    if not isinstance(preserve_existing, bool):
        errors.append(_manifest_error(
            "root-manifest-preserve-existing-invalid",
            f"manifest.preserve_existing={preserve_existing!r} expected bool",
        ))
        preserve_existing = None

    preserved_rows = payload.get("preserved_rows_by_index")
    if not isinstance(preserved_rows, dict):
        errors.append(_manifest_error("root-manifest-preserved-rows-invalid", "preserved_rows_by_index must be an object"))
        preserved_rows = {}
    row_counts = payload.get("row_counts_by_index")
    if not isinstance(row_counts, dict):
        errors.append(_manifest_error("root-manifest-row-counts-invalid", "row_counts_by_index must be an object"))
        row_counts = {}

    normalized_row_counts = {
        str(key): value
        for key, value in sorted(row_counts.items())
        if isinstance(value, int)
    }
    if normalized_row_counts != counted_rows_by_index:
        errors.append(_manifest_error(
            "root-manifest-row-counts-mismatch",
            f"manifest.row_counts_by_index={normalized_row_counts!r} counted={counted_rows_by_index!r}",
        ))

    expected = build_mod.build_root_index_manifest(
        index_dir,
        preserve_existing=preserve_existing,
        preserved_rows_by_index=preserved_rows,
        row_counts_by_index=row_counts,
    )

    if payload.get("file_count") != expected.get("file_count"):
        errors.append(_manifest_error(
            "root-manifest-filecount-mismatch",
            f"manifest.file_count={payload.get('file_count')!r} expected {expected.get('file_count')!r}",
        ))
    if payload.get("files") != expected.get("files"):
        errors.append(_manifest_error("root-manifest-files-mismatch", "manifest.files do not match canonical index artifacts"))
    if payload.get("corpus_index_hash") != expected.get("corpus_index_hash"):
        errors.append(_manifest_error(
            "root-manifest-hash-mismatch",
            f"manifest.corpus_index_hash={payload.get('corpus_index_hash')!r} expected {expected.get('corpus_index_hash')!r}",
        ))
    if payload.get("index_names") != expected.get("index_names"):
        errors.append(_manifest_error("root-manifest-index-names-mismatch", "manifest.index_names do not match builder"))
    if payload.get("sharded_index_names") != expected.get("sharded_index_names"):
        errors.append(_manifest_error("root-manifest-sharded-index-names-mismatch", "manifest.sharded_index_names do not match builder"))

    return summary, errors


def validate_indexes(index_dir: Path) -> Dict[str, Any]:
    """Walk ``index_dir`` and return a deterministic validate verdict."""
    build_mod = _load_index_build_module()
    index_names: Tuple[str, ...] = tuple(build_mod.INDEX_NAMES)
    sharded_names = set(build_mod.SHARDED_INDEX_NAMES)
    expected_schema: str = build_mod.SHARDED_INDEX_SCHEMA

    verdict: Dict[str, Any] = {
        "schema": SCHEMA_VERSION,
        "index_dir": str(index_dir),
        "expected_indexes": list(index_names),
        "indexes": {},
        "root_manifest": {},
        "missing_indexes": [],
        "unknown_indexes": [],
        "errors": [],
        "verdict": "pass",
        "summary": "",
    }

    if not index_dir.is_dir():
        verdict["verdict"] = "fail"
        verdict["errors"].append({
            "index": None,
            "code": "index-dir-missing",
            "detail": f"{index_dir} is not a directory",
        })
        verdict["summary"] = f"index_dir {index_dir} not found"
        return verdict

    on_disk_monoliths = {
        p.stem for p in index_dir.glob("*.jsonl") if p.is_file()
    }
    on_disk_sharded = {
        p.name[:-2] for p in index_dir.glob("*.d") if p.is_dir() and p.name.endswith(".d")
    }
    on_disk_all = on_disk_monoliths | on_disk_sharded

    for name in index_names:
        if name in sharded_names:
            shard_dir = index_dir / f"{name}.d"
            if not shard_dir.is_dir():
                verdict["missing_indexes"].append(name)
                continue
            entry = _validate_sharded_index(name, shard_dir, expected_schema)
            verdict["indexes"][name] = entry
            verdict["errors"].extend(entry.pop("errors", []))
        else:
            monolith = index_dir / f"{name}.jsonl"
            if not monolith.exists():
                verdict["missing_indexes"].append(name)
                continue
            rows, row_errors = _count_jsonl_rows(monolith)
            verdict["indexes"][name] = {
                "kind": "monolith",
                "path": str(monolith),
                "rows": rows,
                "shards": [],
                "manifest_rows": None,
                "manifest_shards": None,
            }
            for err in row_errors:
                verdict["errors"].append({"index": name, **err})

    unknown = sorted(on_disk_all - set(index_names))
    verdict["unknown_indexes"] = unknown

    counted_rows_by_index = {
        name: int(entry["rows"])
        for name, entry in sorted(verdict["indexes"].items())
        if name in index_names
    }
    root_manifest_summary, root_manifest_errors = _validate_root_manifest(
        index_dir,
        build_mod,
        counted_rows_by_index,
    )
    verdict["root_manifest"] = root_manifest_summary
    verdict["errors"].extend(root_manifest_errors)

    if verdict["missing_indexes"] or verdict["errors"]:
        verdict["verdict"] = "fail"

    total_rows = sum(entry["rows"] for entry in verdict["indexes"].values())
    summary_parts: List[str] = [
        f"{len(verdict['indexes'])}/{len(index_names)} indexes present",
        f"{total_rows} total rows",
    ]
    if verdict["missing_indexes"]:
        summary_parts.append(f"missing={verdict['missing_indexes']}")
    if verdict["errors"]:
        summary_parts.append(f"errors={len(verdict['errors'])}")
    if verdict["unknown_indexes"]:
        summary_parts.append(f"unknown={verdict['unknown_indexes']}")
    verdict["summary"] = "; ".join(summary_parts)
    return verdict


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--index-dir",
        default=str(DEFAULT_INDEX_DIR),
        help="Directory containing by_*.jsonl + by_*.d/ index files.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress JSON output; only the exit code signals pass/fail.",
    )
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Print only the one-line ``summary`` field instead of full JSON.",
    )
    args = parser.parse_args(argv)

    verdict = validate_indexes(Path(args.index_dir))
    if not args.quiet:
        if args.summary_only:
            print(verdict["summary"])
        else:
            print(json.dumps(verdict, indent=2, sort_keys=True))
    return 0 if verdict["verdict"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
