#!/usr/bin/env python3
"""Build deterministic JSONL indices for hackerman_record v1 YAML files."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


REPO_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = REPO_ROOT / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

from hackerman_query_common import compute_shape_from_signature

DEFAULT_TAG_DIR = REPO_ROOT / "audit" / "corpus_tags" / "tags"
DEFAULT_INDEX_DIR = REPO_ROOT / "audit" / "corpus_tags" / "index"

INDEX_NAMES = (
    "by_attack_class",
    "by_target_repo",
    "by_bug_class",
    "by_language",
    "by_function_shape",
    "by_shape_hash",
    "by_target_domain",
    "by_audit_year",
    "by_attacker_role",
    "by_fix_pattern",
    "by_severity",
    # Wave-2 PR-A additive indexes (5 new acceptance-criterion indexes).
    "by_cve_id",
    "by_ghsa_id",
    "by_firm",
    "by_verification_tier",
    "by_incident_date",
)
SHARDED_INDEX_NAMES = {"by_function_shape"}
SHARDED_INDEX_SCHEMA = "auditooor.hackerman_index_shards.v1"
ROOT_INDEX_MANIFEST_SCHEMA = "auditooor.hackerman_index_manifest.v1"
UNKNOWN_AUDIT_YEAR_KEY = "unknown"
UNKNOWN_INCIDENT_DATE_KEY = "unknown"
FUNCTION_NAME_HINT_PREFIX = "function-name-hint:"

# Wave-2 PR-A additive extraction patterns.
_CVE_REGEX = re.compile(r"\bCVE-\d{4}-\d{4,}\b")
_GHSA_REGEX = re.compile(r"\bGHSA-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}\b")
_VERIFICATION_TIER_SHAPE_PREFIX = "verification_tier:"
_FIRM_SHAPE_PREFIX = "firm-"
# source_audit_ref prefixes that identify the publishing firm/source.
# Maps the leading colon-segment to a canonical firm key.
_SOURCE_AUDIT_REF_FIRM_PREFIX = "audit-firm:"


def shard_for_key(key: Any) -> str:
    return hashlib.sha256(str(key).encode("utf-8")).hexdigest()[:2]


def _load_validator() -> Any:
    spec = importlib.util.spec_from_file_location(
        "_hackerman_record_validate", str(REPO_ROOT / "tools" / "hackerman-record-validate.py")
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


_VALIDATOR = _load_validator()


def _base_row(record: Dict[str, Any], tag_file: str) -> Dict[str, Any]:
    # record_id is the index key and stays strict. The remaining descriptive
    # fields are optional on a handful of older/partial corpus records; a single
    # field-less record previously aborted the entire corpus reindex. Default to
    # empty/unknown so the build is robust (the index rows already tolerate
    # empties, and the per-field indices key on the resolved value).
    row = {
        "record_id": record["record_id"],
        "source_audit_ref": record.get("source_audit_ref", ""),
        "tag_file": tag_file,
        "target_repo": record.get("target_repo", "unknown"),
        "target_language": record.get("target_language", "unknown"),
        "target_domain": record.get("target_domain", "unknown"),
        "bug_class": record.get("bug_class", "unknown-class"),
        "attack_class": record.get("attack_class", "unknown-attack"),
        "severity_at_finding": record.get("severity_at_finding", "unknown"),
        "year": record.get("year", 0),
    }
    extensions = record.get("record_extensions") or {}
    if isinstance(extensions, dict):
        backfill = extensions.get("heuristic_attack_class_backfill") or extensions.get(
            "audit_firm_report_attack_class_backfill"
        )
        if isinstance(backfill, dict) and backfill.get("new_attack_class") == record.get("attack_class"):
            row["attack_class_provenance"] = "heuristic"
            row["classification_scope"] = str(backfill.get("classification_scope") or "")
            confidence = backfill.get("confidence")
            if isinstance(confidence, (int, float)):
                row["attack_class_confidence"] = float(confidence)
    return row


IndexMap = Dict[str, Dict[str, List[Dict[str, Any]]]]


def _append(index: IndexMap, name: str, key: Any, row: Dict[str, Any]) -> None:
    index[name].setdefault(str(key), []).append(row)


def _audit_year_index_key(record: Dict[str, Any]) -> Any:
    """Keep Solodit unknown-year sentinel rows out of the real year-2000 bucket."""
    if record.get("year") == 2000 and str(record.get("source_audit_ref") or "").startswith("solodit-spec:"):
        return UNKNOWN_AUDIT_YEAR_KEY
    # ``year`` is optional on a few partial records; fall back to the unknown
    # sentinel rather than abort the whole reindex on a single field-less row.
    return record.get("year", UNKNOWN_AUDIT_YEAR_KEY)


def _shape_hash_indexable_signature(signature: str) -> bool:
    """Only real source signatures should join the exact shape-hash index."""
    return bool(signature.strip()) and not signature.strip().lower().startswith(FUNCTION_NAME_HINT_PREFIX)


def _extract_cve_ids(record: Dict[str, Any]) -> List[str]:
    """Return all CVE identifiers attached to ``record``.

    Order of precedence:
    1. Top-level ``cve_id`` (v1.1 first-class field).
    2. Regex match against ``source_audit_ref``, ``record_id``,
       ``target_component``, and ``attacker_action_sequence`` (legacy
       free-form fields). Duplicates are de-duplicated while preserving
       discovery order.
    """
    ids: List[str] = []
    seen: set[str] = set()
    primary = record.get("cve_id")
    if isinstance(primary, str) and primary:
        ids.append(primary)
        seen.add(primary)
    for field in ("source_audit_ref", "record_id", "target_component", "attacker_action_sequence"):
        value = record.get(field)
        if not isinstance(value, str):
            continue
        for match in _CVE_REGEX.findall(value):
            if match not in seen:
                seen.add(match)
                ids.append(match)
    return ids


def _extract_ghsa_ids(record: Dict[str, Any]) -> List[str]:
    """Return all GHSA identifiers attached to ``record`` (precedence mirrors CVE)."""
    ids: List[str] = []
    seen: set[str] = set()
    primary = record.get("ghsa_id")
    if isinstance(primary, str) and primary:
        ids.append(primary)
        seen.add(primary)
    for field in ("source_audit_ref", "record_id", "target_component", "attacker_action_sequence"):
        value = record.get(field)
        if not isinstance(value, str):
            continue
        for match in _GHSA_REGEX.findall(value):
            if match not in seen:
                seen.add(match)
                ids.append(match)
    return ids


def _extract_firms(record: Dict[str, Any]) -> List[str]:
    """Return all firm keys attached to ``record``.

    Sources (de-duplicated, discovery-order preserved):
    1. Any ``function_shape.shape_tags`` entry starting with ``firm-``
       (e.g. ``firm-pashov-audits``). The ``firm-`` prefix is stripped.
    2. ``source_audit_ref`` second colon-segment when the ref begins with
       ``audit-firm:`` (e.g. ``audit-firm:pashov-audits:...`` -> ``pashov-audits``).
    """
    firms: List[str] = []
    seen: set[str] = set()
    shape = record.get("function_shape") or {}
    shape_tags = shape.get("shape_tags") or []
    for tag in shape_tags:
        if not isinstance(tag, str):
            continue
        if tag.startswith(_FIRM_SHAPE_PREFIX):
            key = tag[len(_FIRM_SHAPE_PREFIX):]
            if key and key not in seen:
                seen.add(key)
                firms.append(key)
    source_ref = record.get("source_audit_ref")
    if isinstance(source_ref, str) and source_ref.startswith(_SOURCE_AUDIT_REF_FIRM_PREFIX):
        rest = source_ref[len(_SOURCE_AUDIT_REF_FIRM_PREFIX):]
        firm_key = rest.split(":", 1)[0] if rest else ""
        if firm_key and firm_key not in seen:
            seen.add(firm_key)
            firms.append(firm_key)
    return firms


def _extract_verification_tiers(record: Dict[str, Any]) -> List[str]:
    """Return all verification-tier keys attached to ``record``.

    Top-level ``verification_tier`` (v1.1) takes precedence; legacy
    ``function_shape.shape_tags`` entries with the ``verification_tier:``
    prefix are surfaced as fallback so v1 records still index.
    """
    tiers: List[str] = []
    seen: set[str] = set()
    primary = record.get("verification_tier")
    if isinstance(primary, str) and primary:
        tiers.append(primary)
        seen.add(primary)
    shape = record.get("function_shape") or {}
    shape_tags = shape.get("shape_tags") or []
    for tag in shape_tags:
        if not isinstance(tag, str):
            continue
        if tag.startswith(_VERIFICATION_TIER_SHAPE_PREFIX):
            key = tag[len(_VERIFICATION_TIER_SHAPE_PREFIX):]
            if key and key not in seen:
                seen.add(key)
                tiers.append(key)
    return tiers


def _incident_date_index_key(record: Dict[str, Any]) -> str:
    """Return the incident-date index key for ``record``.

    Wave-2 PR-A: index by stringified ``year`` (YYYY). Mirrors the
    ``by_audit_year`` Solodit-2000-sentinel handling so the index does not
    pollute year 2000 with thousands of undated Solodit specs.
    """
    if record.get("year") == 2000 and str(record.get("source_audit_ref") or "").startswith("solodit-spec:"):
        return UNKNOWN_INCIDENT_DATE_KEY
    year = record.get("year")
    if isinstance(year, int):
        return str(year)
    if isinstance(year, str) and year:
        return year
    return UNKNOWN_INCIDENT_DATE_KEY


def _index_record(index: IndexMap, record: Dict[str, Any], tag_file: str) -> None:
    row = _base_row(record, tag_file)
    # Index off the resolved ``row`` values (which carry safe defaults for
    # partial records) so a missing descriptive field can never abort the build.
    _append(index, "by_attack_class", row["attack_class"], row)
    _append(index, "by_target_repo", row["target_repo"], row)
    _append(index, "by_bug_class", row["bug_class"], row)
    _append(index, "by_language", row["target_language"], row)
    _append(index, "by_target_domain", row["target_domain"], row)
    _append(index, "by_audit_year", _audit_year_index_key(record), row)
    _append(index, "by_attacker_role", record.get("attacker_role", "unknown"), row)
    _append(index, "by_fix_pattern", record.get("fix_pattern", "unknown"), row)
    _append(index, "by_severity", row["severity_at_finding"], row)

    # Wave-2 PR-A additive indexes. Records without any extractable
    # identifier do not emit a row (the index then carries only records
    # that actually carry the field, mirroring how by_shape_hash only
    # carries records with a real raw_signature).
    #
    # Record-ID-dedup for identifier indexes (Wave-2 W2.6 fix, 2026-05-16):
    # ``by_cve_id`` / ``by_ghsa_id`` are *identifier* indexes - they map
    # a unique external advisory ID to its canonical record. The regex
    # fallback in ``_extract_cve_ids`` / ``_extract_ghsa_ids`` walks
    # ``source_audit_ref`` / ``record_id`` / ``target_component`` /
    # ``attacker_action_sequence`` and can surface *cross-referenced*
    # advisory IDs (e.g. a Vyper record whose ``attacker_action_sequence``
    # cites a sibling GHSA in prose). Emitting an index row per
    # cross-reference inflates the index above the unique-record-id count
    # (caught by ``tools/wave2-index-dual-form-audit.py`` commit
    # ``2a4fffda8f``: by_ghsa_id 200 rows vs 193 unique record_ids = 7
    # cross-reference inflations). Index consumers want one canonical
    # row per record keyed by the record's *primary* identifier, so we
    # take the first ID (top-level field has precedence over regex
    # fallback per ``_extract_*_ids`` ordering) and drop the rest.
    cve_ids = _extract_cve_ids(record)
    if cve_ids:
        _append(index, "by_cve_id", cve_ids[0], row)
    ghsa_ids = _extract_ghsa_ids(record)
    if ghsa_ids:
        _append(index, "by_ghsa_id", ghsa_ids[0], row)
    for firm in _extract_firms(record):
        _append(index, "by_firm", firm, row)
    for tier in _extract_verification_tiers(record):
        _append(index, "by_verification_tier", tier, row)
    _append(index, "by_incident_date", _incident_date_index_key(record), row)

    shape = record.get("function_shape") or {}
    if not isinstance(shape, dict):
        shape = {}
    shape_signature = str(shape.get("raw_signature") or "")
    shape_row = {
        **row,
        "function_signature": shape_signature,
    }
    for shape_tag in (shape.get("shape_tags") or []):
        _append(index, "by_function_shape", shape_tag, shape_row)
    if _shape_hash_indexable_signature(shape_signature):
        try:
            computed_shape = compute_shape_from_signature(shape_signature, str(row["target_language"]))
        except Exception:
            computed_shape = {}
        for key in (computed_shape.get("shape_hash"), computed_shape.get("shape_hash_fine")):
            if key:
                hash_row = {**shape_row, "shape_hash": key}
                _append(index, "by_shape_hash", key, hash_row)
                _append(index, "by_function_shape", key, hash_row)


def _new_index() -> IndexMap:
    return {name: {} for name in INDEX_NAMES}


# Subtree-name prefixes whose records are intentionally excluded from the
# derived routing indices. ``_tok_a_enrichment`` / ``_deep_mine_summary`` are
# generated ENRICHMENT-MIRROR overlays that deliberately reuse the canonical
# record_id of the finding they annotate (e.g.
# bridge_incidents/_tok_a_enrichment/* mirrors
# bridge_incidents/<incident>/record.yaml). Indexing them produced a duplicate
# record_id that fail-closed the entire corpus reindex; they belong with the
# quarantine/deprecated subtrees that must not leak into vault_corpus_search.
_EXCLUDED_SUBTREE_PREFIXES = (
    "_QUARANTINE_",
    "_deprecated",
    "_tok_a_enrichment",
    "_deep_mine_summary",
)


def _is_excluded_path(path: Path, tag_dir: Path) -> bool:
    """Return True for paths under intentionally excluded subtrees.

    Mirrors the production-analytics exclusion semantics used by
    ``tools/hackerman-corpus-stats.py`` (see ``QUARANTINE_PREFIX``) so that
    fabricated-CVE quarantine and deprecated records do NOT leak into the
    derived indices consumed by ``vault_corpus_search`` / ``vault_search``.
    """
    try:
        rel = path.relative_to(tag_dir)
    except ValueError:
        return False
    if not rel.parts:
        return False
    # Excluded subtrees may be nested (e.g. bridge_incidents/_tok_a_enrichment/),
    # so match an excluded prefix on ANY path component, not just the top level.
    return any(part.startswith(_EXCLUDED_SUBTREE_PREFIXES) for part in rel.parts)


def _load_record_doc(path: Path) -> Any:
    """Parse a record file as YAML or JSON based on its suffix.

    Walker-harmonization helper (Wave-2 PR-A, 2026-05-16): the index-builder
    now ingests ``record.json`` siblings (39 JSON-only records under
    ``move_aptos_sui/`` and a small set of other subtrees) in addition to
    ``record.yaml`` / ``*.yaml`` / ``*.yml``. JSON parsing is direct
    ``json.loads``; YAML continues to go through ``_VALIDATOR.load_yaml``.
    """
    if path.suffix.lower() == ".json":
        return json.loads(path.read_text(encoding="utf-8"))
    return _VALIDATOR.load_yaml(path)


def _is_root_level_record(path: Path, tag_dir: Path) -> bool:
    try:
        rel = path.relative_to(tag_dir)
    except ValueError:
        return False
    return len(rel.parts) == 1


def _drop_mirrored_record_duplicates(
    records: List[Tuple[Path, Dict[str, Any]]],
    tag_dir: Path,
) -> Tuple[List[Tuple[Path, Dict[str, Any]]], int]:
    """Drop generated mirror copies when a flat canonical record exists.

    The live corpus contains thousands of records that were materialized in
    both flat-root form and a historical nested subtree. Those pairs share the
    same ``record_id`` and should index once. This function only auto-dedupes
    the unambiguous mirror shape: exactly one root-level record plus one or more
    nested copies. Ambiguous duplicate IDs remain in the returned list so the
    existing duplicate-record guard in ``write_indices`` still fails loudly.
    """
    grouped: Dict[str, List[Tuple[Path, Dict[str, Any]]]] = {}
    for path, record in records:
        grouped.setdefault(str(record["record_id"]), []).append((path, record))

    deduped: List[Tuple[Path, Dict[str, Any]]] = []
    dropped = 0
    for items in grouped.values():
        if len(items) == 1:
            deduped.extend(items)
            continue
        roots = [(path, record) for path, record in items if _is_root_level_record(path, tag_dir)]
        if len(roots) == 1:
            deduped.append(roots[0])
            dropped += len(items) - 1
            continue
        deduped.extend(items)

    return deduped, dropped


def load_records(tag_dir: Path) -> Tuple[List[Tuple[Path, Dict[str, Any]]], List[str], int]:
    # Wave-2 PR-A: per-doc schema dispatch so v1 and v1.1 records both
    # validate. The legacy single-schema load (``_VALIDATOR.load_schema()``)
    # rejected v1.1 records as "additional property 'cve_id' not allowed".
    records: List[Tuple[Path, Dict[str, Any]]] = []
    errors: List[str] = []
    skipped = 0
    # Walker harmonization (Wave-2 spec §4.1, mirrors hackerman-corpus-stats.py
    # and tools/wave2-w21-post-migration-validator.py::iter_record_files):
    # rglob captures both flat-shape (`<name>.yaml` at root) and nested-shape
    # (`<subtree>/<slug>/record.yaml`). Pre-extension non-recursive glob silently
    # dropped 6,278 nested records across 21 subtrees.
    #
    # record.yaml skip guard: when iterating the unified *.yaml pass we skip
    # files named ``record.yaml`` to prevent double-counting against the
    # structured record.yaml walk used by future ingesters (defense-in-depth;
    # rglob already returns each path exactly once but the guard preserves
    # invariants if callers union this iterator with a record.yaml-first walk).
    #
    # record.json walk (Wave-2 PR-A, 2026-05-16): the validator's
    # ``iter_record_files`` (post-migration-validator.py:161-177) yields both
    # ``record.yaml`` and ``record.json`` and its index_drift_check (added at
    # 130a942a5b) caught the index-builder missing a JSON-only record's
    # ghsa_id row (surgical patch ``58eed3f43a`` added the row by hand). This
    # block closes the structural root cause: the index-builder now walks
    # ``record.json`` alongside ``record.yaml`` so any indexed field
    # (cve_id, ghsa_id, firm, verification_tier, incident_date) carried by
    # a JSON-only record populates the corresponding index automatically.
    #
    # Dual-form dedup rule: when a directory contains BOTH ``record.yaml``
    # and ``record.json``, the YAML form is canonical and the JSON sibling
    # is skipped (no double-counting). 6,258 dual-form records exist in the
    # corpus as of 2026-05-16; 39 directories are JSON-only.
    structured_yaml_paths = sorted(tag_dir.rglob("record.yaml"))
    structured_yaml_parents = {p.parent for p in structured_yaml_paths}
    structured_json_paths = [
        p
        for p in sorted(tag_dir.rglob("record.json"))
        if p.parent not in structured_yaml_parents
    ]
    flat_paths = [
        p
        for p in sorted(list(tag_dir.rglob("*.yaml")) + list(tag_dir.rglob("*.yml")))
        if p.name != "record.yaml"
    ]
    for path in structured_yaml_paths + structured_json_paths + flat_paths:
        if _is_excluded_path(path, tag_dir):
            skipped += 1
            continue
        try:
            doc = _load_record_doc(path)
        except Exception as exc:
            label = "JSON parse error" if path.suffix.lower() == ".json" else "YAML parse error"
            errors.append(f"{path}: {label}: {exc}")
            continue
        if not _VALIDATOR.is_hackerman_record(doc):
            skipped += 1
            continue
        try:
            errs = _VALIDATOR.validate_doc(doc)  # schema=None -> per-doc dispatch
        except TypeError:
            # Older validators may require an explicit schema arg.
            errs = _VALIDATOR.validate_doc(doc, _VALIDATOR.load_schema())
        if errs:
            errors.extend(f"{path}: {err}" for err in errs)
            continue
        records.append((path, doc))
    records, mirrored_duplicates = _drop_mirrored_record_duplicates(records, tag_dir)
    skipped += mirrored_duplicates
    return records, errors, skipped


def _load_existing_index_file(path: Path) -> Dict[str, List[Dict[str, Any]]]:
    buckets: Dict[str, List[Dict[str, Any]]] = {}
    if not path.exists():
        return buckets
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(row, dict):
                continue
            key = row.get("key")
            if key in (None, ""):
                continue
            stored = dict(row)
            stored.pop("key", None)
            buckets.setdefault(str(key), []).append(stored)
    return buckets


def _load_existing_index(index_dir: Path, name: str) -> Dict[str, List[Dict[str, Any]]]:
    buckets = _load_existing_index_file(index_dir / f"{name}.jsonl")
    shard_dir = index_dir / f"{name}.d"
    if not shard_dir.is_dir():
        return buckets
    for shard_path in sorted(shard_dir.glob("*.jsonl")):
        for key, rows in _load_existing_index_file(shard_path).items():
            buckets.setdefault(key, []).extend(rows)
    return buckets


def _row_identity(key: str, row: Dict[str, Any]) -> str:
    return json.dumps({"key": key, **row}, sort_keys=True, default=str)


def _row_sort_key(row: Dict[str, Any]) -> Tuple[str, str, str, str]:
    return (
        str(row.get("record_id") or row.get("verdict_id") or ""),
        str(row.get("tag_file") or ""),
        str(row.get("source_audit_ref") or ""),
        json.dumps(row, sort_keys=True, default=str),
    )


def _row_has_stale_tag_file(row: Dict[str, Any], current_tag_files: set[str]) -> bool:
    tag_file = str(row.get("tag_file") or "")
    if not tag_file:
        return False
    if not (row.get("record_id") or row.get("source_audit_ref")):
        return False
    path = Path(tag_file)
    if path.is_absolute():
        return not path.exists()
    return tag_file not in current_tag_files


def _tag_file_ref(path: Path, tag_dir: Optional[Path] = None) -> str:
    """Return a stable tag-file reference for index rows.

    Flat files keep their basename. Structured records use tag-root-relative
    paths such as ``solodit/foo/record.yaml`` so preservation cannot confuse
    unrelated nested ``record.yaml`` rows.
    """
    if tag_dir is not None:
        try:
            return path.resolve().relative_to(tag_dir.resolve()).as_posix()
        except (OSError, ValueError):
            pass
    return path.name


def _current_tag_file_refs(records: Iterable[Tuple[Path, Dict[str, Any]]], tag_dir: Optional[Path] = None) -> set[str]:
    refs: set[str] = set()
    for path, _ in records:
        ref = _tag_file_ref(path, tag_dir)
        refs.add(ref)
        if "/" not in ref:
            refs.add(path.name)
    return refs


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _root_manifest_files(index_dir: Path) -> List[Dict[str, Any]]:
    files: List[Dict[str, Any]] = []
    paths: List[Path] = []
    for name in INDEX_NAMES:
        if name in SHARDED_INDEX_NAMES:
            shard_dir = index_dir / f"{name}.d"
            if not shard_dir.is_dir():
                continue
            manifest = shard_dir / "manifest.json"
            if manifest.is_file():
                paths.append(manifest)
            paths.extend(sorted(shard_dir.glob("*.jsonl")))
            continue
        path = index_dir / f"{name}.jsonl"
        if not path.is_file():
            continue
        paths.append(path)
    for path in sorted(paths, key=lambda p: p.relative_to(index_dir).as_posix()):
        rel = path.relative_to(index_dir).as_posix()
        files.append({
            "path": rel,
            "size_bytes": path.stat().st_size,
            "sha256": _sha256_file(path),
        })
    return files


def _clean_int_map(values: Optional[Dict[str, int]]) -> Dict[str, int]:
    if not isinstance(values, dict):
        return {}
    return {
        str(key): int(value)
        for key, value in sorted(values.items())
        if isinstance(value, int) and value >= 0
    }


def build_root_index_manifest(
    index_dir: Path,
    *,
    preserve_existing: Optional[bool] = None,
    preserved_rows_by_index: Optional[Dict[str, int]] = None,
    row_counts_by_index: Optional[Dict[str, int]] = None,
) -> Dict[str, Any]:
    files = _root_manifest_files(index_dir)
    preserved_rows = _clean_int_map(preserved_rows_by_index)
    row_counts = _clean_int_map(row_counts_by_index)
    hash_payload = {
        "schema": ROOT_INDEX_MANIFEST_SCHEMA,
        "index_names": list(INDEX_NAMES),
        "sharded_index_names": sorted(SHARDED_INDEX_NAMES),
        "preserve_existing": preserve_existing,
        "preserved_rows_by_index": preserved_rows,
        "row_counts_by_index": row_counts,
        "files": files,
    }
    canonical = json.dumps(hash_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return {
        **hash_payload,
        "corpus_index_hash": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        "file_count": len(files),
    }


def write_root_index_manifest(
    index_dir: Path,
    *,
    preserve_existing: Optional[bool] = None,
    preserved_rows_by_index: Optional[Dict[str, int]] = None,
    row_counts_by_index: Optional[Dict[str, int]] = None,
) -> Dict[str, Any]:
    manifest = build_root_index_manifest(
        index_dir,
        preserve_existing=preserve_existing,
        preserved_rows_by_index=preserved_rows_by_index,
        row_counts_by_index=row_counts_by_index,
    )
    (index_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest


def write_indices(
    records: Iterable[Tuple[Path, Dict[str, Any]]],
    index_dir: Path,
    *,
    preserve_existing: bool = True,
    tag_dir: Optional[Path] = None,
) -> Dict[str, int]:
    records_list = list(records)
    replacement_record_ids = {str(record["record_id"]) for _, record in records_list}
    # ``source_audit_ref`` is optional on some corpus records (a handful of older
    # solodit backfill rows omit it). It is only used here to filter superseded
    # rows out of the preserved index, so a missing value can be treated as the
    # empty string without affecting correctness. Hard-indexing crashed the whole
    # build on a single fieldless record.
    replacement_source_refs = {str(record.get("source_audit_ref") or "") for _, record in records_list}
    current_tag_files = _current_tag_file_refs(records_list, tag_dir)
    index = _new_index()
    preserved_rows_by_index: Dict[str, int] = {name: 0 for name in INDEX_NAMES}
    if preserve_existing:
        for name in INDEX_NAMES:
            for key, rows in _load_existing_index(index_dir, name).items():
                filtered_rows = [
                    row
                    for row in rows
                    if str(row.get("record_id") or "") not in replacement_record_ids
                    and str(row.get("source_audit_ref") or "") not in replacement_source_refs
                    and not _row_has_stale_tag_file(row, current_tag_files)
                ]
                if filtered_rows:
                    preserved_rows_by_index[name] += len(filtered_rows)
                    index[name].setdefault(key, []).extend(filtered_rows)

    record_ids: Dict[str, str] = {}
    for path, record in records_list:
        record_id = record["record_id"]
        if record_id in record_ids:
            raise ValueError(f"duplicate record_id {record_id!r}: {record_ids[record_id]} and {path}")
        record_ids[record_id] = str(path)
        _index_record(index, record, _tag_file_ref(path, tag_dir))

    index_dir.mkdir(parents=True, exist_ok=True)
    counts: Dict[str, int] = {}
    row_counts_by_index: Dict[str, int] = {}
    for name in INDEX_NAMES:
        rows_written = 0
        if name in SHARDED_INDEX_NAMES:
            shard_dir = index_dir / f"{name}.d"
            if shard_dir.exists():
                shutil.rmtree(shard_dir)
            shard_dir.mkdir(parents=True, exist_ok=True)
            monolith = index_dir / f"{name}.jsonl"
            if monolith.exists():
                monolith.unlink()
            shard_handles: dict[str, Any] = {}
            try:
                for key in sorted(index[name].keys()):
                    seen_rows: set[str] = set()
                    rows = sorted(index[name][key], key=_row_sort_key)
                    shard = shard_for_key(key)
                    fh = shard_handles.get(shard)
                    if fh is None:
                        fh = (shard_dir / f"{shard}.jsonl").open("w", encoding="utf-8")
                        shard_handles[shard] = fh
                    for row in rows:
                        identity = _row_identity(key, row)
                        if identity in seen_rows:
                            continue
                        seen_rows.add(identity)
                        fh.write(json.dumps({"key": key, **row}, sort_keys=True) + "\n")
                        rows_written += 1
            finally:
                for fh in shard_handles.values():
                    fh.close()
            manifest = {
                "schema": SHARDED_INDEX_SCHEMA,
                "index_name": name,
                "shard_key": "sha256(key)[:2]",
                "rows": rows_written,
                "shards": sorted(path.name for path in shard_dir.glob("*.jsonl")),
            }
            (shard_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            counts[f"{name}.d"] = rows_written
            row_counts_by_index[name] = rows_written
            continue
        out_path = index_dir / f"{name}.jsonl"
        with out_path.open("w", encoding="utf-8") as fh:
            for key in sorted(index[name].keys()):
                seen_rows: set[str] = set()
                rows = sorted(index[name][key], key=_row_sort_key)
                for row in rows:
                    identity = _row_identity(key, row)
                    if identity in seen_rows:
                        continue
                    seen_rows.add(identity)
                    fh.write(json.dumps({"key": key, **row}, sort_keys=True) + "\n")
                    rows_written += 1
        counts[f"{name}.jsonl"] = rows_written
        row_counts_by_index[name] = rows_written
    manifest = write_root_index_manifest(
        index_dir,
        preserve_existing=preserve_existing,
        preserved_rows_by_index={k: v for k, v in preserved_rows_by_index.items() if v},
        row_counts_by_index=row_counts_by_index,
    )
    counts["corpus_index_hash"] = manifest["corpus_index_hash"]
    counts["records_indexed"] = len(record_ids)
    return counts


def build_indices(tag_dir: Path, index_dir: Path, *, preserve_existing: bool = True) -> Dict[str, int]:
    if not tag_dir.is_dir():
        raise FileNotFoundError(f"tag dir not found: {tag_dir}")
    records, errors, skipped = load_records(tag_dir)
    if errors:
        raise ValueError("\n".join(errors))
    counts = write_indices(records, index_dir, preserve_existing=preserve_existing, tag_dir=tag_dir)
    counts["records_skipped"] = skipped
    return counts


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag-dir", default=str(DEFAULT_TAG_DIR))
    parser.add_argument("--index-dir", default=str(DEFAULT_INDEX_DIR))
    parser.add_argument(
        "--no-preserve-existing",
        action="store_true",
        help="Rebuild only hackerman v1 rows instead of overlaying onto existing corpus index files.",
    )
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    try:
        counts = build_indices(
            Path(args.tag_dir),
            Path(args.index_dir),
            preserve_existing=not args.no_preserve_existing,
        )
    except (OSError, ValueError) as exc:
        print(f"hackerman-index-build: {exc}", file=sys.stderr)
        return 1
    if not args.quiet:
        print(json.dumps(counts, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
