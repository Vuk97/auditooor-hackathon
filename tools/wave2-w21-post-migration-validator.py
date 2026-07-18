#!/usr/bin/env python3
"""wave2-w21-post-migration-validator.

Wave-2 PR-A post-migration validator. Runs AFTER
``tools/hackerman-schema-v1-to-v1.1-migrator.py`` has been swept across the
entire ``audit/corpus_tags/tags/`` corpus and asserts the migration landed
cleanly:

  1. Every non-quarantine, non-deprecated hackerman record YAML declares a
     ``schema_version`` whose prefix is ``auditooor.hackerman_record.v1``.
     POST-MIGRATION TARGET: every audited record at ``v1.1`` (``v1_record_count``
     must be zero); pre-migration runs surface a non-zero v1 count and FAIL
     loudly so an operator can re-trigger the migrator.

  2. Every audited record carries a populated ``verification_tier`` field
     whose value is in the canonical tier-1..tier-5 taxonomy OR the literal
     string ``no_tier``. (We also accept the legacy
     ``function_shape.shape_tags`` ``verification_tier:tier-N-*`` entry as a
     migration-source signal, but the v1.1 top-level field is the hard gate.)

  3. The five Wave-2 PR-A additive index files
     (``by_cve_id``, ``by_ghsa_id``, ``by_firm``,
     ``by_verification_tier``, ``by_incident_date``) exist under
     ``audit/corpus_tags/index/``, are non-empty for indexes whose source
     fields are populated in the corpus, and parse as JSONL.

  4. No record path under any ``_QUARANTINE_*`` subtree leaks into
     ``by_cve_id.jsonl`` (fabricated-CVE quarantine must NEVER reach a
     public-facing CVE index).

  5. ``index_drift_check`` (W2.5-followup, 2026-05-16): the identifier
     indexes ``by_cve_id`` / ``by_ghsa_id`` are not under-populated
     relative to the corpus. Recomputes the expected distinct-record-id
     set per index by walking records whose top-level ``cve_id`` /
     ``ghsa_id`` field is populated and compares it to the index's
     emitted record_id set. FAILs when any record carries the corpus
     field but emits no index row (operator must re-run
     ``tools/hackerman-index-build.py``). Anchor: the 2026-05-16
     integrity sweep at commit ``2c4d9b5b3b`` (by_cve_id drift 11
     actual vs 121 expected).

The tool emits a JSON status pack of schema
``auditooor.wave2_w21_post_migration_validator.v1`` and, when run with
``--strict``, exits non-zero on FAIL. It is safe to run on a pre-migration
corpus: it will report ``overall_status=FAIL`` with a precise list of
clauses that haven't satisfied yet.

CLI:

    python3 tools/wave2-w21-post-migration-validator.py \\
        --workspace /Users/wolf/auditooor-702-full --strict --json

    # Override the tags dir directly (overrides --workspace-derived default):
    python3 tools/wave2-w21-post-migration-validator.py \\
        --tags-dir /Users/wolf/audits/thegraph/audit/corpus_tags/tags --json

Exit code conventions:

  Harmonized with ``tools/hackerman-schema-v1-to-v1.1-runner.py`` so a
  single exit-code branch in a wrapper script can route both tools'
  outcomes:

    * ``0`` PASS - ``overall_status=PASS``. Also returned in non-strict
      mode when ``overall_status=FAIL`` (the operator opted into a soft
      gate).
    * ``1`` FAIL - ``overall_status=FAIL`` and ``--strict`` was passed
      (records found, post-migration validation failed).
    * ``2`` ERROR - ``overall_status=ERROR``: tool / input error such as
      the tags directory missing or unreadable. This bypasses
      ``--strict`` (the error is structural, not a verdict on content).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

SCHEMA = "auditooor.wave2_w21_post_migration_validator.v1"
HACKERMAN_V1_PREFIX = "auditooor.hackerman_record.v1"
HACKERMAN_V11_SCHEMA = "auditooor.hackerman_record.v1.1"

REPO_ROOT_GUESS = Path(__file__).resolve().parent.parent
DEFAULT_WORKSPACE = REPO_ROOT_GUESS

QUARANTINE_PATH_MARKERS = (
    "_QUARANTINE_FABRICATED_CVE",
    "_QUARANTINE_FABRICATED",
    "_QUARANTINE_",
)
DEPRECATED_PATH_MARKERS = ("_deprecated",)

WAVE2_ADDITIVE_INDEXES = (
    "by_cve_id",
    "by_ghsa_id",
    "by_firm",
    "by_verification_tier",
    "by_incident_date",
)

VERIFICATION_TIERS = (
    "tier-1-verified-realtime-api",
    "tier-1-officially-disclosed",
    "tier-2-verified-public-archive",
    "tier-3-synthetic-taxonomy-anchored",
    "tier-4-bundled-fixture",
    "tier-5-quarantine",
)
NO_TIER_SENTINEL = "no_tier"
ACCEPTABLE_TIER_VALUES = frozenset(VERIFICATION_TIERS) | {NO_TIER_SENTINEL}

_SHAPE_TAG_PREFIX = "verification_tier:"
_VERIFICATION_TIER_VALUE_RE = re.compile(
    r"^verification_tier:(tier-[1-5]-[a-z0-9][a-z0-9-]*)$"
)


# --------------------------------------------------------------------------- #
# Path classification
# --------------------------------------------------------------------------- #


def _path_under_marker(path: Path, tags_dir: Path, markers: Iterable[str]) -> bool:
    """True iff any path component between tags_dir and ``path`` matches one
    of ``markers`` (case-insensitive)."""
    try:
        rel = path.resolve().relative_to(tags_dir.resolve())
    except ValueError:
        rel = path
    upper_markers = tuple(m.upper() for m in markers)
    for part in rel.parts:
        upart = part.upper()
        for marker in upper_markers:
            if marker in upart:
                return True
    return False


def is_under_quarantine(path: Path, tags_dir: Path) -> bool:
    return _path_under_marker(path, tags_dir, QUARANTINE_PATH_MARKERS)


def is_under_deprecated(path: Path, tags_dir: Path) -> bool:
    return _path_under_marker(path, tags_dir, DEPRECATED_PATH_MARKERS)


def iter_record_files(tags_dir: Path) -> Iterable[Path]:
    """Yield every candidate record YAML/JSON under ``tags_dir``.

    Mirrors ``hackerman-record-verification-tier-check.py`` so both gates
    agree on which files are "records". Quarantine + deprecated subtrees are
    NOT excluded here (the caller decides per-file via the dedicated
    predicates) so a quarantine-leak assertion can still iterate over them.
    """
    if not tags_dir.exists():
        return
    for path in sorted(tags_dir.rglob("*")):
        if not path.is_file():
            continue
        name = path.name.lower()
        if name == "readme.md":
            continue
        if name in {"record.yaml", "record.json"}:
            yield path
            continue
        if path.suffix.lower() == ".yaml" and path.parent == tags_dir:
            yield path
            continue
        if path.suffix.lower() == ".yaml" and path.parent != tags_dir:
            sibling_record = path.parent / "record.yaml"
            if sibling_record.exists() and sibling_record != path:
                continue
            yield path


# --------------------------------------------------------------------------- #
# Minimal YAML/JSON record parsing
# --------------------------------------------------------------------------- #


def _strip_yaml_quotes(value: str) -> str:
    v = value.strip()
    if len(v) >= 2 and (
        (v[0] == '"' and v[-1] == '"') or (v[0] == "'" and v[-1] == "'")
    ):
        return v[1:-1]
    return v


def _parse_record(path: Path) -> Dict[str, Any]:
    """Return a dict with the fields we care about: ``schema_version``,
    ``record_id``, ``verification_tier`` (top-level v1.1 field if present),
    ``shape_tag_tier`` (legacy v1 shape_tags signal), ``target_repo``,
    ``bug_class``, ``attack_class``.

    PyYAML is not assumed; a minimal hand parser is used (consistent with
    sibling tools). JSON files use ``json.loads``.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return {"_unreadable": str(exc)}

    if path.suffix.lower() == ".json":
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            return {"_parse_error": f"json decode: {exc}"}
        if not isinstance(payload, dict):
            return {"_parse_error": "json root is not an object"}
        result: Dict[str, Any] = {
            "schema_version": payload.get("schema_version"),
            "record_id": payload.get("record_id"),
            "verification_tier": payload.get("verification_tier"),
            "target_repo": payload.get("target_repo"),
            "bug_class": payload.get("bug_class"),
            "attack_class": payload.get("attack_class"),
            "cve_id": payload.get("cve_id"),
            "ghsa_id": payload.get("ghsa_id"),
        }
        fn_shape = payload.get("function_shape") or {}
        shape_tags = fn_shape.get("shape_tags") if isinstance(fn_shape, dict) else []
        shape_tag_tier: Optional[str] = None
        if isinstance(shape_tags, list):
            for t in shape_tags:
                if not isinstance(t, str):
                    continue
                m = _VERIFICATION_TIER_VALUE_RE.match(t.strip())
                if m:
                    shape_tag_tier = m.group(1)
                    break
        result["shape_tag_tier"] = shape_tag_tier
        return result

    # YAML scan (top-level scalar fields + function_shape.shape_tags)
    result = {
        "schema_version": None,
        "record_id": None,
        "verification_tier": None,
        "shape_tag_tier": None,
        "target_repo": None,
        "bug_class": None,
        "attack_class": None,
        "cve_id": None,
        "ghsa_id": None,
    }
    in_fs = False
    in_tags = False
    tags_indent: Optional[int] = None

    for raw in text.splitlines():
        if not raw.strip():
            continue
        stripped = raw.strip()
        is_top_level = not (raw.startswith(" ") or raw.startswith("\t"))

        if is_top_level:
            # Reset nested-state on any new top-level key.
            in_fs = False
            in_tags = False

            for field in (
                "schema_version",
                "record_id",
                "verification_tier",
                "target_repo",
                "bug_class",
                "attack_class",
                "cve_id",
                "ghsa_id",
            ):
                prefix = f"{field}:"
                if stripped.startswith(prefix):
                    _, _, rhs = stripped.partition(":")
                    val = _strip_yaml_quotes(rhs.strip())
                    if val:
                        result[field] = val
                    break

            if stripped.startswith("function_shape:"):
                in_fs = True
            continue

        # Indented line — only interesting if we're inside function_shape.
        if not in_fs:
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if stripped.startswith("shape_tags:"):
            in_tags = True
            tags_indent = indent
            continue
        if in_tags:
            if stripped.startswith("- "):
                if tags_indent is not None and indent >= tags_indent:
                    val = _strip_yaml_quotes(stripped[2:].strip())
                    if result["shape_tag_tier"] is None:
                        m = _VERIFICATION_TIER_VALUE_RE.match(val)
                        if m:
                            result["shape_tag_tier"] = m.group(1)
                    continue
                else:
                    in_tags = False
            else:
                if tags_indent is not None and indent <= tags_indent:
                    in_tags = False
    return result


# --------------------------------------------------------------------------- #
# Index health checks
# --------------------------------------------------------------------------- #


def check_indexes(
    index_dir: Path, quarantine_record_ids: set, quarantine_files: set
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Verify Wave-2 PR-A additive indexes parse cleanly.

    Returns (index_health, quarantine_leak_check) -- two flat dicts suitable
    for direct insertion into the JSON status pack.
    """
    index_health: Dict[str, Any] = {}
    leak_hits: List[Dict[str, Any]] = []

    if not index_dir.exists():
        for name in WAVE2_ADDITIVE_INDEXES:
            index_health[name] = {"status": "FAIL", "reason": "index dir missing"}
        return index_health, {
            "by_cve_id_leaks": leak_hits,
            "status": "FAIL",
            "reason": f"index dir missing: {index_dir}",
        }

    for name in WAVE2_ADDITIVE_INDEXES:
        path = index_dir / f"{name}.jsonl"
        info: Dict[str, Any] = {"path": str(path)}
        if not path.exists():
            info["status"] = "FAIL"
            info["reason"] = "missing"
            index_health[name] = info
            continue
        try:
            stat = path.stat()
        except OSError as exc:
            info["status"] = "FAIL"
            info["reason"] = f"stat failed: {exc}"
            index_health[name] = info
            continue
        info["size_bytes"] = stat.st_size
        line_count = 0
        parse_errors = 0
        cve_leak_lines_for_index: List[Dict[str, Any]] = []
        try:
            with path.open("r", encoding="utf-8", errors="replace") as fh:
                for lineno, line in enumerate(fh, start=1):
                    line = line.strip()
                    if not line:
                        continue
                    line_count += 1
                    try:
                        row = json.loads(line)
                    except json.JSONDecodeError:
                        parse_errors += 1
                        continue
                    if name == "by_cve_id":
                        rid = row.get("record_id") or ""
                        tag_file = row.get("tag_file") or ""
                        # A "leak" is any by_cve_id row whose record_id or
                        # tag_file ties back to a quarantine path.
                        leak_via: List[str] = []
                        if rid and rid in quarantine_record_ids:
                            leak_via.append("record_id")
                        if tag_file:
                            tf_upper = tag_file.upper()
                            for marker in QUARANTINE_PATH_MARKERS:
                                if marker.upper() in tf_upper:
                                    leak_via.append("tag_file-path-marker")
                                    break
                            # Also catch exact filename matches against any
                            # quarantine file's basename.
                            base = Path(tag_file).name
                            if base in quarantine_files:
                                leak_via.append("tag_file-basename")
                        if leak_via:
                            cve_leak_lines_for_index.append(
                                {
                                    "lineno": lineno,
                                    "record_id": rid,
                                    "tag_file": tag_file,
                                    "key": row.get("key"),
                                    "matched_via": sorted(set(leak_via)),
                                }
                            )
        except OSError as exc:
            info["status"] = "FAIL"
            info["reason"] = f"read failed: {exc}"
            index_health[name] = info
            continue

        info["line_count"] = line_count
        info["parse_errors"] = parse_errors
        if parse_errors > 0:
            info["status"] = "FAIL"
            info["reason"] = f"{parse_errors} JSONL parse errors"
        else:
            info["status"] = "OK"
        index_health[name] = info

        if name == "by_cve_id":
            leak_hits.extend(cve_leak_lines_for_index)

    leak_status = "OK" if not leak_hits else "FAIL"
    leak_payload: Dict[str, Any] = {
        "by_cve_id_leaks": leak_hits[:50],
        "by_cve_id_leak_count": len(leak_hits),
        "status": leak_status,
    }
    if leak_hits:
        leak_payload["reason"] = (
            f"{len(leak_hits)} quarantined record(s) leaked into by_cve_id.jsonl"
        )
    return index_health, leak_payload


# --------------------------------------------------------------------------- #
# Index drift check (W2.5-followup, 2026-05-16)
# --------------------------------------------------------------------------- #
#
# Existing validators only catch INFLATION (cross-reference rows, dup
# emits). They do not catch UNDER-POPULATION: when the corpus gains a
# field across N records but the index file is not regenerated, the index
# silently lags. The 2026-05-16 integrity sweep at commit ``2c4d9b5b3b``
# surfaced this on ``by_cve_id`` (11 actual rows vs 121 expected from
# corpus walk). To prevent regression, this check recomputes the expected
# distinct-record-id count per identifier index by walking the corpus
# YAMLs for records carrying the top-level field, then compares to the
# distinct ``record_id`` set the index actually emits.
#
# Coverage is intentionally scoped to the ``by_cve_id`` and ``by_ghsa_id``
# identifier indexes - both use top-level v1.1 fields with regex fallback
# through ``source_audit_ref`` etc. (see
# ``tools/hackerman-index-build.py::_extract_cve_ids``). The other three
# Wave-2 PR-A indexes (``by_firm``, ``by_verification_tier``,
# ``by_incident_date``) emit one row per record from fall-through keys
# (year defaults to ``unknown``; verification_tier from a shape tag) so
# they cannot under-populate the same way. They remain covered by the
# parse / leak checks above.
#
# A "drift" verdict means: expected_record_count > actual_record_count
# AND ``corpus_only_record_count > 0``, which is the under-population
# signature. The check is one-sided (over-population is captured by the
# dual-form audit at ``tools/wave2-index-dual-form-audit.py``).

INDEX_DRIFT_FIELDS = (
    ("by_cve_id", "cve_id"),
    ("by_ghsa_id", "ghsa_id"),
)


def check_index_drift(
    index_dir: Path,
    corpus_field_record_ids: Dict[str, set],
) -> Dict[str, Any]:
    """Detect under-population drift between corpus and identifier indexes.

    ``corpus_field_record_ids`` is a dict mapping field name
    (``cve_id`` / ``ghsa_id``) to the set of record_ids whose top-level
    field is populated in the corpus walk. We compare that set to the
    set of record_ids the index actually emits a row for. A non-empty
    ``corpus_only_record_ids`` (corpus knows the field but the index has
    no row) means the index was not regenerated after a corpus field
    addition and is under-populated.

    Status: ``OK`` (no drift), ``FAIL`` (under-population detected), or
    ``SKIP`` (index file missing - handled by ``check_indexes``).
    """
    drift: Dict[str, Any] = {"per_index": {}}
    overall_status = "OK"
    failures: List[str] = []

    for index_name, field_name in INDEX_DRIFT_FIELDS:
        index_path = index_dir / f"{index_name}.jsonl"
        per: Dict[str, Any] = {"index_path": str(index_path), "field": field_name}
        expected_ids = corpus_field_record_ids.get(field_name, set())
        per["expected_record_count"] = len(expected_ids)

        if not index_path.exists():
            per["status"] = "SKIP"
            per["reason"] = "index file missing (handled by index_health)"
            drift["per_index"][index_name] = per
            continue

        actual_ids: set = set()
        parse_errors = 0
        try:
            with index_path.open("r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        row = json.loads(line)
                    except json.JSONDecodeError:
                        parse_errors += 1
                        continue
                    rid = row.get("record_id")
                    if rid:
                        actual_ids.add(rid)
        except OSError as exc:
            per["status"] = "FAIL"
            per["reason"] = f"read failed: {exc}"
            drift["per_index"][index_name] = per
            overall_status = "FAIL"
            failures.append(
                f"index {index_name} drift check: read failed ({exc})"
            )
            continue

        per["actual_record_count"] = len(actual_ids)
        per["parse_errors"] = parse_errors

        corpus_only = sorted(expected_ids - actual_ids)
        index_only = sorted(actual_ids - expected_ids)
        per["corpus_only_record_count"] = len(corpus_only)
        per["index_only_record_count"] = len(index_only)
        # Cap diagnostic samples to keep payload small.
        per["corpus_only_sample"] = corpus_only[:10]
        per["index_only_sample"] = index_only[:10]

        if corpus_only:
            per["status"] = "FAIL"
            per["reason"] = (
                f"{len(corpus_only)} record(s) carry top-level "
                f"{field_name} but emit no {index_name} row "
                "(under-population - re-run hackerman-index-build.py)"
            )
            overall_status = "FAIL"
            failures.append(per["reason"])
        else:
            per["status"] = "OK"

        drift["per_index"][index_name] = per

    drift["status"] = overall_status
    if failures:
        drift["failures"] = failures
    return drift


# --------------------------------------------------------------------------- #
# Driver
# --------------------------------------------------------------------------- #


def validate(
    workspace: Path,
    *,
    limit: Optional[int] = None,
    tags_dir: Optional[Path] = None,
) -> Tuple[int, Dict[str, Any]]:
    """Run the post-migration validator.

    ``tags_dir`` overrides the workspace-derived default
    (``workspace/audit/corpus_tags/tags``) when supplied. The companion
    ``index_dir`` is always resolved as the sibling ``index/`` directory of
    the resolved tags dir so the two stay aligned.
    """
    if tags_dir is not None:
        tags_dir = Path(tags_dir).expanduser()
        try:
            tags_dir = Path(os.path.realpath(str(tags_dir)))
        except OSError:
            # Fall back to the un-resolved path; downstream existence check
            # will surface the failure cleanly.
            pass
        # Sibling index/ alongside the explicit tags dir.
        index_dir = tags_dir.parent / "index"
    else:
        tags_dir = workspace / "audit" / "corpus_tags" / "tags"
        index_dir = workspace / "audit" / "corpus_tags" / "index"

    payload: Dict[str, Any] = {
        "schema": SCHEMA,
        "workspace": str(workspace),
        "tags_dir": str(tags_dir),
        "tags_dir_used": str(tags_dir),
        "index_dir": str(index_dir),
        "total_records": 0,
        "audited_hackerman_v1x": 0,
        "skipped_non_hackerman": 0,
        "v1_record_count": 0,
        "v1_1_record_count": 0,
        "other_v1x_record_count": 0,
        "verification_tier_populated": 0,
        "verification_tier_missing": 0,
        "verification_tier_invalid_value": 0,
        "tier_distribution": {},
        "quarantine_record_count": 0,
        "deprecated_record_count": 0,
        "distinct_firms": 0,
        "distinct_attack_classes": 0,
        "distinct_target_repos": 0,
        "index_health": {},
        "quarantine_leak_check": {},
        "index_drift_check": {},
        "overall_status": "PASS",
        "failures": [],
        "sample_failed_records": [],
    }

    if not tags_dir.exists():
        payload["overall_status"] = "ERROR"
        payload["failures"].append(f"tags dir missing: {tags_dir}")
        return 2, payload

    quarantine_record_ids: set = set()
    quarantine_files: set = set()
    firms: Counter = Counter()
    attack_classes: Counter = Counter()
    target_repos: Counter = Counter()
    tier_distribution: Counter = Counter()
    sample_failures: List[Dict[str, Any]] = []
    # Drift detection: tally record_ids whose top-level identifier field
    # is populated in the corpus (non-quarantine, non-deprecated).
    corpus_field_record_ids: Dict[str, set] = {"cve_id": set(), "ghsa_id": set()}

    scanned = 0
    for path in iter_record_files(tags_dir):
        scanned += 1
        if limit is not None and scanned > limit:
            scanned -= 1
            break

        quarantine = is_under_quarantine(path, tags_dir)
        deprecated = is_under_deprecated(path, tags_dir)
        record = _parse_record(path)

        if quarantine:
            payload["quarantine_record_count"] += 1
            rid = record.get("record_id")
            if rid:
                quarantine_record_ids.add(rid)
            try:
                rel = path.relative_to(tags_dir)
                quarantine_files.add(rel.name)
            except ValueError:
                pass
            quarantine_files.add(path.name)
            # Quarantine records are NOT audited for migration progress —
            # they're tracked separately for the leak check.
            continue

        if deprecated:
            payload["deprecated_record_count"] += 1
            continue

        if record.get("_unreadable") or record.get("_parse_error"):
            sample_failures.append(
                {
                    "file": str(path),
                    "verdict": "parse-error",
                    "reason": record.get("_unreadable") or record.get("_parse_error"),
                }
            )
            continue

        schema_version = record.get("schema_version") or ""
        if not str(schema_version).startswith(HACKERMAN_V1_PREFIX):
            payload["skipped_non_hackerman"] += 1
            continue

        payload["audited_hackerman_v1x"] += 1

        # Schema version classification.
        if schema_version == HACKERMAN_V11_SCHEMA:
            payload["v1_1_record_count"] += 1
        elif schema_version == HACKERMAN_V1_PREFIX or schema_version == HACKERMAN_V1_PREFIX + ".0":
            payload["v1_record_count"] += 1
        else:
            # Any other v1.x minor (forward-compat).
            payload["other_v1x_record_count"] += 1

        # verification_tier population check.
        tier_value = record.get("verification_tier")
        shape_tag_tier = record.get("shape_tag_tier")
        if tier_value:
            tier_str = str(tier_value).strip()
            if tier_str in ACCEPTABLE_TIER_VALUES:
                payload["verification_tier_populated"] += 1
                tier_distribution[tier_str] += 1
            else:
                payload["verification_tier_invalid_value"] += 1
                if len(sample_failures) < 25:
                    sample_failures.append(
                        {
                            "file": str(path),
                            "verdict": "invalid-tier-value",
                            "reason": f"verification_tier={tier_str!r} not in taxonomy",
                            "record_id": record.get("record_id"),
                        }
                    )
        else:
            payload["verification_tier_missing"] += 1
            if len(sample_failures) < 25:
                sample_failures.append(
                    {
                        "file": str(path),
                        "verdict": "missing-verification-tier",
                        "reason": (
                            "v1.1 verification_tier field missing"
                            + (
                                f"; legacy shape_tag={shape_tag_tier} available"
                                if shape_tag_tier
                                else ""
                            )
                        ),
                        "record_id": record.get("record_id"),
                        "schema_version": schema_version,
                    }
                )

        # Firm extraction from source_audit_ref-style prefixes is delegated to
        # the index build; here we approximate distinct_firms by reading the
        # index directly later. We do tally distinct repos and attack classes
        # from the records though.
        ar = record.get("attack_class")
        if ar:
            attack_classes[str(ar)] += 1
        tr = record.get("target_repo")
        if tr:
            target_repos[str(tr)] += 1

        # Drift detection tally: record_ids that carry a top-level v1.1
        # identifier field. Index emit is expected per
        # ``tools/hackerman-index-build.py::_extract_*_ids`` precedence
        # rules (top-level field beats regex fallback). A record whose
        # top-level field is set MUST appear in the corresponding index.
        rid = record.get("record_id")
        if rid:
            cve_val = record.get("cve_id")
            if isinstance(cve_val, str) and cve_val.strip():
                corpus_field_record_ids["cve_id"].add(str(rid))
            ghsa_val = record.get("ghsa_id")
            if isinstance(ghsa_val, str) and ghsa_val.strip():
                corpus_field_record_ids["ghsa_id"].add(str(rid))

    payload["total_records"] = scanned
    payload["tier_distribution"] = dict(tier_distribution)
    payload["distinct_attack_classes"] = len(attack_classes)
    payload["distinct_target_repos"] = len(target_repos)
    payload["sample_failed_records"] = sample_failures[:25]

    # Index health + quarantine-leak check.
    index_health, leak_check = check_indexes(
        index_dir, quarantine_record_ids, quarantine_files
    )
    payload["index_health"] = index_health
    payload["quarantine_leak_check"] = leak_check

    # Index drift check (W2.5-followup, 2026-05-16): detect when corpus
    # carries a top-level identifier field but the corresponding index
    # row is missing (under-population).
    drift_check = check_index_drift(index_dir, corpus_field_record_ids)
    payload["index_drift_check"] = drift_check

    # Derive distinct_firms from the index when available (it's where the
    # firm extraction logic lives).
    firms_index = index_dir / "by_firm.jsonl"
    if firms_index.exists():
        distinct_firms: set = set()
        try:
            with firms_index.open("r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        row = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    key = row.get("key")
                    if key:
                        distinct_firms.add(key)
        except OSError:
            pass
        payload["distinct_firms"] = len(distinct_firms)

    # Verdict resolution.
    failures: List[str] = []
    if payload["v1_record_count"] > 0:
        failures.append(
            f"{payload['v1_record_count']} record(s) still at v1 (migration incomplete)"
        )
    if payload["verification_tier_missing"] > 0:
        failures.append(
            f"{payload['verification_tier_missing']} record(s) missing verification_tier"
        )
    if payload["verification_tier_invalid_value"] > 0:
        failures.append(
            f"{payload['verification_tier_invalid_value']} record(s) have invalid verification_tier value"
        )
    for name, info in index_health.items():
        if info.get("status") != "OK":
            failures.append(
                f"index {name}: {info.get('status')} ({info.get('reason', 'unknown')})"
            )
    if leak_check.get("status") != "OK":
        failures.append(
            leak_check.get("reason", "quarantine leak check FAILED")
        )
    if drift_check.get("status") != "OK":
        for _f in drift_check.get("failures") or []:
            failures.append(f"index drift: {_f}")

    payload["failures"] = failures
    payload["overall_status"] = "PASS" if not failures else "FAIL"
    rc = 0 if not failures else 1
    return rc, payload


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def _print_human(payload: Dict[str, Any]) -> None:
    print("# wave2-w21-post-migration-validator")
    print(f"workspace: {payload['workspace']}")
    print(f"tags_dir:  {payload['tags_dir']}")
    print(f"index_dir: {payload['index_dir']}")
    print(f"total_records:         {payload['total_records']}")
    print(f"audited_hackerman_v1x: {payload['audited_hackerman_v1x']}")
    print(f"  v1_record_count:     {payload['v1_record_count']} (post-migration: 0)")
    print(f"  v1.1_record_count:   {payload['v1_1_record_count']}")
    print(f"  other_v1x_count:     {payload['other_v1x_record_count']}")
    print(
        f"verification_tier:     {payload['verification_tier_populated']} populated / "
        f"{payload['verification_tier_missing']} missing / "
        f"{payload['verification_tier_invalid_value']} invalid"
    )
    if payload.get("tier_distribution"):
        print("tier_distribution:")
        for tier, n in sorted(payload["tier_distribution"].items()):
            print(f"  {tier:<40} {n:>7}")
    print(f"quarantine_record_count: {payload['quarantine_record_count']}")
    print(f"deprecated_record_count: {payload['deprecated_record_count']}")
    print(f"distinct_firms: {payload['distinct_firms']}")
    print(f"distinct_attack_classes: {payload['distinct_attack_classes']}")
    print(f"distinct_target_repos:   {payload['distinct_target_repos']}")
    print()
    print("# index_health")
    for name, info in payload["index_health"].items():
        line_count = info.get("line_count")
        size = info.get("size_bytes")
        extras = []
        if line_count is not None:
            extras.append(f"lines={line_count}")
        if size is not None:
            extras.append(f"bytes={size}")
        if info.get("reason"):
            extras.append(f"reason={info['reason']}")
        suffix = (" " + " ".join(extras)) if extras else ""
        print(f"  {name:<28} {info.get('status', '?'):<6}{suffix}")
    print()
    leak = payload["quarantine_leak_check"]
    leak_count = leak.get("by_cve_id_leak_count", 0)
    print(f"quarantine_leak_check: {leak.get('status', '?')} ({leak_count} leaks)")
    if leak.get("reason"):
        print(f"  reason: {leak['reason']}")
    print()
    drift = payload.get("index_drift_check") or {}
    print(f"index_drift_check: {drift.get('status', '?')}")
    for iname, dinfo in (drift.get("per_index") or {}).items():
        extras = []
        if "expected_record_count" in dinfo:
            extras.append(f"expected={dinfo['expected_record_count']}")
        if "actual_record_count" in dinfo:
            extras.append(f"actual={dinfo['actual_record_count']}")
        if dinfo.get("corpus_only_record_count"):
            extras.append(f"corpus_only={dinfo['corpus_only_record_count']}")
        if dinfo.get("index_only_record_count"):
            extras.append(f"index_only={dinfo['index_only_record_count']}")
        suffix = (" " + " ".join(extras)) if extras else ""
        print(f"  {iname:<28} {dinfo.get('status', '?'):<6}{suffix}")
        if dinfo.get("reason"):
            print(f"    reason: {dinfo['reason']}")
    print()
    print(f"overall_status: {payload['overall_status']}")
    if payload["failures"]:
        print("failures:")
        for f in payload["failures"]:
            print(f"  - {f}")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument(
        "--workspace",
        type=Path,
        default=DEFAULT_WORKSPACE,
        help="Repo root containing audit/corpus_tags/{tags,index}/.",
    )
    parser.add_argument(
        "--tags-dir",
        type=Path,
        default=None,
        help=(
            "Override the tags directory path directly. When supplied, "
            "takes precedence over --workspace and the sibling index/ "
            "directory is derived from this path's parent. Mirrors the "
            "--tags-dir flag on tools/hackerman-schema-v1-to-v1.1-runner.py."
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit the JSON status pack on stdout (silences the human report).",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero when overall_status=FAIL.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Cap scanned record files (for smoke / CI sanity).",
    )
    args = parser.parse_args(argv)

    tags_dir_arg = args.tags_dir.expanduser() if args.tags_dir is not None else None
    rc, payload = validate(
        args.workspace.expanduser(),
        limit=args.limit,
        tags_dir=tags_dir_arg,
    )

    if args.json:
        json.dump(payload, sys.stdout, sort_keys=True, indent=2)
        sys.stdout.write("\n")
    else:
        _print_human(payload)

    if payload["overall_status"] == "ERROR":
        return 2
    if not args.strict:
        return 0
    return rc


if __name__ == "__main__":
    sys.exit(main())
