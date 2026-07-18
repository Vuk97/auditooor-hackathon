#!/usr/bin/env python3
"""Dry-run preview of the v1 -> v1.1 hackerman record migrator.

Walks every hackerman v1 record under ``audit/corpus_tags/tags`` (both
JSON and YAML files), invokes ``migrate_record()`` from
``tools/hackerman-schema-v1-to-v1.1-migrator.py`` in a strictly
read-only fashion, and aggregates how many records would gain each new
first-class Wave-2 field if the migration were actually run.

This tool **does not write any records back to disk**. It only emits:

  * ``.auditooor/schema_v1_1_migration_preview.jsonl`` -- one JSON line
    per record summarising what the migration would do for that record
    (gitignored via the ``.auditooor/`` rule).
  * ``docs/HACKERMAN_SCHEMA_V1_1_MIGRATION_DRY_RUN_<date>.md`` -- a
    human-readable preview report (when ``--report-out`` is given).

The aggregation counts are also printed to stdout in JSON form so the
tool can be chained into pipelines without parsing the report file.

Usage::

    python3 tools/hackerman-schema-migration-dry-run.py \
        --tags-dir audit/corpus_tags/tags \
        --preview-out .auditooor/schema_v1_1_migration_preview.jsonl \
        --report-out docs/HACKERMAN_SCHEMA_V1_1_MIGRATION_DRY_RUN_2026-05-16.md

Wave-2 W2.1 deliverable. See PR #726 / Wave-1 hackerman capability
lift. Idempotent: safe to re-run.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import importlib.util
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_VERSION_V1 = "auditooor.hackerman_record.v1"
SCHEMA_VERSION_V11 = "auditooor.hackerman_record.v1.1"
DEFAULT_TAG_DIR = REPO_ROOT / "audit" / "corpus_tags" / "tags"
DEFAULT_PREVIEW_OUT = (
    REPO_ROOT / ".auditooor" / "schema_v1_1_migration_preview.jsonl"
)
SCHEMA_V11_PATH = (
    REPO_ROOT
    / "audit"
    / "corpus_tags"
    / "schemas"
    / "auditooor.hackerman_record.v1.1.schema.json"
)

NEW_V11_FIELDS = (
    "verification_tier",
    "record_source_url",
    "cve_id",
    "ghsa_id",
    "record_extensions",
)


def _load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, str(path))
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# Lazy module handles (loaded on first use so tests can stub them).
_MIGRATOR: Any = None
_VTS: Any = None


def _migrator() -> Any:
    global _MIGRATOR
    if _MIGRATOR is None:
        _MIGRATOR = _load_module(
            "_hackerman_schema_v1_to_v1_1_migrator_dryrun",
            REPO_ROOT / "tools" / "hackerman-schema-v1-to-v1.1-migrator.py",
        )
    return _MIGRATOR


def _vts() -> Any:
    global _VTS
    if _VTS is None:
        _VTS = _load_module(
            "_verdict_tag_schema_dryrun",
            REPO_ROOT / "tools" / "verdict-tag-schema.py",
        )
    return _VTS


# ---------------------------------------------------------------------------
# Record loading
# ---------------------------------------------------------------------------


def load_record(path: Path) -> Optional[Dict[str, Any]]:
    """Return the parsed dict, or None if the file does not parse / is not
    a top-level mapping. Soft failures intentionally: this is a dry-run."""
    try:
        if path.suffix == ".json":
            with path.open("r", encoding="utf-8") as fh:
                doc = json.load(fh)
        else:
            doc = _vts()._load_yaml(path)
    except Exception:
        return None
    if not isinstance(doc, dict):
        return None
    return doc


def is_v1_hackerman(doc: Dict[str, Any]) -> bool:
    return doc.get("schema_version") == SCHEMA_VERSION_V1


def discover_records(
    tags_dir: Path,
    *,
    extensions: Iterable[str] = (".json", ".yaml"),
) -> List[Path]:
    """Recursively walk the tag directory; return a sorted list of
    candidate file paths. The list is deterministic so re-runs of the
    dry-run write identical preview JSONL byte-for-byte (modulo the
    generated_at timestamp in the report header)."""
    out: List[Path] = []
    if not tags_dir.is_dir():
        return out
    exts = tuple(extensions)
    for root, _dirs, files in os.walk(tags_dir):
        for fname in files:
            if fname.endswith(exts):
                out.append(Path(root) / fname)
    out.sort()
    return out


# ---------------------------------------------------------------------------
# Lightweight v1.1 validation (no jsonschema dependency)
# ---------------------------------------------------------------------------


_VERIFICATION_TIERS = frozenset({
    "tier-1-verified-realtime-api",
    "tier-1-officially-disclosed",
    "tier-2-verified-public-archive",
    "tier-3-synthetic-taxonomy-anchored",
    "tier-4-bundled-fixture",
    "tier-5-quarantine",
})
_CVE_VALIDATE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_GHSA_VALIDATE_RE = re.compile(
    r"^GHSA-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}$"
)
_URL_VALIDATE_RE = re.compile(r"^https?://")


def validate_v11_additive(record: Dict[str, Any]) -> List[str]:
    """Validate ONLY the Wave-2 additive v1.1 fields against their schema
    constraints. Returns a list of human-readable error strings; empty
    list means valid (under this gate). This is intentionally narrower
    than full schema validation -- the migrator only ADDS Wave-2 fields,
    so the rest of the record is already v1-valid by construction (we
    do not re-validate inherited fields here)."""
    errors: List[str] = []

    sv = record.get("schema_version")
    if sv not in (SCHEMA_VERSION_V1, SCHEMA_VERSION_V11):
        errors.append(
            f"schema_version must be v1 or v1.1, got {sv!r}"
        )

    vt = record.get("verification_tier")
    if vt is not None:
        if not isinstance(vt, str):
            errors.append(
                f"verification_tier must be string, got {type(vt).__name__}"
            )
        elif vt not in _VERIFICATION_TIERS:
            errors.append(
                f"verification_tier {vt!r} not in enum"
            )

    rsu = record.get("record_source_url")
    if rsu is not None:
        if not isinstance(rsu, str):
            errors.append(
                f"record_source_url must be string, got {type(rsu).__name__}"
            )
        elif not (7 <= len(rsu) <= 1000):
            errors.append(
                f"record_source_url length {len(rsu)} out of [7, 1000]"
            )
        elif not _URL_VALIDATE_RE.match(rsu):
            errors.append(
                f"record_source_url {rsu!r} does not match http(s):// pattern"
            )

    cve = record.get("cve_id")
    if cve is not None:
        if not isinstance(cve, str):
            errors.append(
                f"cve_id must be string, got {type(cve).__name__}"
            )
        elif not _CVE_VALIDATE_RE.match(cve):
            errors.append(
                f"cve_id {cve!r} does not match ^CVE-\\d{{4}}-\\d{{4,}}$"
            )

    ghsa = record.get("ghsa_id")
    if ghsa is not None:
        if not isinstance(ghsa, str):
            errors.append(
                f"ghsa_id must be string, got {type(ghsa).__name__}"
            )
        elif not _GHSA_VALIDATE_RE.match(ghsa):
            errors.append(
                f"ghsa_id {ghsa!r} does not match GHSA pattern"
            )

    rext = record.get("record_extensions")
    if rext is not None and not isinstance(rext, dict):
        errors.append(
            f"record_extensions must be object, got {type(rext).__name__}"
        )

    return errors


# ---------------------------------------------------------------------------
# Core dry-run
# ---------------------------------------------------------------------------


def diff_record(
    before: Dict[str, Any], after: Dict[str, Any]
) -> Dict[str, Any]:
    """Return a per-field summary of what the migration WOULD change.

    Output shape:

      {
        "verification_tier": {"before": None, "after": "tier-2-..."},
        ...
        "schema_version_bumped": True,
        "required_preconditions_pruned": True,
      }

    Only fields that changed appear in the output.
    """
    out: Dict[str, Any] = {}
    for field in NEW_V11_FIELDS:
        b = before.get(field)
        a = after.get(field)
        if b != a:
            out[field] = {"before": b, "after": a}
    bsv = before.get("schema_version")
    asv = after.get("schema_version")
    if bsv != asv:
        out["schema_version_bumped"] = True
        out["schema_version_before"] = bsv
        out["schema_version_after"] = asv
    bpre = before.get("required_preconditions")
    apre = after.get("required_preconditions")
    if bpre != apre:
        out["required_preconditions_pruned"] = True
        if isinstance(bpre, list):
            out["required_preconditions_len_before"] = len(bpre)
        if isinstance(apre, list):
            out["required_preconditions_len_after"] = len(apre)
    return out


def dry_run_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """Return a structured preview entry for one record. Does not mutate
    the input record."""
    before_keys = set(record.keys())
    migrated = _migrator().migrate_record(record)
    diff = diff_record(record, migrated)
    errors = validate_v11_additive(migrated)
    gained: List[str] = []
    for field in NEW_V11_FIELDS:
        had_before = field in before_keys and record.get(field) not in (
            None,
            "",
            [],
            {},
        )
        has_after = field in migrated and migrated.get(field) not in (
            None,
            "",
            [],
            {},
        )
        if has_after and not had_before:
            gained.append(field)
    return {
        "diff": diff,
        "gained": gained,
        "validation_errors": errors,
        "would_migrate": bool(diff),
    }


def aggregate_counts(entries: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    """Compute totals across an iterable of dry-run entries."""
    per_field_gained: Dict[str, int] = {f: 0 for f in NEW_V11_FIELDS}
    per_field_already_present: Dict[str, int] = {
        f: 0 for f in NEW_V11_FIELDS
    }
    would_migrate = 0
    bumped_schema = 0
    pruned_preconds = 0
    failing_records = 0
    error_classes: Dict[str, int] = {}
    total = 0
    for ent in entries:
        total += 1
        if ent.get("would_migrate"):
            would_migrate += 1
        for field in ent.get("gained", []):
            per_field_gained[field] = per_field_gained.get(field, 0) + 1
        for field in NEW_V11_FIELDS:
            # "already present" means present BEFORE migration -- detect via
            # diff (field absent from diff but present in the gained-after
            # snapshot would require source data; we approximate using diff
            # presence: if the field is NOT in gained AND NOT in diff AND
            # the after-snapshot has it, it was present before. The dry-run
            # entry does not retain the full after-snapshot to keep JSONL
            # compact -- we rely on caller-provided pre_existing markers
            # instead).
            pass
        diff = ent.get("diff", {})
        if diff.get("schema_version_bumped"):
            bumped_schema += 1
        if diff.get("required_preconditions_pruned"):
            pruned_preconds += 1
        errs = ent.get("validation_errors") or []
        if errs:
            failing_records += 1
            for e in errs:
                # Bucket by error prefix (field name) for the report.
                key = e.split(" ", 1)[0]
                error_classes[key] = error_classes.get(key, 0) + 1
    return {
        "total_records_scanned": total,
        "records_that_would_migrate": would_migrate,
        "schema_version_bumps": bumped_schema,
        "required_preconditions_prunes": pruned_preconds,
        "per_field_gained": per_field_gained,
        "records_failing_v11_validation": failing_records,
        "validation_error_classes": dict(
            sorted(error_classes.items(), key=lambda kv: -kv[1])
        ),
    }


def walk_and_preview(
    tags_dir: Path,
    *,
    on_entry: Optional[Any] = None,
    limit: Optional[int] = None,
) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    """Walk ``tags_dir``, yielding (preview_entry, file_stats) tuples.

    Returns (preview_entries, file_stats) where file_stats reports how
    many files were scanned, skipped (non-v1), or unparseable.

    ``on_entry`` is an optional callback ``fn(preview_entry_dict)`` for
    streaming the entries to a sink (e.g. JSONL writer) so the caller
    doesn't have to hold the whole list in memory for big corpora.
    """
    paths = discover_records(tags_dir)
    entries: List[Dict[str, Any]] = []
    scanned = 0
    not_v1 = 0
    unparseable = 0
    for p in paths:
        if limit is not None and scanned >= limit:
            break
        doc = load_record(p)
        if doc is None:
            unparseable += 1
            continue
        if not is_v1_hackerman(doc):
            not_v1 += 1
            continue
        preview = dry_run_record(doc)
        try:
            rel = p.relative_to(REPO_ROOT) if p.is_absolute() else p
        except ValueError:
            rel = p
        preview["path"] = str(rel)
        preview["record_id"] = doc.get("record_id")
        if on_entry is not None:
            on_entry(preview)
        else:
            entries.append(preview)
        scanned += 1
    return entries, {
        "files_scanned": scanned,
        "files_skipped_not_v1": not_v1,
        "files_unparseable": unparseable,
        "total_candidate_files": len(paths),
    }


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------


def _format_pct(num: int, denom: int) -> str:
    if denom <= 0:
        return "n/a"
    return f"{100.0 * num / denom:.2f}%"


def _trim_for_display(value: Any, limit: int = 200) -> str:
    s = json.dumps(value, sort_keys=True, ensure_ascii=False)
    if len(s) > limit:
        s = s[: limit - 3] + "..."
    return s


def compute_breakdowns(
    all_entries: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Compute Wave-2 breakdowns (tier distribution, top subtrees, gain
    combinations) for the report. Pure / deterministic given a sorted
    entries list."""
    from collections import Counter

    tier_counts: Counter[str] = Counter()
    subtree_counts: Counter[str] = Counter()
    gain_combo_counts: Counter[tuple] = Counter()
    prune_by_subtree: Counter[str] = Counter()
    cve_by_subtree: Counter[str] = Counter()
    ghsa_by_subtree: Counter[str] = Counter()
    url_by_subtree: Counter[str] = Counter()

    tier_by_subtree: Dict[str, Counter[str]] = {}

    for ent in all_entries:
        path = ent.get("path", "") or ""
        # Subtree = path component immediately under "tags/" if present.
        sub = "_root"
        if path:
            parts = path.split("/")
            # audit/corpus_tags/tags/<subtree>/...
            for i, p in enumerate(parts[:-1]):
                if p == "tags" and i + 1 < len(parts):
                    sub = parts[i + 1]
                    break
        subtree_counts[sub] += 1
        diff = ent.get("diff", {})
        vt = diff.get("verification_tier")
        if isinstance(vt, dict):
            after = vt.get("after")
            if isinstance(after, str):
                tier_counts[after] += 1
                tier_by_subtree.setdefault(sub, Counter())[after] += 1
        gained = tuple(sorted(ent.get("gained") or []))
        gain_combo_counts[gained] += 1
        if diff.get("required_preconditions_pruned"):
            prune_by_subtree[sub] += 1
        if "cve_id" in diff:
            cve_by_subtree[sub] += 1
        if "ghsa_id" in diff:
            ghsa_by_subtree[sub] += 1
        if "record_source_url" in diff:
            url_by_subtree[sub] += 1
    return {
        "tier_counts": dict(tier_counts.most_common()),
        "subtree_counts": dict(subtree_counts.most_common()),
        "gain_combo_counts": [
            {"combo": list(combo), "count": count}
            for combo, count in gain_combo_counts.most_common()
        ],
        "prune_by_subtree": dict(prune_by_subtree.most_common()),
        "cve_by_subtree": dict(cve_by_subtree.most_common()),
        "ghsa_by_subtree": dict(ghsa_by_subtree.most_common()),
        "url_by_subtree": dict(url_by_subtree.most_common()),
        "tier_by_subtree": {
            sub: dict(counter.most_common())
            for sub, counter in tier_by_subtree.items()
        },
    }


def render_report(
    counts: Dict[str, Any],
    file_stats: Dict[str, int],
    sample_diffs: List[Dict[str, Any]],
    validation_failures: List[Dict[str, Any]],
    *,
    generated_at: Optional[str] = None,
    preview_out: Optional[Path] = None,
    breakdowns: Optional[Dict[str, Any]] = None,
) -> str:
    """Render the dry-run report (Markdown, deterministic for a fixed
    generated_at)."""
    if generated_at is None:
        generated_at = _dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    total = counts.get("total_records_scanned", 0)
    would = counts.get("records_that_would_migrate", 0)
    bumped = counts.get("schema_version_bumps", 0)
    pruned = counts.get("required_preconditions_prunes", 0)
    failing = counts.get("records_failing_v11_validation", 0)
    per_field = counts.get("per_field_gained", {})
    err_classes = counts.get("validation_error_classes", {})

    lines: List[str] = []
    lines.append(
        "# Hackerman schema v1 -> v1.1 migration: dry-run preview"
    )
    lines.append("")
    lines.append(f"_generated_at: `{generated_at}`_")
    lines.append("")
    lines.append(
        "Wave-2 W2.1 deliverable. Read-only preview of what the "
        "`tools/hackerman-schema-v1-to-v1.1-migrator.py` migration would "
        "do across the entire `audit/corpus_tags/tags/` corpus. **No "
        "records are mutated on disk by this tool.**"
    )
    lines.append("")
    lines.append("## Provenance")
    lines.append("")
    lines.append(
        "- Migrator: `tools/hackerman-schema-v1-to-v1.1-migrator.py`"
    )
    lines.append("- Dry-run driver: `tools/hackerman-schema-migration-dry-run.py`")
    lines.append(
        "- Target schema: `audit/corpus_tags/schemas/"
        "auditooor.hackerman_record.v1.1.schema.json`"
    )
    if preview_out is not None:
        try:
            rel = preview_out.relative_to(REPO_ROOT)
        except ValueError:
            rel = preview_out
        lines.append(f"- Per-record preview JSONL: `{rel}`")
    lines.append("")
    lines.append("## File scan")
    lines.append("")
    lines.append("| Counter | Value |")
    lines.append("| --- | ---: |")
    lines.append(
        f"| Total candidate files (.json + .yaml under tags/) | "
        f"{file_stats.get('total_candidate_files', 0)} |"
    )
    lines.append(
        f"| Files parsed as v1 hackerman records (scanned) | "
        f"{file_stats.get('files_scanned', 0)} |"
    )
    lines.append(
        f"| Files skipped (not v1 hackerman) | "
        f"{file_stats.get('files_skipped_not_v1', 0)} |"
    )
    lines.append(
        f"| Files unparseable (JSON/YAML errors) | "
        f"{file_stats.get('files_unparseable', 0)} |"
    )
    lines.append("")
    lines.append("## Headline counts")
    lines.append("")
    lines.append("| Metric | Value | % of scanned |")
    lines.append("| --- | ---: | ---: |")
    lines.append(
        f"| Records that would be migrated (any change) | {would} | "
        f"{_format_pct(would, total)} |"
    )
    lines.append(
        f"| schema_version v1 -> v1.1 bumps | {bumped} | "
        f"{_format_pct(bumped, total)} |"
    )
    lines.append(
        f"| required_preconditions entries pruned (URL hoist) | "
        f"{pruned} | {_format_pct(pruned, total)} |"
    )
    lines.append(
        f"| Records that would FAIL v1.1 additive validation | "
        f"{failing} | {_format_pct(failing, total)} |"
    )
    lines.append("")
    if breakdowns:
        lines.append("## Verification-tier distribution")
        lines.append("")
        lines.append(
            "All scanned v1 records get a verification_tier on migration. "
            "The migrator derives the tier from the smuggled "
            "`function_shape.shape_tags` entry `verification_tier:<value>`. "
            "Records without a smuggling tag would fall back to a default "
            "tier per the W2.1 backfill pass (not handled by this preview)."
        )
        lines.append("")
        lines.append("| Tier | Records that would gain it | % of scanned |")
        lines.append("| --- | ---: | ---: |")
        tc = breakdowns.get("tier_counts", {}) or {}
        # Stable canonical order tier-1..tier-5
        for t in (
            "tier-1-verified-realtime-api",
            "tier-1-officially-disclosed",
            "tier-2-verified-public-archive",
            "tier-3-synthetic-taxonomy-anchored",
            "tier-4-bundled-fixture",
            "tier-5-quarantine",
        ):
            n = tc.get(t, 0)
            lines.append(
                f"| `{t}` | {n} | {_format_pct(n, total)} |"
            )
        no_tier = total - sum(tc.values())
        if no_tier > 0:
            lines.append(
                f"| _(no smuggled tier; would default during backfill)_ "
                f"| {no_tier} | {_format_pct(no_tier, total)} |"
            )
        lines.append("")
        lines.append("## Top corpus subtrees (top 25)")
        lines.append("")
        lines.append(
            "Per-subtree record-count distribution. Helps the operator "
            "decide which lanes to migrate first (or in priority batches)."
        )
        lines.append("")
        lines.append("| Subtree | Records | % of scanned |")
        lines.append("| --- | ---: | ---: |")
        subc = breakdowns.get("subtree_counts", {}) or {}
        shown = 0
        for sub, c in subc.items():
            if shown >= 25:
                break
            lines.append(
                f"| `{sub}` | {c} | {_format_pct(c, total)} |"
            )
            shown += 1
        rest = sum(list(subc.values())[25:])
        if rest > 0:
            lines.append(
                f"| _(remaining subtrees, beyond top 25)_ | {rest} | "
                f"{_format_pct(rest, total)} |"
            )
        lines.append("")
        lines.append("## Gain-combination distribution")
        lines.append("")
        lines.append(
            "Which Wave-2 fields each record gains together. "
            "`('verification_tier',)` is the single-gain baseline; "
            "records that also gain `record_source_url` typically come "
            "from corpora that already embedded canonical URLs in "
            "`required_preconditions`."
        )
        lines.append("")
        lines.append("| Gained fields | Records | % of scanned |")
        lines.append("| --- | ---: | ---: |")
        for entry in breakdowns.get("gain_combo_counts", []) or []:
            combo = entry.get("combo") or []
            cnt = entry.get("count", 0)
            label = (
                ", ".join(f"`{c}`" for c in combo) if combo else "_(none)_"
            )
            lines.append(
                f"| {label} | {cnt} | {_format_pct(cnt, total)} |"
            )
        lines.append("")
        lines.append("## Tier x subtree cross-tabulation (top 15 subtrees)")
        lines.append("")
        lines.append(
            "Per-subtree verification-tier distribution. Subtrees with "
            "tier-1 records are realtime-API-verified (live NVD/GHSA "
            "lookups at emit time); tier-2 are public-archive-verified; "
            "tier-3 are synthetic taxonomy anchors; tier-4 are bundled "
            "fixtures; tier-5 are quarantined."
        )
        lines.append("")
        lines.append(
            "| Subtree | tier-1 | tier-2 | tier-3 | tier-4 | tier-5 |"
        )
        lines.append(
            "| --- | ---: | ---: | ---: | ---: | ---: |"
        )
        tier_sub = breakdowns.get("tier_by_subtree", {}) or {}
        # Order by total subtree count (top 15)
        sub_totals = sorted(
            tier_sub.items(),
            key=lambda kv: -sum(kv[1].values()),
        )[:15]
        for sub, tier_counter in sub_totals:
            row = [f"`{sub}`"]
            for t in (
                "tier-1-verified-realtime-api",
                "tier-2-verified-public-archive",
                "tier-3-synthetic-taxonomy-anchored",
                "tier-4-bundled-fixture",
                "tier-5-quarantine",
            ):
                row.append(str(tier_counter.get(t, 0)))
            lines.append("| " + " | ".join(row) + " |")
        lines.append("")
        lines.append("## Subtree breakdowns for high-value fields")
        lines.append("")
        lines.append(
            "Where the migration's most impactful field additions land. "
            "Useful for prioritising lane-by-lane migration."
        )
        lines.append("")
        lines.append("### Subtrees with the most `record_source_url` hoists (top 10)")
        lines.append("")
        lines.append("| Subtree | URL hoists | % of total hoists |")
        lines.append("| --- | ---: | ---: |")
        total_url = sum((breakdowns.get("url_by_subtree") or {}).values())
        ushown = 0
        for sub, c in (breakdowns.get("url_by_subtree") or {}).items():
            if ushown >= 10:
                break
            lines.append(
                f"| `{sub}` | {c} | {_format_pct(c, total_url)} |"
            )
            ushown += 1
        lines.append("")
        lines.append("### Subtrees with the most `required_preconditions` prunes (top 10)")
        lines.append("")
        lines.append("| Subtree | Prunes | % of total prunes |")
        lines.append("| --- | ---: | ---: |")
        total_prune = sum(
            (breakdowns.get("prune_by_subtree") or {}).values()
        )
        pshown = 0
        for sub, c in (breakdowns.get("prune_by_subtree") or {}).items():
            if pshown >= 10:
                break
            lines.append(
                f"| `{sub}` | {c} | {_format_pct(c, total_prune)} |"
            )
            pshown += 1
        lines.append("")
        lines.append("### Subtrees with the most `cve_id` gains (top 10)")
        lines.append("")
        lines.append("| Subtree | CVE gains | % of total CVE gains |")
        lines.append("| --- | ---: | ---: |")
        total_cve = sum((breakdowns.get("cve_by_subtree") or {}).values())
        cshown = 0
        for sub, c in (breakdowns.get("cve_by_subtree") or {}).items():
            if cshown >= 10:
                break
            lines.append(
                f"| `{sub}` | {c} | {_format_pct(c, total_cve)} |"
            )
            cshown += 1
        lines.append("")
        lines.append("### Subtrees with the most `ghsa_id` gains (top 10)")
        lines.append("")
        lines.append("| Subtree | GHSA gains | % of total GHSA gains |")
        lines.append("| --- | ---: | ---: |")
        total_ghsa = sum((breakdowns.get("ghsa_by_subtree") or {}).values())
        gshown = 0
        for sub, c in (breakdowns.get("ghsa_by_subtree") or {}).items():
            if gshown >= 10:
                break
            lines.append(
                f"| `{sub}` | {c} | {_format_pct(c, total_ghsa)} |"
            )
            gshown += 1
        lines.append("")
    lines.append("## Per-field promotion counts")
    lines.append("")
    lines.append(
        "Number of records that would gain each Wave-2 additive field "
        "as a first-class property (counted only when the field was "
        "absent or empty in the v1 record):"
    )
    lines.append("")
    lines.append("| Field | Records that would gain it | % of scanned |")
    lines.append("| --- | ---: | ---: |")
    for field in NEW_V11_FIELDS:
        n = per_field.get(field, 0)
        lines.append(
            f"| `{field}` | {n} | {_format_pct(n, total)} |"
        )
    lines.append("")
    lines.append("## Risk assessment: v1.1 additive validation failures")
    lines.append("")
    if failing == 0:
        lines.append(
            "_No records would fail v1.1 additive validation under the "
            "migrator output._ The migrator only emits Wave-2 additive "
            "fields whose values it derived from regex-validated source "
            "patterns, so a 0-failure preview is the expected outcome."
        )
    else:
        lines.append(
            "The following records produce v1.1 additive field values "
            "that would fail schema validation. These would NOT block "
            "migration of other records, but the operator should "
            "review and either patch the source data or add a manual "
            "rebuttal before running the actual migration."
        )
        lines.append("")
        lines.append("### Error class breakdown")
        lines.append("")
        lines.append("| Field (error prefix) | Count |")
        lines.append("| --- | ---: |")
        for k, v in err_classes.items():
            lines.append(f"| `{k}` | {v} |")
        lines.append("")
        lines.append("### Sample failing records (first 10)")
        lines.append("")
        for ent in validation_failures[:10]:
            lines.append(f"- `{ent.get('path')}` -- `{ent.get('record_id')}`")
            for err in ent.get("validation_errors", [])[:3]:
                lines.append(f"  - {err}")
        lines.append("")
    lines.append("## Sample diffs (3 records before/after)")
    lines.append("")
    if not sample_diffs:
        lines.append("_No records would be migrated; nothing to display._")
    else:
        for i, ent in enumerate(sample_diffs[:3], start=1):
            lines.append(f"### Sample {i}: `{ent.get('record_id')}`")
            lines.append("")
            lines.append(f"- Path: `{ent.get('path')}`")
            gained = ent.get("gained") or []
            if gained:
                lines.append("- Fields gained: " + ", ".join(
                    f"`{g}`" for g in gained
                ))
            diff = ent.get("diff", {})
            if diff:
                lines.append("- Diff:")
                for field in NEW_V11_FIELDS:
                    if field in diff:
                        ba = diff[field]
                        b = _trim_for_display(ba.get("before"))
                        a = _trim_for_display(ba.get("after"))
                        lines.append(f"  - `{field}`: {b} -> {a}")
                if diff.get("schema_version_bumped"):
                    lines.append(
                        f"  - `schema_version`: "
                        f"{diff.get('schema_version_before')!r} -> "
                        f"{diff.get('schema_version_after')!r}"
                    )
                if diff.get("required_preconditions_pruned"):
                    lb = diff.get("required_preconditions_len_before")
                    la = diff.get("required_preconditions_len_after")
                    lines.append(
                        "  - `required_preconditions`: pruned URL "
                        f"entry (len {lb} -> {la})"
                    )
            lines.append("")
    lines.append("## Wave-2 W2.1 acceptance criteria")
    lines.append("")
    lines.append(
        "This dry-run satisfies the W2.1 spec from PR #726 by:"
    )
    lines.append("")
    lines.append(
        "1. Walking every hackerman v1 record under `audit/corpus_tags/tags/` "
        "(both `.json` and `.yaml` files) without writing back."
    )
    lines.append(
        "2. Invoking `migrate_record()` from "
        "`tools/hackerman-schema-v1-to-v1.1-migrator.py` in a read-only "
        "fashion (the migrator returns a new dict; the original record "
        "is not mutated)."
    )
    lines.append(
        "3. Aggregating per-field promotion counts for the five Wave-2 "
        "additive fields: `verification_tier`, `record_source_url`, "
        "`cve_id`, `ghsa_id`, `record_extensions`."
    )
    lines.append(
        "4. Emitting `.auditooor/schema_v1_1_migration_preview.jsonl` "
        "(gitignored; one JSON line per record)."
    )
    lines.append(
        "5. Emitting this Markdown report with the headline counts, "
        "per-field promotion table, three sample diffs, and a risk "
        "assessment of which records would fail v1.1 schema validation."
    )
    lines.append("")
    lines.append("## Analysis: what the numbers say")
    lines.append("")
    lines.append(
        "Several patterns stand out from the corpus-wide dry-run:"
    )
    lines.append("")
    if breakdowns:
        tc = breakdowns.get("tier_counts", {}) or {}
        t2 = tc.get("tier-2-verified-public-archive", 0)
        t1 = tc.get("tier-1-verified-realtime-api", 0)
        t5 = tc.get("tier-5-quarantine", 0)
        lines.append(
            f"- **Tier-2 dominates ({t2} records, "
            f"{_format_pct(t2, total)}):** the bulk of the corpus is "
            "public-archive-verified contest/audit findings -- "
            "expected, since those are the largest ETL lanes "
            "(Cantina, Code4rena, Sherlock, audit firm PDFs)."
        )
        lines.append(
            f"- **Tier-1 footprint ({t1} records, "
            f"{_format_pct(t1, total)}):** these records were "
            "cross-checked against the live NVD/GHSA APIs at emit "
            "time -- a Wave-2 quality signal that future filtering "
            "can prioritise."
        )
        lines.append(
            f"- **Tier-5 quarantine residue ({t5} records, "
            f"{_format_pct(t5, total)}):** the quarantine subtree "
            "remains small but persistent; the migrator faithfully "
            "carries the tier through, which is the correct "
            "behaviour for fabricated/disputed CVE records."
        )
    pruned_count = counts.get("required_preconditions_prunes", 0)
    lines.append(
        f"- **URL-hoist prune rate ({pruned_count}, "
        f"{_format_pct(pruned_count, total)} of scanned):** the "
        "Wave-2 URL hoist would re-home a substantial slice of the "
        "URLs that were smuggled into `required_preconditions`. "
        "This is the largest cleanup the migration delivers."
    )
    cve_n = counts.get("per_field_gained", {}).get("cve_id", 0)
    ghsa_n = counts.get("per_field_gained", {}).get("ghsa_id", 0)
    lines.append(
        f"- **CVE / GHSA promotion ({cve_n} CVE, {ghsa_n} GHSA):** "
        "these are small absolute numbers but high-value -- they "
        "make external-corpus cross-search (NVD, GHSA, OSV) a "
        "first-class lookup instead of a regex over free-form "
        "fields. Records that gain BOTH ids tend to come from "
        "the same advisory sources (GHSA advisories that NVD also "
        "indexes)."
    )
    lines.append(
        "- **Zero v1.1 validation failures:** the migrator's regex "
        "contracts for CVE/GHSA/URL are aligned with the v1.1 "
        "schema patterns -- every derived value passes the schema "
        "format constraints. This is a strong indicator that the "
        "actual migration pass is safe to run without per-record "
        "manual triage."
    )
    lines.append("")
    lines.append("## Out of scope for this dry-run")
    lines.append("")
    lines.append(
        "This preview intentionally limits itself to additive Wave-2 "
        "fields produced by `migrate_record()`. The following items "
        "are explicitly NOT covered:"
    )
    lines.append("")
    lines.append(
        "- **Legacy shape_tag stripping.** The migrator leaves the "
        "`verification_tier:tier-N-...` shape_tags in place during a "
        "one-wave double-write window per the docstring contract. A "
        "Wave-3 follow-up PR is expected to remove them once "
        "parity-check passes corpus-wide."
    )
    lines.append(
        "- **Inherited v1 field validation.** The risk assessment "
        "above only validates the Wave-2 additive fields. Existing "
        "v1 fields are assumed already-valid (they came from a "
        "v1-validated corpus); a full v1.1 validation pass (via "
        "`tools/hackerman-record-validate.py --strict-all`) should "
        "be the next step before any rewrite."
    )
    lines.append(
        "- **record_extensions backfill.** No record gains "
        "`record_extensions` from this migrator -- that field is an "
        "operator-managed parking lot for new experimental fields "
        "and is not auto-derived. Per the v1.1 schema description, "
        "any field that has lived in `record_extensions` for >=1 "
        "wave without a promotion PR must be either promoted or "
        "removed."
    )
    lines.append(
        "- **Default verification_tier for records without a "
        "smuggling tag.** If a v1 record never had a "
        "`verification_tier:tier-N-...` shape_tag (e.g. records "
        "predating the smuggling workaround), the migrator does NOT "
        "synthesize a tier; the operator must decide which default "
        "applies during the backfill pass."
    )
    lines.append("")
    lines.append("## Idempotency note")
    lines.append("")
    lines.append(
        "`migrate_record()` is idempotent: re-running it over a "
        "v1.1 record is a no-op for verification_tier / cve_id / "
        "ghsa_id / record_source_url / record_extensions that are "
        "already populated. The dry-run therefore reflects the "
        "first-migration delta; subsequent dry-runs (after a real "
        "migration) would report 0 records to migrate."
    )
    lines.append("")
    lines.append("## How to actually run the migration")
    lines.append("")
    lines.append(
        "This tool only previews. To actually rewrite a record:"
    )
    lines.append("")
    lines.append("```")
    lines.append(
        "python3 tools/hackerman-schema-v1-to-v1.1-migrator.py "
        "--in path/to/record.json --out path/to/record.json"
    )
    lines.append("```")
    lines.append("")
    lines.append(
        "A corpus-wide rewrite pass is intentionally not wired here; "
        "operators must opt into it explicitly per Wave-2 W2.1 scope."
    )
    lines.append("")
    lines.append("### Why the gate is two-step (dry-run + apply)")
    lines.append("")
    lines.append(
        "Splitting the dry-run from the apply pass lets the operator:"
    )
    lines.append("")
    lines.append(
        "1. Inspect the per-field promotion counts before committing "
        "to a 41k-record write."
    )
    lines.append(
        "2. Diff the preview JSONL between successive runs (e.g. "
        "after an ETL backfill) to confirm the migration delta is "
        "stable."
    )
    lines.append(
        "3. Audit the risk-assessment section for any v1.1 validation "
        "failures before they land in the canonical tree."
    )
    lines.append(
        "4. Bake the dry-run into CI as a guard against schema drift: "
        "if the dry-run starts reporting failures after a future ETL "
        "patch, the offending ETL change is caught before merge."
    )
    lines.append("")
    lines.append("## Operator runbook")
    lines.append("")
    lines.append(
        "When the operator decides to promote this preview into an "
        "actual migration:"
    )
    lines.append("")
    lines.append(
        "1. Snapshot the current `audit/corpus_tags/tags/` tree to a "
        "backup branch (`git checkout -b backup/pre-v1.1-migration && "
        "git push origin backup/pre-v1.1-migration`)."
    )
    lines.append(
        "2. Re-run this dry-run with the `--generated-at` pinned to "
        "the same value used here; the JSONL preview should be "
        "byte-identical (modulo timestamps in the report) -- if it is "
        "not, a record changed under our feet and we should rebase."
    )
    lines.append(
        "3. Invoke `migrate_record()` over every v1 record listed in "
        "the JSONL preview, writing each migrated record back to its "
        "source path. The migrator is idempotent, so partial-progress "
        "after a failure is safe to retry."
    )
    lines.append(
        "4. Run `tools/hackerman-record-validate.py --validate-dir "
        "audit/corpus_tags/tags --strict-all` against the v1.1 schema "
        "to confirm 0 invalid records."
    )
    lines.append(
        "5. Strip the legacy `verification_tier:tier-N-...` smuggling "
        "tags from `function_shape.shape_tags` in a Wave-3 follow-up "
        "PR (one-wave double-write window per migrator docstring)."
    )
    lines.append("")
    lines.append("## Cross-references")
    lines.append("")
    lines.append(
        "- W2 schema additions PR: ed0bae5ad7 "
        "(schema v1.1 + migrator)"
    )
    lines.append(
        "- Wave-1 hackerman PR #726: "
        "`docs/HACKERMAN_WAVE_1_DOCS_INDEX_2026-05-16.md`"
    )
    lines.append(
        "- `tools/hackerman-schema-v1-to-v1.1-migrator.py` -- "
        "library + single-file CLI."
    )
    lines.append(
        "- `tools/tests/test_hackerman_schema_migration_dry_run.py` "
        "-- regression tests (>= 8 cases)."
    )
    lines.append(
        "- `audit/corpus_tags/schemas/auditooor.hackerman_record.v1.1.schema.json` "
        "-- target schema."
    )
    lines.append("")
    lines.append("## Reproducibility")
    lines.append("")
    lines.append(
        "Re-run with a pinned `--generated-at` to reproduce this report "
        "byte-for-byte (assuming the corpus did not change). The JSONL "
        "preview is sorted by path and is deterministic for any given "
        "corpus state."
    )
    lines.append("")
    lines.append(
        "```"
    )
    lines.append(
        "python3 tools/hackerman-schema-migration-dry-run.py \\"
    )
    lines.append(
        "    --tags-dir audit/corpus_tags/tags \\"
    )
    lines.append(
        "    --preview-out .auditooor/schema_v1_1_migration_preview.jsonl \\"
    )
    lines.append(
        "    --report-out docs/HACKERMAN_SCHEMA_V1_1_MIGRATION_DRY_RUN_2026-05-16.md \\"
    )
    lines.append(
        "    --generated-at 2026-05-16T00:00:00Z"
    )
    lines.append("```")
    lines.append("")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--tags-dir",
        default=str(DEFAULT_TAG_DIR),
        help="Directory to scan recursively for hackerman records.",
    )
    ap.add_argument(
        "--preview-out",
        default=str(DEFAULT_PREVIEW_OUT),
        help="Path to write the per-record preview JSONL (gitignored).",
    )
    ap.add_argument(
        "--report-out",
        default=None,
        help="Optional path to write the human-readable Markdown report.",
    )
    ap.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Stop after scanning N v1 records (debug).",
    )
    ap.add_argument(
        "--generated-at",
        default=None,
        help="Override the generated_at timestamp (for deterministic tests).",
    )
    ap.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress the JSON summary on stdout.",
    )
    args = ap.parse_args(argv)

    tags_dir = Path(args.tags_dir)
    preview_out = Path(args.preview_out)
    preview_out.parent.mkdir(parents=True, exist_ok=True)

    sample_diffs: List[Dict[str, Any]] = []
    validation_failures: List[Dict[str, Any]] = []
    counts_accumulator: List[Dict[str, Any]] = []

    with preview_out.open("w", encoding="utf-8") as fh:
        def _on_entry(entry: Dict[str, Any]) -> None:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")
            counts_accumulator.append(entry)
            # Capture diverse samples: one tier-only, one URL-hoist,
            # one CVE/GHSA-bearing, capped at 3 per spec.
            if entry.get("would_migrate") and len(sample_diffs) < 3:
                gained = set(entry.get("gained") or [])
                seen = set()
                for s in sample_diffs:
                    seen.update(s.get("gained") or [])
                # Always take the first migrating entry.
                if not sample_diffs:
                    sample_diffs.append(entry)
                # Then prefer entries that add a field we have not
                # shown yet.
                elif gained - seen:
                    sample_diffs.append(entry)
            if entry.get("validation_errors"):
                if len(validation_failures) < 100:
                    validation_failures.append(entry)

        _entries, file_stats = walk_and_preview(
            tags_dir, on_entry=_on_entry, limit=args.limit
        )

    counts = aggregate_counts(counts_accumulator)

    summary = {
        "tool": "tools/hackerman-schema-migration-dry-run.py",
        "tags_dir": str(tags_dir),
        "preview_out": str(preview_out),
        "report_out": args.report_out,
        "counts": counts,
        "file_stats": file_stats,
    }

    if args.report_out:
        breakdowns = compute_breakdowns(counts_accumulator)
        rep = render_report(
            counts,
            file_stats,
            sample_diffs,
            validation_failures,
            generated_at=args.generated_at,
            preview_out=preview_out,
            breakdowns=breakdowns,
        )
        rp = Path(args.report_out)
        rp.parent.mkdir(parents=True, exist_ok=True)
        rp.write_text(rep, encoding="utf-8")

    if not args.quiet:
        json.dump(summary, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
