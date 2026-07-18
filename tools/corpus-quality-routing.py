#!/usr/bin/env python3
"""corpus-quality-routing.py - J3 Full-corpus quality routing.

Classifies each hackerman corpus record into exactly one routing bucket:
  - usable_for_hunting
  - advisory_context_only
  - blocked

Blocked rows are assigned a specific blocked_class and routed to a named
work_queue for concrete remediation action.

Schema ID: auditooor.corpus_quality_routing.v1

Usage:
  python3 tools/corpus-quality-routing.py [--json] [--subtrees A,B,...] [--limit N]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SCHEMA_ID = "auditooor.corpus_quality_routing.v1"
REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TAGS_DIR = REPO_ROOT / "audit" / "corpus_tags" / "tags"

ACCEPTED_SCHEMAS = (
    "auditooor.hackerman_record.v1",
    "auditooor.hackerman_record.v1.1",
    # Phase 1 (trusted-corpus, v1.2): accept the wide-shape v1.2 records so a
    # v1.2 drop cannot be silently hidden from routing. run_scan reports
    # per-schema-version counts in the output so the breakdown is visible.
    "auditooor.hackerman_record.v1.2",
)

EXCLUDED_SUBTREE_PREFIXES = ("_QUARANTINE_", "_deprecated")

# Routing buckets
BUCKET_USABLE = "usable_for_hunting"
BUCKET_ADVISORY = "advisory_context_only"
BUCKET_BLOCKED = "blocked"

# Blocked class vocabulary (exact, as specified in plan)
BC_DARK_AUDIT_FIRM = "dark_audit_firm_report_no_extraction"
BC_LOW_CONFIDENCE_PROSE = "low_confidence_prose_draft"
BC_MISSING_PROOF = "missing_proof_artifact_path"
BC_WEAK_TIER = "missing_or_weak_verification_tier"
BC_ORPHAN_ATTACK = "orphan_attack_class"
BC_UNKNOWN_YEAR = "unknown_year_no_source_date"
BC_STALE_SOURCE = "stale_external_source_state"
BC_SYNTHETIC_FIXTURE = "synthetic_fixture_only"
BC_TEMPLATE_ANALOGUE = "template_analogue_no_provenance"

# Work queue names - one per blocked class
WORK_QUEUES: dict[str, str] = {
    BC_DARK_AUDIT_FIRM: "audit_firm_extraction_queue",
    BC_LOW_CONFIDENCE_PROSE: "prose_draft_confidence_uplift_queue",
    BC_MISSING_PROOF: "proof_artifact_backfill_queue",
    BC_WEAK_TIER: "verification_tier_uplift_queue",
    BC_ORPHAN_ATTACK: "attack_class_normalisation_queue",
    BC_UNKNOWN_YEAR: "source_date_resolution_queue",
    BC_STALE_SOURCE: "stale_source_refresh_queue",
    BC_SYNTHETIC_FIXTURE: "synthetic_fixture_review_queue",
    BC_TEMPLATE_ANALOGUE: "template_analogue_provenance_queue",
}

# Tier thresholds for routing decisions
# tier-1 and tier-2 = strong evidence (hunting-eligible)
# tier-3 = advisory only (synthetic/taxonomy-anchored)
# tier-4 = bundled fixture = blocked (synthetic_fixture_only)
# tier-5 or missing = blocked (weak_tier)
STRONG_TIERS = frozenset({
    "tier-1-verified-realtime-api",
    "tier-1-officially-disclosed",
    "tier-2-verified-public-archive",
})
ADVISORY_TIERS = frozenset({
    "tier-3-synthetic-taxonomy-anchored",
})
FIXTURE_TIER = "tier-4-bundled-fixture"
QUARANTINE_TIER = "tier-5-quarantine"

# Low-confidence threshold for source_extraction_confidence
CONFIDENCE_FLOOR = 0.5

# cap example rows per work queue in output
MAX_ROWS_PER_QUEUE = 20

# Attack class taxonomy path (pre-built by hackerman-attack-class-distribution.py)
TAXONOMY_PATH = REPO_ROOT / "audit" / "corpus_tags" / "derived" / "attack_class_taxonomy.json"

# Known dark audit-firm report attack/bug classes (index-level only, no per-finding extraction)
DARK_AUDIT_FIRM_BUG_CLASSES = frozenset({
    "audit-firm-public-report-index",
    "audit-firm-public-report",
})
DARK_AUDIT_FIRM_ATTACK_CLASSES = frozenset({
    "audit-firm-public-report",
})

# Sentinel year for "unknown" - corpus_mined uses year=2000 as placeholder
UNKNOWN_YEAR_SENTINELS = frozenset({0, 2000, 1970})

# Synthetic/template provenance markers
SYNTHETIC_PROVENANCE_MARKERS = frozenset({
    "dsl_pattern_synthesis",
    "template-expansion",
    "synthetic-taxonomy",
    "corpus-etl-synthetic",
})

# Solodit-spec draft pattern in record_id / source_audit_ref
SOLODIT_DRAFT_PATTERNS = ("solodit-spec:drafts", "solodit-spec:m-")


# ---------------------------------------------------------------------------
# YAML loading (mirrors hackerman_query_common.py approach)
# ---------------------------------------------------------------------------

def _yaml_load(text: str) -> Any:
    try:
        import yaml  # type: ignore
        return yaml.safe_load(text)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Taxonomy loader (optional; graceful fallback)
# ---------------------------------------------------------------------------

def _load_orphan_classes() -> frozenset[str]:
    """Return set of orphan attack_class values (single subtree or <20 records)."""
    if not TAXONOMY_PATH.exists():
        return frozenset()
    try:
        data = json.loads(TAXONOMY_PATH.read_text(encoding="utf-8"))
        classes: list[dict] = data.get("classes", [])
        orphans: set[str] = set()
        for entry in classes:
            cls = entry.get("attack_class", "")
            subtrees = entry.get("subtrees", [])
            total = entry.get("total_records", 0)
            if len(subtrees) <= 1 or total < 20:
                orphans.add(cls)
        return frozenset(orphans)
    except Exception:
        return frozenset()


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------

def _should_skip_path(path: Path) -> bool:
    sp = str(path)
    for prefix in EXCLUDED_SUBTREE_PREFIXES:
        if f"/{prefix}" in sp or f"\\{prefix}" in sp:
            return True
    return False


def _is_hackerman_record(doc: Any) -> bool:
    return isinstance(doc, dict) and doc.get("schema_version") in ACCEPTED_SCHEMAS


def _as_text(value: Any) -> str:
    return str(value or "").strip()


# ---------------------------------------------------------------------------
# Classification logic
# ---------------------------------------------------------------------------

def _effective_verification_tier(record: dict) -> str:
    """Extract verification_tier from record, with shape_tags fallback."""
    # First-class field (v1.1 schema)
    vt = _as_text(record.get("verification_tier"))
    if vt:
        return vt
    # Legacy: smuggled into shape_tags (v1 schema anti-pattern, R37)
    shape = record.get("function_shape") or {}
    tags: list = shape.get("shape_tags") or []
    for tag in tags:
        if isinstance(tag, str) and tag.startswith("verification_tier:"):
            return tag.split(":", 1)[1].strip()
    return ""


def _classify_record(
    record: dict,
    record_id: str,
    orphan_classes: frozenset[str],
) -> tuple[str, str, str]:
    """Classify one record.

    Returns (bucket, blocked_class_or_empty, work_queue_or_empty).
    """
    # --- Guard 1: dark audit-firm public report (index-level only, no extraction) ---
    bug_class = _as_text(record.get("bug_class"))
    attack_class = _as_text(record.get("attack_class"))
    if bug_class in DARK_AUDIT_FIRM_BUG_CLASSES or attack_class in DARK_AUDIT_FIRM_ATTACK_CLASSES:
        return BUCKET_BLOCKED, BC_DARK_AUDIT_FIRM, WORK_QUEUES[BC_DARK_AUDIT_FIRM]

    # --- Guard 2: tier-5 quarantine -> blocked (weak tier) ---
    vt = _effective_verification_tier(record)
    if vt == QUARANTINE_TIER:
        return BUCKET_BLOCKED, BC_WEAK_TIER, WORK_QUEUES[BC_WEAK_TIER]

    # --- Guard 3: tier-4 bundled fixture -> blocked (synthetic_fixture_only) ---
    extraction_method = _as_text(record.get("source_extraction_method"))
    extraction_provenance = _as_text(record.get("extraction_provenance"))
    if vt == FIXTURE_TIER:
        return BUCKET_BLOCKED, BC_SYNTHETIC_FIXTURE, WORK_QUEUES[BC_SYNTHETIC_FIXTURE]

    # --- Guard 4: synthetic fixture / template analogue (DSL pattern records) ---
    if extraction_provenance in SYNTHETIC_PROVENANCE_MARKERS:
        return BUCKET_BLOCKED, BC_SYNTHETIC_FIXTURE, WORK_QUEUES[BC_SYNTHETIC_FIXTURE]

    # --- Guard 5: template analogue with no mined-source provenance ---
    # Detected by: extraction_method == "corpus-etl-synthetic" or
    # source_audit_ref starts with "corpus-mined:" AND has no real repo
    source_ref = _as_text(record.get("source_audit_ref"))
    target_repo = _as_text(record.get("target_repo"))
    if source_ref.startswith("corpus-mined:") and (
        target_repo in ("unknown", "unknown/unknown", "")
    ):
        return BUCKET_BLOCKED, BC_TEMPLATE_ANALOGUE, WORK_QUEUES[BC_TEMPLATE_ANALOGUE]

    # --- Guard 6: low-confidence prose-to-spec drafts ---
    confidence = record.get("source_extraction_confidence")
    is_solodit_draft = any(record_id.startswith(p) for p in SOLODIT_DRAFT_PATTERNS) or \
                       any(source_ref.startswith(p) for p in SOLODIT_DRAFT_PATTERNS)
    if confidence is not None:
        try:
            conf_val = float(confidence)
            if conf_val < CONFIDENCE_FLOOR:
                return BUCKET_BLOCKED, BC_LOW_CONFIDENCE_PROSE, WORK_QUEUES[BC_LOW_CONFIDENCE_PROSE]
        except (TypeError, ValueError):
            pass

    # --- Guard 7: missing or weak verification tier ---
    if not vt:
        return BUCKET_BLOCKED, BC_WEAK_TIER, WORK_QUEUES[BC_WEAK_TIER]

    # --- Guard 8: unknown year + no source date (Solodit rows + corpus-mined year=2000) ---
    year = record.get("year")
    try:
        year_int = int(year) if year is not None else 0
    except (TypeError, ValueError):
        year_int = 0
    year_unknown = year_int in UNKNOWN_YEAR_SENTINELS or year_int == 0
    # "unknown-year Solodit rows without source dates" from the plan
    if year_unknown:
        source_url = _as_text(record.get("record_source_url"))
        # No external corroboration if year unknown and no source URL
        if not source_url:
            return BUCKET_BLOCKED, BC_UNKNOWN_YEAR, WORK_QUEUES[BC_UNKNOWN_YEAR]

    # --- Guard 9: stale external source-state ---
    # Identified by: shape_tags contains "state-pre-fix" AND no post-fix equivalent noted
    shape = record.get("function_shape") or {}
    shape_tags: list = shape.get("shape_tags") or []
    tag_str = " ".join(str(t) for t in shape_tags)
    if "state-pre-fix" in tag_str and "state-post-fix" not in tag_str:
        # Pre-fix records are stale source-state; advisory at best, blocked if no URL
        source_url = _as_text(record.get("record_source_url"))
        if not source_url:
            return BUCKET_BLOCKED, BC_STALE_SOURCE, WORK_QUEUES[BC_STALE_SOURCE]

    # --- Guard 10: orphan attack class ---
    if attack_class and orphan_classes and attack_class in orphan_classes:
        # Orphan does not block outright - but downgrades to advisory unless tier-1
        if vt not in ("tier-1-verified-realtime-api", "tier-1-officially-disclosed"):
            # Only block if also low-confidence (not enough signal)
            if is_solodit_draft or vt in ("tier-3-synthetic-taxonomy-anchored", ""):
                return BUCKET_BLOCKED, BC_ORPHAN_ATTACK, WORK_QUEUES[BC_ORPHAN_ATTACK]
            # Otherwise advisory
            return BUCKET_ADVISORY, "", ""

    # --- Bucket assignment by tier ---
    if vt in STRONG_TIERS:
        # Check missing proof_artifact_path for submission-derived / filed records
        # (Only required for high-provenance tiers where proof binding matters most)
        record_tier = _as_text(record.get("record_tier"))
        if record_tier in ("submission-derived", "dydx-filed", "mezo-filed", "local-workspace"):
            proof_path = _as_text(record.get("proof_artifact_path"))
            if not proof_path:
                return BUCKET_BLOCKED, BC_MISSING_PROOF, WORK_QUEUES[BC_MISSING_PROOF]
        return BUCKET_USABLE, "", ""

    if vt in ADVISORY_TIERS:
        return BUCKET_ADVISORY, "", ""

    # Fallback: if tier is unrecognized string (not quarantine/fixture/strong/advisory)
    # treat as advisory rather than crashing
    if vt:
        return BUCKET_ADVISORY, "", ""

    # Should not reach here after Guard 7, but be defensive
    return BUCKET_BLOCKED, BC_WEAK_TIER, WORK_QUEUES[BC_WEAK_TIER]


# ---------------------------------------------------------------------------
# Corpus iterator
# ---------------------------------------------------------------------------

def iter_records(
    tag_dir: Path,
    subtrees: list[str] | None = None,
    limit: int | None = None,
):
    """Yield (path, record_id, record_dict) for hackerman records."""
    count = 0
    if subtrees:
        # Only scan requested subtrees
        search_dirs = []
        for st in subtrees:
            candidate = tag_dir / st
            if candidate.is_dir():
                search_dirs.append(candidate)
        if not search_dirs:
            return
        for search_dir in search_dirs:
            for path in sorted(search_dir.rglob("*.yaml")):
                if _should_skip_path(path):
                    continue
                if limit is not None and count >= limit:
                    return
                doc = _load_file(path)
                if doc is not None:
                    yield path, _as_text(doc.get("record_id", path.stem)), doc
                    count += 1
    else:
        for path in sorted(tag_dir.rglob("*.yaml")):
            if _should_skip_path(path):
                continue
            if limit is not None and count >= limit:
                return
            doc = _load_file(path)
            if doc is not None:
                yield path, _as_text(doc.get("record_id", path.stem)), doc
                count += 1


def _load_file(path: Path) -> dict | None:
    """Load a YAML file; return dict if it's a hackerman record, else None."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        doc = _yaml_load(text)
        if not _is_hackerman_record(doc):
            return None
        return doc
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Main scan
# ---------------------------------------------------------------------------

def run_scan(
    tag_dir: Path,
    subtrees: list[str] | None = None,
    limit: int | None = None,
) -> dict:
    """Scan corpus and return routing report dict."""
    orphan_classes = _load_orphan_classes()

    # Counters
    bucket_counts: dict[str, int] = {
        BUCKET_USABLE: 0,
        BUCKET_ADVISORY: 0,
        BUCKET_BLOCKED: 0,
    }
    blocked_class_counts: dict[str, int] = {bc: 0 for bc in WORK_QUEUES}
    # work_queue rows (capped)
    work_queue_rows: dict[str, list[str]] = {q: [] for q in set(WORK_QUEUES.values())}
    work_queue_totals: dict[str, int] = {q: 0 for q in set(WORK_QUEUES.values())}

    total_scanned = 0
    malformed = 0
    # Phase 1: report per-schema-version counts so a v1.2 drop cannot be hidden.
    schema_version_counts: dict[str, int] = {}

    for path, record_id, record in iter_records(tag_dir, subtrees=subtrees, limit=limit):
        total_scanned += 1
        sv = _as_text(record.get("schema_version"))
        schema_version_counts[sv] = schema_version_counts.get(sv, 0) + 1
        try:
            bucket, bc, wq = _classify_record(record, record_id, orphan_classes)
        except Exception:
            # Defensive: malformed record -> blocked/low_confidence_prose
            bucket = BUCKET_BLOCKED
            bc = BC_LOW_CONFIDENCE_PROSE
            wq = WORK_QUEUES[BC_LOW_CONFIDENCE_PROSE]
            malformed += 1

        bucket_counts[bucket] += 1
        if bc:
            blocked_class_counts[bc] = blocked_class_counts.get(bc, 0) + 1
        if wq:
            work_queue_totals[wq] = work_queue_totals.get(wq, 0) + 1
            if len(work_queue_rows[wq]) < MAX_ROWS_PER_QUEUE:
                work_queue_rows[wq].append(record_id)

    # Build work_queue section: only queues with entries
    queues_out: list[dict] = []
    for blocked_cls, queue_name in sorted(WORK_QUEUES.items()):
        total = work_queue_totals.get(queue_name, 0)
        if total == 0:
            continue
        queues_out.append({
            "work_queue": queue_name,
            "blocked_class": blocked_cls,
            "total_rows": total,
            "example_rows_capped_at": MAX_ROWS_PER_QUEUE,
            "example_rows": work_queue_rows.get(queue_name, []),
        })

    return {
        "schema": SCHEMA_ID,
        "summary": {
            "total_records_scanned": total_scanned,
            "malformed_routed_to_blocked": malformed,
            "taxonomy_orphan_classes_loaded": len(orphan_classes),
        },
        "schema_version_counts": schema_version_counts,
        "bucket_counts": bucket_counts,
        "blocked_class_counts": {
            k: v for k, v in blocked_class_counts.items() if v > 0
        },
        "work_queues": queues_out,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="J3 full-corpus quality routing: classify corpus rows into hunting/advisory/blocked buckets."
    )
    p.add_argument(
        "--tags-dir",
        default=str(DEFAULT_TAGS_DIR),
        help="Path to audit/corpus_tags/tags/ directory (default: repo-relative).",
    )
    p.add_argument(
        "--subtrees",
        default=None,
        help="Comma-separated list of top-level subtree names to scan (default: all).",
    )
    p.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Max records to scan (for fast testing).",
    )
    p.add_argument(
        "--json",
        dest="json_output",
        action="store_true",
        help="Emit JSON report instead of human-readable summary.",
    )
    return p.parse_args(argv)


def _human_report(report: dict) -> None:
    summary = report["summary"]
    counts = report["bucket_counts"]
    blocked = report["blocked_class_counts"]
    queues = report["work_queues"]

    print(f"Corpus Quality Routing Report  [{SCHEMA_ID}]")
    print(f"  Records scanned : {summary['total_records_scanned']}")
    print(f"  Malformed       : {summary['malformed_routed_to_blocked']}")
    print(f"  Orphan classes  : {summary['taxonomy_orphan_classes_loaded']}")
    print()
    print("Bucket counts:")
    print(f"  usable_for_hunting    : {counts.get(BUCKET_USABLE, 0)}")
    print(f"  advisory_context_only : {counts.get(BUCKET_ADVISORY, 0)}")
    print(f"  blocked               : {counts.get(BUCKET_BLOCKED, 0)}")
    print()
    svc = report.get("schema_version_counts") or {}
    if svc:
        print("Schema-version counts:")
        for sv, cnt in sorted(svc.items(), key=lambda x: -x[1]):
            print(f"  {sv or '(none)':<45} : {cnt}")
        print()
    if blocked:
        print("Blocked class breakdown:")
        for bc, cnt in sorted(blocked.items(), key=lambda x: -x[1]):
            print(f"  {bc:<50} : {cnt}")
        print()
    if queues:
        print("Work queues:")
        for q in queues:
            print(f"  {q['work_queue']} ({q['blocked_class']}) -> {q['total_rows']} rows")


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    tag_dir = Path(args.tags_dir)
    if not tag_dir.exists():
        print(f"ERROR: tags dir not found: {tag_dir}", file=sys.stderr)
        return 1

    subtrees = [s.strip() for s in args.subtrees.split(",")] if args.subtrees else None

    report = run_scan(tag_dir, subtrees=subtrees, limit=args.limit)

    if args.json_output:
        print(json.dumps(report, indent=2))
    else:
        _human_report(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
