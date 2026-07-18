#!/usr/bin/env python3
"""analogue-provenance.py -- J3c: Evidence-aware analogue provenance enrichment.

Reads cross_language_analogues.jsonl and, for each row, derives/attaches
provenance fields sourced from the exploit_predicates sidecar and attack_class
taxonomy:

  source_record_tier    - verification_tier of the source corpus record
                          (mapped from record_tier in exploit_predicates)
  source_proof_available - bool: does the source record carry a non-empty
                           source_audit_ref (treated as proof anchor presence)
  analogue_origin       - "mined_report" | "template_expansion"
                          derived from source_record_id prefix:
                            corpus-mined / corpus-txt -> mined_report
                            critical: / submission-derived / dsl_* -> mined_report
                            template_* / missing prefix -> template_expansion
  target_language       - forwarded from the analogue row (already present)
  analogue_confidence   - bounded float [0.0, 1.0] forwarded from row

Usage-class verdict per analogue (J3c acceptance rule):
  usable_hacker_question   - any analogue, always available as a hacker question
  usable_detector_seed     - analogue with mined_report origin
  blocked_no_provenance    - analogue with template_expansion origin AND
                             source_record_tier is tier-3 or tier-4 or missing

Severity upgrade gate (J3c acceptance rule):
  cannot_upgrade_severity_or_proof - set True when analogue lacks
                                     mined-source/proof provenance.
                                     Defined as: origin != mined_report
                                     OR source_record_tier in
                                     {tier-3-synthetic-taxonomy-anchored,
                                      tier-4-bundled-fixture, tier-5-quarantine,
                                      None}

Writes an enriched provenance sidecar JSONL to:
  audit/corpus_tags/derived/analogue_provenance.jsonl   (default)
or to the path given by --out.

Emits a JSON summary (schema auditooor.analogue_provenance.v1) with --json.

Strict mode (--strict): exits non-zero if any analogue row is marked
  cannot_upgrade_severity_or_proof=True but was not already flagged blocked.

# Rule 37: this tool emits at tier-3-synthetic-taxonomy-anchored for
# provenance-derived output rows (they carry forward source tier data but
# are themselves metadata, not primary source records).
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

SCHEMA = "auditooor.analogue_provenance.v1"
VERSION = "1.0.0"

REPO_ROOT = Path(__file__).resolve().parents[1]

DEFAULT_ANALOGUE_PATH = (
    REPO_ROOT / "audit" / "corpus_tags" / "derived" / "cross_language_analogues.jsonl"
)
DEFAULT_PREDICATES_PATH = (
    REPO_ROOT / "audit" / "corpus_tags" / "derived" / "exploit_predicates.jsonl"
)
DEFAULT_TAXONOMY_PATH = (
    REPO_ROOT / "audit" / "corpus_tags" / "derived" / "attack_class_taxonomy.json"
)
DEFAULT_OUT_PATH = (
    REPO_ROOT / "audit" / "corpus_tags" / "derived" / "analogue_provenance.jsonl"
)

# record_tier values (from exploit_predicates) -> canonical verification_tier label
_RECORD_TIER_MAP: dict[str, str] = {
    "public-corpus": "tier-2-verified-public-archive",
    "submission-derived": "tier-1-verified-realtime-api",
    "tier-1-ghsa-cache": "tier-1-officially-disclosed",
    "tier-1-verified-realtime-api": "tier-1-verified-realtime-api",
    "tier-1-officially-disclosed": "tier-1-officially-disclosed",
    "tier-2-verified-public-archive": "tier-2-verified-public-archive",
    "tier-3-synthetic-taxonomy-anchored": "tier-3-synthetic-taxonomy-anchored",
    "tier-4-bundled-fixture": "tier-4-bundled-fixture",
    "tier-5-quarantine": "tier-5-quarantine",
}

# Tiers that block severity/proof upgrade
_WEAK_TIERS = frozenset(
    {
        "tier-3-synthetic-taxonomy-anchored",
        "tier-4-bundled-fixture",
        "tier-5-quarantine",
        None,
        "",
    }
)

# Source-record-id prefixes that indicate a mined report (not template expansion)
_MINED_PREFIXES = frozenset(
    {
        "corpus-mined",
        "corpus-txt",
        "critical",
        "high",
        "medium",
        "low",
        "submission-derived",
        "solodit",
        "rekt",
        "darknavy",
        "pashov",
    }
)


# ---------------------------------------------------------------------------
# Index builders
# ---------------------------------------------------------------------------


def _build_predicates_index(predicates_path: Path) -> dict[str, dict[str, Any]]:
    """Build record_id -> {record_tier, source_audit_ref, target_language} index."""
    index: dict[str, dict[str, Any]] = {}
    if not predicates_path.exists():
        return index
    try:
        with predicates_path.open(encoding="utf-8") as fh:
            for raw in fh:
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    row = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                rid = row.get("record_id", "")
                if rid:
                    index[rid] = {
                        "record_tier": row.get("record_tier") or row.get("verification_tier"),
                        "source_audit_ref": row.get("source_audit_ref", ""),
                        "target_language": row.get("target_language", ""),
                    }
    except OSError:
        pass
    return index


def _build_taxonomy_index(taxonomy_path: Path) -> dict[str, dict[str, Any]]:
    """Build attack_class -> {subtrees, total_records, tier12_count} index."""
    index: dict[str, dict[str, Any]] = {}
    if not taxonomy_path.exists():
        return index
    try:
        with taxonomy_path.open(encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return index
    for entry in data.get("classes", []):
        ac = entry.get("attack_class", "")
        if ac:
            index[ac] = {
                "subtrees": entry.get("subtrees", []),
                "total_records": entry.get("total_records", 0),
                "tier12_count": entry.get("tier12_count", 0),
            }
    return index


# ---------------------------------------------------------------------------
# Provenance derivation
# ---------------------------------------------------------------------------


def _derive_origin(source_record_id: str) -> str:
    """Return 'mined_report' or 'template_expansion' from source_record_id prefix."""
    if not source_record_id:
        return "template_expansion"
    prefix = source_record_id.split(":")[0].lower()
    if prefix in _MINED_PREFIXES:
        return "mined_report"
    # Template-style ids often lack colons or start with 'template'
    return "template_expansion"


def _normalize_confidence(raw: Any) -> float:
    """Clamp confidence to [0.0, 1.0]."""
    try:
        v = float(raw)
    except (TypeError, ValueError):
        return 0.0
    return max(0.0, min(1.0, v))


def _map_record_tier(raw_tier: str | None) -> str | None:
    """Normalize a raw record_tier string to canonical verification_tier."""
    if not raw_tier:
        return None
    return _RECORD_TIER_MAP.get(raw_tier, raw_tier)


def _is_orphan_class(attack_class: str, taxonomy_index: dict[str, dict[str, Any]]) -> bool:
    """Return True if attack_class has <2 subtrees or <20 total_records in taxonomy."""
    if not taxonomy_index:
        return False
    entry = taxonomy_index.get(attack_class)
    if entry is None:
        return True  # completely unknown class = orphan
    return len(entry.get("subtrees", [])) < 2 or entry.get("total_records", 0) < 20


def _canonical_family_suggestion(
    attack_class: str, taxonomy_index: dict[str, dict[str, Any]]
) -> str | None:
    """Suggest a canonical family for an orphan attack class via token matching."""
    # Simple heuristic: find the taxonomy class with the most token overlap
    if not taxonomy_index or not attack_class:
        return None
    tokens = set(attack_class.lower().replace("-", " ").split())
    best_class = None
    best_score = 0
    for cls, meta in taxonomy_index.items():
        if cls == attack_class:
            continue
        if meta.get("total_records", 0) < 20:
            continue
        cls_tokens = set(cls.lower().replace("-", " ").split())
        score = len(tokens & cls_tokens)
        if score > best_score:
            best_score = score
            best_class = cls
    return best_class if best_score > 0 else None


def _derive_provenance(
    row: dict[str, Any],
    predicates_index: dict[str, dict[str, Any]],
    taxonomy_index: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Derive all provenance fields for a single analogue row."""
    source_record_id = row.get("source_record_id", "")
    attack_class = row.get("attack_class", "")

    # --- source_record_tier ---
    pred_entry = predicates_index.get(source_record_id, {})
    raw_tier = pred_entry.get("record_tier")
    source_record_tier = _map_record_tier(raw_tier)

    # --- source_proof_available ---
    audit_ref = pred_entry.get("source_audit_ref", "")
    source_proof_available = bool(audit_ref and audit_ref.strip())

    # --- analogue_origin ---
    analogue_origin = _derive_origin(source_record_id)

    # --- target_language (forwarded, already in row) ---
    target_language = row.get("target_language", "")

    # --- analogue_confidence (bounded) ---
    analogue_confidence = _normalize_confidence(row.get("confidence"))

    # --- cannot_upgrade_severity_or_proof ---
    cannot_upgrade = (
        analogue_origin != "mined_report"
        or source_record_tier in _WEAK_TIERS
        or not source_proof_available
    )

    # --- usage_class verdict ---
    # All analogues are usable as hacker questions regardless of provenance
    # Detector seeds require mined_report origin
    # blocked_no_provenance: template_expansion AND weak tier
    if analogue_origin != "mined_report" and source_record_tier in _WEAK_TIERS:
        usage_class = "blocked_no_provenance"
    elif analogue_origin == "mined_report":
        usage_class = "usable_detector_seed"
    else:
        usage_class = "usable_hacker_question"

    # --- orphan class info ---
    is_orphan = _is_orphan_class(attack_class, taxonomy_index)
    canonical_family = None
    if is_orphan:
        canonical_family = _canonical_family_suggestion(attack_class, taxonomy_index)

    out: dict[str, Any] = {
        "analogue_record_id": row.get("analogue_record_id", ""),
        "source_record_id": source_record_id,
        "attack_class": attack_class,
        "source_language": row.get("source_language", ""),
        "target_language": target_language,
        "analogue_confidence": analogue_confidence,
        "source_record_tier": source_record_tier,
        "source_proof_available": source_proof_available,
        "analogue_origin": analogue_origin,
        "usage_class": usage_class,
        "cannot_upgrade_severity_or_proof": cannot_upgrade,
        "is_orphan_attack_class": is_orphan,
        "canonical_family_suggestion": canonical_family,
        "pattern_translation": row.get("pattern_translation", ""),
    }
    return out


# ---------------------------------------------------------------------------
# Main processing
# ---------------------------------------------------------------------------


def process(
    analogue_path: Path,
    predicates_path: Path,
    taxonomy_path: Path,
    out_path: Path | None,
    limit: int | None,
    json_mode: bool,
    strict: bool,
) -> int:
    """Main processing loop. Returns exit code."""

    # Resolve sharded layout: prefer manifest when it exists alongside the monolith path.
    manifest_path = analogue_path.with_name(f"{analogue_path.stem}.manifest.json")
    shard_paths: list[Path] = []
    if manifest_path.is_file():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except Exception:
            manifest = {}
        if isinstance(manifest, dict) and manifest.get("shard_dir"):
            shard_dir = analogue_path.parent / str(manifest["shard_dir"])
            shard_paths = [
                shard_dir / str(s.get("path") or "")
                for s in (manifest.get("shards") or [])
                if s.get("path")
            ]

    monolith_exists = analogue_path.exists() and analogue_path.stat().st_size > 0
    if not shard_paths and not monolith_exists:
        result = {
            "schema": SCHEMA,
            "version": VERSION,
            "status": "missing",
            "message": f"analogue file not found: {analogue_path}",
            "total_analogues": 0,
            "usage_class_counts": {},
            "cannot_upgrade_count": 0,
            "orphan_class_count": 0,
            "origin_counts": {},
            "tier_counts": {},
        }
        if json_mode:
            print(json.dumps(result, indent=2))
        else:
            print(f"[analogue-provenance] MISSING: {analogue_path}")
        return 0  # not an error - defensive

    # Build lookup indexes
    predicates_index = _build_predicates_index(predicates_path)
    taxonomy_index = _build_taxonomy_index(taxonomy_path)

    # Prepare output path
    if out_path is not None:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_fh = out_path.open("w", encoding="utf-8")
    else:
        out_fh = None

    usage_counter: Counter[str] = Counter()
    origin_counter: Counter[str] = Counter()
    tier_counter: Counter[str] = Counter()
    cannot_upgrade_count = 0
    orphan_count = 0
    total = 0
    strict_violation = False

    def _iter_analogue_rows(paths: list[Path], monolith: Path) -> Any:
        """Yield raw JSON line strings from shards (if present) or monolith."""
        if paths:
            for p in paths:
                if p.is_file():
                    with p.open(encoding="utf-8") as fh:
                        yield from fh
        elif monolith.exists():
            with monolith.open(encoding="utf-8") as fh:
                yield from fh

    try:
        for raw in _iter_analogue_rows(shard_paths, analogue_path):
                if limit is not None and total >= limit:
                    break
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    row = json.loads(raw)
                except json.JSONDecodeError:
                    continue

                prov = _derive_provenance(row, predicates_index, taxonomy_index)
                total += 1

                usage_counter[prov["usage_class"]] += 1
                origin_counter[prov["analogue_origin"]] += 1
                tier_counter[str(prov["source_record_tier"])] += 1

                if prov["cannot_upgrade_severity_or_proof"]:
                    cannot_upgrade_count += 1

                if prov["is_orphan_attack_class"]:
                    orphan_count += 1

                if strict and prov["cannot_upgrade_severity_or_proof"]:
                    strict_violation = True

                if out_fh is not None:
                    out_fh.write(json.dumps(prov) + "\n")
    finally:
        if out_fh is not None:
            out_fh.close()

    summary = {
        "schema": SCHEMA,
        "version": VERSION,
        "status": "ok",
        "total_analogues": total,
        "usage_class_counts": dict(usage_counter),
        "cannot_upgrade_count": cannot_upgrade_count,
        "orphan_class_count": orphan_count,
        "origin_counts": dict(origin_counter),
        "tier_counts": dict(tier_counter),
        "output_path": str(out_path) if out_path else None,
        "predicates_index_size": len(predicates_index),
        "taxonomy_index_size": len(taxonomy_index),
    }

    if json_mode:
        print(json.dumps(summary, indent=2))
    else:
        print(f"[analogue-provenance] processed {total} analogues")
        print(f"  usage_class: {dict(usage_counter)}")
        print(f"  origin: {dict(origin_counter)}")
        print(f"  cannot_upgrade: {cannot_upgrade_count}/{total}")
        print(f"  orphan_attack_classes: {orphan_count}/{total}")
        if out_path:
            print(f"  output: {out_path}")

    if strict and strict_violation:
        if not json_mode:
            print(
                f"[analogue-provenance] STRICT FAIL: {cannot_upgrade_count} analogue(s) "
                "cannot_upgrade_severity_or_proof=True",
                file=sys.stderr,
            )
        return 1

    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="J3c: Derive provenance fields for cross-language analogue rows.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--analogue-file",
        type=Path,
        default=DEFAULT_ANALOGUE_PATH,
        help="Path to cross_language_analogues.jsonl (default: derived sidecar)",
    )
    p.add_argument(
        "--predicates-file",
        type=Path,
        default=DEFAULT_PREDICATES_PATH,
        help="Path to exploit_predicates.jsonl for tier/proof lookups",
    )
    p.add_argument(
        "--taxonomy-file",
        type=Path,
        default=DEFAULT_TAXONOMY_PATH,
        help="Path to attack_class_taxonomy.json for orphan detection",
    )
    p.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUT_PATH,
        help="Output path for enriched provenance sidecar JSONL (use '-' for stdout-only)",
    )
    p.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Process at most N rows (for testing / bounded scan)",
    )
    p.add_argument(
        "--json",
        dest="json_mode",
        action="store_true",
        help="Emit JSON summary to stdout instead of human-readable output",
    )
    p.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero if any analogue cannot upgrade severity/proof",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    out_path: Path | None = args.out
    if str(out_path) == "-":
        out_path = None

    return process(
        analogue_path=args.analogue_file,
        predicates_path=args.predicates_file,
        taxonomy_path=args.taxonomy_file,
        out_path=out_path,
        limit=args.limit,
        json_mode=args.json_mode,
        strict=args.strict,
    )


if __name__ == "__main__":
    sys.exit(main())
