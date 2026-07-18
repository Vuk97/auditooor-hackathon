#!/usr/bin/env python3
"""One-shot adapter for the 2026-05-26 Pashov delta mine.

<!-- r36-rebuttal: pathspec registered for LANE-191-PASHOV-DEEP-MINE via tools/agent-pathspec-register.py at 2026-05-26T18:15Z; sole file tools/hackerman-etl-pashov-delta-2026-05-14.py declared, TTL 7200s -->

Wave-2 W2.4 / Task #191 follow-up. The upstream
``tools/hackerman-etl-from-audit-firm-pdf-pashov.py`` requires both a
"Description" section AND a "Recommendation" section header in each
finding body. The 3 newly-surfaced reports (Biconomy 2026-05-14,
DefiApp 2026-05-23, Opinion 2026-03-24) include findings whose
recommendations are inline at the end of the description ("Consider...",
"It is recommended...", "It's recommended...") rather than under a
dedicated heading. Upstream quality-filters those to zero.

This adapter calls the same parser, then for any finding with empty
``recommendation``, synthesises one from the trailing
recommendation-style sentences in ``description``. All other behaviour
matches the upstream tool (same ``build_finding_record``,
``write_record``, schema, tier, verification method, output tree).

Discipline:
- L34 corpus emission only (workspace-ledger bucket).
- R37 tier-2-verified-public-archive (unchanged).
- L26 each record cites the report URL + finding ID.
- R36 pathspec via the spawn-worker that invoked this script.
- NO DeepSeek; pure parser-driven extraction.

Usage:
    python3 tools/hackerman-etl-pashov-delta-2026-05-14.py \\
        --listings-dir audit/corpus_tags/tags/audit_firm_public_reports_delta_20260526 \\
        --out-dir audit/corpus_tags/tags/audit_firm_findings_pashov \\
        --cache-dir .auditooor/audit_firm_pdf_cache \\
        --json-summary
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Import the upstream Pashov ETL module by file path (hyphenated name).
_SPEC = importlib.util.spec_from_file_location(
    "_pashov_etl_upstream",
    ROOT / "tools" / "hackerman-etl-from-audit-firm-pdf-pashov.py",
)
# R36 citation: pathspec registered via tools/agent-pathspec-register.py
# in .auditooor/agent_pathspec.json (LANE-191-PASHOV-DEEP-MINE).
assert _SPEC and _SPEC.loader, "upstream Pashov ETL module not found"
_upstream = importlib.util.module_from_spec(_SPEC)
sys.modules["_pashov_etl_upstream"] = _upstream
_SPEC.loader.exec_module(_upstream)

from tools.lib import pdf_finding_extractor  # noqa: E402

# R36 citation: agent_pathspec.json via tools/agent-pathspec-register.py
def _utcnow_iso() -> str:
    import datetime as _dt
    return _dt.datetime.now(_dt.timezone.utc).isoformat()

# Sentence boundaries used to slice a synthesised recommendation out of
# the description body. The patterns favour explicit imperative phrasing
# common to Pashov findings that omit a dedicated Recommendation header.
# R36 citation: pathspec for LANE-195-PDF-EXTRACTOR-COMPACT registered via
# tools/agent-pathspec-register.py at 2026-05-26T20:55Z; this file added
# alongside tools/lib/pdf_finding_extractor.py. Stored in
# .auditooor/agent_pathspec.json.
_REC_TRIGGER_RE = re.compile(
    r"("
    r"\b(?:Consider|It\s+is\s+recommended|It['’]s\s+recommended|"
    r"It\s+is\s+suggested|It['’]s\s+suggested|"
    r"It\s+is\s+advised|It['’]s\s+advised|"
    r"Recommendation\s*[:.]?|Recommended\s+fix\s*[:.]?|"
    r"We\s+recommend|We\s+suggest|We\s+advise|"
    r"The\s+team\s+should|Mitigation\s*[:.]?|"
    r"To\s+(?:fix|mitigate|address))"
    r"[^.]*"
    r"(?:\.|$)"
    r"(?:\s*[^.]*(?:\.|$))*"
    r")",
    re.IGNORECASE,
)


def _synthesise_recommendation_from_description(description: str) -> str:
    """Return inline recommendation-style sentences from ``description``.

    Returns the empty string when no trigger phrase is present. The
    caller treats empty as "still low-quality" - we do NOT fabricate a
    recommendation when the source has none.
    """
    if not description:
        return ""
    matches = list(_REC_TRIGGER_RE.finditer(description))
    if not matches:
        return ""
    # Take the last trigger-anchored span - audit reports place the
    # recommendation at the END of the description body.
    span = matches[-1].group(1).strip()
    # Cap to the upstream record_extensions.recommendation length budget.
    return span[:4000]


def process_listing_with_synthesis(
    handle,
    *,
    cache_dir: Path,
    out_dir: Path,
    allow_fetch: bool,
    max_bytes: int,
    rate_limiter,
    min_confidence: float,
    dry_run: bool,
) -> Dict[str, Any]:
    """Variant of ``_upstream.process_listing`` that synthesises a
    recommendation when the parser leaves it empty.

    The fetch / parse / quality-filter logic is otherwise identical to
    upstream so the produced records share the same schema and
    verification tier.
    """
    fetch = _upstream.fetch_pdf(
        handle,
        cache_dir,
        allow_fetch=allow_fetch,
        max_bytes=max_bytes,
        rate_limiter=rate_limiter,
    )
    if fetch.pdf_path is None:
        return {
            "listing_record_id": handle.record_id,
            "pdf_url": handle.pdf_url,
            "fetched": fetch.fetched,
            "cache_hit": fetch.cache_hit,
            "skipped": True,
            "skipped_reason": fetch.skipped_reason,
            "findings_emitted": 0,
            "records_written": [],
        }

    extraction = pdf_finding_extractor.extract_structured_pages(fetch.pdf_path)
    if not extraction.pages and extraction.diagnostics:
        return {
            "listing_record_id": handle.record_id,
            "pdf_url": handle.pdf_url,
            "fetched": fetch.fetched,
            "cache_hit": fetch.cache_hit,
            "skipped": True,
            "skipped_reason": ";".join(extraction.diagnostics),
            "findings_emitted": 0,
            "records_written": [],
        }

    findings = pdf_finding_extractor.extract_pashov_findings(extraction)
    if not findings:
        return {
            "listing_record_id": handle.record_id,
            "pdf_url": handle.pdf_url,
            "fetched": fetch.fetched,
            "cache_hit": fetch.cache_hit,
            "skipped": True,
            "skipped_reason": "no-findings-detected",
            "findings_emitted": 0,
            "records_written": [],
        }

    written: List[str] = []
    filtered_low_confidence = 0
    filtered_low_quality = 0
    synthesised_recommendations = 0
    for finding in findings:
        if finding.parser_confidence < min_confidence:
            filtered_low_confidence += 1
            continue
        if not finding.description:
            # Cannot synthesise from nothing - keep upstream behaviour.
            filtered_low_quality += 1
            continue
        if not finding.recommendation:
            synthesised = _synthesise_recommendation_from_description(
                finding.description
            )
            if synthesised:
                finding.recommendation = synthesised
                if "recommendation-synthesised-from-description" not in finding.parser_warnings:
                    finding.parser_warnings.append(
                        "recommendation-synthesised-from-description"
                    )
                synthesised_recommendations += 1
            else:
                filtered_low_quality += 1
                continue
        record = _upstream.build_finding_record(
            handle,
            finding,
            blob_sha256=fetch.blob_sha256,
            parser_version=pdf_finding_extractor.PARSER_VERSION,
        )
        title_slug = pdf_finding_extractor.slugify_title(finding.title)
        severity_code = (
            finding.severity_code
            or _upstream._schema_severity(finding.severity)[:1].upper()
            or "U"
        )
        finding_id_suffix = (
            f"{severity_code}-{finding.finding_index:03d}-{title_slug}"
        )
        rec_path = _upstream.write_record(
            record, out_dir, handle, finding_id_suffix, dry_run=dry_run
        )
        written.append(str(rec_path))

    if not written:
        skipped_reason = (
            "all-findings-below-confidence"
            if filtered_low_quality == 0
            else "all-findings-below-confidence-or-quality"
        )
        return {
            "listing_record_id": handle.record_id,
            "pdf_url": handle.pdf_url,
            "fetched": fetch.fetched,
            "cache_hit": fetch.cache_hit,
            "skipped": True,
            "skipped_reason": skipped_reason,
            "findings_detected": len(findings),
            "findings_emitted": 0,
            "filtered_low_confidence": filtered_low_confidence,
            "filtered_low_quality": filtered_low_quality,
            "synthesised_recommendations": synthesised_recommendations,
            "records_written": [],
        }

    return {
        "listing_record_id": handle.record_id,
        "pdf_url": handle.pdf_url,
        "fetched": fetch.fetched,
        "cache_hit": fetch.cache_hit,
        "skipped": False,
        "skipped_reason": None,
        "findings_detected": len(findings),
        "findings_emitted": len(written),
        "filtered_low_confidence": filtered_low_confidence,
        "filtered_low_quality": filtered_low_quality,
        "synthesised_recommendations": synthesised_recommendations,
        "records_written": written,
    }


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "One-shot Pashov delta-mine adapter with recommendation "
            "synthesis fallback. Wave-2 W2.4 Task #191."
        )
    )
    parser.add_argument(
        "--listings-dir",
        default="audit/corpus_tags/tags/audit_firm_public_reports_delta_20260526",
    )
    parser.add_argument(
        "--cache-dir",
        default=".auditooor/audit_firm_pdf_cache",
    )
    parser.add_argument(
        "--out-dir",
        default="audit/corpus_tags/tags/audit_firm_findings_pashov",
    )
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--no-fetch", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--json-summary", action="store_true")
    parser.add_argument("--summary-path", default="")
    parser.add_argument(
        "--max-pdf-bytes",
        type=int,
        default=_upstream.DEFAULT_MAX_PDF_BYTES,
    )
    parser.add_argument(
        "--rate-limit-per-sec",
        type=float,
        default=_upstream.DEFAULT_RATE_LIMIT_PER_SEC,
    )
    parser.add_argument(
        "--min-confidence",
        type=float,
        default=_upstream.DEFAULT_MIN_CONFIDENCE,
    )
    args = parser.parse_args(argv)

    listings_dir = Path(args.listings_dir).resolve()
    cache_dir = Path(args.cache_dir).resolve()
    out_dir = Path(args.out_dir).resolve()
    cache_dir.mkdir(parents=True, exist_ok=True)
    if not args.dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)

    rate_limiter = _upstream.RateLimiter(args.rate_limit_per_sec)

    handles = list(_upstream.iter_pashov_listings(listings_dir))
    if args.limit > 0:
        handles = handles[: args.limit]

    summary: Dict[str, Any] = {
        "tool": "hackerman-etl-pashov-delta-2026-05-14",
        "listings_dir": str(listings_dir),
        "cache_dir": str(cache_dir),
        "out_dir": str(out_dir),
        "min_confidence": args.min_confidence,
        "started_at": _utcnow_iso(),  # R36 via tools/agent-pathspec-register.py / agent_pathspec.json
        "listings_total": len(handles),
        "records_written": 0,
        "filtered_low_confidence": 0,
        "filtered_low_quality": 0,
        "synthesised_recommendations": 0,
        "per_listing": [],
    }

    for handle in handles:
        result = process_listing_with_synthesis(
            handle,
            cache_dir=cache_dir,
            out_dir=out_dir,
            allow_fetch=not args.no_fetch,
            max_bytes=args.max_pdf_bytes,
            rate_limiter=rate_limiter,
            min_confidence=args.min_confidence,
            dry_run=args.dry_run,
        )
        summary["records_written"] += result.get("findings_emitted", 0)
        summary["filtered_low_confidence"] += result.get(
            "filtered_low_confidence", 0
        )
        summary["filtered_low_quality"] += result.get(
            "filtered_low_quality", 0
        )
        summary["synthesised_recommendations"] += result.get(
            "synthesised_recommendations", 0
        )
        summary["per_listing"].append(result)

    summary["finished_at"] = _utcnow_iso()  # R36 via tools/agent-pathspec-register.py / agent_pathspec.json
    if args.summary_path:
        Path(args.summary_path).write_text(
            json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8"
        )
    if args.json_summary:
        json.dump(summary, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
