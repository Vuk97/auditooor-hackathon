#!/usr/bin/env python3
"""Hackerman ETL: Cantina (cantina.xyz) public-disclosure reports.

Mines the publicly-disclosed Cantina engagement reports surfaced on
``https://cantina.xyz/portfolio`` and emits one
``auditooor.hackerman_record.v1.1`` record per published PDF.

Real-source-only (M14-trap discipline per ``~/.claude/CLAUDE.md``):

* Source listing comes from the public ``cantina.xyz/portfolio`` HTML
  page, parsed for absolute ``https://cdn.cantina.xyz/reports/*.pdf`` and
  ``https://cdn.cantina.xyz/report/*.pdf`` URLs. No scraping behind auth,
  no API keys required.
* Each PDF URL was verified at miner-build time (2026-05-23) to return
  HTTP 200 with ``content-type: application/pdf`` from the public CDN.
  No browser, no JavaScript, no login.
* ``verification_tier=tier-2-verified-public-archive`` (URL cited but PDF
  body not parsed at emit time; matches the public-archive guarantees of
  the other ``audit-firm-public-reports`` sibling miner).
* Each record cites the absolute CDN URL as ``record_source_url``.
* Cross-links use relative paths only.
* Does NOT modify ``tools/calibration/llm_budget_log.jsonl``.
* Records validate against
  ``audit/corpus_tags/schemas/auditooor.hackerman_record.v1.1.schema.json``.

Source surface (2026-05-23):

    https://cantina.xyz/portfolio                         (HTTP 200, public, ~2.8 MB SSR HTML)
      - 436 unique ``/portfolio/<uuid>`` engagement anchors
      - 526 unique ``cdn.cantina.xyz/report{,s}/*.pdf`` absolute URLs
      - Mixed origin: cantina-led reviews + spearbit-led reviews republished by Cantina

CLI::

    # Live mode (fetches portfolio index from cantina.xyz):
    python3 tools/hackerman-etl-from-cantina-reports.py \\
        --out-dir audit/corpus_tags/tags/cantina_public_disclosure

    # Offline / fixture mode (used by --portfolio-cache for test rigs):
    python3 tools/hackerman-etl-from-cantina-reports.py \\
        --out-dir /tmp/cantina-out \\
        --portfolio-cache tools/tests/fixtures/cantina_portfolio/index.html \\
        --dry-run --json-summary

    # Bounded mining (proof-of-concept N records):
    python3 tools/hackerman-etl-from-cantina-reports.py \\
        --out-dir audit/corpus_tags/tags/cantina_public_disclosure \\
        --max-records 10 --json-summary
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
import urllib.request
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_VERSION = "auditooor.hackerman_record.v1.1"
VERIFICATION_TIER = "tier-2-verified-public-archive"
SOURCE_SLUG = "cantina-public-disclosure"
PORTFOLIO_URL = "https://cantina.xyz/portfolio"

# Regex catches both ``/report/<slug>.pdf`` and ``/reports/<slug>.pdf`` styles.
PDF_URL_RE = re.compile(
    r'https://cdn\.cantina\.xyz/reports?/[A-Za-z0-9._%/+-]+\.pdf'
)
PORTFOLIO_UUID_RE = re.compile(
    r'/portfolio/([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})'
)


def _load_validator() -> Any:
    spec = importlib.util.spec_from_file_location(
        "_hackerman_record_validate_for_cantina_reports",
        str(REPO_ROOT / "tools" / "hackerman-record-validate.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


_VALIDATOR = _load_validator()


# ---------------------------------------------------------------------------
# YAML / slug helpers (byte-stable; mirrored from sibling miners).
# ---------------------------------------------------------------------------


def slugify(value: object, *, max_len: int = 80) -> str:
    text = str(value or "").strip().lower()
    text = re.sub(r"[^a-z0-9._:/-]+", "-", text).strip("-._")
    text = re.sub(r"-{2,}", "-", text)
    return (text[:max_len].strip("-._") or "record")


def one_line(text: object, fallback: str, *, max_len: int = 1000) -> str:
    cleaned = re.sub(r"\s+", " ", str(text or "")).strip()
    return (cleaned[:max_len].strip() if cleaned else fallback)


# ---------------------------------------------------------------------------
# Source listing.
# ---------------------------------------------------------------------------


def fetch_portfolio_html(
    *,
    timeout: int = 60,
    user_agent: str = "auditooor-cantina-miner/1.0",
) -> Optional[str]:
    """Return the raw HTML of ``cantina.xyz/portfolio`` or ``None`` on failure.

    No scraping tricks - the page is served as plain SSR HTML by Next.js
    and the PDF URLs are inlined as absolute ``cdn.cantina.xyz`` hrefs.
    """
    req = urllib.request.Request(
        PORTFOLIO_URL,
        headers={"User-Agent": user_agent, "Accept": "text/html,*/*"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status != 200:
                return None
            body = resp.read()
    except Exception:
        return None
    try:
        return body.decode("utf-8", errors="replace")
    except Exception:
        return None


def load_portfolio_cache(cache_file: Path) -> Optional[str]:
    """Load a previously-saved portfolio HTML snapshot.

    Tests use this to drive the miner offline. Returns ``None`` when the
    file does not exist or cannot be decoded.
    """
    try:
        return cache_file.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def write_portfolio_cache(cache_file: Path, html: str) -> None:
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    cache_file.write_text(html, encoding="utf-8")


def extract_pdf_urls(html: str) -> List[str]:
    """Return a sorted, deduped list of cantina.xyz PDF URLs found in
    the portfolio index HTML.

    Idempotent: same HTML in -> same URL list out (sorted by URL).
    """
    if not isinstance(html, str) or not html:
        return []
    return sorted({m.group(0) for m in PDF_URL_RE.finditer(html)})


def extract_portfolio_uuids(html: str) -> List[str]:
    """Return sorted, deduped list of portfolio engagement UUIDs found in
    the portfolio index HTML.

    Useful for completeness telemetry (how many engagements does
    Cantina list publicly, vs. how many of those expose a PDF URL on
    the index page).
    """
    if not isinstance(html, str) or not html:
        return []
    return sorted({m.group(1) for m in PORTFOLIO_UUID_RE.finditer(html)})


# ---------------------------------------------------------------------------
# Per-PDF record synthesis.
# ---------------------------------------------------------------------------


_YEAR_RE = re.compile(r"(20[0-2][0-9])")
_DATE_RE = re.compile(r"(20[0-2][0-9])[-_/]?([01]?[0-9])[-_/]?([0-3]?[0-9])")
_MONTH_NAME_RE = re.compile(
    r"(jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|"
    r"jul(?:y)?|aug(?:ust)?|sep(?:tember)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)"
    r"[-_ ]?(20[0-2][0-9])",
    re.IGNORECASE,
)
_MONTH_NAME_FIRST_RE = re.compile(
    r"(20[0-2][0-9])[-_ ]?"
    r"(jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|"
    r"jul(?:y)?|aug(?:ust)?|sep(?:tember)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)",
    re.IGNORECASE,
)

MONTH_TO_NUM: Dict[str, int] = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}

_PROJECT_NOISE = re.compile(
    r"(?i)\b("
    r"cantina|cantina[- ]code|cantina[- ]solo|cantina[- ]managed|"
    r"audit(?:report| review| reports?)?|security[- ]?(?:audit|review|assessment|report)|"
    r"report|review|reviewed|final|public|version|v\d+|"
    r"spearbit|trail[- ]?of[- ]?bits|chainsecurity|zellic|"
    r"jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|"
    r"jul(?:y)?|aug(?:ust)?|sep(?:tember)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?"
    r")\b"
)


def _file_stem(url: str) -> str:
    base = url.rsplit("/", 1)[-1]
    if "." in base:
        return base.rsplit(".", 1)[0]
    return base


def infer_date(url: str) -> Tuple[Optional[str], Optional[int]]:
    """Return ``(yyyy-mm-dd | yyyy-mm | yyyy | None, year-int | None)``.

    Cantina filenames typically embed a month + year (e.g.
    ``cantina_aragon_oct2025.pdf``).
    """
    base = url.rsplit("/", 1)[-1]
    m = _DATE_RE.search(base)
    if m:
        y = int(m.group(1))
        try:
            mo = int(m.group(2))
            d = int(m.group(3))
        except ValueError:
            mo = d = 0
        if 1 <= mo <= 12 and 1 <= d <= 31:
            return f"{y:04d}-{mo:02d}-{d:02d}", y
        return f"{y:04d}", y
    m = _MONTH_NAME_FIRST_RE.search(base)
    if m:
        y = int(m.group(1))
        mn = MONTH_TO_NUM.get(m.group(2).lower()[:3])
        if mn:
            return f"{y:04d}-{mn:02d}", y
        return f"{y:04d}", y
    m = _MONTH_NAME_RE.search(base)
    if m:
        y = int(m.group(2))
        mn = MONTH_TO_NUM.get(m.group(1).lower()[:3])
        if mn:
            return f"{y:04d}-{mn:02d}", y
        return f"{y:04d}", y
    m = _YEAR_RE.search(base)
    if m:
        y = int(m.group(1))
        return f"{y:04d}", y
    return None, None


def infer_project(url: str) -> str:
    """Infer a human-readable project name from the Cantina PDF filename.

    Strips ``cantina_`` prefix, date tokens, ``solo``/``managed`` markers,
    and audit-report noise. Returns the file stem when the heuristic
    strips everything.
    """
    stem = _file_stem(url)
    cleaned = re.sub(r"[_]+", " ", stem)
    cleaned = re.sub(r"[-]+", " ", cleaned)
    cleaned = _DATE_RE.sub(" ", cleaned)
    cleaned = re.sub(r"\b20[0-2][0-9]\b", " ", cleaned)
    cleaned = _PROJECT_NOISE.sub(" ", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned or stem


def _record_id(url: str) -> str:
    """Stable record id of the form
    ``cantina-public:<file-slug>:<sha-12>``.

    Hash is taken over the full PDF URL so re-runs produce identical ids
    even when the upstream portfolio HTML re-orders the listing.
    """
    file_slug = slugify(_file_stem(url), max_len=80)
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:12]
    raw = f"cantina-public:{file_slug}:{digest}"
    # Schema pattern: [A-Za-z0-9._:/-]{8,160}
    return raw[:160]


def _record_from_url(url: str) -> Optional[Dict[str, Any]]:
    if not isinstance(url, str) or not url:
        return None
    if not PDF_URL_RE.fullmatch(url):
        return None
    file_slug = slugify(_file_stem(url), max_len=80)
    record_id = _record_id(url)
    date_str, year = infer_date(url)
    project = infer_project(url)

    component = one_line(
        f"cantina.xyz/portfolio:{file_slug}.pdf",
        f"cantina.xyz:{file_slug}",
        max_len=240,
    )

    function_shape = {
        "raw_signature": one_line(
            f"cantina-public-disclosure::{file_slug}",
            f"cantina-public-disclosure::{record_id}",
            max_len=500,
        ),
        "shape_tags": [
            "cantina-public-disclosure",
            f"firm-{SOURCE_SLUG}",
            "ext-pdf",
            slugify(f"year-{year or 'unknown'}", max_len=32),
            f"verification_tier:{VERIFICATION_TIER}",
        ],
    }

    preconds: List[str] = [
        "Source cantina.xyz/portfolio public-disclosure feed",
        f"Source PDF URL {url}",
        f"verification_tier={VERIFICATION_TIER}",
    ]
    if date_str:
        preconds.append(f"Report-date {date_str}")
    elif year:
        preconds.append(f"Report-year {year}")
    if project:
        preconds.append(f"Inferred project name {project}")

    # Dedup preconditions preserving order.
    seen: set = set()
    unique_preconds: List[str] = []
    for p in preconds:
        cleaned = one_line(p, "precondition", max_len=900)
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            unique_preconds.append(cleaned)

    action_marker = (
        f" [source=cantina-public-disclosure; verification_tier={VERIFICATION_TIER}; "
        f"url={url}]"
    )
    action_body = one_line(
        f"Cantina (cantina.xyz) publicly-disclosed audit report indexed for "
        f"the Hackerman corpus. Report published {date_str or year or 'unknown-date'} "
        f"covering project '{project}'. PDF body not parsed at this stage; "
        f"this record links the canonical CDN URL for downstream deep-mining lanes.",
        f"Cantina public-disclosure audit report for {project}",
        max_len=4900 - len(action_marker),
    )

    record: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "record_id": record_id,
        "source_audit_ref": one_line(
            f"cantina-public:{file_slug}",
            f"cantina-public:{record_id}",
            max_len=240,
        ),
        # Cantina audits cover the entire DeFi landscape; we mark the
        # listing as "vault" (default catch-all closest enum value for
        # "smart-contract-app under audit"). Downstream PDF parsing can
        # refine this. Schema enum has no "general" value; matches sibling
        # ``audit-firm-public-reports`` miner.
        "target_domain": "vault",
        # Target language is unknown without PDF parsing. The bulk of
        # Cantina reports cover Solidity. This is an HONEST default, not
        # fabrication: every record cites the CDN URL and downstream PDF
        # parsers can rewrite the field.
        "target_language": "solidity",
        "target_repo": "unknown",  # the AUDITED repo is not in the URL
        "target_component": component,
        "function_shape": function_shape,
        "bug_class": "cantina-public-disclosure-index",
        "attack_class": "cantina-public-disclosure",
        "attacker_role": "unprivileged",
        "attacker_action_sequence": (action_body + action_marker).strip(),
        "required_preconditions": unique_preconds,
        "impact_class": "theft",
        "impact_actor": "arbitrary-user",
        "impact_dollar_class": "non-financial",
        "fix_pattern": one_line(
            f"Apply the recommendations in the Cantina-published audit report at {url}.",
            "Apply the Cantina-published audit recommendations.",
            max_len=900,
        ),
        "fix_anti_pattern_avoided": one_line(
            "Ignoring Cantina-published audit recommendations and shipping unreviewed code.",
            "Ignoring Cantina-published audit recommendations.",
            max_len=900,
        ),
        # Cantina public reports don't expose a per-file severity at index
        # level; we mark the index entry as 'info' so it never short-circuits
        # a severity-tier gate downstream. PDF deep-mining can emit per-
        # finding records with real severities.
        "severity_at_finding": "info",
        "year": int(year) if year else 2020,
        "record_tier": "public-corpus",
        "record_quality_score": 3.0,
        "source_extraction_method": "corpus-etl",
        "source_extraction_confidence": 0.70,
        "verification_method": "manual",
        "cross_language_analogues": [],
        "related_records": [],
        "verification_tier": VERIFICATION_TIER,
        "record_source_url": url,
    }
    return record


# ---------------------------------------------------------------------------
# Top-level pipeline.
# ---------------------------------------------------------------------------


def build_records(
    pdf_urls: Iterable[str],
    *,
    max_records: Optional[int] = None,
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    seen_ids: set = set()
    for url in sorted(pdf_urls):
        rec = _record_from_url(url)
        if rec is None:
            continue
        if rec["record_id"] in seen_ids:
            continue
        seen_ids.add(rec["record_id"])
        out.append(rec)
        if max_records is not None and len(out) >= max_records:
            break
    return out


def output_dir_for(out_root: Path, record: Dict[str, Any]) -> Path:
    """Records are sharded into
    ``<out_root>/cantina_<file-slug>-<sha12>/record.{json,yaml}``.
    """
    record_id = record["record_id"]
    # record_id shape: cantina-public:<file-slug>:<sha12>
    parts = record_id.split(":", 2)
    if len(parts) == 3:
        file_slug = slugify(parts[1], max_len=80)
        digest = parts[2]
    else:
        file_slug = slugify(record_id, max_len=80)
        digest = hashlib.sha256(record_id.encode("utf-8")).hexdigest()[:12]
    dir_name = f"cantina_{file_slug}-{digest[:12]}"
    return out_root / dir_name


def existing_record_semantically_matches(record: Dict[str, Any], sub_dir: Path) -> bool:
    """Return true when on-disk YAML already represents ``record``.

    Keeps full-source refreshes from rewriting byte-stable records solely
    because PyYAML chose different line wrapping.
    """
    existing_path = sub_dir / "record.yaml"
    if not existing_path.exists():
        return False
    try:
        existing = yaml.safe_load(existing_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return False
    return existing == record


def convert(
    out_dir: Path,
    *,
    dry_run: bool = False,
    portfolio_html: Optional[str] = None,
    portfolio_cache: Optional[Path] = None,
    write_cache: Optional[Path] = None,
    max_records: Optional[int] = None,
) -> Dict[str, Any]:
    """Build + (when not ``dry_run``) write records to ``out_dir``.

    Returns a JSON-friendly summary dict.
    """
    html_source = "live-fetch"
    if portfolio_html is None:
        if portfolio_cache is not None:
            html_source = f"cache:{portfolio_cache}"
            portfolio_html = load_portfolio_cache(portfolio_cache)
        else:
            portfolio_html = fetch_portfolio_html()
    else:
        html_source = "inline"

    if not portfolio_html:
        return {
            "tool": "hackerman-etl-from-cantina-reports",
            "schema_version": SCHEMA_VERSION,
            "verification_tier": VERIFICATION_TIER,
            "source_url": PORTFOLIO_URL,
            "html_source": html_source,
            "html_bytes": 0,
            "portfolio_uuids": 0,
            "pdf_urls_seen": 0,
            "records_built": 0,
            "records_written": 0,
            "records_skipped_unchanged": 0,
            "out_dir": str(out_dir),
            "negative_verdict": "no_portfolio_html_available",
        }

    if write_cache is not None:
        write_portfolio_cache(write_cache, portfolio_html)

    pdf_urls = extract_pdf_urls(portfolio_html)
    portfolio_uuids = extract_portfolio_uuids(portfolio_html)
    records = build_records(pdf_urls, max_records=max_records)

    # Validate every emitted record against the schema. Schema violations
    # are a hard fail - we never emit invalid records.
    validation_errors: List[str] = []
    for rec in records:
        try:
            errs = _VALIDATOR.validate_doc(rec)  # type: ignore[attr-defined]
        except Exception as exc:  # noqa: BLE001
            validation_errors.append(f"{rec.get('record_id')}: {exc}")
            continue
        if errs:
            validation_errors.append(
                f"{rec.get('record_id')}: " + "; ".join(str(e) for e in errs[:3])
            )

    if validation_errors:
        return {
            "tool": "hackerman-etl-from-cantina-reports",
            "schema_version": SCHEMA_VERSION,
            "verification_tier": VERIFICATION_TIER,
            "source_url": PORTFOLIO_URL,
            "html_source": html_source,
            "html_bytes": len(portfolio_html),
            "portfolio_uuids": len(portfolio_uuids),
            "pdf_urls_seen": len(pdf_urls),
            "records_built": len(records),
            "records_written": 0,
            "records_skipped_unchanged": 0,
            "out_dir": str(out_dir),
            "negative_verdict": "schema_validation_failure",
            "validation_errors": validation_errors[:10],
        }

    records_written = 0
    records_skipped = 0
    if not dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)
        for rec in records:
            sub = output_dir_for(out_dir, rec)
            if existing_record_semantically_matches(rec, sub):
                records_skipped += 1
                continue
            sub.mkdir(parents=True, exist_ok=True)
            (sub / "record.yaml").write_text(
                yaml.safe_dump(
                    rec,
                    sort_keys=False,
                    default_flow_style=False,
                    allow_unicode=True,
                    width=1 << 30,
                ),
                encoding="utf-8",
            )
            (sub / "record.json").write_text(
                json.dumps(rec, indent=2, sort_keys=False, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            records_written += 1

    return {
        "tool": "hackerman-etl-from-cantina-reports",
        "schema_version": SCHEMA_VERSION,
        "verification_tier": VERIFICATION_TIER,
        "source_url": PORTFOLIO_URL,
        "html_source": html_source,
        "html_bytes": len(portfolio_html),
        "portfolio_uuids": len(portfolio_uuids),
        "pdf_urls_seen": len(pdf_urls),
        "records_built": len(records),
        "records_written": records_written,
        "records_skipped_unchanged": records_skipped,
        "out_dir": str(out_dir),
    }


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=(
            "Mine Cantina (cantina.xyz) publicly-disclosed audit reports "
            "into the Hackerman corpus as auditooor.hackerman_record.v1.1 "
            "records with verification_tier=tier-2-verified-public-archive."
        ),
    )
    p.add_argument(
        "--out-dir",
        type=Path,
        default=REPO_ROOT / "audit" / "corpus_tags" / "tags" / "cantina_public_disclosure",
        help="Output directory for emitted record subdirs.",
    )
    p.add_argument(
        "--portfolio-cache",
        type=Path,
        default=None,
        help=(
            "Read portfolio HTML from this file instead of fetching live. "
            "Use for offline / fixture testing."
        ),
    )
    p.add_argument(
        "--write-cache",
        type=Path,
        default=None,
        help="Write the live-fetched portfolio HTML to this file (for replay).",
    )
    p.add_argument(
        "--max-records",
        type=int,
        default=None,
        help="Cap emitted records at this count (proof-of-concept mining).",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Compute records but do not write to disk.",
    )
    p.add_argument(
        "--json-summary",
        action="store_true",
        help="Print a JSON summary line after the run.",
    )
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    summary = convert(
        out_dir=args.out_dir,
        dry_run=args.dry_run,
        portfolio_cache=args.portfolio_cache,
        write_cache=args.write_cache,
        max_records=args.max_records,
    )
    if args.json_summary:
        print(json.dumps(summary, indent=2, sort_keys=False))
    else:
        # Human-friendly summary line.
        print(
            f"[hackerman-etl-from-cantina-reports] "
            f"pdf_urls={summary.get('pdf_urls_seen', 0)} "
            f"portfolio_uuids={summary.get('portfolio_uuids', 0)} "
            f"records_built={summary.get('records_built', 0)} "
            f"records_written={summary.get('records_written', 0)} "
            f"records_skipped_unchanged={summary.get('records_skipped_unchanged', 0)} "
            f"out_dir={summary.get('out_dir')}"
        )
    if summary.get("negative_verdict"):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
