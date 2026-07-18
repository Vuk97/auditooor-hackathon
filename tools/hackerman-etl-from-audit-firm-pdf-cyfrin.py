#!/usr/bin/env python3
"""Wave-2 W2.4 Cyfrin-firm PDF deep-mine ETL.

Walks the Wave-1 listing tree, filters to the ``cyfrin-audits`` firm
subset (open-source Cyfrin audit-reports), fetches the PDF blob into a
local gitignored cache, and emits one
``auditooor.hackerman_record.v1``-style per-finding record per Cyfrin
finding to::

    audit/corpus_tags/tags/firm-cyfrin-audits/<sanitized-report-slug>/<finding-id>.yaml

Sibling driver to ``hackerman-etl-from-audit-firm-pdf-tob.py``,
``hackerman-etl-from-audit-firm-pdf-sherlock.py``,
``hackerman-etl-from-audit-firm-pdf-pashov.py``, and
``hackerman-etl-from-audit-firm-pdf-zellic.py``. Cyfrin reports use a
bracketed severity-coded finding-ID layout (``[C-1]``, ``[H-1]``,
``[M-1]``, ``[L-1]``, ``[I-1]``, ``[G-1]``) where ``G`` is Gas
optimisation. Findings carry Description / Impact / Proof of Concept /
Recommendation subsections with an optional ``Resolution: Fixed in
commit <sha>`` / ``Status: Acknowledged`` trailer.

See ``tools/lib/pdf_finding_extractor.py`` ``extract_cyfrin_findings``
for the parser implementation.

Spec ref: ``docs/HACKERMAN_AUDIT_FIRM_PDF_PREVIEW_2026-05-16.md``
(Cyfrin section, PR-Wave2-B task brief).

Real-source-only / M14-trap discipline:

* PDFs fetched via ``urllib.request`` to the canonical
  ``raw.githubusercontent.com`` URL Wave-1 already validated; no
  scraping, no firm-website crawling. Cyfrin filenames occasionally
  contain spaces and dashes; the URL path is percent-encoded before
  fetch (host + scheme left untouched).
* No live PDF fetch in dry-run / fixture mode. The driver consults the
  local cache first; missing entries are an error unless ``--fetch``
  is passed.
* Each emitted record cites the parent Wave-1 listing in
  ``related_records`` so the corpus stays linked.
* No edits to existing tools. W2.4 Cyfrin is purely additive.
* Does NOT modify ``tools/calibration/llm_budget_log.jsonl``.
* Record schema sets ``record_tier=public-corpus`` AND a sibling
  ``verification_tier=tier-2-verified-public-archive`` per the
  W2.7.a Immunefi-miner precedent (schema-enum gap workaround).
* When the source PDF carries ``synthetic_fixture:true`` in its
  Keywords metadata, the emitted record adds a
  ``synthetic_fixture: true`` flag to ``record_extensions`` so
  downstream consumers can filter out hermetic-test rows.

CLI::

    # Tool-only sample run (no live fetch, parses cached fixture PDFs):
    python3 tools/hackerman-etl-from-audit-firm-pdf-cyfrin.py \\
        --source tools/tests/fixtures/audit_firm_pdf_samples/cyfrin \\
        --out /tmp/cyfrin_test_emit --dry-run --json-summary

    # Wave-1 corpus run (cached PDFs only, no fetch):
    python3 tools/hackerman-etl-from-audit-firm-pdf-cyfrin.py \\
        --listings-dir audit/corpus_tags/tags/audit_firm_public_reports \\
        --cache-dir .auditooor/audit_firm_pdf_cache \\
        --out-dir audit/corpus_tags/tags/firm-cyfrin-audits \\
        --limit 3 --no-fetch --dry-run --json-summary
"""
from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import hashlib
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = REPO_ROOT / "tools"
LIB_DIR = TOOLS_DIR / "lib"

# Make ``tools/lib`` importable as a flat module path without polluting
# any package init.
sys.path.insert(0, str(LIB_DIR))

import pdf_finding_extractor  # noqa: E402  type: ignore


SCHEMA_VERSION = "auditooor.hackerman_record.v1"
VERIFICATION_TIER = "tier-2-verified-public-archive"
FIRM_PREFIX = "cyfrin-audit-reports"  # must match the Wave-1 listing dir prefix (was "cyfrin-audits" - drift -> 0 listings)
PARSER_FIRM_VARIANT = "cyfrin"
RECORD_TIER = "public-corpus"
HTTP_USER_AGENT = "auditooor-hackerman-w24/1.0"
DEFAULT_MAX_PDF_BYTES = 50 * 1024 * 1024
DEFAULT_RATE_LIMIT_PER_SEC = 2.0
SYNTHETIC_FIXTURE_MARKER = "synthetic_fixture:true"


# ---------------------------------------------------------------------------
# Listing parser - reads Wave-1 records to recover URL + project + year.
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class ListingHandle:
    record_id: str
    pdf_url: str
    firm: str
    filename: str
    project_label: str
    year: int
    parent_record_path: Path

    @property
    def project_slug(self) -> str:
        return _slugify(self.project_label)


_PROJECT_LABEL_RE = re.compile(r"Inferred project name\s+(.*)")
_RAW_URL_RE = re.compile(r"https?://raw\.githubusercontent\.com/[^\s\"']+\.(?:pdf|PDF)")


def _slugify(value: str, max_len: int = 60) -> str:
    s = value.lower()
    s = re.sub(r"[^a-z0-9]+", "-", s).strip("-")
    if len(s) > max_len:
        s = s[:max_len].rstrip("-")
    return s or "unknown"


def _percent_encode_path(url: str) -> str:
    """Percent-encode only the path component of a URL.

    Cyfrin filenames can carry spaces / parentheses / commas.
    ``urllib.request`` chokes on unencoded spaces; explicit path-only
    quoting preserves slashes and the scheme/host while making the
    request well-formed.

    Idempotent: ``%`` is included in ``safe`` so re-encoding an already
    percent-encoded path does not double-encode.
    """
    parts = urllib.parse.urlsplit(url)
    quoted_path = urllib.parse.quote(parts.path, safe="/%")
    return urllib.parse.urlunsplit(
        (parts.scheme, parts.netloc, quoted_path, parts.query, parts.fragment)
    )


def parse_listing(record_path: Path) -> Optional[ListingHandle]:
    """Decode a Wave-1 listing record.json into a ``ListingHandle``."""
    try:
        data = json.loads(record_path.read_text(encoding="utf-8"))
    except Exception:
        return None

    shape_tags = (data.get("function_shape") or {}).get("shape_tags") or []
    firm = ""
    for tag in shape_tags:
        if isinstance(tag, str) and tag.startswith("firm-"):
            firm = tag[len("firm-"):]
            break
    if firm != FIRM_PREFIX:
        return None

    preconditions = data.get("required_preconditions") or []
    pdf_url = ""
    project_label = ""
    filename = ""
    for line in preconditions:
        if not isinstance(line, str):
            continue
        if not pdf_url:
            m = _RAW_URL_RE.search(line)
            if m:
                pdf_url = m.group(0)
                filename = Path(urllib.parse.unquote(pdf_url)).name
        if not project_label:
            m = _PROJECT_LABEL_RE.search(line)
            if m:
                project_label = m.group(1).strip()

    if not pdf_url:
        # Schema drift: newer Wave-1 listings store the PDF URL in the top-level
        # `record_source_url` field, not inside required_preconditions text.
        src = data.get("record_source_url")
        if isinstance(src, str) and src.strip():
            pdf_url = src.strip()
            filename = Path(urllib.parse.unquote(pdf_url)).name
    if not pdf_url:
        return None
    if not project_label:
        project_label = Path(filename).stem.replace("_", " ").replace("-", " ")

    record_id = data.get("record_id") or ""
    year = data.get("year") or 0
    try:
        year = int(year)
    except Exception:
        year = 0

    return ListingHandle(
        record_id=str(record_id),
        pdf_url=pdf_url,
        firm=firm,
        filename=filename,
        project_label=project_label,
        year=year,
        parent_record_path=record_path,
    )


def iter_cyfrin_listings(listings_dir: Path) -> Iterable[ListingHandle]:
    if not listings_dir.is_dir():
        return
    for child in sorted(listings_dir.iterdir()):
        if not child.is_dir():
            continue
        if not child.name.startswith(FIRM_PREFIX + "__"):
            continue
        record_json = child / "record.json"
        if not record_json.is_file():
            continue
        handle = parse_listing(record_json)
        if handle is None:
            continue
        yield handle


# ---------------------------------------------------------------------------
# Source-mode listings (--source <dir-of-pdfs>): synthesise listing
# handles directly from a directory of PDFs without requiring a Wave-1
# listings tree. Used by the hermetic test suite and by the operator
# brief's --source override.
# ---------------------------------------------------------------------------


def iter_source_dir_listings(source_dir: Path) -> Iterable[ListingHandle]:
    """Yield one synthesised ``ListingHandle`` per PDF in ``source_dir``.

    Used when the operator passes ``--source <dir>``. Each fixture is
    treated as a self-contained listing with an inferred project_label
    from the filename stem; the URL is the synthetic local file:// URL.
    """
    if not source_dir.is_dir():
        return
    for child in sorted(source_dir.iterdir()):
        if child.is_file() and child.suffix.lower() == ".pdf":
            label = child.stem.replace("_", " ").replace("-", " ")
            yield ListingHandle(
                record_id=f"source-mode:cyfrin:{child.stem}",
                pdf_url=child.as_uri(),
                firm=FIRM_PREFIX,
                filename=child.name,
                project_label=label,
                year=0,
                parent_record_path=child,
            )


# ---------------------------------------------------------------------------
# PDF cache + fetch.
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class FetchResult:
    pdf_path: Optional[Path]
    blob_sha256: str
    cache_hit: bool
    fetched: bool
    skipped_reason: Optional[str]


class RateLimiter:
    def __init__(self, per_sec: float) -> None:
        self._interval = 1.0 / max(per_sec, 0.001)
        self._last = 0.0

    def wait(self) -> None:
        now = time.monotonic()
        gap = now - self._last
        if gap < self._interval:
            time.sleep(self._interval - gap)
        self._last = time.monotonic()


def _sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch_pdf(
    handle: ListingHandle,
    cache_dir: Path,
    *,
    allow_fetch: bool,
    max_bytes: int,
    rate_limiter: RateLimiter,
) -> FetchResult:
    target_dir = cache_dir / handle.firm
    target_dir.mkdir(parents=True, exist_ok=True)
    target_path = target_dir / handle.filename

    # Source-mode fast-path: when the URL is a local file:// URL the
    # PDF already lives on disk; bypass cache lookups entirely.
    if handle.pdf_url.startswith("file://"):
        local_path = Path(urllib.parse.unquote(handle.pdf_url[7:]))
        if local_path.is_file():
            return FetchResult(
                pdf_path=local_path,
                blob_sha256=_sha256_of(local_path),
                cache_hit=True,
                fetched=False,
                skipped_reason=None,
            )
        return FetchResult(
            pdf_path=None,
            blob_sha256="",
            cache_hit=False,
            fetched=False,
            skipped_reason="source-mode-file-missing",
        )

    if target_path.is_file():
        return FetchResult(
            pdf_path=target_path,
            blob_sha256=_sha256_of(target_path),
            cache_hit=True,
            fetched=False,
            skipped_reason=None,
        )

    if not allow_fetch:
        return FetchResult(
            pdf_path=None,
            blob_sha256="",
            cache_hit=False,
            fetched=False,
            skipped_reason="no-fetch-and-not-cached",
        )

    rate_limiter.wait()
    fetch_url = _percent_encode_path(handle.pdf_url)
    req = urllib.request.Request(fetch_url, headers={"User-Agent": HTTP_USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            length_hdr = resp.headers.get("Content-Length")
            if length_hdr:
                try:
                    if int(length_hdr) > max_bytes:
                        return FetchResult(
                            pdf_path=None,
                            blob_sha256="",
                            cache_hit=False,
                            fetched=False,
                            skipped_reason="oversize",
                        )
                except ValueError:
                    pass
            tmp_path = target_path.with_suffix(target_path.suffix + ".part")
            written = 0
            with tmp_path.open("wb") as out:
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > max_bytes:
                        tmp_path.unlink(missing_ok=True)
                        return FetchResult(
                            pdf_path=None,
                            blob_sha256="",
                            cache_hit=False,
                            fetched=False,
                            skipped_reason="oversize",
                        )
                    out.write(chunk)
            tmp_path.replace(target_path)
    except urllib.error.HTTPError as exc:
        return FetchResult(
            pdf_path=None,
            blob_sha256="",
            cache_hit=False,
            fetched=False,
            skipped_reason=f"http-{exc.code}",
        )
    except Exception as exc:
        return FetchResult(
            pdf_path=None,
            blob_sha256="",
            cache_hit=False,
            fetched=False,
            skipped_reason=f"unreachable:{exc!r}",
        )

    return FetchResult(
        pdf_path=target_path,
        blob_sha256=_sha256_of(target_path),
        cache_hit=False,
        fetched=True,
        skipped_reason=None,
    )


# ---------------------------------------------------------------------------
# Synthetic-fixture marker detection.
# ---------------------------------------------------------------------------


def _pdf_has_synthetic_fixture_marker(pdf_path: Path) -> bool:
    """Return True if the PDF metadata Keywords field carries the
    ``synthetic_fixture:true`` marker.

    Used by the driver to flag emitted records as hermetic-fixture
    rows so downstream consumers can filter them out of production
    corpus aggregates.
    """
    try:
        import pypdf  # type: ignore
    except Exception:
        return False
    try:
        reader = pypdf.PdfReader(str(pdf_path))
        meta = reader.metadata or {}
        # pypdf's metadata keys often use ``/Keywords`` notation.
        for key in ("/Keywords", "Keywords", "keywords"):
            value = meta.get(key) if hasattr(meta, "get") else None
            if value and SYNTHETIC_FIXTURE_MARKER in str(value):
                return True
    except Exception:
        return False
    return False


# ---------------------------------------------------------------------------
# Record assembly.
# ---------------------------------------------------------------------------


def _attack_class_from_title(title: str) -> str:
    """Best-effort attack-class label derived from a finding title."""
    lowered = title.lower()
    for needle, klass in (
        ("reentrancy", "reentrancy"),
        ("integer overflow", "integer-overflow"),
        ("overflow", "integer-overflow"),
        ("underflow", "integer-overflow"),
        ("access control", "access-control"),
        ("authorization", "access-control"),
        ("missing access", "access-control"),
        ("uninitialized", "uninitialized-state"),
        ("denial of service", "dos"),
        ("dos", "dos"),
        ("oracle", "oracle-manipulation"),
        ("price manipulation", "oracle-manipulation"),
        ("slippage", "slippage"),
        ("rounding", "rounding"),
        ("front-running", "front-running"),
        ("frontrunning", "front-running"),
        ("signature", "signature-malleability"),
        ("replay", "replay-attack"),
        ("flash loan", "flash-loan"),
        ("griefing", "griefing"),
        ("zero-address", "zero-address-check"),
        ("zero address", "zero-address-check"),
        ("centralisation", "centralisation"),
        ("centralization", "centralisation"),
        ("gas", "gas-optimisation"),
        ("event", "event-emission"),
    ):
        if needle in lowered:
            return klass
    return "audit-firm-finding-other"


def _impact_class_from_severity(severity: str) -> str:
    if severity in ("critical", "high"):
        return "theft"
    if severity == "medium":
        return "griefing"
    if severity == "gas":
        return "gas-optimisation"
    return "informational-finding"


def build_finding_record(
    handle: ListingHandle,
    finding: "pdf_finding_extractor.CyfrinFinding",
    blob_sha256: str,
    *,
    parser_version: str,
    synthetic_fixture: bool,
) -> Dict[str, Any]:
    title_slug = pdf_finding_extractor.slugify_title(finding.title)
    finding_id_suffix = f"{finding.finding_id}-{title_slug}"
    project_slug = handle.project_slug
    record_id = f"audit-firm-finding:{handle.firm}:{project_slug}:{finding_id_suffix}"

    record: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "record_id": record_id,
        "record_tier": RECORD_TIER,
        "verification_tier": VERIFICATION_TIER,
        "record_quality_score": 4.0,
        "attack_class": _attack_class_from_title(finding.title),
        "bug_class": "audit-firm-public-finding",
        "severity_at_finding": finding.severity,
        "title": finding.title,
        "summary": finding.summary,
        "recommendation": finding.recommendation,
        "lines_cited": finding.lines_cited,
        "code_snippet_pre_fix": finding.code_snippet_pre_fix,
        "code_snippet_post_fix": "",
        "fix_pattern": finding.recommendation[:600] if finding.recommendation else "",
        "fix_anti_pattern_avoided": (
            "Shipping the code path described in the finding summary without "
            "applying the audit-firm's recommended mitigation."
        ),
        "target_language": "solidity",
        "target_component": handle.project_label,
        "target_repo": "unknown",
        "target_domain": "vault",
        "year": handle.year or 0,
        "function_shape": {
            "raw_signature": f"audit-firm-finding::{handle.firm}/{project_slug}/{finding_id_suffix}",
            "shape_tags": [
                "audit-firm-public-finding",
                f"firm-{handle.firm}",
                f"verification_tier:{VERIFICATION_TIER}",
                f"year-{handle.year or 'unknown'}",
                f"severity-{finding.severity}",
                f"attack-{_attack_class_from_title(finding.title)}",
            ],
        },
        "source_audit_ref": f"audit-firm-finding:{handle.firm}:{handle.filename}:{finding_id_suffix}",
        "source_extraction_method": "pdf-deep-mine",
        "source_extraction_confidence": round(finding.parser_confidence, 3),
        "verification_method": "auto-pdf-parse",
        "attacker_role": "unprivileged",
        "attacker_action_sequence": (
            finding.proof_of_concept[:1200] if finding.proof_of_concept else
            (finding.summary[:1200] if finding.summary else
             f"Audit-firm finding extracted from Cyfrin PDF '{handle.filename}'.")
        ),
        "impact_class": _impact_class_from_severity(finding.severity),
        "impact_actor": "arbitrary-user",
        "impact_dollar_class": "financial" if finding.severity in ("critical", "high") else "non-financial",
        "required_preconditions": [
            f"Reference public audit report at {handle.pdf_url}",
            f"Source firm {handle.firm}",
            f"Project {handle.project_label}",
            f"verification_tier={VERIFICATION_TIER}",
            f"Cyfrin finding {finding.finding_id}",
        ],
        "cross_language_analogues": [],
        "related_records": [handle.record_id] if handle.record_id else [],
        "record_source_url": _percent_encode_path(handle.pdf_url) if "://" in handle.pdf_url else handle.pdf_url,
        "record_extensions": {
            "pdf_blob_sha256": blob_sha256,
            "pdf_page_range": list(finding.page_range),
            "pdf_parser_version": parser_version,
            "pdf_parser_firm_variant": PARSER_FIRM_VARIANT,
            "severity_verbatim": finding.severity_verbatim,
            "severity_code": finding.severity_code,
            "finding_id": finding.finding_id,
            "impact_section": finding.impact,
            "proof_of_concept": finding.proof_of_concept,
            "resolution_status": finding.resolution_status,
            "resolution_commit_ref": finding.resolution_commit_ref,
            "parser_warnings": finding.parser_warnings,
            "synthetic_fixture": synthetic_fixture,
        },
    }
    return record


def write_record(
    record: Dict[str, Any],
    out_dir: Path,
    handle: ListingHandle,
    finding_id_suffix: str,
    *,
    dry_run: bool = False,
) -> Path:
    rec_dir_name = f"{handle.firm}__{handle.project_slug}__{finding_id_suffix}"
    rec_dir = out_dir / rec_dir_name
    if dry_run:
        return rec_dir
    rec_dir.mkdir(parents=True, exist_ok=True)
    (rec_dir / "record.json").write_text(
        json.dumps(record, indent=2, sort_keys=True), encoding="utf-8"
    )
    (rec_dir / "record.yaml").write_text(
        yaml.safe_dump(record, sort_keys=True, default_flow_style=False), encoding="utf-8"
    )
    return rec_dir


# ---------------------------------------------------------------------------
# Top-level driver.
# ---------------------------------------------------------------------------


def process_listing(
    handle: ListingHandle,
    *,
    cache_dir: Path,
    out_dir: Path,
    allow_fetch: bool,
    max_bytes: int,
    rate_limiter: RateLimiter,
    dry_run: bool,
) -> Dict[str, Any]:
    fetch = fetch_pdf(
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
        # Malformed-header / OCR-required / encrypted PDF: skip gracefully
        # with exit-0 contract (zero records emitted but driver returns OK).
        return {
            "listing_record_id": handle.record_id,
            "pdf_url": handle.pdf_url,
            "fetched": fetch.fetched,
            "cache_hit": fetch.cache_hit,
            "skipped": True,
            "skipped_reason": ";".join(extraction.diagnostics) or "malformed-header",
            "findings_emitted": 0,
            "records_written": [],
        }

    findings = pdf_finding_extractor.extract_cyfrin_findings(extraction)
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

    synthetic = _pdf_has_synthetic_fixture_marker(fetch.pdf_path)

    written: list[str] = []
    for finding in findings:
        record = build_finding_record(
            handle,
            finding,
            blob_sha256=fetch.blob_sha256,
            parser_version=pdf_finding_extractor.PARSER_VERSION,
            synthetic_fixture=synthetic,
        )
        title_slug = pdf_finding_extractor.slugify_title(finding.title)
        finding_id_suffix = f"{finding.finding_id}-{title_slug}"
        rec_path = write_record(record, out_dir, handle, finding_id_suffix, dry_run=dry_run)
        written.append(str(rec_path))

    return {
        "listing_record_id": handle.record_id,
        "pdf_url": handle.pdf_url,
        "fetched": fetch.fetched,
        "cache_hit": fetch.cache_hit,
        "skipped": False,
        "skipped_reason": None,
        "findings_emitted": len(findings),
        "records_written": written,
        "synthetic_fixture": synthetic,
        "parser_diagnostics": extraction.diagnostics,
    }


def run(args: argparse.Namespace) -> int:
    cache_dir = Path(args.cache_dir).resolve()
    out_dir = Path(args.out_dir).resolve()
    cache_dir.mkdir(parents=True, exist_ok=True)
    if not args.dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)

    rate_limiter = RateLimiter(args.rate_limit_per_sec)

    summary: Dict[str, Any] = {
        "started_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "firm": FIRM_PREFIX,
        "cache_dir": str(cache_dir),
        "out_dir": str(out_dir),
        "dry_run": bool(args.dry_run),
        "no_fetch": bool(args.no_fetch),
        "listings_seen": 0,
        "listings_processed": 0,
        "listings_skipped": 0,
        "findings_emitted": 0,
        "records_written": 0,
        "per_listing": [],
    }

    if args.source:
        source_dir = Path(args.source).resolve()
        summary["source_dir"] = str(source_dir)
        handles = list(iter_source_dir_listings(source_dir))
    else:
        listings_dir = Path(args.listings_dir).resolve()
        summary["listings_dir"] = str(listings_dir)
        handles = list(iter_cyfrin_listings(listings_dir))

    if args.limit and args.limit > 0:
        handles = handles[: args.limit]
    summary["listings_seen"] = len(handles)

    for handle in handles:
        result = process_listing(
            handle,
            cache_dir=cache_dir,
            out_dir=out_dir,
            allow_fetch=(not args.no_fetch),
            max_bytes=args.max_pdf_bytes,
            rate_limiter=rate_limiter,
            dry_run=args.dry_run,
        )
        summary["per_listing"].append(result)
        if result["skipped"]:
            summary["listings_skipped"] += 1
        else:
            summary["listings_processed"] += 1
            summary["findings_emitted"] += result["findings_emitted"]
            summary["records_written"] += len(result["records_written"])

    summary["ended_at"] = dt.datetime.now(dt.timezone.utc).isoformat()

    if args.json_summary:
        sys.stdout.write(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    else:
        sys.stdout.write(
            f"[w24-cyfrin] listings_seen={summary['listings_seen']} "
            f"processed={summary['listings_processed']} "
            f"skipped={summary['listings_skipped']} "
            f"findings={summary['findings_emitted']} "
            f"records={summary['records_written']}\n"
        )

    if args.summary_path:
        Path(args.summary_path).write_text(
            json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8"
        )

    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument(
        "--listings-dir",
        default="audit/corpus_tags/tags/audit_firm_public_reports",
        help="Wave-1 listings tree root (used when --source is not provided).",
    )
    p.add_argument(
        "--source",
        default="",
        help=(
            "Directory of Cyfrin PDFs to mine directly (bypasses Wave-1 "
            "listings tree). One synthesised listing handle per *.pdf."
        ),
    )
    p.add_argument(
        "--cache-dir",
        default=".auditooor/audit_firm_pdf_cache",
        help="Local PDF cache (gitignored).",
    )
    p.add_argument(
        "--out-dir",
        default="audit/corpus_tags/tags/firm-cyfrin-audits",
        help="Per-finding record output tree.",
    )
    # Alias --out for --out-dir for parity with the brief's CLI sample.
    p.add_argument("--out", dest="out_dir", help=argparse.SUPPRESS)
    p.add_argument("--limit", type=int, default=0, help="Cap on listings to process (0=all).")
    p.add_argument("--no-fetch", action="store_true", help="Disable network fetch; cache-only.")
    p.add_argument("--dry-run", action="store_true", help="Parse but do not write records.")
    p.add_argument("--json-summary", action="store_true", help="Emit JSON summary to stdout.")
    p.add_argument("--summary-path", default="", help="Optional path to write summary JSON.")
    p.add_argument("--max-pdf-bytes", type=int, default=DEFAULT_MAX_PDF_BYTES)
    p.add_argument("--rate-limit-per-sec", type=float, default=DEFAULT_RATE_LIMIT_PER_SEC)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
