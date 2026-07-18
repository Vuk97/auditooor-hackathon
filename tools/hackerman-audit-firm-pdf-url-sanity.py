#!/usr/bin/env python3
"""hackerman-audit-firm-pdf-url-sanity.

Verify that every record under
``audit/corpus_tags/tags/audit_firm_public_reports/<slug>/record.{json,yaml}``
cites a URL that actually resolves to a valid PDF.

For each record this tool:

  1. Extracts the canonical PDF URL from the ``required_preconditions``
     entry that begins with ``Reference public audit report at``
     (falling back to ``fix_pattern`` line scrape if absent).
  2. Issues an HTTP HEAD request with a 5s timeout (per request) and
     a small inter-request sleep (rate-limit budget). Up to ``--retries``
     attempts are made on transient errors / 5xx / 429.
  3. Records the status code, ``Content-Type`` header (lowercased,
     stripped of parameters), final URL (after redirects), and
     verdict.

Verdicts:

  - ``pass``                     HTTP 200 AND content-type in the PDF
                                 mime-allowlist (``application/pdf``
                                 or ``application/octet-stream`` for
                                 github-raw).
  - ``fail-status``              status != 200 (excludes 429 -> rate-limit).
  - ``fail-wrong-mime``          status == 200 but content-type not in
                                 allowlist (HTML error page, JSON,
                                 etc.).
  - ``rate-limited``             status == 429 OR explicit retry-after.
  - ``timeout``                  socket / urllib timeout exception.
  - ``no-url``                   record has no extractable URL.
  - ``error``                    any other exception.

Mode flags:

  --sample N         Pick the first N records (lexicographic by slug) and
                     check only those. Useful for a 50-row smoke test
                     before a full 1681-row run.
  --workers K        Run K parallel HEAD requests via
                     ``concurrent.futures.ThreadPoolExecutor``. Default
                     4. Set to 1 for fully-serial.
  --rate-limit-sleep S
                     Sleep S seconds between per-worker HEAD requests.
                     Default 0.05s (50ms). Combine with --workers 4
                     gives ~80 req/s peak, well below github-raw's
                     5000 req/h authenticated quota and roughly aligned
                     with the 60 req/h unauthenticated quota *per IP*
                     (which is why a sample run is recommended first).
  --timeout T        Per-request timeout in seconds. Default 5.
  --retries R        Retry attempts on 5xx / 429 / transient errors.
                     Default 1 (= 2 total attempts).
  --tags-dir PATH    Override corpus root.
  --output-jsonl PATH
                     Override the per-record JSONL artifact path.
                     Default ``.auditooor/audit_firm_pdf_url_sanity.jsonl``.
  --output-md PATH   Override the markdown summary path.
                     Default
                     ``docs/HACKERMAN_AUDIT_FIRM_PDF_URL_SANITY_2026-05-16.md``.
  --skip-network     Skip the HEAD requests entirely; emit ``no-url``
                     verdicts for records lacking a URL and a synthetic
                     ``skip-network`` verdict otherwise. For CI / offline
                     smoke testing of the walker + aggregator.
  --dry-run          Compute, print summary, write nothing.

Artifacts:

  - ``.auditooor/audit_firm_pdf_url_sanity.jsonl`` (gitignored)
  - ``docs/HACKERMAN_AUDIT_FIRM_PDF_URL_SANITY_2026-05-16.md`` (committed)

Markdown summary surfaces:

  - Total URLs checked.
  - Pass / fail-status / fail-wrong-mime / rate-limited / timeout /
    no-url / error / skip-network counts.
  - Top 20 failure URLs (most-recent-first by record path).
  - Per-firm pass-rate table (descending by record count).

Exit codes:

  0 - all records pass OR ``--dry-run`` (also 0 if every failure verdict
      is exclusively rate-limited / timeout; the operator should
      re-run those).
  1 - one or more records fail (status / wrong-mime / no-url / error).
  2 - corpus tree missing / unreadable.
"""
from __future__ import annotations

import argparse
import concurrent.futures as futures
import json
import re
import socket
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

SCHEMA = "auditooor.hackerman_audit_firm_pdf_url_sanity.v1"

REPO_ROOT_GUESS = Path(__file__).resolve().parent.parent
DEFAULT_TAGS_DIR = (
    REPO_ROOT_GUESS / "audit" / "corpus_tags" / "tags" / "audit_firm_public_reports"
)
DEFAULT_OUTPUT_JSONL = (
    REPO_ROOT_GUESS / ".auditooor" / "audit_firm_pdf_url_sanity.jsonl"
)
DEFAULT_DOCS_PATH = (
    REPO_ROOT_GUESS / "docs" / "HACKERMAN_AUDIT_FIRM_PDF_URL_SANITY_2026-05-16.md"
)

# NOTE: corpus URLs occasionally contain literal spaces (e.g. filenames
# like ``WishWish-security-review_2025-11-04 (1).pdf``); the regex must
# tolerate this and we URL-encode at probe time.
RE_REFERENCE_LINE = re.compile(
    r"^Reference public audit report at\s+(https?://.+?)\s*$"
)
RE_FIX_PATTERN_URL = re.compile(
    r"(https?://[^\s][^\s]*?\.(?:pdf|md|txt|html))",
    re.IGNORECASE,
)

# Allowed Content-Type values for a record to count as a valid PDF.
# - application/pdf: canonical PDF MIME.
# - application/octet-stream: github-raw frequently serves the PDF this way
#   when X-Content-Type-Options: nosniff is set. We treat it as PASS only
#   when the URL ends in ``.pdf``.
PDF_MIME_ALLOWLIST = {"application/pdf", "application/octet-stream"}

# Verdict enum.
VERDICT_PASS = "pass"
VERDICT_FAIL_STATUS = "fail-status"
VERDICT_FAIL_WRONG_MIME = "fail-wrong-mime"
VERDICT_RATE_LIMITED = "rate-limited"
VERDICT_TIMEOUT = "timeout"
VERDICT_NO_URL = "no-url"
VERDICT_ERROR = "error"
VERDICT_SKIP_NETWORK = "skip-network"

NON_FATAL_VERDICTS = {
    VERDICT_PASS,
    VERDICT_RATE_LIMITED,
    VERDICT_TIMEOUT,
    VERDICT_SKIP_NETWORK,
}


# ---------------------------------------------------------------------------
# Minimal YAML loader (mirrors sibling preview extractor's shape)
# ---------------------------------------------------------------------------
def _yaml_load(text: str) -> Dict[str, Any]:
    """Parse the restricted Hackerman YAML shape: top-level scalars +
    top-level ``key:`` followed by ``- item`` block lists. Lossy on
    nested maps; sufficient for the fields this tool extracts
    (``required_preconditions`` / ``fix_pattern`` / ``schema_version``).
    """
    out: Dict[str, Any] = {}
    lines = text.splitlines()
    i = 0
    n = len(lines)
    while i < n:
        raw = lines[i]
        if not raw.strip() or raw.lstrip().startswith("#"):
            i += 1
            continue
        if raw.startswith(" "):
            i += 1
            continue
        if ":" not in raw:
            i += 1
            continue
        key, _, rest = raw.partition(":")
        key = key.strip()
        rest = rest.strip()
        if rest:
            out[key] = _coerce_scalar(rest)
            i += 1
            continue
        # block list / nested map: gather indented lines, take only
        # top-level ``- item`` shape (the rest we don't need).
        items: List[Any] = []
        j = i + 1
        while j < n:
            nxt = lines[j]
            if not nxt.strip():
                j += 1
                continue
            if not nxt.startswith(" "):
                break
            s = nxt.lstrip()
            if s.startswith("- "):
                items.append(_coerce_scalar(s[2:].strip()))
            j += 1
        out[key] = items
        i = j
    return out


def _coerce_scalar(raw: str) -> Any:
    if raw == "" or raw.lower() == "null" or raw == "~":
        return None
    if raw.lower() == "true":
        return True
    if raw.lower() == "false":
        return False
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in ("'", '"'):
        return raw[1:-1]
    try:
        if "." in raw:
            return float(raw)
        return int(raw)
    except ValueError:
        return raw


# ---------------------------------------------------------------------------
# Record loading + URL extraction
# ---------------------------------------------------------------------------
def _load_record(record_dir: Path) -> Optional[Dict[str, Any]]:
    """YAML preferred (matches corpus-author convention); JSON fallback."""
    yaml_path = record_dir / "record.yaml"
    json_path = record_dir / "record.json"
    if yaml_path.is_file():
        try:
            return _yaml_load(yaml_path.read_text(encoding="utf-8"))
        except Exception:
            pass
    if json_path.is_file():
        try:
            return json.loads(json_path.read_text(encoding="utf-8"))
        except Exception:
            return None
    return None


def extract_url(record: Dict[str, Any]) -> Optional[str]:
    """Find the canonical PDF URL.

    Priority:
      1. ``required_preconditions`` entry matching
         ``Reference public audit report at <URL>``.
      2. First ``https?://...\\.(pdf|md|txt|html)`` substring in
         ``fix_pattern``.
    """
    preconds = record.get("required_preconditions") or []
    for line in preconds:
        if not isinstance(line, str):
            continue
        m = RE_REFERENCE_LINE.match(line)
        if m:
            return m.group(1)
    fix = record.get("fix_pattern")
    if isinstance(fix, str):
        m = RE_FIX_PATTERN_URL.search(fix)
        if m:
            return m.group(1)
    return None


def _extract_firm(slug: str) -> str:
    if "__" in slug:
        return slug.split("__", 1)[0]
    return slug


# ---------------------------------------------------------------------------
# HTTP HEAD probe
# ---------------------------------------------------------------------------
def _normalize_content_type(value: Optional[str]) -> str:
    if not value:
        return ""
    # strip parameters: "application/pdf; charset=utf-8" -> "application/pdf"
    return value.split(";", 1)[0].strip().lower()


def head_request(
    url: str,
    *,
    timeout: float = 5.0,
    user_agent: str = "auditooor-hackerman-pdf-url-sanity/1.0",
) -> Dict[str, Any]:
    """Issue a single HEAD request and return a structured result dict.

    Returns a dict with keys:
      - ``status``: int (HTTP status) or None on transport error.
      - ``content_type``: normalized lowercase mime or "".
      - ``final_url``: URL after any redirect chain.
      - ``transport_error``: str or None.
      - ``rate_limited``: bool (status 429 OR Retry-After header).
      - ``timed_out``: bool.
    """
    # urllib refuses URLs containing raw spaces. The Hackerman corpus has
    # records whose PDF filenames include literal spaces (e.g.
    # ``... (1).pdf``); percent-encode them before issuing the HEAD.
    safe_url = url.replace(" ", "%20")
    req = urllib.request.Request(safe_url, method="HEAD")
    req.add_header("User-Agent", user_agent)
    req.add_header("Accept", "application/pdf,application/octet-stream;q=0.9,*/*;q=0.5")

    result: Dict[str, Any] = {
        "status": None,
        "content_type": "",
        "final_url": url,
        "transport_error": None,
        "rate_limited": False,
        "timed_out": False,
    }
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            result["status"] = int(resp.status)
            result["content_type"] = _normalize_content_type(
                resp.headers.get("Content-Type")
            )
            result["final_url"] = resp.geturl() or url
            if resp.headers.get("Retry-After"):
                result["rate_limited"] = True
    except urllib.error.HTTPError as exc:
        result["status"] = int(exc.code)
        try:
            result["content_type"] = _normalize_content_type(
                exc.headers.get("Content-Type") if exc.headers else ""
            )
        except Exception:
            result["content_type"] = ""
        if exc.code == 429:
            result["rate_limited"] = True
    except (socket.timeout, TimeoutError):
        result["timed_out"] = True
        result["transport_error"] = "timeout"
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", exc)
        if isinstance(reason, socket.timeout) or "timed out" in str(reason).lower():
            result["timed_out"] = True
            result["transport_error"] = "timeout"
        else:
            result["transport_error"] = str(reason)
    except Exception as exc:  # noqa: BLE001 (defensive)
        result["transport_error"] = f"{type(exc).__name__}: {exc}"
    return result


def classify_response(url: str, probe: Dict[str, Any]) -> str:
    """Map a HEAD probe result to a verdict enum value."""
    if probe.get("timed_out"):
        return VERDICT_TIMEOUT
    status = probe.get("status")
    if status == 429 or probe.get("rate_limited"):
        return VERDICT_RATE_LIMITED
    if probe.get("transport_error") and status is None:
        return VERDICT_ERROR
    if status != 200:
        return VERDICT_FAIL_STATUS
    ct = probe.get("content_type") or ""
    if ct in PDF_MIME_ALLOWLIST:
        # application/octet-stream is only acceptable for .pdf URLs.
        if ct == "application/octet-stream" and not url.lower().endswith(".pdf"):
            return VERDICT_FAIL_WRONG_MIME
        return VERDICT_PASS
    return VERDICT_FAIL_WRONG_MIME


def probe_url(
    url: str,
    *,
    timeout: float = 5.0,
    retries: int = 1,
    rate_limit_sleep: float = 0.05,
) -> Tuple[str, Dict[str, Any]]:
    """Probe a URL with retries on transient/rate-limited responses.

    Returns ``(verdict, probe_result)``. ``probe_result`` is the last
    HEAD-request dict (post-retry).
    """
    attempt = 0
    last: Dict[str, Any] = {}
    verdict = VERDICT_ERROR
    while attempt <= retries:
        last = head_request(url, timeout=timeout)
        verdict = classify_response(url, last)
        if verdict in (VERDICT_PASS, VERDICT_FAIL_WRONG_MIME, VERDICT_NO_URL):
            break
        # retry on transient (timeout / rate-limit / 5xx / error)
        if verdict == VERDICT_FAIL_STATUS and isinstance(last.get("status"), int) and last["status"] < 500:
            break  # 4xx is not transient (besides 429 already routed)
        attempt += 1
        if attempt > retries:
            break
        time.sleep(min(2.0, rate_limit_sleep * (2 ** attempt)))
    if rate_limit_sleep > 0:
        time.sleep(rate_limit_sleep)
    return verdict, last


# ---------------------------------------------------------------------------
# Corpus walker + driver
# ---------------------------------------------------------------------------
def walk_records(tags_dir: Path) -> List[Tuple[str, Path, Dict[str, Any]]]:
    """Return ``[(slug, record_dir, record_dict), ...]`` sorted by slug."""
    out: List[Tuple[str, Path, Dict[str, Any]]] = []
    if not tags_dir.is_dir():
        return out
    for entry in sorted(tags_dir.iterdir()):
        if not entry.is_dir():
            continue
        rec = _load_record(entry)
        if rec is None:
            continue
        out.append((entry.name, entry, rec))
    return out


def check_records(
    records: List[Tuple[str, Path, Dict[str, Any]]],
    *,
    workers: int = 4,
    timeout: float = 5.0,
    retries: int = 1,
    rate_limit_sleep: float = 0.05,
    skip_network: bool = False,
) -> List[Dict[str, Any]]:
    """Drive the URL probe for each record and return a list of result
    rows. Network probes run via a thread pool; results are emitted in
    the same order as the input (sorted by slug).
    """
    rows: List[Optional[Dict[str, Any]]] = [None] * len(records)

    def _build_row(
        idx: int,
        slug: str,
        url: Optional[str],
        verdict: str,
        probe: Dict[str, Any],
    ) -> None:
        rows[idx] = {
            "slug": slug,
            "firm": _extract_firm(slug),
            "pdf_url": url,
            "verdict": verdict,
            "status": probe.get("status"),
            "content_type": probe.get("content_type"),
            "final_url": probe.get("final_url"),
            "transport_error": probe.get("transport_error"),
        }

    if skip_network:
        for i, (slug, _rec_dir, record) in enumerate(records):
            url = extract_url(record)
            if url is None:
                _build_row(i, slug, None, VERDICT_NO_URL, {})
            else:
                _build_row(i, slug, url, VERDICT_SKIP_NETWORK, {})
        return [r for r in rows if r is not None]

    jobs: List[Tuple[int, str, str]] = []  # (idx, slug, url)
    for i, (slug, _rec_dir, record) in enumerate(records):
        url = extract_url(record)
        if url is None:
            _build_row(i, slug, None, VERDICT_NO_URL, {})
            continue
        jobs.append((i, slug, url))

    if not jobs:
        return [r for r in rows if r is not None]

    workers = max(1, int(workers))
    with futures.ThreadPoolExecutor(max_workers=workers) as pool:
        fut_to_meta = {
            pool.submit(
                probe_url,
                url,
                timeout=timeout,
                retries=retries,
                rate_limit_sleep=rate_limit_sleep,
            ): (idx, slug, url)
            for (idx, slug, url) in jobs
        }
        for fut in futures.as_completed(fut_to_meta):
            idx, slug, url = fut_to_meta[fut]
            try:
                verdict, probe = fut.result()
            except Exception as exc:  # noqa: BLE001
                verdict, probe = (
                    VERDICT_ERROR,
                    {"transport_error": f"{type(exc).__name__}: {exc}"},
                )
            _build_row(idx, slug, url, verdict, probe)

    return [r for r in rows if r is not None]


# ---------------------------------------------------------------------------
# Aggregation + markdown rendering
# ---------------------------------------------------------------------------
def summarize(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    verdict_counts: Counter = Counter(r["verdict"] for r in rows)
    firm_totals: Counter = Counter(r["firm"] for r in rows)
    firm_pass: Counter = Counter(
        r["firm"] for r in rows if r["verdict"] == VERDICT_PASS
    )
    failures = [r for r in rows if r["verdict"] not in NON_FATAL_VERDICTS]
    return {
        "total": len(rows),
        "by_verdict": dict(verdict_counts),
        "firm_totals": dict(firm_totals),
        "firm_pass": dict(firm_pass),
        "failures": failures,
    }


def render_markdown(
    summary: Dict[str, Any],
    *,
    generated_at: str,
    sample: Optional[int],
    workers: int,
    timeout: float,
    skip_network: bool,
    top_failures: int = 20,
) -> str:
    by_verdict = summary["by_verdict"]
    firm_totals = summary["firm_totals"]
    firm_pass = summary["firm_pass"]
    failures = summary["failures"]

    def _count(v: str) -> int:
        return int(by_verdict.get(v, 0))

    lines: List[str] = []
    lines.append("# Hackerman Audit-Firm PDF URL Sanity 2026-05-16")
    lines.append("")
    lines.append(f"- Generated at: `{generated_at}`")
    lines.append(f"- Schema: `{SCHEMA}`")
    lines.append(f"- Sample: `{sample if sample is not None else 'full'}`")
    lines.append(f"- Workers: `{workers}`")
    lines.append(f"- Per-request timeout (s): `{timeout}`")
    lines.append(f"- Skip-network mode: `{skip_network}`")
    lines.append("")
    lines.append("## Totals")
    lines.append("")
    lines.append(f"- Total URLs checked: **{summary['total']}**")
    lines.append(f"- Pass: **{_count(VERDICT_PASS)}**")
    lines.append(f"- Fail (status != 200): **{_count(VERDICT_FAIL_STATUS)}**")
    lines.append(f"- Fail (wrong MIME): **{_count(VERDICT_FAIL_WRONG_MIME)}**")
    lines.append(f"- Rate-limited (429 / Retry-After): **{_count(VERDICT_RATE_LIMITED)}**")
    lines.append(f"- Timeout: **{_count(VERDICT_TIMEOUT)}**")
    lines.append(f"- No URL extractable: **{_count(VERDICT_NO_URL)}**")
    lines.append(f"- Transport error: **{_count(VERDICT_ERROR)}**")
    if skip_network:
        lines.append(
            f"- Skip-network (no probe issued): **{_count(VERDICT_SKIP_NETWORK)}**"
        )
    lines.append("")

    lines.append("## Verdict legend")
    lines.append("")
    lines.append("- `pass` - HTTP 200 and `Content-Type` in `application/pdf` / `application/octet-stream` (`.pdf` URL only).")
    lines.append("- `fail-status` - HTTP status != 200 and != 429 (404 / 403 / 500 etc.).")
    lines.append("- `fail-wrong-mime` - HTTP 200 but `Content-Type` is HTML / JSON / text / other.")
    lines.append("- `rate-limited` - HTTP 429 OR `Retry-After` header present; operator should re-run.")
    lines.append("- `timeout` - per-request `--timeout` exceeded; operator should re-run.")
    lines.append("- `no-url` - record has no extractable PDF URL (data-quality bug).")
    lines.append("- `error` - other transport error (DNS / TLS / connection reset).")
    lines.append("")

    lines.append("## Per-firm pass rate")
    lines.append("")
    lines.append("| Firm | Records | Pass | Pass rate |")
    lines.append("|------|---------|------|-----------|")
    for firm, total in sorted(firm_totals.items(), key=lambda kv: (-kv[1], kv[0])):
        passed = firm_pass.get(firm, 0)
        rate = (passed / total * 100.0) if total else 0.0
        lines.append(f"| `{firm}` | {total} | {passed} | {rate:.1f}% |")
    lines.append("")

    lines.append(f"## Top {top_failures} failure URLs")
    lines.append("")
    if not failures:
        lines.append("- (none)")
    else:
        lines.append("| Slug | Verdict | Status | Content-Type | URL |")
        lines.append("|------|---------|--------|--------------|-----|")
        for row in failures[:top_failures]:
            status = row.get("status")
            status_str = str(status) if status is not None else "-"
            ct = row.get("content_type") or "-"
            url = row.get("pdf_url") or "(no url)"
            lines.append(
                f"| `{row['slug']}` | `{row['verdict']}` | `{status_str}` | `{ct}` | {url} |"
            )
    lines.append("")

    lines.append("## How to re-run")
    lines.append("")
    lines.append("```")
    lines.append("# Smoke test (50 records, 4 workers, 5s timeout):")
    lines.append("python3 tools/hackerman-audit-firm-pdf-url-sanity.py --sample 50 --workers 4")
    lines.append("")
    lines.append("# Full corpus run (1681 records):")
    lines.append("python3 tools/hackerman-audit-firm-pdf-url-sanity.py --workers 4")
    lines.append("")
    lines.append("# Offline walker / aggregator smoke (no HTTP):")
    lines.append("python3 tools/hackerman-audit-firm-pdf-url-sanity.py --skip-network")
    lines.append("```")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _parse_args(argv: List[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Verify Hackerman audit-firm-public-report URLs resolve to valid PDFs.",
    )
    p.add_argument("--tags-dir", type=Path, default=DEFAULT_TAGS_DIR)
    p.add_argument("--output-jsonl", type=Path, default=DEFAULT_OUTPUT_JSONL)
    p.add_argument("--output-md", type=Path, default=DEFAULT_DOCS_PATH)
    p.add_argument("--sample", type=int, default=None)
    p.add_argument("--workers", type=int, default=4)
    p.add_argument("--rate-limit-sleep", type=float, default=0.05)
    p.add_argument("--timeout", type=float, default=5.0)
    p.add_argument("--retries", type=int, default=1)
    p.add_argument("--skip-network", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = _parse_args(list(argv) if argv is not None else sys.argv[1:])

    if not args.tags_dir.is_dir():
        sys.stderr.write(
            f"hackerman-audit-firm-pdf-url-sanity: tags dir not found: {args.tags_dir}\n"
        )
        return 2

    records = walk_records(args.tags_dir)
    if not records:
        sys.stderr.write(
            f"hackerman-audit-firm-pdf-url-sanity: no records under {args.tags_dir}\n"
        )
        return 2

    if isinstance(args.sample, int) and args.sample > 0:
        records = records[: args.sample]

    rows = check_records(
        records,
        workers=args.workers,
        timeout=args.timeout,
        retries=args.retries,
        rate_limit_sleep=args.rate_limit_sleep,
        skip_network=args.skip_network,
    )

    summary = summarize(rows)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    md = render_markdown(
        summary,
        generated_at=generated_at,
        sample=args.sample,
        workers=args.workers,
        timeout=args.timeout,
        skip_network=args.skip_network,
    )

    print(
        f"[hackerman-pdf-url-sanity] total={summary['total']} "
        f"pass={summary['by_verdict'].get(VERDICT_PASS, 0)} "
        f"fail-status={summary['by_verdict'].get(VERDICT_FAIL_STATUS, 0)} "
        f"fail-wrong-mime={summary['by_verdict'].get(VERDICT_FAIL_WRONG_MIME, 0)} "
        f"rate-limited={summary['by_verdict'].get(VERDICT_RATE_LIMITED, 0)} "
        f"timeout={summary['by_verdict'].get(VERDICT_TIMEOUT, 0)} "
        f"no-url={summary['by_verdict'].get(VERDICT_NO_URL, 0)} "
        f"error={summary['by_verdict'].get(VERDICT_ERROR, 0)}"
    )

    if not args.dry_run:
        args.output_jsonl.parent.mkdir(parents=True, exist_ok=True)
        with args.output_jsonl.open("w", encoding="utf-8") as fh:
            for row in rows:
                fh.write(json.dumps({**row, "schema": SCHEMA}, sort_keys=True))
                fh.write("\n")
        args.output_md.parent.mkdir(parents=True, exist_ok=True)
        args.output_md.write_text(md, encoding="utf-8")

    failures = summary["failures"]
    if failures:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
