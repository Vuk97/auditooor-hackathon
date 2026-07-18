#!/usr/bin/env python3
"""defimon-staleness-check — corpus staleness check + BLOCKED_NO_LIVE_SOURCE status.

Lane 9 corpus-mining commitments (PR #658 Tier-B #15).
Reads the defimon entry from reference/corpus_registry.json extended_corpora,
computes staleness, and reports status.

I2 SPEC COMPLIANCE:
  Defimon has no stable live alert-feed API, cursor endpoint, RSS feed, or
  Telegram JSON source. A bounded Next.js SSG blog JSON route is discoverable
  at runtime and is handled by tools/defimon-nextjs-blog-miner.py, but that is
  blog-only coverage rather than a live/cursor incident feed.
  The two public sources that exist are:
    1. https://t.me/s/defimon_alerts  - public Telegram channel mirror
       (HTML-only, no JSON API, no pagination cursor, bot-detection on scrape)
    2. https://defimon.xyz/blog       - HTML blog with runtime-discovered
       Next.js SSG JSON data routes
  The prior mining was done via MANUAL review of the public Telegram mirror
  (posts 2332-3038) and the public blog writeups. Telegram is not automatable
  without a headless browser or third-party scraper, which we intentionally
  exclude from this tool; blog mining is now handled by a bounded SSG miner.

  Per the I2 spec: "Defimon currently has only staleness/remine scaffolding,
  so the plan must either implement the real miner or emit BLOCKED_NO_LIVE_SOURCE
  with evidence."

  This tool emits BLOCKED_NO_LIVE_SOURCE with full evidence when --blocked-status
  is requested or when --remine is invoked and no live alert-feed API is available.

CLI shape matches tools/external-corpus-fetch.py (argparse, --json, stdlib-only).

Usage
-----
    # check staleness against registry default TTL
    python3 tools/defimon-staleness-check.py

    # emit typed BLOCKED_NO_LIVE_SOURCE status (I2 spec compliance)
    python3 tools/defimon-staleness-check.py --blocked-status --json

    # run bounded live preflight for durable machine-readable surfaces
    python3 tools/defimon-staleness-check.py --live-preflight --json

    # override registry + TTL
    python3 tools/defimon-staleness-check.py \\
        --registry reference/corpus_registry.json \\
        --slug defimon \\
        --ttl-days 14 \\
        --json

    # check + update last_mined timestamp without network scrape (stub intent)
    python3 tools/defimon-staleness-check.py --remine --dry-run

    # check + trigger real re-mine (blocked; emits BLOCKED_NO_LIVE_SOURCE)
    python3 tools/defimon-staleness-check.py --remine
"""
from __future__ import annotations

import argparse
import datetime
import html.parser
import json
import pathlib
import subprocess
import sys
import re
import urllib.error
import urllib.request

_HERE = pathlib.Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent
_DEFAULT_REGISTRY = _REPO_ROOT / "reference" / "corpus_registry.json"
_DEFAULT_TIMEOUT_SECONDS = 20.0
_DEFAULT_MAX_BYTES = 192 * 1024
_USER_AGENT = "auditooor-defimon-live-preflight/1.0"

_PRIMARY_PUBLIC_SOURCES = (
    "https://t.me/s/defimon_alerts",
    "https://defimon.xyz/blog",
)
_STRUCTURED_ENDPOINT_PROBES = (
    "https://defimon.xyz/rss.xml",
    "https://defimon.xyz/feed.xml",
    "https://defimon.xyz/atom.xml",
    "https://defimon.xyz/sitemap.xml",
)

_MACHINE_CONTENT_TYPES = (
    "application/json",
    "application/feed+json",
    "application/rss+xml",
    "application/atom+xml",
    "text/xml",
    "application/xml",
)
_DEFIMON_ORIGIN = "https://defimon.xyz"
_DEFIMON_BLOG_URL = f"{_DEFIMON_ORIGIN}/blog"
_NEXTJS_BUILD_MANIFEST_PATH = "/_next/static/{build_id}/_buildManifest.js"
_NEXTJS_SSG_MANIFEST_PATH = "/_next/static/{build_id}/_ssgManifest.js"
_NEXTJS_DATA_BLOG_PATH = "/_next/data/{build_id}/blog.json"
_NEXTJS_BLOG_BUILD_RE = re.compile(r"/_next/static/([A-Za-z0-9_-]+)/_buildManifest\.js")
_NEXTJS_REQUIRED_ROUTES = ("/blog", "/blog/[slug]")


def _extract_nextjs_build_id(html: str) -> str | None:
    """Return a Next.js blog build id discovered from /blog HTML."""
    match = _NEXTJS_BLOG_BUILD_RE.search(html or "")
    return match.group(1) if match else None


def _nextjs_manifest_contains_blog_routes(manifest_body: str) -> set[str]:
    """Return blog routes found in a Next.js manifest payload."""
    normalized = (manifest_body or "").replace("\\/", "/")
    found: set[str] = set()
    for route in _NEXTJS_REQUIRED_ROUTES:
        # Match exact quoted route tokens. A plain substring check would treat
        # "/blog/[slug]" as evidence for "/blog".
        if re.search(rf'["\']{re.escape(route)}["\']', normalized):
            found.add(route)
    return found



def _validate_live_preflight_bounds(timeout: float, max_bytes: int) -> None:
    if timeout <= 0:
        raise ValueError("--timeout-seconds must be greater than 0")
    if max_bytes <= 0:
        raise ValueError("--max-bytes must be greater than 0")


# ---------------------------------------------------------------------------
# Registry helpers
# ---------------------------------------------------------------------------

def _load_registry(path: pathlib.Path) -> dict:
    if not path.exists():
        print(f"[defimon-staleness-check] ERR registry not found: {path}", file=sys.stderr)
        sys.exit(2)
    with path.open() as fh:
        return json.load(fh)


def _find_slug(registry: dict, slug: str) -> dict | None:
    """Return the extended_corpora entry for slug, or None."""
    for entry in registry.get("extended_corpora", []):
        if entry.get("slug") == slug:
            return entry
    return None


def _save_registry(path: pathlib.Path, registry: dict) -> None:
    path.write_text(json.dumps(registry, indent=2) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Live-source preflight
# ---------------------------------------------------------------------------

class _AlternateLinkParser(html.parser.HTMLParser):
    """Collect durable alternate machine-source hints from HTML link tags."""

    def __init__(self) -> None:
        super().__init__()
        self.alternates: list[dict] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "link":
            return
        attr = {name.lower(): value or "" for name, value in attrs}
        rel = attr.get("rel", "").lower()
        content_type = attr.get("type", "").lower()
        href = attr.get("href", "")
        if "alternate" not in rel or not href:
            return
        if any(marker in content_type for marker in _MACHINE_CONTENT_TYPES):
            self.alternates.append(
                {
                    "href": href,
                    "type": content_type,
                    "title": attr.get("title", ""),
                }
            )


def _read_bounded_url(
    url: str,
    timeout: float,
    max_bytes: int,
    *,
    include_body: bool = False,
) -> dict:
    """Fetch at most max_bytes from url and return transport-level evidence."""
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": _USER_AGENT,
            "Accept": (
                "application/json, application/rss+xml, application/atom+xml, "
                "text/xml, text/html;q=0.8, */*;q=0.1"
            ),
        },
    )
    result: dict = {
        "url": url,
        "ok": False,
        "status_code": None,
        "content_type": None,
        "bytes_read": 0,
        "machine_content_type": False,
        "alternate_machine_links": [],
        "error": None,
    }
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status = getattr(response, "status", None) or response.getcode()
            headers = response.headers
            content_type = headers.get("content-type", "")
            body = response.read(max_bytes + 1)
    except urllib.error.HTTPError as exc:
        status = exc.code
        headers = exc.headers
        content_type = headers.get("content-type", "") if headers else ""
        try:
            body = exc.read(max_bytes + 1)
        except Exception:
            body = b""
        result["error"] = f"http_error:{exc.code}"
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        result["error"] = f"{type(exc).__name__}:{exc}"
        return result

    body = body[:max_bytes]
    lowered_type = content_type.lower()
    result.update(
        {
            "ok": 200 <= int(status or 0) < 400,
            "status_code": status,
            "content_type": content_type,
            "bytes_read": len(body),
            "machine_content_type": any(marker in lowered_type for marker in _MACHINE_CONTENT_TYPES),
        }
    )
    if include_body:
        result["body"] = body.decode("utf-8", errors="replace")

    if "text/html" in lowered_type and body:
        parser = _AlternateLinkParser()
        parser.feed(body.decode("utf-8", errors="ignore"))
        result["alternate_machine_links"] = parser.alternates

    return result


def build_live_preflight(timeout: float = _DEFAULT_TIMEOUT_SECONDS, max_bytes: int = _DEFAULT_MAX_BYTES) -> dict:
    """Run a bounded no-secret preflight for Defimon machine-source availability.

    This intentionally does not extract incidents, post IDs, article titles, or
    exploit mechanics from HTML pages. It only answers whether a stable
    machine-readable source appears to exist.
    """
    _validate_live_preflight_bounds(timeout, max_bytes)
    checked = [
        _read_bounded_url(
            url,
            timeout=timeout,
            max_bytes=max_bytes,
            include_body=(url == _DEFIMON_BLOG_URL),
        )
        for url in (*_PRIMARY_PUBLIC_SOURCES, *_STRUCTURED_ENDPOINT_PROBES)
    ]
    candidates = []
    seen_candidate_urls: set[str] = set()

    def _append_candidate(candidate: dict) -> None:
        url = str(candidate.get("url") or "")
        if not url or url in seen_candidate_urls:
            return
        seen_candidate_urls.add(url)
        candidates.append(candidate)

    # Lightweight Next.js SSG candidate probe for /blog index JSON:
    # - discover build id from /blog HTML,
    # - verify manifest routes include blog and blog/[slug],
    # - and confirm _next/data/<build-id>/blog.json returns JSON.
    blog_row = next((row for row in checked if row["url"] == _DEFIMON_BLOG_URL), None)
    if blog_row and blog_row.get("ok") and isinstance(blog_row.get("body"), str):
        build_id = _extract_nextjs_build_id(blog_row["body"])
    else:
        build_id = None
    if build_id:
        build_manifest_url = f"{_DEFIMON_ORIGIN}{_NEXTJS_BUILD_MANIFEST_PATH.format(build_id=build_id)}"
        ssg_manifest_url = f"{_DEFIMON_ORIGIN}{_NEXTJS_SSG_MANIFEST_PATH.format(build_id=build_id)}"
        index_url = f"{_DEFIMON_ORIGIN}{_NEXTJS_DATA_BLOG_PATH.format(build_id=build_id)}"
        build_manifest_row = _read_bounded_url(build_manifest_url, timeout=timeout, max_bytes=max_bytes, include_body=True)
        ssg_manifest_row = _read_bounded_url(ssg_manifest_url, timeout=timeout, max_bytes=max_bytes, include_body=True)
        index_row = _read_bounded_url(index_url, timeout=timeout, max_bytes=max_bytes)
        checked.extend([build_manifest_row, ssg_manifest_row, index_row])
        build_manifest_routes = _nextjs_manifest_contains_blog_routes(build_manifest_row.get("body", ""))
        ssg_manifest_routes = _nextjs_manifest_contains_blog_routes(ssg_manifest_row.get("body", ""))
        required_routes_present = {
            route: route in (build_manifest_routes | ssg_manifest_routes)
            for route in _NEXTJS_REQUIRED_ROUTES
        }
        if (
            build_manifest_row.get("ok")
            and ssg_manifest_row.get("ok")
            and all(required_routes_present.values())
            and index_row.get("machine_content_type")
        ):
            _append_candidate(
                {
                    "url": index_url,
                    "status_code": index_row.get("status_code"),
                    "content_type": index_row.get("content_type"),
                    "reason": "nextjs_ssg_blog_json_candidate",
                    "discovered_from": _DEFIMON_BLOG_URL,
                    "build_id": build_id,
                    "requires_runtime_build_discovery": True,
                    "required_routes_present": required_routes_present,
                }
            )

    for row in checked:
        if not (row.get("ok") and row.get("machine_content_type")):
            continue
        if row["url"].endswith("/sitemap.xml"):
            # A sitemap can help manual discovery, but it is not an incident feed.
            continue
        _append_candidate(
            {
                "url": row["url"],
                "status_code": row["status_code"],
                "content_type": row["content_type"],
                "reason": "machine content-type",
            }
        )
    for row in checked:
        for alternate in row.get("alternate_machine_links", []):
            _append_candidate(
                {
                    "url": alternate.get("href"),
                    "discovered_on": row["url"],
                    "content_type": alternate.get("type"),
                    "reason": "html alternate link",
                }
            )

    status = "MACHINE_SOURCE_CANDIDATE_FOUND" if candidates else "BLOCKED_NO_MACHINE_SOURCE"
    return {
        "schema": "auditooor.defimon_live_preflight.v1",
        "source_id": "defimon_delta_blocked_no_live_source",
        "slug": "defimon",
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "status": status,
        "network_performed": True,
        "secret_required": False,
        "timeout_seconds": timeout,
        "max_bytes_per_url": max_bytes,
        "automation_boundary": (
            "Preflight only: checks headers, content types, known feed endpoints, "
            "known Next.js SSG markers, and HTML alternate-link machine-source hints. "
            "It does not scrape or mine Telegram/blog HTML incident content."
        ),
        "sources_checked": checked,
        "candidate_machine_sources": candidates,
        "safe_miner_available": bool(candidates),
        "next_action": (
            "review_candidate_machine_source_before_miner"
            if candidates
            else "keep_blocked_or_use_manual_review"
        ),
    }


# ---------------------------------------------------------------------------
# Staleness logic
# ---------------------------------------------------------------------------

def _compute_staleness(entry: dict, ttl_days: int | None) -> dict:
    """Return a staleness report dict."""
    staleness = entry.get("staleness", {})
    last_mined_raw = staleness.get("last_mined")
    effective_ttl = ttl_days if ttl_days is not None else staleness.get("ttl_days", 30)

    now = datetime.datetime.now(datetime.timezone.utc)

    if last_mined_raw is None:
        age_days = None
        is_stale = True
        status = "never_mined"
    else:
        try:
            last_mined_dt = datetime.datetime.fromisoformat(last_mined_raw.rstrip("Z")).replace(
                tzinfo=datetime.timezone.utc
            )
            age_days = (now - last_mined_dt).days
            is_stale = age_days >= effective_ttl
            status = "stale" if is_stale else "fresh"
        except ValueError:
            age_days = None
            is_stale = True
            status = "parse_error"

    return {
        "slug": entry.get("slug", "defimon"),
        "last_mined": last_mined_raw,
        "last_commit_sha": entry.get("last_commit_sha"),
        "last_commit_msg": entry.get("last_commit_msg"),
        "age_days": age_days,
        "ttl_days": effective_ttl,
        "is_stale": is_stale,
        "status": status,
        "produces": entry.get("produces"),
        "source": entry.get("source"),
    }


# ---------------------------------------------------------------------------
# BLOCKED_NO_LIVE_SOURCE status builder (I2 spec)
# ---------------------------------------------------------------------------

# Evidence record for the BLOCKED_NO_LIVE_SOURCE verdict.
# This is the canonical evidence that no automatable live API exists.
_BLOCKED_EVIDENCE: dict = {
    "sources_checked": [
        {
            "url": "https://t.me/s/defimon_alerts",
            "type": "public_telegram_channel_mirror",
            "api_available": False,
            "reason": (
                "HTML-only public mirror; no JSON API, no cursor-compatible endpoint, "
                "bot-detection blocks automated HTTP scraping. Prior mining used manual "
                "review of posts 2332-3038 (2026-05-20)."
            ),
        },
        {
            "url": "https://defimon.xyz/blog",
            "type": "public_blog_html",
            "api_available": False,
            "blog_only_machine_source_available": True,
            "reason": (
                "No public RSS/live-cursor API with structured exploit data. A bounded "
                "Next.js SSG blog JSON route is runtime-discoverable and handled by "
                "tools/defimon-nextjs-blog-miner.py, but it covers blog posts only and "
                "does not replace the missing alert-feed/Telegram cursor source."
            ),
        },
        {
            "url": "https://de.fi/rekt-database",
            "type": "web_ui_only",
            "api_available": False,
            "reason": (
                "Web UI only; no public REST API documented. Referenced in prior stub "
                "as potential scrape target but blocked: no stable JSON endpoint, "
                "rate-limiting on unauthenticated requests."
            ),
        },
    ],
    "prior_mine_method": "manual_review",
    "prior_mine_date": "2026-05-20",
    "prior_mine_posts_reviewed": "2332-3038 (Telegram) + 6 blog writeups",
    "prior_mine_output": (
        "reference/patterns.dsl.r98_defimon_refresh_20260520 (Transit callBytes self-call pattern) + "
        "reference/patterns.dsl.r99_defimon_blog_refresh_20260520 (5 patterns) + "
        "audit/corpus_tags/tags/defimon_blog_incidents (6 records)"
    ),
    "unblock_path": (
        "Either: (a) accept blog-only coverage through tools/defimon-nextjs-blog-miner.py "
        "for roadmap source-mining; (b) implement a headless-browser scraper "
        "(Playwright/Selenium) for the Telegram public mirror; (c) wait for Defimon "
        "to expose a public REST API/RSS/cursor feed with structured incident data; "
        "or (d) continue manual-review mining on a per-sprint cadence."
    ),
}


def build_blocked_status(entry: dict | None, staleness_report: dict | None) -> dict:
    """Build a typed BLOCKED_NO_LIVE_SOURCE status record."""
    return {
        "status": "BLOCKED_NO_LIVE_SOURCE",
        "schema": "auditooor.defimon_blocked_status.v1",
        "source_id": "defimon_delta_blocked_no_live_source",
        "slug": "defimon",
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "staleness": staleness_report,
        "registry_entry_source": (entry or {}).get("source", "N/A"),
        "blocked_evidence": _BLOCKED_EVIDENCE,
        "next_action": "manual_review_or_wait_for_api",
        "network_performed": False,
    }


# ---------------------------------------------------------------------------
# Re-mine handler (emits BLOCKED_NO_LIVE_SOURCE; no actual scrape)
# ---------------------------------------------------------------------------

def _do_remine(
    entry: dict,
    registry: dict,
    registry_path: pathlib.Path,
    dry_run: bool,
    json_out: bool = False,
) -> int:
    """Handle --remine for defimon.

    Defimon has NO automatable live API. This function emits a typed
    BLOCKED_NO_LIVE_SOURCE status (I2 spec requirement) rather than
    silently failing or pretending to scrape.

    The stub path that called external-corpus-fetch.py --kind defimon
    is removed: that tool does not support defimon, and the command would
    always fail. Instead we emit honest blocked status.
    """
    staleness = _compute_staleness(entry, None)
    blocked = build_blocked_status(entry, staleness)

    if json_out:
        print(json.dumps(blocked, indent=2))
    else:
        print(
            f"[defimon-staleness-check] BLOCKED_NO_LIVE_SOURCE: no automatable API exists. "
            f"Last manual mine: {staleness.get('last_mined', 'never')}. "
            f"Unblock path: {_BLOCKED_EVIDENCE['unblock_path'][:120]}...",
            file=sys.stderr,
        )

    if dry_run:
        print("[defimon-staleness-check] DRY RUN — registry not updated.", file=sys.stderr)
        return 0

    # Do NOT update registry last_mined: no actual mine was performed.
    # Record only the blocked-status check time in a sidecar if desired.
    print(
        "[defimon-staleness-check] Registry NOT updated (BLOCKED_NO_LIVE_SOURCE; "
        "no actual ingest performed).",
        file=sys.stderr,
    )
    return 2  # exit 2 = blocked (distinct from 0=ok, 1=stale)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Check defimon corpus staleness; emit BLOCKED_NO_LIVE_SOURCE status.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--registry",
        metavar="PATH",
        default=str(_DEFAULT_REGISTRY),
        help=f"Path to corpus_registry.json (default: {_DEFAULT_REGISTRY})",
    )
    p.add_argument(
        "--slug",
        metavar="SLUG",
        default="defimon",
        help="Extended corpus slug to check (default: defimon)",
    )
    p.add_argument(
        "--ttl-days",
        metavar="N",
        type=int,
        default=None,
        help="Override TTL in days (default: use registry entry's ttl_days field)",
    )
    p.add_argument(
        "--json",
        dest="json_out",
        action="store_true",
        help="Print JSON report to stdout",
    )
    p.add_argument(
        "--blocked-status",
        action="store_true",
        help=(
            "Emit a typed BLOCKED_NO_LIVE_SOURCE status record with evidence "
            "(I2 spec compliance). Implies --json."
        ),
    )
    p.add_argument(
        "--live-preflight",
        action="store_true",
        help=(
            "Perform a bounded no-secret network preflight for durable machine-readable "
            "Defimon sources. Does not scrape incident content."
        ),
    )
    p.add_argument(
        "--timeout-seconds",
        type=float,
        default=_DEFAULT_TIMEOUT_SECONDS,
        help=f"Per-request timeout for --live-preflight (default: {_DEFAULT_TIMEOUT_SECONDS:g})",
    )
    p.add_argument(
        "--max-bytes",
        type=int,
        default=_DEFAULT_MAX_BYTES,
        help=f"Maximum bytes to read per URL for --live-preflight (default: {_DEFAULT_MAX_BYTES})",
    )
    p.add_argument(
        "--remine",
        action="store_true",
        help=(
            "If stale, emit BLOCKED_NO_LIVE_SOURCE (no automatable live API exists). "
            "Does NOT trigger any network scrape."
        ),
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="With --remine: print blocked status but do not update registry",
    )
    return p.parse_args(argv)


def run(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    registry_path = pathlib.Path(args.registry).expanduser().resolve()
    registry = _load_registry(registry_path)

    entry = _find_slug(registry, args.slug)
    if entry is None:
        print(
            f"[defimon-staleness-check] ERR slug '{args.slug}' not found in extended_corpora of {registry_path}",
            file=sys.stderr,
        )
        sys.exit(2)

    report = _compute_staleness(entry, args.ttl_days)

    if args.live_preflight:
        try:
            preflight = build_live_preflight(timeout=args.timeout_seconds, max_bytes=args.max_bytes)
        except ValueError as exc:
            print(f"[defimon-staleness-check] ERR {exc}", file=sys.stderr)
            return 2
        print(json.dumps(preflight, indent=2))
        return 0

    # --blocked-status: emit the typed BLOCKED_NO_LIVE_SOURCE record and exit 0.
    if args.blocked_status:
        blocked = build_blocked_status(entry, report)
        print(json.dumps(blocked, indent=2))
        return 0

    if args.json_out:
        print(json.dumps(report, indent=2))
    else:
        status_label = "STALE" if report["is_stale"] else "FRESH"
        age_str = f"{report['age_days']}d" if report["age_days"] is not None else "unknown"
        print(
            f"[defimon-staleness-check] {args.slug}: {status_label} "
            f"(age={age_str}, ttl={report['ttl_days']}d, last_mined={report['last_mined']})"
        )

    if report["is_stale"] and args.remine:
        return _do_remine(
            entry,
            registry,
            registry_path,
            dry_run=args.dry_run,
            json_out=args.json_out,
        )

    # Exit 1 if stale and no --remine (callers can use || true to soft-fail)
    return 1 if report["is_stale"] else 0


if __name__ == "__main__":
    sys.exit(run())
