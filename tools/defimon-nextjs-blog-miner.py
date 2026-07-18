#!/usr/bin/env python3
"""Defimon Next.js static-blog SSG preflight/miner.

This tool discovers the current Next.js build id from the public
``/blog`` page, validates that the SSG/build manifests contain blog routes,
fetches ``/_next/data/<build-id>/blog.json`` and then, bounded by
``--max-posts``, fetches each corresponding per-post JSON payload.

Offline testing is supported via ``--inject-fixtures``. The fixture is a JSON
mapping from URL -> body or a structured record:

``{"<url>": "..."}``

or

``{"<url>": {"status_code": 200, "content_type": "application/json", "body": "..."}}``

If fixtures are provided, all network calls become strictly fixture-backed.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

TOOL_NAME = "defimon-nextjs-blog-miner"
SCHEMA = "auditooor.defimon_nextjs_blog_miner.v1"
SOURCE = "https://defimon.xyz/blog"
BASE_URL = "https://defimon.xyz"
DEFAULT_TIMEOUT_SECONDS = 20.0
DEFAULT_MAX_POSTS = 0  # 0 = unbounded
MAX_BYTES_PER_FETCH = 2_000_000
USER_AGENT = f"{TOOL_NAME}/1.0"

BLOG_ID_RE = re.compile(r"/_next/static/([A-Za-z0-9_-]+)/_buildManifest\.js")
MANIFEST_ROUTE_RE = re.compile(r'"(/blog(?:/\[slug\])?)"')
BUILD_ID_MISSING = "build-id-missing"


def _as_text(body: bytes) -> str:
    return body.decode("utf-8", errors="replace")


def extract_build_id_from_blog_html(html: str) -> str | None:
    """Return the build id from ``/_next/static/<id>/_buildManifest.js``."""
    m = BLOG_ID_RE.search(html or "")
    return m.group(1) if m else None


def _extract_jsonish_object(manifest_text: str) -> Any:
    """Parse a Next.js JS manifest assignment into JSON when possible."""
    normalized = (manifest_text or "").replace("\\/", "/").strip()
    if not normalized:
        return None

    candidates = [normalized]
    eq = normalized.find("=")
    if eq >= 0:
        candidates.append(normalized[eq + 1:].strip().rstrip(";"))

    for candidate in candidates:
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            continue
    return None


def _walk_manifest_routes(value: Any) -> set[str]:
    routes: set[str] = set()
    wanted = {"/blog", "/blog/[slug]"}
    if isinstance(value, dict):
        for key, child in value.items():
            if isinstance(key, str) and key in wanted:
                routes.add(key)
            if key in {"pages", "routes", "sortedPages", "__rewrites"}:
                routes.update(_walk_manifest_routes(child))
            elif isinstance(child, (dict, list)):
                routes.update(_walk_manifest_routes(child))
    elif isinstance(value, list):
        for child in value:
            routes.update(_walk_manifest_routes(child))
    elif isinstance(value, str) and value in wanted:
        routes.add(value)
    return routes


def extract_manifest_routes(manifest_text: str) -> set[str]:
    """Return blog routes from known Next.js manifest structures."""
    parsed = _extract_jsonish_object(manifest_text)
    if parsed is not None:
        return _walk_manifest_routes(parsed)

    # Fallback for partially captured JS payloads. Keep this narrow to avoid
    # treating arbitrary prose as manifest route evidence.
    normalized = (manifest_text or "").replace("\\/", "/")
    if "__BUILD_MANIFEST" not in normalized and "__SSG_MANIFEST" not in normalized:
        return set()
    routes = set(MANIFEST_ROUTE_RE.findall(normalized))
    return {route for route in routes if route in {"/blog", "/blog/[slug]"}}


def _normalize_url(url: str) -> str:
    return url.strip()


def _coerce_fixture_entry(entry: Any) -> tuple[int, str, bytes]:
    if isinstance(entry, bytes):
        return 200, "application/octet-stream", entry
    if isinstance(entry, str):
        return 200, "text/plain", entry.encode("utf-8")
    if isinstance(entry, dict):
        body = entry.get("body", b"")
        if isinstance(body, str):
            body = body.encode("utf-8")
        elif not isinstance(body, (bytes, bytearray)):
            body = _as_text(json.dumps(body)).encode("utf-8")
        status = int(entry.get("status_code", 200))
        content_type = str(entry.get("content_type", "text/plain"))
        return status, content_type, bytes(body)
    return 200, "text/plain", str(entry).encode("utf-8")


def _load_fixtures(path: Path | None) -> dict[str, dict[str, Any]]:
    if path is None:
        return {}
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("--inject-fixtures JSON must be an object mapping URL -> body/record")
    out: dict[str, dict[str, Any]] = {}
    for url, entry in raw.items():
        status_code, content_type, body = _coerce_fixture_entry(entry)
        out[_normalize_url(str(url))] = {
            "status_code": status_code,
            "content_type": content_type,
            "body": body,
        }
    return out


def _fetch_url(
    url: str,
    *,
    timeout_seconds: float,
    fixtures: dict[str, dict[str, Any]],
    max_bytes: int = MAX_BYTES_PER_FETCH,
    strict_fixtures: bool = False,
) -> dict[str, Any]:
    """Fetch one URL and return a dict with status, content-type, and bytes."""
    normalized = _normalize_url(url)
    if normalized in fixtures:
        entry = fixtures[normalized]
        body = entry["body"]
        if isinstance(body, str):
            body = body.encode("utf-8")
        body = bytes(body or b"")
        return {
            "url": normalized,
            "status_code": int(entry.get("status_code", 200)),
            "content_type": str(entry.get("content_type", "")),
            "body": body[:max_bytes],
            "from_fixture": True,
        }

    if strict_fixtures:
        raise RuntimeError(f"missing fixture for URL: {normalized}")

    req = urllib.request.Request(
        normalized,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": (
                "application/json, text/html, application/javascript, */*;q=0.2"
            ),
        },
    )
    with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
        status = int(getattr(resp, "status", 200))
        content_type = str(getattr(resp.headers, "get", lambda *_: "")("content-type") or "")
        body = resp.read(max_bytes + 1)
    return {
        "url": normalized,
        "status_code": status,
        "content_type": content_type,
        "body": body[:max_bytes],
        "from_fixture": False,
    }


def _safe_fetch(
    url: str,
    *,
    timeout_seconds: float,
    fixtures: dict[str, dict[str, Any]],
    strict_fixtures: bool,
) -> tuple[dict[str, Any] | None, str | None]:
    try:
        return (
            _fetch_url(
                url,
                timeout_seconds=timeout_seconds,
                fixtures=fixtures,
                strict_fixtures=strict_fixtures,
            ),
            None,
        )
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return None, f"network error while fetching {url}: {exc}"
    except ValueError as exc:
        return None, f"invalid status/error while fetching {url}: {exc}"
    except RuntimeError as exc:
        return None, str(exc)


def _parse_json(url: str, body: bytes) -> dict[str, Any]:
    try:
        data = json.loads(_as_text(body))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON from {url}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"non-object JSON payload from {url}")
    return data


def _validate_index_payload(payload: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
    page_props = payload.get("pageProps")
    if not isinstance(page_props, dict):
        raise ValueError("blog index payload missing pageProps")

    posts = page_props.get("posts")
    if not isinstance(posts, list):
        raise ValueError("blog index payload missing pageProps.posts array")

    rows: list[dict[str, Any]] = []
    seen_slugs: set[str] = set()
    malformed: list[str] = []

    for idx, item in enumerate(posts):
        if not isinstance(item, dict):
            malformed.append(f"posts[{idx}] is not an object")
            continue
        slug = str(item.get("slug", "")).strip()
        if not slug:
            malformed.append(f"posts[{idx}] missing slug")
            continue
        if slug in seen_slugs:
            continue
        seen_slugs.add(slug)
        rows.append(
            {
                "slug": slug,
                "title": item.get("title"),
                "date": item.get("date"),
                "network_source": item.get("network") or item.get("impact"),
            }
        )

    return rows, malformed


def _validate_post_payload(url: str, payload: dict[str, Any]) -> tuple[str | None, bool]:
    page_props = payload.get("pageProps")
    if not isinstance(page_props, dict):
        return "missing pageProps", False
    post = page_props.get("post")
    if not isinstance(post, dict):
        return "missing pageProps.post", False
    title = post.get("title")
    has_content = bool(post.get("content"))
    if not title:
        return "post.title missing", has_content
    return None, has_content


def mine_defimon_blog(
    *,
    max_posts: int,
    timeout_seconds: float,
    fixtures: dict[str, dict[str, Any]] | None = None,
    strict_fixtures: bool = False,
) -> dict[str, Any]:
    """Execute a bounded preflight/miner run and return a structured report."""
    if max_posts < 0:
        raise ValueError("max_posts must be >= 0")
    if fixtures is None:
        fixtures = {}
    requested_urls: list[str] = []
    errors: list[dict[str, Any]] = []

    def fetch(url: str) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        requested_urls.append(url)
        result, err = _safe_fetch(
            url,
            timeout_seconds=timeout_seconds,
            fixtures=fixtures,
            strict_fixtures=strict_fixtures,
        )
        if err is not None or result is None:
            errors.append({"url": url, "severity": "fatal", "reason": err})
            return None, None
        return result, {"url": url, "status_code": result["status_code"], "from_fixture": result["from_fixture"]}

    report: dict[str, Any] = {
        "schema": SCHEMA,
        "tool": TOOL_NAME,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": SOURCE,
        "build_id": None,
        "manifests": {},
        "index": {"url": None, "status_code": None, "post_count": 0, "posts": []},
        "post_fetches": [],
        "requests": [],
        "errors": [],
    }

    blog_resp, meta = fetch(BLOG_URL := f"{BASE_URL}/blog")
    if not blog_resp:
        report["errors"] = errors
        report["status"] = "failed"
        return report
    report["requests"].append(meta)
    if blog_resp["status_code"] >= 400:
        errors.append({"url": BLOG_URL, "severity": "fatal", "reason": "/blog returned non-2xx"})
        report["errors"] = errors
        report["status"] = "failed"
        return report

    build_id = extract_build_id_from_blog_html(_as_text(blog_resp["body"]))
    report["build_id"] = build_id
    if not build_id:
        errors.append({"url": BLOG_URL, "severity": "fatal", "reason": BUILD_ID_MISSING})
        report["errors"] = errors
        report["status"] = "failed"
        return report

    build_url = f"{BASE_URL}/_next/static/{build_id}/_buildManifest.js"
    ssg_url = f"{BASE_URL}/_next/static/{build_id}/_ssgManifest.js"

    build_resp, build_meta = fetch(build_url)
    if build_resp:
        report["requests"].append(build_meta)
    else:
        report["errors"] = errors
        report["status"] = "failed"
        return report

    ssg_resp, ssg_meta = fetch(ssg_url)
    if ssg_resp:
        report["requests"].append(ssg_meta)
    else:
        report["errors"] = errors
        report["status"] = "failed"
        return report

    build_routes = extract_manifest_routes(_as_text(build_resp["body"])) if build_resp else set()
    ssg_routes = extract_manifest_routes(_as_text(ssg_resp["body"])) if ssg_resp else set()

    has_blog = "/blog" in build_routes or "/blog" in ssg_routes
    has_blog_slug = "/blog/[slug]" in build_routes or "/blog/[slug]" in ssg_routes
    report["manifests"] = {
        "_buildManifest": {
            "url": build_url,
            "status_code": build_resp["status_code"],
            "routes": sorted(build_routes),
        },
        "_ssgManifest": {
            "url": ssg_url,
            "status_code": ssg_resp["status_code"],
            "routes": sorted(ssg_routes),
        },
        "required_routes_present": {
            "/blog": has_blog,
            "/blog/[slug]": has_blog_slug,
        },
    }
    if not (has_blog and has_blog_slug):
        errors.append(
            {
                "url": f"{build_url}, {ssg_url}",
                "severity": "fatal",
                "reason": "required routes missing in Next.js manifests",
            }
        )
        report["errors"] = errors
        report["status"] = "failed"
        return report

    index_url = f"{BASE_URL}/_next/data/{build_id}/blog.json"
    report["index"]["url"] = index_url
    index_resp, index_meta = fetch(index_url)
    if index_resp:
        report["requests"].append(index_meta)
    else:
        report["errors"] = errors
        report["status"] = "failed"
        return report

    if index_resp["status_code"] >= 400:
        errors.append({"url": index_url, "severity": "fatal", "reason": "blog.json non-2xx"})
        report["errors"] = errors
        report["status"] = "failed"
        return report
    report["index"]["status_code"] = index_resp["status_code"]

    try:
        index_payload = _parse_json(index_url, index_resp["body"])
        index_posts, index_malformed = _validate_index_payload(index_payload)
        for issue in index_malformed:
            errors.append({"url": index_url, "severity": "warn", "reason": issue})
    except Exception as exc:  # defensive: keep bounded shape for testability
        errors.append({"url": index_url, "severity": "fatal", "reason": str(exc)})
        report["errors"] = errors
        report["status"] = "failed"
        return report

    if max_posts > 0:
        index_posts = index_posts[:max_posts]

    report["index"]["post_count"] = len(index_posts)
    report["index"]["posts"] = index_posts

    for post in index_posts:
        slug = post["slug"]
        post_url = f"{BASE_URL}/_next/data/{build_id}/blog/{urllib.parse.quote(slug)}.json?slug={urllib.parse.quote(slug)}"
        post_resp, post_meta = fetch(post_url)
        if not post_resp:
            continue
        report["requests"].append(post_meta)

        if post_resp["status_code"] >= 400:
            report["post_fetches"].append({
                "slug": slug,
                "url": post_url,
                "status_code": post_resp["status_code"],
                "ok": False,
                "has_content": False,
            })
            errors.append({"url": post_url, "severity": "warn", "reason": "post payload non-2xx"})
            continue

        try:
            post_payload = _parse_json(post_url, post_resp["body"])
            warn, has_content = _validate_post_payload(post_url, post_payload)
            row = {
                "slug": slug,
                "url": post_url,
                "status_code": post_resp["status_code"],
                "ok": True,
                "has_content": has_content,
            }
            if warn:
                row["warning"] = warn
                errors.append({"url": post_url, "severity": "warn", "reason": warn})
            report["post_fetches"].append(row)
        except Exception as exc:
            report["post_fetches"].append({
                "slug": slug,
                "url": post_url,
                "status_code": post_resp["status_code"],
                "ok": False,
                "has_content": False,
            })
            errors.append({"url": post_url, "severity": "warn", "reason": str(exc)})

    report["errors"] = errors
    if any(item["severity"] == "fatal" for item in errors):
        report["status"] = "failed"
    elif any(item["severity"] == "warn" for item in errors):
        report["status"] = "partial"
    else:
        report["status"] = "ok"

    report["requests_count"] = len(requested_urls)
    report["requested_urls"] = requested_urls
    return report


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Mine bounded Defimon Next.js static-blog SSG payloads.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--max-posts",
        type=int,
        default=DEFAULT_MAX_POSTS,
        help="Maximum number of posts to fetch from the index payload (0 = unbounded)",
    )
    p.add_argument(
        "--timeout-seconds",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
        help=f"Per-request timeout (default: {DEFAULT_TIMEOUT_SECONDS:g})",
    )
    p.add_argument(
        "--json-only",
        action="store_true",
        help="Print report JSON only (no human-readable lines)",
    )
    p.add_argument(
        "--inject-fixtures",
        help="Path to JSON fixture map for offline tests (strict offline mode when provided)",
    )
    return p.parse_args(argv)


def run(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.max_posts < 0:
        raise ValueError("--max-posts must be >= 0")
    if args.timeout_seconds <= 0:
        raise ValueError("--timeout-seconds must be > 0")

    fixture_path = Path(args.inject_fixtures).expanduser().resolve() if args.inject_fixtures else None
    fixtures = _load_fixtures(fixture_path) if fixture_path else {}

    report = mine_defimon_blog(
        max_posts=args.max_posts,
        timeout_seconds=args.timeout_seconds,
        fixtures=fixtures,
        strict_fixtures=fixture_path is not None,
    )

    if args.json_only:
        print(json.dumps(report, indent=2))
    else:
        # Keep output compact and bounded for readability in local use.
        status = report.get("status", "failed")
        count = len(report.get("post_fetches", []))
        print(f"{TOOL_NAME}: status={status}, build_id={report.get('build_id')}, posts={count}")
        if report.get("errors"):
            for row in report["errors"]:
                print(f"- {row['severity']}: {row['reason']}")

    status = report.get("status")
    if status == "failed":
        return 2
    if status == "partial":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(run())
