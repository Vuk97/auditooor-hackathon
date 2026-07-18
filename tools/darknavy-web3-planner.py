#!/usr/bin/env python3
"""Offline-first planner for DARKNAVY Web3 archive ingestion.

The live source is https://www.darknavy.org/web3/.  This tool deliberately
does not fetch it by default.  It emits the page URLs, stable source IDs,
cursor path, and ETL task rows a later live fetcher can consume.  If local
HTML snapshots are supplied, it also extracts article links from those
snapshots without touching the network.
"""
from __future__ import annotations

import argparse
import html
import json
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse


SCHEMA = "auditooor.darknavy_web3_planner.v1"
TASK_SCHEMA = "auditooor.darknavy_web3_etl_task.v1"
BASE_URL = "https://www.darknavy.org/web3/"
MAX_PAGE = 8
DEFAULT_CURSOR_PATH = Path(".auditooor/external_intel_cursors/darknavy_web3.json")
DEFAULT_OUT = Path("reports/darknavy_web3_plan.json")
SOURCE_ID_PREFIX = "darknavy_web3"
ARTICLE_SKIP_SEGMENTS = {
    "author",
    "category",
    "page",
    "tag",
    "tags",
    "wp-content",
}

HREF_RE = re.compile(
    r"""<a\b[^>]*?\bhref\s*=\s*(?:"(?P<double>[^"]+)"|'(?P<single>[^']+)'|(?P<bare>[^\s>]+))""",
    re.IGNORECASE | re.DOTALL,
)


def page_url(page: int) -> str:
    if page == 1:
        return BASE_URL
    return f"{BASE_URL}page/{page}/"


def page_source_id(page: int) -> str:
    return f"{SOURCE_ID_PREFIX}_page_{page}"


def article_source_id(url: str) -> str:
    parsed = urlparse(url)
    slug = parsed.path.strip("/").split("/")[-1] or "article"
    slug = re.sub(r"[^a-zA-Z0-9_.-]+", "-", slug).strip("-._").lower()
    return f"{SOURCE_ID_PREFIX}_article_{slug or 'article'}"


def validate_page_range(start_page: int, end_page: int) -> None:
    if start_page < 1:
        raise ValueError("start page must be >= 1")
    if end_page > MAX_PAGE:
        raise ValueError(f"end page must be <= {MAX_PAGE}")
    if start_page > end_page:
        raise ValueError("start page must be <= end page")


def planned_pages(start_page: int = 1, end_page: int = MAX_PAGE) -> list[dict[str, Any]]:
    validate_page_range(start_page, end_page)
    return [
        {
            "page": page,
            "url": page_url(page),
            "source_id": page_source_id(page),
        }
        for page in range(start_page, end_page + 1)
    ]


def _clean_href(value: str) -> str:
    return html.unescape(value.strip()).split("#", 1)[0]


def _is_article_url(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return False
    if parsed.netloc.lower() != "www.darknavy.org":
        return False
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if not parts:
        return False
    # The current Web3 archive includes skills, language switches, RSS links,
    # and generic site navigation. Only exploit reports are case-study records.
    if not (len(parts) >= 3 and parts[0] == "web3" and parts[1] == "exploits"):
        return False
    if parts[0] in ARTICLE_SKIP_SEGMENTS:
        return False
    if any(part in ARTICLE_SKIP_SEGMENTS for part in parts):
        return False
    return True


def extract_article_links(html_text: str, *, base_url: str = BASE_URL) -> list[str]:
    """Return de-duplicated DARKNAVY article URLs from one archive page."""
    links: list[str] = []
    seen: set[str] = set()
    for match in HREF_RE.finditer(html_text):
        href = match.group("double") or match.group("single") or match.group("bare") or ""
        href = _clean_href(href)
        if not href:
            continue
        url = urljoin(base_url, href)
        if not _is_article_url(url):
            continue
        if not url.endswith("/"):
            url += "/"
        if url not in seen:
            seen.add(url)
            links.append(url)
    return links


def _candidate_html_names(page: int) -> list[str]:
    if page == 1:
        return [
            "web3.html",
            "web3.htm",
            "page-1.html",
            "page1.html",
            "1.html",
            "index.html",
        ]
    return [
        f"page-{page}.html",
        f"page{page}.html",
        f"{page}.html",
        f"web3-page-{page}.html",
        f"web3_page_{page}.html",
    ]


def local_html_path(local_html_dir: Path, page: int) -> Path | None:
    for name in _candidate_html_names(page):
        candidate = local_html_dir / name
        if candidate.exists():
            return candidate
    return None


def _relpath(repo_root: Path, path: Path) -> str:
    try:
        return str(path.resolve().relative_to(repo_root.resolve()))
    except ValueError:
        return str(path)


def build_etl_task_rows(
    pages: list[dict[str, Any]],
    *,
    cursor_path: Path,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for page in pages:
        rows.append(
            {
                "schema": TASK_SCHEMA,
                "task_id": f"fetch_{page['source_id']}",
                "task_type": "darknavy_web3_archive_page_fetch",
                "source_id": page["source_id"],
                "url": page["url"],
                "page": page["page"],
                "output_cursor_path": str(cursor_path),
                "network_required": True,
                "advisory_only": True,
                "expected_next_action": "fetch page HTML, cache payload hash, then extract article links",
            }
        )
        for article_url in page.get("article_links", []):
            source_id = article_source_id(article_url)
            rows.append(
                {
                    "schema": TASK_SCHEMA,
                    "task_id": f"fetch_{source_id}",
                    "task_type": "darknavy_web3_article_fetch",
                    "source_id": source_id,
                    "url": article_url,
                    "discovered_from_source_id": page["source_id"],
                    "output_cursor_path": str(cursor_path),
                    "network_required": True,
                    "advisory_only": True,
                    "expected_next_action": "fetch article HTML and emit a DARKNAVY source record",
                }
            )
    return rows


def build_plan(
    *,
    repo_root: Path,
    start_page: int = 1,
    end_page: int = MAX_PAGE,
    cursor_path: Path = DEFAULT_CURSOR_PATH,
    local_html_dir: Path | None = None,
    fetch_requested: bool = False,
) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    cursor_abs = cursor_path if cursor_path.is_absolute() else repo_root / cursor_path
    pages = planned_pages(start_page, end_page)
    local_dir_abs = local_html_dir.resolve() if local_html_dir else None

    for page in pages:
        page["article_links"] = []
        if local_dir_abs:
            html_path = local_html_path(local_dir_abs, page["page"])
            if html_path:
                page["local_html_path"] = _relpath(repo_root, html_path)
                text = html_path.read_text(encoding="utf-8", errors="replace")
                page["article_links"] = extract_article_links(text, base_url=page["url"])
            else:
                page["local_html_path"] = None

    task_rows = build_etl_task_rows(pages, cursor_path=cursor_abs)
    planned_url_rows = [{"page": page["page"], "url": page["url"]} for page in pages]
    article_urls = [url for page in pages for url in page.get("article_links", [])]

    return {
        "schema": SCHEMA,
        "source": "darknavy_web3",
        "base_url": BASE_URL,
        "offline_first": True,
        "fetch_requested": fetch_requested,
        "fetch_mode": "local_html" if local_dir_abs else "plan_only",
        "page_range": {"start": start_page, "end": end_page, "max_supported": MAX_PAGE},
        "planned_urls": planned_url_rows,
        "expected_source_ids": [page["source_id"] for page in pages],
        "output_cursor_path": str(cursor_abs),
        "local_html_dir": str(local_dir_abs) if local_dir_abs else None,
        "pages": pages,
        "article_urls": article_urls,
        "article_count": len(article_urls),
        "etl_task_rows": task_rows,
        "etl_task_count": len(task_rows),
        "network_performed": False,
        "proof_boundary": (
            "Planner output is offline routing metadata only. It does not prove URL "
            "availability, article content, vulnerability relevance, or ingestion readiness."
        ),
    }


def write_plan(plan: dict[str, Any], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--start-page", type=int, default=1)
    parser.add_argument("--end-page", type=int, default=MAX_PAGE)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument(
        "--json",
        action="store_true",
        help="Also print the generated plan JSON to stdout after writing --out.",
    )
    parser.add_argument("--cursor-path", type=Path, default=DEFAULT_CURSOR_PATH)
    parser.add_argument(
        "--local-html-dir",
        type=Path,
        help="Directory of local archive-page HTML snapshots; enables offline extraction.",
    )
    parser.add_argument(
        "--fetch",
        action="store_true",
        help="Accepted for future live mode, but fail-closed unless --local-html-dir is provided.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        validate_page_range(args.start_page, args.end_page)
    except ValueError as exc:
        print(f"PAGE-RANGE-ERROR: {exc}", file=sys.stderr)
        return 2

    if args.fetch and not args.local_html_dir:
        print(
            "FETCH-BLOCKED: live fetching is not implemented for DARKNAVY Web3. "
            "Pass --local-html-dir with saved HTML snapshots for offline extraction.",
            file=sys.stderr,
        )
        return 3

    if args.local_html_dir and not args.local_html_dir.exists():
        print(f"LOCAL-HTML-DIR-MISSING: {args.local_html_dir}", file=sys.stderr)
        return 2

    repo_root = args.repo_root.resolve()
    out_path = args.out if args.out.is_absolute() else repo_root / args.out
    plan = build_plan(
        repo_root=repo_root,
        start_page=args.start_page,
        end_page=args.end_page,
        cursor_path=args.cursor_path,
        local_html_dir=args.local_html_dir,
        fetch_requested=args.fetch,
    )
    write_plan(plan, out_path)
    if args.json:
        print(json.dumps(plan, indent=2, sort_keys=True))
    else:
        print(str(out_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
