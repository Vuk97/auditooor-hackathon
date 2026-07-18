#!/usr/bin/env python3
"""Mine Solodit public issue-language evidence for residual enum blockers.

This tool intentionally uses Solodit's public tRPC surface rather than the
credentialed REST API. It does not read SOLODIT_API_KEY. It caches the public
issue-language enum plus a bounded findings-page scan so a blocker verdict can
be reproduced without relying on private headers or raw browser state.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

TOOL_NAME = "solodit-language-enum-miner"
TOOL_VERSION = "phase-ii10-1.0.0"

PUBLIC_BASE = "https://solodit.cyfrin.io"
TRPC_BASE = f"{PUBLIC_BASE}/api/trpc"
ISSUE_LANGUAGES_PROC = "filters.getIssueLanguages"
FINDINGS_GET_PROC = "findings.get"
BLOCKER_ID = "BLK-V3-SOURCE-SOLODIT-LANGUAGE-ENUM-PROOF"

DEFAULT_TARGETS = ("huff", "leo", "cairo-zk")
TARGET_ENUM_CANDIDATES = {
    "huff": ("Huff", "HUFF", "huff"),
    "leo": ("Leo", "LEO", "leo", "Aleo", "Aleo Leo"),
    "cairo-zk": ("Cairo-ZK", "Cairo ZK", "CairoZK", "Cairo Zero Knowledge", "ZK Cairo"),
}

DEFAULT_FILTERS: Dict[str, Any] = {
    "firms": [],
    "tags": [],
    "forked": [],
    "impact": ["HIGH", "MEDIUM", "LOW", "GAS"],
    "protocolCategory": [],
    "languages": [],
    "reported": {"value": "alltime", "label": "All time"},
    "minFinders": "",
    "maxFinders": "",
    "rarityScore": 1,
    "qualityScore": 1,
    "bookmarked": False,
    "read": True,
    "unread": True,
    "sortField": "Recency",
    "sortDirection": "Desc",
}

TARGET_PATTERNS = {
    "huff": re.compile(r"\bhuff\b", re.IGNORECASE),
    "leo": re.compile(r"\b(?:aleo|leo)\b", re.IGNORECASE),
    "cairo-zk": re.compile(
        r"(?:\bcairo[-\s]?zk\b|\bcairozk\b|\bcairo\s+zero[-\s]+knowledge\b|\bzk\s+cairo\b)",
        re.IGNORECASE,
    ),
}
GENERIC_CAIRO_RE = re.compile(r"\bcairo\b", re.IGNORECASE)


class SoloditMinerError(RuntimeError):
    pass


def devalue_serialize(value: Any) -> str:
    """Serialize JSON-like values in the devalue table shape used by Solodit.

    The current public tRPC client wraps inputs as:
        encodeURIComponent(JSON.stringify(devalue_serialize(input)))

    Only JSON-compatible objects are needed for this miner.
    """
    entries: List[str] = []

    def encode(item: Any) -> int:
        idx = len(entries)
        entries.append("")
        if item is None:
            entries[idx] = "null"
        elif item is True:
            entries[idx] = "true"
        elif item is False:
            entries[idx] = "false"
        elif isinstance(item, int) and not isinstance(item, bool):
            entries[idx] = str(item)
        elif isinstance(item, float):
            if item != item:
                raise ValueError("NaN is not supported by the minimal devalue serializer")
            entries[idx] = json.dumps(item)
        elif isinstance(item, str):
            entries[idx] = json.dumps(item)
        elif isinstance(item, list):
            entries[idx] = "[" + ",".join(str(encode(child)) for child in item) + "]"
        elif isinstance(item, dict):
            parts = []
            for key, child in item.items():
                parts.append(json.dumps(str(key)) + ":" + str(encode(child)))
            entries[idx] = "{" + ",".join(parts) + "}"
        else:
            raise TypeError(f"unsupported value for devalue serialization: {type(item).__name__}")
        return idx

    encode(value)
    return "[" + ",".join(entries) + "]"


def trpc_query_url(procedure: str, input_obj: Optional[Dict[str, Any]] = None) -> str:
    url = f"{TRPC_BASE}/{procedure}"
    if input_obj is None:
        return url
    serialized = devalue_serialize(input_obj)
    encoded = urllib.parse.quote(json.dumps(serialized), safe="")
    return f"{url}?input={encoded}"


def _request_json(url: str, timeout: int, *, retries: int = 3, retry_sleep: float = 8.0) -> Tuple[Dict[str, Any], int]:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "Origin": PUBLIC_BASE,
            "Referer": PUBLIC_BASE + "/",
            "User-Agent": f"{TOOL_NAME}/{TOOL_VERSION}",
        },
    )
    attempt = 0
    while True:
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                body = response.read()
                return json.loads(body.decode("utf-8")), int(response.status)
        except urllib.error.HTTPError as exc:
            preview = exc.read().decode("utf-8", errors="replace")[:500]
            retryable = exc.code in {429, 500, 502, 503, 504} and (
                exc.code != 500 or "Too many requests" in preview
            )
            if retryable and attempt < retries:
                time.sleep(retry_sleep * (attempt + 1))
                attempt += 1
                continue
            raise SoloditMinerError(f"HTTP {exc.code} for {url}: {preview}") from exc
        except urllib.error.URLError as exc:
            if attempt < retries:
                time.sleep(retry_sleep * (attempt + 1))
                attempt += 1
                continue
            raise SoloditMinerError(f"network error for {url}: {exc.reason}") from exc


def trpc_data_string(payload: Dict[str, Any]) -> str:
    if "error" in payload:
        raise SoloditMinerError(f"tRPC error: {payload['error']}")
    try:
        data = payload["result"]["data"]
    except (KeyError, TypeError) as exc:
        raise SoloditMinerError(f"unexpected tRPC payload shape: {payload!r}") from exc
    if not isinstance(data, str):
        raise SoloditMinerError(f"expected tRPC result.data string, got {type(data).__name__}")
    return data


def parse_issue_languages(data: str) -> List[str]:
    match = re.search(r"languages:\[(.*?)\]\s*\}?\s*$", data, flags=re.DOTALL)
    if not match:
        raise SoloditMinerError("could not parse issue language list from tRPC data")
    values: List[str] = []
    for raw in re.findall(r'"(?:\\.|[^"\\])*"', match.group(1)):
        values.append(json.loads(raw))
    return values


def _last_int_match(pattern: str, text: str) -> Optional[int]:
    matches = re.findall(pattern, text)
    if not matches:
        return None
    return int(matches[-1])


def parse_findings_page_stats(data: str) -> Dict[str, Any]:
    ids = re.findall(r"\bid:(\d+)n", data)
    total_count = _last_int_match(r"\bcount:(\d+)", data)
    total_pages = _last_int_match(r"\bpages:(\d+)", data)
    return {
        "finding_count": len(ids),
        "finding_ids": ids,
        "first_id": ids[0] if ids else None,
        "last_id": ids[-1] if ids else None,
        "total_count": total_count,
        "total_pages": total_pages,
    }


def _object_slice_for_match(data: str, offset: int) -> str:
    start = data.rfind("{id:", 0, offset)
    if start == -1:
        start = max(0, offset - 500)
    next_obj = data.find(",{id:", max(start + 1, offset))
    end_count = data.find("],count:", max(start + 1, offset))
    candidates = [pos for pos in (next_obj, end_count) if pos != -1]
    end = min(candidates) if candidates else min(len(data), offset + 1200)
    return data[start:end]


def _extract_js_string_field(obj_text: str, field: str) -> Optional[str]:
    match = re.search(rf"\b{re.escape(field)}:\"((?:\\.|[^\"\\])*)\"", obj_text)
    if not match:
        return None
    try:
        return json.loads('"' + match.group(1) + '"')
    except json.JSONDecodeError:
        return match.group(1)


def _bounded_context(data: str, offset: int, width: int = 220) -> str:
    start = max(0, offset - width // 2)
    end = min(len(data), offset + width // 2)
    context = data[start:end]
    context = context.replace("\\n", " ")
    context = re.sub(r"\s+", " ", context)
    return context[:width]


def scan_findings_data(data: str, page: int) -> Dict[str, Any]:
    target_hits: Dict[str, List[Dict[str, Any]]] = {target: [] for target in DEFAULT_TARGETS}
    for target, pattern in TARGET_PATTERNS.items():
        for match in pattern.finditer(data):
            obj_text = _object_slice_for_match(data, match.start())
            finding_id_match = re.search(r"\bid:(\d+)n", obj_text)
            slug = _extract_js_string_field(obj_text, "slug")
            title = _extract_js_string_field(obj_text, "title")
            target_hits[target].append(
                {
                    "page": page,
                    "finding_id": finding_id_match.group(1) if finding_id_match else None,
                    "title": title,
                    "source_url": f"{PUBLIC_BASE}/issues/{slug}" if slug else None,
                    "matched_text": match.group(0),
                    "context": _bounded_context(data, match.start()),
                }
            )
    return {
        "target_hits": target_hits,
        "generic_cairo_mentions": len(GENERIC_CAIRO_RE.findall(data)),
    }


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def findings_input(page: int) -> Dict[str, Any]:
    return {"filters": dict(DEFAULT_FILTERS), "page": page}


def mine(
    *,
    pages: int,
    cache_dir: Path,
    timeout: int,
    min_request_interval: float,
    targets: Iterable[str] = DEFAULT_TARGETS,
) -> Dict[str, Any]:
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    cache_dir.mkdir(parents=True, exist_ok=True)
    targets = tuple(targets)
    network_performed = False

    language_url = trpc_query_url(ISSUE_LANGUAGES_PROC)
    language_cache = cache_dir / "issue_languages.json"
    if language_cache.exists():
        cached_language = read_json(language_cache)
        language_status = int(cached_language.get("http_status", 0))
        language_data = str(cached_language["data"])
        languages = list(cached_language["parsed_languages"])
    else:
        language_payload, language_status = _request_json(language_url, timeout)
        network_performed = True
        language_data = trpc_data_string(language_payload)
        languages = parse_issue_languages(language_data)
        write_json(
            language_cache,
            {
                "source_url": language_url,
                "http_status": language_status,
                "response_sha256": sha256_text(json.dumps(language_payload, sort_keys=True)),
                "data": language_data,
                "parsed_languages": languages,
            },
        )

    enum_hits = {
        target: [candidate for candidate in TARGET_ENUM_CANDIDATES[target] if candidate in languages]
        for target in targets
    }

    page_rows: List[Dict[str, Any]] = []
    all_hits: Dict[str, List[Dict[str, Any]]] = {target: [] for target in targets}
    records_scanned = 0
    generic_cairo_mentions = 0

    for page in range(1, pages + 1):
        if page > 1 and min_request_interval > 0:
            time.sleep(min_request_interval)
        page_cache = cache_dir / f"findings_page_{page:03d}.json"
        page_input = findings_input(page)
        page_url = trpc_query_url(FINDINGS_GET_PROC, page_input)
        if page_cache.exists():
            cached_page = read_json(page_cache)
            status = int(cached_page.get("http_status", 0))
            data = str(cached_page["data"])
            stats = dict(cached_page["stats"])
            scan = dict(cached_page["scan"])
            response_sha = str(cached_page.get("response_sha256", ""))
        else:
            payload, status = _request_json(page_url, timeout)
            network_performed = True
            data = trpc_data_string(payload)
            stats = parse_findings_page_stats(data)
            scan = scan_findings_data(data, page)
            response_sha = sha256_text(json.dumps(payload, sort_keys=True))
            write_json(
                page_cache,
                {
                    "source_url": page_url,
                    "procedure": FINDINGS_GET_PROC,
                    "http_status": status,
                    "request_input": page_input,
                    "response_sha256": response_sha,
                    "data": data,
                    "stats": stats,
                    "scan": scan,
                },
            )
        records_scanned += int(stats["finding_count"])
        generic_cairo_mentions += int(scan["generic_cairo_mentions"])

        for target in targets:
            all_hits[target].extend(scan["target_hits"].get(target, []))

        page_rows.append(
            {
                "page": page,
                "source_url": page_url,
                "cache_ref": str(page_cache),
                "http_status": status,
                "response_sha256": response_sha,
                "finding_count": stats["finding_count"],
                "first_id": stats["first_id"],
                "last_id": stats["last_id"],
                "total_count": stats["total_count"],
                "total_pages": stats["total_pages"],
                "target_hit_count": sum(len(scan["target_hits"].get(target, [])) for target in targets),
                "generic_cairo_mentions": scan["generic_cairo_mentions"],
            }
        )

    target_counts = {
        target: {
            "enum_candidate_hits": enum_hits[target],
            "enum_candidate_hit_count": len(enum_hits[target]),
            "page_hit_count": len(all_hits[target]),
            "page_hits": all_hits[target][:25],
        }
        for target in targets
    }
    positive_targets = [
        target
        for target in targets
        if target_counts[target]["enum_candidate_hit_count"] > 0 or target_counts[target]["page_hit_count"] > 0
    ]

    if positive_targets:
        disposition = "downgrade_positive_evidence_review_required"
        reason = (
            "At least one residual target produced a public enum or page-scan hit. "
            "Review hit contexts before enabling a REST filter because content hits can be keyword-only."
        )
    else:
        disposition = "downgrade_to_checked_negative_nonblocking_watchlist"
        reason = (
            "Solodit's public issue-language enum omits Huff, Leo/Aleo, and Cairo-ZK variants, "
            "and the bounded 50-page public findings scan produced no target-language evidence."
        )

    return {
        "schema": "auditooor.v3_iter.solodit_language_enum_mining.v1",
        "tool": TOOL_NAME,
        "tool_version": TOOL_VERSION,
        "generated_at_utc": generated_at,
        "blocker_id": BLOCKER_ID,
        "network_performed": network_performed,
        "credential_policy": {
            "api_key_read": False,
            "api_key_printed": False,
            "raw_headers_persisted": False,
            "public_trpc_only": True,
        },
        "public_enum_source": {
            "source_url": language_url,
            "cache_ref": str(language_cache),
            "http_status": language_status,
            "languages": languages,
            "target_enum_hits": enum_hits,
            "target_enum_misses": [target for target in targets if not enum_hits[target]],
        },
        "mining_scope": {
            "pages_requested": pages,
            "pages_fetched": len(page_rows),
            "records_scanned": records_scanned,
            "sort_field": DEFAULT_FILTERS["sortField"],
            "sort_direction": DEFAULT_FILTERS["sortDirection"],
            "impact_filter": DEFAULT_FILTERS["impact"],
            "cache_dir": str(cache_dir),
        },
        "hit_miss_counts": {
            "targets_with_positive_evidence": positive_targets,
            "targets_without_positive_evidence": [target for target in targets if target not in positive_targets],
            "target_counts": target_counts,
            "generic_cairo_mentions_not_counted_as_cairo_zk": generic_cairo_mentions,
        },
        "page_results": page_rows,
        "verdict": {
            "blocker_id": BLOCKER_ID,
            "recommended_disposition": disposition,
            "close_current_positive_enum_gap": not positive_targets,
            "enable_new_api_filters": False,
            "remaining_external_state_required": [],
            "watchlist_targets": list(targets),
            "reason": reason,
        },
    }


def markdown_report(summary: Dict[str, Any]) -> str:
    target_counts = summary["hit_miss_counts"]["target_counts"]
    lines = [
        "# Phase II.10 Solodit Language Enum Mining",
        "",
        f"Blocker: `{summary['blocker_id']}`",
        "",
        "## Verdict",
        "",
        f"`{summary['verdict']['recommended_disposition']}`. {summary['verdict']['reason']}",
        "",
        "Do not add `huff`, `leo`, or `cairo-zk` to `API_VERIFIED_LANGUAGE_VALUES`: the public enum source does not list those values and the page scan did not produce positive target evidence.",
        "",
        "## Public Enum Source",
        "",
        f"- Source URL: `{summary['public_enum_source']['source_url']}`",
        f"- Cache ref: `{summary['public_enum_source']['cache_ref']}`",
        f"- Parsed languages: `{', '.join(summary['public_enum_source']['languages'])}`",
        f"- Target enum misses: `{', '.join(summary['public_enum_source']['target_enum_misses'])}`",
        "",
        "## 50-Page Scan",
        "",
        f"- Pages fetched: `{summary['mining_scope']['pages_fetched']}` / `{summary['mining_scope']['pages_requested']}`",
        f"- Records scanned: `{summary['mining_scope']['records_scanned']}`",
        f"- Cache dir: `{summary['mining_scope']['cache_dir']}`",
        f"- Generic Cairo mentions not counted as Cairo-ZK: `{summary['hit_miss_counts']['generic_cairo_mentions_not_counted_as_cairo_zk']}`",
        "",
        "| Target | Enum hits | Page hits | Verdict |",
        "|---|---:|---:|---|",
    ]
    for target, row in target_counts.items():
        verdict = "positive-review" if row["enum_candidate_hit_count"] or row["page_hit_count"] else "miss"
        lines.append(
            f"| `{target}` | {row['enum_candidate_hit_count']} | {row['page_hit_count']} | {verdict} |"
        )
    lines.extend(
        [
            "",
            "## Page Cache Index",
            "",
            "| Page | Findings | First ID | Last ID | Target hits | Cache ref |",
            "|---:|---:|---:|---:|---:|---|",
        ]
    )
    for row in summary["page_results"]:
        lines.append(
            f"| {row['page']} | {row['finding_count']} | {row['first_id'] or ''} | {row['last_id'] or ''} | {row['target_hit_count']} | `{row['cache_ref']}` |"
        )
    return "\n".join(lines) + "\n"


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pages", type=int, default=50, help="Number of public findings pages to scan")
    parser.add_argument("--cache-dir", required=True, help="Directory for page/language cache JSON")
    parser.add_argument("--out", required=True, help="Summary JSON output path")
    parser.add_argument("--markdown-out", help="Optional Markdown report output path")
    parser.add_argument("--timeout", type=int, default=30, help="HTTP timeout seconds")
    parser.add_argument("--min-request-interval", type=float, default=0.2, help="Seconds to sleep between page requests")
    args = parser.parse_args(argv)

    if args.pages <= 0:
        raise SystemExit("--pages must be positive")

    summary = mine(
        pages=args.pages,
        cache_dir=Path(args.cache_dir),
        timeout=args.timeout,
        min_request_interval=args.min_request_interval,
    )
    out_path = Path(args.out)
    write_json(out_path, summary)
    if args.markdown_out:
        md_path = Path(args.markdown_out)
        md_path.parent.mkdir(parents=True, exist_ok=True)
        md_path.write_text(markdown_report(summary), encoding="utf-8")
    print(json.dumps({"out": str(out_path), "pages_fetched": summary["mining_scope"]["pages_fetched"], "records_scanned": summary["mining_scope"]["records_scanned"], "verdict": summary["verdict"]["recommended_disposition"]}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
