#!/usr/bin/env python3
"""Mine DARKNAVY Web3 exploit-analysis pages into source-backed records.

The offline planner at ``tools/darknavy-web3-planner.py`` deliberately does
not fetch. This miner is the live/cached ETL counterpart:

1. Fetch archive pages ``/web3/`` through ``/web3/page/8/`` via WebCache.
2. Extract and dedupe exploit article links.
3. Fetch each article and emit one JSON + YAML record.

Network I/O is gated behind ``--fetch``. Without it, the tool only reads the
existing cache and fails closed on cache misses.
"""
from __future__ import annotations

import argparse
import hashlib
import html
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse


REPO_ROOT = Path(__file__).resolve().parent.parent
VERIFICATION_TIER = "tier-2-verified-public-archive"
SOURCE_EXTRACTION_METHOD = "web-scrape-darknavy-web3"
DEFAULT_CACHE_DIR = Path("cache/darknavy-web3")
DEFAULT_OUT_DIR = Path("audit/corpus_tags/tags/darknavy_web3_incidents")
MAX_ARCHIVE_PAGE = 8


def _load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


_WC = _load_module(REPO_ROOT / "tools" / "lib" / "hackerman_web_cache.py", "_darknavy_web_cache")
_PLANNER = _load_module(REPO_ROOT / "tools" / "darknavy-web3-planner.py", "_darknavy_web3_planner_for_etl")
_PM = _load_module(REPO_ROOT / "tools" / "hackerman-etl-from-post-mortem.py", "_darknavy_postmortem_helpers")


SCRIPT_JSON_RE = re.compile(
    r"<script\b[^>]*type\s*=\s*['\"]application/ld\+json['\"][^>]*>(?P<body>.*?)</script>",
    re.IGNORECASE | re.DOTALL,
)
META_RE = re.compile(
    r"<meta\b[^>]*(?:name|property)\s*=\s*['\"](?P<name>[^'\"]+)['\"][^>]*content\s*=\s*['\"](?P<content>[^'\"]*)['\"][^>]*>",
    re.IGNORECASE | re.DOTALL,
)
HREF_RE = re.compile(
    r"""<a\b[^>]*?\bhref\s*=\s*(?:"(?P<double>[^"]+)"|'(?P<single>[^']+)'|(?P<bare>[^\s>]+))""",
    re.IGNORECASE | re.DOTALL,
)
POST_META_RE = re.compile(r"<div[^>]+class=[\"'][^\"']*post-meta[^\"']*[\"'][^>]*>(?P<body>.*?)</div>", re.I | re.S)
VULN_CHAIN_RE = re.compile(
    r"(?P<date>\d{4}-\d{2}-\d{2})\s*(?:&nbsp;|·|\s|-)*\s*Loss:\s*(?P<loss>[^·<]+)\s*(?:&nbsp;|·|\s|-)*\s*(?P<vuln>[^<]+)",
    re.I,
)
CHAIN_NAMES = (
    "Ethereum",
    "Arbitrum",
    "BNB Chain",
    "BSC",
    "Base",
    "Polygon",
    "Sui",
    "Solana",
    "Optimism",
    "Avalanche",
    "Blast",
)


ATTACK_KEYWORDS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bbridge\b|\bproof\b|\bimport\b|\bpayout\b", re.I), "bridge-proof-domain-bypass"),
    (re.compile(r"\bre[- ]?entranc", re.I), "reentrancy"),
    (re.compile(r"\baccess control\b|\bunauthori[sz]ed|\bunprotected initializer\b", re.I), "access-control-bypass"),
    (re.compile(r"\bprice manipulation\b|\bspot[- ]price\b|\boracle\b", re.I), "oracle-price-manipulation"),
    (re.compile(r"\bflash[- ]loan\b", re.I), "flash-loan"),
    (re.compile(r"\bapproval\b", re.I), "approval-drain"),
    (re.compile(r"\bdelegatecall\b", re.I), "delegatecall-injection"),
    (re.compile(r"\brounding\b|\bprecision\b", re.I), "precision-loss"),
    (re.compile(r"\bupgrade\b", re.I), "upgrade-compromise"),
)


def _text(value: str) -> str:
    return re.sub(r"\s+", " ", html.unescape(_PM.strip_tags(value))).strip()


def _meta_map(html_text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for match in META_RE.finditer(html_text):
        out[match.group("name").lower()] = html.unescape(match.group("content")).strip()
    return out


def _jsonld_objects(html_text: str) -> list[dict[str, Any]]:
    objects: list[dict[str, Any]] = []
    for match in SCRIPT_JSON_RE.finditer(html_text):
        raw = html.unescape(match.group("body")).strip()
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict):
            objects.append(data)
        elif isinstance(data, list):
            objects.extend(obj for obj in data if isinstance(obj, dict))
    return objects


def _blogposting_jsonld(html_text: str) -> dict[str, Any]:
    for obj in _jsonld_objects(html_text):
        typ = obj.get("@type")
        if typ == "BlogPosting" or (isinstance(typ, list) and "BlogPosting" in typ):
            return obj
    return {}


def _archive_page_urls(start_page: int = 1, end_page: int = MAX_ARCHIVE_PAGE) -> list[str]:
    _PLANNER.validate_page_range(start_page, end_page)
    return [_PLANNER.page_url(page) for page in range(start_page, end_page + 1)]


def extract_archive_article_links(html_text: str, *, base_url: str) -> list[str]:
    return list(_PLANNER.extract_article_links(html_text, base_url=base_url))


def _source_anchors(html_text: str, page_url: str) -> list[str]:
    anchors: list[str] = [page_url]
    seen = set(anchors)
    for match in HREF_RE.finditer(html_text):
        href = (match.group("double") or match.group("single") or match.group("bare") or "").strip()
        href = html.unescape(href).split("#", 1)[0]
        if not href.startswith("http"):
            continue
        if href not in seen:
            seen.add(href)
            anchors.append(href)
    return anchors[:20]


def _article_body(html_text: str, jsonld: dict[str, Any]) -> tuple[str, list[str]]:
    drift: list[str] = []
    body = str(jsonld.get("articleBody") or "").strip()
    if body:
        return body, drift
    drift.append("missing-jsonld-articleBody")
    paragraphs = _PM.first_paragraphs(html_text, 30)
    if not paragraphs:
        drift.append("missing-paragraph-body")
    return "\n".join(paragraphs), drift


def _title(html_text: str, jsonld: dict[str, Any], metas: dict[str, str]) -> str:
    for value in (
        jsonld.get("headline"),
        jsonld.get("name"),
        metas.get("og:title"),
        metas.get("twitter:title"),
    ):
        if value:
            return _text(str(value).replace("| DARKNAVY", ""))
    match = _PM.TITLE_RE.search(html_text)
    return _text(match.group("text")).replace("| DARKNAVY", "").strip() if match else "DARKNAVY Web3 report"


def _post_meta(html_text: str) -> dict[str, str]:
    match = POST_META_RE.search(html_text)
    if not match:
        return {}
    text = _text(match.group("body"))
    parsed: dict[str, str] = {}
    vuln_match = VULN_CHAIN_RE.search(text)
    if vuln_match:
        parsed["date"] = vuln_match.group("date").strip()
        parsed["loss"] = vuln_match.group("loss").strip()
        parsed["vulnerability"] = vuln_match.group("vuln").strip()
    for chain in CHAIN_NAMES:
        if re.search(rf"\b{re.escape(chain)}\b", html_text, re.I):
            parsed["chain_or_language"] = chain
            break
    return parsed


def _report_date(jsonld: dict[str, Any], metas: dict[str, str], post_meta: dict[str, str], body: str) -> tuple[str, str]:
    for source, value in (
        ("post-meta", post_meta.get("date")),
        ("jsonld-datePublished", jsonld.get("datePublished")),
        ("article:published_time", metas.get("article:published_time")),
    ):
        if value:
            match = _PM.ISO_DATE_RE.search(str(value))
            if match:
                return match.group("iso"), source
    paragraphs = body.splitlines()[:4]
    date, source = _PM.extract_incident_date(paragraphs, body)
    return date, source


def _amount(body: str, post_meta: dict[str, str]) -> tuple[int, str, str]:
    candidates = [post_meta.get("loss", ""), body]
    best = (0, "low", "")
    for candidate in candidates:
        amount, confidence, literal = _PM.extract_amount_stolen([candidate])
        if amount > best[0]:
            best = (amount, confidence, literal)
    return best


def _attack_class(body: str, vulnerability: str, title: str) -> str:
    hay = "\n".join([title, vulnerability, body])
    for pattern, label in ATTACK_KEYWORDS:
        if pattern.search(hay):
            return label
    pm_class = _PM.extract_attack_class(hay)
    return "logic-error" if pm_class == "unspecified" and "logic" in hay.lower() else pm_class


def _component(body: str, title: str) -> str:
    selector_hits = re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\([^)]*\)", body)
    if selector_hits:
        return selector_hits[0][:160]
    return title[:160]


def _chain_or_language(body: str, post_meta: dict[str, str]) -> str:
    if post_meta.get("chain_or_language"):
        return post_meta["chain_or_language"]
    for chain in CHAIN_NAMES:
        if re.search(rf"\b{re.escape(chain)}\b", body, re.I):
            return chain
    return "unknown"


def _detector_hypotheses(attack_class: str, component: str, chain: str) -> list[str]:
    tags = [attack_class]
    if "bridge" in attack_class or "bridge" in component.lower():
        tags.extend(["bridge-source-commitment-binding", "bridge-replay-or-consumption-key"])
    if "price" in attack_class:
        tags.extend(["spot-price-oracle-use", "same-block-manipulation"])
    if "access" in attack_class:
        tags.extend(["missing-authorizer", "unprotected-entrypoint"])
    if chain != "unknown":
        tags.append(f"chain:{_PM.slugify(chain, max_len=40)}")
    return list(dict.fromkeys(tags))


def build_darknavy_record(
    *,
    page_url: str,
    html_text: str,
    payload_sha256: str,
    fetched_at_utc: str,
) -> dict[str, Any]:
    metas = _meta_map(html_text)
    jsonld = _blogposting_jsonld(html_text)
    body, drift = _article_body(html_text, jsonld)
    post_meta = _post_meta(html_text)
    title = _title(html_text, jsonld, metas)
    report_date, report_date_source = _report_date(jsonld, metas, post_meta, body)
    amount_usd, amount_confidence, amount_literal = _amount(body, post_meta)
    severity = _PM.severity_from_amount(amount_usd)
    vulnerability = post_meta.get("vulnerability") or ""
    attack_class = _attack_class(body, vulnerability, title)
    component = _component(body, title)
    chain = _chain_or_language(body, post_meta)
    slug = _PM.slugify(urlparse(page_url).path.strip("/").split("/")[-1] or title, max_len=80)
    digest = hashlib.sha256(f"darknavy\n{page_url}\n{payload_sha256}".encode("utf-8")).hexdigest()[:12]
    anchors = _source_anchors(html_text, page_url)
    hypotheses = _detector_hypotheses(attack_class, component, chain)
    action_summary = body[:1200].strip() or title
    root_cause = vulnerability or attack_class
    impact = amount_literal or post_meta.get("loss") or _PM.amount_to_dollar_class(amount_usd)
    protocol = title.split(" via ", 1)[0].split(":", 1)[0][:160]

    record: dict[str, Any] = {
        "schema": "auditooor.darknavy_web3_record.v1",
        "record_id": f"darknavy-web3:{slug}:{digest}",
        "record_tier": "public-corpus",
        "verification_tier": VERIFICATION_TIER,
        "source_extraction_method": SOURCE_EXTRACTION_METHOD,
        "record_source_url": page_url,
        "source_audit_ref": {
            "url": page_url,
            "fetched_at_utc": fetched_at_utc,
            "payload_sha256": payload_sha256,
        },
        "title": title,
        "target_project": protocol,
        "target_project_slug": slug,
        "target_repo": _PM.extract_target_repo(html_text) or "unknown",
        "target_component": component,
        "report_date": report_date,
        "report_date_source": report_date_source,
        "protocol": protocol,
        "chain_or_language": chain,
        "exploit_preconditions": _PM.first_paragraphs(body, 3) or [title],
        "attacker_action_sequence": action_summary,
        "root_cause": root_cause,
        "impact": impact,
        "source_anchors": anchors,
        "detector_hypotheses": hypotheses,
        "attack_class": attack_class,
        "severity_at_finding": severity,
        "amount_stolen_usd_estimate": amount_usd,
        "amount_stolen_confidence": amount_confidence,
        "amount_stolen_literal_match": amount_literal,
        "impact_dollar_class": _PM.amount_to_dollar_class(amount_usd),
        "fix_commit_ref": _PM.extract_fix_commit_refs(html_text),
        "record_extensions": {
            "article_body_sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
            "jsonld_available": bool(jsonld),
            "darknavy_vulnerability_label": vulnerability,
            "detector_hypotheses": hypotheses,
        },
        "title_h2_mismatch": False,
        "jsonld_schema_drift": drift,
        "verification_chain": [
            {"step": "fetch", "proof": payload_sha256},
            {
                "step": "parse",
                "proof": hashlib.sha256(
                    json.dumps(
                        {"url": page_url, "title": title, "amount": amount_usd, "attack_class": attack_class},
                        sort_keys=True,
                    ).encode("utf-8")
                ).hexdigest(),
            },
        ],
        "notes": "tier-2 DARKNAVY Web3 exploit analysis; deterministic HTML/JSON-LD extraction",
    }
    emit_seed = json.dumps({key: val for key, val in record.items() if key != "verification_chain"}, sort_keys=True).encode(
        "utf-8"
    )
    record["verification_chain"].append({"step": "emit", "proof": hashlib.sha256(emit_seed).hexdigest()})
    return record


def write_record(out_dir: Path, record: dict[str, Any]) -> tuple[Path, Path]:
    slug = str(record.get("target_project_slug") or "unknown")
    target = out_dir / slug
    target.mkdir(parents=True, exist_ok=True)
    digest = record["record_id"].rsplit(":", 1)[-1]
    base = f"{_PM.slugify(record['severity_at_finding'])}-{digest}"
    json_path = target / f"{base}.json"
    yaml_path = target / f"{base}.yaml"
    json_path.write_text(json.dumps(record, indent=2, sort_keys=True), encoding="utf-8")
    yaml_path.write_text(_PM.yaml_dump(record), encoding="utf-8")
    return json_path, yaml_path


def convert(
    *,
    cache: "_WC.WebCache",
    out_dir: Path,
    fetch_live: bool,
    dry_run: bool,
    start_page: int = 1,
    end_page: int = MAX_ARCHIVE_PAGE,
    max_articles: int | None = None,
) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "source": "darknavy_web3",
        "verification_tier": VERIFICATION_TIER,
        "source_extraction_method": SOURCE_EXTRACTION_METHOD,
        "cache_dir": str(cache.cache_dir),
        "out_dir": str(out_dir),
        "fetch_live": bool(fetch_live),
        "dry_run": bool(dry_run),
        "archive_pages_visited": 0,
        "article_urls_resolved": 0,
        "records_emitted": 0,
        "by_severity": {},
        "by_attack_class": {},
        "files": [],
        "errors": [],
    }
    out_dir.mkdir(parents=True, exist_ok=True)

    article_urls: list[str] = []
    seen: set[str] = set()
    for archive_url in _archive_page_urls(start_page, end_page):
        try:
            result = cache.fetch(archive_url)
        except Exception as exc:  # noqa: BLE001
            summary["errors"].append(f"fetch archive {archive_url}: {exc}")
            continue
        summary["archive_pages_visited"] += 1
        for article_url in extract_archive_article_links(result.payload.decode("utf-8", errors="replace"), base_url=archive_url):
            if article_url not in seen:
                seen.add(article_url)
                article_urls.append(article_url)

    if max_articles is not None:
        article_urls = article_urls[:max_articles]
    summary["article_urls_resolved"] = len(article_urls)

    for article_url in article_urls:
        try:
            result = cache.fetch(article_url)
        except Exception as exc:  # noqa: BLE001
            summary["errors"].append(f"fetch article {article_url}: {exc}")
            continue
        record = build_darknavy_record(
            page_url=article_url,
            html_text=result.payload.decode("utf-8", errors="replace"),
            payload_sha256=result.payload_sha256,
            fetched_at_utc=result.fetched_at_utc,
        )
        if not record["attacker_action_sequence"] or not record["record_source_url"]:
            summary["errors"].append(f"quality gate failed for {article_url}: missing body/source url")
            continue
        summary["by_severity"][record["severity_at_finding"]] = summary["by_severity"].get(record["severity_at_finding"], 0) + 1
        summary["by_attack_class"][record["attack_class"]] = summary["by_attack_class"].get(record["attack_class"], 0) + 1
        summary["records_emitted"] += 1
        if not dry_run:
            json_path, yaml_path = write_record(out_dir, record)
            summary["files"].extend([str(json_path), str(yaml_path)])
    return summary


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE_DIR)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--fetch", action="store_true", help="Allow bounded live network fetches through WebCache.")
    parser.add_argument("--dry-run", action="store_true", help="Count records without writing JSON/YAML files.")
    parser.add_argument("--start-page", type=int, default=1)
    parser.add_argument("--end-page", type=int, default=MAX_ARCHIVE_PAGE)
    parser.add_argument("--max-pages", type=int, default=None, help="Alias for --end-page, capped at 8.")
    parser.add_argument("--max-articles", type=int, default=None)
    parser.add_argument("--rate-limit-ms", type=int, default=1500)
    parser.add_argument("--respect-robots", dest="respect_robots", action="store_true", default=True)
    parser.add_argument("--no-respect-robots", dest="respect_robots", action="store_false")
    parser.add_argument("--i-acknowledge-tos", action="store_true", default=False)
    parser.add_argument("--json-summary", action="store_true")
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = build_arg_parser().parse_args(list(argv) if argv is not None else None)
    if not args.respect_robots and not args.i_acknowledge_tos:
        print("ERROR: --no-respect-robots requires --i-acknowledge-tos", file=sys.stderr)
        return 2
    end_page = args.max_pages if args.max_pages is not None else args.end_page
    try:
        _PLANNER.validate_page_range(args.start_page, end_page)
    except ValueError as exc:
        print(f"PAGE-RANGE-ERROR: {exc}", file=sys.stderr)
        return 2
    cache = _WC.WebCache(
        cache_dir=args.cache_dir,
        rate_limit_ms=args.rate_limit_ms,
        respect_robots=args.respect_robots,
        i_acknowledge_tos=args.i_acknowledge_tos,
        offline=not bool(args.fetch),
    )
    summary = convert(
        cache=cache,
        out_dir=args.out_dir,
        fetch_live=bool(args.fetch),
        dry_run=bool(args.dry_run),
        start_page=args.start_page,
        end_page=end_page,
        max_articles=args.max_articles,
    )
    if args.json_summary:
        print(json.dumps(summary, indent=2, sort_keys=True))
    if summary["records_emitted"] == 0 and summary["article_urls_resolved"] == 0:
        print("BLOCKED-NO-REAL-SOURCE: empty cache and --fetch not requested", file=sys.stderr)
        return 3
    return 0 if not summary["errors"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
