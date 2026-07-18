#!/usr/bin/env python3
"""Mine medium.com/immunefi for hackerman tier-2 post-incident records.

W2.7.a target #2. See ``docs/WAVE2_W27A_IMMUNEFI_DASHBOARD_SPEC_2026-05-16.md``
§3.2 for the full contract.

Pipeline:

1. Walk the Atom feed at ``--feed-url`` (default
   ``https://medium.com/feed/immunefi``) for post URLs.
2. Per post, fetch the full Medium page and pull the JSON-LD block
   embedded for SEO (``"@type": "NewsArticle"`` typically). The block
   carries ``headline``, ``datePublished``, ``author``, ``articleBody``.
3. Extract five fields from the body via deterministic regex:
   - incident_date (heuristic; first calendar date in opening
     3 paragraphs; fall back to datePublished).
   - target_project (title + first ``<h2>``; mismatch logged).
   - amount_stolen_usd (regex over the first 5 paragraphs; largest
     match wins; confidence tag attached).
   - attack_class (keyword-match against the corpus taxonomy).
   - fix_commit_ref (regex over GitHub commit / PR URLs in the body).
4. Emit one ``<out-dir>/<post_slug>/<record_id>.json|.yaml`` per post.

Hard rules:

* No live scrape on import path. ``--feed-url`` is contacted only when
  ``--fetch`` is set; tests inject feed bytes via the cache.
* No LLM. All extraction is deterministic regex.
* Verification tier: ``tier-2-verified-public-archive``.
* SHA256 hash evidence per page recorded in source_audit_ref + sidecar.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


REPO_ROOT = Path(__file__).resolve().parent.parent
VERIFICATION_TIER = "tier-2-verified-public-archive"
SOURCE_EXTRACTION_METHOD = "web-scrape-medium-jsonld"
DEFAULT_RATE_LIMIT_MS = 2000
DEFAULT_FEED_URL = "https://medium.com/feed/immunefi"


def _load_web_cache():
    spec = importlib.util.spec_from_file_location(
        "_hackerman_web_cache_for_immunefi_medium",
        str(REPO_ROOT / "tools" / "lib" / "hackerman_web_cache.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


_WC = _load_web_cache()


# ---------------------------------------------------------------------------
# Helpers shared with the dashboard miner. Kept local to avoid coupling.
# ---------------------------------------------------------------------------


def slugify(value: object, *, max_len: int = 80) -> str:
    text = str(value or "").strip().lower()
    text = re.sub(r"[^a-z0-9._:/-]+", "-", text).strip("-._")
    text = re.sub(r"-{2,}", "-", text)
    return (text[:max_len].strip("-._") or "record")


def yaml_scalar(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    text = str(value if value is not None else "")
    if text == "":
        return '""'
    numeric = re.fullmatch(r"[-+]?(?:0|[1-9][0-9_]*)(?:\.[0-9_]+)?", text)
    ambiguous = text.lower() in {"true", "false", "null", "yes", "no", "on", "off", "~"}
    plain_safe = (
        re.fullmatch(r"[A-Za-z0-9._:/<>=,$#@-]+", text)
        and not text.endswith(":")
        and not text.startswith(("#", "-", "?", ":", "<", ">", "@", "`", "&", "*", "!", "|", "%", "{", "}", "[", "]", ","))
    )
    if plain_safe and not numeric and not ambiguous:
        return text
    return json.dumps(text, ensure_ascii=False)


def yaml_dump(data: Dict[str, Any]) -> str:
    lines: List[str] = []

    def render(obj: Any, indent: int) -> None:
        pad = "  " * indent
        if isinstance(obj, dict):
            for key, value in obj.items():
                if isinstance(value, dict):
                    lines.append(f"{pad}{key}:")
                    render(value, indent + 1)
                elif isinstance(value, list):
                    if not value:
                        lines.append(f"{pad}{key}: []")
                        continue
                    lines.append(f"{pad}{key}:")
                    for item in value:
                        if isinstance(item, dict):
                            first = True
                            for subk, subv in item.items():
                                prefix = f"{pad}- " if first else f"{pad}  "
                                if isinstance(subv, (dict, list)):
                                    lines.append(f"{prefix}{subk}:")
                                    render(subv, indent + 2)
                                else:
                                    lines.append(f"{prefix}{subk}: {yaml_scalar(subv)}")
                                first = False
                        else:
                            lines.append(f"{pad}- {yaml_scalar(item)}")
                else:
                    lines.append(f"{pad}{key}: {yaml_scalar(value)}")
    render(data, 0)
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Feed parsing.
# ---------------------------------------------------------------------------


# Atom feeds use <entry><link href="..."/></entry>; RSS uses <item><link>...</link>.
ATOM_ENTRY_RE = re.compile(r"<entry[^>]*>(?P<body>.*?)</entry>", re.DOTALL | re.IGNORECASE)
ATOM_LINK_RE = re.compile(r'<link[^>]+href=["\'](?P<href>https?://[^"\']+)["\']', re.IGNORECASE)
RSS_ITEM_RE = re.compile(r"<item[^>]*>(?P<body>.*?)</item>", re.DOTALL | re.IGNORECASE)
RSS_LINK_RE = re.compile(r"<link[^>]*>(?P<href>https?://[^<]+)</link>", re.IGNORECASE)
FEED_NEXT_RE = re.compile(
    r'<link[^>]+rel=["\']next["\'][^>]+href=["\'](?P<href>https?://[^"\']+)["\']',
    re.IGNORECASE,
)
JSONLD_RE = re.compile(
    r'<script[^>]+type=["\']application/ld\+json["\'][^>]*>(.*?)</script>',
    re.DOTALL | re.IGNORECASE,
)
H2_RE = re.compile(r"<h2[^>]*>(?P<text>.*?)</h2>", re.DOTALL | re.IGNORECASE)
TITLE_RE = re.compile(r"<title[^>]*>(?P<text>.*?)</title>", re.DOTALL | re.IGNORECASE)
PARAGRAPH_RE = re.compile(r"<p[^>]*>(?P<text>.*?)</p>", re.DOTALL | re.IGNORECASE)
DATE_RE = re.compile(
    r"\b(?P<full>(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|"
    r"Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|"
    r"Nov(?:ember)?|Dec(?:ember)?)\s+\d{1,2},?\s+\d{4})\b",
    re.IGNORECASE,
)
ISO_DATE_RE = re.compile(r"\b(?P<iso>\d{4}-\d{2}-\d{2})\b")
AMOUNT_RE = re.compile(
    r"\$(?P<amt>[\d,]+(?:\.\d+)?)\s*(?P<unit>million|m|billion|b|k|thousand)?",
    re.IGNORECASE,
)
FIX_COMMIT_RE = re.compile(
    r"https?://github\.com/(?P<owner>[A-Za-z0-9._-]+)/(?P<repo>[A-Za-z0-9._-]+)/(?:commit|pull)/(?P<id>[A-Za-z0-9]+)",
    re.IGNORECASE,
)


ATTACK_CLASS_KEYWORDS: Tuple[Tuple[re.Pattern, str], ...] = (
    (re.compile(r"\bre[- ]?entranc(?:y|e)\b", re.I), "reentrancy"),
    (re.compile(r"\boracle\s+manipulation\b|\bprice\s+manipulation\b", re.I), "oracle-manipulation"),
    (re.compile(r"\bsignature[- ]replay\b|\breplay\s+attack\b", re.I), "signature-replay"),
    (re.compile(r"\bsignature\s+verification\s+bypass\b|\buninitiali[sz]ed\s+proxy\b", re.I), "signature-verification-bypass"),
    (re.compile(r"\baccess[- ]control\b|\bmissing\s+onlyowner\b", re.I), "access-control-bypass"),
    (re.compile(r"\bgovernance[- ]takeover\b|\bquorum\s+manipulation\b", re.I), "governance-takeover"),
    (re.compile(r"\bbridge[- ](?:message[- ])?replay\b|\bcross[- ]chain\s+replay\b", re.I), "bridge-message-replay"),
    (re.compile(r"\bflash[- ]loan\b", re.I), "flash-loan"),
    (re.compile(r"\binteger\s+(?:under|over)flow\b|\boob\b|\bout\s+of\s+bounds\b", re.I), "memory-corruption"),
    (re.compile(r"\bprecision[- ]loss\b|\brounding\b", re.I), "precision-loss"),
    (re.compile(r"\bfront[- ]?runn?ing\b|\bsandwich\b", re.I), "frontrunning"),
    (re.compile(r"\bdenial[- ]of[- ]service\b|\bDoS\b", re.I), "dos"),
    (re.compile(r"\b(theft|stolen|drain|drained)\b", re.I), "theft-of-funds"),
    (re.compile(r"\bpermanent\s+freezing\b|\bfreeze\b|\bfrozen\b", re.I), "freeze-of-funds"),
)


def parse_feed(feed_body: str) -> List[str]:
    """Return the list of post URLs found in an Atom or RSS feed body."""
    urls: List[str] = []
    seen: set = set()
    for match in ATOM_ENTRY_RE.finditer(feed_body):
        body = match.group("body")
        link = ATOM_LINK_RE.search(body)
        if link:
            href = link.group("href")
            if href not in seen:
                seen.add(href)
                urls.append(href)
    if urls:
        return urls
    for match in RSS_ITEM_RE.finditer(feed_body):
        body = match.group("body")
        link = RSS_LINK_RE.search(body)
        if link:
            href = link.group("href").strip()
            if href and href not in seen:
                seen.add(href)
                urls.append(href)
    return urls


def feed_next_link(feed_body: str) -> Optional[str]:
    m = FEED_NEXT_RE.search(feed_body)
    return m.group("href") if m else None


def extract_jsonld(html: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for match in JSONLD_RE.finditer(html):
        body = match.group(1).strip()
        try:
            decoded = json.loads(body)
        except json.JSONDecodeError:
            continue
        if isinstance(decoded, dict):
            out.append(decoded)
        elif isinstance(decoded, list):
            for item in decoded:
                if isinstance(item, dict):
                    out.append(item)
    return out


def strip_tags(html: str) -> str:
    return re.sub(r"<[^>]+>", " ", html).strip()


def first_paragraphs(article_body: str, n: int) -> List[str]:
    paragraphs = [strip_tags(m.group("text")) for m in PARAGRAPH_RE.finditer(article_body)]
    cleaned = [re.sub(r"\s+", " ", p).strip() for p in paragraphs if p.strip()]
    if not cleaned:
        # JSON-LD articleBody is plain prose (no <p> tags); split on
        # double-newline / sentence-boundary as a fallback.
        chunks = re.split(r"\n\s*\n|(?<=[.!?])\s+(?=[A-Z])", article_body)
        cleaned = [re.sub(r"\s+", " ", c).strip() for c in chunks if c and c.strip()]
    return cleaned[:n]


def extract_incident_date(paragraphs: List[str], fallback_iso: str) -> Tuple[str, str]:
    for p in paragraphs:
        m = DATE_RE.search(p)
        if m:
            return (m.group("full"), "regex-body")
        m_iso = ISO_DATE_RE.search(p)
        if m_iso:
            return (m_iso.group("iso"), "iso-body")
    if fallback_iso:
        return (fallback_iso, "datePublished-fallback")
    return ("", "none")


def extract_target_project(title: str, h2_first: str) -> Tuple[str, bool]:
    title_norm = re.sub(r"\s+", " ", title or "").strip()
    h2_norm = re.sub(r"\s+", " ", h2_first or "").strip()
    if not title_norm:
        return (h2_norm[:200], False)
    if not h2_norm:
        return (title_norm[:200], False)
    mismatch = title_norm.lower()[:30] != h2_norm.lower()[:30]
    return (title_norm[:200], bool(mismatch))


def parse_amount(amount: str, unit: Optional[str]) -> int:
    raw = float(amount.replace(",", ""))
    unit_norm = (unit or "").strip().lower()
    if unit_norm in {"billion", "b"}:
        return int(raw * 1_000_000_000)
    if unit_norm in {"million", "m"}:
        return int(raw * 1_000_000)
    if unit_norm in {"thousand", "k"}:
        return int(raw * 1_000)
    return int(raw)


def extract_amount_stolen(paragraphs: List[str]) -> Tuple[int, str, str]:
    """Return (amount_usd, confidence, literal_match) for the first 5 paragraphs."""
    best_amount = 0
    best_literal = ""
    best_confidence = "low"
    for p in paragraphs[:5]:
        for m in AMOUNT_RE.finditer(p):
            amt = parse_amount(m.group("amt"), m.group("unit"))
            if amt > best_amount:
                best_amount = amt
                best_literal = m.group(0)
                # If unit is million/billion + amt >= 1M, give "medium"; otherwise low.
                unit_norm = (m.group("unit") or "").strip().lower()
                if amt >= 1_000_000 and unit_norm in {"million", "m", "billion", "b"}:
                    best_confidence = "medium"
                else:
                    best_confidence = "low"
    return best_amount, best_confidence, best_literal


def severity_from_amount(amount_usd: int) -> str:
    if amount_usd >= 1_000_000:
        return "critical"
    if amount_usd >= 100_000:
        return "high"
    if amount_usd > 0:
        return "medium"
    return "info"


def amount_to_dollar_class(amount: int) -> str:
    if amount >= 1_000_000:
        return ">=$1M"
    if amount >= 100_000:
        return "$100K-$1M"
    if amount >= 10_000:
        return "$10K-$100K"
    if amount > 0:
        return "<$10K"
    return "non-financial"


def extract_attack_class(article_body: str) -> str:
    hay = strip_tags(article_body).lower()
    for pat, label in ATTACK_CLASS_KEYWORDS:
        if pat.search(hay):
            return label
    return "unspecified"


def extract_fix_commit_refs(article_body: str) -> List[str]:
    seen: List[str] = []
    seen_set: set = set()
    for m in FIX_COMMIT_RE.finditer(article_body):
        url = m.group(0)
        if url not in seen_set:
            seen_set.add(url)
            seen.append(url)
    return seen


def extract_target_repo(article_body: str) -> str:
    m = FIX_COMMIT_RE.search(article_body)
    if not m:
        return ""
    owner = m.group("owner")
    repo = re.sub(r"\.git$", "", m.group("repo"))
    return f"github.com/{owner}/{repo}"


# ---------------------------------------------------------------------------
# Record assembly
# ---------------------------------------------------------------------------


def make_record_id(post_url: str, payload_sha: str) -> str:
    digest = hashlib.sha256(f"medium\n{post_url}\n{payload_sha}".encode("utf-8")).hexdigest()[:12]
    slug = slugify(post_url.rsplit("/", 1)[-1], max_len=64)
    return f"immunefi-medium:{slug}:{digest}"


def build_record(
    *,
    post_url: str,
    html: str,
    payload_sha256: str,
    fetched_at_utc: str,
) -> Optional[Dict[str, Any]]:
    blocks = extract_jsonld(html)
    article = None
    for block in blocks:
        atype = block.get("@type")
        if isinstance(atype, list):
            atype_set = {str(x).lower() for x in atype}
        else:
            atype_set = {str(atype or "").lower()}
        if atype_set & {"newsarticle", "article", "blogposting"}:
            article = block
            break
    # We tolerate missing JSON-LD by emitting a SCHEMA-DRIFT marker;
    # callers can check the `jsonld_schema_drift` field.
    schema_drift_missing: List[str] = []
    headline = ""
    date_published_iso = ""
    article_body = ""
    author = ""
    if article is not None:
        headline = str(article.get("headline") or article.get("name") or "")
        date_published_iso = str(article.get("datePublished") or "")
        article_body = str(article.get("articleBody") or "")
        author_field = article.get("author")
        if isinstance(author_field, dict):
            author = str(author_field.get("name") or "")
        elif isinstance(author_field, list) and author_field:
            first = author_field[0]
            if isinstance(first, dict):
                author = str(first.get("name") or "")
        elif isinstance(author_field, str):
            author = author_field
        for required in ("headline", "datePublished", "articleBody"):
            if not article.get(required):
                schema_drift_missing.append(required)
    else:
        schema_drift_missing.extend(["headline", "datePublished", "articleBody"])

    if not article_body:
        # Fall back to the raw <p> body of the HTML (article-body-less Medium pages).
        article_body = html

    title_html = TITLE_RE.search(html)
    title_text = strip_tags(title_html.group("text")) if title_html else headline
    h2_match = H2_RE.search(html)
    h2_text = strip_tags(h2_match.group("text")) if h2_match else ""
    target_project, title_h2_mismatch = extract_target_project(title_text or headline, h2_text)

    paragraphs = first_paragraphs(article_body, 6)
    # date_published_iso may carry full ISO like 2022-02-03T10:00:00Z; trim.
    fallback_iso = date_published_iso[:10] if re.match(r"\d{4}-\d{2}-\d{2}", date_published_iso) else ""
    incident_date, incident_date_source = extract_incident_date(paragraphs, fallback_iso)
    amount_usd, amount_conf, amount_literal = extract_amount_stolen(paragraphs)
    severity = severity_from_amount(amount_usd)
    dollar_class = amount_to_dollar_class(amount_usd)
    attack_class = extract_attack_class(article_body)
    fix_refs = extract_fix_commit_refs(article_body)
    target_repo = extract_target_repo(article_body)

    record_id = make_record_id(post_url, payload_sha256)
    record: Dict[str, Any] = {
        "record_id": record_id,
        "record_tier": "public-corpus",
        "verification_tier": VERIFICATION_TIER,
        "source_extraction_method": SOURCE_EXTRACTION_METHOD,
        "source_audit_ref": {
            "url": post_url,
            "fetched_at_utc": fetched_at_utc,
            "payload_sha256": payload_sha256,
        },
        "target_project": target_project or post_url.rsplit("/", 1)[-1],
        "target_project_slug": slugify(target_project or post_url.rsplit("/", 1)[-1]),
        "target_repo": target_repo or "unknown",
        "incident_date": incident_date,
        "incident_date_source": incident_date_source,
        "severity_at_finding": severity,
        "amount_stolen_usd_estimate": amount_usd,
        "amount_stolen_confidence": amount_conf,
        "amount_stolen_literal_match": amount_literal,
        "impact_dollar_class": dollar_class,
        "attack_class": attack_class,
        "fix_commit_ref": fix_refs,
        "author": author,
        "title_h2_mismatch": bool(title_h2_mismatch),
        "jsonld_schema_drift": schema_drift_missing,
        "verification_chain": [
            {"step": "fetch", "proof": payload_sha256},
            {"step": "parse", "proof": hashlib.sha256(
                json.dumps({"url": post_url, "title": target_project, "amount": amount_usd},
                           sort_keys=True).encode("utf-8")).hexdigest()},
        ],
        "notes": "tier-2 medium-writeup; amount via regex over first 5 paragraphs",
    }
    emit_seed = json.dumps({k: v for k, v in record.items() if k != "verification_chain"},
                           sort_keys=True).encode("utf-8")
    record["verification_chain"].append(
        {"step": "emit", "proof": hashlib.sha256(emit_seed).hexdigest()}
    )
    return record


def write_record(out_dir: Path, record: Dict[str, Any]) -> Tuple[Path, Path]:
    slug = record.get("target_project_slug", "unknown")
    target = out_dir / slug
    target.mkdir(parents=True, exist_ok=True)
    digest = record["record_id"].rsplit(":", 1)[-1]
    base = f"{slugify(record['severity_at_finding'])}-{digest}"
    json_path = target / f"{base}.json"
    yaml_path = target / f"{base}.yaml"
    json_path.write_text(json.dumps(record, indent=2, sort_keys=True), encoding="utf-8")
    yaml_path.write_text(yaml_dump(record), encoding="utf-8")
    return json_path, yaml_path


# ---------------------------------------------------------------------------
# Top-level convert / CLI
# ---------------------------------------------------------------------------


def convert(
    *,
    cache: "_WC.WebCache",
    out_dir: Path,
    fetch_live: bool,
    max_posts: Optional[int],
    dry_run: bool,
    feed_url: str = DEFAULT_FEED_URL,
) -> Dict[str, Any]:
    summary: Dict[str, Any] = {
        "verification_tier": VERIFICATION_TIER,
        "source_extraction_method": SOURCE_EXTRACTION_METHOD,
        "cache_dir": str(cache.cache_dir),
        "out_dir": str(out_dir),
        "fetch_live": bool(fetch_live),
        "dry_run": bool(dry_run),
        "feed_pages_visited": 0,
        "posts_discovered": 0,
        "records_emitted": 0,
        "by_severity": {},
        "by_attack_class": {},
        "files": [],
        "errors": [],
    }
    post_urls: List[str] = []
    next_url: Optional[str] = feed_url
    while next_url:
        try:
            feed = cache.fetch(next_url)
        except Exception as exc:  # noqa: BLE001
            summary["errors"].append(f"fetch feed {next_url}: {exc}")
            break
        summary["feed_pages_visited"] += 1
        body = feed.payload.decode("utf-8", errors="replace")
        urls = parse_feed(body)
        for url in urls:
            if url not in post_urls:
                post_urls.append(url)
        next_url = feed_next_link(body)
    if max_posts is not None:
        post_urls = post_urls[:max_posts]
    summary["posts_discovered"] = len(post_urls)

    out_dir.mkdir(parents=True, exist_ok=True)

    for post_url in post_urls:
        try:
            post = cache.fetch(post_url)
        except Exception as exc:  # noqa: BLE001
            summary["errors"].append(f"fetch post {post_url}: {exc}")
            continue
        html = post.payload.decode("utf-8", errors="replace")
        record = build_record(
            post_url=post_url,
            html=html,
            payload_sha256=post.payload_sha256,
            fetched_at_utc=post.fetched_at_utc,
        )
        if record is None:
            summary["errors"].append(f"build_record returned None for {post_url}")
            continue
        summary["by_severity"][record["severity_at_finding"]] = (
            summary["by_severity"].get(record["severity_at_finding"], 0) + 1
        )
        summary["by_attack_class"][record["attack_class"]] = (
            summary["by_attack_class"].get(record["attack_class"], 0) + 1
        )
        if dry_run:
            summary["records_emitted"] += 1
            continue
        json_path, _yaml_path = write_record(out_dir, record)
        summary["records_emitted"] += 1
        summary["files"].append(str(json_path))
    return summary


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="hackerman-etl-from-immunefi-medium",
        description="Mine medium.com/immunefi feed into hackerman tier-2 records.",
    )
    p.add_argument("--cache-dir", required=True, type=Path)
    p.add_argument("--out-dir", required=True, type=Path)
    p.add_argument("--fetch", action="store_true")
    p.add_argument("--feed-url", default=DEFAULT_FEED_URL)
    p.add_argument("--rate-limit-ms", type=int, default=DEFAULT_RATE_LIMIT_MS)
    p.add_argument("--max-posts", type=int, default=None)
    p.add_argument("--respect-robots", dest="respect_robots", action="store_true", default=True)
    p.add_argument("--no-respect-robots", dest="respect_robots", action="store_false")
    p.add_argument("--i-acknowledge-tos", dest="i_acknowledge_tos", action="store_true", default=False)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--json-summary", action="store_true")
    return p


def main(argv: Optional[Iterable[str]] = None) -> int:
    args = build_arg_parser().parse_args(list(argv) if argv is not None else None)
    if not args.respect_robots and not args.i_acknowledge_tos:
        sys.stderr.write(
            "ERROR: --no-respect-robots requires --i-acknowledge-tos (operator-only override).\n"
        )
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
        max_posts=args.max_posts,
        dry_run=bool(args.dry_run),
        feed_url=args.feed_url,
    )
    if args.json_summary:
        sys.stdout.write(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    if summary.get("records_emitted", 0) == 0 and not summary.get("posts_discovered"):
        sys.stderr.write("BLOCKED-NO-REAL-SOURCE: empty cache and --fetch not requested\n")
        return 3
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
