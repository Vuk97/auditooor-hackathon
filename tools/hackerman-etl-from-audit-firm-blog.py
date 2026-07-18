#!/usr/bin/env python3
"""Mine audit-firm engineering blogs for hackerman tier-2 detector seeds.

Wave-4 P0 W4.4. Roadmap anchor:
``docs/HACKERMAN_WAVE4_CAPABILITY_ROADMAP_2026-05-16.md`` (commit 91ed239131)
lists this lane as P0: "Live audit-firm blog scraper (beyond PDFs:
ToB / Spearbit / OpenZeppelin / Halborn engineering blogs)".

Companion to W4.2 (``tools/hackerman-etl-from-post-mortem.py``, commit
156a0ccf3b) and W2.7.a (``tools/hackerman-etl-from-immunefi-medium.py``,
commit bc6830bcb7). All three families share ``tools/lib/hackerman_web_cache.py``.

Supported sources (``--source <name>``):

- ``tob``           trailofbits.com/blog/ (Trail of Bits engineering blog)
- ``spearbit``      blog.spearbit.com (Spearbit / Cantina blog)
- ``openzeppelin``  blog.openzeppelin.com (OZ security blog)
- ``chainsecurity`` chainsecurity.com/blog/ (ChainSecurity)
- ``halborn``       halborn.com/blog/ (Halborn)
- ``certik``        certik.com/research/ (CertiK Research)
- ``cyfrin``        blog.cyfrin.io (Cyfrin blog)

These blogs publish security writeups, deep-dives, and technique posts
that do NOT appear in firm-PDF audit reports (which are covered by
``tools/hackerman-etl-from-audit-firm-public-reports.py``).

Pipeline:

1. Build a list of source URLs.
   - ``--url <single-url>``: one-page mode.
   - ``--url-list <file>``: newline-separated URL list (one per line;
     blank + ``#`` lines ignored).
   - No URL: walk the source's default index URL once and extract
     per-post anchors.

2. Per page: fetch via the shared WebCache; extract:
   - title (``<title>`` or first ``<h1>``)
   - author (``<meta name="author">`` or byline regex)
   - published_date (``<meta article:published_time>`` / regex)
   - tags (``<meta keywords>`` or article:tag)
   - summary (``<meta description>`` or first paragraph)
   - attack_class (keyword match across body)
   - affected_protocols (mentioned in body, heuristic)
   - severity_estimate (from keyword presence)
   - fix_commit_ref (GitHub commit / PR URLs)

3. Emit one ``<out-dir>/<source>/<slug>/<record_id>.json|.yaml`` per
   record, with ``verification_tier: tier-2-verified-public-archive``
   and SHA256 evidence per scraped page.

Hard rules:

- No live scrape on import path. ``--fetch`` required for network I/O;
  tests inject bytes via the cache.
- No LLM. All extraction is deterministic regex.
- Robots.txt respected by default; ``--no-respect-robots`` requires
  ``--i-acknowledge-tos``.
- SHA256 hash per scraped page in ``source_audit_ref.payload_sha256``.
- M14-trap discipline: every record's URL must resolve. No fabrication.
- Audit-firm blogs are public-source legitimate (no private-submission
  scraping per operator correction precedent at 7d131254ac).

Rule 37: tier-2-verified-public-archive on every emit.
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
SOURCE_EXTRACTION_METHOD = "web-scrape-audit-firm-blog"

DEFAULT_RATE_LIMIT_MS = 2000

SUPPORTED_SOURCES = (
    "tob",
    "spearbit",
    "openzeppelin",
    "chainsecurity",
    "halborn",
    "certik",
    "cyfrin",
)

SOURCE_DEFAULTS: Dict[str, Dict[str, Any]] = {
    "tob":           {"index_url": "https://blog.trailofbits.com/", "host": "blog.trailofbits.com"},
    "spearbit":      {"index_url": "https://blog.spearbit.com/",     "host": "blog.spearbit.com"},
    "openzeppelin":  {"index_url": "https://blog.openzeppelin.com/", "host": "blog.openzeppelin.com"},
    "chainsecurity": {"index_url": "https://www.chainsecurity.com/blog", "host": "www.chainsecurity.com"},
    "halborn":       {"index_url": "https://www.halborn.com/blog",   "host": "www.halborn.com"},
    "certik":        {"index_url": "https://www.certik.com/resources", "host": "www.certik.com"},
    "cyfrin":        {"index_url": "https://www.cyfrin.io/blog",     "host": "www.cyfrin.io"},
}


def _load_web_cache():
    spec = importlib.util.spec_from_file_location(
        "_hackerman_web_cache_for_audit_firm_blog",
        str(REPO_ROOT / "tools" / "lib" / "hackerman_web_cache.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


_WC = _load_web_cache()


# ---------------------------------------------------------------------------
# Local helpers (kept inline; sibling miners use the same shapes).
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
# HTML / regex primitives shared across all blog sources.
# ---------------------------------------------------------------------------


TITLE_RE = re.compile(r"<title[^>]*>(?P<text>.*?)</title>", re.DOTALL | re.IGNORECASE)
H1_RE = re.compile(r"<h1[^>]*>(?P<text>.*?)</h1>", re.DOTALL | re.IGNORECASE)
H2_RE = re.compile(r"<h2[^>]*>(?P<text>.*?)</h2>", re.DOTALL | re.IGNORECASE)
PARAGRAPH_RE = re.compile(r"<p[^>]*>(?P<text>.*?)</p>", re.DOTALL | re.IGNORECASE)

META_DATE_RE = re.compile(
    r'<meta[^>]+(?:property|name)=["\'](?:article:published_time|date|pubdate|og:article:published_time|published_time)["\'][^>]+content=["\'](?P<iso>[^"\']+)["\']',
    re.IGNORECASE,
)
META_AUTHOR_RE = re.compile(
    r'<meta[^>]+(?:name|property)=["\'](?:author|article:author|og:article:author)["\'][^>]+content=["\'](?P<author>[^"\']+)["\']',
    re.IGNORECASE,
)
META_DESCRIPTION_RE = re.compile(
    r'<meta[^>]+(?:name|property)=["\'](?:description|og:description|twitter:description)["\'][^>]+content=["\'](?P<desc>[^"\']+)["\']',
    re.IGNORECASE,
)
META_KEYWORDS_RE = re.compile(
    r'<meta[^>]+name=["\']keywords["\'][^>]+content=["\'](?P<kw>[^"\']+)["\']',
    re.IGNORECASE,
)
META_ARTICLE_TAG_RE = re.compile(
    r'<meta[^>]+property=["\']article:tag["\'][^>]+content=["\'](?P<tag>[^"\']+)["\']',
    re.IGNORECASE,
)

BYLINE_RE = re.compile(
    r"\bby\s+(?P<author>[A-Z][A-Za-z][A-Za-z\.\-\']+(?:\s+[A-Z][A-Za-z\.\-\']+){0,3})\b",
)

ANCHOR_RE = re.compile(
    r'<a[^>]+href=["\'](?P<href>[^"\']+)["\'][^>]*>(?P<text>.*?)</a>',
    re.DOTALL | re.IGNORECASE,
)
DATE_RE = re.compile(
    r"\b(?P<full>(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|"
    r"Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|"
    r"Nov(?:ember)?|Dec(?:ember)?)\s+\d{1,2},?\s+\d{4})\b",
    re.IGNORECASE,
)
ISO_DATE_RE = re.compile(r"\b(?P<iso>\d{4}-\d{2}-\d{2})\b")

FIX_COMMIT_RE = re.compile(
    r"https?://github\.com/(?P<owner>[A-Za-z0-9._-]+)/(?P<repo>[A-Za-z0-9._-]+)/(?:commit|pull)/(?P<id>[A-Za-z0-9]+)",
    re.IGNORECASE,
)


# Attack-class taxonomy. Same shape as W4.2 + a few blog-specific
# additions (formal verification, smart contract design patterns, etc.).
ATTACK_CLASS_KEYWORDS: Tuple[Tuple[re.Pattern, str], ...] = (
    (re.compile(r"\bre[- ]?entranc(?:y|e)\b", re.I), "reentrancy"),
    (re.compile(r"\boracle\s+manipulation\b|\bprice\s+manipulation\b", re.I), "oracle-manipulation"),
    (re.compile(r"\bsignature[- ]replay\b|\breplay\s+attack\b", re.I), "signature-replay"),
    (re.compile(r"\bsignature\s+verification\s+bypass\b|\buninitiali[sz]ed\s+proxy\b", re.I), "signature-verification-bypass"),
    (re.compile(r"\baccess[- ]control\b|\bmissing\s+onlyowner\b|\bauthori[sz]ation\s+bypass\b", re.I), "access-control-bypass"),
    (re.compile(r"\bgovernance[- ]takeover\b|\bquorum\s+manipulation\b", re.I), "governance-takeover"),
    (re.compile(r"\bbridge[- ](?:message[- ])?replay\b|\bcross[- ]chain\s+replay\b", re.I), "bridge-message-replay"),
    (re.compile(r"\bflash[- ]loan\b", re.I), "flash-loan"),
    (re.compile(r"\binteger\s+(?:under|over)flow\b|\boob\b|\bout\s+of\s+bounds\b", re.I), "memory-corruption"),
    (re.compile(r"\bprecision[- ]loss\b|\brounding\s+error\b", re.I), "precision-loss"),
    (re.compile(r"\bfront[- ]?runn?ing\b|\bsandwich\b|\bmev\b", re.I), "frontrunning"),
    (re.compile(r"\bdenial[- ]of[- ]service\b|\bDoS\b", re.I), "dos"),
    (re.compile(r"\bdelegatecall\s+(?:abuse|injection)\b|\bproxy\s+collision\b", re.I), "delegatecall-injection"),
    (re.compile(r"\bphishing\b|\bsocial\s+engineering\b", re.I), "phishing"),
    (re.compile(r"\bformal\s+verification\b|\bsmt\s+solver\b", re.I), "formal-verification"),
    (re.compile(r"\bfuzz(?:ing)?\b|\bechidna\b|\bmedusa\b|\bfoundry\s+fuzz\b", re.I), "fuzzing-technique"),
    (re.compile(r"\binvariant\s+test\b|\bproperty[- ]based\s+test\b", re.I), "invariant-testing"),
    (re.compile(r"\bzero[- ]knowledge\b|\bzk[- ]proof\b|\bzk[- ]circuit\b", re.I), "zk-circuit"),
    (re.compile(r"\bmerkle\s+(?:proof|tree)\s+(?:forgery|manipulation)\b", re.I), "merkle-proof-forgery"),
    (re.compile(r"\b(theft|stolen|drain|drained)\b", re.I), "theft-of-funds"),
    (re.compile(r"\bpermanent\s+freezing\b|\bfreeze\b|\bfrozen\b", re.I), "freeze-of-funds"),
    (re.compile(r"\bprivate[- ]key\s+(?:leak|compromise)\b", re.I), "private-key-compromise"),
)


# Affected-protocol heuristic. Detects common protocol names mentioned
# in a blog post body. Conservative list; widen via env override if
# needed.
KNOWN_PROTOCOL_PATTERNS: Tuple[Tuple[re.Pattern, str], ...] = (
    (re.compile(r"\b(uniswap)\b", re.I), "uniswap"),
    (re.compile(r"\b(curve)\b", re.I), "curve"),
    (re.compile(r"\b(balancer)\b", re.I), "balancer"),
    (re.compile(r"\b(aave)\b", re.I), "aave"),
    (re.compile(r"\b(compound)\b", re.I), "compound"),
    (re.compile(r"\b(makerdao|maker)\b", re.I), "makerdao"),
    (re.compile(r"\b(yearn)\b", re.I), "yearn"),
    (re.compile(r"\b(synthetix)\b", re.I), "synthetix"),
    (re.compile(r"\b(lido)\b", re.I), "lido"),
    (re.compile(r"\b(rocket\s*pool)\b", re.I), "rocketpool"),
    (re.compile(r"\b(eigen\s*layer)\b", re.I), "eigenlayer"),
    (re.compile(r"\b(arbitrum)\b", re.I), "arbitrum"),
    (re.compile(r"\b(optimism)\b", re.I), "optimism"),
    (re.compile(r"\b(polygon)\b", re.I), "polygon"),
    (re.compile(r"\b(starknet|starkware)\b", re.I), "starknet"),
    (re.compile(r"\b(zksync)\b", re.I), "zksync"),
    (re.compile(r"\b(cosmos[- ]sdk|cosmos)\b", re.I), "cosmos-sdk"),
    (re.compile(r"\b(tendermint|cometbft)\b", re.I), "cometbft"),
    (re.compile(r"\b(solana)\b", re.I), "solana"),
    (re.compile(r"\b(nomad)\b", re.I), "nomad"),
    (re.compile(r"\b(wormhole)\b", re.I), "wormhole"),
    (re.compile(r"\b(ronin)\b", re.I), "ronin"),
    (re.compile(r"\b(euler)\b", re.I), "euler"),
    (re.compile(r"\b(beanstalk)\b", re.I), "beanstalk"),
    (re.compile(r"\b(yearn|yvault)\b", re.I), "yearn"),
    (re.compile(r"\b(morpho)\b", re.I), "morpho"),
    (re.compile(r"\b(spark)\b", re.I), "spark"),
    (re.compile(r"\b(dydx)\b", re.I), "dydx"),
)


# Severity-estimate keyword heuristic. We only assign a severity when
# the body contains an explicit critical/high signal, otherwise
# default to "info" to avoid over-claiming. Operator-corrected at
# 7d131254ac: "info default, never silently upgrade".
SEVERITY_CRITICAL_RE = re.compile(
    # NOTE: no `\b` before `\$` - `$` is a non-word char usually preceded
    # by whitespace, so a leading word-boundary anchor can never match a
    # `$NN million drained` phrase. (Salvaged-tool dead-branch fix.)
    r"\bcritical\s+(?:bug|vuln|severity|finding)\b|(\$\d+\s*(?:million|m|billion|b))\s+(?:stolen|drained|lost)\b",
    re.IGNORECASE,
)
SEVERITY_HIGH_RE = re.compile(
    r"\bhigh\s+(?:severity|risk|impact|finding)\b",
    re.IGNORECASE,
)
SEVERITY_MEDIUM_RE = re.compile(
    r"\bmedium\s+(?:severity|risk|impact|finding)\b",
    re.IGNORECASE,
)


def strip_tags(html: str) -> str:
    return re.sub(r"<[^>]+>", " ", html).strip()


def first_paragraphs(article_body: str, n: int) -> List[str]:
    paragraphs = [strip_tags(m.group("text")) for m in PARAGRAPH_RE.finditer(article_body)]
    cleaned = [re.sub(r"\s+", " ", p).strip() for p in paragraphs if p.strip()]
    if not cleaned:
        chunks = re.split(r"\n\s*\n|(?<=[.!?])\s+(?=[A-Z])", article_body)
        cleaned = [re.sub(r"\s+", " ", c).strip() for c in chunks if c and c.strip()]
    return cleaned[:n]


def extract_published_date(paragraphs: List[str], html: str) -> Tuple[str, str]:
    # Prefer meta tag (most reliable for blogs).
    meta = META_DATE_RE.search(html)
    if meta:
        iso = meta.group("iso")[:10]
        if re.match(r"\d{4}-\d{2}-\d{2}", iso):
            return (iso, "meta-tag")
    for p in paragraphs:
        m_iso = ISO_DATE_RE.search(p)
        if m_iso:
            return (m_iso.group("iso"), "iso-body")
        m = DATE_RE.search(p)
        if m:
            return (m.group("full"), "regex-body")
    return ("", "none")


def extract_author(html: str, paragraphs: List[str]) -> Tuple[str, str]:
    """Return (author, source). Prefer meta tag, fallback to byline regex."""
    meta = META_AUTHOR_RE.search(html)
    if meta:
        return (meta.group("author").strip(), "meta-tag")
    for p in paragraphs[:4]:
        m = BYLINE_RE.search(p)
        if m:
            return (m.group("author").strip(), "byline-regex")
    return ("", "none")


def extract_summary(html: str, paragraphs: List[str]) -> str:
    meta = META_DESCRIPTION_RE.search(html)
    if meta:
        return strip_tags(meta.group("desc"))[:400]
    if paragraphs:
        return paragraphs[0][:400]
    return ""


def extract_tags(html: str) -> List[str]:
    tags: List[str] = []
    seen: set = set()
    kw = META_KEYWORDS_RE.search(html)
    if kw:
        for raw in kw.group("kw").split(","):
            t = raw.strip().lower()
            if t and t not in seen:
                seen.add(t)
                tags.append(t)
    for m in META_ARTICLE_TAG_RE.finditer(html):
        t = m.group("tag").strip().lower()
        if t and t not in seen:
            seen.add(t)
            tags.append(t)
    return tags


def extract_attack_class(article_body: str) -> str:
    hay = strip_tags(article_body).lower()
    for pat, label in ATTACK_CLASS_KEYWORDS:
        if pat.search(hay):
            return label
    return "unspecified"


def extract_affected_protocols(article_body: str) -> List[str]:
    hay = strip_tags(article_body)
    found: List[str] = []
    seen: set = set()
    for pat, label in KNOWN_PROTOCOL_PATTERNS:
        if pat.search(hay) and label not in seen:
            seen.add(label)
            found.append(label)
    return found


def extract_severity_estimate(article_body: str) -> str:
    hay = strip_tags(article_body)
    if SEVERITY_CRITICAL_RE.search(hay):
        return "critical"
    if SEVERITY_HIGH_RE.search(hay):
        return "high"
    if SEVERITY_MEDIUM_RE.search(hay):
        return "medium"
    return "info"


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


def extract_post_title(title: str, h1_first: str) -> str:
    text = (title or h1_first or "").strip()
    text = re.sub(r"\s+", " ", text)
    # Drop trailing firm name suffix variants:
    #   "...| Trail of Bits Blog", "- Spearbit", "| OpenZeppelin Blog", etc.
    text = re.sub(
        r"\s*[-|]\s*(?:trail\s+of\s+bits(?:\s+blog)?|spearbit|openzeppelin(?:\s+blog)?|"
        r"chainsecurity|halborn|certik(?:\s+research)?|cyfrin(?:\s+blog)?)\s*$",
        "",
        text,
        flags=re.IGNORECASE,
    )
    return text[:200]


# ---------------------------------------------------------------------------
# Index-page anchor extraction (per-source heuristic).
# ---------------------------------------------------------------------------


def parse_index_anchors(html: str, source: str) -> List[str]:
    """Extract per-post URLs from a firm's blog index page.

    Per-source heuristic: each blog uses a different URL pattern. We
    walk all anchors and keep ones whose href matches the source's
    expected post-path shape AND whose host matches.
    """
    host = SOURCE_DEFAULTS.get(source, {}).get("host", "")
    urls: List[str] = []
    seen: set = set()
    for m in ANCHOR_RE.finditer(html):
        href = m.group("href").strip()
        if not href.startswith("http"):
            continue
        if host and host not in href:
            continue
        # Heuristic per-source path filters.
        if source == "tob":
            # /<YYYY>/<MM>/<DD>/<slug>/ or /blog/<slug>/
            if not (re.search(r"/\d{4}/\d{2}/", href) or "/blog/" in href):
                continue
        elif source == "spearbit":
            if not (href.rstrip("/").count("/") >= 3 or "/blog/" in href):
                continue
        elif source == "openzeppelin":
            # blog.openzeppelin.com/<slug>
            path = href.split(host, 1)[-1].strip("/") if host in href else ""
            if not path or path in {"", "blog"}:
                continue
        elif source == "chainsecurity":
            if "/blog/" not in href and "/post/" not in href:
                continue
        elif source == "halborn":
            if "/blog/" not in href:
                continue
        elif source == "certik":
            if not any(seg in href for seg in ("/resources/", "/research/", "/insights/", "/blog/")):
                continue
        elif source == "cyfrin":
            if "/blog/" not in href:
                continue
        # Skip pure category / tag landing pages.
        if any(seg in href for seg in ("/tag/", "/category/", "/page/", "/author/")):
            continue
        normalized = href.split("#", 1)[0].split("?", 1)[0]
        if not normalized.endswith("/"):
            normalized = normalized + "/"
        # Skip the index pages themselves.
        default_index = SOURCE_DEFAULTS.get(source, {}).get("index_url", "")
        if default_index and normalized.rstrip("/") == default_index.rstrip("/"):
            continue
        if normalized not in seen:
            seen.add(normalized)
            urls.append(normalized)
    return urls


# ---------------------------------------------------------------------------
# Generic page-based record builder
# ---------------------------------------------------------------------------


def build_blog_record(
    *,
    source: str,
    page_url: str,
    html: str,
    payload_sha256: str,
    fetched_at_utc: str,
) -> Dict[str, Any]:
    title_m = TITLE_RE.search(html)
    title_text = strip_tags(title_m.group("text")) if title_m else ""
    h1_m = H1_RE.search(html)
    h1_text = strip_tags(h1_m.group("text")) if h1_m else ""
    post_title = extract_post_title(title_text, h1_text)
    paragraphs = first_paragraphs(html, 8)
    published_date, published_date_source = extract_published_date(paragraphs, html)
    author, author_source = extract_author(html, paragraphs)
    summary = extract_summary(html, paragraphs)
    tags = extract_tags(html)
    attack_class = extract_attack_class(html)
    affected_protocols = extract_affected_protocols(html)
    severity_estimate = extract_severity_estimate(html)
    fix_refs = extract_fix_commit_refs(html)
    target_repo = extract_target_repo(html)

    slug_basis = page_url.rstrip("/").rsplit("/", 1)[-1] or post_title or "unknown"
    slug = slugify(slug_basis, max_len=64)
    digest_seed = f"{source}\n{page_url}\n{payload_sha256}".encode("utf-8")
    digest = hashlib.sha256(digest_seed).hexdigest()[:12]
    record_id = f"blog-{source}-{slug}-{digest}"

    record: Dict[str, Any] = {
        "record_id": record_id,
        "record_tier": "public-corpus",
        "verification_tier": VERIFICATION_TIER,
        "source_extraction_method": f"web-scrape-blog-{source}",
        "record_source_url": page_url,
        "source_audit_ref": {
            "url": page_url,
            "fetched_at_utc": fetched_at_utc,
            "payload_sha256": payload_sha256,
        },
        "target_project": post_title or slug,
        "target_project_slug": slug,
        "target_repo": target_repo or "unknown",
        "post_title": post_title,
        "published_date": published_date,
        "published_date_source": published_date_source,
        "author": author,
        "author_source": author_source,
        "severity_estimate": severity_estimate,
        "attack_class": attack_class,
        "affected_protocols": affected_protocols,
        "tags": tags,
        "summary": summary,
        "fix_commit_ref": fix_refs,
        "record_extensions": {
            "published_at": published_date,
            "author": author,
            "affected_protocols": affected_protocols,
            "summary": summary,
            "tags": tags,
        },
        "title_h2_mismatch": False,
        "jsonld_schema_drift": [],
        "verification_chain": [
            {"step": "fetch", "proof": payload_sha256},
            {"step": "parse", "proof": hashlib.sha256(
                json.dumps({
                    "url": page_url,
                    "title": post_title,
                    "date": published_date,
                    "author": author,
                    "attack_class": attack_class,
                }, sort_keys=True).encode("utf-8")).hexdigest()},
        ],
        "notes": f"tier-2 {source} audit-firm-blog post; regex-extracted body",
    }
    emit_seed = json.dumps(
        {k: v for k, v in record.items() if k != "verification_chain"},
        sort_keys=True,
    ).encode("utf-8")
    record["verification_chain"].append(
        {"step": "emit", "proof": hashlib.sha256(emit_seed).hexdigest()}
    )
    return record


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


def write_record(out_dir: Path, source: str, record: Dict[str, Any]) -> Tuple[Path, Path]:
    slug = record.get("target_project_slug", "unknown")
    target = out_dir / source / slug
    target.mkdir(parents=True, exist_ok=True)
    # Spec says filename is blog-<source>-<slug>.yaml; ensure unique via digest tail.
    digest = record["record_id"].rsplit("-", 1)[-1]
    base = f"blog-{source}-{slug}-{digest}"
    json_path = target / f"{base}.json"
    yaml_path = target / f"{base}.yaml"
    json_path.write_text(json.dumps(record, indent=2, sort_keys=True), encoding="utf-8")
    yaml_path.write_text(yaml_dump(record), encoding="utf-8")
    return json_path, yaml_path


# ---------------------------------------------------------------------------
# URL-list mode
# ---------------------------------------------------------------------------


def load_url_list(path: Path) -> List[str]:
    out: List[str] = []
    seen: set = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line not in seen:
            seen.add(line)
            out.append(line)
    return out


# ---------------------------------------------------------------------------
# Top-level convert / CLI
# ---------------------------------------------------------------------------


def convert(
    *,
    cache: "_WC.WebCache",
    out_dir: Path,
    source: str,
    fetch_live: bool,
    urls: List[str],
    index_url: Optional[str],
    dry_run: bool,
    max_pages: Optional[int],
) -> Dict[str, Any]:
    summary: Dict[str, Any] = {
        "source": source,
        "verification_tier": VERIFICATION_TIER,
        "source_extraction_method": SOURCE_EXTRACTION_METHOD,
        "cache_dir": str(cache.cache_dir),
        "out_dir": str(out_dir),
        "fetch_live": bool(fetch_live),
        "dry_run": bool(dry_run),
        "index_pages_visited": 0,
        "urls_resolved": 0,
        "records_emitted": 0,
        "by_severity": {},
        "by_attack_class": {},
        "files": [],
        "errors": [],
    }
    out_dir.mkdir(parents=True, exist_ok=True)

    resolved: List[str] = list(urls)
    if not resolved and index_url:
        try:
            res = cache.fetch(index_url)
        except Exception as exc:  # noqa: BLE001
            summary["errors"].append(f"fetch index {index_url}: {exc}")
            return summary
        summary["index_pages_visited"] += 1
        body = res.payload.decode("utf-8", errors="replace")
        resolved = parse_index_anchors(body, source)

    if max_pages is not None:
        resolved = resolved[:max_pages]
    summary["urls_resolved"] = len(resolved)

    for url in resolved:
        try:
            res = cache.fetch(url)
        except Exception as exc:  # noqa: BLE001
            summary["errors"].append(f"fetch {url}: {exc}")
            continue
        html = res.payload.decode("utf-8", errors="replace")
        record = build_blog_record(
            source=source,
            page_url=url,
            html=html,
            payload_sha256=res.payload_sha256,
            fetched_at_utc=res.fetched_at_utc,
        )
        summary["by_severity"][record["severity_estimate"]] = (
            summary["by_severity"].get(record["severity_estimate"], 0) + 1
        )
        summary["by_attack_class"][record["attack_class"]] = (
            summary["by_attack_class"].get(record["attack_class"], 0) + 1
        )
        if dry_run:
            summary["records_emitted"] += 1
            continue
        json_path, _yaml_path = write_record(out_dir, source, record)
        summary["records_emitted"] += 1
        summary["files"].append(str(json_path))
    return summary


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="hackerman-etl-from-audit-firm-blog",
        description="Mine audit-firm engineering blogs into hackerman tier-2 records (W4.4).",
    )
    p.add_argument("--source", required=True, choices=SUPPORTED_SOURCES)
    p.add_argument("--cache-dir", required=True, type=Path)
    p.add_argument("--out-dir", required=True, type=Path)
    p.add_argument("--url", default=None, help="single-page mode (overrides --url-list)")
    p.add_argument("--url-list", default=None, type=Path, help="batch mode (one URL per line)")
    p.add_argument("--index-url", default=None, help="override the source's default index URL")
    p.add_argument("--fetch", action="store_true")
    p.add_argument("--rate-limit-ms", type=int, default=DEFAULT_RATE_LIMIT_MS)
    p.add_argument("--max-pages", type=int, default=None)
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
    urls: List[str] = []
    if args.url:
        urls = [args.url]
    elif args.url_list:
        if not args.url_list.exists():
            sys.stderr.write(f"ERROR: --url-list path missing: {args.url_list}\n")
            return 2
        urls = load_url_list(args.url_list)
    cache = _WC.WebCache(
        cache_dir=args.cache_dir,
        rate_limit_ms=args.rate_limit_ms,
        respect_robots=args.respect_robots,
        i_acknowledge_tos=args.i_acknowledge_tos,
        offline=not bool(args.fetch),
    )
    index_url = args.index_url or SOURCE_DEFAULTS[args.source].get("index_url") or None
    summary = convert(
        cache=cache,
        out_dir=args.out_dir,
        source=args.source,
        fetch_live=bool(args.fetch),
        urls=urls,
        index_url=index_url if not urls else None,
        dry_run=bool(args.dry_run),
        max_pages=args.max_pages,
    )
    if args.json_summary:
        sys.stdout.write(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    if summary.get("records_emitted", 0) == 0 and summary.get("urls_resolved", 0) == 0:
        sys.stderr.write("BLOCKED-NO-REAL-SOURCE: empty cache and --fetch not requested\n")
        return 3
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
