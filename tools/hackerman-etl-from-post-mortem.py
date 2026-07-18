#!/usr/bin/env python3
"""Mine public exploit post-mortems for hackerman tier-2 detector seeds.

Wave-4 P0 W4.2. Roadmap anchor:
``docs/HACKERMAN_WAVE4_CAPABILITY_ROADMAP_2026-05-16.md`` (commit 91ed239131)
lists this lane as P0: "every public exploit writeup -> real-source
detector pattern seed".

Supported sources (``--source <name>``):

- ``rekt``         rekt.news incident pages (https://rekt.news/<slug>/)
- ``defillama``    defillama.com/hacks JSON API at
                   https://api.llama.fi/hacks (one record per hack)
- ``samczsun``     samczsun.com/research blog archive (operator-curated
                   URL list mode)
- ``pcaversaccio`` pcaversaccio.com + cantina.xyz/u/pcaversaccio blog
                   archive (operator-curated URL list mode)
- ``hackmd``       generic hackmd.io URL list mode (post-mortems land
                   here often; operator-curated list)

Pipeline:

1. Build a list of source URLs.
   - ``--url <single-url>``: one-page mode.
   - ``--url-list <file>``: newline-separated URL list (one per line;
     blank + ``#`` lines ignored).
   - ``--source defillama`` with no URL: pull the JSON API once at
     https://api.llama.fi/hacks and emit one record per incident
     entry (no individual page-fetch).
   - ``--source rekt`` with no URL: walk the ``--index-url`` once
     (default https://rekt.news/leaderboard/) and extract per-slug
     anchors.

2. Per page (rekt / samczsun / pcaversaccio / hackmd):
   fetch via the shared WebCache; extract:
   - title (``<title>`` or first ``<h1>``)
   - incident_date (first calendar date in opening paragraphs)
   - amount_stolen_usd (largest dollar amount in the body)
   - attack_class (keyword match)
   - fix_commit_ref (GitHub commit / PR URLs)
   - protocol / target_project (heuristic from title)

3. Per defillama JSON entry: emit one record straight from the JSON
   row (no body parse).

4. Emit one ``<out-dir>/<source>/<slug>/<record_id>.json|.yaml`` per
   record, with ``verification_tier: tier-2-verified-public-archive``
   and SHA256 evidence per scraped page.

Hard rules:

- No live scrape on import path. ``--fetch`` required for network I/O;
  tests inject bytes via the cache.
- No LLM. All extraction is deterministic regex + JSON parse.
- Robots.txt respected by default; ``--no-respect-robots`` requires
  ``--i-acknowledge-tos``.
- SHA256 hash per scraped page in ``source_audit_ref.payload_sha256``.
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
SOURCE_EXTRACTION_METHOD = "web-scrape-post-mortem"

DEFAULT_RATE_LIMIT_MS = 2000

SUPPORTED_SOURCES = ("rekt", "defillama", "samczsun", "pcaversaccio", "hackmd")

SOURCE_DEFAULTS: Dict[str, Dict[str, Any]] = {
    "rekt":         {"index_url": "https://rekt.news/leaderboard/"},
    "defillama":    {"index_url": "https://api.llama.fi/hacks"},
    "samczsun":     {"index_url": "https://samczsun.com/research/"},
    "pcaversaccio": {"index_url": "https://pcaversaccio.com/"},
    "hackmd":       {"index_url": ""},  # always URL-list driven
}


def _load_web_cache():
    spec = importlib.util.spec_from_file_location(
        "_hackerman_web_cache_for_post_mortem",
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
# HTML / regex primitives shared across page-based sources.
# ---------------------------------------------------------------------------


TITLE_RE = re.compile(r"<title[^>]*>(?P<text>.*?)</title>", re.DOTALL | re.IGNORECASE)
H1_RE = re.compile(r"<h1[^>]*>(?P<text>.*?)</h1>", re.DOTALL | re.IGNORECASE)
H2_RE = re.compile(r"<h2[^>]*>(?P<text>.*?)</h2>", re.DOTALL | re.IGNORECASE)
PARAGRAPH_RE = re.compile(r"<p[^>]*>(?P<text>.*?)</p>", re.DOTALL | re.IGNORECASE)
META_DATE_RE = re.compile(
    r'<meta[^>]+(?:property|name)=["\'](?:article:published_time|date|pubdate|og:article:published_time)["\'][^>]+content=["\'](?P<iso>[^"\']+)["\']',
    re.IGNORECASE,
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
    (re.compile(r"\bprivate[- ]key\s+(?:leak|compromise)\b", re.I), "private-key-compromise"),
    (re.compile(r"\bdelegatecall\s+(?:abuse|injection)\b", re.I), "delegatecall-injection"),
    (re.compile(r"\bphishing\b|\bsocial\s+engineering\b", re.I), "phishing"),
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


def extract_incident_date(paragraphs: List[str], html: str) -> Tuple[str, str]:
    for p in paragraphs:
        m = DATE_RE.search(p)
        if m:
            return (m.group("full"), "regex-body")
        m_iso = ISO_DATE_RE.search(p)
        if m_iso:
            return (m_iso.group("iso"), "iso-body")
    meta = META_DATE_RE.search(html)
    if meta:
        iso = meta.group("iso")[:10]
        if re.match(r"\d{4}-\d{2}-\d{2}", iso):
            return (iso, "meta-tag")
    return ("", "none")


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
    """Return (amount_usd, confidence, literal_match)."""
    best_amount = 0
    best_literal = ""
    best_confidence = "low"
    for p in paragraphs[:6]:
        for m in AMOUNT_RE.finditer(p):
            amt = parse_amount(m.group("amt"), m.group("unit"))
            if amt > best_amount:
                best_amount = amt
                best_literal = m.group(0)
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


def extract_target_project(title: str, h1_first: str) -> str:
    text = (title or h1_first or "").strip()
    text = re.sub(r"\s+", " ", text)
    # Drop trailing "- rekt", "| Cantina", etc.
    text = re.sub(r"\s*[-|]\s*(?:rekt|cantina|samczsun|hackmd|medium).*$", "", text, flags=re.I)
    return text[:200]


# ---------------------------------------------------------------------------
# Per-source page extractors
# ---------------------------------------------------------------------------


def extract_rekt_slug(url: str) -> str:
    """`https://rekt.news/euler-rekt/` -> `euler-rekt`."""
    path = url.rstrip("/").rsplit("/", 1)[-1]
    return slugify(path or "rekt", max_len=80)


REKT_SKIP_PATHS = {
    "",
    "/",
    "/leaderboard",
    "/research",
    "/termAndConditions",
    "/term-and-conditions",
}


def parse_rekt_index(html: str, base: str = "https://rekt.news") -> List[str]:
    urls: List[str] = []
    seen: set = set()
    for m in ANCHOR_RE.finditer(html):
        href = m.group("href").strip()
        if href.startswith("//"):
            href = "https:" + href
        if href.startswith("/"):
            path = "/" + href.strip("/")
            href = base.rstrip("/") + path
        if not href.startswith(("https://rekt.news/", "https://www.rekt.news/")):
            continue
        href = href.split("#", 1)[0].split("?", 1)[0].rstrip("/")
        path = re.sub(r"^https://(?:www\.)?rekt\.news", "", href, flags=re.I)
        path = "/" + path.strip("/")
        if path in REKT_SKIP_PATHS:
            continue
        # Static assets and Next.js internals are not incident pages.
        if path.startswith(("/_next/", "/api/", "/images/", "/assets/")):
            continue
        if re.search(r"\.(?:css|js|json|png|jpe?g|svg|webp|gif|ico)$", path, re.I):
            continue
        href = "https://rekt.news" + path.rstrip("/") + "/"
        if href not in seen:
            seen.add(href)
            urls.append(href)
    return urls


# ---------------------------------------------------------------------------
# DefiLlama JSON API parser
# ---------------------------------------------------------------------------


def parse_defillama_hacks(json_body: bytes) -> List[Dict[str, Any]]:
    """Return a list of hack-incident dicts (best-effort across schema variants)."""
    try:
        data = json.loads(json_body.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        return []
    # API returns a top-level list of hack dicts.
    if isinstance(data, list):
        return [e for e in data if isinstance(e, dict)]
    # Sometimes wrapped in {"hacks": [...]}.
    if isinstance(data, dict):
        for key in ("hacks", "data", "items"):
            if isinstance(data.get(key), list):
                return [e for e in data[key] if isinstance(e, dict)]
    return []


def build_defillama_record(
    *,
    entry: Dict[str, Any],
    source_url: str,
    payload_sha256: str,
    fetched_at_utc: str,
) -> Dict[str, Any]:
    name = str(entry.get("name") or entry.get("project") or entry.get("protocol") or "")
    date_iso = ""
    raw_date = entry.get("date")
    if isinstance(raw_date, str):
        m_iso = ISO_DATE_RE.search(raw_date)
        if m_iso:
            date_iso = m_iso.group("iso")
        elif re.fullmatch(r"\d+", raw_date.strip()):
            # Unix seconds.
            from datetime import datetime, timezone

            date_iso = datetime.fromtimestamp(int(raw_date), tz=timezone.utc).strftime("%Y-%m-%d")
    elif isinstance(raw_date, (int, float)):
        from datetime import datetime, timezone

        date_iso = datetime.fromtimestamp(int(raw_date), tz=timezone.utc).strftime("%Y-%m-%d")
    amount_usd_field = entry.get("amount") or entry.get("amountLost") or 0
    try:
        amount_usd = int(float(amount_usd_field))
    except (TypeError, ValueError):
        amount_usd = 0
    # Heuristic attack-class derivation from "technique" / "classification" field.
    technique = str(entry.get("technique") or entry.get("category") or entry.get("classification") or "")
    attack_class = extract_attack_class(technique) if technique else "unspecified"
    if attack_class == "unspecified" and amount_usd > 0:
        # Default for incidents with no technique tag.
        attack_class = "theft-of-funds"
    target_repo = str(entry.get("source") or entry.get("repo") or "unknown")
    source_ref = str(entry.get("source") or entry.get("link") or source_url)
    payload_keys = sorted(entry.keys())
    severity = severity_from_amount(amount_usd)
    dollar_class = amount_to_dollar_class(amount_usd)
    slug = slugify(name or "unknown-defillama", max_len=80)
    digest_seed = f"defillama\n{name}\n{date_iso}\n{amount_usd}".encode("utf-8")
    digest = hashlib.sha256(digest_seed).hexdigest()[:12]
    record_id = f"post-mortem-defillama:{slug}:{digest}"
    record: Dict[str, Any] = {
        "record_id": record_id,
        "record_tier": "public-corpus",
        "verification_tier": VERIFICATION_TIER,
        "source_extraction_method": "web-scrape-defillama-hacks-api",
        "source_audit_ref": {
            "url": source_url,
            "fetched_at_utc": fetched_at_utc,
            "payload_sha256": payload_sha256,
            "external_source_ref": source_ref,
        },
        "target_project": name or slug,
        "target_project_slug": slug,
        "target_repo": target_repo or "unknown",
        "incident_date": date_iso,
        "incident_date_source": "defillama-api",
        "severity_at_finding": severity,
        "amount_stolen_usd_estimate": amount_usd,
        "amount_stolen_confidence": "high" if amount_usd > 0 else "low",
        "amount_stolen_literal_match": str(amount_usd_field),
        "impact_dollar_class": dollar_class,
        "attack_class": attack_class,
        "fix_commit_ref": [],
        "record_extensions": {
            "incident_date": date_iso,
            "impact_usd": amount_usd,
            "attack_vector_summary": technique[:400],
            "defillama_payload_keys": payload_keys,
        },
        "title_h2_mismatch": False,
        "jsonld_schema_drift": [],
        "verification_chain": [
            {"step": "fetch", "proof": payload_sha256},
            {"step": "parse", "proof": hashlib.sha256(
                json.dumps({"name": name, "amount": amount_usd, "date": date_iso},
                           sort_keys=True).encode("utf-8")).hexdigest()},
        ],
        "notes": "tier-2 defillama-hacks api row; no body parse",
    }
    emit_seed = json.dumps({k: v for k, v in record.items() if k != "verification_chain"},
                           sort_keys=True).encode("utf-8")
    record["verification_chain"].append(
        {"step": "emit", "proof": hashlib.sha256(emit_seed).hexdigest()}
    )
    return record


# ---------------------------------------------------------------------------
# Generic page-based record builder
# ---------------------------------------------------------------------------


def build_page_record(
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
    target_project = extract_target_project(title_text, h1_text)
    paragraphs = first_paragraphs(html, 8)
    incident_date, incident_date_source = extract_incident_date(paragraphs, html)
    amount_usd, amount_conf, amount_literal = extract_amount_stolen(paragraphs)
    severity = severity_from_amount(amount_usd)
    dollar_class = amount_to_dollar_class(amount_usd)
    attack_class = extract_attack_class(html)
    fix_refs = extract_fix_commit_refs(html)
    target_repo = extract_target_repo(html)

    slug_basis = page_url.rstrip("/").rsplit("/", 1)[-1] or target_project or "unknown"
    slug = slugify(slug_basis, max_len=64)
    digest_seed = f"{source}\n{page_url}\n{payload_sha256}".encode("utf-8")
    digest = hashlib.sha256(digest_seed).hexdigest()[:12]
    record_id = f"post-mortem-{source}:{slug}:{digest}"
    attack_vector_summary = paragraphs[0][:400] if paragraphs else ""
    record: Dict[str, Any] = {
        "record_id": record_id,
        "record_tier": "public-corpus",
        "verification_tier": VERIFICATION_TIER,
        "source_extraction_method": f"web-scrape-{source}",
        "source_audit_ref": {
            "url": page_url,
            "fetched_at_utc": fetched_at_utc,
            "payload_sha256": payload_sha256,
        },
        "target_project": target_project or slug,
        "target_project_slug": slug,
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
        "record_extensions": {
            "incident_date": incident_date,
            "impact_usd": amount_usd,
            "attack_vector_summary": attack_vector_summary,
        },
        "title_h2_mismatch": False,
        "jsonld_schema_drift": [],
        "verification_chain": [
            {"step": "fetch", "proof": payload_sha256},
            {"step": "parse", "proof": hashlib.sha256(
                json.dumps({"url": page_url, "title": target_project, "amount": amount_usd},
                           sort_keys=True).encode("utf-8")).hexdigest()},
        ],
        "notes": f"tier-2 {source} post-mortem; regex-extracted body",
    }
    emit_seed = json.dumps({k: v for k, v in record.items() if k != "verification_chain"},
                           sort_keys=True).encode("utf-8")
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
    digest = record["record_id"].rsplit(":", 1)[-1]
    base = f"{slugify(record['severity_at_finding'])}-{digest}"
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

    # -------- defillama JSON API --------
    if source == "defillama":
        target = urls[0] if urls else (index_url or SOURCE_DEFAULTS["defillama"]["index_url"])
        try:
            res = cache.fetch(target)
        except Exception as exc:  # noqa: BLE001
            summary["errors"].append(f"fetch defillama {target}: {exc}")
            return summary
        summary["index_pages_visited"] += 1
        entries = parse_defillama_hacks(res.payload)
        if max_pages is not None:
            entries = entries[:max_pages]
        summary["urls_resolved"] = len(entries)
        for entry in entries:
            record = build_defillama_record(
                entry=entry,
                source_url=target,
                payload_sha256=res.payload_sha256,
                fetched_at_utc=res.fetched_at_utc,
            )
            summary["by_severity"][record["severity_at_finding"]] = (
                summary["by_severity"].get(record["severity_at_finding"], 0) + 1
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

    # -------- rekt / samczsun / pcaversaccio / hackmd --------
    resolved: List[str] = list(urls)
    if not resolved and index_url:
        try:
            res = cache.fetch(index_url)
        except Exception as exc:  # noqa: BLE001
            summary["errors"].append(f"fetch index {index_url}: {exc}")
            return summary
        summary["index_pages_visited"] += 1
        body = res.payload.decode("utf-8", errors="replace")
        if source == "rekt":
            resolved = parse_rekt_index(body)
        else:
            # samczsun / pcaversaccio / hackmd index pages: extract anchors.
            for m in ANCHOR_RE.finditer(body):
                href = m.group("href").strip()
                if href.startswith("http") and href not in resolved:
                    resolved.append(href)

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
        record = build_page_record(
            source=source,
            page_url=url,
            html=html,
            payload_sha256=res.payload_sha256,
            fetched_at_utc=res.fetched_at_utc,
        )
        summary["by_severity"][record["severity_at_finding"]] = (
            summary["by_severity"].get(record["severity_at_finding"], 0) + 1
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
        prog="hackerman-etl-from-post-mortem",
        description="Mine public exploit post-mortems into hackerman tier-2 records (W4.2).",
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
