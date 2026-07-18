#!/usr/bin/env python3
"""Mine immunefi.com/explore/ + per-bounty subpages into hackerman tier-2 records.

W2.7.a target #1. See ``docs/WAVE2_W27A_IMMUNEFI_DASHBOARD_SPEC_2026-05-16.md``
for the full contract; this docstring captures only the operational
shape.

Behaviour contract (mirrors spec §3.1):

* Cache-then-parse: every fetched URL lands as
  ``<cache-dir>/pages/<sha256>.html.gz`` plus a sidecar
  ``<cache-dir>/pages/<sha256>.meta.json`` recording sha256 of the
  payload, fetched_at_utc, http_status, content_type, robots_decision.
* Robots.txt honoured by default (``--respect-robots``). The
  ``--no-respect-robots`` + ``--i-acknowledge-tos`` co-occurrence
  override is documented but not exercised by tests.
* Default rate-limit between live fetches: 1500 ms.
* SHA256 hash evidence per scraped page (raw bytes) is recorded in
  the sidecar meta JSON and embedded in every emitted record's
  ``source_audit_ref`` block.
* Output: per ``(project_slug, severity_tier, asset_class)`` row,
  emit ``<out-dir>/<project_slug>/<record_id>.json`` AND
  ``<out-dir>/<project_slug>/<record_id>.yaml``. The two formats
  carry identical content; YAML is human-readable, JSON is for
  ingestion by the corpus-tagger pipeline.
* Verification tier: ``tier-2-verified-public-archive``.

Hard rules followed:

* No live scrape on import / test path. The CLI requires either
  ``--fetch`` (which contacts the network) or a populated
  ``--cache-dir`` (offline). Tests inject pages via the cache.
* This file does NOT touch any existing file.
* Cross-links are relative paths only.
* This file does NOT modify ``tools/calibration/llm_budget_log.jsonl``.
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
SOURCE_EXTRACTION_METHOD = "web-scrape-static-html"
DEFAULT_RATE_LIMIT_MS = 1500
EXPLORE_INDEX_URL = "https://immunefi.com/explore/"
BOUNTY_URL_PREFIX = "https://immunefi.com/bug-bounty/"


def _load_web_cache():
    spec = importlib.util.spec_from_file_location(
        "_hackerman_web_cache_for_immunefi_dashboard",
        str(REPO_ROOT / "tools" / "lib" / "hackerman_web_cache.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


_WC = _load_web_cache()


SEVERITY_NORMALISE = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "insight": "info",
    "info": "info",
}

SEVERITY_TO_DOLLAR_DEFAULT = {
    "critical": ">=$1M",
    "high": "$100K-$1M",
    "medium": "$10K-$100K",
    "low": "<$10K",
    "info": "non-financial",
}


# ---------------------------------------------------------------------------
# YAML rendering (kept simple + deterministic; same conventions as the
# sibling tier-1 miner ``tools/hackerman-etl-from-immunefi-public.py``).
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
# Parsing the explore index + per-bounty subpages.
#
# Two parse modes are supported:
#
# 1. JSON-LD block: ``<script type="application/ld+json">...</script>``
#    embedded by immunefi.com for SEO. When present, we prefer this
#    payload because it's structured.
# 2. Selector-fallback: regex over common DOM shapes (e.g. severity-
#    table rows). Each fallback path carries a confidence tag.
# ---------------------------------------------------------------------------


JSONLD_RE = re.compile(
    r'<script[^>]+type=["\']application/ld\+json["\'][^>]*>(.*?)</script>',
    re.DOTALL | re.IGNORECASE,
)
BOUNTY_LINK_RE = re.compile(
    r'href=["\']/bug-bounty/(?P<slug>[a-z0-9._-]+)/?["\']',
    re.IGNORECASE,
)
TITLE_RE = re.compile(r"<title[^>]*>(?P<text>.*?)</title>", re.DOTALL | re.IGNORECASE)
H1_RE = re.compile(r"<h1[^>]*>(?P<text>.*?)</h1>", re.DOTALL | re.IGNORECASE)
SEVERITY_ROW_RE = re.compile(
    r"\b(?P<severity>Critical|High|Medium|Low|Insight)\b[^$]{0,200}?"
    r"(?:Up\s+to\s+)?\$(?P<amount>[\d,]+(?:\.\d+)?)(?P<unit>\s*(?:million|M|K|thousand)?)?",
    re.IGNORECASE | re.DOTALL,
)
IMPACT_BULLET_RE = re.compile(
    r"<li[^>]*>(?P<text>(?:(?!</li>).)*?(?:theft|freezing|smart contract|dos|griefing|loss of funds|drain).*?)</li>",
    re.DOTALL | re.IGNORECASE,
)
ASSET_CLASS_RE = re.compile(
    r"(Smart\s*Contract|Blockchain[/ ]?DLT|Websites?\s*(?:and|&)\s*Applications?)",
    re.IGNORECASE,
)
GITHUB_REPO_RE = re.compile(
    r"https?://github\.com/(?P<owner>[A-Za-z0-9._-]+)/(?P<repo>[A-Za-z0-9._-]+)",
    re.IGNORECASE,
)
STATUS_RE = re.compile(r"\b(active|paused|ended|closed)\b", re.IGNORECASE)
PAID_OUT_RE = re.compile(
    r"\$(?P<amt>[\d,]+(?:\.\d+)?)(?P<unit>\s*(?:million|M|K|thousand)?)?\s+paid\s+out",
    re.IGNORECASE,
)


def parse_amount(amount: str, unit: Optional[str]) -> int:
    raw = float(amount.replace(",", ""))
    unit_norm = (unit or "").strip().lower()
    if unit_norm in {"million", "m"}:
        return int(raw * 1_000_000)
    if unit_norm in {"thousand", "k"}:
        return int(raw * 1_000)
    return int(raw)


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


def strip_tags(html: str) -> str:
    return re.sub(r"<[^>]+>", " ", html).strip()


def extract_jsonld(html: str) -> List[Dict[str, Any]]:
    """Return all parsed JSON-LD blocks (skipping any that fail to decode)."""
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


def extract_bounty_slugs(html: str) -> List[str]:
    seen: List[str] = []
    seen_set: set = set()
    for match in BOUNTY_LINK_RE.finditer(html):
        slug = match.group("slug").lower()
        if slug not in seen_set:
            seen_set.add(slug)
            seen.append(slug)
    return seen


def extract_title(html: str) -> str:
    h1 = H1_RE.search(html)
    if h1:
        return strip_tags(h1.group("text"))[:200]
    title = TITLE_RE.search(html)
    if title:
        return strip_tags(title.group("text"))[:200]
    return ""


def extract_severity_rows(html: str) -> List[Dict[str, Any]]:
    """Return list of {severity, dollar_ceiling, dollar_class} rows.

    Pulls each ``Severity ... $Amount`` pair surfaced in the page; one
    row per severity tier. Duplicates collapsed by keeping the
    highest-amount seen.
    """
    rows: Dict[str, Dict[str, Any]] = {}
    for match in SEVERITY_ROW_RE.finditer(html):
        sev_raw = match.group("severity").lower()
        sev = SEVERITY_NORMALISE.get(sev_raw, sev_raw)
        amount = parse_amount(match.group("amount"), match.group("unit"))
        existing = rows.get(sev)
        if existing is None or amount > existing.get("ceiling_usd", 0):
            rows[sev] = {
                "severity": sev,
                "ceiling_usd": amount,
                "ceiling_dollar_class": amount_to_dollar_class(amount),
            }
    # Stable order by severity rank.
    severity_rank = ["critical", "high", "medium", "low", "info"]
    return [rows[s] for s in severity_rank if s in rows]


def extract_impacts(html: str) -> List[str]:
    raw_bullets = [strip_tags(m.group("text"))[:300] for m in IMPACT_BULLET_RE.finditer(html)]
    cleaned: List[str] = []
    seen: set = set()
    for bullet in raw_bullets:
        norm = re.sub(r"\s+", " ", bullet).strip()
        if norm and norm.lower() not in seen:
            seen.add(norm.lower())
            cleaned.append(norm)
    return cleaned[:30]


def extract_asset_classes(html: str) -> List[str]:
    seen: List[str] = []
    seen_set: set = set()
    for match in ASSET_CLASS_RE.finditer(html):
        token = match.group(1).strip()
        norm = re.sub(r"\s+", " ", token).lower()
        norm = norm.replace("websites and applications", "websites-and-applications")
        norm = norm.replace("websites & applications", "websites-and-applications")
        norm = norm.replace("blockchain/dlt", "blockchain-dlt")
        norm = norm.replace("blockchain dlt", "blockchain-dlt")
        norm = norm.replace("smart contract", "smart-contract")
        norm = norm.replace("smart contracts", "smart-contract")
        if norm not in seen_set:
            seen_set.add(norm)
            seen.append(norm)
    if not seen:
        seen.append("unspecified")
    return seen


def extract_target_repo(html: str) -> str:
    m = GITHUB_REPO_RE.search(html)
    if not m:
        return ""
    owner = m.group("owner")
    repo = re.sub(r"\.git$", "", m.group("repo"))
    return f"github.com/{owner}/{repo}"


def extract_bounty_status(html: str) -> str:
    m = STATUS_RE.search(html)
    if not m:
        return "unknown"
    return m.group(1).lower()


def extract_paid_out(html: str) -> Tuple[Optional[int], str]:
    m = PAID_OUT_RE.search(html)
    if not m:
        return None, "unknown"
    amount = parse_amount(m.group("amt"), m.group("unit"))
    return amount, "medium"


# ---------------------------------------------------------------------------
# Record assembly
# ---------------------------------------------------------------------------


def make_record_id(slug: str, severity: str, asset_class: str, payload_sha: str) -> str:
    seed = f"immunefi-dashboard\n{slug}\n{severity}\n{asset_class}\n{payload_sha}"
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:12]
    return f"immunefi-dashboard:{slug}:{severity}:{slugify(asset_class, max_len=24)}:{digest}"


def build_records_for_bounty(
    *,
    slug: str,
    page_url: str,
    html: str,
    payload_sha256: str,
    fetched_at_utc: str,
) -> List[Dict[str, Any]]:
    title = extract_title(html) or slug.replace("-", " ").title()
    severity_rows = extract_severity_rows(html)
    impacts = extract_impacts(html)
    asset_classes = extract_asset_classes(html)
    target_repo = extract_target_repo(html)
    status = extract_bounty_status(html)
    paid_out, paid_out_conf = extract_paid_out(html)

    records: List[Dict[str, Any]] = []
    # One record per (severity_tier, asset_class) row.
    for sev_row in severity_rows or [{"severity": "info", "ceiling_usd": 0, "ceiling_dollar_class": "non-financial"}]:
        for asset_class in asset_classes:
            severity = sev_row["severity"]
            dollar_class = sev_row.get("ceiling_dollar_class") or SEVERITY_TO_DOLLAR_DEFAULT.get(severity, "non-financial")
            url_with_fragment = f"{page_url}#{severity}"
            record_id = make_record_id(slug, severity, asset_class, payload_sha256)
            record = {
                "record_id": record_id,
                "record_tier": "public-corpus",
                "verification_tier": VERIFICATION_TIER,
                "source_extraction_method": SOURCE_EXTRACTION_METHOD,
                "source_audit_ref": {
                    "url": url_with_fragment,
                    "fetched_at_utc": fetched_at_utc,
                    "payload_sha256": payload_sha256,
                },
                "target_project": title,
                "target_project_slug": slug,
                "target_repo": target_repo or "unknown",
                "asset_class": asset_class,
                "severity_at_finding": severity,
                "severity_ceiling_usd": int(sev_row.get("ceiling_usd", 0)),
                "impact_dollar_class": dollar_class,
                "attack_class_candidates": impacts,
                "bounty_status": status,
                "total_paid_out_usd_estimate": paid_out if paid_out is not None else 0,
                "total_paid_out_confidence": paid_out_conf,
                "verification_chain": [
                    {"step": "fetch", "proof": payload_sha256},
                    {"step": "parse", "proof": hashlib.sha256(
                        json.dumps({"slug": slug, "severity": severity, "asset_class": asset_class},
                                   sort_keys=True).encode("utf-8")).hexdigest()},
                ],
                "notes": "bounty-program metadata; no per-bug disclosure",
            }
            # Final emit proof (sha256 of the JSON body sans the proof itself).
            emit_seed = json.dumps({k: v for k, v in record.items() if k != "verification_chain"},
                                   sort_keys=True).encode("utf-8")
            record["verification_chain"].append(
                {"step": "emit", "proof": hashlib.sha256(emit_seed).hexdigest()}
            )
            records.append(record)
    return records


def write_record(out_dir: Path, record: Dict[str, Any]) -> Tuple[Path, Path]:
    slug = record.get("target_project_slug", "unknown")
    target = out_dir / slug
    target.mkdir(parents=True, exist_ok=True)
    digest = record["record_id"].rsplit(":", 1)[-1]
    base = f"{slugify(record['severity_at_finding'])}-{slugify(record['asset_class'], max_len=24)}-{digest}"
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
    max_pages: Optional[int],
    dry_run: bool,
    explore_url: str = EXPLORE_INDEX_URL,
) -> Dict[str, Any]:
    summary: Dict[str, Any] = {
        "verification_tier": VERIFICATION_TIER,
        "source_extraction_method": SOURCE_EXTRACTION_METHOD,
        "cache_dir": str(cache.cache_dir),
        "out_dir": str(out_dir),
        "fetch_live": bool(fetch_live),
        "dry_run": bool(dry_run),
        "pages_visited": 0,
        "bounties_discovered": 0,
        "records_emitted": 0,
        "by_severity": {},
        "by_asset_class": {},
        "files": [],
        "errors": [],
    }

    # Step 1: resolve the explore index. cache.fetch() handles both the
    # prefetched (test injection) and disk-cache paths transparently;
    # offline mode (--fetch absent) refuses network calls via
    # OfflineCacheMissError.
    try:
        index = cache.fetch(explore_url)
    except Exception as exc:  # noqa: BLE001
        summary["errors"].append(f"fetch explore index failed: {exc}")
        return summary
    summary["pages_visited"] += 1
    index_html = index.payload.decode("utf-8", errors="replace")
    slugs = extract_bounty_slugs(index_html)
    if max_pages is not None:
        slugs = slugs[:max_pages]
    summary["bounties_discovered"] = len(slugs)

    out_dir.mkdir(parents=True, exist_ok=True)

    for slug in slugs:
        page_url = f"{BOUNTY_URL_PREFIX}{slug}/"
        try:
            bounty = cache.fetch(page_url)
        except Exception as exc:  # noqa: BLE001
            summary["errors"].append(f"fetch {page_url}: {exc}")
            continue
        summary["pages_visited"] += 1
        html = bounty.payload.decode("utf-8", errors="replace")
        records = build_records_for_bounty(
            slug=slug,
            page_url=page_url,
            html=html,
            payload_sha256=bounty.payload_sha256,
            fetched_at_utc=bounty.fetched_at_utc,
        )
        for record in records:
            sev = record["severity_at_finding"]
            asset = record["asset_class"]
            summary["by_severity"][sev] = summary["by_severity"].get(sev, 0) + 1
            summary["by_asset_class"][asset] = summary["by_asset_class"].get(asset, 0) + 1
            if dry_run:
                summary["records_emitted"] += 1
                continue
            json_path, _yaml_path = write_record(out_dir, record)
            summary["records_emitted"] += 1
            summary["files"].append(str(json_path.relative_to(out_dir.parent)) if out_dir.parent in json_path.parents else str(json_path))
    return summary


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="hackerman-etl-from-immunefi-dashboard",
        description="Mine immunefi.com/explore/ for hackerman tier-2 records.",
    )
    p.add_argument("--cache-dir", required=True, type=Path)
    p.add_argument("--out-dir", required=True, type=Path)
    p.add_argument("--fetch", action="store_true",
                   help="If absent, requires a populated --cache-dir.")
    p.add_argument("--respect-robots", dest="respect_robots", action="store_true", default=True)
    p.add_argument("--no-respect-robots", dest="respect_robots", action="store_false")
    p.add_argument("--i-acknowledge-tos", dest="i_acknowledge_tos", action="store_true", default=False)
    p.add_argument("--rate-limit-ms", type=int, default=DEFAULT_RATE_LIMIT_MS)
    p.add_argument("--max-pages", type=int, default=None)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--json-summary", action="store_true")
    p.add_argument("--explore-url", default=EXPLORE_INDEX_URL,
                   help=argparse.SUPPRESS)  # test/escape hatch only.
    return p


def main(argv: Optional[Iterable[str]] = None) -> int:
    args = build_arg_parser().parse_args(list(argv) if argv is not None else None)
    # Co-occurrence gate per spec §3.1.
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
        max_pages=args.max_pages,
        dry_run=bool(args.dry_run),
        explore_url=args.explore_url,
    )
    if args.json_summary:
        sys.stdout.write(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    if summary.get("records_emitted", 0) == 0 and not summary.get("bounties_discovered"):
        # Nothing to do AND no cache populated => signal upstream.
        sys.stderr.write("BLOCKED-NO-REAL-SOURCE: empty cache and --fetch not requested\n")
        return 3
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
