#!/usr/bin/env python3
# r36-rebuttal: registered to lane DEFIMON-TG-BACKFILL in .auditooor/agent_pathspec.json (expires 2026-05-26T19:12Z); see tools/agent-pathspec-register.py list
"""
Lane DEFIMON-TG-BACKFILL: parse the public Telegram preview of the
`defimon_alerts` channel and emit hackerman_record.v1.2 corpus rows for
each real-incident post.

This miner does NOT call any LLM. It is a pure parse+ETL step that:

  1. Fetches `https://t.me/s/defimon_alerts` (and `?before=<id>` pages)
  2. Walks backward through the channel one page at a time
  3. Classifies each post via simple regex/keyword heuristics:
       SKIP -> return-request, legal-warning, on-chain message, bounty,
               unpause / pause monitoring alerts, small MEV (<$5K),
               and any non-mechanics post
       KEEP -> incident posts with $-amounts, target name, and mechanics
  4. Emits `audit/corpus_tags/tags/defimon_telegram_incidents/<slug>/record.yaml`
     for each KEPT post. Schema: hackerman_record.v1.2 with
     verification_tier: tier-2-verified-public-archive.
  5. Maintains a cursor at
     `.auditooor/external_intel_cursors/defimon_telegram.json`.

Outputs are written ONLY to the new per-incident folders under
`defimon_telegram_incidents/`; no draft / paste-ready file is ever
touched (L34 discipline). Each emitted record carries a first-class
`verification_tier` field (R37 discipline).
"""

from __future__ import annotations

import argparse
import datetime as dt
import html
import json
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT_DIR = (
    REPO_ROOT / "audit" / "corpus_tags" / "tags" / "defimon_telegram_incidents"
)
DEFAULT_CURSOR_PATH = (
    REPO_ROOT / ".auditooor" / "external_intel_cursors" / "defimon_telegram.json"
)
DEFAULT_DEDUP_SCAN_DIRS = [
    REPO_ROOT / "audit" / "corpus_tags" / "tags" / "defimon_blog_incidents",
    REPO_ROOT / "audit" / "corpus_tags" / "tags" / "rekt_news_incidents" / "rekt",
    REPO_ROOT / "audit" / "corpus_tags" / "tags" / "darknavy_web3_incidents",
    REPO_ROOT / "audit" / "corpus_tags" / "tags" / "bridge_incidents",
]

CHANNEL_NAME = "defimon_alerts"
BASE_URL = f"https://t.me/s/{CHANNEL_NAME}"
USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/118.0 Safari/537.36"
)

# -- classifier vocabularies ---------------------------------------------------

SKIP_KEYWORDS = (
    # r36-rebuttal: registered in DEFIMON-TG-BACKFILL pathspec
    "please return",
    "white hat",
    "whitehat",
    "you have ",
    "contact us",
    "legal notice",
    "legal warning",
    "law enforcement",
    "return the funds",
    "return funds",
    "onchain message",
    "on-chain message",
    "on chain message",
    "bounty offer",
    "ten percent",
    "10% bounty",
    "10 percent",
    "unpaused",
    "is now paused",
    "fundraising",
    "research link",
    # additional negotiation / settlement language
    "write off",
    "criminal complaint",
    "criminal proceedings",
    "discussing a settlement",
    "we once again propose",
    "company is prepared to",
    "proceed with a criminal",
)

INCIDENT_KEYWORDS = (
    "exploit",
    "exploited",
    "exploiter",
    "drain",
    "drained",
    "hack",
    "hacked",
    "attack",
    "attacker",
    "vulnerability",
    "manipulation",
    "manipulated",
    "stolen",
    "loss of",
    "incident summary",
    "callbytes",
    "initialize()",
    "uninitialized",
    "backdoor",
)

USD_AMOUNT_RE = re.compile(
    # r36-rebuttal: registered in DEFIMON-TG-BACKFILL pathspec
    # Prefer the LARGEST plausible integer / suffixed form. Match either
    # "$1,234,567" or "$1.5M" or a bare "$16134" (no thousands sep).
    r"""(?ix)
    \$\s*
    (
        \d{1,3}(?:,\d{3})+        # 1,234 / 1,234,567 (comma-separated)
        |
        \d+(?:\.\d+)?              # 16134.38 (bare with optional decimal)
    )
    \s*([kKmMbB])?
    """,
    re.VERBOSE,
)

CONTRACT_ADDR_RE = re.compile(r"0x[a-fA-F0-9]{40}")
FUNC_SIG_RE = re.compile(
    r"\b("
    r"callBytes|initialize|wrapTo|mint|transferFrom|sync|callBack|"
    r"swap|borrow|withdraw|deposit|cook|callback|delegateCall|"
    r"upgradeTo|setImplementation"
    r")\b",
    re.IGNORECASE,
)

SEVERITY_THRESHOLDS_USD = (
    (1_000_000, "critical"),
    (250_000, "high"),
    (25_000, "medium"),
)

ATTACK_CLASS_KEYWORDS = (
    ("callbytes", "router-self-call-arbitrary-target"),
    ("initialize", "unprotected-initializer"),
    ("uninitialized", "unprotected-initializer"),
    ("wrapto", "privileged-bridge-mint"),
    ("backdoor", "implementation-backdoor"),
    ("flash loan", "flash-loan-price-manipulation"),
    ("oracle", "oracle-manipulation"),
    ("reentrancy", "reentrancy"),
    ("asymmetric", "amm-asymmetric-liquidity"),
    ("rounding", "rounding-arithmetic"),
    ("sync", "amm-reserve-manipulation"),
    ("delegatecall", "delegatecall-injection"),
    ("signature", "signature-replay-or-forgery"),
    ("proxy", "proxy-upgrade-misconfiguration"),
)


# -- HTML helpers --------------------------------------------------------------


def fetch(url: str, timeout: int = 20) -> str:
    req = urllib.request.Request(
        url, headers={"User-Agent": USER_AGENT, "Accept": "text/html"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8", errors="replace")
    return body


def _strip_html(raw: str) -> str:
    raw = re.sub(r"<br\s*/?>", "\n", raw, flags=re.IGNORECASE)
    raw = re.sub(r"<[^>]+>", "", raw)
    text = html.unescape(raw)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _balanced_div_extract(blob: str, start: int) -> tuple[str, int]:
    """
    Given an HTML blob and a start index immediately AFTER an opening
    `<div ...>` tag, walk forward and return the contents of that div up
    to the matching `</div>` and the absolute index just past it.
    """
    depth = 1
    i = start
    pattern = re.compile(r"<(/?)div\b[^>]*>")
    while i < len(blob):
        m = pattern.search(blob, i)
        if not m:
            break
        if m.group(1) == "/":
            depth -= 1
            if depth == 0:
                return blob[start : m.start()], m.end()
        else:
            depth += 1
        i = m.end()
    return blob[start:], len(blob)


def parse_page(body: str) -> dict[str, Any]:
    """
    Parse a single `https://t.me/s/<channel>[?before=N]` page.
    Returns {"posts": [...], "older_cursor": int|None}.
    """
    posts: list[dict[str, Any]] = []
    wrap_starts = [
        m.start() for m in re.finditer(r'<div class="tgme_widget_message_wrap', body)
    ]
    if not wrap_starts:
        return {"posts": [], "older_cursor": None}
    wrap_ranges: list[tuple[int, int]] = []
    for idx, s in enumerate(wrap_starts):
        e = wrap_starts[idx + 1] if idx + 1 < len(wrap_starts) else len(body)
        wrap_ranges.append((s, e))

    for s, e in wrap_ranges:
        chunk = body[s:e]
        pid_match = re.search(
            r'data-post="' + re.escape(CHANNEL_NAME) + r'/(\d+)"', chunk
        )
        if not pid_match:
            continue
        post_id = int(pid_match.group(1))
        dt_match = re.search(r'<time[^>]+datetime="([^"]+)"', chunk)
        post_dt = dt_match.group(1) if dt_match else ""
        text_open = re.search(
            r'<div class="tgme_widget_message_text js-message_text"[^>]*>',
            chunk,
        )
        text_raw = ""
        if text_open:
            inner, _ = _balanced_div_extract(chunk, text_open.end())
            text_raw = inner
        text = _strip_html(text_raw) if text_raw else ""
        links: list[str] = []
        for href in re.findall(r'href="(https?://[^"]+)"', text_raw):
            if "t.me/" in href and ("share" in href or "i_telegram" in href):
                continue
            links.append(href)
        posts.append(
            {
                "post_id": post_id,
                "datetime": post_dt,
                "text": text,
                "links": links,
                "channel": CHANNEL_NAME,
            }
        )

    posts.sort(key=lambda p: p["post_id"])

    older_cursor: int | None = None
    hist_match = re.search(r'data-before="(\d+)"', body)
    if hist_match:
        older_cursor = int(hist_match.group(1))
    else:
        prev_link = re.search(r'rel="prev"[^>]+href="[^"]*\?before=(\d+)"', body)
        if prev_link:
            older_cursor = int(prev_link.group(1))

    return {"posts": posts, "older_cursor": older_cursor}


# -- classifier ----------------------------------------------------------------


def _has_strong_incident_signal(text: str) -> bool:
    low = text.lower()
    return any(kw in low for kw in INCIDENT_KEYWORDS)


def _has_skip_signal(text: str) -> bool:
    low = text.lower()
    return any(kw in low for kw in SKIP_KEYWORDS)


def _parse_usd_amount(text: str) -> tuple[float | None, str]:
    best: float | None = None
    best_raw = ""
    for m in USD_AMOUNT_RE.finditer(text):
        try:
            num_part = m.group(1).replace(",", "")
            value = float(num_part)
        except ValueError:
            continue
        suffix = (m.group(2) or "").lower()
        if suffix == "k":
            value *= 1_000.0
        elif suffix == "m":
            value *= 1_000_000.0
        elif suffix == "b":
            value *= 1_000_000_000.0
        if best is None or value > best:
            best = value
            best_raw = m.group(0)
    return best, best_raw


def classify_post(
    post: dict[str, Any], min_usd_for_mev: float = 5000.0
) -> dict[str, Any]:
    text = post.get("text") or ""
    if len(text) < 30:
        return {
            "verdict": "skip",
            "reason": "empty-or-trivial",
            "amount_usd": None,
            "attack_class": "",
            "severity_heuristic": "info",
            "mechanics_signals": 0,
            "target_hint": "",
        }

    low = text.lower()
    incident_signal = _has_strong_incident_signal(text)
    skip_signal = _has_skip_signal(text)
    amount_usd, _ = _parse_usd_amount(text)
    contract_addrs = CONTRACT_ADDR_RE.findall(text)
    func_sigs = FUNC_SIG_RE.findall(text)
    mech = (
        (1 if amount_usd else 0)
        + (1 if contract_addrs else 0)
        + (1 if func_sigs else 0)
    )

    # MEV quick-reject (very small extractions are not bug-shaped).
    if "mev-bot" in low or "mev sandwich" in low or " mev " in low:
        if amount_usd is None or amount_usd < min_usd_for_mev:
            return {
                "verdict": "skip",
                "reason": "small-mev",
                "amount_usd": amount_usd,
                "attack_class": "",
                "severity_heuristic": "info",
                "mechanics_signals": mech,
                "target_hint": "",
            }
        if mech < 2:
            return {
                "verdict": "skip",
                "reason": "mev-no-mechanics",
                "amount_usd": amount_usd,
                "attack_class": "",
                "severity_heuristic": "info",
                "mechanics_signals": mech,
                "target_hint": "",
            }

    # r36-rebuttal: registered to lane DEFIMON-TG-BACKFILL in pathspec
    # Hard-stop SKIP markers: on-chain-message posts use a fixed header
    # ("Onchain message" / "On-chain message") even when their bodies
    # mention "stolen funds" and contain From/To addresses. These are
    # negotiations, not bug-shaped writeups.
    # r36-rebuttal: registered in DEFIMON-TG-BACKFILL pathspec
    HARD_STOP_SKIPS = (
        "onchain message",
        "on-chain message",
        "on chain message",
        "please return",
        "white hat",
        "whitehat",
        "criminal complaint",
        "write off the stolen",
        "is now paused",
        "unpaused",
        "fundraising",
    )
    if any(stop in low for stop in HARD_STOP_SKIPS):
        return {
            "verdict": "skip",
            "reason": "negotiation-or-monitoring",
            "amount_usd": amount_usd,
            "attack_class": "",
            "severity_heuristic": "info",
            "mechanics_signals": mech,
            "target_hint": "",
        }

    # Soft skip: weaker SKIP keyword + no $-amount and weak mechanics.
    if skip_signal and (amount_usd is None and mech < 2):
        return {
            "verdict": "skip",
            "reason": "negotiation-or-monitoring",
            "amount_usd": amount_usd,
            "attack_class": "",
            "severity_heuristic": "info",
            "mechanics_signals": mech,
            "target_hint": "",
        }

    if not incident_signal:
        return {
            "verdict": "skip",
            "reason": "no-incident-signal",
            "amount_usd": amount_usd,
            "attack_class": "",
            "severity_heuristic": "info",
            "mechanics_signals": mech,
            "target_hint": "",
        }
    if amount_usd is None and mech < 2:
        return {
            "verdict": "skip",
            "reason": "no-mechanics-no-amount",
            "amount_usd": amount_usd,
            "attack_class": "",
            "severity_heuristic": "info",
            "mechanics_signals": mech,
            "target_hint": "",
        }

    attack_class = "unspecified"
    for kw, cls in ATTACK_CLASS_KEYWORDS:
        if kw in low:
            attack_class = cls
            break
    severity = "info"
    if amount_usd is not None:
        for threshold, sev in SEVERITY_THRESHOLDS_USD:
            if amount_usd >= threshold:
                severity = sev
                break
    target_hint = _extract_target_hint(text)
    return {
        "verdict": "keep",
        "reason": "incident-with-mechanics",
        "amount_usd": amount_usd,
        "attack_class": attack_class,
        "severity_heuristic": severity,
        "mechanics_signals": mech,
        "target_hint": target_hint,
    }


_BLOCK_EXPLORER_HOSTS = {
    # r36-rebuttal: registered in DEFIMON-TG-BACKFILL pathspec
    "etherscan",
    "arbiscan",
    "polygonscan",
    "basescan",
    "bscscan",
    "ftmscan",
    "snowtrace",
    "blockscout",
    "celoscan",
    "optimistic",
    "scrollscan",
    "lineascan",
    "moonscan",
    "tronscan",
    "solscan",
    "explorer",
}

_GENERIC_TOKENS = {
    # r36-rebuttal: registered in DEFIMON-TG-BACKFILL pathspec
    "the",
    "this",
    "after",
    "during",
    "today",
    "yesterday",
    "type",
    "many",
    "yet",
    "another",
    "attacker",
    "onchain",
    "loss",
    # Defimon alert headers
    "alert",
    "victim",
    "exploit",
    "network",
    "balance",
    "change",
    "rug",
    "rug_pull",
    "transaction",
    "type",
    "address",
    "approval",
    "drain",
    "drained",
    "exploit",
    "hack",
    "amount",
    "phalcon",
    "tenderly",
    "dedaub",
    # generic CEFI/DEX names that appear in 90% of writeups
    "uniswap",
    "balancer",
    "curve",
    "sushiswap",
    "pancakeswap",
    "1inch",
    "aave",
    "compound",
}


def _extract_target_hint(text: str) -> str:
    # Defimon writeups frequently lead with the project name on the first
    # bold/heading line: e.g. "Sharwa.finance - Loss $X" or
    # "Renegade incident summary: ...". Try those shapes first.
    first_lines = text.splitlines()[:3]
    head_blob = " ".join(first_lines)
    # explicit "Project: <name>" or "Project: <url>"
    proj = re.search(
        r"(?i)project\s*[:\-]\s*(?:https?://[^\s<]+/([^/\s<]+)|([A-Za-z0-9_\-\.]+))",
        text[:800],
    )
    if proj:
        candidate = (proj.group(1) or proj.group(2) or "").strip().rstrip("/.,)")
        if candidate and candidate.lower() not in _BLOCK_EXPLORER_HOSTS:
            return candidate.lower()

    # "<Project>.<tld> - Loss" / "<Project>.<tld> ($TOKEN) - Loss"
    head_dom = re.search(
        r"\b([A-Za-z][A-Za-z0-9_\-]{2,})\.(finance|io|exchange|xyz|app|fi|com|org|protocol|so|net)\b",
        head_blob,
    )
    if head_dom and head_dom.group(1).lower() not in _BLOCK_EXPLORER_HOSTS:
        return head_dom.group(1).lower()

    # any in-text TLD match (skip block-explorer hosts)
    for dom in re.finditer(
        r"\b([A-Za-z][A-Za-z0-9_\-]{2,})\.(finance|io|exchange|xyz|app|fi|com|org|protocol|so|net)\b",
        text,
    ):
        name = dom.group(1).lower()
        if name in _BLOCK_EXPLORER_HOSTS:
            continue
        return name

    # fallback: capitalized token at start of first line (Defimon lede)
    head_tokens = re.findall(r"\b([A-Z][a-zA-Z0-9]{2,})\b", head_blob)
    for tok in head_tokens:
        if tok.lower() in _GENERIC_TOKENS:
            continue
        if tok.lower() in _BLOCK_EXPLORER_HOSTS:
            continue
        return tok.lower()
    return "unknown"


# -- record emission -----------------------------------------------------------


def _slugify(token: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", (token or "").lower()).strip("-")
    return slug or "unknown"


def build_slug(post_id: int, target_hint: str) -> str:
    return f"defimon-tg-{post_id}-{_slugify(target_hint)}"


def build_record_id(post_id: int, target_hint: str) -> str:
    return f"defimon-telegram:{post_id}:{_slugify(target_hint)}"


def _yaml_quote(value: Any) -> str:
    if value is None:
        return "''"
    txt = str(value)
    if "\n" in txt:
        return "|\n" + "\n".join("  " + ln for ln in txt.splitlines())
    if any(c in txt for c in ":#'\"") or txt.strip() != txt:
        escaped = txt.replace("'", "''")
        return f"'{escaped}'"
    return txt


def render_record_yaml(
    *,
    post: dict[str, Any],
    classification: dict[str, Any],
    dedup_hits: list[str],
) -> str:
    post_id = post["post_id"]
    target_hint = classification["target_hint"] or "unknown"
    record_id = build_record_id(post_id, target_hint)
    source_url = f"https://t.me/{CHANNEL_NAME}/{post_id}"
    incident_date = (post.get("datetime") or "")[:10]
    severity = classification["severity_heuristic"] or "info"
    amount_usd = classification.get("amount_usd")
    attack_class = classification.get("attack_class") or "unspecified"

    text = post.get("text") or ""
    summary = re.sub(r"\s+", " ", text.strip())[:1200]

    notes_parts: list[str] = [
        f"Source: Defimon Alerts Telegram public mirror (https://t.me/s/{CHANNEL_NAME})",
        f"Post permalink: {source_url}",
        "Classifier: defimon-telegram-archive-miner.py (regex+keyword, no LLM)",
        f"Mechanics signal count: {classification.get('mechanics_signals', 0)}",
    ]
    if amount_usd is not None:
        notes_parts.append(f"Heuristic USD amount: ~${amount_usd:,.0f}")
    if dedup_hits:
        notes_parts.append(
            "Possible duplicate(s) flagged for operator review: " + ", ".join(dedup_hits)
        )

    lines: list[str] = [
        "schema_version: auditooor.hackerman_record.v1.2",  # lane227: incident-mining shape -> v1.2
        f"record_id: {_yaml_quote(record_id)}",
        "verification_tier: tier-2-verified-public-archive",
        f"source_url: {_yaml_quote(source_url)}",
        f"source_audit_ref: {_yaml_quote(source_url)}",
        f"incident_date: {_yaml_quote(incident_date)}",
        f"target_project: {_yaml_quote(target_hint)}",
        f"severity: {_yaml_quote(severity)}",
        f"attack_class: {_yaml_quote(attack_class)}",
        f"attack_vector_summary: {_yaml_quote(summary)}",
        f"amount_usd: {amount_usd if amount_usd is not None else '~'}",
        "fix_commit_refs: []",
        "shape_tags:",
        "  - defimon-telegram",
        "  - verification_tier:tier-2-verified-public-archive",
        f"  - attack-class:{_slugify(attack_class)}",
        f"  - severity:{severity}",
        "notes: |",
    ]
    for n in notes_parts:
        lines.append(f"  {n}")
    return "\n".join(lines) + "\n"


# -- dedup ---------------------------------------------------------------------


def build_dedup_index(scan_dirs: list[Path]) -> dict[str, list[str]]:
    index: dict[str, list[str]] = {}
    for root in scan_dirs:
        if not root.exists():
            continue
        for path in root.rglob("record.yaml"):
            tokens: set[str] = set()
            tokens.add(_slugify(path.parent.name))
            try:
                content = path.read_text(encoding="utf-8", errors="replace").lower()
            except OSError:
                content = ""
            for m in re.finditer(
                r"target_project\s*:\s*['\"]?([a-z0-9_\-\.\/]+)['\"]?",
                content,
            ):
                tokens.add(_slugify(m.group(1).split("/")[-1]))
            for m in re.finditer(r"record_id\s*:\s*['\"]?([^'\"\n]+)", content):
                rid = m.group(1)
                last = rid.rsplit(":", 1)[-1] if ":" in rid else rid
                tokens.add(_slugify(last))
            for tok in tokens:
                if not tok or len(tok) < 4:
                    continue
                index.setdefault(tok, []).append(str(path))
        for sub in root.iterdir() if root.exists() else []:
            if sub.is_dir():
                index.setdefault(_slugify(sub.name), []).append(str(sub))
    return index


def find_dedup_hits(target_hint: str, dedup_index: dict[str, list[str]]) -> list[str]:
    if not target_hint:
        return []
    needle = _slugify(target_hint)
    if not needle or len(needle) < 4:
        return []
    hits: list[str] = []
    for key, paths in dedup_index.items():
        if needle in key or key in needle:
            hits.extend(paths)
    seen: set[str] = set()
    out: list[str] = []
    for p in hits:
        if p in seen:
            continue
        seen.add(p)
        out.append(p)
    return out


# -- main loop -----------------------------------------------------------------


def write_record(
    *,
    output_dir: Path,
    post: dict[str, Any],
    classification: dict[str, Any],
    dedup_hits: list[str],
    dry_run: bool,
) -> Path:
    slug = build_slug(post["post_id"], classification["target_hint"])
    folder = output_dir / slug
    target = folder / "record.yaml"
    if dry_run:
        return target
    folder.mkdir(parents=True, exist_ok=True)
    yaml_text = render_record_yaml(
        post=post, classification=classification, dedup_hits=dedup_hits
    )
    target.write_text(yaml_text, encoding="utf-8")
    return target


def update_cursor(
    cursor_path: Path,
    *,
    oldest: int | None,
    newest: int | None,
    dry_run: bool,
) -> None:
    if dry_run:
        return
    payload = {
        "channel": CHANNEL_NAME,
        "oldest_post_id_mined": oldest,
        "newest_post_id_mined": newest,
        "last_run_utc": dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    cursor_path.parent.mkdir(parents=True, exist_ok=True)
    cursor_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def run(args: argparse.Namespace) -> int:
    output_dir = Path(args.output_dir).resolve()
    cursor_path = Path(args.cursor_path).resolve()
    summary_path = Path(args.json_summary).resolve() if args.json_summary else None

    dedup_index = build_dedup_index(DEFAULT_DEDUP_SCAN_DIRS)

    start_url = BASE_URL
    if args.start_from and args.start_from != "latest":
        try:
            start_id = int(args.start_from)
            start_url = f"{BASE_URL}?before={start_id + 1}"
        except ValueError:
            print(
                f"[defimon-tg] invalid --start-from {args.start_from!r}; using latest",
                file=sys.stderr,
            )
            start_url = BASE_URL

    visited_cursors: set[int] = set()
    next_url: str | None = start_url
    pages_fetched = 0
    posts_seen: list[dict[str, Any]] = []

    while next_url and pages_fetched < args.max_pages:
        pages_fetched += 1
        print(f"[defimon-tg] fetching page {pages_fetched}: {next_url}")
        try:
            body = fetch(next_url, timeout=args.timeout)
        except (urllib.error.URLError, urllib.error.HTTPError) as exc:
            print(f"[defimon-tg] fetch failed: {exc}", file=sys.stderr)
            if pages_fetched == 1:
                return 1
            break
        page = parse_page(body)
        if not page["posts"]:
            print("[defimon-tg] page returned 0 posts; stopping")
            break
        posts_seen.extend(page["posts"])
        older = page.get("older_cursor")
        if older is None:
            print("[defimon-tg] no older cursor on page; reached channel start")
            break
        if older in visited_cursors:
            print("[defimon-tg] cursor loop detected; stopping")
            break
        visited_cursors.add(older)
        next_url = f"{BASE_URL}?before={older}"
        time.sleep(args.sleep)

    posts_by_id: dict[int, dict[str, Any]] = {}
    for p in posts_seen:
        posts_by_id[p["post_id"]] = p
    posts_ordered = sorted(posts_by_id.values(), key=lambda p: p["post_id"])

    kept_records: list[dict[str, Any]] = []
    skipped_records: list[dict[str, Any]] = []
    dedup_hit_count = 0

    for post in posts_ordered:
        cls = classify_post(post)
        if cls["verdict"] == "skip":
            skipped_records.append(
                {
                    "post_id": post["post_id"],
                    "reason": cls["reason"],
                }
            )
            continue
        hits = find_dedup_hits(cls["target_hint"], dedup_index)
        if hits:
            dedup_hit_count += 1
        path = write_record(
            output_dir=output_dir,
            post=post,
            classification=cls,
            dedup_hits=hits,
            dry_run=args.dry_run,
        )
        kept_records.append(
            {
                "post_id": post["post_id"],
                "record_path": str(path),
                "target_hint": cls["target_hint"],
                "severity": cls["severity_heuristic"],
                "amount_usd": cls["amount_usd"],
                "attack_class": cls["attack_class"],
                "dedup_hits": hits,
            }
        )

    oldest_id = posts_ordered[0]["post_id"] if posts_ordered else None
    newest_id = posts_ordered[-1]["post_id"] if posts_ordered else None
    update_cursor(cursor_path, oldest=oldest_id, newest=newest_id, dry_run=args.dry_run)

    summary = {
        "channel": CHANNEL_NAME,
        "pages_fetched": pages_fetched,
        "posts_seen": len(posts_ordered),
        "records_kept": len(kept_records),
        "records_skipped": len(skipped_records),
        "dedup_hits_found": dedup_hit_count,
        "oldest_post_id": oldest_id,
        "newest_post_id": newest_id,
        "dry_run": bool(args.dry_run),
        "kept_records": kept_records,
        "skipped_records": skipped_records,
        "cursor_path": str(cursor_path),
        "output_dir": str(output_dir),
        "ran_at_utc": dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if summary_path:
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        summary_path.write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(f"[defimon-tg] summary written to {summary_path}")
    print(
        f"[defimon-tg] done: pages={pages_fetched} "
        f"seen={len(posts_ordered)} kept={len(kept_records)} "
        f"skipped={len(skipped_records)} dedup_hits={dedup_hit_count} "
        f"oldest={oldest_id} newest={newest_id} dry_run={args.dry_run}"
    )
    return 0


def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Mine the public Telegram preview of defimon_alerts "
        "into hackerman_record.v1.2 corpus rows."
    )
    p.add_argument("--start-from", default="latest")
    p.add_argument("--max-pages", type=int, default=30)
    p.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR))
    p.add_argument("--cursor-path", default=str(DEFAULT_CURSOR_PATH))
    p.add_argument("--json-summary", default=None)
    p.add_argument("--sleep", type=float, default=1.0)
    p.add_argument("--timeout", type=int, default=20)
    p.add_argument("--dry-run", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_argparser()
    args = parser.parse_args(argv)
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
