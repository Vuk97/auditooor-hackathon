#!/usr/bin/env python3
# r36-rebuttal: lane-189-CONSOLIDATE-TX-TOOLS declared via tools/agent-pathspec-register.py at lane start (Task #189)
"""Consolidated incident-corpus TX-field enrichment tool.

Task #189 consolidation of:
  - tools/defimon-tg-tx-enrichment.py (Task #172, P2.1 - defimon-TG specific
    with role-attribution + cross-corpus target_hint resolution).
  - tools/incident-corpus-tx-enrichment.py (Task #178, P2.7 - generic for
    mev / darknavy / rekt / bridge / defimon_blog).

Single tool with --corpus-shape flag selects the appropriate extraction
shape per corpus so re-runs against already-enriched corpora are byte-
idempotent (same structured_extraction block as the per-shape tool that
originally enriched them).

Scans every `*.yaml` (or `record.yaml`, per shape) under `--input-dir`
recursively, extracts transaction-level structured fields from any
free-text field present in the record, and appends a
`structured_extraction` block to the record. Existing fields are
preserved (write back the full record, only adding the new top-level
key when content is non-empty).

Per-shape behavior:

  defimon-tg:
    - Walk `record.yaml` only.
    - Source-field set: attack_vector_summary + notes (joined).
    - Emit `auditooor.defimon_tg_tx_enrichment.v1` block shape:
      tx_hashes / contract_addresses are list-of-dict with chain_hint
      + evidence_text snippets; contract_addresses also has `role`
      (victim / attacker / exploit) inferred from 🤕/🎩/🪄 prefixes.
      Includes amount_usd_refined, asset_tokens (list-of-dict), and
      explorer_urls (list-of-string). Chain is `{value, source, evidence_text}`.
    - Cross-corpus target_hint resolution via address overlap (when
      target_project=='unknown' and --cross-corpus-dirs supplied).

  mev | darknavy | rekt | bridge | defimon-blog | generic:
    - Walk every `*.yaml`.
    - Source-field set: TEXT_FIELDS allowlist (attacker_action_sequence,
      required_preconditions, ... full list below).
    - Emit `auditooor.incident_corpus_tx_enrichment.v1` block shape:
      tx_hashes / contract_addresses / asset_token / explorer_urls are
      list-of-string. amount_usd is `{value, confidence, literal_match}`.
      Chain is a plain string. Includes a `provenance` block recording
      per-field source citations.
    - Cross-corpus dedup via tx_hash / address overlap (when
      --cross-corpus-dirs supplied) into the `cross_corpus_dedup` field.

Both shapes:

  - L34 bucket = workspace-ledger (enrichment is metadata on records,
    not modification to filed drafts).
  - L26 cite-source-text: per-field provenance / evidence_text snippets
    so each match knows which source field it came from.
  - R37 tier preserved: existing verification_tier field untouched.
  - Pure regex; no LLM, no network. Deterministic.

CLI:

    # Generic shapes (mev, darknavy, rekt, bridge, defimon-blog, generic):
    python3 tools/incident-corpus-tx-enrichment.py \\
        --input-dir audit/corpus_tags/tags/mev_exploits/ \\
        --corpus-shape mev \\
        --cross-corpus-dirs audit/corpus_tags/tags/bridge_incidents/ \\
        --json-summary /tmp/enrichment_mev_exploits.json

    # Defimon-TG shape (role attribution + cross-corpus target resolution):
    python3 tools/incident-corpus-tx-enrichment.py \\
        --input-dir audit/corpus_tags/tags/defimon_telegram_incidents/ \\
        --corpus-shape defimon-tg \\
        --cross-corpus-dirs audit/corpus_tags/tags/bridge_incidents/,audit/corpus_tags/tags/darknavy_web3_incidents/

    # Dry-run (no in-place writes):
    python3 tools/incident-corpus-tx-enrichment.py \\
        --input-dir audit/corpus_tags/tags/mev_exploits/ \\
        --corpus-shape mev \\
        --dry-run \\
        --json-summary /tmp/enrichment_mev_exploits.json

Default shape: `generic` (equivalent to P2.7 behavior pre-consolidation).
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import yaml

SCHEMA_VERSION = "auditooor.incident_corpus_tx_enrichment.v1"
DEFIMON_TG_SCHEMA_VERSION = "auditooor.defimon_tg_tx_enrichment.v1"
DEFIMON_TG_SUMMARY_SCHEMA_VERSION = (
    "auditooor.defimon_tg_tx_enrichment.summary.v1"
)
TOOL_PATH = "tools/incident-corpus-tx-enrichment.py"
DEFIMON_TG_EXTRACTOR = "tools/defimon-tg-tx-enrichment.py"

CORPUS_SHAPES = (
    "defimon-tg",
    "mev",
    "rekt",
    "darknavy",
    "bridge",
    "defimon-blog",
    "generic",
)

REPO_ROOT = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# Generic-shape regex library (incident-corpus-tx-enrichment.v1)
# ---------------------------------------------------------------------------

# EVM tx hash: 0x + 64 hex
RE_EVM_TX_HASH = re.compile(r"\b0x[a-fA-F0-9]{64}\b")
# Bitcoin tx hash: 64-hex without 0x prefix (loose; we require nearby
# bitcoin context to avoid pulling random 64-hex payload-shas).
RE_BTC_TX_HASH_LOOSE = re.compile(r"\b[a-fA-F0-9]{64}\b")
# Tron tx hash: 64-hex (same shape as BTC), require Tron context.
RE_TRON_TX_HASH = RE_BTC_TX_HASH_LOOSE

# EVM contract / EOA address: 0x + 40 hex.
RE_EVM_ADDRESS = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
# Tron base58 address: T + 33 chars from base58 alphabet
RE_TRON_ADDRESS = re.compile(r"\bT[1-9A-HJ-NP-Za-km-z]{33}\b")
# Solana base58 address: 32-44 chars from base58 alphabet, restricted to
# token mints / program ids. We require a leading word boundary and the
# absence of 0x prefix (which would have already matched EVM).
RE_SOL_ADDRESS = re.compile(
    r"(?<![A-Za-z0-9])[1-9A-HJ-NP-Za-km-z]{32,44}(?![A-Za-z0-9])"
)

# Amount in USD. Order matters: more specific patterns first.
# Modifier must end at a word boundary (so "main" is not parsed as "m").
RE_AMOUNT_DOLLAR = [
    # "$181 million", "$1.2B", "$608,705", "$1,234,567.89"
    re.compile(
        r"\$\s*([0-9]+(?:[,\.][0-9]+)*)\s*"
        r"(million|billion|thousand|[MmBbKkTt])?(?![A-Za-z0-9])",
    ),
    # "1,234,567 USD" / "1.2M USD"
    re.compile(
        r"\b([0-9]+(?:[,\.][0-9]+)*)\s*"
        r"(million|billion|thousand|[MmBbKkTt])?(?![A-Za-z0-9])\s*USD\b",
        re.IGNORECASE,
    ),
]

# Explorer URL patterns
EXPLORER_HOSTS = [
    "etherscan.io",
    "bscscan.com",
    "polygonscan.com",
    "arbiscan.io",
    "optimistic.etherscan.io",
    "snowtrace.io",
    "ftmscan.com",
    "tronscan.org",
    "blockchain.com/btc",
    "mempool.space",
    "solscan.io",
    "solana.fm",
    "explorer.solana.com",
    "lineascan.build",
    "basescan.org",
    "scrollscan.com",
    "blockscout.com",
    "celoscan.io",
    "moonscan.io",
    "ronininfo",
]
RE_EXPLORER_URL = re.compile(
    r"https?://(?:[a-zA-Z0-9_\-\.]+\.)?(?:"
    + "|".join(re.escape(h) for h in EXPLORER_HOSTS)
    + r")(?:[/\w\-\.\?\=\&\#%]*)?",
    re.IGNORECASE,
)

# Asset / token tickers (most common DeFi)
ASSET_TOKENS = [
    "USDT",
    "USDC",
    "DAI",
    "WETH",
    "ETH",
    "WBTC",
    "BTC",
    "BNB",
    "BUSD",
    "FRAX",
    "FEI",
    "LUSD",
    "TUSD",
    "MATIC",
    "AVAX",
    "FTM",
    "TRX",
    "SOL",
    "stETH",
    "rETH",
    "cbETH",
    "wstETH",
    "OP",
    "ARB",
    "qXETH",
]
# Token regex: word boundary + literal token + word boundary, case sensitive.
RE_ASSET_TOKEN = re.compile(
    r"(?<![A-Za-z0-9])("
    + "|".join(re.escape(t) for t in ASSET_TOKENS)
    + r")(?![A-Za-z0-9])"
)

# Chain inference from URL + body keywords
CHAIN_INDICATORS: List[Tuple[str, List[str]]] = [
    ("ethereum", ["etherscan.io", "ethereum mainnet", "eth mainnet"]),
    ("bsc", ["bscscan.com", "bnb chain", "binance smart chain", "bsc block"]),
    ("polygon", ["polygonscan.com", "polygon mainnet", "matic mainnet"]),
    ("arbitrum", ["arbiscan.io", "arbitrum one", "arbitrum mainnet"]),
    ("optimism", ["optimistic.etherscan.io", "optimism mainnet"]),
    ("avalanche", ["snowtrace.io", "avalanche c-chain"]),
    ("fantom", ["ftmscan.com", "fantom opera"]),
    ("tron", ["tronscan.org", "tron mainnet", "tron network"]),
    (
        "solana",
        ["solscan.io", "solana.fm", "explorer.solana.com", "solana mainnet"],
    ),
    ("bitcoin", ["blockchain.com/btc", "mempool.space", "bitcoin mainnet"]),
    ("base", ["basescan.org", "base mainnet"]),
    ("linea", ["lineascan.build", "linea mainnet"]),
    ("scroll", ["scrollscan.com", "scroll mainnet"]),
    ("ronin", ["ronininfo", "ronin network", "ronin bridge"]),
    ("moonbeam", ["moonscan.io", "moonbeam"]),
]


# ---------------------------------------------------------------------------
# Defimon-TG-shape regex library (defimon_tg_tx_enrichment.v1)
# ---------------------------------------------------------------------------

# EVM tx_hash: 0x + 64 hex chars (alias)
DTG_EVM_TX_HASH_RE = re.compile(r"\b0x[a-fA-F0-9]{64}\b")
# EVM address: 0x + 40 hex chars (alias)
DTG_EVM_ADDRESS_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")

# Tron tx hash: 64 hex chars w/o 0x prefix, on tronscan URLs the path
# carries /transaction/<hash> with 64 hex chars. Standalone hex w/o 0x is
# ambiguous so we restrict to URL-context matches.
DTG_TRON_TX_URL_RE = re.compile(
    r"tronscan\.org/#?/transaction/([a-fA-F0-9]{64})", re.IGNORECASE
)
DTG_TRON_ADDR_URL_RE = re.compile(
    r"tronscan\.org/#?/(?:contract|address)/(T[A-HJ-NP-Za-km-z1-9]{33})",
    re.IGNORECASE,
)
# Tron addresses standalone (base58 T-prefix, 34 chars).
DTG_TRON_ADDR_RE = re.compile(r"\bT[A-HJ-NP-Za-km-z1-9]{33}\b")

# Bitcoin tx hash: 64 hex chars without 0x prefix - we only accept in URL
# form (blockchair / blockstream / mempool.space) to avoid FP collision
# with Tron.
DTG_BTC_TX_URL_RE = re.compile(
    r"(?:blockchair\.com/bitcoin|blockstream\.info|mempool\.space)"
    r"/(?:tx|transaction)/([a-fA-F0-9]{64})",
    re.IGNORECASE,
)

# Solana tx + address: base58 strings; restrict to URL-context matches.
DTG_SOLANA_TX_URL_RE = re.compile(
    r"solscan\.io/tx/([1-9A-HJ-NP-Za-km-z]{43,88})", re.IGNORECASE
)
DTG_SOLANA_ADDR_URL_RE = re.compile(
    r"solscan\.io/(?:account|address|token)/([1-9A-HJ-NP-Za-km-z]{32,44})",
    re.IGNORECASE,
)

# Defimon-TG explorer URL detector.
DTG_EXPLORER_URL_RE = re.compile(
    r"https?://(?:[a-zA-Z0-9-]+\.)?"
    r"(?:etherscan\.io|tronscan\.org|bscscan\.com|polygonscan\.com|"
    r"basescan\.org|arbiscan\.io|optimistic\.etherscan\.io|snowtrace\.io|"
    r"ftmscan\.com|blockchair\.com|solscan\.io|tonscan\.org|"
    r"explorer\.solana\.com|"
    r"explorer\.aptoslabs\.com|explorer\.zksync\.io|lineascan\.build|"
    r"explorer\.starknet\.io)"
    r"(?:/[^\s\"'<>|`]*)?",
    re.IGNORECASE,
)

# Defimon-TG dollar-amount refinement. Order matters: try labelled
# magnitudes first, then explicit comma-separated, then plain $N.
DTG_AMOUNT_PATTERNS = [
    # "$X Billion" / "$X.XB"
    (
        re.compile(
            r"\$\s*([\d,]+(?:\.\d+)?)\s*(?:billion|bn|B)\b", re.IGNORECASE
        ),
        1e9,
    ),
    # "$X Million" / "$X.XM"
    (
        re.compile(
            r"\$\s*([\d,]+(?:\.\d+)?)\s*(?:million|mln|m)\b", re.IGNORECASE
        ),
        1e6,
    ),
    # "$X Thousand" / "$X.Xk" / "$XXX,XXXk"
    (
        re.compile(
            r"\$\s*([\d,]+(?:\.\d+)?)\s*(?:thousand|k)\b", re.IGNORECASE
        ),
        1e3,
    ),
    # plain "$1,234,567.89" / "$1234567" - default multiplier 1
    (re.compile(r"\$\s*([\d,]+(?:\.\d+)?)"), 1.0),
]

# Defimon-TG chain inference from explicit URL hosts.
DTG_URL_HOST_TO_CHAIN = {
    "etherscan.io": "ethereum",
    "optimistic.etherscan.io": "optimism",
    "tronscan.org": "tron",
    "bscscan.com": "bsc",
    "polygonscan.com": "polygon",
    "basescan.org": "base",
    "arbiscan.io": "arbitrum",
    "snowtrace.io": "avalanche",
    "ftmscan.com": "fantom",
    "blockchair.com": "bitcoin",
    "solscan.io": "solana",
    "explorer.solana.com": "solana",
    "tonscan.org": "ton",
    "explorer.aptoslabs.com": "aptos",
    "explorer.zksync.io": "zksync",
    "lineascan.build": "linea",
    "explorer.starknet.io": "starknet",
}

# Defimon-TG chain inference from "Network: <name>" marker.
DTG_NETWORK_TOKEN_TO_CHAIN = {
    "mainnet": "ethereum",
    "ethereum": "ethereum",
    "eth": "ethereum",
    "bsc": "bsc",
    "binance": "bsc",
    "bnb": "bsc",
    "polygon": "polygon",
    "matic": "polygon",
    "base": "base",
    "arbitrum": "arbitrum",
    "arb": "arbitrum",
    "optimism": "optimism",
    "op": "optimism",
    "avax": "avalanche",
    "avalanche": "avalanche",
    "fantom": "fantom",
    "ftm": "fantom",
    "tron": "tron",
    "solana": "solana",
    "sol": "solana",
    "ton": "ton",
    "aptos": "aptos",
    "zksync": "zksync",
    "linea": "linea",
    "starknet": "starknet",
}

DTG_NETWORK_MARKER_RE = re.compile(
    r"(?:🎪\s*)?Network\s*[:\-]?\s*([A-Za-z][A-Za-z0-9_-]+)", re.IGNORECASE
)

# Defimon-TG asset token detection.
DTG_KNOWN_ASSET_TOKENS = (
    "USDT", "USDC", "WETH", "WBTC", "WBNB", "DAI", "FRAX", "BUSD", "TUSD",
    "USDP",
    "SOL", "BNB", "MATIC", "AVAX", "ARB", "OP", "FTM", "TRX",
    "stETH", "rETH", "cbETH", "wstETH", "stMATIC", "rsETH", "weETH",
    "ETH", "BTC", "USDe", "sUSDe", "PYUSD", "GUSD", "LINK", "UNI", "AAVE",
    "CRV", "CVX", "BAL", "COMP", "MKR", "SNX",
)
DTG_ASSET_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9_])("
    + "|".join(re.escape(t) for t in DTG_KNOWN_ASSET_TOKENS)
    + r")(?![A-Za-z0-9_])"
)


# ---------------------------------------------------------------------------
# Generic-shape helpers (incident-corpus-tx-enrichment.v1)
# ---------------------------------------------------------------------------

# Allowlist of source fields we will scan for matches (generic shape).
TEXT_FIELDS = [
    "attacker_action_sequence",
    "required_preconditions",
    "exploit_preconditions",
    "fix_pattern",
    "fix_anti_pattern_avoided",
    "raw_signature",
    "notes",
    "source_audit_ref",
    "record_source_url",
    "source_anchors",
    "record_extensions",
    "title",
    "target_project",
    "target_repo",
    "target_component",
    "protocol",
    "chain_or_language",
    "root_cause",
    "impact",
    "amount_stolen_literal_match",
    "attack_vector_summary",
    "report_date",
    "incident_date",
    "function_shape",
]


def _walk_strings(value: Any, path: str = "") -> Iterable[Tuple[str, str]]:
    """Yield (source_path, text) tuples from arbitrarily nested record."""
    if isinstance(value, str):
        if value.strip():
            yield path or "<root>", value
    elif isinstance(value, dict):
        for k, v in value.items():
            sub = f"{path}.{k}" if path else str(k)
            yield from _walk_strings(v, sub)
    elif isinstance(value, list):
        for i, item in enumerate(value):
            sub = f"{path}[{i}]"
            yield from _walk_strings(item, sub)
    # ignore numerics / nulls


def _gather_text(record: Dict[str, Any]) -> List[Tuple[str, str]]:
    """Return [(source_path, text)] for every string in TEXT_FIELDS."""
    out: List[Tuple[str, str]] = []
    for key in TEXT_FIELDS:
        if key in record:
            out.extend(_walk_strings(record[key], path=key))
    return out


def _parse_amount(literal: str, modifier: Optional[str]) -> Optional[int]:
    """Parse the literal $X (modifier?) into an integer USD value."""
    try:
        cleaned = literal.replace(",", "")
        amount_f = float(cleaned)
    except ValueError:
        return None
    if modifier:
        m = modifier.lower()
        if m in ("k", "thousand"):
            amount_f *= 1_000
        elif m in ("m", "million"):
            amount_f *= 1_000_000
        elif m in ("b", "billion"):
            amount_f *= 1_000_000_000
        elif m in ("t",):
            amount_f *= 1_000_000_000_000
    return int(amount_f)


def _extract_amount_usd(
    texts: List[Tuple[str, str]],
) -> Optional[Dict[str, Any]]:
    """Pick the largest plausible $-amount across all source texts."""
    best: Optional[Tuple[int, str, str]] = None
    for source, text in texts:
        for rx in RE_AMOUNT_DOLLAR:
            for m in rx.finditer(text):
                literal_full = m.group(0)
                num_lit = m.group(1)
                modifier = (
                    m.group(2) if m.lastindex and m.lastindex >= 2 else None
                )
                value = _parse_amount(num_lit, modifier)
                if value is None or value < 1:
                    continue
                if value < 100 or value > 1_000_000_000_000:
                    continue
                if best is None or value > best[0]:
                    best = (value, literal_full, source)
    if best is None:
        return None
    value, literal, source = best
    txt_lower = literal.lower()
    confidence = "low"
    if any(
        kw in source.lower() for kw in ("amount_stolen", "impact", "loss")
    ):
        confidence = "high"
    elif any(
        kw in txt_lower for kw in (" m", "million", "billion", " b")
    ):
        confidence = "medium"
    return {
        "value": value,
        "confidence": confidence,
        "literal_match": literal,
        "source_field": source,
    }


def _extract_chain(texts: List[Tuple[str, str]]) -> Optional[str]:
    """Vote across all texts for the most-mentioned chain slug."""
    counts: Dict[str, int] = {}
    for _source, text in texts:
        lower = text.lower()
        for chain_slug, keywords in CHAIN_INDICATORS:
            for kw in keywords:
                if kw in lower:
                    counts[chain_slug] = counts.get(chain_slug, 0) + 1
    if not counts:
        return None
    best_count = max(counts.values())
    for chain_slug, _ in CHAIN_INDICATORS:
        if counts.get(chain_slug, 0) == best_count:
            return chain_slug
    return None


def _extract_tx_hashes(
    texts: List[Tuple[str, str]],
) -> List[Dict[str, str]]:
    """Extract tx hashes; EVM unambiguous, BTC/Tron require context."""
    out: List[Dict[str, str]] = []
    seen: set = set()
    for source, text in texts:
        for m in RE_EVM_TX_HASH.finditer(text):
            val = m.group(0).lower()
            if val not in seen:
                seen.add(val)
                out.append(
                    {"value": val, "kind": "evm", "source_field": source}
                )
        lower = text.lower()
        if any(
            kw in lower
            for kw in (
                "bitcoin",
                "btc tx",
                "blockchain.com/btc",
                "mempool.space",
            )
        ):
            for m in RE_BTC_TX_HASH_LOOSE.finditer(text):
                val = m.group(0).lower()
                if val.startswith("0x"):
                    continue
                if "payload_sha256" in text and val in text:
                    continue
                if val not in seen:
                    seen.add(val)
                    out.append(
                        {
                            "value": val,
                            "kind": "bitcoin",
                            "source_field": source,
                        }
                    )
        if (
            "tron" in lower
            or "tronscan" in lower
            or "trx" in lower
        ):
            for m in RE_TRON_TX_HASH.finditer(text):
                val = m.group(0).lower()
                if val.startswith("0x"):
                    continue
                if "payload_sha256" in text and val in text:
                    continue
                if val not in seen:
                    seen.add(val)
                    out.append(
                        {
                            "value": val,
                            "kind": "tron",
                            "source_field": source,
                        }
                    )
    return out


def _extract_addresses(
    texts: List[Tuple[str, str]],
) -> List[Dict[str, str]]:
    """Extract contract / EOA addresses across EVM / Tron / Solana."""
    out: List[Dict[str, str]] = []
    seen: set = set()
    for source, text in texts:
        for m in RE_EVM_ADDRESS.finditer(text):
            val = m.group(0).lower()
            if val not in seen:
                seen.add(val)
                out.append(
                    {"value": val, "kind": "evm", "source_field": source}
                )
        for m in RE_TRON_ADDRESS.finditer(text):
            val = m.group(0)
            if val not in seen:
                seen.add(val)
                out.append(
                    {"value": val, "kind": "tron", "source_field": source}
                )
        lower = text.lower()
        if any(
            kw in lower
            for kw in (
                "solana",
                "solscan",
                "sol mainnet",
                "sol token",
            )
        ):
            for m in RE_SOL_ADDRESS.finditer(text):
                val = m.group(0)
                if val.startswith("T") and RE_TRON_ADDRESS.fullmatch(val):
                    continue
                if all(c in "0123456789abcdefABCDEF" for c in val):
                    continue
                if val not in seen:
                    seen.add(val)
                    out.append(
                        {
                            "value": val,
                            "kind": "solana",
                            "source_field": source,
                        }
                    )
    return out


def _extract_explorer_urls(
    texts: List[Tuple[str, str]],
) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    seen: set = set()
    for source, text in texts:
        for m in RE_EXPLORER_URL.finditer(text):
            val = m.group(0).rstrip(".,;)]}")
            if val not in seen:
                seen.add(val)
                out.append({"value": val, "source_field": source})
    return out


def _extract_asset_tokens(
    texts: List[Tuple[str, str]],
) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    seen: set = set()
    for source, text in texts:
        for m in RE_ASSET_TOKEN.finditer(text):
            val = m.group(1)
            if val not in seen:
                seen.add(val)
                out.append({"value": val, "source_field": source})
    return out


# ---------------------------------------------------------------------------
# Defimon-TG-shape helpers (defimon_tg_tx_enrichment.v1)
# ---------------------------------------------------------------------------


def extract_evidence(text: str, start: int, end: int, ctx: int = 24) -> str:
    """Return a bounded evidence_text excerpt around a match (L26)."""
    a = max(0, start - ctx)
    b = min(len(text), end + ctx)
    snippet = text[a:b].replace("\n", " ").strip()
    if len(snippet) > 160:
        snippet = snippet[:157] + "..."
    return snippet


def _dtg_dedup_preserve_order(items: List[Any]) -> List[Any]:
    seen: set = set()
    out: List[Any] = []
    for item in items:
        key = item if not isinstance(item, str) else item.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def extract_tx_hashes(text: str) -> List[Dict[str, str]]:
    """Defimon-TG shape: list of {hash, chain_hint, evidence_text}."""
    out: List[Dict[str, str]] = []
    seen: set = set()

    for m in DTG_EVM_TX_HASH_RE.finditer(text):
        h = m.group(0).lower()
        key = (h, "evm")
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "hash": h,
            "chain_hint": "evm",
            "evidence_text": extract_evidence(text, m.start(), m.end()),
        })

    for m in DTG_TRON_TX_URL_RE.finditer(text):
        h = m.group(1).lower()
        key = (h, "tron")
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "hash": h,
            "chain_hint": "tron",
            "evidence_text": extract_evidence(text, m.start(), m.end()),
        })

    for m in DTG_BTC_TX_URL_RE.finditer(text):
        h = m.group(1).lower()
        key = (h, "bitcoin")
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "hash": h,
            "chain_hint": "bitcoin",
            "evidence_text": extract_evidence(text, m.start(), m.end()),
        })

    for m in DTG_SOLANA_TX_URL_RE.finditer(text):
        h = m.group(1)
        key = (h, "solana")
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "hash": h,
            "chain_hint": "solana",
            "evidence_text": extract_evidence(text, m.start(), m.end()),
        })

    return out


def extract_contract_addresses(text: str) -> List[Dict[str, str]]:
    """Defimon-TG shape: list of {address, chain_hint, role, evidence_text}.

    Role markers (best-effort from 🤕 Victim / 🎩 Attacker / 🪄 Exploit
    prefixes) inferred when an EVM address appears immediately after one
    of those tokens; otherwise role is "unknown".
    """
    out: List[Dict[str, str]] = []
    seen: set = set()

    # Locate role markers and capture the next EVM address.
    role_re = re.compile(
        r"(?P<role>Victim|Attacker|Exploit|Contract|Token|EOA)"
        r"[\s:🤕🎩🪄]*[\s:]*(?P<addr>0x[a-fA-F0-9]{40})",
        re.IGNORECASE,
    )
    role_map: Dict[str, str] = {}
    for m in role_re.finditer(text):
        addr = m.group("addr").lower()
        role = m.group("role").lower()
        if addr not in role_map:
            role_map[addr] = role

    for m in DTG_EVM_ADDRESS_RE.finditer(text):
        addr = m.group(0).lower()
        key = (addr, "evm")
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "address": addr,
            "chain_hint": "evm",
            "role": role_map.get(addr, "unknown"),
            "evidence_text": extract_evidence(text, m.start(), m.end()),
        })

    for m in DTG_TRON_ADDR_URL_RE.finditer(text):
        addr = m.group(1)
        key = (addr, "tron")
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "address": addr,
            "chain_hint": "tron",
            "role": "unknown",
            "evidence_text": extract_evidence(text, m.start(), m.end()),
        })

    for m in DTG_TRON_ADDR_RE.finditer(text):
        addr = m.group(0)
        key = (addr, "tron")
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "address": addr,
            "chain_hint": "tron",
            "role": "unknown",
            "evidence_text": extract_evidence(text, m.start(), m.end()),
        })

    for m in DTG_SOLANA_ADDR_URL_RE.finditer(text):
        addr = m.group(1)
        key = (addr, "solana")
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "address": addr,
            "chain_hint": "solana",
            "role": "unknown",
            "evidence_text": extract_evidence(text, m.start(), m.end()),
        })

    return out


def refine_amount_usd(
    text: str, existing_amount: Optional[float]
) -> Optional[Dict[str, Any]]:
    """Defimon-TG shape: {value_usd, literal_match, evidence_text,
    matches_existing_amount_usd} or None.

    Picks the LARGEST dollar amount found (typical headline-impact pattern).
    Tie-break by literal length (longer literals tend to be more specific).
    """
    candidates: List[Tuple[float, str, str]] = []
    for pat, mult in DTG_AMOUNT_PATTERNS:
        for m in pat.finditer(text):
            raw = m.group(1)
            try:
                num = float(raw.replace(",", ""))
            except ValueError:
                continue
            value = num * mult
            literal = m.group(0)
            evidence = extract_evidence(text, m.start(), m.end())
            candidates.append((value, literal, evidence))

    if not candidates:
        return None
    candidates.sort(key=lambda t: (t[0], len(t[1])), reverse=True)
    value, literal, evidence = candidates[0]
    return {
        "value_usd": value,
        "literal_match": literal,
        "evidence_text": evidence,
        "matches_existing_amount_usd": (
            existing_amount is not None
            and abs(existing_amount - value)
            / max(1.0, max(abs(existing_amount), abs(value)))
            < 0.05
        ),
    }


def infer_chain(
    text: str, explorer_urls: List[str]
) -> Optional[Dict[str, Any]]:
    """Defimon-TG shape: {value, source, evidence_text} or None.

    Priority: explicit explorer URL host > Network: marker > inline keyword.
    """
    # 1) URL host
    for url in explorer_urls:
        m = re.match(r"https?://([^/]+)/?", url)
        if not m:
            continue
        host = m.group(1).lower()
        for suffix, chain in DTG_URL_HOST_TO_CHAIN.items():
            if host.endswith(suffix):
                return {
                    "value": chain,
                    "source": "explorer_url_host",
                    "evidence_text": url,
                }

    # 2) Network: marker
    for m in DTG_NETWORK_MARKER_RE.finditer(text):
        token = m.group(1).strip().lower()
        if token in DTG_NETWORK_TOKEN_TO_CHAIN:
            return {
                "value": DTG_NETWORK_TOKEN_TO_CHAIN[token],
                "source": "network_marker",
                "evidence_text": extract_evidence(text, m.start(), m.end()),
            }

    # 3) inline keyword fallback
    lowered = text.lower()
    for token in sorted(
        DTG_NETWORK_TOKEN_TO_CHAIN.keys(), key=len, reverse=True
    ):
        if re.search(r"\b" + re.escape(token) + r"\b", lowered):
            idx = lowered.find(token)
            return {
                "value": DTG_NETWORK_TOKEN_TO_CHAIN[token],
                "source": "inline_keyword",
                "evidence_text": extract_evidence(
                    text, idx, idx + len(token)
                ),
            }
    return None


def extract_asset_tokens(text: str) -> List[Dict[str, str]]:
    """Defimon-TG shape: list of {token, evidence_text}."""
    out: List[Dict[str, str]] = []
    seen: set = set()
    for m in DTG_ASSET_TOKEN_RE.finditer(text):
        token = m.group(1).upper()
        # Normalize stETH-family casing.
        if token in ("STETH",):
            token = "stETH"
        elif token in ("RETH",):
            token = "rETH"
        elif token in ("WSTETH",):
            token = "wstETH"
        elif token in ("CBETH",):
            token = "cbETH"
        elif token in ("STMATIC",):
            token = "stMATIC"
        elif token in ("RSETH",):
            token = "rsETH"
        elif token in ("WEETH",):
            token = "weETH"
        elif token == "USDE":
            token = "USDe"
        elif token == "SUSDE":
            token = "sUSDe"
        if token in seen:
            continue
        seen.add(token)
        out.append({
            "token": token,
            "evidence_text": extract_evidence(text, m.start(), m.end()),
        })
    return out


def extract_explorer_urls(text: str) -> List[str]:
    """Defimon-TG shape: list of explorer URL strings."""
    return _dtg_dedup_preserve_order(
        [m.group(0) for m in DTG_EXPLORER_URL_RE.finditer(text)]
    )


# ---------------------------------------------------------------------------
# Defimon-TG cross-corpus target-resolution index
# ---------------------------------------------------------------------------


def build_cross_corpus_address_index(
    cross_corpus_dirs: List[Path],
) -> Dict[str, List[Dict[str, str]]]:
    """Build an address -> [{project, record_id, source_path, chain_hint}].

    Walks every *.yaml under each cross-corpus tag dir, extracts EVM /
    Tron addresses from any string field of the record, and indexes them.
    Flexible about schema because the cross-corpora use different keys.

    Used by defimon-tg shape for cross-corpus target_hint resolution.
    """
    index: Dict[str, List[Dict[str, str]]] = {}

    for base in cross_corpus_dirs:
        if not base.exists():
            continue
        for path in base.rglob("*.yaml"):
            try:
                payload = (
                    yaml.safe_load(path.read_text(encoding="utf-8")) or {}
                )
            except (yaml.YAMLError, OSError):
                continue
            if not isinstance(payload, dict):
                continue

            project = (
                payload.get("target_project")
                or payload.get("target_project_slug")
                or payload.get("target_repo")
                or payload.get("title")
                or ""
            )
            record_id = payload.get("record_id", "")
            blob = json.dumps(payload, default=str)
            for m in DTG_EVM_ADDRESS_RE.finditer(blob):
                addr = m.group(0).lower()
                index.setdefault(addr, []).append({
                    "project": str(project),
                    "record_id": str(record_id),
                    "source_path": (
                        str(path.relative_to(REPO_ROOT))
                        if path.is_relative_to(REPO_ROOT)
                        else str(path)
                    ),
                    "chain_hint": "evm",
                })
            for m in DTG_TRON_ADDR_RE.finditer(blob):
                addr = m.group(0)
                index.setdefault(addr, []).append({
                    "project": str(project),
                    "record_id": str(record_id),
                    "source_path": (
                        str(path.relative_to(REPO_ROOT))
                        if path.is_relative_to(REPO_ROOT)
                        else str(path)
                    ),
                    "chain_hint": "tron",
                })
    return index


def resolve_target_via_cross_corpus(
    addresses: List[Dict[str, str]],
    cross_corpus_index: Dict[str, List[Dict[str, str]]],
) -> Optional[Dict[str, Any]]:
    """Defimon-TG: attempt target_project resolution via address overlap.

    Returns {project, evidence: [{address, project, record_id,
    source_path}, ...]} on at least one hit, else None.
    """
    if not addresses or not cross_corpus_index:
        return None
    hits: List[Dict[str, str]] = []
    for entry in addresses:
        addr = entry.get("address", "")
        if not addr:
            continue
        key = addr if entry.get("chain_hint") != "evm" else addr.lower()
        matches = cross_corpus_index.get(key) or []
        for m in matches:
            hits.append({
                "address": key,
                "project": m["project"],
                "record_id": m["record_id"],
                "source_path": m["source_path"],
            })
    if not hits:
        return None
    counter = Counter(h["project"] for h in hits if h["project"])
    if not counter:
        return None
    project, _ = counter.most_common(1)[0]
    return {
        "project": project,
        "evidence": hits[:10],  # cap at 10 to keep YAML readable
    }


# ---------------------------------------------------------------------------
# Generic-shape cross-corpus dedup index
# ---------------------------------------------------------------------------


def _build_cross_corpus_index(
    cross_dirs: List[Path],
) -> Dict[str, List[Dict[str, str]]]:
    """Index (lowercased) tx_hash / address -> [{record_id, corpus_dir}].

    Used by generic shapes for cross-corpus dedup annotation.
    """
    index: Dict[str, List[Dict[str, str]]] = {}
    for cdir in cross_dirs:
        if not cdir.exists():
            continue
        corpus_dir_str = str(cdir).rstrip("/")
        for yaml_path in cdir.rglob("*.yaml"):
            try:
                with open(yaml_path, "r", encoding="utf-8") as fh:
                    record = yaml.safe_load(fh)
            except (yaml.YAMLError, OSError):
                continue
            if not isinstance(record, dict):
                continue
            record_id = record.get("record_id") or yaml_path.stem
            texts = _gather_text(record)
            for m_list in (
                _extract_tx_hashes(texts),
                _extract_addresses(texts),
            ):
                for entry in m_list:
                    key = entry["value"]
                    index.setdefault(key, []).append(
                        {
                            "matched_record_id": str(record_id),
                            "matched_corpus_dir": corpus_dir_str,
                            "matched_file": str(yaml_path),
                        }
                    )
    return index


# ---------------------------------------------------------------------------
# Per-record enrichment dispatchers
# ---------------------------------------------------------------------------


def enrich_record(
    record: Dict[str, Any],
    cross_corpus_index: Optional[Dict[str, List[Dict[str, str]]]] = None,
    self_record_id: Optional[str] = None,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Generic-shape per-record enrichment.

    Returns (structured_extraction_block, cross_corpus_dedup_list).
    Shape: auditooor.incident_corpus_tx_enrichment.v1.
    """
    texts = _gather_text(record)
    tx_hashes = _extract_tx_hashes(texts)
    addresses = _extract_addresses(texts)
    amount = _extract_amount_usd(texts)
    chain = _extract_chain(texts)
    asset_tokens = _extract_asset_tokens(texts)
    explorer_urls = _extract_explorer_urls(texts)

    block: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "enriched_at_utc": dt.datetime.now(dt.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "tx_hashes": [e["value"] for e in tx_hashes],
        "contract_addresses": [e["value"] for e in addresses],
        "amount_usd": (
            {
                "value": amount["value"],
                "confidence": amount["confidence"],
                "literal_match": amount["literal_match"],
            }
            if amount
            else {
                "value": None,
                "confidence": "none",
                "literal_match": None,
            }
        ),
        "chain": chain,
        "asset_token": [e["value"] for e in asset_tokens],
        "explorer_urls": [e["value"] for e in explorer_urls],
        "provenance": {
            "tx_hashes": tx_hashes,
            "contract_addresses": addresses,
            "asset_token": asset_tokens,
            "explorer_urls": explorer_urls,
            "amount_usd_source_field": (
                amount["source_field"] if amount else None
            ),
        },
        "tool": TOOL_PATH,
    }

    dedup: List[Dict[str, Any]] = []
    if cross_corpus_index:
        for entry in tx_hashes:
            matches = cross_corpus_index.get(entry["value"], [])
            for m in matches:
                if (
                    self_record_id
                    and m.get("matched_record_id") == self_record_id
                ):
                    continue
                dedup.append(
                    {
                        "field": "tx_hash",
                        "value": entry["value"],
                        **m,
                    }
                )
        for entry in addresses:
            matches = cross_corpus_index.get(entry["value"], [])
            for m in matches:
                if (
                    self_record_id
                    and m.get("matched_record_id") == self_record_id
                ):
                    continue
                dedup.append(
                    {
                        "field": "contract_address",
                        "value": entry["value"],
                        **m,
                    }
                )

    return block, dedup


def enrich_record_defimon_tg(
    payload: Dict[str, Any],
    cross_corpus_index: Dict[str, List[Dict[str, str]]],
) -> Dict[str, Any]:
    """Defimon-TG-shape per-record enrichment.

    Returns the structured_extraction block. Shape:
    auditooor.defimon_tg_tx_enrichment.v1. Source fields:
    attack_vector_summary + notes (joined).
    """
    summary = str(payload.get("attack_vector_summary") or "")
    notes = str(payload.get("notes") or "")
    haystack = "\n".join([summary, notes])

    tx_hashes = extract_tx_hashes(haystack)
    addresses = extract_contract_addresses(haystack)
    explorer_urls = extract_explorer_urls(haystack)
    chain = infer_chain(haystack, explorer_urls)
    amount = refine_amount_usd(haystack, payload.get("amount_usd"))
    asset_tokens = extract_asset_tokens(haystack)

    existing_target = str(payload.get("target_project") or "").strip().lower()
    target_was_unknown = existing_target in ("", "unknown")

    resolution: Optional[Dict[str, Any]] = None
    resolution_attempted = False
    if target_was_unknown and addresses:
        resolution_attempted = True
        resolution = resolve_target_via_cross_corpus(
            addresses, cross_corpus_index
        )

    block: Dict[str, Any] = {
        "schema_version": DEFIMON_TG_SCHEMA_VERSION,
        "enriched_at_utc": dt.datetime.utcnow().strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "extractor": DEFIMON_TG_EXTRACTOR,
        "tx_hashes": tx_hashes,
        "contract_addresses": addresses,
        "amount_usd_refined": amount,
        "chain": chain,
        "asset_tokens": asset_tokens,
        "explorer_urls": explorer_urls,
        "resolution_attempted": resolution_attempted,
        "cross_corpus_resolution": resolution,
    }
    return block


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def iter_yaml_files(
    input_dir: Path, shape: str = "generic"
) -> Iterable[Path]:
    """Yield yaml record paths per shape.

    Defimon-TG shape walks `record.yaml` only; other shapes walk every
    `*.yaml` so already-enriched mev / darknavy / rekt records keep
    their existing file naming compatibility.
    """
    if shape == "defimon-tg":
        yield from sorted(input_dir.rglob("record.yaml"))
    else:
        yield from input_dir.rglob("*.yaml")


def process_corpus(
    input_dir: Path,
    cross_dirs: List[Path],
    dry_run: bool = False,
    shape: str = "generic",
    limit: Optional[int] = None,
) -> Dict[str, Any]:
    """Dispatch per-shape enrichment over the corpus.

    Defimon-TG shape uses defimon-tg cross-corpus address-index and emits
    the defimon-tg block + summary. Other shapes use generic cross-corpus
    dedup and emit the generic block + summary.
    """
    if shape == "defimon-tg":
        return _process_corpus_defimon_tg(
            input_dir, cross_dirs, dry_run=dry_run, limit=limit
        )
    return _process_corpus_generic(
        input_dir, cross_dirs, dry_run=dry_run, shape=shape, limit=limit
    )


def _process_corpus_generic(
    input_dir: Path,
    cross_dirs: List[Path],
    dry_run: bool = False,
    shape: str = "generic",
    limit: Optional[int] = None,
) -> Dict[str, Any]:
    """Generic-shape driver (mev / darknavy / rekt / bridge / defimon-blog)."""
    cross_index: Dict[str, List[Dict[str, str]]] = {}
    if cross_dirs:
        cross_index = _build_cross_corpus_index(cross_dirs)

    summary: Dict[str, Any] = {
        "input_dir": str(input_dir),
        "cross_corpus_dirs": [str(c) for c in cross_dirs],
        "corpus_shape": shape,
        "records_scanned": 0,
        "records_enriched": 0,
        "tx_hash_extraction_count": 0,
        "address_extraction_count": 0,
        "amount_usd_parsed_count": 0,
        "chain_inferred_count": 0,
        "asset_token_count": 0,
        "explorer_url_count": 0,
        "cross_corpus_dedup_hits": 0,
        "errors": [],
        "files_written": 0,
        "dry_run": dry_run,
    }

    paths = list(iter_yaml_files(input_dir, shape=shape))
    if limit is not None:
        paths = paths[:limit]

    for yaml_path in paths:
        summary["records_scanned"] += 1
        try:
            with open(yaml_path, "r", encoding="utf-8") as fh:
                record = yaml.safe_load(fh)
        except (yaml.YAMLError, OSError) as exc:
            summary["errors"].append(
                {"path": str(yaml_path), "error": str(exc)}
            )
            continue
        if not isinstance(record, dict):
            summary["errors"].append(
                {"path": str(yaml_path), "error": "not-a-mapping"}
            )
            continue
        self_record_id = record.get("record_id")
        block, dedup = enrich_record(
            record,
            cross_corpus_index=cross_index,
            self_record_id=(
                str(self_record_id) if self_record_id else None
            ),
        )

        if block["tx_hashes"]:
            summary["tx_hash_extraction_count"] += len(block["tx_hashes"])
        if block["contract_addresses"]:
            summary["address_extraction_count"] += len(
                block["contract_addresses"]
            )
        if block["amount_usd"].get("value") is not None:
            summary["amount_usd_parsed_count"] += 1
        if block["chain"]:
            summary["chain_inferred_count"] += 1
        if block["asset_token"]:
            summary["asset_token_count"] += len(block["asset_token"])
        if block["explorer_urls"]:
            summary["explorer_url_count"] += len(block["explorer_urls"])
        if dedup:
            summary["cross_corpus_dedup_hits"] += len(dedup)

        anything_found = bool(
            block["tx_hashes"]
            or block["contract_addresses"]
            or block["amount_usd"].get("value") is not None
            or block["chain"]
            or block["asset_token"]
            or block["explorer_urls"]
        )
        if anything_found:
            summary["records_enriched"] += 1

        record["structured_extraction"] = block
        if dedup:
            record["cross_corpus_dedup"] = dedup

        if not dry_run:
            try:
                with open(yaml_path, "w", encoding="utf-8") as fh:
                    yaml.safe_dump(
                        record, fh, sort_keys=False, allow_unicode=True
                    )
                summary["files_written"] += 1
            except OSError as exc:
                summary["errors"].append(
                    {"path": str(yaml_path), "error": str(exc)}
                )

    return summary


def _process_corpus_defimon_tg(
    input_dir: Path,
    cross_corpus_dirs: List[Path],
    *,
    dry_run: bool = False,
    limit: Optional[int] = None,
) -> Dict[str, Any]:
    """Defimon-TG-shape driver. Walks record.yaml only."""
    if not input_dir.exists():
        raise SystemExit(f"input dir does not exist: {input_dir}")

    cross_corpus_index = build_cross_corpus_address_index(cross_corpus_dirs)

    records_seen = 0
    records_enriched = 0
    tx_hash_total = 0
    address_total = 0
    amount_refined = 0
    chain_inferred = 0
    target_resolved = 0
    target_was_unknown_before = 0
    chain_distribution: Counter = Counter()
    chain_inference_source: Counter = Counter()
    tx_chain_distribution: Counter = Counter()
    cross_corpus_dedup_hits = 0
    resolution_attempted_total = 0

    record_paths = sorted(input_dir.rglob("record.yaml"))
    if limit is not None:
        record_paths = record_paths[:limit]

    for path in record_paths:
        records_seen += 1
        try:
            payload = (
                yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            )
        except (yaml.YAMLError, OSError):
            continue
        if not isinstance(payload, dict):
            continue

        existing_target = str(
            payload.get("target_project") or ""
        ).strip().lower()
        if existing_target in ("", "unknown"):
            target_was_unknown_before += 1

        block = enrich_record_defimon_tg(payload, cross_corpus_index)
        if not dry_run:
            # Preserve insertion order: existing fields first, then
            # structured_extraction at end. Existing block replaced wholesale.
            merged = {
                k: v
                for k, v in payload.items()
                if k != "structured_extraction"
            }
            merged["structured_extraction"] = block
            serialized = yaml.safe_dump(
                merged,
                sort_keys=False,
                allow_unicode=True,
                default_flow_style=False,
                width=1000,
            )
            path.write_text(serialized, encoding="utf-8")
        records_enriched += 1

        tx_hash_total += len(block["tx_hashes"])
        address_total += len(block["contract_addresses"])
        for entry in block["tx_hashes"]:
            tx_chain_distribution[entry["chain_hint"]] += 1
        if block["amount_usd_refined"]:
            amount_refined += 1
        if block["chain"]:
            chain_inferred += 1
            chain_distribution[block["chain"]["value"]] += 1
            chain_inference_source[block["chain"]["source"]] += 1
        if block["resolution_attempted"]:
            resolution_attempted_total += 1
        if block["cross_corpus_resolution"]:
            target_resolved += 1
            cross_corpus_dedup_hits += len(
                block["cross_corpus_resolution"]["evidence"]
            )

    summary = {
        "schema_version": DEFIMON_TG_SUMMARY_SCHEMA_VERSION,
        "corpus_shape": "defimon-tg",
        "input_dir": (
            str(input_dir.relative_to(REPO_ROOT))
            if input_dir.is_relative_to(REPO_ROOT)
            else str(input_dir)
        ),
        "cross_corpus_dirs": [
            str(d.relative_to(REPO_ROOT))
            if d.is_relative_to(REPO_ROOT)
            else str(d)
            for d in cross_corpus_dirs
        ],
        "cross_corpus_index_size": len(cross_corpus_index),
        "records_seen": records_seen,
        "records_enriched": records_enriched,
        "tx_hash_total": tx_hash_total,
        "tx_chain_distribution": dict(tx_chain_distribution),
        "address_total": address_total,
        "amount_refined": amount_refined,
        "chain_inferred": chain_inferred,
        "chain_distribution": dict(chain_distribution),
        "chain_inference_source": dict(chain_inference_source),
        "target_was_unknown_before": target_was_unknown_before,
        "resolution_attempted_total": resolution_attempted_total,
        "target_resolved_cross_corpus": target_resolved,
        "cross_corpus_dedup_hits": cross_corpus_dedup_hits,
        "dry_run": dry_run,
    }
    return summary


# ---------------------------------------------------------------------------
# Defimon-TG walk_records (back-compat for direct callers of the legacy API)
# ---------------------------------------------------------------------------


def walk_records(
    input_dir: Path,
    cross_corpus_dirs: List[Path],
    *,
    dry_run: bool = False,
    limit: Optional[int] = None,
) -> Dict[str, Any]:
    """Back-compat alias for legacy defimon-tg callers.

    Equivalent to process_corpus(..., shape="defimon-tg").
    """
    return _process_corpus_defimon_tg(
        input_dir, cross_corpus_dirs, dry_run=dry_run, limit=limit
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            __doc__.splitlines()[0] if __doc__ else ""
        )
    )
    parser.add_argument(
        "--input-dir",
        required=True,
        type=Path,
        help="Corpus directory (recursive *.yaml scan).",
    )
    parser.add_argument(
        "--corpus-shape",
        choices=CORPUS_SHAPES,
        default="generic",
        help=(
            "Per-corpus extraction shape. defimon-tg enables role "
            "attribution + cross-corpus target_hint resolution; the other "
            "shapes use the generic block schema. Default: generic."
        ),
    )
    parser.add_argument(
        "--cross-corpus-dirs",
        default="",
        help=(
            "Comma-separated list of sibling corpus dirs. Used for "
            "cross-corpus dedup (generic shapes) or target_hint resolution "
            "(defimon-tg shape)."
        ),
    )
    parser.add_argument(
        "--json-summary",
        type=Path,
        default=None,
        help="Write the summary JSON to this path (otherwise stdout).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Do not write any files; just report counts.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help=(
            "Process only the first N records (useful for smoke testing)."
        ),
    )
    args = parser.parse_args(argv)

    if not args.input_dir.exists() or not args.input_dir.is_dir():
        print(
            f"[error] --input-dir not a directory: {args.input_dir}",
            file=sys.stderr,
        )
        return 2

    cross_dirs: List[Path] = []
    if args.cross_corpus_dirs:
        for token in args.cross_corpus_dirs.split(","):
            token = token.strip()
            if not token:
                continue
            cross_dirs.append(Path(token))

    summary = process_corpus(
        args.input_dir,
        cross_dirs,
        dry_run=args.dry_run,
        shape=args.corpus_shape,
        limit=args.limit,
    )
    out_json = json.dumps(summary, indent=2, sort_keys=True, default=str)
    if args.json_summary:
        args.json_summary.parent.mkdir(parents=True, exist_ok=True)
        with open(args.json_summary, "w", encoding="utf-8") as fh:
            fh.write(out_json)
    else:
        print(out_json)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
